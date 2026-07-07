// Package egress implements the trusted credential-injecting egress proxy
// for mediated agent runs (protocol/injection.md). It receives plaintext
// requests from the agent on localhost, fetches injectable headers from
// brokerd under its own egress-role identity, injects them, and re-originates
// TLS to the pinned upstream host. The agent never possesses a credential.
package egress

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Placeholder is the documented zero-entropy constant from
// protocol/injection.md. Request headers carrying it are always stripped
// before injection; it must never reach an upstream.
const Placeholder = "NVT-PLACEHOLDER-NOT-A-KEY"

// Route maps one local listener to one capability and upstream host.
type Route struct {
	// Listen is the local address, e.g. "127.0.0.1:8471".
	Listen string `json:"listen"`
	// Capability is the broker capability (provider name) whose injectable
	// headers authorize this route.
	Capability string `json:"capability"`
	// Upstream is the pinned upstream host[:port]. TLS is re-originated to
	// this host; the incoming request cannot choose a different one.
	Upstream string `json:"upstream"`
	// AllowInsecureUpstream permits a plain-HTTP upstream. Test/dev only.
	AllowInsecureUpstream bool `json:"allow_insecure_upstream"`
	// ListenTLSCert and ListenTLSKey optionally make the agent-facing
	// listener serve HTTPS. Needed when the client refuses a plaintext base
	// URL; the agent must trust the serving cert's CA. This is the same
	// agent-facing TLS termination Phase 4 generalizes — used here only so
	// the Phase 2 gate can distinguish "client requires https" from "client
	// pins certs". Both must be set together or neither.
	ListenTLSCert string `json:"listen_tls_cert"`
	ListenTLSKey  string `json:"listen_tls_key"`
	// ListenTLS selects a managed TLS mode for the agent-facing listener.
	// The only supported value is "ca": serve HTTPS with an on-demand leaf
	// signed by the boot-generated per-agent CA (requires the config-level
	// ca block). Mutually exclusive with listen_tls_cert/listen_tls_key.
	ListenTLS string `json:"listen_tls"`
	// MaxRequests caps proxied requests on this route. 0 means unlimited.
	// The counter lives for the egressd process, not the run: an egressd
	// restart resets it. This is a soft resource guard, not a security
	// boundary (docs/phase5-6b-observability-pr-plan.md decision 3).
	MaxRequests int `json:"max_requests"`
}

// TLSEnabled reports whether the agent-facing listener serves HTTPS.
func (r Route) TLSEnabled() bool {
	return r.ListenTLS == RouteListenTLSCA || (r.ListenTLSCert != "" && r.ListenTLSKey != "")
}

// RouteListenTLSCA is the managed listen_tls mode backed by the per-agent CA.
const RouteListenTLSCA = "ca"

// Config is the egressd configuration file shape.
type Config struct {
	// BrokerURL is the brokerd base URL. Must be https: the egressd-broker
	// leg is the one network path carrying real credentials through the
	// agent's network namespace (docs/mediated-egress-plan.md section 2).
	BrokerURL string `json:"broker_url"`
	// AllowInsecureBroker permits a plain-HTTP broker URL. Local dev only;
	// a mediated deployment serving injection over plaintext reachable from
	// the agent netns is a conformance failure.
	AllowInsecureBroker bool `json:"allow_insecure_broker"`
	// BrokerCAFile optionally pins a CA bundle for the broker TLS endpoint.
	BrokerCAFile string              `json:"broker_ca_file"`
	Routes       []Route             `json:"routes"`
	ForwardProxy *ForwardProxyConfig `json:"forward_proxy"`
	// CA enables the boot-generated per-agent CA backing listen_tls: ca
	// routes. Only the CA certificate is ever published; the key stays in
	// egressd memory.
	CA *CAConfig `json:"ca"`
}

// CAConfig configures the boot-generated per-agent CA.
type CAConfig struct {
	// PublishDir is where ca.crt is written for the agent container to
	// trust (a shared volume mounted read-only on the agent side). Same-Pod
	// mode; optional when ServeAddr distributes the certificate instead.
	PublishDir string `json:"publish_dir"`
	// LeafDNSNames extends leaf SANs and the CA name constraints with
	// synthetic per-run Service names (own-Pod mode). Never upstream names:
	// any overlap with a route upstream host fails validation.
	LeafDNSNames []string `json:"leaf_dns_names"`
	// ServeAddr enables the plain-HTTP CA endpoint (GET /ca.crt, /healthz).
	// The certificate is public material and is the trust anchor being
	// bootstrapped, so TLS here would be circular.
	ServeAddr string `json:"serve_addr"`
	// CertFile and KeyFile load a durable CA keypair. Own-Pod enforcement uses
	// these from a Secret so an egressd restart keeps the agent trust anchor
	// stable. Same-Pod/local modes may leave both empty to generate at boot.
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// ForwardProxyConfig enables CONNECT proxying. AllowHosts are blind-tunnelled
// (no TLS termination, no injection). InjectRoutes are TLS-terminated under the
// per-agent CA and injected — the Phase 6.2 MITM path.
type ForwardProxyConfig struct {
	Listen                   string   `json:"listen"`
	AllowHosts               []string `json:"allow_hosts"`
	AllowPorts               []int    `json:"allow_ports"`
	MaxConcurrentTunnels     int      `json:"max_concurrent_tunnels"`
	TunnelIdleTimeoutSeconds int      `json:"tunnel_idle_timeout_seconds"`
	// InjectRoutes: for each CONNECT to one of these hosts, egressd terminates
	// TLS with a CA-minted leaf for the host, injects the broker credential,
	// and re-originates TLS to the pinned upstream.
	InjectRoutes []ForwardProxyInjectRoute `json:"inject_routes"`
}

// ForwardProxyInjectRoute maps a MITM'd upstream host to a broker capability.
type ForwardProxyInjectRoute struct {
	// Host is the CONNECT/SNI host to terminate TLS for (a DNS name).
	Host string `json:"host"`
	// Capability is the broker capability whose injectable headers authorize
	// requests to this host.
	Capability string `json:"capability"`
	// Upstream is the pinned re-origination target host[:port]. The decrypted
	// request cannot choose a different one.
	Upstream string `json:"upstream"`
	// AllowInsecureUpstream permits a plain-HTTP upstream leg. Test/dev only.
	AllowInsecureUpstream bool `json:"allow_insecure_upstream"`
	// MaxRequests caps proxied requests on this route (0 = unlimited).
	MaxRequests int `json:"max_requests"`
}

// LoadConfig reads and validates the configuration file.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var config Config
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &config, nil
}

// Validate enforces the transport and route rules.
func (c *Config) Validate() error {
	if len(c.Routes) == 0 && c.ForwardProxy == nil {
		return fmt.Errorf("at least one route or forward_proxy is required")
	}
	if len(c.Routes) > 0 {
		parsed, err := url.Parse(c.BrokerURL)
		if err != nil || parsed.Host == "" {
			return fmt.Errorf("broker_url must be a valid URL")
		}
		switch parsed.Scheme {
		case "https":
		case "http":
			if !c.AllowInsecureBroker {
				return fmt.Errorf("broker_url must be https unless allow_insecure_broker is set (local dev only)")
			}
		default:
			return fmt.Errorf("broker_url must be an http(s) URL")
		}
	}
	for index, route := range c.Routes {
		if route.Listen == "" {
			return fmt.Errorf("routes[%d].listen is required", index)
		}
		if route.Capability == "" {
			return fmt.Errorf("routes[%d].capability is required", index)
		}
		if err := validateUpstream(route.Upstream); err != nil {
			return fmt.Errorf("routes[%d].upstream: %w", index, err)
		}
		if route.MaxRequests < 0 {
			return fmt.Errorf("routes[%d].max_requests must be non-negative", index)
		}
		if (route.ListenTLSCert == "") != (route.ListenTLSKey == "") {
			return fmt.Errorf("routes[%d]: listen_tls_cert and listen_tls_key must be set together", index)
		}
		switch route.ListenTLS {
		case "":
		case RouteListenTLSCA:
			if route.ListenTLSCert != "" || route.ListenTLSKey != "" {
				return fmt.Errorf("routes[%d]: listen_tls: ca is mutually exclusive with listen_tls_cert/listen_tls_key", index)
			}
			if c.CA == nil {
				return fmt.Errorf("routes[%d]: listen_tls: ca requires the config-level ca block", index)
			}
		default:
			return fmt.Errorf("routes[%d]: listen_tls must be %q when set, got %q", index, RouteListenTLSCA, route.ListenTLS)
		}
	}
	if c.CA != nil {
		if c.CA.PublishDir == "" && c.CA.ServeAddr == "" {
			return fmt.Errorf("ca requires publish_dir or serve_addr")
		}
		if (c.CA.CertFile == "") != (c.CA.KeyFile == "") {
			return fmt.Errorf("ca cert_file and key_file must be set together")
		}
		routeUpstreamHosts := map[string]bool{}
		for _, route := range c.Routes {
			if host, ok := normalizedRouteUpstreamHost(route.Upstream); ok {
				routeUpstreamHosts[host] = true
			}
		}
		for index, name := range c.CA.LeafDNSNames {
			if name == "" {
				return fmt.Errorf("ca.leaf_dns_names[%d] must not be empty", index)
			}
			// Leaf names are synthetic redirect names; minting for a real
			// upstream is exactly the boundary Phase 4 established.
			if routeUpstreamHosts[strings.ToLower(name)] {
				return fmt.Errorf("ca.leaf_dns_names[%d] %q matches a route upstream host", index, name)
			}
		}
	}
	if c.ForwardProxy != nil {
		if err := c.ForwardProxy.Validate(); err != nil {
			return fmt.Errorf("forward_proxy: %w", err)
		}
		if err := c.validateForwardProxyRouteOverlap(); err != nil {
			return err
		}
		if len(c.ForwardProxy.InjectRoutes) > 0 && c.CA == nil {
			return fmt.Errorf("forward_proxy.inject_routes require the config-level ca block")
		}
	}
	return nil
}

func (c *Config) validateForwardProxyRouteOverlap() error {
	routeHosts := map[string]bool{}
	for _, route := range c.Routes {
		host, ok := normalizedRouteUpstreamHost(route.Upstream)
		if ok {
			routeHosts[host] = true
		}
	}
	for _, host := range c.ForwardProxy.AllowHosts {
		normalized := strings.ToLower(host)
		if routeHosts[normalized] {
			return fmt.Errorf("forward_proxy.allow_hosts[%q] overlaps mediated route upstream", host)
		}
	}
	// Each MITM host must be a valid DNS host mapped to a capability and a
	// pinned upstream, and must not collide with a mediated route upstream or a
	// blind-tunnel host — a host mediates exactly one way.
	blindHosts := map[string]bool{}
	for _, host := range c.ForwardProxy.AllowHosts {
		if normalized, err := normalizeProxyHost(host); err == nil {
			blindHosts[normalized] = true
		}
	}
	injectHosts := map[string]bool{}
	for index, route := range c.ForwardProxy.InjectRoutes {
		host, err := normalizeProxyHost(route.Host)
		if err != nil {
			return fmt.Errorf("forward_proxy.inject_routes[%d].host: %w", index, err)
		}
		if net.ParseIP(host) != nil {
			return fmt.Errorf("forward_proxy.inject_routes[%d].host must be a DNS name, not an IP", index)
		}
		if route.Capability == "" {
			return fmt.Errorf("forward_proxy.inject_routes[%d].capability is required", index)
		}
		if err := validateUpstream(route.Upstream); err != nil {
			return fmt.Errorf("forward_proxy.inject_routes[%d].upstream: %w", index, err)
		}
		if route.MaxRequests < 0 {
			return fmt.Errorf("forward_proxy.inject_routes[%d].max_requests must be non-negative", index)
		}
		if injectHosts[host] {
			return fmt.Errorf("forward_proxy.inject_routes[%d].host %q is duplicated", index, route.Host)
		}
		if blindHosts[host] || routeHosts[host] {
			return fmt.Errorf("forward_proxy.inject_routes[%d].host %q overlaps a blind-tunnel or mediated route host", index, route.Host)
		}
		injectHosts[host] = true
	}
	return nil
}

// ForwardProxyUpstreamLeafNames is the set of MITM host names the CA must be
// able to mint a leaf for. Used to widen the CA name constraints at boot.
func (c *Config) ForwardProxyUpstreamLeafNames() []string {
	if c.ForwardProxy == nil {
		return nil
	}
	names := make([]string, 0, len(c.ForwardProxy.InjectRoutes))
	for _, route := range c.ForwardProxy.InjectRoutes {
		if host, err := normalizeProxyHost(route.Host); err == nil {
			names = append(names, host)
		}
	}
	return names
}

// Validate enforces the forward proxy's fail-closed shape. An empty allowlist
// is valid and means deny all.
func (c *ForwardProxyConfig) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen is required")
	}
	for _, host := range c.AllowHosts {
		if _, err := normalizeProxyHost(host); err != nil {
			return fmt.Errorf("allow_hosts[%q]: %w", host, err)
		}
	}
	for _, port := range c.effectiveAllowPorts() {
		if port < 1 || port > 65535 {
			return fmt.Errorf("allow_ports contains invalid port %d", port)
		}
	}
	if c.MaxConcurrentTunnels < 0 {
		return fmt.Errorf("max_concurrent_tunnels must be non-negative")
	}
	if c.TunnelIdleTimeoutSeconds < 0 {
		return fmt.Errorf("tunnel_idle_timeout_seconds must be non-negative")
	}
	return nil
}

func (c *ForwardProxyConfig) effectiveAllowPorts() []int {
	if len(c.AllowPorts) == 0 {
		return []int{443}
	}
	return c.AllowPorts
}

func (c *ForwardProxyConfig) effectiveMaxConcurrentTunnels() int {
	if c.MaxConcurrentTunnels == 0 {
		return defaultForwardProxyMaxConcurrentTunnels
	}
	return c.MaxConcurrentTunnels
}

func (c *ForwardProxyConfig) effectiveTunnelIdleTimeout() time.Duration {
	if c.TunnelIdleTimeoutSeconds == 0 {
		return defaultForwardProxyTunnelIdleTimeout
	}
	return time.Duration(c.TunnelIdleTimeoutSeconds) * time.Second
}

func normalizedRouteUpstreamHost(upstream string) (string, bool) {
	host := upstream
	if strings.Contains(upstream, ":") {
		split, _, err := net.SplitHostPort(upstream)
		if err != nil {
			return "", false
		}
		host = split
	}
	normalized, err := normalizeProxyHost(host)
	if err != nil {
		return "", false
	}
	return normalized, true
}

// validateUpstream enforces that the pinned re-origination target is a bare
// host[:port]. Schemes, paths, userinfo, and malformed ports are rejected:
// this value decides where credentials are sent, so upstream-host confusion
// is an SSRF vector, not a formatting nit.
func validateUpstream(upstream string) error {
	if upstream == "" {
		return fmt.Errorf("must not be empty")
	}
	if strings.Contains(upstream, "://") || strings.ContainsAny(upstream, "/\\@?# \t") {
		return fmt.Errorf("must be a bare host[:port], got %q", upstream)
	}
	host := upstream
	if strings.Contains(upstream, ":") {
		split, port, err := net.SplitHostPort(upstream)
		if err != nil {
			return fmt.Errorf("invalid host:port %q", upstream)
		}
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return fmt.Errorf("invalid port in %q", upstream)
		}
		host = split
	}
	if host == "" {
		return fmt.Errorf("empty host in %q", upstream)
	}
	return nil
}
