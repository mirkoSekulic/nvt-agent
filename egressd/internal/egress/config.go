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
}

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
	BrokerCAFile string  `json:"broker_ca_file"`
	Routes       []Route `json:"routes"`
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
	if len(c.Routes) == 0 {
		return fmt.Errorf("at least one route is required")
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
	}
	return nil
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
