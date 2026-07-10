package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	dialTimeout                             = 10 * time.Second
	defaultForwardProxyMaxConcurrentTunnels = 64
	defaultForwardProxyTunnelIdleTimeout    = 60 * time.Second
	forwardProxyMITMReadHeaderTimeout       = 30 * time.Second
)

// ForwardProxy is a CONNECT-only proxy. Non-inject hosts are blind-tunnelled;
// inject-route hosts are TLS-terminated under the per-agent CA and dispatched
// through Proxy, which injects credentials on the decrypted HTTP request. It
// never inspects WebSocket frames after an HTTP Upgrade is established.
// forwardProxyCapability labels forward-proxy CONNECT audit reports. The
// forward proxy is not per-capability; this is a fixed observability label.
const forwardProxyCapability = "forward-proxy"

type ForwardProxy struct {
	Config   ForwardProxyConfig
	Dialer   *net.Dialer
	Resolver IPResolver
	// DialContext is a test seam. Production dials the already validated IP
	// address and never resolves the hostname a second time.
	DialContext func(context.Context, string, string) (net.Conn, error)
	Logger      *log.Logger
	Reporter    *Reporter
	// CA, Broker, and Transport back the TLS-terminating inject routes. Nil
	// when the forward proxy only blind-tunnels.
	CA        *CA
	Broker    *BrokerClient
	Transport http.RoundTripper

	once              sync.Once
	allowHosts        map[string]bool
	allowPorts        map[int]bool
	tunnelSlots       chan struct{}
	injectProxies     map[string][]injectProxy
	destinationPolicy destinationPolicy
}

type injectProxy struct {
	capability            string
	requireCapabilityHint bool
	proxy                 *Proxy
}

func (p *ForwardProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		p.writeDecision("", 0, "deny", "plain_http_not_supported")
		http.Error(w, "plain HTTP proxying is not supported", http.StatusMethodNotAllowed)
		return
	}
	target, err := connectTargetFromRequest(r)
	if err != nil {
		p.writeDecision("", 0, "deny", "malformed_target")
		http.Error(w, "malformed CONNECT target", http.StatusBadRequest)
		return
	}
	// A CONNECT to an inject-route host is TLS-terminated and injected; every
	// other host falls through to the blind-tunnel allowlist.
	proxy, found, err := p.injectProxy(target.host, capabilityHintFromConnect(r))
	if err != nil {
		p.writeDecision(target.host, target.port, "deny", "capability_not_allowed")
		http.Error(w, "CONNECT capability not allowed", http.StatusForbidden)
		return
	}
	if found {
		p.serveMITM(w, target, proxy)
		return
	}
	if !p.allowed(target) {
		p.writeDecision(target.host, target.port, "deny", "target_not_allowed")
		http.Error(w, "CONNECT target not allowed", http.StatusForbidden)
		return
	}
	releaseTunnel, ok := p.acquireTunnel()
	if !ok {
		p.writeDecision(target.host, target.port, "deny", "tunnel_limit_exceeded")
		http.Error(w, "CONNECT tunnel limit exceeded", http.StatusServiceUnavailable)
		return
	}
	defer releaseTunnel()

	address, err := p.resolveTarget(r.Context(), target)
	if err != nil {
		p.writeDecision(target.host, target.port, "deny", "destination_denied")
		http.Error(w, "CONNECT destination denied", http.StatusForbidden)
		return
	}
	upstream, err := p.dial(r.Context(), net.JoinHostPort(address.String(), strconv.Itoa(target.port)))
	if err != nil {
		p.writeDecision(target.host, target.port, "deny", "upstream_unreachable")
		http.Error(w, "CONNECT upstream unreachable", http.StatusBadGateway)
		return
	}
	defer func() { _ = upstream.Close() }()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.writeDecision(target.host, target.port, "deny", "hijack_unavailable")
		http.Error(w, "CONNECT unavailable", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		p.writeDecision(target.host, target.port, "deny", "hijack_failed")
		http.Error(w, "CONNECT unavailable", http.StatusInternalServerError)
		return
	}
	defer func() { _ = client.Close() }()

	p.writeDecision(target.host, target.port, "allow", "")
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	tunnel(client, buffered, upstream, p.Config.effectiveTunnelIdleTimeout())
}

// serveMITM terminates TLS for an inject-route host under the per-agent CA,
// then serves the decrypted request(s) through the capability's Proxy —
// reusing its material fetch, header injection, placeholder strip, upstream
// pinning, quota, audit, and streaming exactly as a redirect route. The agent
// trusts the CA, so the minted leaf validates; the real upstream never sees the
// placeholder and the decrypted request cannot redirect off the pinned host.
func (p *ForwardProxy) serveMITM(w http.ResponseWriter, target connectTarget, proxy *Proxy) {
	if p.CA == nil {
		p.writeDecision(target.host, target.port, "deny", "mitm_unconfigured")
		http.Error(w, "CONNECT unavailable", http.StatusInternalServerError)
		return
	}
	if !p.portAllowed(target.port) {
		p.writeDecision(target.host, target.port, "deny", "target_not_allowed")
		http.Error(w, "CONNECT target not allowed", http.StatusForbidden)
		return
	}
	releaseTunnel, ok := p.acquireTunnel()
	if !ok {
		p.writeDecision(target.host, target.port, "deny", "tunnel_limit_exceeded")
		http.Error(w, "CONNECT tunnel limit exceeded", http.StatusServiceUnavailable)
		return
	}
	defer releaseTunnel()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.writeDecision(target.host, target.port, "deny", "hijack_unavailable")
		http.Error(w, "CONNECT unavailable", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		p.writeDecision(target.host, target.port, "deny", "hijack_failed")
		http.Error(w, "CONNECT unavailable", http.StatusInternalServerError)
		return
	}
	defer func() { _ = client.Close() }()

	p.writeDecision(target.host, target.port, "allow", "")
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// Terminate TLS under the per-agent CA. GetCertificate refuses any SNI not
	// in the configured upstream allowlist (empty SNI -> the local leaf; a
	// sibling allowlisted host's SNI -> that sibling's leaf), so a client
	// cannot obtain a leaf for a non-allowlisted host. Routing stays pinned to
	// the CONNECT host regardless of SNI: this proxy and its pinned upstream
	// were selected by target.host, not by the ClientHello.
	tlsConn := tls.Server(&mitmConn{Conn: client, reader: buffered.Reader}, p.CA.ServerTLSConfig())
	defer func() { _ = tlsConn.Close() }()
	idle := p.Config.effectiveTunnelIdleTimeout()
	if idle > 0 {
		_ = tlsConn.SetDeadline(time.Now().Add(idle))
	}
	if err := tlsConn.Handshake(); err != nil {
		p.logf("event=mitm target_host=%s handshake_failed", target.host)
		return
	}
	// Reset the deadline: the per-request path manages its own timeouts, and a
	// long-lived SSE stream must not be killed by the handshake deadline.
	_ = tlsConn.SetDeadline(time.Time{})

	p.serveDecrypted(tlsConn, proxy, idle)
}

// serveDecrypted runs an HTTP server over the single decrypted MITM connection,
// dispatching each request through the capability Proxy (an http.Handler). It
// blocks until the connection closes (keep-alive drained).
func (p *ForwardProxy) serveDecrypted(conn net.Conn, proxy *Proxy, idle time.Duration) {
	done := make(chan struct{})
	listener := newSingleConnListener(&notifyConn{Conn: conn, done: done})
	server := &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: forwardProxyMITMReadHeaderTimeout,
		IdleTimeout:       idle,
	}
	go func() { _ = server.Serve(listener) }()
	<-done
	_ = listener.Close()
	_ = server.Close()
}

func (p *ForwardProxy) portAllowed(port int) bool {
	p.init()
	return p.allowPorts[port]
}

func (p *ForwardProxy) logf(format string, args ...any) {
	logger := p.Logger
	if logger == nil {
		logger = log.Default()
	}
	logger.Printf(format, args...)
}

func (p *ForwardProxy) allowed(target connectTarget) bool {
	p.init()
	return (p.Config.AllowUnmatchedHosts || p.allowHosts[target.host]) && p.allowPorts[target.port]
}

func (p *ForwardProxy) acquireTunnel() (func(), bool) {
	p.init()
	select {
	case p.tunnelSlots <- struct{}{}:
		return func() { <-p.tunnelSlots }, true
	default:
		return nil, false
	}
}

func (p *ForwardProxy) init() {
	p.once.Do(func() {
		p.allowHosts = map[string]bool{}
		for _, host := range p.Config.AllowHosts {
			normalized, err := normalizeProxyHost(host)
			if err != nil {
				p.writeInvalidAllowHost(host)
				continue
			}
			p.allowHosts[normalized] = true
		}
		p.allowPorts = map[int]bool{}
		for _, port := range p.Config.effectiveAllowPorts() {
			p.allowPorts[port] = true
		}
		p.tunnelSlots = make(chan struct{}, p.Config.effectiveMaxConcurrentTunnels())
		p.injectProxies = map[string][]injectProxy{}
		p.destinationPolicy, _ = newDestinationPolicy(p.Config.DenyCIDRs)
		for _, route := range p.Config.InjectRoutes {
			host, err := normalizeProxyHost(route.Host)
			if err != nil {
				p.writeInvalidAllowHost(route.Host)
				continue
			}
			p.injectProxies[host] = append(p.injectProxies[host], injectProxy{
				capability:            route.Capability,
				requireCapabilityHint: route.RequireCapabilityHint,
				proxy: &Proxy{
					Route: Route{
						Capability:            route.Capability,
						Upstream:              route.Upstream,
						AllowInsecureUpstream: route.AllowInsecureUpstream,
						MaxRequests:           route.MaxRequests,
					},
					Broker:             p.Broker,
					Transport:          p.Transport,
					Reporter:           p.Reporter,
					UpgradeIdleTimeout: p.Config.effectiveTunnelIdleTimeout(),
				},
			})
		}
	})
}

func (p *ForwardProxy) injectProxy(host, capabilityHint string) (*Proxy, bool, error) {
	p.init()
	routes := p.injectProxies[host]
	if len(routes) == 0 {
		return nil, false, nil
	}
	if capabilityHint != "" {
		for _, route := range routes {
			if route.capability == capabilityHint {
				return route.proxy, true, nil
			}
		}
		return nil, true, fmt.Errorf("capability %q is not configured for host %s", capabilityHint, host)
	}
	autoRoutes := make([]injectProxy, 0, len(routes))
	for _, route := range routes {
		if !route.requireCapabilityHint {
			autoRoutes = append(autoRoutes, route)
		}
	}
	if len(autoRoutes) == 0 {
		return nil, false, nil
	}
	if len(autoRoutes) == 1 {
		return autoRoutes[0].proxy, true, nil
	}
	return nil, true, fmt.Errorf("host %s has multiple injectable capabilities and requires an explicit capability hint", host)
}

func capabilityHintFromConnect(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get("X-NVT-Capability")); value != "" {
		return value
	}
	value := strings.TrimSpace(r.Header.Get("Proxy-Authorization"))
	if value == "" {
		return ""
	}
	const prefix = "Basic "
	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[len(prefix):]))
	if err != nil {
		return ""
	}
	user, _, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return ""
	}
	return user
}

func (p *ForwardProxy) writeInvalidAllowHost(host string) {
	logger := p.Logger
	if logger == nil {
		logger = log.Default()
	}
	logger.Printf("event=forward_proxy_init allow_host=%q decision=deny error_class=invalid_allow_host", host)
}

func (p *ForwardProxy) dialer() *net.Dialer {
	if p.Dialer != nil {
		return p.Dialer
	}
	return &net.Dialer{Timeout: dialTimeout}
}

func (p *ForwardProxy) resolver() IPResolver {
	if p.Resolver != nil {
		return p.Resolver
	}
	return net.DefaultResolver
}

func (p *ForwardProxy) resolveTarget(ctx context.Context, target connectTarget) (netip.Addr, error) {
	p.init()
	return resolveAllowedAddress(ctx, p.resolver(), p.destinationPolicy, target.host)
}

func (p *ForwardProxy) dial(ctx context.Context, address string) (net.Conn, error) {
	if p.DialContext != nil {
		return p.DialContext(ctx, "tcp", address)
	}
	return p.dialer().DialContext(ctx, "tcp", address)
}

func (p *ForwardProxy) writeDecision(host string, port int, decision, errorClass string) {
	// A resolved target is audit-worthy; targetless denials (malformed/plain
	// HTTP) have no host and are logged only. The broker requires a host.
	if host != "" {
		p.Reporter.Enqueue(ReportEntry{
			Capability: forwardProxyCapability,
			Host:       host,
			Port:       port,
			Decision:   decision,
		})
	}
	logger := p.Logger
	if logger == nil {
		logger = log.Default()
	}
	if errorClass != "" {
		logger.Printf("event=connect target_host=%s target_port=%d decision=%s error_class=%s", host, port, decision, errorClass)
		return
	}
	logger.Printf("event=connect target_host=%s target_port=%d decision=%s", host, port, decision)
}

type connectTarget struct {
	host string
	port int
}

func parseConnectTarget(value string) (connectTarget, error) {
	if strings.Contains(value, "://") || strings.ContainsAny(value, "/\\@?# \t\r\n") || strings.Contains(value, "%") {
		return connectTarget{}, fmt.Errorf("target must be host:port")
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return connectTarget{}, fmt.Errorf("target must be host:port")
	}
	host, err = normalizeProxyHost(host)
	if err != nil {
		return connectTarget{}, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return connectTarget{}, fmt.Errorf("invalid port")
	}
	return connectTarget{host: host, port: port}, nil
}

func connectTargetFromRequest(r *http.Request) (connectTarget, error) {
	target, err := parseConnectTarget(r.URL.Host)
	if err != nil {
		return connectTarget{}, err
	}
	if r.Host != "" {
		hostHeader, err := parseConnectTarget(r.Host)
		if err != nil {
			return connectTarget{}, err
		}
		if hostHeader != target {
			return connectTarget{}, fmt.Errorf("host header does not match CONNECT target")
		}
	}
	return target, nil
}

func normalizeProxyHost(host string) (string, error) {
	if host == "" {
		return "", fmt.Errorf("empty host")
	}
	if strings.HasPrefix(host, "[") || strings.HasSuffix(host, "]") {
		return "", fmt.Errorf("bracketed host is not allowed in allowlist")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Unmap().String(), nil
	}
	if strings.ContainsAny(host, "/\\@?#: \t\r\n") || strings.Contains(host, "%") {
		return "", fmt.Errorf("invalid host")
	}
	if strings.HasSuffix(host, ".") {
		return "", fmt.Errorf("trailing dot host is not allowed")
	}
	lower := strings.ToLower(host)
	for _, r := range lower {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			continue
		}
		return "", fmt.Errorf("host must be ascii DNS name or IPv4 literal")
	}
	return lower, nil
}

func tunnel(client net.Conn, buffered *bufio.ReadWriter, upstream net.Conn, idleTimeout time.Duration) {
	setTunnelDeadline(idleTimeout, client, upstream)
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, tunnelActivityReader{
			reader:      buffered,
			idleTimeout: idleTimeout,
			conns:       []net.Conn{client, upstream},
		})
		_ = closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, tunnelActivityReader{
			reader:      upstream,
			idleTimeout: idleTimeout,
			conns:       []net.Conn{client, upstream},
		})
		_ = closeWrite(client)
		done <- struct{}{}
	}()
	<-done
	<-done
}

type tunnelActivityReader struct {
	reader      io.Reader
	idleTimeout time.Duration
	conns       []net.Conn
}

func (r tunnelActivityReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		setTunnelDeadline(r.idleTimeout, r.conns...)
	}
	return n, err
}

func setTunnelDeadline(idleTimeout time.Duration, conns ...net.Conn) {
	if idleTimeout <= 0 {
		return
	}
	deadline := time.Now().Add(idleTimeout)
	for _, conn := range conns {
		_ = conn.SetDeadline(deadline)
	}
}

func closeWrite(conn net.Conn) error {
	type closeWriter interface {
		CloseWrite() error
	}
	if writer, ok := conn.(closeWriter); ok {
		return writer.CloseWrite()
	}
	return conn.Close()
}

// mitmConn feeds tls.Server from the hijack's buffered reader (which may hold
// bytes read past the CONNECT line) while writing to the raw client conn.
type mitmConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *mitmConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// notifyConn closes done when the connection is closed, so serveDecrypted can
// wait for the HTTP server to finish with the single MITM connection.
type notifyConn struct {
	net.Conn
	once sync.Once
	done chan struct{}
}

func (c *notifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

// singleConnListener yields exactly one connection to http.Server.Serve, then
// blocks until Close so Serve stays alive to handle keep-alive requests.
type singleConnListener struct {
	mu     sync.Mutex
	conn   net.Conn
	closed chan struct{}
	once   sync.Once
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{conn: conn, closed: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	conn := l.conn
	l.conn = nil
	l.mu.Unlock()
	if conn != nil {
		return conn, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return dummyAddr{} }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "mitm" }
func (dummyAddr) String() string  { return "mitm" }
