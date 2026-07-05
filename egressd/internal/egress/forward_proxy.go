package egress

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	dialTimeout                             = 10 * time.Second
	defaultForwardProxyMaxConcurrentTunnels = 64
	defaultForwardProxyTunnelIdleTimeout    = 60 * time.Second
)

// ForwardProxy is a CONNECT-only blind tunnel. It does not inspect or modify
// TLS, WebSocket frames, headers, cookies, bodies, or credentials.
type ForwardProxy struct {
	Config ForwardProxyConfig
	Dialer *net.Dialer
	Logger *log.Logger

	once        sync.Once
	allowHosts  map[string]bool
	allowPorts  map[int]bool
	tunnelSlots chan struct{}
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

	upstream, err := p.dialer().DialContext(r.Context(), "tcp", net.JoinHostPort(target.host, strconv.Itoa(target.port)))
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

func (p *ForwardProxy) allowed(target connectTarget) bool {
	p.init()
	return p.allowHosts[target.host] && p.allowPorts[target.port]
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
	})
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

func (p *ForwardProxy) writeDecision(host string, port int, decision, errorClass string) {
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
