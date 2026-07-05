package egress

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newForwardProxyServer(t *testing.T, config ForwardProxyConfig, logs *bytes.Buffer) *httptest.Server {
	t.Helper()
	proxy := &ForwardProxy{
		Config: config,
		Logger: log.New(logs, "", 0),
	}
	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)
	return server
}

func newEchoTCPServer(t *testing.T) (address string, port int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return
		}
		_, _ = io.WriteString(conn, "echo:"+line)
	}()
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err = strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return listener.Addr().String(), port
}

func proxyAddress(t *testing.T, server *httptest.Server) string {
	t.Helper()
	address := strings.TrimPrefix(server.URL, "http://")
	if strings.Contains(address, "://") {
		t.Fatalf("unexpected httptest URL %q", server.URL)
	}
	return address
}

func sendRawProxyRequest(t *testing.T, proxy, request string) (net.Conn, string) {
	t.Helper()
	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, request); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	return conn, status
}

func TestForwardProxyAllowedConnectEstablishesBlindTunnel(t *testing.T) {
	upstreamAddress, upstreamPort := newEchoTCPServer(t)
	var logs bytes.Buffer
	proxy := newForwardProxyServer(t, ForwardProxyConfig{
		AllowHosts: []string{"127.0.0.1"},
		AllowPorts: []int{upstreamPort},
	}, &logs)
	target := upstreamAddress
	conn, status := sendRawProxyRequest(t, proxyAddress(t, proxy), fmt.Sprintf(
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target,
	))
	defer func() { _ = conn.Close() }()
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT status = %q", status)
	}
	if _, err := io.WriteString(conn, "ping\n"); err != nil {
		t.Fatal(err)
	}
	response, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if response != "echo:ping\n" {
		t.Fatalf("tunnel response = %q", response)
	}
	if got := logs.String(); !strings.Contains(got, "event=connect target_host=127.0.0.1") ||
		!strings.Contains(got, fmt.Sprintf("target_port=%d", upstreamPort)) ||
		!strings.Contains(got, "decision=allow") {
		t.Fatalf("missing sanitized allow log: %q", got)
	}
}

func TestForwardProxyUsesConnectAuthorityInsteadOfHostHeader(t *testing.T) {
	upstreamAddress, upstreamPort := newEchoTCPServer(t)
	var logs bytes.Buffer
	proxy := newForwardProxyServer(t, ForwardProxyConfig{
		AllowHosts: []string{"127.0.0.1"},
		AllowPorts: []int{upstreamPort},
	}, &logs)
	conn, status := sendRawProxyRequest(t, proxyAddress(t, proxy), fmt.Sprintf(
		"CONNECT example.com:%d HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamPort, upstreamAddress,
	))
	defer func() { _ = conn.Close() }()
	if !strings.Contains(status, "403") {
		t.Fatalf("CONNECT status = %q", status)
	}
	if got := logs.String(); !strings.Contains(got, "event=connect target_host=example.com") ||
		!strings.Contains(got, "decision=deny error_class=target_not_allowed") {
		t.Fatalf("CONNECT authority was not used for allow decision: %q", got)
	}
}

func TestConnectTargetFromRequestRejectsHostHeaderMismatch(t *testing.T) {
	request, err := http.NewRequest(http.MethodConnect, "http://chatgpt.com:443", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.URL.Scheme = ""
	request.Host = "api.openai.com:443"
	if _, err := connectTargetFromRequest(request); err == nil {
		t.Fatal("Host header mismatch must be rejected")
	}
}

func TestForwardProxyDeniedConnectFailsClosed(t *testing.T) {
	var logs bytes.Buffer
	proxy := newForwardProxyServer(t, ForwardProxyConfig{
		AllowHosts: []string{"chatgpt.com"},
	}, &logs)
	conn, status := sendRawProxyRequest(t, proxyAddress(t, proxy),
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	defer func() { _ = conn.Close() }()
	if !strings.Contains(status, "403") {
		t.Fatalf("CONNECT status = %q", status)
	}
	if got := logs.String(); !strings.Contains(got, "event=connect target_host=example.com target_port=443 decision=deny error_class=target_not_allowed") {
		t.Fatalf("missing sanitized deny log: %q", got)
	}
}

func TestForwardProxyTunnelWaitsForHalfClosedClientResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		body, err := io.ReadAll(conn)
		if err != nil || string(body) != "request-body" {
			return
		}
		_, _ = io.WriteString(conn, "upstream-response")
	}()
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	upstreamPort, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	proxy := newForwardProxyServer(t, ForwardProxyConfig{
		AllowHosts: []string{"127.0.0.1"},
		AllowPorts: []int{upstreamPort},
	}, &logs)
	conn, status := sendRawProxyRequest(t, proxyAddress(t, proxy), fmt.Sprintf(
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", listener.Addr().String(), listener.Addr().String(),
	))
	defer func() { _ = conn.Close() }()
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT status = %q", status)
	}
	if _, err := io.WriteString(conn, "request-body"); err != nil {
		t.Fatal(err)
	}
	type closeWriter interface {
		CloseWrite() error
	}
	writer, ok := conn.(closeWriter)
	if !ok {
		t.Fatalf("client connection does not support CloseWrite")
	}
	if err := writer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "upstream-response" {
		t.Fatalf("tunnel response after half-close = %q", response)
	}
}

func TestForwardProxyTunnelIdleTimeoutCleansUpStalledPeers(t *testing.T) {
	clientPeer, client := net.Pipe()
	upstream, upstreamPeer := net.Pipe()
	defer func() { _ = clientPeer.Close() }()
	defer func() { _ = upstreamPeer.Close() }()

	done := make(chan struct{})
	go func() {
		tunnel(client, bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client)), upstream, 50*time.Millisecond)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stalled tunnel did not clean up after idle timeout")
	}
}

func TestForwardProxyConcurrentTunnelLimitFailsClosed(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	upstreamAccepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		upstreamAccepted <- conn
	}()
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	upstreamPort, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	proxy := newForwardProxyServer(t, ForwardProxyConfig{
		AllowHosts:           []string{"127.0.0.1"},
		AllowPorts:           []int{upstreamPort},
		MaxConcurrentTunnels: 1,
	}, &logs)
	first, status := sendRawProxyRequest(t, proxyAddress(t, proxy), fmt.Sprintf(
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", listener.Addr().String(), listener.Addr().String(),
	))
	defer func() { _ = first.Close() }()
	if !strings.Contains(status, "200") {
		t.Fatalf("first CONNECT status = %q", status)
	}
	var upstreamConn net.Conn
	select {
	case upstreamConn = <-upstreamAccepted:
	case <-time.After(time.Second):
		t.Fatal("upstream did not accept first tunnel")
	}
	defer func() { _ = upstreamConn.Close() }()

	const canary = "CANARY-SECOND-TUNNEL-SECRET"
	second, status := sendRawProxyRequest(t, proxyAddress(t, proxy), fmt.Sprintf(
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Bearer %s\r\n\r\n",
		listener.Addr().String(), listener.Addr().String(), canary,
	))
	defer func() { _ = second.Close() }()
	if !strings.Contains(status, "503") {
		t.Fatalf("second CONNECT status = %q", status)
	}
	got := logs.String()
	if !strings.Contains(got, "decision=deny error_class=tunnel_limit_exceeded") {
		t.Fatalf("missing tunnel limit denial log: %q", got)
	}
	if strings.Contains(got, canary) || strings.Contains(strings.ToLower(got), "authorization") {
		t.Fatalf("tunnel limit log contains sensitive input: %q", got)
	}
}

func TestForwardProxyMalformedConnectTargetsRejected(t *testing.T) {
	malformed := []string{
		"chatgpt.com",
		"https://chatgpt.com:443",
		"user@chatgpt.com:443",
		"chatgpt.com:bad",
		"chatgpt.com:0",
		"chatgpt.com:443/path",
		"chatgpt.com.:443",
		"[::1]:443",
	}
	for _, target := range malformed {
		t.Run(target, func(t *testing.T) {
			if _, err := parseConnectTarget(target); err == nil {
				t.Fatalf("target %q should be rejected", target)
			}
		})
	}
}

func TestForwardProxyRuntimeMalformedConnectRejected(t *testing.T) {
	var logs bytes.Buffer
	proxy := newForwardProxyServer(t, ForwardProxyConfig{
		AllowHosts: []string{"chatgpt.com"},
	}, &logs)
	conn, status := sendRawProxyRequest(t, proxyAddress(t, proxy),
		"CONNECT chatgpt.com HTTP/1.1\r\nHost: chatgpt.com\r\n\r\n")
	defer func() { _ = conn.Close() }()
	if !strings.Contains(status, "400") {
		t.Fatalf("CONNECT status = %q", status)
	}
	if got := logs.String(); !strings.Contains(got, "decision=deny error_class=malformed_target") {
		t.Fatalf("missing malformed log: %q", got)
	}
}

func TestForwardProxyLogsAreSanitized(t *testing.T) {
	const canary = "CANARY-SECRET-AUTHORIZATION-COOKIE-TOKEN"
	var logs bytes.Buffer
	proxy := newForwardProxyServer(t, ForwardProxyConfig{
		AllowHosts: []string{"chatgpt.com"},
	}, &logs)
	conn, status := sendRawProxyRequest(t, proxyAddress(t, proxy), ""+
		"CONNECT example.com:443 HTTP/1.1\r\n"+
		"Host: example.com:443\r\n"+
		"Proxy-Authorization: Bearer "+canary+"\r\n"+
		"Cookie: session="+canary+"\r\n"+
		"\r\n")
	defer func() { _ = conn.Close() }()
	if !strings.Contains(status, "403") {
		t.Fatalf("CONNECT status = %q", status)
	}
	if got := logs.String(); strings.Contains(got, canary) ||
		strings.Contains(strings.ToLower(got), "authorization") ||
		strings.Contains(strings.ToLower(got), "cookie") {
		t.Fatalf("logs contain sensitive input: %q", got)
	}
}

func TestForwardProxyRejectsPlainHTTPProxying(t *testing.T) {
	var logs bytes.Buffer
	proxy := newForwardProxyServer(t, ForwardProxyConfig{
		AllowHosts: []string{"chatgpt.com"},
	}, &logs)
	request, err := http.NewRequest(http.MethodGet, proxy.URL+"/https://chatgpt.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Proxy-Authorization", "Bearer should-not-log")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("plain HTTP proxying status = %d", response.StatusCode)
	}
	if got := logs.String(); !strings.Contains(got, "event=connect target_host= target_port=0 decision=deny error_class=plain_http_not_supported") ||
		strings.Contains(got, "should-not-log") {
		t.Fatalf("unexpected log for plain HTTP rejection: %q", got)
	}
}

func TestForwardProxyDefaultAllowPortIs443(t *testing.T) {
	config := &ForwardProxyConfig{Listen: "127.0.0.1:0", AllowHosts: []string{"ChatGPT.com"}}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	if ports := config.effectiveAllowPorts(); len(ports) != 1 || ports[0] != 443 {
		t.Fatalf("default ports = %v", ports)
	}
	if got := config.effectiveMaxConcurrentTunnels(); got != defaultForwardProxyMaxConcurrentTunnels {
		t.Fatalf("default max concurrent tunnels = %d", got)
	}
	if got := config.effectiveTunnelIdleTimeout(); got != defaultForwardProxyTunnelIdleTimeout {
		t.Fatalf("default tunnel idle timeout = %s", got)
	}
}

func TestConfigRejectsForwardProxyAllowHostOverlappingMediatedRoute(t *testing.T) {
	config := &Config{
		BrokerURL: "https://broker:7347",
		Routes: []Route{{
			Listen:     "127.0.0.1:8470",
			Capability: "codex-main",
			Upstream:   "ChatGPT.com:443",
		}},
		ForwardProxy: &ForwardProxyConfig{
			Listen:     "127.0.0.1:8471",
			AllowHosts: []string{"chatgpt.com"},
		},
	}
	if err := config.Validate(); err == nil {
		t.Fatal("forward proxy allowlist overlap with mediated route upstream must be rejected")
	}

	config.ForwardProxy.AllowHosts = []string{"api.openai.com"}
	if err := config.Validate(); err != nil {
		t.Fatalf("non-overlapping forward proxy host should validate: %v", err)
	}
}
