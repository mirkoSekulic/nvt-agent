package egress

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type staticResolver struct {
	addresses []netip.Addr
	err       error
	calls     int
}

func (r *staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.calls++
	return append([]netip.Addr(nil), r.addresses...), r.err
}

func newForwardProxyServer(t *testing.T, config ForwardProxyConfig, logs *bytes.Buffer) *httptest.Server {
	t.Helper()
	proxy := &ForwardProxy{
		Config:   config,
		Logger:   log.New(logs, "", 0),
		Resolver: &staticResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		},
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
	_, upstreamPort := newEchoTCPServer(t)
	var logs bytes.Buffer
	proxy := newForwardProxyServer(t, ForwardProxyConfig{
		AllowHosts: []string{"fixture.external"},
		AllowPorts: []int{upstreamPort},
	}, &logs)
	target := net.JoinHostPort("fixture.external", strconv.Itoa(upstreamPort))
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
	if got := logs.String(); !strings.Contains(got, "event=connect target_host=fixture.external") ||
		!strings.Contains(got, fmt.Sprintf("target_port=%d", upstreamPort)) ||
		!strings.Contains(got, "decision=allow") {
		t.Fatalf("missing sanitized allow log: %q", got)
	}
}

func TestForwardProxyUsesConnectAuthorityInsteadOfHostHeader(t *testing.T) {
	_, upstreamPort := newEchoTCPServer(t)
	var logs bytes.Buffer
	proxy := newForwardProxyServer(t, ForwardProxyConfig{
		AllowHosts: []string{"fixture.external"},
		AllowPorts: []int{upstreamPort},
	}, &logs)
	conn, status := sendRawProxyRequest(t, proxyAddress(t, proxy), fmt.Sprintf(
		"CONNECT example.com:%d HTTP/1.1\r\nHost: fixture.external:%d\r\n\r\n", upstreamPort, upstreamPort,
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

func TestForwardProxyAllowUnmatchedHostsBlindTunnels(t *testing.T) {
	_, upstreamPort := newEchoTCPServer(t)
	var logs bytes.Buffer
	proxy := newForwardProxyServer(t, ForwardProxyConfig{
		AllowUnmatchedHosts: true,
		AllowPorts:          []int{upstreamPort},
	}, &logs)
	conn, status := sendRawProxyRequest(t, proxyAddress(t, proxy), fmt.Sprintf(
		"CONNECT fixture.external:%d HTTP/1.1\r\nHost: fixture.external:%d\r\n\r\n", upstreamPort, upstreamPort,
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
	if got := logs.String(); !strings.Contains(got, "decision=allow") ||
		!strings.Contains(got, fmt.Sprintf("target_port=%d", upstreamPort)) {
		t.Fatalf("missing blind-tunnel allow log: %q", got)
	}
}

func TestForwardProxyHintRequiredRouteDoesNotCaptureGenericTraffic(t *testing.T) {
	proxy := &ForwardProxy{
		Config: ForwardProxyConfig{
			AllowUnmatchedHosts: true,
			InjectRoutes: []ForwardProxyInjectRoute{{
				Host:                  "github.com",
				Capability:            "github-main-app",
				Upstream:              "github.com:443",
				RequireCapabilityHint: true,
			}},
		},
	}
	if got, found, err := proxy.injectProxy("github.com", ""); err != nil || found || got != nil {
		t.Fatalf("generic traffic to a hint-required route must blind-tunnel, got proxy=%v found=%v err=%v", got, found, err)
	}
	if _, found, err := proxy.injectProxy("github.com", "github-main-app"); err != nil || !found {
		t.Fatalf("explicit capability hint must select the route, found=%v err=%v", found, err)
	}
	if _, found, err := proxy.injectProxy("github.com", "github-other-app"); err == nil || !found {
		t.Fatalf("wrong capability hint must fail closed, found=%v err=%v", found, err)
	}
}

func TestTransparentProviderSelectionHonorsHintRequirements(t *testing.T) {
	proxy := &ForwardProxy{Config: ForwardProxyConfig{TransparentMode: true, InjectRoutes: []ForwardProxyInjectRoute{
		{Host: "api.example", Capability: "one", Upstream: "api.example:443", RequireCapabilityHint: true},
		{Host: "api.example", Capability: "two", Upstream: "api.example:443", RequireCapabilityHint: true},
	}}}
	if selected, found, err := proxy.transparentInjectProxy("api.example", ""); err != nil || found || selected != nil {
		t.Fatalf("hint-only transparent host must blind-tunnel without credentials, found=%v err=%v", found, err)
	}
	if selected, found, err := proxy.transparentInjectProxy("api.example", "two"); err != nil || !found || selected == nil {
		t.Fatalf("explicit transparent hint must select provider: found=%v err=%v", found, err)
	}
	singleRequired := &ForwardProxy{Config: ForwardProxyConfig{TransparentMode: true, InjectRoutes: []ForwardProxyInjectRoute{
		{Host: "required.example", Capability: "one", Upstream: "required.example:443", RequireCapabilityHint: true},
	}}}
	if selected, found, err := singleRequired.transparentInjectProxy("required.example", ""); err != nil || found || selected != nil {
		t.Fatalf("single hint-required route must blind-tunnel without credentials, found=%v err=%v", found, err)
	}
	singleAutomatic := &ForwardProxy{Config: ForwardProxyConfig{TransparentMode: true, InjectRoutes: []ForwardProxyInjectRoute{
		{Host: "automatic.example", Capability: "one", Upstream: "automatic.example:443"},
	}}}
	if selected, found, err := singleAutomatic.transparentInjectProxy("automatic.example", ""); err != nil || !found || selected == nil {
		t.Fatalf("unambiguous automatic route was not selected: found=%v err=%v", found, err)
	}
}

func TestForgedTransparentHeaderCannotSelectHintRequiredRoute(t *testing.T) {
	var logs bytes.Buffer
	proxy := &ForwardProxy{Config: ForwardProxyConfig{
		Listen: "127.0.0.1:0",
		InjectRoutes: []ForwardProxyInjectRoute{{
			Host: "required.example", Capability: "one", Upstream: "required.example:443", RequireCapabilityHint: true,
		}},
	}, Logger: log.New(&logs, "", 0)}
	server := httptest.NewServer(proxy)
	defer server.Close()
	conn, status := sendRawProxyRequest(t, proxyAddress(t, server),
		"CONNECT required.example:443 HTTP/1.1\r\nHost: required.example:443\r\nX-NVT-Transparent: 1\r\n\r\n")
	defer conn.Close()
	if !strings.Contains(status, "403") {
		t.Fatalf("forged marker status = %q, want target denial", status)
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
		AllowHosts: []string{"fixture.external"},
		AllowPorts: []int{upstreamPort},
	}, &logs)
	conn, status := sendRawProxyRequest(t, proxyAddress(t, proxy), fmt.Sprintf(
		"CONNECT fixture.external:%d HTTP/1.1\r\nHost: fixture.external:%d\r\n\r\n", upstreamPort, upstreamPort,
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

func TestForwardProxyConcurrentTunnelLimitWaitsThenFailsClosed(t *testing.T) {
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
		AllowHosts:           []string{"fixture.external"},
		AllowPorts:           []int{upstreamPort},
		MaxConcurrentTunnels: 1,
	}, &logs)
	proxy.Config.Handler.(*ForwardProxy).TunnelQueueTimeout = 50 * time.Millisecond
	first, status := sendRawProxyRequest(t, proxyAddress(t, proxy), fmt.Sprintf(
		"CONNECT fixture.external:%d HTTP/1.1\r\nHost: fixture.external:%d\r\n\r\n", upstreamPort, upstreamPort,
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
		"CONNECT fixture.external:%d HTTP/1.1\r\nHost: fixture.external:%d\r\nProxy-Authorization: Bearer %s\r\n\r\n",
		upstreamPort, upstreamPort, canary,
	))
	defer func() { _ = second.Close() }()
	if !strings.Contains(status, "503") {
		t.Fatalf("second CONNECT status = %q", status)
	}
	got := logs.String()
	if !strings.Contains(got, "outcome=queued active=1 queued=1") ||
		!strings.Contains(got, "outcome=timed_out active=1 queued=0 admitted=1 timed_out=1 rejected=1") ||
		!strings.Contains(got, "decision=deny error_class=tunnel_queue_timeout") {
		t.Fatalf("missing tunnel limit denial log: %q", got)
	}
	if strings.Contains(got, canary) || strings.Contains(strings.ToLower(got), "authorization") {
		t.Fatalf("tunnel limit log contains sensitive input: %q", got)
	}
}

func TestForwardProxyTunnelQueueAdmitsAfterRelease(t *testing.T) {
	var logs bytes.Buffer
	proxy := &ForwardProxy{
		Config:             ForwardProxyConfig{MaxConcurrentTunnels: 1},
		TunnelQueueTimeout: time.Second,
		Logger:             log.New(&logs, "", 0),
	}
	first, errorClass := proxy.acquireTunnel(context.Background())
	if first == nil || errorClass != "" {
		t.Fatalf("first acquire = (%v, %q)", first != nil, errorClass)
	}
	type result struct {
		release    func()
		errorClass string
	}
	resultCh := make(chan result, 1)
	go func() {
		release, class := proxy.acquireTunnel(context.Background())
		resultCh <- result{release: release, errorClass: class}
	}()
	waitForAtomicValue(t, &proxy.queuedTunnels, 1)
	first()
	select {
	case got := <-resultCh:
		if got.release == nil || got.errorClass != "" {
			t.Fatalf("queued acquire = (%v, %q)", got.release != nil, got.errorClass)
		}
		got.release()
	case <-time.After(time.Second):
		t.Fatal("queued tunnel was not admitted after release")
	}
	if got := logs.String(); !strings.Contains(got, "outcome=admitted_after_wait") {
		t.Fatalf("missing queued admission telemetry: %q", got)
	}
}

func TestForwardProxyTunnelQueueCancellationAndBound(t *testing.T) {
	var logs bytes.Buffer
	proxy := &ForwardProxy{
		Config:             ForwardProxyConfig{MaxConcurrentTunnels: 1},
		TunnelQueueTimeout: time.Second,
		Logger:             log.New(&logs, "", 0),
	}
	first, _ := proxy.acquireTunnel(context.Background())
	defer first()

	ctx, cancel := context.WithCancel(context.Background())
	cancelled := make(chan string, 1)
	go func() {
		_, class := proxy.acquireTunnel(ctx)
		cancelled <- class
	}()
	waitForAtomicValue(t, &proxy.queuedTunnels, 1)
	if release, class := proxy.acquireTunnel(context.Background()); release != nil || class != "tunnel_queue_full" {
		t.Fatalf("full queue acquire = (%v, %q)", release != nil, class)
	}
	cancel()
	select {
	case class := <-cancelled:
		if class != "tunnel_queue_cancelled" {
			t.Fatalf("cancelled acquire class = %q", class)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled queue wait did not return")
	}
	if proxy.queuedTunnels.Load() != 0 || len(proxy.tunnelQueueSlots) != 0 {
		t.Fatalf("cancelled wait leaked queue state: count=%d slots=%d", proxy.queuedTunnels.Load(), len(proxy.tunnelQueueSlots))
	}
	got := logs.String()
	if !strings.Contains(got, "outcome=queue_full") || !strings.Contains(got, "outcome=cancelled") {
		t.Fatalf("missing bounded/cancelled telemetry: %q", got)
	}
}

func waitForAtomicValue(t *testing.T, value *atomic.Int64, want int64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if value.Load() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("atomic value = %d, want %d", value.Load(), want)
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

func TestForwardProxyInitLogsInvalidAllowHostAndFailsClosed(t *testing.T) {
	var logs bytes.Buffer
	proxy := &ForwardProxy{
		Config: ForwardProxyConfig{
			AllowHosts: []string{"chatgpt.com", "bad\nhost"},
		},
		Logger: log.New(&logs, "", 0),
	}

	proxy.init()

	if !proxy.allowHosts["chatgpt.com"] {
		t.Fatalf("valid allow host was not initialized: %#v", proxy.allowHosts)
	}
	if proxy.allowHosts["bad\nhost"] {
		t.Fatalf("invalid allow host was initialized: %#v", proxy.allowHosts)
	}
	got := logs.String()
	if !strings.Contains(got, `event=forward_proxy_init allow_host="bad\nhost" decision=deny error_class=invalid_allow_host`) {
		t.Fatalf("missing invalid allow host diagnostic: %q", got)
	}
	if strings.Contains(got, "\nbad") {
		t.Fatalf("invalid allow host log was not escaped: %q", got)
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

func TestForwardProxyDefaultAllowPortsSupportHTTPAndHTTPS(t *testing.T) {
	config := &ForwardProxyConfig{Listen: "127.0.0.1:0", AllowHosts: []string{"ChatGPT.com"}}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	if ports := config.effectiveAllowPorts(); len(ports) != 2 || ports[0] != 80 || ports[1] != 443 {
		t.Fatalf("default ports = %v", ports)
	}
	if got := config.effectiveMaxConcurrentTunnels(); got != defaultForwardProxyMaxConcurrentTunnels {
		t.Fatalf("default max concurrent tunnels = %d", got)
	}
	if got := defaultForwardProxyMaxConcurrentTunnels; got != 256 {
		t.Fatalf("package-manager tunnel default = %d, want 256", got)
	}
	if got := config.effectiveTunnelIdleTimeout(); got != defaultForwardProxyTunnelIdleTimeout {
		t.Fatalf("default tunnel idle timeout = %s", got)
	}
}

func TestForwardProxyConfiguredTunnelCapacityIsBounded(t *testing.T) {
	config := &ForwardProxyConfig{Listen: "127.0.0.1:0", MaxConcurrentTunnels: 512}
	if err := config.Validate(); err != nil {
		t.Fatalf("configured capacity rejected: %v", err)
	}
	if got := config.effectiveMaxConcurrentTunnels(); got != 512 {
		t.Fatalf("configured max concurrent tunnels = %d", got)
	}
	config.MaxConcurrentTunnels = maxForwardProxyConcurrentTunnels + 1
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "between 1 and 4096") {
		t.Fatalf("excessive capacity must fail closed, got %v", err)
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
