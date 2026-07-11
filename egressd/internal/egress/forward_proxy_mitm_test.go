package egress

// Phase 6.2 forward-proxy TLS-MITM: egressd terminates CONNECT under the
// per-agent CA, injects the broker credential into the decrypted request, and
// re-originates to the pinned upstream. The agent never holds the credential;
// the upstream never sees the placeholder; SNI/upstream are pinned.

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type trackingClientSessionCache struct {
	cache tls.ClientSessionCache
	puts  int
	gets  int
}

func (c *trackingClientSessionCache) Put(key string, state *tls.ClientSessionState) {
	c.puts++
	c.cache.Put(key, state)
}

func (c *trackingClientSessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	c.gets++
	return c.cache.Get(key)
}

func newMITMProxy(t *testing.T, broker *fakeBroker, route ForwardProxyInjectRoute, upstreamNames ...string) (*httptest.Server, *CA) {
	t.Helper()
	ca, err := NewCAWithUpstreams(nil, upstreamNames)
	if err != nil {
		t.Fatal(err)
	}
	fp := &ForwardProxy{
		Config: ForwardProxyConfig{
			Listen:       "unused",
			InjectRoutes: []ForwardProxyInjectRoute{route},
		},
		CA:        ca,
		Broker:    &BrokerClient{URL: broker.server.URL, Token: "egress-role-token", Client: broker.server.Client()},
		Transport: http.DefaultTransport,
		Resolver:  &staticResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}},
	}
	server := httptest.NewServer(fp)
	t.Cleanup(server.Close)
	return server, ca
}

// mitmDial performs the CONNECT handshake and returns a TLS client conn over
// the tunnel, validating the minted leaf against the given SNI.
func mitmDial(t *testing.T, proxy *httptest.Server, ca *CA, connectHost, sni string) *tls.Conn {
	t.Helper()
	return mitmDialWithCapability(t, proxy, ca, connectHost, sni, "")
}

func mitmDialWithCapability(t *testing.T, proxy *httptest.Server, ca *CA, connectHost, sni, capability string) *tls.Conn {
	t.Helper()
	extra := ""
	if capability != "" {
		token := base64.StdEncoding.EncodeToString([]byte(capability + ":"))
		extra = "Proxy-Authorization: Basic " + token + "\r\n"
	}
	conn, status := sendRawProxyRequest(t, proxyAddress(t, proxy), fmt.Sprintf(
		"CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n%s\r\n", connectHost, connectHost, extra))
	if !strings.Contains(status, "200") {
		_ = conn.Close()
		t.Fatalf("CONNECT status = %q", status)
	}
	tlsConn := tls.Client(conn, &tls.Config{RootCAs: caCertPool(t, ca), ServerName: sni})
	t.Cleanup(func() { _ = tlsConn.Close() })
	return tlsConn
}

func mitmRequest(t *testing.T, tlsConn *tls.Conn, path string) *http.Response {
	t.Helper()
	fmt.Fprintf(tlsConn, "GET %s HTTP/1.1\r\nHost: chatgpt.com\r\nAuthorization: Bearer %s\r\nConnection: close\r\n\r\n", path, Placeholder)
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read MITM response: %v", err)
	}
	return resp
}

func TestForwardProxyMITMInjectsRealToken(t *testing.T) {
	broker := newFakeBroker(t)
	upstream := newFakeUpstream(t)
	proxy, ca := newMITMProxy(t, broker, ForwardProxyInjectRoute{
		Host: "chatgpt.com", Capability: "codex-main",
		Upstream: proxyAddress(t, upstream.server), AllowInsecureUpstream: true,
	}, "chatgpt.com")

	tlsConn := mitmDial(t, proxy, ca, "chatgpt.com", "chatgpt.com")
	resp := mitmRequest(t, tlsConn, "/v1/responses?stream=true")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("MITM request status = %d", resp.StatusCode)
	}
	record := upstream.last(t)
	if len(record.authorization) != 1 || record.authorization[0] != "Bearer "+realToken {
		t.Fatalf("upstream Authorization = %v, want the injected real token", record.authorization)
	}
	if strings.Contains(fmt.Sprint(record.header), Placeholder) {
		t.Fatal("placeholder reached the upstream")
	}
	if record.path != "/v1/responses?stream=true" {
		t.Fatalf("upstream path = %q, want the preserved request path", record.path)
	}
}

// TestForwardProxyMITMRemintsExpiredLeafOnNextCONNECT exercises the real
// production CONNECT -> TLS termination path with one shared TLS 1.3 client
// config and a populated session cache. The second handshake must resume while
// the leaf is still fresh; once the leaf enters the remint window, the next
// handshake must observe a new certificate and ticket key.
func TestForwardProxyMITMRemintsExpiredLeafOnNextCONNECT(t *testing.T) {
	const host = "chatgpt.com"
	broker := newFakeBroker(t)
	upstream := newFakeUpstream(t)
	proxy, ca := newMITMProxy(t, broker, ForwardProxyInjectRoute{
		Host: host, Capability: "codex-main",
		Upstream: proxyAddress(t, upstream.server), AllowInsecureUpstream: true,
	}, host)
	clock := time.Now().UTC().Truncate(time.Second)
	ca.Now = func() time.Time { return clock }
	sessions := &trackingClientSessionCache{cache: tls.NewLRUClientSessionCache(1)}
	clientConfig := &tls.Config{
		RootCAs:            caCertPool(t, ca),
		ServerName:         host,
		Time:               func() time.Time { return clock },
		ClientSessionCache: sessions,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}
	dial := func() *tls.Conn {
		t.Helper()
		conn, status := sendRawProxyRequest(t, proxyAddress(t, proxy),
			"CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\n\r\n")
		if !strings.Contains(status, "200") {
			_ = conn.Close()
			t.Fatalf("CONNECT status = %q", status)
		}
		tlsConn := tls.Client(conn, clientConfig)
		if err := tlsConn.Handshake(); err != nil {
			t.Fatalf("MITM handshake: %v", err)
		}
		return tlsConn
	}

	first := dial()
	firstState := first.ConnectionState()
	if firstState.DidResume {
		t.Fatal("first MITM handshake unexpectedly resumed")
	}
	oldLeaf := firstState.PeerCertificates[0]
	response := mitmRequest(t, first, "/first")
	_ = response.Body.Close()
	_ = first.Close()
	if sessions.puts == 0 {
		t.Fatal("first handshake did not populate the client session cache")
	}

	clock = oldLeaf.NotAfter.Add(-leafRemintMargin - time.Minute)
	second := dial()
	defer second.Close()
	secondState := second.ConnectionState()
	if !secondState.DidResume {
		t.Fatal("second CONNECT did not resume before the remint boundary")
	}
	if sessions.gets == 0 {
		t.Fatal("second handshake did not consult the populated client session cache")
	}
	newLeaf := secondState.PeerCertificates[0]
	if newLeaf.SerialNumber.Cmp(oldLeaf.SerialNumber) != 0 {
		t.Fatalf("second CONNECT leaf serial changed too early: old=%s new=%s", oldLeaf.SerialNumber, newLeaf.SerialNumber)
	}
	if !newLeaf.NotAfter.Equal(oldLeaf.NotAfter) {
		t.Fatalf("second CONNECT leaf expiry changed before remint boundary: old=%s new=%s", oldLeaf.NotAfter, newLeaf.NotAfter)
	}
	response = mitmRequest(t, second, "/second")
	_ = response.Body.Close()
}

// TestForwardProxyMITMRemintsAcrossMultipleExpiryCycles exercises the real
// CONNECT -> TLS termination path across two renewal boundaries. The shared
// client config resumes before each renewal boundary, then receives a fresh
// certificate with a later expiry once the current leaf crosses the margin.
func TestForwardProxyMITMRemintsAcrossMultipleExpiryCycles(t *testing.T) {
	const host = "chatgpt.com"
	broker := newFakeBroker(t)
	upstream := newFakeUpstream(t)
	proxy, ca := newMITMProxy(t, broker, ForwardProxyInjectRoute{
		Host: host, Capability: "codex-main",
		Upstream: proxyAddress(t, upstream.server), AllowInsecureUpstream: true,
	}, host)
	clock := time.Now().UTC().Truncate(time.Second)
	ca.Now = func() time.Time { return clock }

	sessions := &trackingClientSessionCache{cache: tls.NewLRUClientSessionCache(1)}
	clientConfig := &tls.Config{
		RootCAs:            caCertPool(t, ca),
		ServerName:         host,
		Time:               func() time.Time { return clock },
		ClientSessionCache: sessions,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}
	type result struct {
		serial  string
		expiry  time.Time
		resumed bool
	}
	handshake := func(path string) result {
		t.Helper()
		conn, status := sendRawProxyRequest(t, proxyAddress(t, proxy),
			"CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\n\r\n")
		if !strings.Contains(status, "200") {
			_ = conn.Close()
			t.Fatalf("CONNECT status = %q", status)
		}
		tlsConn := tls.Client(conn, clientConfig)
		if err := tlsConn.Handshake(); err != nil {
			t.Fatalf("MITM handshake: %v", err)
		}
		resp := mitmRequest(t, tlsConn, path)
		_ = resp.Body.Close()
		state := tlsConn.ConnectionState()
		leaf := state.PeerCertificates[0]
		resumed := state.DidResume
		_ = tlsConn.Close()
		return result{serial: leaf.SerialNumber.String(), expiry: leaf.NotAfter.UTC(), resumed: resumed}
	}

	first := handshake("/first")
	if first.resumed {
		t.Fatal("first MITM handshake unexpectedly resumed")
	}
	clock = first.expiry.Add(-leafRemintMargin - time.Minute)
	reused := handshake("/reused")
	if !reused.resumed {
		t.Fatal("second MITM handshake did not resume before the remint boundary")
	}
	if reused.serial != first.serial {
		t.Fatalf("leaf changed before remint margin: first=%s reused=%s", first.serial, reused.serial)
	}

	clock = first.expiry.Add(-leafRemintMargin + time.Minute)
	second := handshake("/renewed")
	if second.resumed {
		t.Fatal("handshake inside the remint window unexpectedly resumed")
	}
	if second.serial == first.serial {
		t.Fatalf("leaf was not renewed in remint margin: serial=%s", second.serial)
	}
	if !second.expiry.After(first.expiry) {
		t.Fatalf("second leaf expiry %s did not advance beyond first expiry %s", second.expiry, first.expiry)
	}

	clock = second.expiry.Add(-leafRemintMargin - time.Minute)
	third := handshake("/second-reused")
	if !third.resumed {
		t.Fatal("third MITM handshake did not resume before the second remint boundary")
	}
	if third.serial != second.serial {
		t.Fatalf("leaf changed before second remint margin: second=%s third=%s", second.serial, third.serial)
	}

	clock = second.expiry.Add(-leafRemintMargin + time.Minute)
	fourth := handshake("/second-renewed")
	if fourth.resumed {
		t.Fatal("handshake inside the second remint window unexpectedly resumed")
	}
	if fourth.serial == second.serial {
		t.Fatalf("leaf was not renewed on the second remint boundary: serial=%s", fourth.serial)
	}
	if !fourth.expiry.After(second.expiry) {
		t.Fatalf("fourth leaf expiry %s did not advance beyond second expiry %s", fourth.expiry, second.expiry)
	}

	clock = fourth.expiry.Add(-leafRemintMargin - time.Minute)
	fifth := handshake("/third-reused")
	if !fifth.resumed {
		t.Fatal("fifth MITM handshake did not resume before the third remint boundary")
	}
	if fifth.serial != fourth.serial {
		t.Fatalf("leaf changed before third remint margin: fourth=%s fifth=%s", fourth.serial, fifth.serial)
	}

	clock = fourth.expiry.Add(-leafRemintMargin + time.Minute)
	sixth := handshake("/third-renewed")
	if sixth.resumed {
		t.Fatal("handshake inside the third remint window unexpectedly resumed")
	}
	if sixth.serial == fourth.serial {
		t.Fatalf("leaf was not renewed after the second expiry: serial=%s", sixth.serial)
	}
	if !sixth.expiry.After(fourth.expiry) {
		t.Fatalf("sixth leaf expiry %s did not advance beyond fourth expiry %s", sixth.expiry, fourth.expiry)
	}
}

func TestForwardProxyMITMRequiresCapabilityForAmbiguousHost(t *testing.T) {
	broker := newFakeBroker(t)
	upstream := newFakeUpstream(t)
	ca, err := NewCAWithUpstreams(nil, []string{"api.github.com"})
	if err != nil {
		t.Fatal(err)
	}
	fp := &ForwardProxy{
		Config: ForwardProxyConfig{
			Listen: "unused",
			InjectRoutes: []ForwardProxyInjectRoute{
				{Host: "api.github.com", Capability: "github-main-app", Upstream: proxyAddress(t, upstream.server), AllowInsecureUpstream: true},
				{Host: "api.github.com", Capability: "github-altinn-app", Upstream: proxyAddress(t, upstream.server), AllowInsecureUpstream: true},
			},
		},
		CA:        ca,
		Broker:    &BrokerClient{URL: broker.server.URL, Token: "egress-role-token", Client: broker.server.Client()},
		Transport: http.DefaultTransport,
		Resolver:  &staticResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}},
	}
	server := httptest.NewServer(fp)
	t.Cleanup(server.Close)

	conn, status := sendRawProxyRequest(t, proxyAddress(t, server),
		"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n")
	_ = conn.Close()
	if !strings.Contains(status, "403") {
		t.Fatalf("ambiguous CONNECT without capability status = %q, want 403", status)
	}

	tlsConn := mitmDialWithCapability(t, server, ca, "api.github.com", "api.github.com", "github-altinn-app")
	fmt.Fprintf(tlsConn, "GET /repos/Altinn/altinn-studio/pulls/1 HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer %s\r\nConnection: close\r\n\r\n", Placeholder)
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read selected MITM response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("selected MITM request status = %d", resp.StatusCode)
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	if len(broker.requests) != 1 || broker.requests[0]["capability"] != "github-altinn-app" {
		t.Fatalf("broker requests = %#v, want selected github-altinn-app capability", broker.requests)
	}
}

func TestForwardProxyMITMInjectsUpgradeHandshakeAndRelays(t *testing.T) {
	broker := newFakeBroker(t)
	upstream := newFakeUpstream(t)
	upstream.handler = func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+realToken {
			t.Errorf("upgrade upstream Authorization = %q, want injected token", r.Header.Get("Authorization"))
		}
		if strings.Contains(fmt.Sprint(r.Header), Placeholder) {
			t.Error("placeholder reached upgrade upstream")
		}
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			t.Errorf("upgrade header = %q, want websocket", r.Header.Get("Upgrade"))
		}
		if !headerHasToken(r.Header, "Connection", "upgrade") {
			t.Errorf("connection header = %q, want Upgrade token", r.Header.Values("Connection"))
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("upstream response writer cannot hijack")
			return
		}
		conn, buffered, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("upstream hijack: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		if _, err := conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")); err != nil {
			t.Errorf("write upgrade response: %v", err)
			return
		}
		line, err := buffered.ReadString('\n')
		if err != nil {
			t.Errorf("read upgraded client bytes: %v", err)
			return
		}
		if line != "ping\n" {
			t.Errorf("upstream upgraded bytes = %q, want ping", line)
			return
		}
		if _, err := io.WriteString(conn, "pong\n"); err != nil {
			t.Errorf("write upgraded upstream bytes: %v", err)
		}
	}
	proxy, ca := newMITMProxy(t, broker, ForwardProxyInjectRoute{
		Host: "chatgpt.com", Capability: "codex-main",
		Upstream: proxyAddress(t, upstream.server), AllowInsecureUpstream: true,
	}, "chatgpt.com")

	tlsConn := mitmDial(t, proxy, ca, "chatgpt.com", "chatgpt.com")
	reader := bufio.NewReader(tlsConn)
	fmt.Fprintf(tlsConn, "GET /backend-api/codex/responses HTTP/1.1\r\nHost: chatgpt.com\r\nAuthorization: Bearer %s\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: fixture\r\nSec-WebSocket-Version: 13\r\n\r\n", Placeholder)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade response status = %d, want 101", resp.StatusCode)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		t.Fatalf("upgrade response header = %q, want websocket", resp.Header.Get("Upgrade"))
	}
	if !headerHasToken(resp.Header, "Connection", "upgrade") {
		t.Fatalf("upgrade response connection = %q, want Upgrade token", resp.Header.Values("Connection"))
	}
	if _, err := io.WriteString(tlsConn, "ping\n"); err != nil {
		t.Fatalf("write upgraded client bytes: %v", err)
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read upgraded upstream bytes: %v", err)
	}
	if line != "pong\n" {
		t.Fatalf("upgraded relay response = %q, want pong", line)
	}
	record := upstream.last(t)
	if record.path != "/backend-api/codex/responses" {
		t.Fatalf("upstream path = %q, want codex websocket path", record.path)
	}
}

func TestUpgradeRelayIdleTimeoutCleansUpStalledPeers(t *testing.T) {
	client, proxySide := net.Pipe()
	upstream, upstreamPeer := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = upstreamPeer.Close() }()

	done := make(chan struct{})
	go func() {
		relayUpgrade(proxySide, bufio.NewReadWriter(bufio.NewReader(proxySide), bufio.NewWriter(proxySide)), upstream, 20*time.Millisecond)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("idle upgraded relay did not clean up stalled peers")
	}
}

// TestForwardProxyMITMRefusesForgedSNI pins the second gate: a client that
// lies about SNI cannot obtain a leaf for a non-allowlisted name.
func TestForwardProxyMITMRefusesForgedSNI(t *testing.T) {
	broker := newFakeBroker(t)
	upstream := newFakeUpstream(t)
	proxy, ca := newMITMProxy(t, broker, ForwardProxyInjectRoute{
		Host: "chatgpt.com", Capability: "codex-main",
		Upstream: proxyAddress(t, upstream.server), AllowInsecureUpstream: true,
	}, "chatgpt.com")

	tlsConn := mitmDial(t, proxy, ca, "chatgpt.com", "evil.example")
	if err := tlsConn.Handshake(); err == nil {
		t.Fatal("MITM handshake succeeded with a forged non-allowlisted SNI")
	}
}

// TestForwardProxyMITMDeniesNonInjectHost pins fail-closed routing: a CONNECT
// to a host that is neither an inject route nor a blind-tunnel host is denied.
func TestForwardProxyMITMDeniesNonInjectHost(t *testing.T) {
	broker := newFakeBroker(t)
	upstream := newFakeUpstream(t)
	proxy, _ := newMITMProxy(t, broker, ForwardProxyInjectRoute{
		Host: "chatgpt.com", Capability: "codex-main",
		Upstream: proxyAddress(t, upstream.server), AllowInsecureUpstream: true,
	}, "chatgpt.com")

	conn, status := sendRawProxyRequest(t, proxyAddress(t, proxy),
		"CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n")
	defer func() { _ = conn.Close() }()
	if !strings.Contains(status, "403") {
		t.Fatalf("non-inject host CONNECT status = %q, want 403", status)
	}
}

// TestForwardProxyMITMFailsClosedOnBrokerDown pins that a broker outage fails
// the proxied request closed — no placeholder reaches the upstream.
func TestForwardProxyMITMFailsClosedOnBrokerDown(t *testing.T) {
	broker := newFakeBroker(t)
	broker.setFail(true)
	upstream := newFakeUpstream(t)
	proxy, ca := newMITMProxy(t, broker, ForwardProxyInjectRoute{
		Host: "chatgpt.com", Capability: "codex-main",
		Upstream: proxyAddress(t, upstream.server), AllowInsecureUpstream: true,
	}, "chatgpt.com")

	tlsConn := mitmDial(t, proxy, ca, "chatgpt.com", "chatgpt.com")
	resp := mitmRequest(t, tlsConn, "/v1/responses")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("broker-down MITM status = %d, want 502", resp.StatusCode)
	}
	if len(upstream.records) != 0 {
		t.Fatal("a request reached the upstream despite the broker being down")
	}
}

// TestForwardProxyMITMQuota pins that the per-route quota applies to MITM'd
// requests exactly as to redirect routes.
func TestForwardProxyMITMQuota(t *testing.T) {
	broker := newFakeBroker(t)
	upstream := newFakeUpstream(t)
	proxy, ca := newMITMProxy(t, broker, ForwardProxyInjectRoute{
		Host: "chatgpt.com", Capability: "codex-main",
		Upstream: proxyAddress(t, upstream.server), AllowInsecureUpstream: true,
		MaxRequests: 1,
	}, "chatgpt.com")

	first := mitmRequest(t, mitmDial(t, proxy, ca, "chatgpt.com", "chatgpt.com"), "/one")
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first MITM request status = %d, want 200", first.StatusCode)
	}
	second := mitmRequest(t, mitmDial(t, proxy, ca, "chatgpt.com", "chatgpt.com"), "/two")
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second MITM request status = %d, want 429", second.StatusCode)
	}
}

// TestForwardProxyMITMCodexShaped is the fixture-level Codex proof
// (docs/phase6.2-forward-proxy-pr-plan.md 4b): the placeholder-file tool talks
// to both the API host and the refresh host (auth.openai.com) through the
// proxy, and egressd injects the real credential for each — a simulated refresh
// leg included. No real token is ever in the "tool" (it sends the placeholder).
func TestForwardProxyMITMCodexShaped(t *testing.T) {
	broker := newFakeBroker(t)
	api := newFakeUpstream(t)
	refresh := newFakeUpstream(t)
	ca, err := NewCAWithUpstreams(nil, []string{"chatgpt.com", "auth.openai.com"})
	if err != nil {
		t.Fatal(err)
	}
	fp := &ForwardProxy{
		Config: ForwardProxyConfig{
			Listen: "unused",
			InjectRoutes: []ForwardProxyInjectRoute{
				{Host: "chatgpt.com", Capability: "codex-main", Upstream: proxyAddress(t, api.server), AllowInsecureUpstream: true},
				{Host: "auth.openai.com", Capability: "codex-main", Upstream: proxyAddress(t, refresh.server), AllowInsecureUpstream: true},
			},
		},
		CA:        ca,
		Broker:    &BrokerClient{URL: broker.server.URL, Token: "egress-role-token", Client: broker.server.Client()},
		Transport: http.DefaultTransport,
		Resolver:  &staticResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}},
	}
	server := httptest.NewServer(fp)
	t.Cleanup(server.Close)

	for _, tc := range []struct {
		host     string
		upstream *fakeUpstream
		path     string
	}{
		{"chatgpt.com", api, "/v1/responses"},
		{"auth.openai.com", refresh, "/oauth/token"},
	} {
		resp := mitmRequest(t, mitmDial(t, server, ca, tc.host, tc.host), tc.path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s MITM request status = %d", tc.host, resp.StatusCode)
		}
		record := tc.upstream.last(t)
		if len(record.authorization) != 1 || record.authorization[0] != "Bearer "+realToken {
			t.Fatalf("%s upstream Authorization = %v, want the injected real token", tc.host, record.authorization)
		}
		if strings.Contains(fmt.Sprint(record.header), Placeholder) {
			t.Fatalf("placeholder reached %s", tc.host)
		}
	}
}
