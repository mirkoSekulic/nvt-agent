package egress

// Phase 6.2 forward-proxy TLS-MITM: egressd terminates CONNECT under the
// per-agent CA, injects the broker credential into the decrypted request, and
// re-originates to the pinned upstream. The agent never holds the credential;
// the upstream never sees the placeholder; SNI/upstream are pinned.

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
	}
	server := httptest.NewServer(fp)
	t.Cleanup(server.Close)
	return server, ca
}

// mitmDial performs the CONNECT handshake and returns a TLS client conn over
// the tunnel, validating the minted leaf against the given SNI.
func mitmDial(t *testing.T, proxy *httptest.Server, ca *CA, connectHost, sni string) *tls.Conn {
	t.Helper()
	conn, status := sendRawProxyRequest(t, proxyAddress(t, proxy), fmt.Sprintf(
		"CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", connectHost, connectHost))
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
