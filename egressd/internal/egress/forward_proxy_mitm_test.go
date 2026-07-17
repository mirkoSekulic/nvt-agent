package egress

// Forward-proxy TLS termination: egressd terminates CONNECT under the
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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
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

func TestForwardProxyMITMOrdinaryClientNeedsNoPlaceholder(t *testing.T) {
	broker := newFakeBroker(t)
	upstream := newFakeUpstream(t)
	ca, err := NewCAWithUpstreams(nil, []string{"api.github.com"})
	if err != nil {
		t.Fatal(err)
	}
	fp := &ForwardProxy{
		Config: ForwardProxyConfig{Listen: "unused", InjectRoutes: []ForwardProxyInjectRoute{
			{Host: "api.github.com", Capability: "github-main", Upstream: proxyAddress(t, upstream.server), AllowInsecureUpstream: true},
			{Host: "api.github.com", Capability: "github-alt", Upstream: proxyAddress(t, upstream.server), AllowInsecureUpstream: true},
		}},
		CA: ca, Broker: &BrokerClient{URL: broker.server.URL, Token: "egress-role-token", Client: broker.server.Client()},
		Transport: http.DefaultTransport,
		Resolver:  &staticResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}},
	}
	server := httptest.NewServer(fp)
	t.Cleanup(server.Close)

	for _, capability := range []string{"github-main", "github-alt"} {
		proxyURL, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		proxyURL.User = url.User(capability)
		client := &http.Client{Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caCertPool(t, ca)},
		}}
		request, err := http.NewRequest(http.MethodGet, "https://api.github.com/repos/example/project", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("ordinary request through %s: %v", capability, err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("ordinary request through %s status = %d", capability, response.StatusCode)
		}
	}

	record := upstream.last(t)
	if got := record.header.Get("Authorization"); got != "Bearer "+realToken {
		t.Fatalf("upstream Authorization = %q", got)
	}
	if strings.Contains(fmt.Sprint(record.header), Placeholder) {
		t.Fatal("ordinary client sent the placeholder")
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	if len(broker.requests) != 2 || broker.requests[0]["capability"] != "github-main" || broker.requests[1]["capability"] != "github-alt" {
		t.Fatalf("provider selections were not exact: %#v", broker.requests)
	}
}

func TestGenericPluginLifecycleMigratesWatcherProviderToOrdinaryHTTPS(t *testing.T) {
	broker := newFakeBroker(t)
	upstream := newFakeUpstream(t)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("plain HTTP request carried authorization: %q", r.Header.Get("Authorization"))
		}
		_, _ = io.WriteString(w, `{"plain":true}`)
	}))
	t.Cleanup(plain.Close)
	plainURL, err := url.Parse(plain.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy, ca := newMITMProxy(t, broker, ForwardProxyInjectRoute{
		Host: "api.github.com", Capability: "github-main",
		Upstream: proxyAddress(t, upstream.server), AllowInsecureUpstream: true,
	}, "api.github.com")

	_, file, _, ok := goruntime.Caller(0)
	if !ok {
		t.Fatal("resolve repository root")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	state := filepath.Join(home, "state")
	if err := os.MkdirAll(filepath.Join(home, ".nvt-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(home, "ca.crt")
	if err := os.WriteFile(caFile, ca.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(home, "ordinary-http-plugin.py")
	pluginScript := fmt.Sprintf(`#!/usr/bin/env python3
import importlib.util
import pathlib
import socket
import sys
from urllib.request import urlopen

module_path = pathlib.Path(%q) / "runtime" / "plugins" / "github-watcher" / "github_watcher_lib.py"
sys.path.insert(0, str(module_path.parent))
spec = importlib.util.spec_from_file_location("github_watcher_lib", module_path)
watcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watcher)

# Model an existing watcher config/registry entry. Generic process egress must
# ignore both legacy direct and broker selectors and make an ordinary request.
watch = watcher.normalize_watch(
    {"repo": "example/project", "number": 1, "provider": "legacy-direct"},
    {"default-provider": "legacy-default", "broker": {"enabled": True, "provider": "legacy-broker"}},
    "registry.prs[0]",
)
result = watcher.github_request(
    "/repos/example/project/pulls/1",
    watch["provider"],
    broker=watch["broker"],
)
if result != {"ok": True}:
    raise SystemExit("unexpected response")

# Plain HTTP stays outside the CONNECT-only provider injection listener. Map a
# fixture hostname locally so an inherited HTTP_PROXY would make this fail.
real_getaddrinfo = socket.getaddrinfo
def fixture_getaddrinfo(host, port, *args, **kwargs):
    if host == "plain.example":
        host = "127.0.0.1"
    return real_getaddrinfo(host, port, *args, **kwargs)
socket.getaddrinfo = fixture_getaddrinfo
with urlopen(%q, timeout=5) as response:
    if response.read() != b'{"plain":true}':
        raise SystemExit("unexpected plain HTTP response")
`, root, "http://plain.example:"+plainURL.Port()+"/plain")
	if err := os.WriteFile(plugin, []byte(pluginScript), 0o755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(home, "agent.yaml")
	configYAML := fmt.Sprintf(`plugins:
  - name: ordinary-http
    source: custom
    command: %q
    egress:
      provider: github-main
`, plugin)
	if err := os.WriteFile(config, []byte(configYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	metadata := `{"mode":"mediated","transport":"forward-proxy","grants":[{"provider":"github-main","materialization":"header-inject"}]}`
	if err := os.WriteFile(filepath.Join(state, "egress.json"), []byte(metadata), 0o600); err != nil {
		t.Fatal(err)
	}
	proxyURL := "http://github-main@" + proxyAddress(t, proxy)
	if err := os.WriteFile(filepath.Join(home, ".nvt-agent", "env"), []byte("export NVT_EGRESS_FORWARD_PROXY_URL_GITHUB_MAIN="+proxyURL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	command := exec.Command("python3", filepath.Join(root, "runtime", "core", "run-plugins.py"), "after-agent", config)
	command.Env = append(os.Environ(),
		"HOME="+home,
		"NVT_STATE_DIR="+state,
		"NVT_EGRESS_MODE=mediated",
		"NVT_EGRESS_FORWARD_PROXY_URL_GITHUB_MAIN="+proxyURL,
		"HTTP_PROXY="+proxyURL,
		"ALL_PROXY="+proxyURL,
		"SSL_CERT_FILE="+caFile,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generic plugin request failed: %v\n%s", err, output)
	}
	record := upstream.last(t)
	if record.header.Get("Authorization") != "Bearer "+realToken {
		t.Fatalf("plugin upstream Authorization = %q", record.header.Get("Authorization"))
	}
	if strings.Contains(fmt.Sprint(record.header), Placeholder) {
		t.Fatal("plugin sent a placeholder upstream")
	}
}

// TestForwardProxyMITMRemintsExpiredLeafOnNextCONNECT exercises the exact
// production CONNECT -> tls.Server(ServerTLSConfig) path across two renewal
// cycles. Each CONNECT receives a fresh server tls.Config, so even a client
// with a populated session cache must perform a full handshake and invoke the
// CA's renewal callback.
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
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
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

	clock = oldLeaf.NotAfter.Add(time.Minute)
	second := dial()
	defer second.Close()
	secondState := second.ConnectionState()
	if secondState.DidResume {
		t.Fatal("second CONNECT resumed despite the production path using a fresh server tls.Config")
	}
	if sessions.gets == 0 {
		t.Fatal("second handshake did not consult the populated client session cache")
	}
	newLeaf := secondState.PeerCertificates[0]
	if newLeaf.SerialNumber.Cmp(oldLeaf.SerialNumber) == 0 {
		t.Fatalf("second CONNECT received stale leaf serial %s", newLeaf.SerialNumber)
	}
	if !newLeaf.NotAfter.After(clock) {
		t.Fatalf("second CONNECT leaf expired at %s before advanced clock %s", newLeaf.NotAfter, clock)
	}
	response = mitmRequest(t, second, "/second")
	_ = response.Body.Close()
	_ = second.Close()

	clock = newLeaf.NotAfter.Add(time.Minute)
	third := dial()
	defer third.Close()
	thirdState := third.ConnectionState()
	if thirdState.DidResume {
		t.Fatal("third CONNECT resumed despite the production path using a fresh server tls.Config")
	}
	thirdLeaf := thirdState.PeerCertificates[0]
	if thirdLeaf.SerialNumber.Cmp(newLeaf.SerialNumber) == 0 {
		t.Fatalf("third CONNECT received stale leaf serial %s", thirdLeaf.SerialNumber)
	}
	if !thirdLeaf.NotAfter.After(clock) {
		t.Fatalf("third CONNECT leaf expired at %s before advanced clock %s", thirdLeaf.NotAfter, clock)
	}
	response = mitmRequest(t, third, "/third")
	_ = response.Body.Close()
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
// (protocol/injection.md): the placeholder-file tool talks
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
