package egress

// Phase 1 proof of the generic injection path (docs/mediated-egress-plan.md):
// agent request -> egressd -> broker /v1/injection/headers -> upstream
// receives the injected Authorization. No real provider credential is
// involved anywhere; the broker and upstream are fakes.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const realToken = "real-injected-token"

type fakeBroker struct {
	server    *httptest.Server
	mu        sync.Mutex
	calls     int
	fail      bool
	expiresAt string
	requests  []map[string]string
}

func newFakeBroker(t *testing.T) *fakeBroker {
	t.Helper()
	broker := &fakeBroker{}
	broker.server = httptest.NewServer(http.HandlerFunc(broker.handle))
	t.Cleanup(broker.server.Close)
	return broker
}

func (b *fakeBroker) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/injection/headers" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if r.Header.Get("Authorization") != "Bearer egress-role-token" {
		http.Error(w, `{"ok":false,"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var payload map[string]string
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	b.mu.Lock()
	b.calls++
	b.requests = append(b.requests, payload)
	fail := b.fail
	expiresAt := b.expiresAt
	b.mu.Unlock()
	if fail {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"ok":false,"error":"token-refresh-failed"}`))
		return
	}
	response := map[string]any{
		"ok":                    true,
		"headers":               map[string]string{"authorization": "Bearer " + realToken},
		"strip_request_headers": []string{"authorization"},
	}
	if expiresAt != "" {
		response["expires_at"] = expiresAt
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (b *fakeBroker) setFail(value bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fail = value
}

func (b *fakeBroker) setExpiresAt(value string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expiresAt = value
}

func (b *fakeBroker) callCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

type upstreamRecord struct {
	authorization []string
	header        http.Header
	path          string
}

type fakeUpstream struct {
	server  *httptest.Server
	mu      sync.Mutex
	records []upstreamRecord
	handler http.HandlerFunc
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	upstream := &fakeUpstream{}
	upstream.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream.mu.Lock()
		upstream.records = append(upstream.records, upstreamRecord{
			authorization: r.Header.Values("Authorization"),
			header:        r.Header.Clone(),
			path:          r.URL.RequestURI(),
		})
		handler := upstream.handler
		upstream.mu.Unlock()
		if handler != nil {
			handler(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+realToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"bad credential"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(upstream.server.Close)
	return upstream
}

func (u *fakeUpstream) last(t *testing.T) upstreamRecord {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.records) == 0 {
		t.Fatal("upstream received no requests")
	}
	return u.records[len(u.records)-1]
}

func newTestProxyWithHandle(t *testing.T, broker *fakeBroker, upstream *fakeUpstream) (*httptest.Server, *Proxy) {
	t.Helper()
	parsed, err := url.Parse(upstream.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &Proxy{
		Route: Route{
			Listen:                "unused",
			Capability:            "codex-main",
			Upstream:              parsed.Host,
			AllowInsecureUpstream: true,
		},
		Broker:    &BrokerClient{URL: broker.server.URL, Token: "egress-role-token", Client: broker.server.Client()},
		Transport: http.DefaultTransport,
	}
	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)
	return server, proxy
}

func newTestProxy(t *testing.T, broker *fakeBroker, upstream *fakeUpstream) *httptest.Server {
	t.Helper()
	server, _ := newTestProxyWithHandle(t, broker, upstream)
	return server
}

// TestRedirectableStaticBearerProof is the Phase 3.5 redirectable-provider
// proof: a generic tool config points at egressd with only the documented
// placeholder, egressd asks the broker for injectable headers, and the fake
// upstream receives only the real broker-owned credential.
func TestRedirectableStaticBearerProof(t *testing.T) {
	broker := newFakeBroker(t)
	upstream := newFakeUpstream(t)
	proxy, handle := newTestProxyWithHandle(t, broker, upstream)
	handle.Route.Capability = "static-bearer-main"

	toolBaseURL := proxy.URL
	toolToken := Placeholder
	request, err := http.NewRequest(http.MethodGet, toolBaseURL+"/v1/static-proof", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+toolToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from upstream, got %d", response.StatusCode)
	}

	record := upstream.last(t)
	if got := record.header.Get("Authorization"); got != "Bearer "+realToken {
		t.Fatalf("upstream Authorization = %q, want injected credential", got)
	}
	for name, values := range record.header {
		for _, value := range values {
			if strings.Contains(value, Placeholder) {
				t.Fatalf("placeholder reached upstream in header %s", name)
			}
		}
	}

	broker.mu.Lock()
	defer broker.mu.Unlock()
	if len(broker.requests) != 1 {
		t.Fatalf("broker request count = %d, want 1", len(broker.requests))
	}
	requested := broker.requests[0]
	if requested["capability"] != "static-bearer-main" ||
		requested["host"] != handle.Route.Upstream ||
		requested["method"] != http.MethodGet ||
		requested["path"] != "/v1/static-proof" {
		t.Fatalf("unexpected broker injection request: %v", requested)
	}
}

// TestInjectsRealTokenForPlaceholderAuth is the core Phase 1 proof: the
// client sends the placeholder (or nothing), the upstream receives exactly
// one Authorization header carrying the real broker-fetched token, and the
// placeholder never reaches the upstream.
func TestInjectsRealTokenForPlaceholderAuth(t *testing.T) {
	broker := newFakeBroker(t)
	upstream := newFakeUpstream(t)
	proxy := newTestProxy(t, broker, upstream)

	request, err := http.NewRequest(http.MethodPost, proxy.URL+"/backend-api/responses?stream=true", strings.NewReader(`{"prompt":"hi"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+Placeholder)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from upstream, got %d", response.StatusCode)
	}

	record := upstream.last(t)
	if len(record.authorization) != 1 || record.authorization[0] != "Bearer "+realToken {
		t.Fatalf("upstream authorization = %v, want exactly the injected token", record.authorization)
	}
	if record.path != "/backend-api/responses?stream=true" {
		t.Fatalf("upstream path = %q", record.path)
	}
	for name, values := range record.header {
		for _, value := range values {
			if strings.Contains(value, Placeholder) {
				t.Fatalf("placeholder reached upstream in header %s", name)
			}
		}
	}
}

// TestPlaceholderStrippedFromAnyHeader pins the scrub rule: a placeholder in
// a header the broker did not list in strip_request_headers is still removed.
func TestPlaceholderStrippedFromAnyHeader(t *testing.T) {
	broker := newFakeBroker(t)
	upstream := newFakeUpstream(t)
	proxy := newTestProxy(t, broker, upstream)

	request, err := http.NewRequest(http.MethodGet, proxy.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Api-Key", Placeholder)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()

	record := upstream.last(t)
	if record.header.Get("X-Api-Key") != "" {
		t.Fatal("placeholder-bearing header forwarded to upstream")
	}
}

// TestFailsClosedWhenBrokerDenies pins fail-closed behavior: a broker denial
// yields 502 with a generic reason, and nothing reaches the upstream.
func TestFailsClosedWhenBrokerDenies(t *testing.T) {
	broker := newFakeBroker(t)
	broker.setFail(true)
	upstream := newFakeUpstream(t)
	proxy := newTestProxy(t, broker, upstream)

	response, err := http.Get(proxy.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", response.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["ok"] != false || strings.Contains(fmt.Sprint(body), realToken) {
		t.Fatalf("unexpected error body: %v", body)
	}
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	if len(upstream.records) != 0 {
		t.Fatal("request reached upstream despite broker denial")
	}
}

// TestExpiredMaterialFromBrokerFailsClosed pins fail-closed at fetch time:
// material that arrives already expired (or inside the safety margin) is an
// error before the upstream is ever contacted.
func TestExpiredMaterialFromBrokerFailsClosed(t *testing.T) {
	broker := newFakeBroker(t)
	broker.setExpiresAt(time.Now().UTC().Add(-time.Minute).Format(time.RFC3339))
	upstream := newFakeUpstream(t)
	proxy := newTestProxy(t, broker, upstream)

	response, err := http.Get(proxy.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("already-expired material must fail closed, got %d", response.StatusCode)
	}
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	if len(upstream.records) != 0 {
		t.Fatal("request reached upstream with expired material")
	}
}

// TestNoStaleMaterialAfterExpiry pins the other half of fail-closed: expired
// cached material is never reused; when the refetch fails, the request fails.
func TestNoStaleMaterialAfterExpiry(t *testing.T) {
	broker := newFakeBroker(t)
	broker.setExpiresAt(time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	upstream := newFakeUpstream(t)
	proxy, handle := newTestProxyWithHandle(t, broker, upstream)

	var offset atomic.Int64
	handle.Now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }

	response, err := http.Get(proxy.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("fresh material should succeed, got %d", response.StatusCode)
	}

	offset.Store(int64(2 * time.Hour))
	broker.setFail(true)
	response, err = http.Get(proxy.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("expired material must not be reused: got %d", response.StatusCode)
	}
}

// TestCacheKeyedByMethodAndPath pins the cache scope: the broker authorizes
// (capability, host, method, path), so material fetched for one method/path
// must not be reused for another without re-asking the broker.
func TestCacheKeyedByMethodAndPath(t *testing.T) {
	broker := newFakeBroker(t)
	broker.setExpiresAt(time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	upstream := newFakeUpstream(t)
	proxy := newTestProxy(t, broker, upstream)

	for _, request := range []struct{ method, path string }{
		{http.MethodGet, "/a"},
		{http.MethodGet, "/a"},
		{http.MethodGet, "/b"},
		{http.MethodPost, "/a"},
	} {
		req, err := http.NewRequest(request.method, proxy.URL+request.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
	}
	if calls := broker.callCount(); calls != 3 {
		t.Fatalf("expected 3 broker fetches for 3 distinct (method, path) scopes, got %d", calls)
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	seen := map[string]bool{}
	for _, request := range broker.requests {
		seen[request["method"]+" "+request["path"]] = true
	}
	for _, scope := range []string{"GET /a", "GET /b", "POST /a"} {
		if !seen[scope] {
			t.Fatalf("broker never asked for scope %q; requests: %v", scope, broker.requests)
		}
	}
}

// TestCacheReusedUntilExpiry pins cache behavior: consecutive requests within
// the validity window trigger exactly one broker fetch.
func TestCacheReusedUntilExpiry(t *testing.T) {
	broker := newFakeBroker(t)
	broker.setExpiresAt(time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	upstream := newFakeUpstream(t)
	proxy := newTestProxy(t, broker, upstream)

	for range 3 {
		response, err := http.Get(proxy.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
	}
	if calls := broker.callCount(); calls != 1 {
		t.Fatalf("expected 1 broker fetch for 3 requests, got %d", calls)
	}
}

// TestStreamingResponsePassthrough pins SSE behavior: the first event reaches
// the client while the upstream is still holding the connection open.
func TestStreamingResponsePassthrough(t *testing.T) {
	broker := newFakeBroker(t)
	upstream := newFakeUpstream(t)
	release := make(chan struct{})
	upstream.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: first\n\n"))
		w.(http.Flusher).Flush()
		<-release
		_, _ = w.Write([]byte("data: second\n\n"))
	}
	proxy := newTestProxy(t, broker, upstream)

	response, err := http.Get(proxy.URL + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	reader := bufio.NewReader(response.Body)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "data: first\n" {
		t.Fatalf("first streamed line = %q", line)
	}
	close(release)
}

// TestHopByHopHeadersNotForwarded pins RFC 9110 hygiene at the proxy hop.
func TestHopByHopHeadersNotForwarded(t *testing.T) {
	broker := newFakeBroker(t)
	upstream := newFakeUpstream(t)
	proxy := newTestProxy(t, broker, upstream)

	request, err := http.NewRequest(http.MethodGet, proxy.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Proxy-Authorization", "Bearer should-not-forward")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()

	record := upstream.last(t)
	if record.header.Get("Proxy-Authorization") != "" {
		t.Fatal("hop-by-hop header forwarded to upstream")
	}
}

// TestConfigRejectsMalformedUpstream pins the SSRF guard on the pinned
// re-origination target: only bare host[:port] values are accepted.
func TestConfigRejectsMalformedUpstream(t *testing.T) {
	invalid := []string{
		"",
		"https://chatgpt.com",
		"chatgpt.com/path",
		"user@chatgpt.com",
		"chatgpt.com:notaport",
		"chatgpt.com:0",
		":8443",
		"chatgpt.com ",
		"chatgpt.com#frag",
	}
	for _, upstream := range invalid {
		if err := validateUpstream(upstream); err == nil {
			t.Errorf("upstream %q must be rejected", upstream)
		}
	}
	valid := []string{"chatgpt.com", "chatgpt.com:443", "127.0.0.1:8080", "[::1]:8443"}
	for _, upstream := range valid {
		if err := validateUpstream(upstream); err != nil {
			t.Errorf("upstream %q should validate: %v", upstream, err)
		}
	}
}

// TestConfigTLSListenerRequiresBothFiles pins that the agent-facing TLS
// listener needs cert and key together, never one alone.
func TestConfigTLSListenerRequiresBothFiles(t *testing.T) {
	base := func() *Config {
		return &Config{
			BrokerURL:           "https://broker:7347",
			Routes:              []Route{{Listen: "0.0.0.0:8471", Capability: "codex-main", Upstream: "chatgpt.com"}},
			AllowInsecureBroker: false,
		}
	}
	certOnly := base()
	certOnly.Routes[0].ListenTLSCert = "/tls/cert.pem"
	if err := certOnly.Validate(); err == nil {
		t.Fatal("cert without key must be rejected")
	}
	keyOnly := base()
	keyOnly.Routes[0].ListenTLSKey = "/tls/key.pem"
	if err := keyOnly.Validate(); err == nil {
		t.Fatal("key without cert must be rejected")
	}
	both := base()
	both.Routes[0].ListenTLSCert = "/tls/cert.pem"
	both.Routes[0].ListenTLSKey = "/tls/key.pem"
	if err := both.Validate(); err != nil {
		t.Fatalf("cert+key should validate: %v", err)
	}
	if !both.Routes[0].TLSEnabled() {
		t.Fatal("TLSEnabled should report true when both set")
	}
}

// TestConfigRefusesPlaintextBrokerByDefault pins the transport rule from the
// plan: the egressd-broker leg carries real credentials and must be TLS
// unless local dev explicitly opts out.
func TestConfigRefusesPlaintextBrokerByDefault(t *testing.T) {
	config := &Config{
		BrokerURL: "http://127.0.0.1:7347",
		Routes:    []Route{{Listen: "127.0.0.1:0", Capability: "c", Upstream: "example.com"}},
	}
	if err := config.Validate(); err == nil {
		t.Fatal("plaintext broker URL must be rejected without allow_insecure_broker")
	}
	config.AllowInsecureBroker = true
	if err := config.Validate(); err != nil {
		t.Fatalf("opt-in insecure broker should validate: %v", err)
	}
}
