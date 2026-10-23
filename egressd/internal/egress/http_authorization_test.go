package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPAllowlistThroughMediatedEgress(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "../../.."))
	private := t.TempDir()
	const pat = "fake-http-policy-private-token"
	writeJSON := func(name string, value any) string {
		t.Helper()
		path := filepath.Join(private, name)
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	secret := filepath.Join(private, "token")
	if err := os.WriteFile(secret, []byte(pat), 0600); err != nil {
		t.Fatal(err)
	}
	rule := map[string]any{"operation": "http.POST", "resource": "http/api.example.test/graphql"}
	policy := map[string]any{"defaultAction": "deny", "rules": []any{rule}}
	empty := map[string]any{"defaultAction": "deny", "rules": []any{}}
	providers := []any{}
	for name, ceiling := range map[string]any{"api": policy, "blocked": empty} {
		providers = append(providers, map[string]any{"name": name, "plugin": "token", "config": map[string]any{"token-file": secret, "injection-hosts": []string{"api.example.test"}}, "allow": map[string]any{"authorization": ceiling}})
	}
	config := writeJSON("broker.json", map[string]any{"providers": providers})
	identity := func(id, role, pair string, grants []any) map[string]any {
		hash := sha256.Sum256([]byte(id + "-fixture"))
		result := map[string]any{"id": id, "role": role, "token-sha256": fmt.Sprintf("sha256:%x", hash), "grants": grants}
		if pair != "" {
			result["paired-agent"] = pair
		}
		return result
	}
	grants := []any{}
	for _, name := range []string{"api", "blocked"} {
		grants = append(grants, map[string]any{"provider": name, "materialization": "header-inject", "authorization": policy})
	}
	agents := writeJSON("agents.json", map[string]any{"agents": []any{identity("agent", "agent", "", grants), identity("egress", "egress", "agent", nil), identity("denied", "agent", "", nil), identity("denied-egress", "egress", "denied", nil)}})
	audit := filepath.Join(private, "audit.jsonl")
	logFile, err := os.Create(filepath.Join(private, "broker.log"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := httpCredentialFixturePython(t, ctx, filepath.Join(root, "tests/http-credentials/broker_fixture.py"))
	command.Env = append(command.Env, "HOME="+private, "NVT_BROKER_CONFIG="+config, "NVT_BROKER_AGENTS_CONFIG="+agents, "NVT_BROKER_AUDIT_LOG="+audit)
	command.Stderr = logFile
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait(); _ = logFile.Close() })
	address, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatal("isolated broker startup failed", err)
	}
	var hits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+pat || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("incorrect upstream credential or leaked selector")
		}
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	defer upstream.Close()
	ca, err := NewCAWithUpstreams(nil, []string{"api.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	makeProxy := func(token string) *httptest.Server {
		routes := []ForwardProxyInjectRoute{}
		for _, name := range []string{"api", "blocked"} {
			routes = append(routes, ForwardProxyInjectRoute{Host: "api.example.test", Capability: name, Upstream: strings.TrimPrefix(upstream.URL, "http://"), AllowInsecureUpstream: true})
		}
		return httptest.NewServer(&ForwardProxy{Config: ForwardProxyConfig{Listen: "unused", InjectRoutes: routes}, CA: ca, Broker: &BrokerClient{URL: strings.TrimSpace(address), Token: token, Client: http.DefaultClient}, Transport: &http.Transport{}, Resolver: &staticResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}})
	}
	proxy := makeProxy("egress-fixture")
	defer proxy.Close()
	denied := makeProxy("denied-egress-fixture")
	defer denied.Close()
	clientFor := func(base, provider string) *http.Client {
		u, _ := url.Parse(base)
		u.User = url.UserPassword(provider, "x")
		transport := &http.Transport{Proxy: http.ProxyURL(u), TLSClientConfig: &tls.Config{RootCAs: caCertPool(t, ca)}}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport}
	}
	client := clientFor(proxy.URL, "api")
	// Warm allowed material, then try every denied variant on the same client.
	for _, tc := range []struct {
		method, path string
		upgrade      bool
		status       int
	}{
		{"POST", "/graphql", false, 200}, {"POST", "/graphql", false, 200},
		{"GET", "/graphql", false, 403}, {"post", "/graphql", false, 403},
		{"POST", "/graphql?x=1", false, 403}, {"POST", "/graphql?", false, 403},
		{"POST", "/%67raphql", false, 403}, {"POST", "/graphql/", false, 403},
		{"POST", "/other", false, 403}, {"POST", "/graphql", true, 403},
	} {
		before := hits.Load()
		req, _ := http.NewRequest(tc.method, "https://api.example.test"+tc.path, strings.NewReader(`{"query":"arbitrary body"}`))
		if tc.upgrade {
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("%s %s upgrade=%t got %d", tc.method, tc.path, tc.upgrade, resp.StatusCode)
		}
		if bytes.Contains(data, []byte(pat)) || strings.Contains(fmt.Sprint(resp.Header), pat) {
			t.Fatal("credential returned to caller")
		}
		if tc.status == 403 && hits.Load() != before {
			t.Fatal("denied request reached upstream")
		}
	}
	for _, client := range []*http.Client{clientFor(proxy.URL, "blocked"), clientFor(denied.URL, "api")} {
		req, _ := http.NewRequest("POST", "https://api.example.test/graphql", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatal("cross-provider/agent cache bypass")
		}
	}
	if hits.Load() != 2 {
		t.Fatal("unauthorized upstream calls")
	}
	for _, path := range []string{audit, logFile.Name()} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(pat)) {
			t.Fatal("secret in logs")
		}
	}
}

func TestHTTPDenialAfterCacheExpiryIs403WithoutDiagnostics(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusOK)
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code := int(status.Load())
		w.WriteHeader(code)
		if code != http.StatusOK {
			_, _ = io.WriteString(w, "private-diagnostic-canary")
			return
		}
		_, _ = io.WriteString(w, `{"ok":true,"headers":{"authorization":"Bearer fake"}}`)
	}))
	defer broker.Close()
	var hits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(200) }))
	defer upstream.Close()
	var offset atomic.Int64
	now := time.Now()
	proxy := &Proxy{Route: Route{Capability: "api", Upstream: strings.TrimPrefix(upstream.URL, "http://"), AllowInsecureUpstream: true}, Broker: &BrokerClient{URL: broker.URL, Token: "fixture", Client: http.DefaultClient}, Transport: &http.Transport{}, Now: func() time.Time { return now.Add(time.Duration(offset.Load())) }}
	request := func(want int) {
		t.Helper()
		w := httptest.NewRecorder()
		proxy.ServeHTTP(w, httptest.NewRequest("POST", "/graphql", nil))
		if w.Code != want || strings.Contains(w.Body.String(), "private-diagnostic-canary") {
			t.Fatalf("response %d %q", w.Code, w.Body.String())
		}
	}
	request(200)
	status.Store(403)
	request(200) // Documented existing revocation window, not instantaneous.
	offset.Store(int64(maxCacheTTL))
	request(403)
	status.Store(500)
	request(502)
	if hits.Load() != 2 {
		t.Fatal("expired or denied material reached upstream")
	}
}
