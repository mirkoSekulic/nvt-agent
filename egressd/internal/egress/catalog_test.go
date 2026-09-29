package egress

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicCatalogBoundaries(t *testing.T) {
	const good = `{"ok":true,"files":[{"path":"public.json","content":"public"}],"expires_at":null}`
	body, status, requests := good, http.StatusOK, 0
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/v1/injection/catalog" || r.Header.Get("Authorization") != "Bearer trusted-only" || r.Method != "POST" {
			t.Error("wrong trusted catalog request")
		}
		input, _ := io.ReadAll(r.Body)
		if string(input) != `{"provider":"selected"}` {
			t.Error("caller selected another identity")
		}
		w.Header().Set("Location", "/should-not-follow")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	defer broker.Close()
	proxy := &ForwardProxy{Config: ForwardProxyConfig{InjectRoutes: []ForwardProxyInjectRoute{{Host: "fixture.test", Capability: "selected"}}}, Broker: &BrokerClient{URL: broker.URL, Token: "trusted-only", Client: broker.Client()}}
	request := func(method, target, selector string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, nil)
		if selector != "" {
			r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(selector+":x")))
		}
		w := httptest.NewRecorder()
		proxy.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", publicCatalogPath, "selected"); w.Code != 200 || !strings.Contains(w.Body.String(), "public.json") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("public catalog failed: %d %s", w.Code, w.Body)
	}
	for _, selector := range []string{"", "other"} {
		if request("GET", publicCatalogPath, selector).Code != 403 {
			t.Fatal("unconfigured selection accepted")
		}
	}
	for _, target := range []string{publicCatalogPath + "?provider=other", "http://upstream.test" + publicCatalogPath} {
		if request("GET", target, "selected").Code != 400 {
			t.Fatal("upstream/query forwarding accepted")
		}
	}
	if request("POST", publicCatalogPath, "selected").Code != 400 || requests != 1 {
		t.Fatal("invalid request reached broker")
	}
	for _, bad := range []string{`{"ok":true,"files":[],"token":"private-canary"}`, `{"ok":true,"files":[],"routes":[]}`, good + good, strings.Repeat("x", maxPublicCatalogBytes+1)} {
		body = bad
		w := request("GET", publicCatalogPath, "selected")
		if w.Code != 502 || strings.Contains(w.Body.String(), "private-canary") || strings.Contains(w.Body.String(), "trusted-only") {
			t.Fatal("unsafe response escaped")
		}
	}
	body = good
	for _, code := range []int{http.StatusForbidden, http.StatusFound} {
		status = code
		before := requests
		if request("GET", publicCatalogPath, "selected").Code != 502 || requests != before+1 {
			t.Fatal("denial or redirect not isolated")
		}
	}
	status = 200
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := proxy.Broker.publicCatalog(ctx, "selected"); err == nil {
		t.Fatal("canceled request succeeded")
	}
}
