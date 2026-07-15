package gateway

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestClaimEnrichmentFailuresFailClosedAndHideCanaries(t *testing.T) {
	const tokenCanary = "oauth-token-canary"
	const bodyCanary = "claim-response-canary"
	tests := []struct {
		name    string
		handler http.HandlerFunc
		timeout time.Duration
	}{
		{name: "redirect", handler: func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", http.StatusFound) }},
		{name: "non-2xx", handler: func(w http.ResponseWriter, _ *http.Request) { http.Error(w, bodyCanary, http.StatusForbidden) }},
		{name: "malformed JSON", handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"state":` + bodyCanary)) }},
		{name: "oversized", handler: func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"state":"` + strings.Repeat("x", maxClaimSourceResponseSize) + `"}`))
		}},
		{name: "missing value", handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"other":"` + bodyCanary + `"}`)) }},
		{name: "timeout", timeout: 20 * time.Millisecond, handler: func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(100 * time.Millisecond)
			_, _ = w.Write([]byte(`{"state":"active"}`))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(test.handler)
			t.Cleanup(server.Close)
			auth := claimTestAuthenticator(server)
			auth.claimSourceTimeout = test.timeout
			var logs bytes.Buffer
			oldOutput := log.Writer()
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(oldOutput) })
			_, err := auth.enrichClaims(context.Background(), tokenCanary, map[string]any{"sub": "subject"})
			if err == nil {
				t.Fatal("claim enrichment unexpectedly succeeded")
			}
			exposed := err.Error() + logs.String()
			if strings.Contains(exposed, tokenCanary) || strings.Contains(exposed, bodyCanary) {
				t.Fatalf("claim failure exposed canary: %q", exposed)
			}
		})
	}
}

func TestClaimEnrichmentRejectsOutputCollision(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"state":"active"}`))
	}))
	t.Cleanup(server.Close)
	auth := claimTestAuthenticator(server)
	_, err := auth.enrichClaims(context.Background(), "token", map[string]any{"organization_membership": "authenticated-value"})
	if err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("collision err=%v", err)
	}
}

func TestClaimEnrichmentRejectsBearerAsSelectedValue(t *testing.T) {
	const tokenCanary = "selected-bearer-token-canary"
	for _, body := range []string{
		`{"state":"` + tokenCanary + `"}`,
		`{"state":"prefix-` + tokenCanary + `-suffix"}`,
		`{"state":["active","` + tokenCanary + `"]}`,
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		auth := claimTestAuthenticator(server)
		_, err := auth.enrichClaims(context.Background(), tokenCanary, nil)
		server.Close()
		if err == nil || strings.Contains(err.Error(), tokenCanary) {
			t.Fatalf("selected bearer err=%v", err)
		}
	}
}

func TestClaimEnrichmentConfigRejectsUnsafeSources(t *testing.T) {
	valid := ClaimEnrichmentConfig{
		AllowedHosts: []string{"api.example.com"},
		Sources:      []OAuthClaimSource{{Endpoint: "https://api.example.com/membership", OutputClaim: "organization_membership", ValuePath: "state"}},
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid claim source failed: %v", err)
	}
	mutations := []func(*ClaimEnrichmentConfig){
		func(c *ClaimEnrichmentConfig) { c.Sources[0].Endpoint = "http://api.example.com/membership" },
		func(c *ClaimEnrichmentConfig) {
			c.Sources[0].Endpoint = "https://user:secret@api.example.com/membership"
		},
		func(c *ClaimEnrichmentConfig) { c.Sources[0].Endpoint = "https://internal.example.com/membership" },
		func(c *ClaimEnrichmentConfig) { c.Sources[0].Endpoint = "https://api.example.com/membership#fragment" },
		func(c *ClaimEnrichmentConfig) { c.Sources[0].OutputClaim = "AccessToken" },
		func(c *ClaimEnrichmentConfig) { c.Sources[0].OutputClaim = "access_token" },
		func(c *ClaimEnrichmentConfig) { c.Sources[0].ValuePath = "accessToken" },
		func(c *ClaimEnrichmentConfig) { c.Sources[0].ValuePath = "credentials.token" },
		func(c *ClaimEnrichmentConfig) { c.Sources = append(c.Sources, c.Sources[0]) },
		func(c *ClaimEnrichmentConfig) { c.AllowedHosts = append(c.AllowedHosts, "api.example.com") },
	}
	for index, mutate := range mutations {
		copy := ClaimEnrichmentConfig{AllowedHosts: append([]string(nil), valid.AllowedHosts...), Sources: append([]OAuthClaimSource(nil), valid.Sources...)}
		mutate(&copy)
		if err := copy.validate(); err == nil {
			t.Fatalf("unsafe mutation %d passed: %#v", index, copy)
		}
	}
}

func TestClaimEnrichmentSendsOnlyBearerAndSelectedClaim(t *testing.T) {
	const tokenCanary = "temporary-access-token"
	const bodyCanary = "raw-response-only-canary"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+tokenCanary {
			t.Errorf("authorization=%q", got)
		}
		if r.Header.Get("Cookie") != "" {
			t.Errorf("claim request forwarded cookie")
		}
		_, _ = fmt.Fprintf(w, `{"state":"active","raw":%q}`, bodyCanary)
	}))
	t.Cleanup(server.Close)
	auth := claimTestAuthenticator(server)
	claims, err := auth.enrichClaims(context.Background(), tokenCanary, map[string]any{"login": "member"})
	if err != nil {
		t.Fatal(err)
	}
	if claims["organization_membership"] != "active" || claims["login"] != "member" || strings.Contains(fmt.Sprintf("%#v", claims), bodyCanary) {
		t.Fatalf("claims=%#v", claims)
	}
}

func claimTestAuthenticator(server *httptest.Server) *Authenticator {
	parsed, _ := url.Parse(server.URL)
	return &Authenticator{
		config: Config{Auth: AuthConfig{ClaimEnrichment: ClaimEnrichmentConfig{
			AllowedHosts: []string{parsed.Hostname()},
			Sources:      []OAuthClaimSource{{Endpoint: server.URL, OutputClaim: "organization_membership", ValuePath: "state"}},
		}}},
		httpClient: noRedirectClient(server.Client()),
	}
}
