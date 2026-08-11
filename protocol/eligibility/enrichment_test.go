package eligibility

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestEnrichmentPreservesBoundedTopLevelArrayForEligibility(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer transient-token" {
			t.Error("temporary bearer was not sent")
		}
		_, _ = w.Write([]byte(`[{"organization":{"ID":"0192:123456789"},"resource":"approved-resource"}]`))
	}))
	t.Cleanup(server.Close)
	config := enrichmentForServer(t, server, "$")
	claims, err := Enrich(t.Context(), config, "transient-token", map[string]any{"sub": "immutable-subject"}, EnrichOptions{Client: noRedirect(server.Client())})
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{Rules: []Rule{{ID: "eligible", Effect: EffectAllow, Where: Where{
		Array: "memberships[]", All: []Condition{
			{ClaimPath: "organization.ID", Values: []string{"0192:123456789"}},
			{ClaimPath: "resource", Values: []string{"approved-resource"}},
		},
	}}}}
	if !Evaluate(policy, claims).Allowed {
		t.Fatalf("enriched top-level array did not satisfy shared policy: %#v", claims)
	}
}

func TestWholeDocumentEnrichmentRejectsNestedSensitiveData(t *testing.T) {
	for _, key := range []string{
		"pid", "ssn", "access_token", "refresh_token", "secret", "client_secret", "password", "databasePassword", "credential",
	} {
		t.Run(key, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`[{"resource":"allowed","nested":{"` + key + `":"must-not-persist"}}]`))
			}))
			defer server.Close()
			_, err := Enrich(
				t.Context(), enrichmentForServer(t, server, "$"), "transient-token", nil,
				EnrichOptions{Client: noRedirect(server.Client())},
			)
			if err == nil {
				t.Fatalf("whole-document enrichment retained sensitive field %q", key)
			}
			if strings.Contains(err.Error(), "must-not-persist") {
				t.Fatalf("error disclosed sensitive value: %v", err)
			}
		})
	}
}

func TestWholeDocumentEnrichmentAllowsAuthorizationStructures(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"authorization_details":[{"authorized_parties":[{"resource":"allowed"}]}]}`))
	}))
	t.Cleanup(server.Close)
	claims, err := Enrich(
		t.Context(), enrichmentForServer(t, server, "$"), "transient-token", nil,
		EnrichOptions{Client: noRedirect(server.Client())},
	)
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{Rules: []Rule{{ID: "authorization detail", Effect: EffectAllow, Where: Where{
		Array: "memberships.authorization_details[].authorized_parties[]",
		All:   []Condition{{ClaimPath: "resource", Values: []string{"allowed"}}},
	}}}}
	if !Evaluate(policy, claims).Allowed {
		t.Fatalf("safe authorization structure did not satisfy eligibility: %#v", claims)
	}
}

func TestEnrichmentFailsClosedWithoutLeakingInputs(t *testing.T) {
	const token = "temporary-token-canary"
	tests := []struct {
		name   string
		body   string
		status int
		delay  time.Duration
		limits ResponseLimits
		path   string
	}{
		{name: "malformed", body: `[{`},
		{name: "duplicate", body: `{"value":"active","value":"other"}`, path: "value"},
		{name: "oversized body", body: strings.Repeat(" ", 65) + `[]`, limits: ResponseLimits{MaxResponseBytes: 64}},
		{name: "excessive array", body: `[1,2,3]`, limits: ResponseLimits{MaxArrayItems: 2}},
		{name: "excessive depth", body: `[[["x"]]]`, limits: ResponseLimits{MaxDepth: 2}},
		{name: "ambiguous", body: `{"values":["a","b"]}`, path: "values[]"},
		{name: "reflected token", body: `{"value":"prefix-` + token + `"}`, path: "value"},
		{name: "rejected", body: "response-canary", status: http.StatusForbidden},
		{name: "timeout", body: `[]`, delay: 100 * time.Millisecond},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if test.delay > 0 {
					time.Sleep(test.delay)
				}
				if test.status != 0 {
					w.WriteHeader(test.status)
				}
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			path := test.path
			if path == "" {
				path = "$"
			}
			config := enrichmentForServer(t, server, path)
			config.Limits = test.limits
			options := EnrichOptions{Client: noRedirect(server.Client())}
			if test.delay > 0 {
				options.TimeoutOverride = 10 * time.Millisecond
			}
			_, err := Enrich(context.Background(), config, token, nil, options)
			if err == nil {
				t.Fatal("unsafe enrichment succeeded")
			}
			if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "response-canary") {
				t.Fatalf("error disclosed input: %v", err)
			}
		})
	}
}

func TestEnrichmentValidationRejectsDisallowedHostAndUnsafeLimits(t *testing.T) {
	valid := EnrichmentConfig{
		AllowedHosts: []string{"claims.example.test"}, TimeoutSeconds: 5,
		Sources: []ClaimSource{{Endpoint: "https://claims.example.test/memberships", OutputClaim: "memberships", ValuePath: "$"}},
	}
	if err := valid.Validate("auth.claimEnrichment"); err != nil {
		t.Fatal(err)
	}
	authorizationPath := valid
	authorizationPath.Sources = append([]ClaimSource(nil), valid.Sources...)
	authorizationPath.Sources[0].ValuePath = "authorization_details"
	if err := authorizationPath.Validate("auth.claimEnrichment"); err != nil {
		t.Fatalf("legitimate authorization structure rejected: %v", err)
	}
	invalid := valid
	invalid.Sources = append([]ClaimSource(nil), valid.Sources...)
	invalid.Sources[0].Endpoint = "https://other.example.test/memberships"
	if err := invalid.Validate("auth.claimEnrichment"); err == nil {
		t.Fatal("disallowed host accepted")
	}
	invalid = valid
	invalid.TimeoutSeconds = hardMaxTimeoutSeconds + 1
	if err := invalid.Validate("auth.claimEnrichment"); err == nil {
		t.Fatal("unsafe timeout accepted")
	}
	invalid = valid
	invalid.Limits.MaxTotalNodes = hardMaxTotalNodes + 1
	if err := invalid.Validate("auth.claimEnrichment"); err == nil {
		t.Fatal("unsafe response limit accepted")
	}
	invalid = valid
	invalid.AllowedHosts = append(invalid.AllowedHosts, invalid.AllowedHosts[0])
	if err := invalid.Validate("auth.claimEnrichment"); err == nil {
		t.Fatal("duplicate allowed host accepted")
	}
	invalid = valid
	invalid.Sources = append(invalid.Sources, invalid.Sources[0])
	if err := invalid.Validate("auth.claimEnrichment"); err == nil {
		t.Fatal("duplicate output claim accepted")
	}
	invalid = valid
	invalid.AllowedHosts = []string{"-invalid.example.test"}
	if err := invalid.Validate("auth.claimEnrichment"); err == nil {
		t.Fatal("invalid DNS label accepted")
	}
	invalid = valid
	invalid.Sources = append([]ClaimSource(nil), valid.Sources...)
	invalid.Sources[0].ValuePath = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q"
	if err := invalid.Validate("auth.claimEnrichment"); err == nil {
		t.Fatal("value path with too many segments accepted")
	}
}

func enrichmentForServer(t *testing.T, server *httptest.Server, valuePath string) EnrichmentConfig {
	t.Helper()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return EnrichmentConfig{AllowedHosts: []string{parsed.Hostname()}, Sources: []ClaimSource{{
		Endpoint: server.URL, OutputClaim: "memberships", ValuePath: valuePath,
	}}}
}

func noRedirect(base *http.Client) *http.Client {
	return &http.Client{Transport: base.Transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}
