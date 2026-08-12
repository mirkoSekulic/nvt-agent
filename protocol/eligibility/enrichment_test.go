package eligibility

import (
	"context"
	"errors"
	"io"
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

func TestLinkPaginationCombinesArraysBeforeEligibilityEvaluation(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bearer transient-token" {
			t.Error("temporary bearer was not sent")
		}
		if r.URL.Query().Get("page") == "2" {
			_, _ = w.Write([]byte(`[{"organization":{"login":"Altinn"},"slug":"allowed-team"}]`))
			return
		}
		w.Header().Set("Link", `<?page=2>; rel="next", <?page=2>; rel="last"`)
		_, _ = w.Write([]byte(`[{"organization":{"login":"Elsewhere"},"slug":"other-team"}]`))
	}))
	t.Cleanup(server.Close)
	config := enrichmentForServer(t, server, "$")
	config.Sources[0].Endpoint = server.URL + "/user/teams"
	config.Sources[0].Pagination = &PaginationConfig{Mode: "link", MaxPages: 3}
	claims, err := Enrich(
		t.Context(), config, "transient-token", nil,
		EnrichOptions{Client: noRedirect(server.Client())},
	)
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{Rules: []Rule{{ID: "team", Effect: EffectAllow, Where: Where{
		Array: "memberships[]", All: []Condition{
			{ClaimPath: "organization.login", Values: []string{"Altinn"}},
			{ClaimPath: "slug", Values: []string{"allowed-team"}},
		},
	}}}}
	if requests != 2 || !Evaluate(policy, claims).Allowed {
		t.Fatalf("page-two team was not admitted: requests=%d claims=%#v", requests, claims)
	}
}

func TestPaginationOmittedPreservesSingleRequestCompatibility(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("Link", `<?page=2>; rel="next"`)
		_, _ = w.Write([]byte(`{"state":"active"}`))
	}))
	t.Cleanup(server.Close)
	config := enrichmentForServer(t, server, "state")
	claims, err := Enrich(t.Context(), config, "token", nil, EnrichOptions{Client: noRedirect(server.Client())})
	if err != nil || claims["memberships"] != "active" || requests != 1 {
		t.Fatalf("unpaginated compatibility changed: requests=%d claims=%#v err=%v", requests, claims, err)
	}
}

func TestLinkPaginationRejectsUnsafeOrPartialResults(t *testing.T) {
	otherRequests := 0
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { otherRequests++ }))
	t.Cleanup(other.Close)
	tests := []struct {
		name      string
		first     string
		second    string
		linkOne   string
		linkTwo   string
		statusTwo int
		pages     int
		limits    ResponseLimits
	}{
		{name: "cross origin", first: `[]`, linkOne: `<` + other.URL + `/user/teams?page=2>; rel="next"`, pages: 3},
		{name: "http", first: `[]`, linkOne: `<http://example.test/user/teams?page=2>; rel="next"`, pages: 3},
		{name: "fragment", first: `[]`, linkOne: `<?page=2#section>; rel="next"`, pages: 3},
		{name: "empty fragment", first: `[]`, linkOne: `<?page=2#>; rel="next"`, pages: 3},
		{name: "changed path", first: `[]`, linkOne: `</other?page=2>; rel="next"`, pages: 3},
		{name: "redirect", first: `[]`, second: `[]`, linkOne: `<?page=2>; rel="next"`, statusTwo: http.StatusFound, pages: 3},
		{name: "loop", first: `[]`, second: `[]`, linkOne: `<?page=2>; rel="next"`, linkTwo: `<?page=2>; rel="next"`, pages: 3},
		{name: "excess pages", first: `[]`, second: `[]`, linkOne: `<?page=2>; rel="next"`, linkTwo: `<?page=3>; rel="next"`, pages: 2},
		{name: "excess items", first: `[1]`, second: `[2]`, linkOne: `<?page=2>; rel="next"`, pages: 3, limits: ResponseLimits{MaxArrayItems: 1}},
		{name: "excess bytes", first: `[1]`, second: `[2]`, linkOne: `<?page=2>; rel="next"`, pages: 3, limits: ResponseLimits{MaxResponseBytes: 5}},
		{name: "excess nodes", first: `[1]`, second: `[2]`, linkOne: `<?page=2>; rel="next"`, pages: 3, limits: ResponseLimits{MaxTotalNodes: 3}},
		{name: "malformed link", first: `[]`, linkOne: `</user/teams?page=2; rel="next"`, pages: 3},
		{name: "ambiguous next", first: `[]`, linkOne: `<?page=2>; rel="next", <?page=3>; rel="next"`, pages: 3},
		{name: "duplicate next relation", first: `[]`, linkOne: `<?page=2>; rel="next next"`, pages: 3},
		{name: "oversized link", first: `[]`, linkOne: `<` + strings.Repeat("x", maxPaginationLinkBytes) + `>; rel="next"`, pages: 3},
		{name: "non-array", first: `[]`, second: `{"items":[]}`, linkOne: `<?page=2>; rel="next"`, pages: 3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("page") == "2" {
					if test.linkTwo != "" {
						w.Header().Set("Link", test.linkTwo)
					}
					if test.statusTwo != 0 {
						w.Header().Set("Location", "/user/teams?redirected=1")
						w.WriteHeader(test.statusTwo)
					}
					_, _ = w.Write([]byte(test.second))
					return
				}
				if test.linkOne != "" {
					w.Header().Set("Link", test.linkOne)
				}
				_, _ = w.Write([]byte(test.first))
			}))
			defer server.Close()
			config := enrichmentForServer(t, server, "$")
			config.Sources[0].Endpoint = server.URL + "/user/teams"
			config.Sources[0].Pagination = &PaginationConfig{Mode: "link", MaxPages: test.pages}
			config.Limits = test.limits
			if _, err := Enrich(
				t.Context(), config, "token", nil, EnrichOptions{Client: noRedirect(server.Client())},
			); err == nil {
				t.Fatal("unsafe or partial pagination succeeded")
			}
		})
	}
	if otherRequests != 0 {
		t.Fatalf("bearer was sent to a cross-origin next link: requests=%d", otherRequests)
	}
}

func TestNextLinkRejectsUserinfoOnOtherwiseMatchingOrigin(t *testing.T) {
	original, err := url.Parse("https://api.example.test/user/teams")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nextLink(
		[]string{`<https://user:password@api.example.test/user/teams?page=2>; rel="next"`},
		original,
		original,
	); err == nil {
		t.Fatal("userinfo-bearing next link was accepted")
	}
}

func TestLinkPaginationClosesEachBodyBeforeRequestingNextPage(t *testing.T) {
	client := &closeOrderedClient{}
	config := EnrichmentConfig{
		AllowedHosts: []string{"api.example.test"},
		Sources: []ClaimSource{{
			Endpoint: "https://api.example.test/user/teams", OutputClaim: "teams", ValuePath: "$",
			Pagination: &PaginationConfig{Mode: "link", MaxPages: 2},
		}},
	}
	claims, err := Enrich(t.Context(), config, "token", nil, EnrichOptions{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	if client.requests != 2 || !client.firstClosed || len(claims["teams"].([]any)) != 0 {
		t.Fatalf("page bodies were not closed in order: requests=%d firstClosed=%t", client.requests, client.firstClosed)
	}
}

func TestLinkPaginationUsesOneTimeoutForAllPages(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(40 * time.Millisecond)
		if r.URL.Query().Get("page") == "" {
			w.Header().Set("Link", `<?page=2>; rel="next"`)
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(server.Close)
	config := enrichmentForServer(t, server, "$")
	config.Sources[0].Endpoint = server.URL + "/user/teams"
	config.Sources[0].Pagination = &PaginationConfig{Mode: "link", MaxPages: 3}
	_, err := Enrich(
		context.Background(), config, "token", nil,
		EnrichOptions{Client: noRedirect(server.Client()), TimeoutOverride: 60 * time.Millisecond},
	)
	if err == nil {
		t.Fatal("per-page timeout reset accepted a source exceeding its total deadline")
	}
}

func TestWholeDocumentEnrichmentRejectsNestedSensitiveData(t *testing.T) {
	for _, key := range []string{
		"pid", "profile.pid", "ssn", "user_ssn_value", "access_token", "refresh_token", "token_value",
		"secret", "client_secret", "password", "databasePassword", "credential", "authorization_code",
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
	for _, pagination := range []*PaginationConfig{
		{Mode: "", MaxPages: 2}, {Mode: "link", MaxPages: 1},
		{Mode: "link", MaxPages: hardMaxPaginationPages + 1}, {Mode: "cursor", MaxPages: 2},
	} {
		invalid = valid
		invalid.Sources = append([]ClaimSource(nil), valid.Sources...)
		invalid.Sources[0].Pagination = pagination
		if err := invalid.Validate("auth.claimEnrichment"); err == nil {
			t.Fatalf("invalid pagination accepted: %#v", pagination)
		}
	}
	invalid = valid
	invalid.Sources = append([]ClaimSource(nil), valid.Sources...)
	invalid.Sources[0].Pagination = &PaginationConfig{Mode: "link", MaxPages: 2}
	invalid.Sources[0].ValuePath = "state"
	if err := invalid.Validate("auth.claimEnrichment"); err == nil {
		t.Fatal("paginated non-root valuePath accepted")
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

type closeOrderedClient struct {
	requests    int
	firstClosed bool
}

func (c *closeOrderedClient) Do(request *http.Request) (*http.Response, error) {
	c.requests++
	if c.requests == 2 && !c.firstClosed {
		return nil, errors.New("second request began before first body closed")
	}
	header := make(http.Header)
	if c.requests == 1 {
		header.Set("Link", `<?page=2>; rel="next"`)
	}
	body := io.NopCloser(strings.NewReader(`[]`))
	if c.requests == 1 {
		body = &trackingReadCloser{Reader: strings.NewReader(`[]`), onClose: func() { c.firstClosed = true }}
	}
	return &http.Response{StatusCode: http.StatusOK, Header: header, Body: body, Request: request}, nil
}

type trackingReadCloser struct {
	io.Reader
	onClose func()
}

func (c *trackingReadCloser) Close() error {
	c.onClose()
	return nil
}
