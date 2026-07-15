package gateway

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestLoginAdmissionUnsetPreservesAuthenticatedSession(t *testing.T) {
	fixture := newGitHubOAuthFixture(t, "access-token", `{"id":42,"login":"owner"}`)
	server := mustNewServer(t, githubTestConfig(fixture.URL), fakeClient(t))
	response := completeGitHubLogin(t, server)
	if response.Code != http.StatusFound || len(server.auth.sessions) != 1 {
		t.Fatalf("unset admission status=%d sessions=%d body=%q", response.Code, len(server.auth.sessions), response.Body.String())
	}
}

func TestLoginAdmissionAllowsMemberAndResourceAuthorizationStillApplies(t *testing.T) {
	const tokenCanary = "oauth-access-token-canary"
	const bodyCanary = "enrichment-response-body-canary"
	claimServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+tokenCanary {
			t.Errorf("claim source authorization=%q", got)
		}
		_, _ = fmt.Fprintf(w, `{"state":"active","unused":%q}`, bodyCanary)
	}))
	t.Cleanup(claimServer.Close)
	fixture := newGitHubOAuthFixture(t, tokenCanary, `{"id":42,"login":"member"}`)
	config := githubTestConfig(fixture.URL)
	config.Auth.Admission = memberAdmission()
	config.Auth.ClaimEnrichment = claimEnrichmentForURL(claimServer.URL)
	config.Auth.Authorization.Rules = []AuthorizationRule{{ID: "owner", Effect: authorizationEffectAllow, Owner: true}}
	otherRun := ownedAgentRun("other", "other-key", "https://github.enterprise.test", "99", "other")
	var proxiedHeaders string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxiedHeaders = fmt.Sprintf("%#v", r.Header)
		_, _ = w.Write([]byte("upstream ok"))
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamPort, _ := strconv.Atoi(upstreamURL.Port())
	ownedRun := ownedAgentRun("owned", "owned-key", "https://github.enterprise.test", "42", "member")
	ownedRun.Annotations[AccessPortAnnotation] = strconv.Itoa(upstreamPort)
	ownedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nvt", Name: "owned-agent", Labels: map[string]string{AgentRunPodLabel: "owned"}},
		Status:     readyPodStatus(upstreamURL.Hostname()),
	}
	server := mustNewServer(t, config, fakeClient(t, &otherRun, &ownedRun, ownedPod))
	server.auth.httpClient = noRedirectClient(claimServer.Client())

	var logs bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldOutput) })
	callback := completeGitHubLogin(t, server)
	if callback.Code != http.StatusFound || len(server.auth.sessions) != 1 {
		t.Fatalf("member login status=%d sessions=%d body=%q", callback.Code, len(server.auth.sessions), callback.Body.String())
	}
	sessionCookie := cookieNamed(t, callback, defaultSessionCookie)
	stored := server.auth.sessions[mustReadSessionID(t, server, sessionCookie)]
	if stored.Principal.Claims["organization_membership"] != "active" {
		t.Fatalf("enriched claims=%#v", stored.Principal.Claims)
	}

	request := httptest.NewRequest(http.MethodGet, "http://other-key.agents.localhost/", nil)
	request.AddCookie(sessionCookie)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("admitted non-owner status=%d body=%q", response.Code, response.Body.String())
	}
	ownedRequest := httptest.NewRequest(http.MethodGet, "http://owned-key.agents.localhost/", nil)
	ownedRequest.AddCookie(sessionCookie)
	ownedResponse := httptest.NewRecorder()
	server.ServeHTTP(ownedResponse, ownedRequest)
	if ownedResponse.Code != http.StatusOK || ownedResponse.Body.String() != "upstream ok" {
		t.Fatalf("owned proxy status=%d body=%q", ownedResponse.Code, ownedResponse.Body.String())
	}
	for _, exposed := range []string{callback.Body.String(), callback.Header().Get("Location"), sessionCookie.String(), logs.String(), fmt.Sprintf("%#v", stored.Principal.Claims), response.Body.String(), proxiedHeaders} {
		if strings.Contains(exposed, tokenCanary) || strings.Contains(exposed, bodyCanary) {
			t.Fatalf("login exposed canary: %q", exposed)
		}
	}
}

func TestLoginAdmissionDeniesNonMemberBeforeSessionEvenWhenPrincipalOwnsRun(t *testing.T) {
	claimServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"state":"pending"}`))
	}))
	t.Cleanup(claimServer.Close)
	fixture := newGitHubOAuthFixture(t, "access-token", `{"id":42,"login":"owner"}`)
	config := githubTestConfig(fixture.URL)
	config.Auth.Admission = memberAdmission()
	config.Auth.ClaimEnrichment = claimEnrichmentForURL(claimServer.URL)
	config.Auth.Authorization.Rules = []AuthorizationRule{{ID: "owner", Effect: authorizationEffectAllow, Owner: true}}
	run := ownedAgentRun("owned", "owned-key", "https://github.enterprise.test", "42", "owner")
	server := mustNewServer(t, config, fakeClient(t, &run))
	server.auth.httpClient = noRedirectClient(claimServer.Client())

	response := completeGitHubLogin(t, server)
	if response.Code != http.StatusUnauthorized || response.Body.String() != "unauthorized\n" || len(server.auth.sessions) != 0 {
		t.Fatalf("non-member status=%d sessions=%d body=%q", response.Code, len(server.auth.sessions), response.Body.String())
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == defaultSessionCookie && cookie.MaxAge >= 0 {
			t.Fatalf("denied principal received session cookie: %#v", cookie)
		}
	}
	clearedLoginState := false
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == loginStateCookie && cookie.MaxAge < 0 {
			clearedLoginState = true
		}
	}
	if !clearedLoginState {
		t.Fatal("denied principal retained login state cookie")
	}
}

func TestClaimEnrichmentFailureCreatesNoSession(t *testing.T) {
	const tokenCanary = "failed-enrichment-token-canary"
	claimServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "failed-enrichment-response-canary", http.StatusForbidden)
	}))
	t.Cleanup(claimServer.Close)
	fixture := newGitHubOAuthFixture(t, tokenCanary, `{"id":42,"login":"member"}`)
	config := githubTestConfig(fixture.URL)
	config.Auth.Admission = memberAdmission()
	config.Auth.ClaimEnrichment = claimEnrichmentForURL(claimServer.URL)
	server := mustNewServer(t, config, fakeClient(t))
	server.auth.httpClient = noRedirectClient(claimServer.Client())
	response := completeGitHubLogin(t, server)
	if response.Code != http.StatusUnauthorized || response.Body.String() != "login unavailable\n" || len(server.auth.sessions) != 0 {
		t.Fatalf("failed enrichment status=%d sessions=%d body=%q", response.Code, len(server.auth.sessions), response.Body.String())
	}
	if strings.Contains(response.Body.String(), tokenCanary) || strings.Contains(response.Body.String(), "failed-enrichment-response-canary") {
		t.Fatalf("failed enrichment exposed canary: %q", response.Body.String())
	}
	if cookie := cookieNamed(t, response, loginStateCookie); cookie.MaxAge >= 0 {
		t.Fatalf("failed enrichment retained login state: %#v", cookie)
	}
}

func TestOAuthAdaptersShareEnrichmentAndAdmissionBoundary(t *testing.T) {
	claimServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"state":"active"}`))
	}))
	t.Cleanup(claimServer.Close)
	provider := newOIDCCallbackFixture(t, "oidc-access-token")
	config := oidcTestConfig(provider.URL)
	config.Auth.Admission = memberAdmission()
	config.Auth.ClaimEnrichment = claimEnrichmentForURL(claimServer.URL)
	server := mustNewServer(t, config, fakeClient(t))
	server.auth.httpClient = noRedirectClient(claimServer.Client())

	login := httptest.NewRecorder()
	server.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "http://agents.localhost/oauth2/login", nil))
	authorizeURL, err := url.Parse(login.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	provider.nonce = authorizeURL.Query().Get("nonce")
	callback := httptest.NewRequest(http.MethodGet,
		"http://agents.localhost/oauth2/callback?state="+url.QueryEscape(authorizeURL.Query().Get("state"))+"&code=test", nil)
	callback.AddCookie(cookieNamed(t, login, loginStateCookie))
	response := httptest.NewRecorder()
	server.ServeHTTP(response, callback)
	if response.Code != http.StatusFound || len(server.auth.sessions) != 1 {
		t.Fatalf("OIDC admission status=%d sessions=%d body=%q", response.Code, len(server.auth.sessions), response.Body.String())
	}
	stored := server.auth.sessions[mustReadSessionID(t, server, cookieNamed(t, response, defaultSessionCookie))]
	if stored.Principal.Claims["organization_membership"] != "active" || provider.tokenCalls != 1 {
		t.Fatalf("OIDC enriched principal=%#v tokenCalls=%d", stored.Principal, provider.tokenCalls)
	}
}

func TestAdmissionValidationRejectsOwnerAndAmbiguousRules(t *testing.T) {
	for _, policy := range []AdmissionConfig{
		{Rules: []AuthorizationRule{{ID: "owner", Effect: authorizationEffectAllow, Owner: true}}},
		{Rules: []AuthorizationRule{{ID: "ambiguous", Effect: authorizationEffectAllow, Authenticated: true, ClaimPath: "group", Values: []string{"member"}}}},
	} {
		if err := policy.validate(); err == nil {
			t.Fatalf("invalid admission policy passed: %#v", policy)
		}
	}
}

func TestAdmissionAndClaimSourceParsingIsStrict(t *testing.T) {
	if admission, err := ParseAdmissionConfig(""); err != nil || admission != nil {
		t.Fatalf("absent admission=(%#v, %v)", admission, err)
	}
	if _, err := ParseAdmissionConfig(`{"default":"deny","unexpected":true}`); err == nil {
		t.Fatal("admission parser accepted unknown field")
	}
	if _, err := ParseClaimEnrichmentConfig(`{"allowedHosts":[],"sources":[],"unexpected":true}`); err == nil {
		t.Fatal("claim enrichment parser accepted unknown field")
	}
	config := Config{BaseDomain: "agents.localhost", ListenAddr: ":8080", DefaultTargetPort: 4090, Auth: AuthConfig{
		Mode: authModeNone, Admission: &AdmissionConfig{Default: authorizationDefaultDeny},
	}}
	if err := config.Validate(); err == nil {
		t.Fatal("auth.mode=none accepted login admission")
	}
}

func completeGitHubLogin(t *testing.T, server *Server) *httptest.ResponseRecorder {
	t.Helper()
	login := httptest.NewRecorder()
	server.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "http://agents.localhost/oauth2/login", nil))
	authorizeURL, err := url.Parse(login.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet,
		"http://agents.localhost/oauth2/github/callback?state="+url.QueryEscape(authorizeURL.Query().Get("state"))+"&code=test", nil)
	request.AddCookie(cookieNamed(t, login, loginStateCookie))
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	return response
}

func memberAdmission() *AdmissionConfig {
	return &AdmissionConfig{Default: authorizationDefaultDeny, Rules: []AuthorizationRule{{
		ID: "member", Effect: authorizationEffectAllow, ClaimPath: "organization_membership", Values: []string{"active"},
	}}}
}

func claimEnrichmentForURL(endpoint string) ClaimEnrichmentConfig {
	parsed, _ := url.Parse(endpoint)
	return ClaimEnrichmentConfig{
		AllowedHosts: []string{parsed.Hostname()},
		Sources:      []OAuthClaimSource{{Endpoint: endpoint, OutputClaim: "organization_membership", ValuePath: "state"}},
	}
}

func noRedirectClient(base *http.Client) *http.Client {
	return &http.Client{
		Transport: base.Transport,
		Timeout:   base.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type oidcCallbackFixture struct {
	*httptest.Server
	key        *rsa.PrivateKey
	nonce      string
	tokenCalls int
}

func newOIDCCallbackFixture(t *testing.T, accessToken string) *oidcCallbackFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &oidcCallbackFixture{key: key}
	var issuer string
	fixture.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(t, w, map[string]any{
				"issuer": issuer, "authorization_endpoint": issuer + "/auth", "token_endpoint": issuer + "/token",
				"userinfo_endpoint": issuer + "/userinfo", "jwks_uri": issuer + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/jwks":
			writeJSON(t, w, map[string]any{"keys": []any{map[string]any{
				"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()), "e": "AQAB",
			}}})
		case "/token":
			fixture.tokenCalls++
			w.Header().Set("Content-Type", "application/json")
			response := map[string]any{"access_token": accessToken, "token_type": "Bearer", "id_token": fixture.signIDToken(t, issuer)}
			writeJSON(t, w, response)
		default:
			http.NotFound(w, r)
		}
	}))
	issuer = fixture.URL
	t.Cleanup(fixture.Close)
	return fixture
}

func (f *oidcCallbackFixture) signIDToken(t *testing.T, issuer string) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "test-key", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss": issuer, "sub": "oidc-member", "aud": "client-id", "nonce": f.nonce,
		"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}
