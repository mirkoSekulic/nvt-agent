package portal

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/mirkoSekulic/nvt-agent/protocol/eligibility"
	"golang.org/x/oauth2"
)

const (
	testLoginPath         = "login"
	testJWTAlg            = "RS256"
	testTokenPath         = "/token"
	testOIDCSubject       = "oidc-owner"
	testOIDCClientID      = "portal-client"
	testOAuthCallbackPath = "/oauth2/callback"
	testEligibilityValue  = "eligible"
	testSubjectClaim      = "sub"
)

var errTestBrokerUnavailable = errors.New("broker unavailable")

type oidcFixture struct {
	*httptest.Server

	key            *rsa.PrivateKey
	accessToken    func(*testing.T, string) string
	userInfoClaims map[string]any
	nonce          string
}

type recordingEligibilityLeaseBroker struct { //nolint:govet // Test recorder favors operation grouping.
	renewed       []Principal
	renewedExpiry []time.Time
	revoked       []Principal
	renewErr      error
}

func (b *recordingEligibilityLeaseBroker) RenewEligibility(
	_ context.Context,
	principal Principal,
	expiresAt time.Time,
) error {
	b.renewed = append(b.renewed, principal)
	b.renewedExpiry = append(b.renewedExpiry, expiresAt)
	return b.renewErr
}

func (b *recordingEligibilityLeaseBroker) RevokeEligibility(_ context.Context, principal Principal) error {
	b.revoked = append(b.revoked, principal)
	return nil
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &oidcFixture{key: key}
	var issuer string
	fixture.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			if err := json.NewEncoder(w).
				Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "userinfo_endpoint": issuer + "/userinfo", "jwks_uri": issuer + "/jwks", "id_token_signing_alg_values_supported": []string{testJWTAlg}}); err != nil {
				http.Error(w, "encode failed", http.StatusInternalServerError)
			}
		case "/jwks":
			if err := json.NewEncoder(w).
				Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "portal-test", "use": "sig", "alg": testJWTAlg, "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}}); err != nil {
				http.Error(w, "encode failed", http.StatusInternalServerError)
			}
		case testTokenPath:
			if err := r.ParseForm(); err != nil || r.Form.Get("code_verifier") == "" {
				http.Error(w, "invalid", http.StatusBadRequest)
				return
			}
			accessToken := "transient-login-access"
			if fixture.accessToken != nil {
				accessToken = fixture.accessToken(t, issuer)
			}
			if err := json.NewEncoder(w).
				Encode(map[string]any{"access_token": accessToken, "token_type": "Bearer", "id_token": fixture.idToken(t, issuer)}); err != nil {
				http.Error(w, "encode failed", http.StatusInternalServerError)
			}
		case "/userinfo":
			if fixture.userInfoClaims == nil {
				http.Error(w, accountStateUnavailable, http.StatusNotFound)
				return
			}
			if err := json.NewEncoder(w).Encode(fixture.userInfoClaims); err != nil {
				http.Error(w, "encode failed", http.StatusInternalServerError)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	issuer = fixture.URL
	t.Cleanup(fixture.Close)
	return fixture
}

func (f *oidcFixture) idToken(t *testing.T, issuer string) string {
	t.Helper()
	return f.signedToken(t, map[string]any{
		"iss": issuer, testSubjectClaim: testOIDCSubject, "aud": testOIDCClientID, "nonce": f.nonce,
		"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
}

func (f *oidcFixture) signedToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": testJWTAlg, "kid": "portal-test", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestOIDCAuthenticationVerifiesNonceAndAdmitsExactSlotOwner(t *testing.T) {
	fixture := newOIDCFixture(t)
	cfg := testConfig()
	cfg.Auth.Mode = authModeOIDC
	cfg.Auth.OIDC = OIDCConfig{
		IssuerURL:    fixture.URL,
		ClientID:     testOIDCClientID,
		Scopes:       []string{"openid", "profile"},
		CallbackPath: testOAuthCallbackPath,
	}
	cfg.Slots[0].Owner = Principal{Issuer: fixture.URL, Subject: testOIDCSubject}
	cfg.Slots = cfg.Slots[:1]
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthenticator(
		context.Background(),
		cfg,
		strings.Repeat("s", 64),
		"",
		"client-secret",
		fixture.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://portal.example/agents/credentials/login",
		nil,
	)
	loginResponse := httptest.NewRecorder()
	auth.Login(loginResponse, login)
	location, err := url.Parse(loginResponse.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.nonce = location.Query().Get("nonce")
	if fixture.nonce == "" {
		t.Fatal("OIDC nonce missing")
	}
	cookies := loginResponse.Result().Cookies()
	callback := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://portal.example/agents/credentials/oauth2/callback?state="+url.QueryEscape(
			location.Query().Get("state"),
		)+"&code=oidc-code&iss="+url.QueryEscape(
			fixture.URL,
		)+"&session_state=provider-session",
		nil,
	)
	callback.AddCookie(cookies[0])
	response := httptest.NewRecorder()
	auth.Callback(response, callback)
	if response.Code != http.StatusFound {
		t.Fatalf("OIDC callback failed with status %d", response.Code)
	}
	fixture.nonce = "wrong-nonce"
	loginResponse = httptest.NewRecorder()
	auth.Login(loginResponse, login)
	location, err = url.Parse(loginResponse.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	cookies = loginResponse.Result().Cookies()
	callback = httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://portal.example/agents/credentials/oauth2/callback?state="+url.QueryEscape(
			location.Query().Get("state"),
		)+"&code=oidc-code",
		nil,
	)
	callback.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	auth.Callback(response, callback)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("mismatched OIDC nonce accepted")
	}
}

func TestEligibleOIDCCallbackRenewsLeaseAndPolicyDenialRevokesIt(t *testing.T) {
	fixture := newOIDCFixture(t)
	cfg := testConfig()
	cfg.Auth.Mode = authModeOIDC
	cfg.Auth.OIDC = OIDCConfig{
		IssuerURL: fixture.URL, ClientID: testOIDCClientID, CallbackPath: testOAuthCallbackPath,
	}
	cfg.Auth.Eligibility = &eligibility.Policy{Default: eligibility.DefaultDeny, Rules: []eligibility.Rule{{
		ID: "current-member", Effect: eligibility.EffectAllow, Authenticated: true,
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthenticator(
		t.Context(), cfg, strings.Repeat("s", 64), "", "client-secret", fixture.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	auth.cfg.Dynamic.Broker.EligibilityLeaseSeconds = 300
	evaluatedAt := time.Now().Truncate(time.Second)
	auth.now = func() time.Time { return evaluatedAt }
	leases := &recordingEligibilityLeaseBroker{}
	auth.eligibility = leases
	if response := performOIDCCallback(t, auth, fixture, cfg.PublicURL); response.Code != http.StatusFound {
		t.Fatalf("eligible callback status=%d body=%q", response.Code, response.Body.String())
	}
	want := Principal{Issuer: fixture.URL, Subject: testOIDCSubject}
	if len(leases.renewed) != 1 || leases.renewed[0] != want || len(leases.revoked) != 0 ||
		len(leases.renewedExpiry) != 1 ||
		!leases.renewedExpiry[0].Equal(evaluatedAt.Add(300*time.Second)) {
		t.Fatalf("eligible identity did not renew its exact lease: %#v", leases)
	}

	auth.cfg.Auth.Eligibility = &eligibility.Policy{Default: eligibility.DefaultDeny}
	if response := performOIDCCallback(t, auth, fixture, cfg.PublicURL); response.Code != http.StatusUnauthorized {
		t.Fatalf("ineligible callback status=%d body=%q", response.Code, response.Body.String())
	}
	if len(leases.revoked) != 1 || leases.revoked[0] != want {
		t.Fatalf("current policy denial did not revoke the exact lease: %#v", leases.revoked)
	}

	auth.cfg.Auth.Eligibility = cfg.Auth.Eligibility
	leases.renewErr = errTestBrokerUnavailable
	if response := performOIDCCallback(t, auth, fixture, cfg.PublicURL); response.Code != http.StatusUnauthorized {
		t.Fatalf("failed lease renewal did not fail login closed: %d", response.Code)
	}
}

func TestOIDCEligibilityUsesOnlyVerifiedConfiguredClaimSource(t *testing.T) {
	fixture := newOIDCFixture(t)
	cfg := testConfig()
	cfg.Auth.Mode = authModeOIDC
	cfg.Auth.OIDC = OIDCConfig{
		IssuerURL: fixture.URL, ClientID: testOIDCClientID, CallbackPath: testOAuthCallbackPath,
		EligibilityClaimSource: eligibility.ClaimSourceAccessToken,
		AccessTokenAudience:    "portal-eligibility",
	}
	cfg.Auth.Eligibility = &eligibility.Policy{Default: eligibility.DefaultDeny, Rules: []eligibility.Rule{{
		ID: "authorized detail", Effect: eligibility.EffectAllow,
		Where: eligibility.Where{Array: "authorization_details[]", All: []eligibility.Condition{{
			ClaimPath: "type", Values: []string{"configured-resource"},
		}}},
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthenticator(
		t.Context(), cfg, strings.Repeat("s", 64), "", "client-secret", fixture.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	validClaims := func(issuer, audience string) map[string]any {
		return map[string]any{
			"iss": issuer, testSubjectClaim: testOIDCSubject, "aud": audience,
			"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(),
			"authorization_details": []any{map[string]any{"type": "configured-resource"}},
		}
	}
	tests := []struct { //nolint:govet // Test table follows claim-source flow.
		name       string
		access     func(*testing.T, string) string
		wantStatus int
	}{
		{name: "verified access token", wantStatus: http.StatusFound, access: func(t *testing.T, issuer string) string {
			t.Helper()
			return fixture.signedToken(t, validClaims(issuer, "portal-eligibility"))
		}},
		{name: "malformed access token", wantStatus: http.StatusUnauthorized, access: func(*testing.T, string) string {
			return "not-a-jwt"
		}},
		{name: "wrong issuer", wantStatus: http.StatusUnauthorized, access: func(t *testing.T, _ string) string {
			t.Helper()
			return fixture.signedToken(t, validClaims("https://wrong-issuer.example", "portal-eligibility"))
		}},
		{name: "wrong audience", wantStatus: http.StatusUnauthorized, access: func(t *testing.T, issuer string) string {
			t.Helper()
			return fixture.signedToken(t, validClaims(issuer, "other-audience"))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture.accessToken = test.access
			response := performOIDCCallback(t, auth, fixture, cfg.PublicURL)
			if response.Code != test.wantStatus {
				t.Fatalf("callback status=%d want=%d body=%q", response.Code, test.wantStatus, response.Body.String())
			}
		})
	}
}

func TestOIDCEligibilitySupportsExactSubjectUserInfoClaims(t *testing.T) {
	fixture := newOIDCFixture(t)
	fixture.userInfoClaims = map[string]any{testSubjectClaim: testOIDCSubject, "groups": []any{testEligibilityValue}}
	cfg := testConfig()
	cfg.Auth.Mode = authModeOIDC
	cfg.Auth.OIDC = OIDCConfig{
		IssuerURL: fixture.URL, ClientID: testOIDCClientID, CallbackPath: testOAuthCallbackPath,
		EligibilityClaimSource: eligibility.ClaimSourceUserInfo,
	}
	cfg.Auth.Eligibility = &eligibility.Policy{Rules: []eligibility.Rule{{
		ID: "userinfo", Effect: eligibility.EffectAllow, ClaimPath: "groups[]", Values: []string{testEligibilityValue},
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthenticator(
		t.Context(), cfg, strings.Repeat("s", 64), "", "client-secret", fixture.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if response := performOIDCCallback(t, auth, fixture, cfg.PublicURL); response.Code != http.StatusFound {
		t.Fatalf("userinfo eligibility callback status=%d body=%q", response.Code, response.Body.String())
	}
	fixture.userInfoClaims[testSubjectClaim] = "different-subject"
	if response := performOIDCCallback(t, auth, fixture, cfg.PublicURL); response.Code != http.StatusUnauthorized {
		t.Fatalf("mismatched userinfo subject admitted: status=%d", response.Code)
	}
}

func performOIDCCallback(
	t *testing.T,
	auth *Authenticator,
	fixture *oidcFixture,
	publicURL string,
) *httptest.ResponseRecorder {
	t.Helper()
	loginResponse := httptest.NewRecorder()
	auth.Login(loginResponse, httptest.NewRequestWithContext(t.Context(), http.MethodGet, publicURL+"/login", nil))
	location, err := url.Parse(loginResponse.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.nonce = location.Query().Get("nonce")
	callback := httptest.NewRequestWithContext(
		t.Context(), http.MethodGet,
		publicURL+"/oauth2/callback?state="+url.QueryEscape(location.Query().Get("state"))+"&code=oidc-code", nil,
	)
	callback.AddCookie(loginResponse.Result().Cookies()[0])
	response := httptest.NewRecorder()
	auth.Callback(response, callback)
	return response
}

//nolint:cyclop,gocyclo // This test deliberately exercises the complete OAuth admission lifecycle.
func TestGenericOAuth2UsesPKCEStateAndDefaultDenySlotAdmission(t *testing.T) {
	identityBody := `{"id":424242,"login":"octocat"}`
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case testTokenPath:
			if err := r.ParseForm(); err != nil || r.Form.Get("code_verifier") == "" ||
				r.Form.Get("code") != "one-time-code" {
				http.Error(w, "invalid exchange", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if _, err := io.WriteString(
				w,
				`{"access_token":"provider-access-value","token_type":"Bearer"}`,
			); err != nil {
				http.Error(w, "write failed", http.StatusInternalServerError)
			}
		case "/identity":
			if r.Header.Get("Authorization") != "Bearer provider-access-value" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if _, err := io.WriteString(w, identityBody); err != nil {
				http.Error(w, "write failed", http.StatusInternalServerError)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	providerURL, err := url.Parse(provider.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.Auth.OAuth2.AuthorizationURL = provider.URL + "/authorize"
	cfg.Auth.OAuth2.TokenURL = provider.URL + testTokenPath
	cfg.Auth.OAuth2.IdentityEndpoint = provider.URL + "/identity"
	cfg.Auth.OAuth2.AllowedHosts = []string{providerURL.Hostname()}
	cfg.Auth.OAuth2.SubjectPath = "id"
	cfg.Auth.OAuth2.DisplayNamePath = testLoginPath
	cfg.Slots[0].Owner.Subject = "424242"
	if validateErr := cfg.Validate(); validateErr != nil {
		t.Fatal(validateErr)
	}
	auth, err := NewAuthenticator(
		context.Background(),
		cfg,
		strings.Repeat("s", 64),
		testOIDCClientID,
		"client-secret",
		provider.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}

	loginRequest := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://portal.example/agents/credentials/login",
		nil,
	)
	loginResponse := httptest.NewRecorder()
	auth.Login(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusFound {
		t.Fatalf("login code=%d", loginResponse.Code)
	}
	location, err := url.Parse(loginResponse.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("code_challenge") == "" || location.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("PKCE missing: %s", location.String())
	}
	loginCookies := loginResponse.Result().Cookies()
	if len(loginCookies) != 1 || !loginCookies[0].Secure || !loginCookies[0].HttpOnly {
		t.Fatal("secure login cookie missing")
	}

	callbackURL := "https://portal.example/agents/credentials/oauth2/callback?state=" + url.QueryEscape(
		location.Query().Get("state"),
	) + "&code=one-time-code&iss=" + url.QueryEscape(
		cfg.Auth.OAuth2.Issuer,
	) + "&session_state=provider-session&slot=bob"
	callbackRequest := httptest.NewRequestWithContext(t.Context(), http.MethodGet, callbackURL, nil)
	callbackRequest.AddCookie(loginCookies[0])
	callbackResponse := httptest.NewRecorder()
	auth.Callback(callbackResponse, callbackRequest)
	if callbackResponse.Code != http.StatusFound {
		t.Fatalf("callback code=%d body=%s", callbackResponse.Code, callbackResponse.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, cookie := range callbackResponse.Result().Cookies() {
		if cookie.Name == cfg.Auth.Session.CookieName {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil || !sessionCookie.Secure || !sessionCookie.HttpOnly {
		t.Fatal("separate secure portal session missing")
	}
	principalRequest := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://portal.example/agents/credentials/",
		nil,
	)
	principalRequest.AddCookie(sessionCookie)
	principal, csrf, expiresAt, eligibilityExpiresAt, ok := auth.Session(principalRequest)
	if !ok || principal.Issuer != testIdentityIssuer || principal.Subject != "424242" ||
		principal.DisplayName != "octocat" ||
		csrf == "" || expiresAt.IsZero() || eligibilityExpiresAt.IsZero() {
		t.Fatalf("unexpected principal: %#v ok=%v", principal, ok)
	}

	identityBody = `{"id":999,"login":"unconfigured"}`
	loginResponse = httptest.NewRecorder()
	auth.Login(loginResponse, loginRequest)
	location, err = url.Parse(loginResponse.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	loginCookies = loginResponse.Result().Cookies()
	callbackRequest = httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://portal.example/agents/credentials/oauth2/callback?state="+url.QueryEscape(
			location.Query().Get("state"),
		)+"&code=one-time-code",
		nil,
	)
	callbackRequest.AddCookie(loginCookies[0])
	callbackResponse = httptest.NewRecorder()
	auth.Callback(callbackResponse, callbackRequest)
	if callbackResponse.Code != http.StatusUnauthorized {
		t.Fatalf("principal without configured slot was admitted: %d", callbackResponse.Code)
	}
}

//nolint:gocyclo,cyclop // One fixture proves the complete configured login boundary.
func TestConfiguredEligibilityAdmitsUnknownPrincipalThroughPaginatedArrayEnrichment(t *testing.T) {
	pageOne := githubTeamsFixturePage(t, 30, false)
	pageTwo := githubTeamsFixturePage(t, 30, true)
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case testTokenPath:
			body := `{"access_token":"transient-eligibility-token","token_type":"Bearer"}`
			if _, err := io.WriteString(w, body); err != nil {
				t.Error(err)
			}
		case "/identity":
			if _, err := io.WriteString(w, `{"id":"new-immutable-subject","login":"new-user"}`); err != nil {
				t.Error(err)
			}
		case "/claims":
			if r.Header.Get("Authorization") != "Bearer transient-eligibility-token" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if r.URL.Query().Get("page") == "2" {
				if _, err := w.Write(pageTwo); err != nil {
					t.Error(err)
				}
				return
			}
			w.Header().Set("Link", `<?page=2>; rel="next"`)
			if _, err := w.Write(pageOne); err != nil {
				t.Error(err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(provider.Close)
	providerURL, err := url.Parse(provider.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.Auth.OAuth2.AuthorizationURL = provider.URL + "/authorize"
	cfg.Auth.OAuth2.TokenURL = provider.URL + testTokenPath
	cfg.Auth.OAuth2.IdentityEndpoint = provider.URL + "/identity"
	cfg.Auth.OAuth2.AllowedHosts = []string{providerURL.Hostname()}
	cfg.Auth.OAuth2.SubjectPath = "id"
	cfg.Auth.OAuth2.DisplayNamePath = "login"
	cfg.Auth.ClaimEnrichment = eligibility.EnrichmentConfig{
		AllowedHosts: []string{providerURL.Hostname()},
		Limits: eligibility.ResponseLimits{
			MaxResponseBytes: 256 * 1024,
			MaxArrayItems:    60,
			MaxTotalNodes:    4096,
		},
		Sources: []eligibility.ClaimSource{{
			Endpoint: provider.URL + "/claims", OutputClaim: "memberships", ValuePath: "$",
			Pagination: &eligibility.PaginationConfig{Mode: "link", MaxPages: 2},
		}},
	}
	cfg.Auth.Eligibility = &eligibility.Policy{Default: eligibility.DefaultDeny, Rules: []eligibility.Rule{{
		ID: testEligibilityValue, Effect: eligibility.EffectAllow,
		Where: eligibility.Where{Array: "memberships[]", All: []eligibility.Condition{
			{ClaimPath: "organization.login", Values: []string{"Altinn"}},
			{ClaimPath: "slug", Values: []string{"allowed-team"}},
		}},
	}}}
	if validateErr := cfg.Validate(); validateErr != nil {
		t.Fatal(validateErr)
	}
	auth, err := NewAuthenticator(
		t.Context(), cfg, strings.Repeat("s", 64), testOIDCClientID, "client-secret", provider.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRecorder()
	auth.Login(login, httptest.NewRequestWithContext(t.Context(), http.MethodGet, cfg.PublicURL+"/login", nil))
	location, err := url.Parse(login.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	callback := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		cfg.PublicURL+"/oauth2/callback?state="+url.QueryEscape(location.Query().Get("state"))+"&code=one-time",
		nil,
	)
	callback.AddCookie(login.Result().Cookies()[0])
	response := httptest.NewRecorder()
	auth.Callback(response, callback)
	if response.Code != http.StatusFound {
		t.Fatalf("eligible unknown principal denied: status=%d body=%q", response.Code, response.Body.String())
	}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, cfg.PublicURL+"/", nil)
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == cfg.Auth.Session.CookieName {
			request.AddCookie(cookie)
		}
	}
	principal, csrf, sessionExpiry, eligibilityExpiry, ok := auth.Session(request)
	if !ok || csrf == "" || sessionExpiry.IsZero() || eligibilityExpiry.IsZero() ||
		principal.Issuer != cfg.Auth.OAuth2.Issuer || principal.Subject != "new-immutable-subject" {
		t.Fatalf("unexpected eligible principal session: %#v ok=%v", principal, ok)
	}
	if auth.hasOwnedSlot(principal) {
		t.Fatal("eligibility incorrectly granted ownership of a configured slot")
	}
}

func githubTeamsFixturePage(t *testing.T, count int, allowLast bool) []byte {
	t.Helper()
	team, err := os.ReadFile("../../../tests/fixtures/oauth/github-team.json")
	if err != nil {
		t.Fatal(err)
	}
	page := make([]byte, 0, count*(len(team)+1)+2)
	page = append(page, '[')
	for index := range count {
		if index > 0 {
			page = append(page, ',')
		}
		entry := team
		if allowLast && index == count-1 {
			entry = bytes.ReplaceAll(entry, []byte(`"slug": "other-team"`), []byte(`"slug": "allowed-team"`))
			entry = bytes.ReplaceAll(entry, []byte(`"login": "Elsewhere"`), []byte(`"login": "Altinn"`))
		}
		page = append(page, entry...)
	}
	return append(page, ']')
}

func TestCallbackRejectsDuplicateAndCraftedState(t *testing.T) {
	cfg := testConfig()
	sum := sha512.Sum512([]byte(strings.Repeat("s", 64)))
	auth := &Authenticator{
		cfg:      cfg,
		cookies:  securecookie.New(sum[:32], sum[32:]),
		sessions: map[string]session{},
		now:      time.Now,
	}
	encoded, err := auth.cookies.Encode(
		cfg.Auth.Session.CookieName+"_login",
		loginState{State: "expected", Verifier: "v", Nonce: "n", Expires: time.Now().Add(time.Minute).Unix()},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"?state=crafted&code=x",
		"?state=expected&state=crafted&code=x",
		"?state=expected&code=x&code=y",
		"?state=expected&code=x&iss=https%3A%2F%2Fwrong.example",
		"?state=expected&code=x&iss=https%3A%2F%2Fidentity.example&iss=https%3A%2F%2Fidentity.example",
	} {
		req := httptest.NewRequestWithContext(
			t.Context(),
			http.MethodGet,
			"https://portal.example/agents/credentials/oauth2/callback"+raw,
			nil,
		)
		req.AddCookie(&http.Cookie{Name: cfg.Auth.Session.CookieName + "_login", Value: encoded})
		response := httptest.NewRecorder()
		auth.Callback(response, req)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("crafted callback %q accepted: %d", raw, response.Code)
		}
	}
}

func fetchOAuth2TestPrincipal(t *testing.T, identityBody, accessToken string) (Principal, error) {
	t.Helper()
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+accessToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, identityBody); err != nil {
			http.Error(w, "write failed", http.StatusInternalServerError)
		}
	}))
	defer provider.Close()
	cfg := testConfig()
	cfg.Auth.OAuth2.IdentityEndpoint = provider.URL
	cfg.Auth.OAuth2.SubjectPath = "id"
	cfg.Auth.OAuth2.DisplayNamePath = testLoginPath
	auth := &Authenticator{cfg: cfg, client: noRedirectClient(provider.Client())}
	principal, _, err := auth.principal(context.Background(), &oauth2.Token{AccessToken: accessToken}, "")
	return principal, err
}

func TestOAuth2IdentityCanonicalizationAndTokenReflection(t *testing.T) {
	const accessToken = "transient-login-token-canary"
	valid := []struct {
		name, body, subject, display string
	}{
		{"github integer", `{"id":424242,"login":"octocat"}`, "424242", "octocat"},
		{
			"large exact integer",
			`{"id":92233720368547758081234567890,"login":"member"}`,
			"92233720368547758081234567890",
			"member",
		},
		{"string", `{"id":"stable-subject","login":"member"}`, "stable-subject", "member"},
	}
	for _, test := range valid {
		t.Run(test.name, func(t *testing.T) {
			principal, err := fetchOAuth2TestPrincipal(t, test.body, accessToken)
			if err != nil || principal.Subject != test.subject || principal.DisplayName != test.display {
				t.Fatalf("valid identity was not canonicalized")
			}
		})
	}
	invalid := []struct{ name, body string }{
		{"fraction", `{"id":42.5,"login":"member"}`},
		{"exponent", `{"id":1e3,"login":"member"}`},
		{"boolean", `{"id":true,"login":"member"}`},
		{"object", `{"id":{"value":42},"login":"member"}`},
		{"empty", `{"id":"","login":"member"}`},
		{"numeric display", `{"id":42,"login":424242}`},
		{"reflected subject", `{"id":"prefix-` + accessToken + `-suffix","login":"member"}`},
		{"reflected display", `{"id":42,"login":"prefix-` + accessToken + `-suffix"}`},
		{"oversized integer", `{"id":` + strings.Repeat("9", 513) + `,"login":"member"}`},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if _, err := fetchOAuth2TestPrincipal(t, test.body, accessToken); err == nil {
				t.Fatal("invalid or reflected identity was accepted")
			}
		})
	}
}
