package portal

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
)

type oidcFixture struct {
	*httptest.Server
	key   *rsa.PrivateKey
	nonce string
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
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/jwks":
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "portal-test", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()), "e": "AQAB"}}})
		case "/token":
			if err := r.ParseForm(); err != nil || r.Form.Get("code_verifier") == "" {
				http.Error(w, "invalid", http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "transient-login-access", "token_type": "Bearer", "id_token": fixture.idToken(t, issuer)})
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
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "portal-test", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{"iss": issuer, "sub": "oidc-owner", "aud": "portal-client", "nonce": f.nonce, "iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix()})
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
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
	cfg.Auth.Mode = "oidc"
	cfg.Auth.OIDC = OIDCConfig{IssuerURL: fixture.URL, ClientID: "portal-client", Scopes: []string{"openid", "profile"}, CallbackPath: "/oauth2/callback"}
	cfg.Slots[0].Owner = Principal{Issuer: fixture.URL, Subject: "oidc-owner"}
	cfg.Slots = cfg.Slots[:1]
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthenticator(context.Background(), cfg, strings.Repeat("s", 64), "", "client-secret", fixture.Client())
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRequest(http.MethodGet, "https://portal.example/agents/credentials/login", nil)
	loginResponse := httptest.NewRecorder()
	auth.Login(loginResponse, login)
	location, _ := url.Parse(loginResponse.Header().Get("Location"))
	fixture.nonce = location.Query().Get("nonce")
	if fixture.nonce == "" {
		t.Fatal("OIDC nonce missing")
	}
	cookies := loginResponse.Result().Cookies()
	callback := httptest.NewRequest(http.MethodGet, "https://portal.example/agents/credentials/oauth2/callback?state="+url.QueryEscape(location.Query().Get("state"))+"&code=oidc-code", nil)
	callback.AddCookie(cookies[0])
	response := httptest.NewRecorder()
	auth.Callback(response, callback)
	if response.Code != http.StatusFound {
		t.Fatalf("OIDC callback failed with status %d", response.Code)
	}
	fixture.nonce = "wrong-nonce"
	loginResponse = httptest.NewRecorder()
	auth.Login(loginResponse, login)
	location, _ = url.Parse(loginResponse.Header().Get("Location"))
	cookies = loginResponse.Result().Cookies()
	callback = httptest.NewRequest(http.MethodGet, "https://portal.example/agents/credentials/oauth2/callback?state="+url.QueryEscape(location.Query().Get("state"))+"&code=oidc-code", nil)
	callback.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	auth.Callback(response, callback)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("mismatched OIDC nonce accepted")
	}
}

func TestGenericOAuth2UsesPKCEStateAndDefaultDenySlotAdmission(t *testing.T) {
	identitySubject := "alice"
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil || r.Form.Get("code_verifier") == "" || r.Form.Get("code") != "one-time-code" {
				http.Error(w, "invalid exchange", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"access_token":"provider-access-value","token_type":"Bearer"}`)
		case "/identity":
			if r.Header.Get("Authorization") != "Bearer provider-access-value" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"identity": identitySubject, "display": "Alice"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	providerURL, _ := url.Parse(provider.URL)
	cfg := testConfig()
	cfg.Auth.OAuth2.AuthorizationURL = provider.URL + "/authorize"
	cfg.Auth.OAuth2.TokenURL = provider.URL + "/token"
	cfg.Auth.OAuth2.IdentityEndpoint = provider.URL + "/identity"
	cfg.Auth.OAuth2.AllowedHosts = []string{providerURL.Hostname()}
	cfg.Auth.OAuth2.SubjectPath = "identity"
	cfg.Auth.OAuth2.DisplayNamePath = "display"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthenticator(context.Background(), cfg, strings.Repeat("s", 64), "portal-client", "client-secret", provider.Client())
	if err != nil {
		t.Fatal(err)
	}

	loginRequest := httptest.NewRequest(http.MethodGet, "https://portal.example/agents/credentials/login", nil)
	loginResponse := httptest.NewRecorder()
	auth.Login(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusFound {
		t.Fatalf("login code=%d", loginResponse.Code)
	}
	location, _ := url.Parse(loginResponse.Header().Get("Location"))
	if location.Query().Get("code_challenge") == "" || location.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("PKCE missing: %s", location.String())
	}
	loginCookies := loginResponse.Result().Cookies()
	if len(loginCookies) != 1 || !loginCookies[0].Secure || !loginCookies[0].HttpOnly {
		t.Fatal("secure login cookie missing")
	}

	callbackURL := "https://portal.example/agents/credentials/oauth2/callback?state=" + url.QueryEscape(location.Query().Get("state")) + "&code=one-time-code"
	callbackRequest := httptest.NewRequest(http.MethodGet, callbackURL, nil)
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
	principalRequest := httptest.NewRequest(http.MethodGet, "https://portal.example/agents/credentials/", nil)
	principalRequest.AddCookie(sessionCookie)
	principal, csrf, ok := auth.Session(principalRequest)
	if !ok || principal.Issuer != "https://identity.example" || principal.Subject != "alice" || csrf == "" {
		t.Fatalf("unexpected principal: %#v ok=%v", principal, ok)
	}

	identitySubject = "unconfigured-user"
	loginResponse = httptest.NewRecorder()
	auth.Login(loginResponse, loginRequest)
	location, _ = url.Parse(loginResponse.Header().Get("Location"))
	loginCookies = loginResponse.Result().Cookies()
	callbackRequest = httptest.NewRequest(http.MethodGet, "https://portal.example/agents/credentials/oauth2/callback?state="+url.QueryEscape(location.Query().Get("state"))+"&code=one-time-code", nil)
	callbackRequest.AddCookie(loginCookies[0])
	callbackResponse = httptest.NewRecorder()
	auth.Callback(callbackResponse, callbackRequest)
	if callbackResponse.Code != http.StatusUnauthorized {
		t.Fatalf("principal without configured slot was admitted: %d", callbackResponse.Code)
	}
}

func TestCallbackRejectsDuplicateAndCraftedState(t *testing.T) {
	cfg := testConfig()
	sum := sha512.Sum512([]byte(strings.Repeat("s", 64)))
	auth := &Authenticator{cfg: cfg, cookies: securecookie.New(sum[:32], sum[32:]), sessions: map[string]session{}, now: time.Now}
	encoded, err := auth.cookies.Encode(cfg.Auth.Session.CookieName+"_login", loginState{State: "expected", Verifier: "v", Nonce: "n", Expires: time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"?state=crafted&code=x", "?state=expected&state=crafted&code=x", "?state=expected&code=x&slot=bob"} {
		req := httptest.NewRequest(http.MethodGet, "https://portal.example/agents/credentials/oauth2/callback"+raw, nil)
		req.AddCookie(&http.Cookie{Name: cfg.Auth.Session.CookieName + "_login", Value: encoded})
		response := httptest.NewRecorder()
		auth.Callback(response, req)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("crafted callback %q accepted: %d", raw, response.Code)
		}
	}
}
