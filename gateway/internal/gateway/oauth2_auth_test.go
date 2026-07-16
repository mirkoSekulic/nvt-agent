package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOAuth2ProducesNormalizedPrincipalWithStateAndPKCE(t *testing.T) {
	const accessToken = "oauth2-access-token-canary"
	const bodyCanary = "oauth2-identity-response-canary"
	fixture := newOAuth2Fixture(t, accessToken, `{"id":424242,"login":"octocat","raw":"`+bodyCanary+`"}`)
	server := mustNewServer(t, oauth2TestConfig(fixture.URL), fakeClient(t))

	loginRequest := httptest.NewRequest(http.MethodGet, "http://agents.localhost/oauth2/login?return_url=%2Fdashboard", nil)
	loginResponse := httptest.NewRecorder()
	server.ServeHTTP(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusFound {
		t.Fatalf("login status=%d body=%s", loginResponse.Code, loginResponse.Body.String())
	}
	authorizeURL, err := url.Parse(loginResponse.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if authorizeURL.Path != "/authorize" || authorizeURL.Query().Get("state") == "" || authorizeURL.Query().Get("code_challenge_method") != "S256" || authorizeURL.Query().Get("code_challenge") == "" {
		t.Fatalf("authorize URL missing state/PKCE: %s", authorizeURL)
	}
	if authorizeURL.Query().Get("scope") != "" {
		t.Fatalf("OAuth2 login requested unexpected scopes: %q", authorizeURL.Query().Get("scope"))
	}
	fixture.codeChallenge = authorizeURL.Query().Get("code_challenge")
	if got := authorizeURL.Query().Get("redirect_uri"); got != "http://agents.localhost/oauth2/callback" {
		t.Fatalf("redirect_uri=%q", got)
	}
	loginCookie := cookieNamed(t, loginResponse, loginStateCookie)

	var logs bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldOutput) })
	callbackRequest := httptest.NewRequest(http.MethodGet,
		"http://agents.localhost/oauth2/callback?state="+url.QueryEscape(authorizeURL.Query().Get("state"))+"&code=test-code", nil)
	callbackRequest.AddCookie(loginCookie)
	callbackResponse := httptest.NewRecorder()
	server.ServeHTTP(callbackResponse, callbackRequest)
	if callbackResponse.Code != http.StatusFound || callbackResponse.Header().Get("Location") != "/dashboard" {
		t.Fatalf("callback status=%d location=%q body=%s", callbackResponse.Code, callbackResponse.Header().Get("Location"), callbackResponse.Body.String())
	}
	if fixture.tokenCalls != 1 || fixture.userCalls != 1 || fixture.userAuthorization != "Bearer "+accessToken {
		t.Fatalf("fixture calls token=%d user=%d authorization=%q", fixture.tokenCalls, fixture.userCalls, fixture.userAuthorization)
	}
	wantChallenge := base64.RawURLEncoding.EncodeToString(sha256Sum(fixture.codeVerifier))
	if fixture.codeChallenge != wantChallenge {
		t.Fatalf("PKCE verifier did not match challenge: got=%q want=%q", fixture.codeChallenge, wantChallenge)
	}
	sessionCookie := cookieNamed(t, callbackResponse, defaultSessionCookie)
	stored := server.auth.sessions[mustReadSessionID(t, server, sessionCookie)]
	principal := stored.Principal
	if principal.Issuer != "https://github.enterprise.test" || principal.Subject != "424242" || principal.DisplayName != "octocat" {
		t.Fatalf("principal=%#v", principal)
	}
	if principal.Claims["oauth2_subject"] != "424242" || principal.Claims["oauth2_display_name"] != "octocat" {
		t.Fatalf("claims=%#v", principal.Claims)
	}
	for _, exposed := range []string{callbackResponse.Body.String(), callbackResponse.Header().Get("Location"), sessionCookie.String(), logs.String(), fmt.Sprintf("%#v", principal.Claims)} {
		if strings.Contains(exposed, accessToken) || strings.Contains(exposed, bodyCanary) {
			t.Fatalf("OAuth2 credential material escaped callback: %q", exposed)
		}
	}
	for _, forbidden := range []string{"424242", "oauth2-refresh-token-canary", "authorization_details", "pid", "SSN", "response-body-canary"} {
		if strings.Contains(sessionCookie.String(), forbidden) || strings.Contains(logs.String(), forbidden) {
			t.Fatalf("session cookie or log exposed %q", forbidden)
		}
	}
}

func TestOAuth2RejectsInvalidStateBeforeExchange(t *testing.T) {
	fixture := newOAuth2Fixture(t, "access-token", `{"id":1,"login":"octocat"}`)
	server := mustNewServer(t, oauth2TestConfig(fixture.URL), fakeClient(t))
	login := httptest.NewRecorder()
	server.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "http://agents.localhost/oauth2/login", nil))
	request := httptest.NewRequest(http.MethodGet, "http://agents.localhost/oauth2/callback?state=wrong&code=test", nil)
	request.AddCookie(cookieNamed(t, login, loginStateCookie))
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || fixture.tokenCalls != 0 || fixture.userCalls != 0 {
		t.Fatalf("status=%d tokenCalls=%d userCalls=%d", response.Code, fixture.tokenCalls, fixture.userCalls)
	}
}

func TestOAuth2RejectsInvalidIdentityAndHidesCanaries(t *testing.T) {
	const tokenCanary = "oauth-token-canary"
	const bodyCanary = "oauth-response-body-canary"
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "missing", body: `{"login":"octocat"}`},
		{name: "empty", body: `{"id":"","login":"octocat"}`},
		{name: "fraction", body: `{"id":42.5,"login":"octocat"}`},
		{name: "object", body: `{"id":{"value":"` + bodyCanary + `"},"login":"octocat"}`},
		{name: "control", body: `{"id":"bad\u0000subject","login":"octocat"}`},
		{name: "reflected bearer", body: `{"id":"` + tokenCanary + `","login":"octocat"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOAuth2Fixture(t, tokenCanary, test.body)
			server := mustNewServer(t, oauth2TestConfig(fixture.URL), fakeClient(t))
			login := httptest.NewRecorder()
			server.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "http://agents.localhost/oauth2/login", nil))
			authorizeURL, _ := url.Parse(login.Header().Get("Location"))
			request := httptest.NewRequest(http.MethodGet,
				"http://agents.localhost/oauth2/callback?state="+url.QueryEscape(authorizeURL.Query().Get("state"))+"&code=test", nil)
			request.AddCookie(cookieNamed(t, login, loginStateCookie))
			response := httptest.NewRecorder()
			server.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), tokenCanary) || strings.Contains(response.Body.String(), bodyCanary) {
				t.Fatalf("error exposed canary: %q", response.Body.String())
			}
			for _, cookie := range response.Result().Cookies() {
				if cookie.Name == defaultSessionCookie && cookie.MaxAge >= 0 {
					t.Fatalf("invalid identity created a session: %#v", cookie)
				}
			}
		})
	}
}

func TestOAuth2CanonicalizesExactIntegerSubjectWithoutFloatConversion(t *testing.T) {
	fixture := newOAuth2Fixture(t, "access-token", `{"id":92233720368547758081234567890,"login":"member"}`)
	server := mustNewServer(t, oauth2TestConfig(fixture.URL), fakeClient(t))
	response := completeOAuth2Login(t, server)
	if response.Code != http.StatusFound {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	stored := server.auth.sessions[mustReadSessionID(t, server, cookieNamed(t, response, defaultSessionCookie))]
	if stored.Principal.Subject != "92233720368547758081234567890" {
		t.Fatalf("subject=%q", stored.Principal.Subject)
	}
}

func TestOAuth2RejectsAmbiguousSubject(t *testing.T) {
	fixture := newOAuth2Fixture(t, "access-token", `{"identities":[{"id":"one"},{"id":"two"}]}`)
	config := oauth2TestConfig(fixture.URL)
	config.Auth.OAuth2.Identity.SubjectPath = "identities[].id"
	server := mustNewServer(t, config, fakeClient(t))
	response := completeOAuth2Login(t, server)
	if response.Code != http.StatusUnauthorized || len(server.auth.sessions) != 0 {
		t.Fatalf("status=%d sessions=%d body=%q", response.Code, len(server.auth.sessions), response.Body.String())
	}
}

func TestOAuth2AuthenticationConfigDefaultsAndRejectsUnsafeValues(t *testing.T) {
	valid := authenticatedTestConfig()
	if err := valid.Validate(); err != nil {
		t.Fatalf("generic OAuth2 configuration failed validation: %v", err)
	}
	for _, mutate := range []func(*Config){
		func(config *Config) { config.Auth.Mode = "github" },
		func(config *Config) { config.Auth.OAuth2.ClientID = "" },
		func(config *Config) { config.Auth.OAuth2.ClientSecret = "" },
		func(config *Config) { config.Auth.OAuth2.CallbackPath = "relative" },
		func(config *Config) { config.Auth.OAuth2.CallbackPath = "/oauth2/../callback" },
		func(config *Config) { config.Auth.OAuth2.CallbackPath = `/oauth2\callback` },
		func(config *Config) { config.Auth.OAuth2.Issuer = "http://github.example" },
		func(config *Config) { config.Auth.OAuth2.Identity.Endpoint = "https://user:secret@github.example/user" },
		func(config *Config) { config.Auth.OAuth2.TokenURL = "http://github.example/token" },
		func(config *Config) { config.Auth.OAuth2.ClientAuthMethod = "auto" },
		func(config *Config) { config.Auth.OAuth2.Identity.AllowedHosts = []string{"other.example"} },
		func(config *Config) { config.Auth.OAuth2.Identity.SubjectPath = "access_token" },
		func(config *Config) { config.Auth.OAuth2.Identity.SubjectPath = "users.*.id" },
		func(config *Config) { config.Auth.OAuth2.Identity.DisplayNamePath = "credentials.secret" },
		func(config *Config) {
			config.Auth.OAuth2.Identity.AllowedHosts = append(config.Auth.OAuth2.Identity.AllowedHosts, config.Auth.OAuth2.Identity.AllowedHosts[0])
		},
	} {
		config := authenticatedTestConfig()
		mutate(&config)
		if err := config.Validate(); err == nil {
			t.Fatalf("unsafe OAuth2 config passed validation: %#v", config.Auth.OAuth2)
		}
	}
}

func TestOAuth2ClientAuthenticationMethods(t *testing.T) {
	for _, method := range []string{oauth2ClientSecretPost, oauth2ClientSecretBasic} {
		t.Run(method, func(t *testing.T) {
			var tokenCalls int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/token":
					tokenCalls++
					if err := r.ParseForm(); err != nil {
						t.Fatal(err)
					}
					clientID, clientSecret, basic := r.BasicAuth()
					if method == oauth2ClientSecretBasic {
						if !basic || clientID != "client" || clientSecret != "secret" || r.Form.Get("client_secret") != "" {
							t.Fatalf("basic token authentication headers=%#v form=%#v", r.Header, r.Form)
						}
					} else if basic || r.Form.Get("client_id") != "client" || r.Form.Get("client_secret") != "secret" {
						t.Fatalf("post token authentication headers=%#v form=%#v", r.Header, r.Form)
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"access_token":"temporary-token","token_type":"bearer"}`))
				case "/user":
					_, _ = w.Write([]byte(`{"id":"principal","login":"member"}`))
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(server.Close)
			config := oauth2TestConfig(server.URL)
			config.Auth.OAuth2.ClientAuthMethod = method
			config.Auth.OAuth2.Scopes = []string{"profile", "membership"}
			gateway := mustNewServer(t, config, fakeClient(t))
			login := httptest.NewRecorder()
			gateway.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "http://agents.localhost/oauth2/login", nil))
			authorizeURL, _ := url.Parse(login.Header().Get("Location"))
			if authorizeURL.Query().Get("scope") != "profile membership" {
				t.Fatalf("scope=%q", authorizeURL.Query().Get("scope"))
			}
			callback := callbackOAuth2Login(t, gateway, login, authorizeURL)
			if callback.Code != http.StatusFound || tokenCalls != 1 {
				t.Fatalf("callback=%d tokenCalls=%d body=%q", callback.Code, tokenCalls, callback.Body.String())
			}
		})
	}
}

func TestOAuth2IdentityFailuresClearStateAndCreateNoSession(t *testing.T) {
	const tokenCanary = "identity-token-canary"
	const bodyCanary = "identity-response-canary"
	tests := []struct {
		name    string
		handler http.HandlerFunc
		timeout time.Duration
	}{
		{name: "redirect", handler: func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", http.StatusFound) }},
		{name: "non-2xx", handler: func(w http.ResponseWriter, _ *http.Request) { http.Error(w, bodyCanary, http.StatusForbidden) }},
		{name: "malformed", handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"id":` + bodyCanary)) }},
		{name: "oversized", handler: func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"id":"` + strings.Repeat("x", maxOAuth2IdentityResponseBytes) + `"}`))
		}},
		{name: "timeout", timeout: 20 * time.Millisecond, handler: func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(100 * time.Millisecond)
			_, _ = w.Write([]byte(`{"id":"member"}`))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOAuth2Fixture(t, tokenCanary, `{"id":"member"}`)
			config := oauth2TestConfig(fixture.URL)
			identity := httptest.NewServer(test.handler)
			t.Cleanup(identity.Close)
			parsed, _ := url.Parse(identity.URL)
			config.Auth.OAuth2.Identity.Endpoint = identity.URL
			config.Auth.OAuth2.Identity.AllowedHosts = []string{parsed.Hostname()}
			server := mustNewServer(t, config, fakeClient(t))
			server.auth.oauth2IdentityTimeout = test.timeout
			var logs bytes.Buffer
			oldOutput := log.Writer()
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(oldOutput) })
			response := completeOAuth2Login(t, server)
			if response.Code != http.StatusUnauthorized || len(server.auth.sessions) != 0 {
				t.Fatalf("status=%d sessions=%d body=%q", response.Code, len(server.auth.sessions), response.Body.String())
			}
			if cookie := cookieNamed(t, response, loginStateCookie); cookie.MaxAge >= 0 {
				t.Fatalf("login state not cleared: %#v", cookie)
			}
			for _, exposed := range []string{response.Body.String(), response.Header().Get("Set-Cookie"), logs.String()} {
				if strings.Contains(exposed, tokenCanary) || strings.Contains(exposed, bodyCanary) {
					t.Fatalf("identity failure exposed canary: %q", exposed)
				}
			}
		})
	}
}

type oauth2Fixture struct {
	*httptest.Server
	tokenCalls        int
	userCalls         int
	codeVerifier      string
	codeChallenge     string
	userAuthorization string
}

func newOAuth2Fixture(t *testing.T, accessToken, userBody string) *oauth2Fixture {
	t.Helper()
	fixture := &oauth2Fixture{}
	fixture.Server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			fixture.tokenCalls++
			if err := request.ParseForm(); err != nil {
				t.Fatal(err)
			}
			fixture.codeVerifier = request.Form.Get("code_verifier")
			if request.Form.Get("client_id") != "client" || request.Form.Get("client_secret") != "secret" || request.Form.Get("code") == "" {
				t.Fatalf("unexpected token exchange form: %#v", request.Form)
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(response, `{"access_token":%q,"refresh_token":"oauth2-refresh-token-canary","token_type":"bearer"}`, accessToken)
		case "/user":
			fixture.userCalls++
			fixture.userAuthorization = request.Header.Get("Authorization")
			if request.Header.Get("Accept") != "application/json" || request.Header.Get("User-Agent") != "nvt-agent-gateway" || request.Header.Get("Cookie") != "" {
				t.Fatalf("unsafe identity request headers: %#v", request.Header)
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(userBody))
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(fixture.Close)
	return fixture
}

func oauth2TestConfig(endpoint string) Config {
	config := authenticatedTestConfig()
	config.Auth.OAuth2.CallbackPath = "/oauth2/callback"
	config.Auth.OAuth2.Issuer = "https://github.enterprise.test/"
	config.Auth.OAuth2.AuthorizationURL = endpoint + "/authorize"
	config.Auth.OAuth2.TokenURL = endpoint + "/token"
	parsed, _ := url.Parse(endpoint)
	config.Auth.OAuth2.Identity = OAuth2IdentityConfig{Endpoint: endpoint + "/user", AllowedHosts: []string{parsed.Hostname()}, SubjectPath: "id", DisplayNamePath: "login"}
	return config
}

func callbackOAuth2Login(t *testing.T, server *Server, login *httptest.ResponseRecorder, authorizeURL *url.URL) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet,
		"http://agents.localhost/oauth2/callback?state="+url.QueryEscape(authorizeURL.Query().Get("state"))+"&code=test", nil)
	request.AddCookie(cookieNamed(t, login, loginStateCookie))
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	return response
}

func cookieNamed(t *testing.T, recorder *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("cookie %q not found", name)
	return nil
}

func sha256Sum(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}
