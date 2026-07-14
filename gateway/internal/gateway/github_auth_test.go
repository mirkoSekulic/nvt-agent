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
)

func TestGitHubOAuthProducesNormalizedPrincipalWithStateAndPKCE(t *testing.T) {
	const accessToken = "github-access-token-canary"
	fixture := newGitHubOAuthFixture(t, accessToken, `{"id":424242,"login":"octocat"}`)
	server := mustNewServer(t, githubTestConfig(fixture.URL), fakeClient(t))

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
		t.Fatalf("GitHub login requested unexpected scopes: %q", authorizeURL.Query().Get("scope"))
	}
	fixture.codeChallenge = authorizeURL.Query().Get("code_challenge")
	if got := authorizeURL.Query().Get("redirect_uri"); got != "http://agents.localhost/oauth2/github/callback" {
		t.Fatalf("redirect_uri=%q", got)
	}
	loginCookie := cookieNamed(t, loginResponse, loginStateCookie)

	var logs bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldOutput) })
	callbackRequest := httptest.NewRequest(http.MethodGet,
		"http://agents.localhost/oauth2/github/callback?state="+url.QueryEscape(authorizeURL.Query().Get("state"))+"&code=test-code", nil)
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
	if principal.Claims["login"] != "octocat" {
		t.Fatalf("claims=%#v", principal.Claims)
	}
	for _, exposed := range []string{callbackResponse.Body.String(), callbackResponse.Header().Get("Location"), sessionCookie.String(), logs.String(), fmt.Sprintf("%#v", principal.Claims)} {
		if strings.Contains(exposed, accessToken) {
			t.Fatalf("GitHub access token escaped callback: %q", exposed)
		}
	}
	for _, forbidden := range []string{"424242", "authorization_details", "pid", "SSN", "response-body-canary"} {
		if strings.Contains(sessionCookie.String(), forbidden) || strings.Contains(logs.String(), forbidden) {
			t.Fatalf("session cookie or log exposed %q", forbidden)
		}
	}
}

func TestGitHubOAuthRejectsInvalidStateBeforeExchange(t *testing.T) {
	fixture := newGitHubOAuthFixture(t, "access-token", `{"id":1,"login":"octocat"}`)
	server := mustNewServer(t, githubTestConfig(fixture.URL), fakeClient(t))
	login := httptest.NewRecorder()
	server.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "http://agents.localhost/oauth2/login", nil))
	request := httptest.NewRequest(http.MethodGet, "http://agents.localhost/oauth2/github/callback?state=wrong&code=test", nil)
	request.AddCookie(cookieNamed(t, login, loginStateCookie))
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || fixture.tokenCalls != 0 || fixture.userCalls != 0 {
		t.Fatalf("status=%d tokenCalls=%d userCalls=%d", response.Code, fixture.tokenCalls, fixture.userCalls)
	}
}

func TestGitHubOAuthRequiresNumericPositiveUserIDAndHidesCanaries(t *testing.T) {
	const tokenCanary = "github-token-canary"
	const bodyCanary = "github-response-body-canary"
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "missing", body: `{"login":"octocat"}`},
		{name: "zero", body: `{"id":0,"login":"octocat"}`},
		{name: "malformed", body: `{"id":"` + bodyCanary + `","login":"octocat"}`},
		{name: "unrepresentable", body: `{"id":9223372036854775808,"login":"octocat"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGitHubOAuthFixture(t, tokenCanary, test.body)
			server := mustNewServer(t, githubTestConfig(fixture.URL), fakeClient(t))
			login := httptest.NewRecorder()
			server.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "http://agents.localhost/oauth2/login", nil))
			authorizeURL, _ := url.Parse(login.Header().Get("Location"))
			request := httptest.NewRequest(http.MethodGet,
				"http://agents.localhost/oauth2/github/callback?state="+url.QueryEscape(authorizeURL.Query().Get("state"))+"&code=test", nil)
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

func TestGitHubAuthenticationConfigDefaultsAndRejectsUnsafeValues(t *testing.T) {
	valid := authenticatedTestConfig()
	if err := valid.Validate(); err != nil {
		t.Fatalf("default GitHub endpoints failed validation: %v", err)
	}
	for _, mutate := range []func(*Config){
		func(config *Config) { config.Auth.GitHub.ClientID = "" },
		func(config *Config) { config.Auth.GitHub.ClientSecret = "" },
		func(config *Config) { config.Auth.GitHub.CallbackPath = "relative" },
		func(config *Config) { config.Auth.GitHub.Issuer = "http://github.example" },
		func(config *Config) { config.Auth.GitHub.UserURL = "https://user:secret@github.example/user" },
		func(config *Config) { config.Auth.GitHub.TokenURL = "http://github.example/token" },
	} {
		config := authenticatedTestConfig()
		mutate(&config)
		if err := config.Validate(); err == nil {
			t.Fatalf("unsafe GitHub config passed validation: %#v", config.Auth.GitHub)
		}
	}
}

type githubOAuthFixture struct {
	*httptest.Server
	tokenCalls        int
	userCalls         int
	codeVerifier      string
	codeChallenge     string
	userAuthorization string
}

func newGitHubOAuthFixture(t *testing.T, accessToken, userBody string) *githubOAuthFixture {
	t.Helper()
	fixture := &githubOAuthFixture{}
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
			_, _ = fmt.Fprintf(response, `{"access_token":%q,"token_type":"bearer"}`, accessToken)
		case "/user":
			fixture.userCalls++
			fixture.userAuthorization = request.Header.Get("Authorization")
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(userBody))
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(fixture.Close)
	return fixture
}

func githubTestConfig(endpoint string) Config {
	config := authenticatedTestConfig()
	config.Auth.GitHub.CallbackPath = "/oauth2/github/callback"
	config.Auth.GitHub.Issuer = "https://github.enterprise.test/"
	config.Auth.GitHub.AuthorizationURL = endpoint + "/authorize"
	config.Auth.GitHub.TokenURL = endpoint + "/token"
	config.Auth.GitHub.UserURL = endpoint + "/user"
	return config
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
