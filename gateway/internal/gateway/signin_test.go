package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestUnauthenticatedBrowserNavigationRendersSignInPage(t *testing.T) {
	for _, test := range []struct {
		name                string
		configure           func(*Config)
		dashboardURL        string
		agentRunURL         string
		missingRunURL       string
		wantDashboardReturn string
		wantAgentRunReturn  string
	}{
		{
			name:                "subdomain",
			dashboardURL:        "http://agents.localhost/?view=all",
			agentRunURL:         "http://known-key.agents.localhost/session?tab=logs",
			missingRunURL:       "http://absent-key.agents.localhost/session?tab=logs",
			wantDashboardReturn: "http://agents.localhost/?view=all",
			wantAgentRunReturn:  "http://known-key.agents.localhost/session?tab=logs",
		},
		{
			name: "path",
			configure: func(config *Config) {
				config.Routing.Mode = routingModePath
				config.PublicURL = "https://staging.altinn.studio/agents"
				config.Auth.Session.Secure = true
			},
			dashboardURL:        "https://staging.altinn.studio/agents/?view=all",
			agentRunURL:         "https://staging.altinn.studio/agents/known-key/session?tab=logs",
			missingRunURL:       "https://staging.altinn.studio/agents/absent-key/session?tab=logs",
			wantDashboardReturn: "https://staging.altinn.studio/agents/?view=all",
			wantAgentRunReturn:  "https://staging.altinn.studio/agents/known-key/session?tab=logs",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := authenticatedTestConfig()
			if test.configure != nil {
				test.configure(&config)
			}
			existing := ownedAgentRun("known-run", "known-key", "https://github.com", "42", "owner")
			server := mustNewServer(t, config, fakeClient(t, &existing,
				dashboardPod("known-run", readyPodStatus("10.0.0.30"))))

			dashboard := serveBrowserGet(t, server, test.dashboardURL)
			if dashboard.Code != http.StatusOK || dashboard.Header().Get("Location") != "" {
				t.Fatalf("dashboard status=%d location=%q", dashboard.Code, dashboard.Header().Get("Location"))
			}
			assertSignInPage(t, dashboard, test.wantDashboardReturn)
			assertNoSessionEstablished(t, server, dashboard)

			// The same page must answer for an AgentRun that exists and one that
			// does not, so an unauthenticated visitor learns nothing about which
			// sessions are running.
			existingRun := serveBrowserGet(t, server, test.agentRunURL)
			if existingRun.Code != http.StatusOK || existingRun.Header().Get("Location") != "" {
				t.Fatalf("AgentRun status=%d location=%q", existingRun.Code, existingRun.Header().Get("Location"))
			}
			assertSignInPage(t, existingRun, test.wantAgentRunReturn)
			assertNoSessionEstablished(t, server, existingRun)

			missingRun := serveBrowserGet(t, server, test.missingRunURL)
			if missingRun.Code != existingRun.Code {
				t.Fatalf("existence disclosed by status: existing=%d missing=%d", existingRun.Code, missingRun.Code)
			}
			// The only difference between the two responses may be the access key
			// the visitor themselves asked for, which the return URL preserves.
			// Anything else would leak whether the AgentRun resolved.
			normalized := strings.ReplaceAll(missingRun.Body.String(), "absent-key", "known-key")
			if normalized != existingRun.Body.String() {
				t.Fatalf("existence disclosed by body:\nexisting=%s\nmissing=%s",
					existingRun.Body.String(), missingRun.Body.String())
			}
			if strings.Contains(missingRun.Body.String(), "known-run") {
				t.Fatalf("sign-in page disclosed the AgentRun name: %s", missingRun.Body.String())
			}

			// HEAD keeps the status and headers and drops only the body.
			head := httptest.NewRecorder()
			headRequest := httptest.NewRequest(http.MethodHead, test.dashboardURL, nil)
			headRequest.Header.Set("Accept", "text/html")
			server.ServeHTTP(head, headRequest)
			if head.Code != dashboard.Code || head.Body.Len() != 0 {
				t.Fatalf("HEAD status=%d bodyLen=%d", head.Code, head.Body.Len())
			}
			for _, header := range []string{"Content-Type", "Content-Length", "Cache-Control"} {
				if head.Header().Get(header) != dashboard.Header().Get(header) {
					t.Fatalf("HEAD %s=%q, GET %s=%q", header, head.Header().Get(header), header, dashboard.Header().Get(header))
				}
			}

			// API clients keep the fail-closed 401 contract.
			for _, apiTest := range []struct {
				name   string
				method string
				accept string
			}{
				{name: "json read", method: http.MethodGet, accept: "application/json"},
				{name: "browser write", method: http.MethodPost, accept: "text/html"},
			} {
				api := httptest.NewRecorder()
				apiRequest := httptest.NewRequest(apiTest.method, test.dashboardURL, nil)
				apiRequest.Header.Set("Accept", apiTest.accept)
				server.ServeHTTP(api, apiRequest)
				if api.Code != http.StatusUnauthorized || api.Header().Get("Location") != "" ||
					strings.Contains(api.Body.String(), "<html") || strings.Contains(api.Body.String(), "Sign in") {
					t.Fatalf("%s status=%d location=%q body=%q", apiTest.name, api.Code,
						api.Header().Get("Location"), api.Body.String())
				}
			}
		})
	}
}

func TestSignInControlStartsProviderFlowAndPreservesReturnURL(t *testing.T) {
	server := mustNewServer(t, authenticatedTestConfig(), fakeClient(t))
	response := serveBrowserGet(t, server, "http://agents.localhost/?view=all")
	signInURL := assertSignInPage(t, response, "http://agents.localhost/?view=all")

	login := httptest.NewRecorder()
	server.ServeHTTP(login, httptest.NewRequest(http.MethodGet, signInURL, nil))
	if login.Code != http.StatusFound || !strings.HasPrefix(login.Header().Get("Location"), "https://oauth.example/authorize?") {
		t.Fatalf("sign-in status=%d location=%q", login.Code, login.Header().Get("Location"))
	}

	// The intended URL is carried in the signed login-state cookie, so a
	// successful login lands back where the user was going.
	var state loginStateCookieValue
	for _, cookie := range login.Result().Cookies() {
		if cookie.Name != loginStateCookie {
			continue
		}
		if err := server.auth.cookieCodec.Decode(loginStateCookie, cookie.Value, &state); err != nil {
			t.Fatal(err)
		}
	}
	if state.ReturnURL != "http://agents.localhost/?view=all" {
		t.Fatalf("login state return URL=%q", state.ReturnURL)
	}
}

func TestSignInPageRejectsUnsafeReturnTargets(t *testing.T) {
	// In subdomain mode the request origin is derived from forwarding headers, so
	// a spoofed host must not become the return target. The control falls back to
	// the mounted dashboard root instead of carrying an off-domain URL.
	subdomain := mustNewServer(t, authenticatedTestConfig(), fakeClient(t))
	spoofed := httptest.NewRequest(http.MethodGet, "http://agents.localhost/?view=all", nil)
	spoofed.Header.Set("Accept", "text/html")
	spoofed.Header.Set("X-Forwarded-Host", "evil.example")
	response := httptest.NewRecorder()
	subdomain.ServeHTTP(response, spoofed)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	returnURL := mustReturnURL(t, assertSignInPageURL(t, response))
	if strings.Contains(returnURL, "evil.example") || returnURL != "/" {
		t.Fatalf("spoofed host reached the return URL: %q", returnURL)
	}

	// In path mode an off-origin request never reaches the sign-in renderer.
	config := authenticatedTestConfig()
	config.Routing.Mode = routingModePath
	config.PublicURL = "https://staging.altinn.studio/agents"
	config.Auth.Session.Secure = true
	pathMode := mustNewServer(t, config, fakeClient(t))
	offOrigin := httptest.NewRecorder()
	offOriginRequest := httptest.NewRequest(http.MethodGet, "https://attacker.example/agents/?view=all", nil)
	offOriginRequest.Header.Set("Accept", "text/html")
	pathMode.ServeHTTP(offOrigin, offOriginRequest)
	if offOrigin.Code != http.StatusNotFound {
		t.Fatalf("off-origin status=%d body=%q", offOrigin.Code, offOrigin.Body.String())
	}
}

func TestAuthModeNoneServesDashboardWithoutSignInPage(t *testing.T) {
	server := mustNewServer(t, Config{
		BaseDomain: "agents.localhost", ListenAddr: ":8080", DefaultTargetPort: 4090,
		Auth: AuthConfig{Mode: authModeNone},
	}, fakeClient(t))
	response := serveBrowserGet(t, server, "http://agents.localhost/")
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "Sign in") {
		t.Fatalf("auth.mode=none status=%d body=%s", response.Code, response.Body.String())
	}
}

func serveBrowserGet(t *testing.T, server *Server, rawURL string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, rawURL, nil)
	request.Header.Set("Accept", "text/html")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	return response
}

var signInHrefPattern = regexp.MustCompile(`<a class="signin" href="([^"]+)">Sign in</a>`)

// assertSignInPage checks the rendered page offers exactly one sign-in control
// that targets the mounted login endpoint with the expected return URL, and
// returns that URL.
func assertSignInPage(t *testing.T, response *httptest.ResponseRecorder, wantReturnURL string) string {
	t.Helper()
	signInURL := assertSignInPageURL(t, response)
	parsed, err := url.Parse(signInURL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(parsed.Path, "/oauth2/login") {
		t.Fatalf("sign-in control does not target the login endpoint: %q", signInURL)
	}
	if got := parsed.Query().Get("return_url"); got != wantReturnURL {
		t.Fatalf("sign-in return_url=%q, want %q", got, wantReturnURL)
	}
	return signInURL
}

func assertSignInPageURL(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	if contentType := response.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("sign-in page content type=%q", contentType)
	}
	matches := signInHrefPattern.FindAllStringSubmatch(response.Body.String(), -1)
	if len(matches) != 1 {
		t.Fatalf("expected one sign-in control, got %d: %s", len(matches), response.Body.String())
	}
	return matches[0][1]
}

func mustReturnURL(t *testing.T, signInURL string) string {
	t.Helper()
	parsed, err := url.Parse(signInURL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Query().Get("return_url")
}

func assertNoSessionEstablished(t *testing.T, server *Server, response *httptest.ResponseRecorder) {
	t.Helper()
	if len(server.auth.sessions) != 0 {
		t.Fatalf("rendering the sign-in page created %d sessions", len(server.auth.sessions))
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.MaxAge >= 0 && cookie.Value != "" {
			t.Fatalf("sign-in page set cookie %s=%q maxAge=%d", cookie.Name, cookie.Value, cookie.MaxAge)
		}
	}
}
