package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestStaleServerSessionCookieRecoversByRequestType(t *testing.T) {
	config := authenticatedTestConfig()
	beforeRestart := mustNewServer(t, config, fakeClient(t))
	requestWithSession := httptest.NewRequest(http.MethodGet, "http://agents.localhost/", nil)
	cookie := setTestSession(t, beforeRestart, requestWithSession, "user-1", map[string]any{"sub": "user-1"})

	afterRestart := mustNewServer(t, config, fakeClient(t))
	for _, test := range []struct {
		name       string
		accept     string
		wantStatus int
		wantLogin  bool
	}{
		{name: "browser", accept: "text/html", wantStatus: http.StatusFound, wantLogin: true},
		{name: "api", accept: "application/json", wantStatus: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://agents.localhost/?view=all", nil)
			request.Header.Set("Accept", test.accept)
			request.AddCookie(cookie)
			response := httptest.NewRecorder()
			afterRestart.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			assertClearedCookie(t, response, defaultSessionCookie, "/")
			if test.wantLogin {
				location, err := url.Parse(response.Header().Get("Location"))
				if err != nil {
					t.Fatal(err)
				}
				if location.Path != "/oauth2/login" || location.Query().Get("return_url") != "http://agents.localhost/?view=all" {
					t.Fatalf("login redirect=%q", location.String())
				}
				login := httptest.NewRecorder()
				afterRestart.ServeHTTP(login, httptest.NewRequest(http.MethodGet, location.String(), nil))
				if login.Code != http.StatusFound || !strings.HasPrefix(login.Header().Get("Location"), "https://oauth.example/authorize?") {
					t.Fatalf("login status=%d location=%q", login.Code, login.Header().Get("Location"))
				}
			} else if response.Body.String() != "authentication required\n" {
				t.Fatalf("API body=%q", response.Body.String())
			}
		})
	}
}

func TestLogoutDeletesServerSessionAndClearsCookies(t *testing.T) {
	for _, test := range []struct {
		name          string
		configure     func(*Config)
		requestURL    string
		wantLoggedOut string
		cookiePath    string
	}{
		{name: "subdomain", requestURL: "http://agents.localhost/oauth2/logout", wantLoggedOut: "/oauth2/logged-out", cookiePath: "/"},
		{
			name: "root path routing",
			configure: func(config *Config) {
				config.Routing.Mode = routingModePath
				config.PublicURL = "https://agents.example.com"
				config.Auth.Session.Secure = true
			},
			requestURL:    "https://agents.example.com/oauth2/logout",
			wantLoggedOut: "/oauth2/logged-out",
			cookiePath:    "/",
		},
		{
			name: "path",
			configure: func(config *Config) {
				config.Routing.Mode = routingModePath
				config.PublicURL = "https://staging.altinn.studio/agents"
				config.Auth.Session.Secure = true
			},
			requestURL:    "https://staging.altinn.studio/agents/oauth2/logout",
			wantLoggedOut: "/agents/oauth2/logged-out",
			cookiePath:    "/agents/",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := authenticatedTestConfig()
			if test.configure != nil {
				test.configure(&config)
			}
			server := mustNewServer(t, config, fakeClient(t))
			request := httptest.NewRequest(http.MethodPost, test.requestURL, nil)
			cookie := setTestSession(t, server, request, "user-1", map[string]any{"sub": "user-1"})
			sessionID := mustReadSessionID(t, server, cookie)
			dashboardRequest := httptest.NewRequest(http.MethodGet, strings.TrimSuffix(test.requestURL, "oauth2/logout"), nil)
			dashboardRequest.AddCookie(cookie)
			dashboardResponse := httptest.NewRecorder()
			server.ServeHTTP(dashboardResponse, dashboardRequest)
			logoutURL, err := url.Parse(test.requestURL)
			if err != nil {
				t.Fatal(err)
			}
			if dashboardResponse.Code != http.StatusOK || !strings.Contains(dashboardResponse.Body.String(), `form method="post" action="`+logoutURL.Path+`"`) {
				t.Fatalf("dashboard status=%d missing logout action %q: %s", dashboardResponse.Code, logoutURL.Path, dashboardResponse.Body.String())
			}
			response := httptest.NewRecorder()
			server.ServeHTTP(response, request)
			if response.Code != http.StatusSeeOther || response.Header().Get("Location") != test.wantLoggedOut {
				t.Fatalf("status=%d location=%q", response.Code, response.Header().Get("Location"))
			}
			if _, ok := server.auth.sessions[sessionID]; ok {
				t.Fatal("logout retained server-side session")
			}
			assertClearedCookie(t, response, defaultSessionCookie, test.cookiePath)
			assertClearedCookie(t, response, loginStateCookie, test.cookiePath)

			loggedOutURL := *logoutURL
			loggedOutURL.Path = test.wantLoggedOut
			loggedOutURL.RawQuery = ""
			loggedOutResponse := httptest.NewRecorder()
			server.ServeHTTP(loggedOutResponse, httptest.NewRequest(http.MethodGet, loggedOutURL.String(), nil))
			if loggedOutResponse.Code != http.StatusOK || loggedOutResponse.Header().Get("Location") != "" || !strings.Contains(loggedOutResponse.Body.String(), "Signed out") {
				t.Fatalf("logged-out status=%d location=%q body=%q", loggedOutResponse.Code, loggedOutResponse.Header().Get("Location"), loggedOutResponse.Body.String())
			}
			wantReturnURL := test.cookiePath
			wantSignIn := strings.TrimSuffix(test.wantLoggedOut, "/oauth2/logged-out") + "/oauth2/login?return_url=" + url.QueryEscape(wantReturnURL)
			if !strings.Contains(loggedOutResponse.Body.String(), `href="`+wantSignIn+`"`) {
				t.Fatalf("logged-out page missing sign-in URL %q: %s", wantSignIn, loggedOutResponse.Body.String())
			}
			if len(server.auth.sessions) != 0 || len(loggedOutResponse.Result().Cookies()) != 0 {
				t.Fatalf("logged-out page created session or cookies: sessions=%d cookies=%v", len(server.auth.sessions), loggedOutResponse.Result().Cookies())
			}
			wrongPathURL := loggedOutURL
			wrongPathURL.Path += "/"
			wrongPath := httptest.NewRecorder()
			server.ServeHTTP(wrongPath, httptest.NewRequest(http.MethodGet, wrongPathURL.String(), nil))
			if wrongPath.Code == http.StatusOK {
				t.Fatalf("non-exact logged-out path was public: %s", wrongPathURL.String())
			}
			if test.cookiePath == "/agents/" {
				wrongOrigin := httptest.NewRecorder()
				server.ServeHTTP(wrongOrigin, httptest.NewRequest(http.MethodGet, "https://wrong.example/agents/oauth2/logged-out", nil))
				if wrongOrigin.Code != http.StatusNotFound {
					t.Fatalf("wrong-origin logged-out status=%d", wrongOrigin.Code)
				}
			}

			getResponse := httptest.NewRecorder()
			server.ServeHTTP(getResponse, httptest.NewRequest(http.MethodGet, test.requestURL, nil))
			if getResponse.Code != http.StatusMethodNotAllowed || getResponse.Header().Get("Allow") != http.MethodPost {
				t.Fatalf("GET status=%d allow=%q", getResponse.Code, getResponse.Header().Get("Allow"))
			}
		})
	}
}

func TestDashboardActiveAndAllViewsUseOnePodList(t *testing.T) {
	runs := []*nvtv1alpha1.AgentRun{
		dashboardRun("active-run", "Active run", nvtv1alpha1.AgentRunPhaseRunning),
		dashboardRun("status-lag-run", "Status lag run", ""),
		dashboardRun("pending-run", "Pending run", nvtv1alpha1.AgentRunPhasePending),
		dashboardRun("failed-run", "Failed run", nvtv1alpha1.AgentRunPhaseFailed),
		dashboardRun("not-ready-run", "Not ready run", nvtv1alpha1.AgentRunPhaseRunning),
		dashboardRun("missing-pod-run", "Missing pod run", nvtv1alpha1.AgentRunPhaseRunning),
	}
	baseClient := fakeClient(t,
		runs[0], runs[1], runs[2], runs[3], runs[4], runs[5],
		dashboardPod("active-run", readyPodStatus("10.0.0.10")),
		dashboardPod("status-lag-run", readyPodStatus("10.0.0.11")),
		dashboardPod("not-ready-run", corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.13"}),
	)
	client := &countingClient{Client: baseClient}
	server := mustNewServer(t, Config{BaseDomain: "agents.localhost", ListenAddr: ":8080", DefaultTargetPort: 4090, Auth: AuthConfig{Mode: authModeNone}}, client)

	for _, rawURL := range []string{"http://agents.localhost/", "http://agents.localhost/?view=unknown"} {
		client.podLists = 0
		response := httptest.NewRecorder()
		server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, rawURL, nil))
		body := response.Body.String()
		if response.Code != http.StatusOK || !strings.Contains(body, "Active run") || !strings.Contains(body, "Status lag run") || !strings.Contains(body, `aria-current="page">Active`) {
			t.Fatalf("active status=%d body=%s", response.Code, body)
		}
		for _, hidden := range []string{"Pending run", "Failed run", "Not ready run", "Missing pod run"} {
			if strings.Contains(body, hidden) {
				t.Fatalf("active view exposed %q: %s", hidden, body)
			}
		}
		if strings.Contains(body, "Log out") {
			t.Fatalf("auth.mode=none rendered logout: %s", body)
		}
		if client.podLists != 1 {
			t.Fatalf("Pod list calls=%d, want 1", client.podLists)
		}
	}

	client.podLists = 0
	all := httptest.NewRecorder()
	server.ServeHTTP(all, httptest.NewRequest(http.MethodGet, "http://agents.localhost/?view=all", nil))
	for _, visible := range []string{"Active run", "Status lag run", "Pending run", "Failed run", "Not ready run", "Missing pod run"} {
		if !strings.Contains(all.Body.String(), visible) {
			t.Fatalf("all view omitted %q: %s", visible, all.Body.String())
		}
	}
	if !strings.Contains(all.Body.String(), `aria-current="page">All`) || client.podLists != 1 {
		t.Fatalf("all view selection or Pod list count incorrect: lists=%d body=%s", client.podLists, all.Body.String())
	}
}

func TestDashboardAuthorizationFiltersBeforeActiveAndAllRendering(t *testing.T) {
	owned := ownedAgentRun("owned-run", "owned-key", "https://github.com", "42", "owner")
	owned.Status.Phase = nvtv1alpha1.AgentRunPhaseRunning
	owned.Annotations[DisplayNameAnnotation] = "Owned visible run"
	hidden := ownedAgentRun("hidden-run", "hidden-key", "https://github.com", "99", "other")
	hidden.Status.Phase = nvtv1alpha1.AgentRunPhaseRunning
	hidden.Annotations[DisplayNameAnnotation] = "Unauthorized metadata canary"

	config := authenticatedTestConfig()
	config.Auth.Authorization.Rules = []AuthorizationRule{{ID: "owner", Effect: authorizationEffectAllow, Owner: true}}
	server := mustNewServer(t, config, fakeClient(t,
		&owned, &hidden,
		dashboardPod(owned.Name, readyPodStatus("10.0.0.20")),
		dashboardPod(hidden.Name, readyPodStatus("10.0.0.21")),
	))
	for _, query := range []string{"", "?view=all"} {
		request := httptest.NewRequest(http.MethodGet, "http://agents.localhost/"+query, nil)
		setTestPrincipalSession(t, server, request, Principal{Issuer: "https://github.com", Subject: "42", DisplayName: "Visible User"})
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Owned visible run") || !strings.Contains(response.Body.String(), "Visible User") {
			t.Fatalf("authorized view status=%d body=%s", response.Code, response.Body.String())
		}
		for _, hiddenValue := range []string{"Unauthorized metadata canary", "hidden-run", "hidden-key"} {
			if strings.Contains(response.Body.String(), hiddenValue) {
				t.Fatalf("view exposed %q: %s", hiddenValue, response.Body.String())
			}
		}
	}
}

func dashboardRun(name, display string, phase nvtv1alpha1.AgentRunPhase) *nvtv1alpha1.AgentRun {
	return &nvtv1alpha1.AgentRun{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nvt", Name: name, Annotations: map[string]string{
			AccessKeyAnnotation: name + "-key", DisplayNameAnnotation: display,
		}},
		Status: nvtv1alpha1.AgentRunStatus{Phase: phase},
	}
}

func dashboardPod(runName string, status corev1.PodStatus) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nvt", Name: runName + "-agent", Labels: map[string]string{
			AgentRunPodLabel: runName, AgentRunRoleLabel: AgentRunRoleAgent,
		}},
		Status: status,
	}
}

func assertClearedCookie(t *testing.T, response *httptest.ResponseRecorder, name, path string) {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == name {
			if cookie.MaxAge >= 0 || cookie.Path != path {
				t.Fatalf("cookie %s maxAge=%d path=%q", name, cookie.MaxAge, cookie.Path)
			}
			return
		}
	}
	t.Fatalf("cookie %s was not cleared", name)
}
