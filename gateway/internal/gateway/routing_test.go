package gateway

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPathRoutingConfigValidation(t *testing.T) {
	validPath := Config{
		PublicURL: "https://agents.altinn.studio", ListenAddr: ":8080", DefaultTargetPort: 4090,
		Routing: RoutingConfig{Mode: routingModePath}, Auth: AuthConfig{Mode: authModeNone},
	}
	if err := validPath.Validate(); err != nil {
		t.Fatalf("valid path config: %v", err)
	}
	validSubdomain := Config{BaseDomain: "agents.localhost", ListenAddr: ":8080", DefaultTargetPort: 4090}
	if err := validSubdomain.Validate(); err != nil {
		t.Fatalf("default subdomain config: %v", err)
	}
	subdomainWithPreviouslyInvalidPublicPath := validSubdomain
	subdomainWithPreviouslyInvalidPublicPath.PublicURL = "https://agents.localhost/"
	if err := subdomainWithPreviouslyInvalidPublicPath.Validate(); err == nil {
		t.Fatal("subdomain routing no longer rejects a publicURL path")
	}
	for _, test := range []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "unknown mode", mutate: func(config *Config) { config.Routing.Mode = "other" }},
		{name: "missing public URL", mutate: func(config *Config) { config.PublicURL = "" }},
		{name: "non HTTPS", mutate: func(config *Config) { config.PublicURL = "http://agents.altinn.studio" }},
		{name: "non root path", mutate: func(config *Config) { config.PublicURL = "https://agents.altinn.studio/base" }},
		{name: "query", mutate: func(config *Config) { config.PublicURL = "https://agents.altinn.studio?next=bad" }},
		{name: "fragment", mutate: func(config *Config) { config.PublicURL = "https://agents.altinn.studio/#bad" }},
		{name: "userinfo", mutate: func(config *Config) { config.PublicURL = "https://user@agents.altinn.studio" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := validPath
			test.mutate(&config)
			if err := config.Validate(); err == nil {
				t.Fatalf("invalid config passed: %#v", config)
			}
		})
	}
	subdomainWithoutBase := validSubdomain
	subdomainWithoutBase.BaseDomain = ""
	if err := subdomainWithoutBase.Validate(); err == nil {
		t.Fatal("subdomain routing accepted an empty baseDomain")
	}
	authenticatedPath := validPath
	authenticatedPath.Auth = authenticatedTestConfig().Auth
	if err := authenticatedPath.Validate(); err == nil || !strings.Contains(err.Error(), "secure") {
		t.Fatalf("insecure authenticated path config error=%v", err)
	}
}

func TestParsePathCanonicalRouting(t *testing.T) {
	for _, test := range []struct {
		name string
		url  *url.URL
		kind routeKind
		key  string
	}{
		{name: "dashboard", url: &url.URL{Path: "/"}, kind: routeDashboard},
		{name: "agent root", url: &url.URL{Path: "/opaque-key/"}, kind: routeAgentRun, key: "opaque-key"},
		{name: "missing canonical slash", url: &url.URL{Path: "/opaque-key"}, kind: routeNotFound},
		{name: "agent nested", url: &url.URL{Path: "/opaque-key/static/out.js"}, kind: routeAgentRun, key: "opaque-key"},
		{name: "health reserved", url: &url.URL{Path: "/healthz/anything"}, kind: routeNotFound},
		{name: "oauth reserved", url: &url.URL{Path: "/oauth2/unknown"}, kind: routeNotFound},
		{name: "dot key", url: &url.URL{Path: "/./"}, kind: routeNotFound},
		{name: "encoded dot key", url: &url.URL{Path: "/./", RawPath: "/%2e/"}, kind: routeNotFound},
		{name: "nested dot", url: &url.URL{Path: "/key/../asset", RawPath: "/key/%2e%2e/asset"}, kind: routeNotFound},
		{name: "encoded slash", url: &url.URL{Path: "/key/other/", RawPath: "/key%2fother/"}, kind: routeNotFound},
		{name: "encoded backslash", url: &url.URL{Path: "/key\\other/", RawPath: "/key%5cother/"}, kind: routeNotFound},
		{name: "literal backslash", url: &url.URL{Path: "/key\\other/"}, kind: routeNotFound},
		{name: "double slash", url: &url.URL{Path: "/key//asset"}, kind: routeNotFound},
		{name: "raw path mismatch", url: &url.URL{Path: "/key/", RawPath: "/other/"}, kind: routeNotFound},
		{name: "malformed raw escape", url: &url.URL{Path: "/key/", RawPath: "/%zz/"}, kind: routeNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := ParsePath(test.url)
			if got.kind != test.kind || got.accessKey != test.key {
				t.Fatalf("ParsePath(%#v)=%#v, want kind=%v key=%q", test.url, got, test.kind, test.key)
			}
		})
	}
}

func TestPathModeDashboardLinkAndNestedProxy(t *testing.T) {
	requestURI := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestURI <- r.URL.RequestURI()
		_, _ = w.Write([]byte("proxied"))
	}))
	defer upstream.Close()
	run, pod := pathRoutableAgentRun(t, upstream.URL, "opaque-key")
	server := mustNewServer(t, pathTestConfig(authModeNone), fakeClient(t, &run, &pod))

	dashboard := httptest.NewRecorder()
	dashboardRequest := httptest.NewRequest(http.MethodGet, "https://agents.altinn.studio/", nil)
	dashboardRequest.Header.Set("X-Forwarded-Host", "evil.example")
	dashboardRequest.Header.Set("X-Forwarded-Proto", "http")
	server.ServeHTTP(dashboard, dashboardRequest)
	if dashboard.Code != http.StatusOK || !strings.Contains(dashboard.Body.String(), `href="https://agents.altinn.studio/opaque-key/"`) {
		t.Fatalf("dashboard status=%d body=%s", dashboard.Code, dashboard.Body.String())
	}
	if strings.Contains(dashboard.Body.String(), "evil.example") {
		t.Fatalf("dashboard trusted forwarded origin: %s", dashboard.Body.String())
	}

	proxyResponse := httptest.NewRecorder()
	server.ServeHTTP(proxyResponse, httptest.NewRequest(http.MethodGet, "https://agents.altinn.studio/opaque-key/static/out.js?theme=dark&n=1", nil))
	if proxyResponse.Code != http.StatusOK || proxyResponse.Body.String() != "proxied" {
		t.Fatalf("proxy status=%d body=%q", proxyResponse.Code, proxyResponse.Body.String())
	}
	if got := <-requestURI; got != "/static/out.js?theme=dark&n=1" {
		t.Fatalf("upstream request URI=%q", got)
	}
}

func TestPathModeOwnerDenialMatchesMissingAndAuthenticationPrecedesLookup(t *testing.T) {
	run := ownedAgentRun("run-1", "opaque-key", "https://github.com", "42", "owner")
	config := pathTestConfig(authModeGitHub)
	config.Auth = authenticatedTestConfig().Auth
	config.Auth.Session.Secure = true
	config.Auth.Authorization.Rules = []AuthorizationRule{{ID: "agent-owner", Effect: authorizationEffectAllow, Owner: true}}
	server := mustNewServer(t, config, fakeClient(t, &run))

	for _, path := range []string{"/opaque-key/", "/missing-key/"} {
		request := httptest.NewRequest(http.MethodGet, "https://agents.altinn.studio"+path, nil)
		request.Header.Set("Accept", "application/json")
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized || response.Body.String() != "authentication required\n" {
			t.Fatalf("unauthenticated path=%q status=%d body=%q", path, response.Code, response.Body.String())
		}
	}

	requestFor := func(path, subject string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "https://agents.altinn.studio"+path, nil)
		setTestPrincipalSession(t, server, request, Principal{Issuer: "https://github.com", Subject: subject})
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		return response
	}
	denied := requestFor("/opaque-key/", "99")
	missing := requestFor("/missing-key/", "99")
	if denied.Code != http.StatusNotFound || denied.Code != missing.Code || denied.Body.String() != missing.Body.String() {
		t.Fatalf("denied=(%d,%q) missing=(%d,%q)", denied.Code, denied.Body.String(), missing.Code, missing.Body.String())
	}
	allowed := requestFor("/opaque-key/", "42")
	if allowed.Code != http.StatusServiceUnavailable {
		t.Fatalf("owner status=%d body=%q", allowed.Code, allowed.Body.String())
	}
}

func TestPathModeOAuthUsesConfiguredOriginAndSafeReturnURLs(t *testing.T) {
	fixture := newGitHubOAuthFixture(t, "access-token", `{"id":42,"login":"owner"}`)
	config := pathTestConfig(authModeGitHub)
	config.Auth = authenticatedTestConfig().Auth
	config.Auth.Session.Secure = true
	config.Auth.GitHub.CallbackPath = "/oauth2/github/callback"
	config.Auth.GitHub.AuthorizationURL = fixture.URL + "/authorize"
	config.Auth.GitHub.TokenURL = fixture.URL + "/token"
	config.Auth.GitHub.UserURL = fixture.URL + "/user"
	server := mustNewServer(t, config, fakeClient(t))

	request := httptest.NewRequest(http.MethodGet, "https://agents.altinn.studio/opaque-key/editor?folder=repo", nil)
	request.Header.Set("X-Forwarded-Host", "evil.example")
	request.Header.Set("X-Forwarded-Proto", "http")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusFound {
		t.Fatalf("authentication redirect status=%d body=%q", response.Code, response.Body.String())
	}
	loginURL, err := url.Parse(response.Header().Get("Location"))
	if err != nil || loginURL.Scheme != "https" || loginURL.Host != "agents.altinn.studio" || loginURL.Path != "/oauth2/login" {
		t.Fatalf("login redirect=%q err=%v", response.Header().Get("Location"), err)
	}
	if got := loginURL.Query().Get("return_url"); got != "https://agents.altinn.studio/opaque-key/editor?folder=repo" {
		t.Fatalf("return_url=%q", got)
	}
	loginRequest := httptest.NewRequest(http.MethodGet, loginURL.String(), nil)
	loginResponse := httptest.NewRecorder()
	server.ServeHTTP(loginResponse, loginRequest)
	providerAuthorizeURL, err := url.Parse(loginResponse.Header().Get("Location"))
	if err != nil || providerAuthorizeURL.Query().Get("state") == "" {
		t.Fatalf("provider authorization redirect=%q err=%v", loginResponse.Header().Get("Location"), err)
	}
	if got := providerAuthorizeURL.Query().Get("redirect_uri"); got != "https://agents.altinn.studio/oauth2/github/callback" {
		t.Fatalf("OAuth redirect_uri=%q", got)
	}
	callbackRequest := httptest.NewRequest(http.MethodGet,
		"https://agents.altinn.studio/oauth2/github/callback?state="+url.QueryEscape(providerAuthorizeURL.Query().Get("state"))+"&code=test", nil)
	callbackRequest.AddCookie(cookieNamed(t, loginResponse, loginStateCookie))
	callbackResponse := httptest.NewRecorder()
	server.ServeHTTP(callbackResponse, callbackRequest)
	if callbackResponse.Code != http.StatusFound || callbackResponse.Header().Get("Location") != "https://agents.altinn.studio/opaque-key/editor?folder=repo" {
		t.Fatalf("callback status=%d location=%q body=%q", callbackResponse.Code, callbackResponse.Header().Get("Location"), callbackResponse.Body.String())
	}
	sessionCookie := cookieNamed(t, callbackResponse, defaultSessionCookie)
	if sessionCookie.Domain != "" || !sessionCookie.Secure {
		t.Fatalf("path-mode session cookie domain=%q secure=%v", sessionCookie.Domain, sessionCookie.Secure)
	}

	for _, test := range []struct {
		raw  string
		want bool
	}{
		{raw: "/", want: true},
		{raw: "/opaque-key/editor?folder=repo", want: true},
		{raw: "https://agents.altinn.studio/opaque-key/", want: true},
		{raw: "https://evil.example/opaque-key/"},
		{raw: "http://agents.altinn.studio/opaque-key/"},
		{raw: "//evil.example/opaque-key/"},
		{raw: "/key%2fother/"},
		{raw: "/oauth2/login"},
		{raw: "/key/../other"},
	} {
		if _, got := server.auth.validateReturnURL(test.raw, request); got != test.want {
			t.Fatalf("validateReturnURL(%q)=%v, want %v", test.raw, got, test.want)
		}
	}

	logout := httptest.NewRecorder()
	server.ServeHTTP(logout, httptest.NewRequest(http.MethodGet, "https://agents.altinn.studio/oauth2/logout", nil))
	if logout.Code != http.StatusFound || logout.Header().Get("Location") != "/" {
		t.Fatalf("logout status=%d location=%q", logout.Code, logout.Header().Get("Location"))
	}
	unknownOAuth := httptest.NewRecorder()
	server.ServeHTTP(unknownOAuth, httptest.NewRequest(http.MethodGet, "https://agents.altinn.studio/oauth2/not-gateway-owned", nil))
	if unknownOAuth.Code != http.StatusNotFound {
		t.Fatalf("reserved OAuth path status=%d", unknownOAuth.Code)
	}
	ambiguousOAuth := httptest.NewRecorder()
	server.ServeHTTP(ambiguousOAuth, httptest.NewRequest(http.MethodGet, "https://agents.altinn.studio/oauth2%2flogin", nil))
	if ambiguousOAuth.Code != http.StatusNotFound {
		t.Fatalf("encoded OAuth separator status=%d", ambiguousOAuth.Code)
	}
	wrongOrigin := httptest.NewRecorder()
	server.ServeHTTP(wrongOrigin, httptest.NewRequest(http.MethodGet, "https://internal.invalid/oauth2/login", nil))
	if wrongOrigin.Code != http.StatusNotFound {
		t.Fatalf("wrong-origin OAuth request status=%d", wrongOrigin.Code)
	}
}

func TestPathModeWebSocketUpgradeStripsOnlyRoutingPrefix(t *testing.T) {
	type upstreamRequest struct {
		path           string
		forwarded      string
		forwardedHost  string
		forwardedProto string
		origin         string
	}
	upstreamCall := make(chan upstreamRequest, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCall <- upstreamRequest{
			path: r.URL.RequestURI(), forwarded: r.Header.Get("Forwarded"), forwardedHost: r.Header.Get("X-Forwarded-Host"),
			forwardedProto: r.Header.Get("X-Forwarded-Proto"), origin: r.Header.Get("Origin"),
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("upstream response does not support hijacking")
			return
		}
		connection, buffer, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer connection.Close()
		_, _ = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = buffer.Flush()
	}))
	defer upstream.Close()
	run, pod := pathRoutableAgentRun(t, upstream.URL, "opaque-key")
	server := mustNewServer(t, pathTestConfig(authModeNone), fakeClient(t, &run, &pod))
	gatewayServer := httptest.NewServer(server)
	defer gatewayServer.Close()

	gatewayURL, _ := url.Parse(gatewayServer.URL)
	connection, err := net.DialTimeout("tcp", gatewayURL.Host, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = fmt.Fprintf(connection, "GET /opaque-key/websocket?reconnect=1 HTTP/1.1\r\nHost: agents.altinn.studio\r\nOrigin: https://agents.altinn.studio\r\nForwarded: host=evil.example;proto=http\r\nX-Forwarded-Host: evil.example\r\nX-Forwarded-Proto: http\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGVzdA==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status=%d", response.StatusCode)
	}
	got := <-upstreamCall
	if got.path != "/websocket?reconnect=1" || got.forwarded != "" || got.forwardedHost != "agents.altinn.studio" || got.forwardedProto != "https" || got.origin != "https://agents.altinn.studio" {
		t.Fatalf("upstream WebSocket request=%#v", got)
	}
}

func TestRealCodeServerPathMode(t *testing.T) {
	upstreamURL := os.Getenv("NVT_GATEWAY_CODE_SERVER_SMOKE_URL")
	if upstreamURL == "" {
		t.Skip("set NVT_GATEWAY_CODE_SERVER_SMOKE_URL to run the real code-server path proof")
	}
	run, pod := pathRoutableAgentRun(t, upstreamURL, "opaque-key")
	server := mustNewServer(t, pathTestConfig(authModeNone), fakeClient(t, &run, &pod))

	requestGateway := func(rawURL string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, rawURL, nil))
		return response
	}
	initialURL, _ := url.Parse("https://agents.altinn.studio/opaque-key/")
	initial := requestGateway(initialURL.String())
	if initial.Code != http.StatusFound {
		t.Fatalf("initial code-server response status=%d body=%q", initial.Code, initial.Body.String())
	}
	redirect, err := url.Parse(initial.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	workbenchURL := initialURL.ResolveReference(redirect)
	workbench := requestGateway(workbenchURL.String())
	if workbench.Code != http.StatusOK || !strings.Contains(workbench.Body.String(), "vscode-workbench-web-configuration") {
		t.Fatalf("workbench status=%d body-prefix=%q", workbench.Code, truncateForTest(workbench.Body.String(), 200))
	}
	assetMatch := regexp.MustCompile(`src="([^"]*stable-[^"]+\.js)"`).FindStringSubmatch(workbench.Body.String())
	if len(assetMatch) != 2 {
		t.Fatalf("workbench HTML did not contain a versioned script asset")
	}
	assetReference, err := url.Parse(assetMatch[1])
	if err != nil {
		t.Fatal(err)
	}
	asset := requestGateway(workbenchURL.ResolveReference(assetReference).String())
	if asset.Code != http.StatusOK || asset.Body.Len() == 0 {
		t.Fatalf("static asset status=%d bytes=%d", asset.Code, asset.Body.Len())
	}

	gatewayServer := httptest.NewServer(server)
	defer gatewayServer.Close()
	gatewayURL, _ := url.Parse(gatewayServer.URL)
	connection, err := net.DialTimeout("tcp", gatewayURL.Host, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = fmt.Fprintf(connection, "GET /opaque-key/ HTTP/1.1\r\nHost: agents.altinn.studio\r\nOrigin: https://agents.altinn.studio\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGVzdC1jb2RlLXNlcnZlcg==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	websocketResponse, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	defer websocketResponse.Body.Close()
	if websocketResponse.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("code-server WebSocket status=%d", websocketResponse.StatusCode)
	}
}

func truncateForTest(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func pathTestConfig(authMode string) Config {
	return Config{
		PublicURL: "https://agents.altinn.studio", ListenAddr: ":8080", DefaultTargetPort: 4090,
		Routing: RoutingConfig{Mode: routingModePath}, Auth: AuthConfig{Mode: authMode},
	}
}

func pathRoutableAgentRun(t *testing.T, upstreamURL, key string) (nvtv1alpha1.AgentRun, corev1.Pod) {
	t.Helper()
	parsed, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatal(err)
	}
	run := nvtv1alpha1.AgentRun{ObjectMeta: metav1.ObjectMeta{
		Namespace: "nvt", Name: "path-run", Annotations: map[string]string{
			AccessKeyAnnotation: key, AccessPortAnnotation: strconv.Itoa(port), DisplayNameAnnotation: "Path run",
		},
	}}
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nvt", Name: "path-pod", Labels: map[string]string{AgentRunPodLabel: run.Name}},
		Status:     readyPodStatus(parsed.Hostname()),
	}
	return run, pod
}
