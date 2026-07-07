package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"golang.org/x/oauth2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestParseHost(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		baseDomain string
		wantKind   routeKind
		wantKey    string
	}{
		{name: "base", host: "agents.localhost", baseDomain: "agents.localhost", wantKind: routeDashboard},
		{name: "base with port", host: "agents.localhost:4090", baseDomain: "agents.localhost", wantKind: routeDashboard},
		{name: "key", host: "run-1.agents.localhost", baseDomain: "agents.localhost", wantKind: routeAgentRun, wantKey: "run-1"},
		{name: "key with port", host: "run-1.agents.localhost:4090", baseDomain: "agents.localhost", wantKind: routeAgentRun, wantKey: "run-1"},
		{name: "nested prefix ignored", host: "x.run-1.agents.localhost", baseDomain: "agents.localhost", wantKind: routeNotFound},
		{name: "other host", host: "example.test", baseDomain: "agents.localhost", wantKind: routeNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseHost(tt.host, tt.baseDomain)
			if got.kind != tt.wantKind || got.accessKey != tt.wantKey {
				t.Fatalf("ParseHost() = %#v, want kind=%v key=%q", got, tt.wantKind, tt.wantKey)
			}
		})
	}
}

func TestResolveTarget(t *testing.T) {
	client := fakeClient(t,
		&nvtv1alpha1.AgentRun{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "nvt",
				Name:      "run-1",
				Annotations: map[string]string{
					AccessKeyAnnotation:  "access-1",
					AccessPortAnnotation: "4999",
				},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "nvt",
				Name:      "run-1-agent",
				Labels:    map[string]string{AgentRunPodLabel: "run-1"},
			},
			Status: readyPodStatus("10.0.0.9"),
		},
	)
	server := mustNewServer(t, Config{BaseDomain: "agents.localhost", ListenAddr: ":8080", DefaultTargetPort: 4090}, client)
	target, err := server.resolveTarget(t.Context(), "access-1")
	if err != nil {
		t.Fatal(err)
	}
	if target.PodIP != "10.0.0.9" || target.Port != 4999 || target.AgentRun.Name != "run-1" {
		t.Fatalf("target = %#v", target)
	}
}

func TestResolveTargetNoRunningPod(t *testing.T) {
	client := fakeClient(t,
		&nvtv1alpha1.AgentRun{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   "nvt",
				Name:        "run-1",
				Annotations: map[string]string{AccessKeyAnnotation: "access-1"},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "nvt",
				Name:      "run-1-agent",
				Labels:    map[string]string{AgentRunPodLabel: "run-1"},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.9"},
		},
	)
	server := mustNewServer(t, Config{BaseDomain: "agents.localhost", ListenAddr: ":8080", DefaultTargetPort: 4090}, client)
	_, err := server.resolveTarget(t.Context(), "access-1")
	if err != errNoRunningPod {
		t.Fatalf("err = %v, want errNoRunningPod", err)
	}
}

func TestDashboardListsAgentRuns(t *testing.T) {
	created := metav1.NewTime(time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC))
	client := fakeClient(t,
		&nvtv1alpha1.AgentRun{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:         "nvt",
				Name:              "run-1",
				CreationTimestamp: created,
				Annotations: map[string]string{
					AccessKeyAnnotation:   "access-1",
					DisplayNameAnnotation: "Issue #7 - PR create",
					RequestedByAnnotation: "alice",
					SourceURLAnnotation:   "https://github.test/acme/widget/issues/7#issuecomment-1",
				},
			},
			Status: nvtv1alpha1.AgentRunStatus{Phase: nvtv1alpha1.AgentRunPhaseRunning},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "nvt",
				Name:      "run-1-agent",
				Labels:    map[string]string{AgentRunPodLabel: "run-1"},
			},
			Status: readyPodStatus("10.0.0.9"),
		},
	)
	server := mustNewServer(t, Config{BaseDomain: "agents.localhost", ListenAddr: ":8080", DefaultTargetPort: 4090}, client)
	req := httptest.NewRequest(http.MethodGet, "http://agents.localhost:4090/", nil)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, body)
	}
	for _, want := range []string{"Issue #7 - PR create", "Running", "alice", "Open Session", "http://access-1.agents.localhost:4090/"} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard missing %q in:\n%s", want, body)
		}
	}
}

func TestHealthzDoesNotRequireKubernetes(t *testing.T) {
	server := mustNewServer(t, Config{BaseDomain: "agents.localhost", ListenAddr: ":8080", DefaultTargetPort: 4090}, nil)
	req := httptest.NewRequest(http.MethodGet, "http://not-the-base-host/healthz", nil)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Body.String() != "ok\n" {
		t.Fatalf("body = %q", recorder.Body.String())
	}
}

func TestAuthModeNonePreservesDashboardBehavior(t *testing.T) {
	client := fakeClient(t)
	server := mustNewServer(t, Config{
		BaseDomain:        "agents.localhost",
		ListenAddr:        ":8080",
		DefaultTargetPort: 4090,
		Auth:              AuthConfig{Mode: "none"},
	}, client)
	req := httptest.NewRequest(http.MethodGet, "http://agents.localhost:4090/", nil)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAuthModeOIDCRedirectsUnauthenticatedDashboardAndSession(t *testing.T) {
	provider := oidcDiscoveryServer(t)
	client := fakeClient(t,
		&nvtv1alpha1.AgentRun{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   "nvt",
				Name:        "run-1",
				Annotations: map[string]string{AccessKeyAnnotation: "access-1"},
			},
		},
	)
	server := mustNewServer(t, oidcTestConfig(provider.URL), client)

	for _, target := range []string{"http://agents.localhost:4090/", "http://access-1.agents.localhost:4090/"} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Header.Set("Accept", "text/html")
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusFound {
			t.Fatalf("target %s status = %d body=%s", target, recorder.Code, recorder.Body.String())
		}
		location := recorder.Header().Get("Location")
		if !strings.Contains(location, "/oauth2/login?return_url=") {
			t.Fatalf("target %s location = %q", target, location)
		}
	}
}

func TestAuthModeOIDCAuthenticatedWithoutAuthorizationRuleIsDenied(t *testing.T) {
	provider := oidcDiscoveryServer(t)
	server := mustNewServer(t, oidcTestConfig(provider.URL), fakeClient(t))
	req := httptest.NewRequest(http.MethodGet, "http://agents.localhost:4090/", nil)
	setTestSession(t, server, req, "user-1", map[string]any{"sub": "user-1"})
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAuthModeOIDCAnyAuthenticatedRuleAllowsAccess(t *testing.T) {
	provider := oidcDiscoveryServer(t)
	config := oidcTestConfig(provider.URL)
	config.Auth.Authorization.Rules = []AuthorizationRule{{
		ID:            "any-authenticated",
		Effect:        authorizationEffectAllow,
		Authenticated: true,
	}}
	server := mustNewServer(t, config, fakeClient(t))
	req := httptest.NewRequest(http.MethodGet, "http://agents.localhost:4090/", nil)
	setTestSession(t, server, req, "user-1", map[string]any{"sub": "user-1"})
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAuthModeOIDCSimpleClaimRuleAllowsAccess(t *testing.T) {
	provider := oidcDiscoveryServer(t)
	config := oidcTestConfig(provider.URL)
	config.Auth.Authorization.Rules = []AuthorizationRule{{
		ID:        "admins",
		Effect:    authorizationEffectAllow,
		ClaimPath: "groups[]",
		Values:    []string{"nvt-agent-admins"},
	}}
	server := mustNewServer(t, config, fakeClient(t))
	req := httptest.NewRequest(http.MethodGet, "http://agents.localhost:4090/", nil)
	setTestSession(t, server, req, "user-1", map[string]any{"sub": "user-1", "groups": []any{"nvt-agent-admins"}})
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAuthorizationWhereArrayRequiresSameElementMatch(t *testing.T) {
	policy := AuthorizationConfig{Rules: []AuthorizationRule{{
		ID:     "allowed-altinn-org",
		Effect: authorizationEffectAllow,
		Where: AuthorizationWhere{
			Array: "authorization_details[].authorized_parties[]",
			All: []AuthorizationCondition{
				{ClaimPath: "orgno.ID", Values: []string{"0192:991825827"}},
				{ClaimPath: "resource", Values: []string{"digdir-selvbetjening-klienter"}},
			},
		},
	}}}
	claims := map[string]any{
		"authorization_details": []any{map[string]any{
			"authorized_parties": []any{
				map[string]any{"orgno": map[string]any{"ID": "0192:991825827"}, "resource": "digdir-selvbetjening-klienter"},
			},
		}},
	}
	decision := EvaluateAuthorization(policy, claims)
	if !decision.Allowed || decision.RuleID != "allowed-altinn-org" {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestAuthorizationWhereArrayDeniesSplitElementMatch(t *testing.T) {
	policy := AuthorizationConfig{Rules: []AuthorizationRule{{
		ID:     "allowed-altinn-org",
		Effect: authorizationEffectAllow,
		Where: AuthorizationWhere{
			Array: "authorization_details[].authorized_parties[]",
			All: []AuthorizationCondition{
				{ClaimPath: "orgno.ID", Values: []string{"0192:991825827"}},
				{ClaimPath: "resource", Values: []string{"digdir-selvbetjening-klienter"}},
			},
		},
	}}}
	claims := map[string]any{
		"authorization_details": []any{map[string]any{
			"authorized_parties": []any{
				map[string]any{"orgno": map[string]any{"ID": "0192:991825827"}, "resource": "other"},
				map[string]any{"orgno": map[string]any{"ID": "0192:000000000"}, "resource": "digdir-selvbetjening-klienter"},
			},
		}},
	}
	decision := EvaluateAuthorization(policy, claims)
	if decision.Allowed {
		t.Fatalf("split element match allowed: %#v", decision)
	}
}

func TestAuthorizationRejectsSensitiveClaimPath(t *testing.T) {
	config := AuthorizationConfig{Rules: []AuthorizationRule{{
		ID:        "bad",
		Effect:    authorizationEffectAllow,
		ClaimPath: "pid",
		Values:    []string{"01017012345"},
	}}}
	if err := config.validate(); err == nil || !strings.Contains(err.Error(), "must not use pid") {
		t.Fatalf("expected sensitive claim path error, got %v", err)
	}
}

func TestAuthorizationRejectsSensitiveWhereArrayPath(t *testing.T) {
	config := AuthorizationConfig{Rules: []AuthorizationRule{{
		ID:     "bad",
		Effect: authorizationEffectAllow,
		Where: AuthorizationWhere{
			Array: "authorization_details[].pid[]",
			All:   []AuthorizationCondition{{ClaimPath: "value", Values: []string{"01017012345"}}},
		},
	}}}
	if err := config.validate(); err == nil || !strings.Contains(err.Error(), "where.array must not use pid") {
		t.Fatalf("expected sensitive where.array error, got %v", err)
	}
}

func TestSessionCookieDoesNotCarryLargeClaims(t *testing.T) {
	provider := oidcDiscoveryServer(t)
	server := mustNewServer(t, oidcTestConfig(provider.URL), fakeClient(t))
	claims := map[string]any{
		"sub":                   "user-1",
		"pid":                   "01017012345",
		"authorization_details": largeAuthorizationDetails(),
	}
	req := httptest.NewRequest(http.MethodGet, "http://agents.localhost:4090/", nil)
	cookie := setTestSession(t, server, req, "user-1", claims)
	if strings.Contains(cookie.Value, "authorization_details") || strings.Contains(cookie.Value, "01017012345") {
		t.Fatalf("session cookie leaked claim material: %q", cookie.Value)
	}
	if len(cookie.String()) > 1024 {
		t.Fatalf("session cookie too large: %d bytes", len(cookie.String()))
	}
	stored := server.auth.sessions[mustReadSessionID(t, server, cookie)]
	if _, ok := stored.Claims["pid"]; ok {
		t.Fatalf("stored authorization claims retained forbidden pid: %#v", stored.Claims)
	}
	if _, ok := stored.Claims["authorization_details"]; !ok {
		t.Fatalf("stored authorization claims lost needed authorization_details: %#v", stored.Claims)
	}
}

func TestAuthorizationClaimSourceUserInfo(t *testing.T) {
	provider := oidcDiscoveryServer(t)
	config := oidcTestConfig(provider.URL)
	config.Auth.Authorization.ClaimSource = claimSourceUserInfo
	server := mustNewServer(t, config, fakeClient(t))
	claims, err := server.auth.authorizationClaims(t.Context(), &oauth2.Token{AccessToken: "opaque-userinfo-token"}, nil, map[string]any{"sub": "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if claimPathMatches(claims, "groups[]", []string{"nvt-agent-admins"}) != true {
		t.Fatalf("userinfo claims not loaded: %#v", claims)
	}
}

func TestAuthorizationClaimSourceAccessTokenRequiresJWT(t *testing.T) {
	provider := oidcDiscoveryServer(t)
	config := oidcTestConfig(provider.URL)
	config.Auth.Authorization.ClaimSource = claimSourceAccessToken
	server := mustNewServer(t, config, fakeClient(t))
	if _, err := server.auth.authorizationClaims(t.Context(), &oauth2.Token{AccessToken: "opaque"}, nil, map[string]any{"sub": "user-1"}); err == nil || !strings.Contains(err.Error(), "requires a JWT access token") {
		t.Fatalf("expected opaque access token to fail closed, got %v", err)
	}
}

func TestOIDCExtraAuthorizeParamsAreIncludedOnAuthorizeURL(t *testing.T) {
	provider := oidcDiscoveryServer(t)
	config := oidcTestConfig(provider.URL)
	config.Auth.OIDC.ExtraAuthParams = map[string]string{
		"prompt":                "login",
		"authorization_details": `[{"type":"ansattporten:altinn:resource"}]`,
	}
	server := mustNewServer(t, config, fakeClient(t))
	req := httptest.NewRequest(http.MethodGet, "http://agents.localhost/oauth2/login", nil)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := location.Query().Get("prompt"); got != "login" {
		t.Fatalf("prompt = %q", got)
	}
	if got := location.Query().Get("authorization_details"); !strings.Contains(got, "ansattporten:altinn:resource") {
		t.Fatalf("authorization_details = %q", got)
	}
}

func TestAuthorizationLogIsSanitized(t *testing.T) {
	provider := oidcDiscoveryServer(t)
	config := oidcTestConfig(provider.URL)
	config.Auth.Authorization.Rules = []AuthorizationRule{{
		ID:        "admins",
		Effect:    authorizationEffectAllow,
		ClaimPath: "groups[]",
		Values:    []string{"nvt-agent-admins"},
	}}
	server := mustNewServer(t, config, fakeClient(t,
		&nvtv1alpha1.AgentRun{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   "nvt",
				Name:        "run-1",
				Annotations: map[string]string{AccessKeyAnnotation: "access-1"},
			},
		},
	))
	var logs bytes.Buffer
	previousOutput := log.Writer()
	previousFlags := log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousOutput)
		log.SetFlags(previousFlags)
	})
	req := httptest.NewRequest(http.MethodGet, "http://access-1.agents.localhost:4090/", nil)
	setTestSession(t, server, req, "subject-sensitive", map[string]any{
		"sub":                   "subject-sensitive",
		"pid":                   "01017012345",
		"fødselsnummer":         "01017012345",
		"authorization_details": []any{map[string]any{"secret": "full-authorization-details"}},
	})
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	logged := logs.String()
	for _, forbidden := range []string{"01017012345", "subject-sensitive", "full-authorization-details", "authorization_details", "pid", "fødselsnummer"} {
		if strings.Contains(logged, forbidden) {
			t.Fatalf("log leaked %q: %s", forbidden, logged)
		}
	}
	for _, want := range []string{"decision=deny", "rule=-", "agent=access-1", "subject_hash="} {
		if !strings.Contains(logged, want) {
			t.Fatalf("log missing %q: %s", want, logged)
		}
	}
}

func TestAuthModeOIDCAgentSubdomainRedirectsToStableLoginHost(t *testing.T) {
	provider := oidcDiscoveryServer(t)
	server := mustNewServer(t, oidcTestConfigWithPublicURL(provider.URL, "https://agents.localhost"), fakeClient(t))
	req := httptest.NewRequest(http.MethodGet, "https://access-1.agents.localhost/session", nil)
	req.Header.Set("Accept", "text/html")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	location := recorder.Header().Get("Location")
	if !strings.HasPrefix(location, "https://agents.localhost/oauth2/login?return_url=") {
		t.Fatalf("location = %q", location)
	}
	if !strings.Contains(location, url.QueryEscape("https://access-1.agents.localhost/session")) {
		t.Fatalf("location missing original return URL: %q", location)
	}
}

func TestAuthCodeURLUsesStablePublicCallbackURL(t *testing.T) {
	provider := oidcDiscoveryServer(t)
	server := mustNewServer(t, oidcTestConfigWithPublicURL(provider.URL, "https://agents.localhost"), fakeClient(t))
	req := httptest.NewRequest(http.MethodGet, "https://agents.localhost/oauth2/login?return_url="+url.QueryEscape("https://access-1.agents.localhost/"), nil)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := location.Query().Get("redirect_uri"); got != "https://agents.localhost/oauth2/callback" {
		t.Fatalf("redirect_uri = %q", got)
	}
}

func TestAuthCodeURLUsesForwardedHeadersWhenPublicURLIsEmpty(t *testing.T) {
	provider := oidcDiscoveryServer(t)
	server := mustNewServer(t, oidcTestConfig(provider.URL), fakeClient(t))
	req := httptest.NewRequest(http.MethodGet, "http://agents.localhost/oauth2/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "agents.example.com")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := location.Query().Get("redirect_uri"); got != "https://agents.example.com/oauth2/callback" {
		t.Fatalf("redirect_uri = %q", got)
	}
}

func TestAuthModeOIDCHealthzIsPublic(t *testing.T) {
	provider := oidcDiscoveryServer(t)
	server := mustNewServer(t, oidcTestConfig(provider.URL), nil)
	req := httptest.NewRequest(http.MethodGet, "http://agents.localhost:4090/healthz", nil)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAuthModeOIDCLogoutClearsCookies(t *testing.T) {
	provider := oidcDiscoveryServer(t)
	server := mustNewServer(t, oidcTestConfig(provider.URL), nil)
	req := httptest.NewRequest(http.MethodGet, "http://agents.localhost:4090/oauth2/logout", nil)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	cleared := 0
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.MaxAge < 0 {
			cleared++
		}
	}
	if cleared != 2 {
		t.Fatalf("cleared cookies = %d, want 2", cleared)
	}
}

func TestOIDCReturnURLRejectsUnsafeExternalURL(t *testing.T) {
	provider := oidcDiscoveryServer(t)
	server := mustNewServer(t, oidcTestConfig(provider.URL), nil)
	req := httptest.NewRequest(http.MethodGet, "http://agents.localhost:4090/oauth2/login?return_url="+url.QueryEscape("https://evil.test/"), nil)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func mustNewServer(t *testing.T, config Config, client ctrlclient.Client) *Server {
	t.Helper()
	server, err := NewServer(config, client, "nvt")
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func setTestSession(t *testing.T, server *Server, req *http.Request, subject string, claims map[string]any) *http.Cookie {
	t.Helper()
	sessionID := randomToken()
	expiresAt := time.Now().Add(time.Hour).Unix()
	server.auth.storeSession(sessionID, storedSession{Subject: subject, ExpiresAt: expiresAt, Claims: stripSensitiveClaims(claims)})
	recorder := httptest.NewRecorder()
	server.auth.setCookie(recorder, server.auth.config.Auth.Session.CookieName, sessionCookie{
		ID:        sessionID,
		ExpiresAt: expiresAt,
	}, server.auth.config.Auth.Session.MaxAgeSeconds)
	cookies := recorder.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("session cookie was not set")
	}
	req.AddCookie(cookies[0])
	return cookies[0]
}

func mustReadSessionID(t *testing.T, server *Server, cookie *http.Cookie) string {
	t.Helper()
	var session sessionCookie
	if err := server.auth.cookieCodec.Decode(server.auth.config.Auth.Session.CookieName, cookie.Value, &session); err != nil {
		t.Fatal(err)
	}
	return session.ID
}

func largeAuthorizationDetails() []any {
	parties := make([]any, 0, 40)
	for index := 0; index < 40; index++ {
		parties = append(parties, map[string]any{
			"orgno":    map[string]any{"ID": fmt.Sprintf("0192:%09d", index)},
			"resource": strings.Repeat("digdir-selvbetjening-klienter-", 4),
		})
	}
	return []any{map[string]any{"authorized_parties": parties}}
}

func oidcTestConfig(issuer string) Config {
	return Config{
		BaseDomain:        "agents.localhost",
		ListenAddr:        ":8080",
		DefaultTargetPort: 4090,
		Auth: AuthConfig{
			Mode: authModeOIDC,
			Session: SessionConfig{
				Secret:        "0123456789abcdef0123456789abcdef",
				CookieName:    defaultSessionCookie,
				MaxAgeSeconds: defaultSessionMaxAge,
				Secure:        true,
			},
			OIDC: OIDCConfig{
				IssuerURL:    issuer,
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				Scopes:       []string{"openid", "profile"},
				CallbackPath: defaultCallbackPath,
			},
		},
	}
}

func oidcTestConfigWithPublicURL(issuer, publicURL string) Config {
	config := oidcTestConfig(issuer)
	config.PublicURL = publicURL
	return config
}

func oidcDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(t, w, map[string]any{
				"issuer":                                issuer,
				"authorization_endpoint":                issuer + "/auth",
				"token_endpoint":                        issuer + "/token",
				"userinfo_endpoint":                     issuer + "/userinfo",
				"jwks_uri":                              issuer + "/jwks",
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/jwks":
			writeJSON(t, w, map[string]any{"keys": []any{}})
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer opaque-userinfo-token" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			writeJSON(t, w, map[string]any{
				"sub":    "user-1",
				"groups": []any{"nvt-agent-admins"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	issuer = server.URL
	t.Cleanup(server.Close)
	return server
}

func writeJSON(t *testing.T, w http.ResponseWriter, value map[string]any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(raw)
}

func fakeClient(t *testing.T, objects ...runtime.Object) ctrlclient.Client {
	t.Helper()
	s := runtime.NewScheme()
	if err := scheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := nvtv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return ctrlfake.NewClientBuilder().WithScheme(s).WithRuntimeObjects(objects...).Build()
}

func readyPodStatus(podIP string) corev1.PodStatus {
	return corev1.PodStatus{
		Phase: corev1.PodRunning,
		PodIP: podIP,
		Conditions: []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionTrue},
		},
	}
}
