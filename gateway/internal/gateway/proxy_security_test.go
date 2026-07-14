package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

func TestProxyIsolatesGatewayCookiesAndScopesAgentCookies(t *testing.T) {
	const loginCanary = "gateway-login-state-canary"
	upstreamCookies := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		upstreamCookies <- request.Header.Get("Cookie")
		response.Header().Add("Set-Cookie", defaultSessionCookie+"=agent-overwrite; Path=/")
		response.Header().Add("Set-Cookie", loginStateCookie+"=agent-overwrite; Path=/")
		response.Header().Add("Set-Cookie", "agent-theme=dark; Domain=agent.invalid; Path=/; HttpOnly; SameSite=Lax")
		response.Header().Add("Set-Cookie", "__Host-agent=unsafe-prefix; Secure; Path=/")
		response.Header().Add("Set-Cookie", "malformed cookie without equals")
		_, _ = response.Write([]byte("ok"))
	}))
	defer upstream.Close()
	run, pod := pathRoutableAgentRun(t, upstream.URL, "routing-key")
	run.Spec.ProfileProvenance = &nvtv1alpha1.AgentRunProfileProvenance{Principal: &nvtv1alpha1.AgentRunPrincipal{
		Issuer: "https://github.com", Subject: "42", DisplayName: "owner",
	}}
	config := pathTestConfig(authModeGitHub)
	config.Auth = authenticatedTestConfig().Auth
	config.Auth.Session.Secure = true
	config.Auth.Authorization.Rules = []AuthorizationRule{{ID: "agent-owner", Effect: authorizationEffectAllow, Owner: true}}
	server := mustNewServer(t, config, fakeClient(t, &run, &pod))

	request := httptest.NewRequest(http.MethodGet, "https://agents.altinn.studio/routing-key/", nil)
	sessionCookie := setTestPrincipalSession(t, server, request, Principal{Issuer: "https://github.com", Subject: "42"})
	request.AddCookie(&http.Cookie{Name: loginStateCookie, Value: loginCanary})
	request.AddCookie(&http.Cookie{Name: "agent-preference", Value: "kept"})
	request.Header.Add("Cookie", "broken-cookie-field")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("proxy status=%d body=%q", response.Code, response.Body.String())
	}
	gotUpstreamCookies := <-upstreamCookies
	for _, forbidden := range []string{defaultSessionCookie, sessionCookie.Value, loginStateCookie, loginCanary} {
		if strings.Contains(gotUpstreamCookies, forbidden) {
			t.Fatalf("gateway cookie material reached upstream: %q", gotUpstreamCookies)
		}
	}
	if gotUpstreamCookies != "agent-preference=kept" {
		t.Fatalf("upstream cookies=%q", gotUpstreamCookies)
	}

	setCookies := response.Header().Values("Set-Cookie")
	if len(setCookies) != 1 {
		t.Fatalf("filtered Set-Cookie headers=%q", setCookies)
	}
	if !strings.HasPrefix(setCookies[0], "agent-theme=dark") || !strings.Contains(setCookies[0], "Path=/routing-key/") || strings.Contains(strings.ToLower(setCookies[0]), "domain=") {
		t.Fatalf("agent cookie was not host-only and path-scoped: %q", setCookies[0])
	}
	for _, forbidden := range []string{defaultSessionCookie, loginStateCookie, "agent-overwrite", "malformed", "__Host-agent"} {
		if strings.Contains(strings.Join(setCookies, "\n"), forbidden) {
			t.Fatalf("unsafe upstream Set-Cookie survived: %q", setCookies)
		}
	}
}

func TestCookieFiltersPreserveUnrelatedSubdomainCookies(t *testing.T) {
	header := http.Header{"Cookie": {"custom_gateway=secret; agent=kept", loginStateCookie + "=state; second=kept-too"}}
	filterUpstreamRequestCookies(header, gatewayCookieNames("custom_gateway"))
	if got := header.Get("Cookie"); got != "agent=kept; second=kept-too" {
		t.Fatalf("filtered request cookies=%q", got)
	}
	response := &http.Response{Header: http.Header{"Set-Cookie": {
		"custom_gateway=overwrite; Path=/", loginStateCookie + "=overwrite; Path=/", "agent=kept; Domain=agent.example; Path=/custom",
	}}}
	filterUpstreamResponseCookies(response, gatewayCookieNames("custom_gateway"), "")
	if got := response.Header.Values("Set-Cookie"); len(got) != 1 || !strings.Contains(got[0], "Domain=agent.example") || !strings.Contains(got[0], "Path=/custom") {
		t.Fatalf("subdomain response cookies=%q", got)
	}
}
