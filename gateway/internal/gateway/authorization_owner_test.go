package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestOwnerAuthorizationUsesExactIssuerAndSubjectOnly(t *testing.T) {
	policy := AuthorizationConfig{Rules: []AuthorizationRule{{ID: "agent-owner", Effect: authorizationEffectAllow, Owner: true}}}
	run := ownedAgentRun("run-1", "access-1", "https://github.com", "42", "old-login")
	for _, test := range []struct {
		name      string
		principal Principal
		want      bool
	}{
		{name: "exact owner despite display rename", principal: Principal{Issuer: "https://github.com", Subject: "42", DisplayName: "new-login"}, want: true},
		{name: "different subject", principal: Principal{Issuer: "https://github.com", Subject: "43"}},
		{name: "same subject different issuer", principal: Principal{Issuer: "https://issuer.example", Subject: "42"}},
		{name: "missing issuer", principal: Principal{Subject: "42"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := EvaluateAuthorization(policy, test.principal, &run).Allowed; got != test.want {
				t.Fatalf("allowed = %v, want %v", got, test.want)
			}
		})
	}
	legacy := nvtv1alpha1.AgentRun{}
	if EvaluateAuthorization(policy, Principal{Issuer: "https://github.com", Subject: "42"}, &legacy).Allowed {
		t.Fatal("owner rule allowed an AgentRun without immutable profile provenance")
	}
}

func TestOwnerRuleValidationRequiresExactlyOnePredicate(t *testing.T) {
	valid := AuthorizationConfig{Rules: []AuthorizationRule{{ID: "owner", Effect: authorizationEffectAllow, Owner: true}}}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	for _, rule := range []AuthorizationRule{
		{ID: "missing", Effect: authorizationEffectAllow},
		{ID: "ambiguous-authenticated", Effect: authorizationEffectAllow, Owner: true, Authenticated: true},
		{ID: "ambiguous-claim", Effect: authorizationEffectAllow, Owner: true, ClaimPath: "groups[]", Values: []string{"admins"}},
	} {
		if err := (AuthorizationConfig{Rules: []AuthorizationRule{rule}}).validate(); err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Fatalf("rule %#v validation error = %v, want exactly-one failure", rule, err)
		}
	}
}

func TestOwnerOnlyDashboardShowsOnlyOwnedAgentRuns(t *testing.T) {
	owned := ownedAgentRun("owned-run", "owned-key", "https://github.com", "42", "old-login")
	owned.Annotations[DisplayNameAnnotation] = "Owned run"
	owned.Annotations[RequestedByAnnotation] = "owned-display"
	owned.Annotations[SourceURLAnnotation] = "https://source.example/owned"
	other := ownedAgentRun("hidden-run", "hidden-key", "https://github.com", "99", "hidden-login")
	other.Annotations[DisplayNameAnnotation] = "Hidden run canary"
	other.Annotations[RequestedByAnnotation] = "hidden-requester-canary"
	other.Annotations[SourceURLAnnotation] = "https://source.example/hidden-canary"
	other.Status.Phase = nvtv1alpha1.AgentRunPhaseFailed

	config := authenticatedTestConfig()
	config.Auth.Authorization.Rules = []AuthorizationRule{{ID: "agent-owner", Effect: authorizationEffectAllow, Owner: true}}
	server := mustNewServer(t, config, fakeClient(t, &owned, &other))
	request := httptest.NewRequest(http.MethodGet, "http://agents.localhost/", nil)
	setTestPrincipalSession(t, server, request, Principal{Issuer: "https://github.com", Subject: "42", DisplayName: "new-login"})
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "Owned run") {
		t.Fatalf("dashboard omitted owned run: %s", body)
	}
	for _, hidden := range []string{"Hidden run canary", "hidden-run", "hidden-key", "hidden-requester-canary", "hidden-canary", "Failed"} {
		if strings.Contains(body, hidden) {
			t.Fatalf("dashboard exposed inaccessible metadata %q: %s", hidden, body)
		}
	}
}

func TestDirectAgentRouteAuthenticatesBeforeLookupAndEnforcesOwner(t *testing.T) {
	run := ownedAgentRun("run-1", "access-1", "https://github.com", "42", "alice")
	config := authenticatedTestConfig()
	config.Auth.Authorization.Rules = []AuthorizationRule{{ID: "agent-owner", Effect: authorizationEffectAllow, Owner: true}}
	server := mustNewServer(t, config, fakeClient(t, &run))

	for _, host := range []string{"access-1.agents.localhost", "missing.agents.localhost"} {
		request := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
		request.Header.Set("Accept", "application/json")
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized || response.Body.String() != "authentication required\n" {
			t.Fatalf("unauthenticated host %s status=%d body=%q", host, response.Code, response.Body.String())
		}
	}

	denied := httptest.NewRequest(http.MethodGet, "http://access-1.agents.localhost/", nil)
	setTestPrincipalSession(t, server, denied, Principal{Issuer: "https://github.com", Subject: "99"})
	deniedResponse := httptest.NewRecorder()
	server.ServeHTTP(deniedResponse, denied)

	missing := httptest.NewRequest(http.MethodGet, "http://missing.agents.localhost/", nil)
	setTestPrincipalSession(t, server, missing, Principal{Issuer: "https://github.com", Subject: "99"})
	missingResponse := httptest.NewRecorder()
	server.ServeHTTP(missingResponse, missing)
	if deniedResponse.Code != http.StatusNotFound || deniedResponse.Code != missingResponse.Code || deniedResponse.Body.String() != missingResponse.Body.String() {
		t.Fatalf("non-owner response=(%d, %q), missing response=(%d, %q), want identical generic 404s",
			deniedResponse.Code, deniedResponse.Body.String(), missingResponse.Code, missingResponse.Body.String())
	}

	allowed := httptest.NewRequest(http.MethodGet, "http://access-1.agents.localhost/", nil)
	setTestPrincipalSession(t, server, allowed, Principal{Issuer: "https://github.com", Subject: "42"})
	allowedResponse := httptest.NewRecorder()
	server.ServeHTTP(allowedResponse, allowed)
	if allowedResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("owner status = %d body=%s, want target-resolution response", allowedResponse.Code, allowedResponse.Body.String())
	}
}

func TestOIDCPrincipalUsesTheSameOwnerPredicate(t *testing.T) {
	provider := oidcDiscoveryServer(t)
	run := ownedAgentRun("run-1", "access-1", provider.URL, "oidc-subject", "old-name")
	config := oidcTestConfig(provider.URL)
	config.Auth.Authorization.Rules = []AuthorizationRule{{ID: "agent-owner", Effect: authorizationEffectAllow, Owner: true}}
	server := mustNewServer(t, config, fakeClient(t, &run))
	request := httptest.NewRequest(http.MethodGet, "http://access-1.agents.localhost/", nil)
	setTestPrincipalSession(t, server, request, Principal{Issuer: provider.URL, Subject: "oidc-subject", DisplayName: "new-name"})
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("OIDC owner status=%d body=%s", response.Code, response.Body.String())
	}
}

func ownedAgentRun(name, key, issuer, subject, displayName string) nvtv1alpha1.AgentRun {
	return nvtv1alpha1.AgentRun{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nvt", Name: name, Annotations: map[string]string{AccessKeyAnnotation: key}},
		Spec: nvtv1alpha1.AgentRunSpec{ProfileProvenance: &nvtv1alpha1.AgentRunProfileProvenance{
			Principal: &nvtv1alpha1.AgentRunPrincipal{Issuer: issuer, Subject: subject, DisplayName: displayName},
		}},
	}
}

func authenticatedTestConfig() Config {
	return Config{
		BaseDomain: "agents.localhost", ListenAddr: ":8080", DefaultTargetPort: 4090,
		Auth: AuthConfig{
			Mode:    authModeOAuth2,
			Session: SessionConfig{Secret: "0123456789abcdef0123456789abcdef", CookieName: defaultSessionCookie, MaxAgeSeconds: defaultSessionMaxAge},
			OAuth2: OAuth2Config{
				ClientID: "client", ClientSecret: "secret", CallbackPath: defaultCallbackPath,
				Issuer: "https://identity.example", AuthorizationURL: "https://oauth.example/authorize", TokenURL: "https://oauth.example/token",
				ClientAuthMethod: oauth2ClientSecretPost,
				Identity:         OAuth2IdentityConfig{Endpoint: "https://oauth.example/identity", AllowedHosts: []string{"oauth.example"}, SubjectPath: "id", DisplayNamePath: "login"},
			},
		},
	}
}
