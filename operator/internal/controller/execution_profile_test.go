package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/yaml"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

type fakeScheduleProducerAuthenticator struct {
	identity string
	err      error
}

func (f fakeScheduleProducerAuthenticator) Authenticate(_ context.Context, token string) (string, error) {
	if token != "projected-token" {
		return "", errScheduleProducerAuthentication
	}
	return f.identity, f.err
}

type fakeTokenReviewCreator struct {
	create func(*authenticationv1.TokenReview) error
}

func (f fakeTokenReviewCreator) Create(_ context.Context, review *authenticationv1.TokenReview) error {
	return f.create(review)
}

func TestKubernetesTokenReviewProducerAuthenticator(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*authenticationv1.TokenReview) error
		wantUser  string
		wantError bool
	}{
		{
			name: "valid service account",
			mutate: func(review *authenticationv1.TokenReview) error {
				if review.Spec.Token != "projected-token" || len(review.Spec.Audiences) != 1 || review.Spec.Audiences[0] != scheduleProducerAudience {
					t.Fatalf("unexpected TokenReview request: %#v", review.Spec)
				}
				review.Status.Authenticated = true
				review.Status.Audiences = []string{scheduleProducerAudience}
				review.Status.User.Username = "system:serviceaccount:nvt:producer"
				return nil
			},
			wantUser: "system:serviceaccount:nvt:producer",
		},
		{
			name: "wrong audience",
			mutate: func(review *authenticationv1.TokenReview) error {
				review.Status.Authenticated = true
				review.Status.Audiences = []string{"other-audience"}
				review.Status.User.Username = "system:serviceaccount:nvt:producer"
				return nil
			},
			wantError: true,
		},
		{
			name: "failed review",
			mutate: func(_ *authenticationv1.TokenReview) error {
				return errors.New("review unavailable")
			},
			wantError: true,
		},
		{
			name:      "unauthenticated",
			mutate:    func(_ *authenticationv1.TokenReview) error { return nil },
			wantError: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authenticator := &KubernetesTokenReviewProducerAuthenticator{
				reviews: fakeTokenReviewCreator{create: test.mutate},
			}
			user, err := authenticator.Authenticate(context.Background(), "projected-token")
			if (err != nil) != test.wantError || user != test.wantUser {
				t.Fatalf("Authenticate() user=%q err=%v", user, err)
			}
		})
	}
}

func TestProfiledScheduleDefaultAndExactSelection(t *testing.T) {
	schedule := testProfiledAgentSchedule()
	fixture := newProfileAdmissionFixture(t, schedule)

	defaultResponse := fixture.serve(t, profiledAdmissionBody(t, "default-work", nil, nil), "Bearer projected-token")
	var defaultDecoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, defaultResponse, http.StatusCreated, &defaultDecoded)
	defaultRun := fixture.run(t, defaultDecoded.AgentRun.Name)
	assertResolvedProfile(t, &defaultRun, "codex-default", "codex-default", "codex-default")
	if defaultRun.Spec.ProfileProvenance.Principal != nil {
		t.Fatalf("default admission unexpectedly recorded a principal: %#v", defaultRun.Spec.ProfileProvenance)
	}

	for index, display := range []string{"john", "renamed-login"} {
		principal := &scheduleAdmissionPrincipal{
			Issuer: "https://github.com", Subject: "immutable-user-42", DisplayName: display,
		}
		response := fixture.serve(t, profiledAdmissionBody(t, fmt.Sprintf("exact-%d", index), principal, nil), "Bearer projected-token")
		var decoded scheduleAdmissionResponse
		decodeAdmissionResponse(t, response, http.StatusCreated, &decoded)
		run := fixture.run(t, decoded.AgentRun.Name)
		assertResolvedProfile(t, &run, "claude-john", "claude-john", "claude-john")
		if run.Spec.ProfileProvenance.Principal.DisplayName != display {
			t.Fatalf("display provenance=%q, want %q", run.Spec.ProfileProvenance.Principal.DisplayName, display)
		}
	}
}

func TestProfiledScheduleNoMatchPolicies(t *testing.T) {
	unknown := &scheduleAdmissionPrincipal{Issuer: "issuer-canary", Subject: "subject-canary", DisplayName: "display-canary"}

	useDefault := testProfiledAgentSchedule()
	fixture := newProfileAdmissionFixture(t, useDefault)
	response := fixture.serve(t, profiledAdmissionBody(t, "unknown-default", unknown, nil), "Bearer projected-token")
	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, http.StatusCreated, &decoded)
	run := fixture.run(t, decoded.AgentRun.Name)
	if run.Spec.ProfileProvenance.SelectedProfile != "codex-default" {
		t.Fatalf("selected profile=%q", run.Spec.ProfileProvenance.SelectedProfile)
	}

	deny := testProfiledAgentSchedule()
	deny.Spec.ProfileSelection.OnNoMatch = nvtv1alpha1.AgentScheduleOnNoMatchDeny
	deny.Spec.ProfileSelection.DefaultProfile = ""
	deniedFixture := newProfileAdmissionFixture(t, deny)
	denied := deniedFixture.serve(t, profiledAdmissionBody(t, "unknown-denied", unknown, nil), "Bearer projected-token")
	decodeAdmissionResponse(t, denied, http.StatusForbidden, &decoded)
	if decoded.Reason != "profile-selection-denied" || strings.Contains(denied.Body.String(), "canary") {
		t.Fatalf("unsafe or unexpected denial: %q", denied.Body.String())
	}
}

func TestProfileConfigurationValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*nvtv1alpha1.AgentSchedule)
	}{
		{
			name: "duplicate profile",
			mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
				schedule.Spec.Profiles = append(schedule.Spec.Profiles, schedule.Spec.Profiles[0])
			},
		},
		{
			name: "missing default profile",
			mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
				schedule.Spec.ProfileSelection.DefaultProfile = "missing"
			},
		},
		{
			name: "missing rule profile",
			mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
				schedule.Spec.ProfileSelection.Rules[0].Profile = "missing"
			},
		},
		{
			name: "ambiguous exact selector",
			mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
				schedule.Spec.ProfileSelection.Rules = append(
					schedule.Spec.ProfileSelection.Rules,
					schedule.Spec.ProfileSelection.Rules[0],
				)
			},
		},
		{
			name: "common runtime override",
			mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
				schedule.Spec.Template.Agent.Config = jsonValue(t, map[string]any{"runtime": map[string]any{"proxy": "producer"}})
			},
		},
		{
			name: "invalid onNoMatch",
			mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
				schedule.Spec.ProfileSelection.OnNoMatch = "guess"
			},
		},
		{
			name: "deny without usable rule",
			mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
				schedule.Spec.ProfileSelection.OnNoMatch = nvtv1alpha1.AgentScheduleOnNoMatchDeny
				schedule.Spec.ProfileSelection.DefaultProfile = ""
				schedule.Spec.ProfileSelection.Rules = nil
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schedule := testProfiledAgentSchedule()
			test.mutate(schedule)
			_, err := (StaticExecutionProfileResolver{}).Resolve(schedule, nil)
			if !errors.Is(err, errInvalidExecutionProfileConfiguration) {
				t.Fatalf("Resolve() error=%v", err)
			}
		})
	}
}

func TestProfiledAdmissionRejectsProducerSecurityFields(t *testing.T) {
	for _, extra := range []map[string]any{
		{"agentRun": map[string]any{"spec": map[string]any{"broker": map[string]any{}}}},
		{"broker": map[string]any{"grants": []any{}}},
		{"profile": "claude-john"},
	} {
		body := profiledAdmissionPayload("security-fields", nil, nil)
		for key, value := range extra {
			body[key] = value
		}
		fixture := newProfileAdmissionFixture(t, testProfiledAgentSchedule())
		response := fixture.serve(t, mustJSON(t, body), "Bearer projected-token")
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "only work and input") {
			t.Fatalf("producer security field accepted: status=%d body=%q", response.Code, response.Body.String())
		}
	}
}

func TestProfiledAdmissionAuthenticationAndAuthorization(t *testing.T) {
	schedule := testProfiledAgentSchedule()
	body := profiledAdmissionBody(t, "auth-work", nil, nil)

	missing := newProfileAdmissionFixture(t, schedule.DeepCopyObject().(*nvtv1alpha1.AgentSchedule))
	if response := missing.serve(t, body, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status=%d", response.Code)
	}

	invalid := newProfileAdmissionFixture(t, schedule.DeepCopyObject().(*nvtv1alpha1.AgentSchedule))
	invalid.authenticator = fakeScheduleProducerAuthenticator{err: errScheduleProducerAuthentication}
	if response := invalid.serve(t, body, "Bearer projected-token"); response.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token status=%d", response.Code)
	}

	wrongAudience := newProfileAdmissionFixture(t, schedule.DeepCopyObject().(*nvtv1alpha1.AgentSchedule))
	wrongAudience.authenticator = &KubernetesTokenReviewProducerAuthenticator{reviews: fakeTokenReviewCreator{
		create: func(review *authenticationv1.TokenReview) error {
			review.Status.Authenticated = true
			review.Status.Audiences = []string{"wrong"}
			review.Status.User.Username = schedule.Spec.AllowedProducers[0]
			return nil
		},
	}}
	if response := wrongAudience.serve(t, body, "Bearer projected-token"); response.Code != http.StatusUnauthorized {
		t.Fatalf("wrong audience status=%d", response.Code)
	}

	unauthorized := newProfileAdmissionFixture(t, schedule.DeepCopyObject().(*nvtv1alpha1.AgentSchedule))
	unauthorized.authenticator = successfulTokenReviewAuthenticator("system:serviceaccount:nvt:other")
	if response := unauthorized.serve(t, body, "Bearer projected-token"); response.Code != http.StatusForbidden {
		t.Fatalf("unauthorized caller status=%d", response.Code)
	}

	allowed := newProfileAdmissionFixture(t, schedule.DeepCopyObject().(*nvtv1alpha1.AgentSchedule))
	allowed.authenticator = successfulTokenReviewAuthenticator(schedule.Spec.AllowedProducers[0])
	if response := allowed.serve(t, body, "Bearer projected-token"); response.Code != http.StatusCreated {
		t.Fatalf("allowed caller status=%d body=%q", response.Code, response.Body.String())
	}
}

func successfulTokenReviewAuthenticator(username string) ScheduleProducerAuthenticator {
	return &KubernetesTokenReviewProducerAuthenticator{reviews: fakeTokenReviewCreator{
		create: func(review *authenticationv1.TokenReview) error {
			review.Status.Authenticated = true
			review.Status.Audiences = []string{scheduleProducerAudience}
			review.Status.User.Username = username
			return nil
		},
	}}
}

func TestProfiledAdmissionSnapshotsConfigurationAndLifecycle(t *testing.T) {
	schedule := testProfiledAgentSchedule()
	fixture := newProfileAdmissionFixture(t, schedule)
	response := fixture.serve(t, profiledAdmissionBody(t, "snapshot", nil, map[string]any{"prompt": "do the work"}), "Bearer projected-token")
	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, http.StatusCreated, &decoded)
	run := fixture.run(t, decoded.AgentRun.Name)

	if run.Spec.Prompt == nil || run.Spec.Prompt.Text != "do the work" || run.Spec.Image != "runtime:profiled" ||
		run.Spec.Runtime.Type != "codex" || run.Spec.Egress != nvtv1alpha1.AgentRunEgressDirect ||
		len(run.Spec.Broker.Grants) != 1 || run.Spec.Broker.Grants[0].Provider != "codex-default" {
		t.Fatalf("resolved spec does not match profile/template: %#v", run.Spec)
	}
	config := map[string]any{}
	if err := json.Unmarshal(run.Spec.Agent.Config.Raw, &config); err != nil {
		t.Fatal(err)
	}
	runtimeConfig := config["runtime"].(map[string]any)
	proxy := runtimeConfig["proxy"].(map[string]any)
	if runtimeConfig["command"] != "codex --profiled" || proxy["provider"] != "codex-default" {
		t.Fatalf("runtime config was not profile-owned: %#v", runtimeConfig)
	}
	plugins := config["plugins"].([]any)
	var callback map[string]any
	for _, value := range plugins {
		plugin := value.(map[string]any)
		if plugin["name"] == "event-webhook" {
			callback = plugin
		}
	}
	if callback == nil {
		t.Fatalf("operator lifecycle callback was not injected: %#v", plugins)
	}
	callbackConfig := callback["config"].(map[string]any)
	if !strings.Contains(callbackConfig["url"].(string), "/"+run.Name+"/events") {
		t.Fatalf("callback URL does not contain final AgentRun name: %#v", callbackConfig)
	}
	filters := callbackConfig["filters"].([]any)
	if len(filters) != 2 || filters[0] != "plugin.work.completed" || filters[1] != "plugin.work.failed" {
		t.Fatalf("lifecycle callback filters=%#v", filters)
	}
	rendered, err := RenderAgentConfigYAML(&run)
	if err != nil || !strings.Contains(rendered, "/"+run.Name+"/events") ||
		!strings.Contains(rendered, "plugin.work.completed") {
		t.Fatalf("resolved lifecycle config was dropped: err=%v\n%s", err, rendered)
	}

	storedSchedule := &nvtv1alpha1.AgentSchedule{}
	if err := fixture.client.Get(context.Background(), types.NamespacedName{Namespace: schedule.Namespace, Name: schedule.Name}, storedSchedule); err != nil {
		t.Fatal(err)
	}
	storedSchedule.Spec.Profiles[0].Runtime.Type = "claude"
	storedSchedule.Spec.Profiles[0].Broker.Grants[0].Provider = "mutated-provider"
	storedSchedule.Spec.Profiles[0].AgentRuntimeConfig = jsonValue(t, map[string]any{"command": "mutated"})
	if err := fixture.client.Update(context.Background(), storedSchedule); err != nil {
		t.Fatal(err)
	}
	unchanged := fixture.run(t, run.Name)
	if unchanged.Spec.Runtime.Type != "codex" || unchanged.Spec.Broker.Grants[0].Provider != "codex-default" ||
		!bytes.Equal(unchanged.Spec.Agent.Config.Raw, run.Spec.Agent.Config.Raw) {
		t.Fatalf("existing run changed after schedule mutation: %#v", unchanged.Spec)
	}
}

func TestProfiledAdmissionSanitizesPrincipalAndProviderErrors(t *testing.T) {
	schedule := testProfiledAgentSchedule()
	schedule.Spec.Profiles[0].Broker.Grants[0].Provider = "provider-canary-secret"
	schedule.Spec.Profiles[0].Broker.Grants[0].Materialization = nvtv1alpha1.AgentRunGrantHeaderInject
	fixture := newProfileAdmissionFixture(t, schedule)
	body := profiledAdmissionBody(t, "sanitized", &scheduleAdmissionPrincipal{
		Issuer: "issuer-canary-secret", Subject: "subject-canary-secret",
	}, nil)
	response := fixture.serve(t, body, "Bearer projected-token")
	if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "canary-secret") {
		t.Fatalf("profile error leaked configured or principal data: %q", response.Body.String())
	}
}

func TestExecutionProfileDeepCopyIsolation(t *testing.T) {
	schedule := testProfiledAgentSchedule()
	copy := schedule.DeepCopyObject().(*nvtv1alpha1.AgentSchedule)
	copy.Spec.Profiles[0].Broker.Grants[0].Repositories[0] = "changed/repo"
	copy.Spec.ProfileSelection.Rules[0].Subject = "changed"
	copy.Spec.AllowedProducers[0] = "changed"
	copy.Spec.Template.Lifecycle.CompleteOn[0] = "changed"
	if schedule.Spec.Profiles[0].Broker.Grants[0].Repositories[0] == "changed/repo" ||
		schedule.Spec.ProfileSelection.Rules[0].Subject == "changed" || schedule.Spec.AllowedProducers[0] == "changed" ||
		schedule.Spec.Template.Lifecycle.CompleteOn[0] == "changed" {
		t.Fatal("AgentSchedule deepcopy shares profiled fields")
	}

	run := testAgentRun()
	run.Spec.ProfileProvenance = &nvtv1alpha1.AgentRunProfileProvenance{
		AuthenticatedProducer: "producer", Principal: &nvtv1alpha1.AgentRunPrincipal{Issuer: "issuer", Subject: "subject"},
	}
	runCopy := run.DeepCopyObject().(*nvtv1alpha1.AgentRun)
	runCopy.Spec.ProfileProvenance.Principal.Subject = "changed"
	if run.Spec.ProfileProvenance.Principal.Subject == "changed" {
		t.Fatal("AgentRun provenance deepcopy shares principal")
	}
}

func TestAgentRunProfileProvenanceCRDSchema(t *testing.T) {
	data, err := os.ReadFile("../../config/crd/bases/nvt.dev_agentruns.yaml")
	if err != nil {
		t.Fatal(err)
	}
	chartData, err := os.ReadFile("../../../charts/nvt/crds/nvt.dev_agentruns.yaml")
	if err != nil || !bytes.Equal(data, chartData) {
		t.Fatalf("generated and Helm AgentRun CRDs differ: %v", err)
	}
	var crd map[string]any
	if err := yaml.Unmarshal(data, &crd); err != nil {
		t.Fatal(err)
	}
	provenance := crdPath(t, crd,
		"spec", "versions", 0, "schema", "openAPIV3Schema", "properties",
		"spec", "properties", "profileProvenance", "properties",
	).(map[string]any)
	if crdPath(t, provenance, "authenticatedProducer", "type") != "string" ||
		crdPath(t, provenance, "principal", "properties", "subject", "type") != "string" {
		t.Fatalf("profile provenance schema incomplete: %#v", provenance)
	}
	validations := crdPath(t, crd,
		"spec", "versions", 0, "schema", "openAPIV3Schema", "properties",
		"spec", "x-kubernetes-validations",
	).([]any)
	if len(validations) != 1 || !strings.Contains(validations[0].(map[string]any)["rule"].(string), "oldSelf.profileProvenance") {
		t.Fatalf("profile provenance immutability rule missing: %#v", validations)
	}
}

type profileAdmissionFixture struct {
	client        client.Client
	schedule      *nvtv1alpha1.AgentSchedule
	authenticator ScheduleProducerAuthenticator
	scheme        *runtime.Scheme
}

func newProfileAdmissionFixture(t *testing.T, schedule *nvtv1alpha1.AgentSchedule) *profileAdmissionFixture {
	t.Helper()
	scheme := testScheme(t)
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentSchedule{}, &nvtv1alpha1.AgentRun{}).
		WithObjects(schedule).
		Build()
	return &profileAdmissionFixture{
		client: k8sClient, schedule: schedule, scheme: scheme,
		authenticator: fakeScheduleProducerAuthenticator{identity: schedule.Spec.AllowedProducers[0]},
	}
}

func (f *profileAdmissionFixture) serve(t *testing.T, body, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	handler := &agentScheduleAdmissionHandler{
		client: f.client, scheme: f.scheme, authenticator: f.authenticator,
		profileResolver: StaticExecutionProfileResolver{}, now: metav1.Now,
	}
	request := httptest.NewRequest(http.MethodPost,
		"/v1/schedules/"+f.schedule.Namespace+"/"+f.schedule.Name+"/admissions",
		strings.NewReader(body),
	)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func (f *profileAdmissionFixture) run(t *testing.T, name string) nvtv1alpha1.AgentRun {
	t.Helper()
	return getScheduledAgentRun(context.Background(), t, f.client, f.schedule.Namespace, name)
}

func testProfiledAgentSchedule() *nvtv1alpha1.AgentSchedule {
	return &nvtv1alpha1.AgentSchedule{
		TypeMeta:   metav1.TypeMeta{APIVersion: nvtv1alpha1.GroupVersion.String(), Kind: "AgentSchedule"},
		ObjectMeta: metav1.ObjectMeta{Name: "profiled", Namespace: "nvt", UID: "profiled-uid", Generation: 7},
		Spec: nvtv1alpha1.AgentScheduleSpec{
			MaxParallelism: 10,
			Template: &nvtv1alpha1.AgentScheduleTemplate{
				Image: "runtime:profiled", Workspace: nvtv1alpha1.AgentRunWorkspace{Mode: "Ephemeral"},
				Agent:     nvtv1alpha1.AgentRunAgent{Config: rawJSON(`{"packages":["git"],"plugins":[{"name":"smoke-complete","source":"builtin","when":"after-agent","config":{}}]}`)},
				Lifecycle: &nvtv1alpha1.AgentRunLifecycle{CompleteOn: []string{"plugin.work.completed"}, FailOn: []string{"plugin.work.failed"}},
			},
			Profiles: []nvtv1alpha1.AgentScheduleExecutionProfile{
				profile("codex-default", "codex", "codex --profiled"),
				profile("claude-john", "claude", "claude --profiled"),
			},
			ProfileSelection: &nvtv1alpha1.AgentScheduleProfileSelection{
				DefaultProfile: "codex-default", OnNoMatch: nvtv1alpha1.AgentScheduleOnNoMatchUseDefault,
				Rules: []nvtv1alpha1.AgentScheduleProfileSelectionRule{{
					Issuer: "https://github.com", Subject: "immutable-user-42", Profile: "claude-john",
				}},
			},
			AllowedProducers: []string{"system:serviceaccount:nvt:nvt-github-comments-producer"},
		},
	}
}

func profile(name, runtimeType, command string) nvtv1alpha1.AgentScheduleExecutionProfile {
	return nvtv1alpha1.AgentScheduleExecutionProfile{
		Name: name, Runtime: nvtv1alpha1.AgentRunRuntime{Type: runtimeType, Autonomy: "trusted-local"},
		AgentRuntimeConfig: rawJSON(fmt.Sprintf(`{"command":%q,"proxy":{"provider":%q}}`, command, name)),
		Egress:             nvtv1alpha1.AgentRunEgressDirect,
		Broker: &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
			Provider: name, Repositories: []string{"example/*"}, Materialization: nvtv1alpha1.AgentRunGrantFileBundle,
		}}},
	}
}

func assertResolvedProfile(t *testing.T, run *nvtv1alpha1.AgentRun, profileName, provider, proxyProvider string) {
	t.Helper()
	if run.Spec.ProfileProvenance == nil || run.Spec.ProfileProvenance.SelectedProfile != profileName ||
		run.Spec.ProfileProvenance.AuthenticatedProducer != "system:serviceaccount:nvt:nvt-github-comments-producer" ||
		run.Spec.ProfileProvenance.ScheduleGeneration != 7 || len(run.Spec.Broker.Grants) != 1 ||
		run.Spec.Broker.Grants[0].Provider != provider {
		t.Fatalf("unexpected profile resolution: %#v", run.Spec)
	}
	config := map[string]any{}
	if err := json.Unmarshal(run.Spec.Agent.Config.Raw, &config); err != nil {
		t.Fatal(err)
	}
	runtimeConfig := config["runtime"].(map[string]any)
	if runtimeConfig["proxy"].(map[string]any)["provider"] != proxyProvider {
		t.Fatalf("unexpected runtime proxy config: %#v", runtimeConfig)
	}
}

func profiledAdmissionBody(t *testing.T, workID string, principal *scheduleAdmissionPrincipal, input map[string]any) string {
	t.Helper()
	return mustJSON(t, profiledAdmissionPayload(workID, principal, input))
}

func profiledAdmissionPayload(workID string, principal *scheduleAdmissionPrincipal, input map[string]any) map[string]any {
	work := map[string]any{
		"id": workID, "title": "Profiled work", "url": "https://example.test/work/1", "repository": "example/repo",
	}
	if principal != nil {
		work["principal"] = principal
	}
	payload := map[string]any{"work": work}
	if input != nil {
		payload["input"] = input
	}
	return payload
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func jsonValue(t *testing.T, value any) apiextensionsv1.JSON {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return apiextensionsv1.JSON{Raw: data}
}

func rawJSON(value string) apiextensionsv1.JSON {
	return apiextensionsv1.JSON{Raw: []byte(value)}
}
