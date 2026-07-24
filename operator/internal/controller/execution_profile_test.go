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
	"reflect"
	"strings"
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/resource"
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
	profileInstructions := "Prefer repository-local checks.\n\n- Keep commits focused.\n"
	schedule.Spec.Profiles[0].WorkspaceInstructions = profileInstructions
	scheduleCopy := schedule.DeepCopyObject().(*nvtv1alpha1.AgentSchedule)
	scheduleCopy.Spec.Profiles[0].WorkspaceInstructions = "copy changed"
	if schedule.Spec.Profiles[0].WorkspaceInstructions != profileInstructions {
		t.Fatal("AgentSchedule profile workspace instructions were not deep-copied")
	}
	runtimeClassName := "kata-vm-isolation"
	tolerationSeconds := int64(60)
	schedule.Spec.Template.RuntimeClassName = &runtimeClassName
	schedule.Spec.Template.Resources = corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2"), corev1.ResourceMemory: resource.MustParse("8Gi")},
		Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2"), corev1.ResourceMemory: resource.MustParse("8Gi")},
	}
	schedule.Spec.Template.Tolerations = []corev1.Toleration{{
		Key: "purpose", Operator: corev1.TolerationOpEqual, Value: "nvt-agent",
		Effect: corev1.TaintEffectNoExecute, TolerationSeconds: &tolerationSeconds,
	}}
	fixture := newProfileAdmissionFixture(t, schedule)

	defaultResponse := fixture.serve(t, profiledAdmissionBody(t, "default-work", nil, nil), "Bearer projected-token")
	var defaultDecoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, defaultResponse, http.StatusCreated, &defaultDecoded)
	defaultRun := fixture.run(t, defaultDecoded.AgentRun.Name)
	assertResolvedProfile(t, &defaultRun, "codex-default", "codex-default", "codex-default")
	if defaultRun.Spec.Agent.WorkspaceInstructions != profileInstructions {
		t.Fatalf("workspace instructions were not snapshotted exactly: %q", defaultRun.Spec.Agent.WorkspaceInstructions)
	}
	if defaultRun.Spec.Agent.WorkflowInstructions != "" || defaultRun.Spec.ProfileProvenance.SelectedWorkflow != "" {
		t.Fatalf("legacy producer allowlist unexpectedly added workflow state: %#v", defaultRun.Spec)
	}
	schedule.Spec.Profiles[0].WorkspaceInstructions = "changed after admission"
	if defaultRun.Spec.Agent.WorkspaceInstructions != profileInstructions {
		t.Fatal("resolved AgentRun workspace instructions alias the AgentSchedule profile")
	}
	if defaultRun.Spec.RuntimeClassName == nil || *defaultRun.Spec.RuntimeClassName != runtimeClassName ||
		!reflect.DeepEqual(defaultRun.Spec.Resources, schedule.Spec.Template.Resources) ||
		!reflect.DeepEqual(defaultRun.Spec.Tolerations, schedule.Spec.Template.Tolerations) {
		t.Fatalf("shared scheduling fields were not propagated: %#v", defaultRun.Spec)
	}
	defaultRun.Spec.Tolerations[0].TolerationSeconds = ptrTo(int64(1))
	defaultRun.Spec.Resources.Limits[corev1.ResourceMemory] = resource.MustParse("1Gi")
	if *schedule.Spec.Template.Tolerations[0].TolerationSeconds != tolerationSeconds {
		t.Fatal("resolved AgentRun tolerations alias the AgentSchedule template")
	}
	if schedule.Spec.Template.Resources.Limits.Memory().Cmp(resource.MustParse("8Gi")) != 0 {
		t.Fatal("resolved AgentRun resources alias the AgentSchedule template")
	}
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

func TestProfiledScheduleSnapshotsForwardProxyTunnelCapacity(t *testing.T) {
	schedule := testProfiledAgentSchedule()
	profile := &schedule.Spec.Profiles[0]
	profile.Egress = nvtv1alpha1.AgentRunEgressMediated
	profile.EgressAllowInsecureBroker = true
	profile.EgressEnforcement = true
	profile.EgressTransport = nvtv1alpha1.AgentRunEgressTransportForwardProxy
	profile.EgressMaxConcurrentTunnels = 512
	profile.Broker.Grants[0].Materialization = nvtv1alpha1.AgentRunGrantPlaceholderFile
	profile.Broker.Grants[0].EgressHosts = []string{"chatgpt.com"}

	resolved, err := (StaticExecutionProfileResolver{}).Resolve(schedule, nil)
	if err != nil {
		t.Fatal(err)
	}
	run, err := buildProfiledAgentRun(schedule, resolved, "system:serviceaccount:nvt:producer", nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if run.Spec.EgressMaxConcurrentTunnels != 512 {
		t.Fatalf("tunnel capacity was not snapshotted: %d", run.Spec.EgressMaxConcurrentTunnels)
	}
	profile.EgressMaxConcurrentTunnels = 1024
	if run.Spec.EgressMaxConcurrentTunnels != 512 {
		t.Fatal("resolved tunnel capacity changed after schedule mutation")
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

func TestWorkflowProfilesAreAuthorizedIndependentlyFromExecutionProfiles(t *testing.T) {
	schedule := testWorkflowProfiledAgentSchedule()
	schedule.Spec.Profiles[0].WorkspaceInstructions = "Execution profile guidance.\n"
	copy := schedule.DeepCopyObject().(*nvtv1alpha1.AgentSchedule)
	copy.Spec.WorkflowProfiles[0].WorkspaceInstructions = "copy changed"
	copy.Spec.ProducerPolicies[0].Workflows[0] = "copy-changed"
	if schedule.Spec.WorkflowProfiles[0].WorkspaceInstructions != "Implement and create a pull request.\n" ||
		schedule.Spec.ProducerPolicies[0].Workflows[0] != "implement-pr" {
		t.Fatal("workflow profiles or producer policies were not deep-copied")
	}
	empty := testProfiledAgentSchedule()
	empty.Spec.WorkflowProfiles = []nvtv1alpha1.AgentScheduleWorkflowProfile{}
	empty.Spec.ProducerPolicies = []nvtv1alpha1.AgentScheduleProducerPolicy{{Identity: "producer", Workflows: []string{}}}
	emptyCopy := empty.DeepCopyObject().(*nvtv1alpha1.AgentSchedule)
	if emptyCopy.Spec.WorkflowProfiles == nil || emptyCopy.Spec.ProducerPolicies[0].Workflows == nil {
		t.Fatal("workflow deep copy changed explicit-empty slices to nil")
	}
	fixture := newProfileAdmissionFixture(t, schedule)

	requests := []struct {
		workID       string
		workflow     string
		wantWorkflow string
		wantText     string
	}{
		{workID: "workflow-default", wantWorkflow: "implement-pr", wantText: "Implement and create a pull request.\n"},
		{workID: "workflow-review", workflow: "review-pr", wantWorkflow: "review-pr", wantText: "Review and report findings first.\n"},
		{workID: "workflow-implement", workflow: "implement-pr", wantWorkflow: "implement-pr", wantText: "Implement and create a pull request.\n"},
	}
	var runs []nvtv1alpha1.AgentRun
	for _, request := range requests {
		body := profiledAdmissionPayload(request.workID, nil, nil)
		if request.workflow != "" {
			body["workflow"] = request.workflow
		}
		response := fixture.serve(t, mustJSON(t, body), "Bearer projected-token")
		var decoded scheduleAdmissionResponse
		decodeAdmissionResponse(t, response, http.StatusCreated, &decoded)
		run := fixture.run(t, decoded.AgentRun.Name)
		if run.Spec.ProfileProvenance.SelectedProfile != "codex-default" ||
			run.Spec.ProfileProvenance.SelectedWorkflow != request.wantWorkflow ||
			run.Spec.Agent.WorkspaceInstructions != "Execution profile guidance.\n" ||
			run.Spec.Agent.WorkflowInstructions != request.wantText {
			t.Fatalf("independent workflow resolution failed: %#v", run.Spec)
		}
		runs = append(runs, run)
	}

	schedule.Spec.WorkflowProfiles[0].WorkspaceInstructions = "mutated"
	schedule.Spec.ProducerPolicies[0].DefaultWorkflow = "review-pr"
	if runs[0].Spec.Agent.WorkflowInstructions != "Implement and create a pull request.\n" ||
		runs[0].Spec.ProfileProvenance.SelectedWorkflow != "implement-pr" {
		t.Fatal("resolved workflow snapshot changed after schedule mutation")
	}

	second := testWorkflowProfiledAgentSchedule()
	secondFixture := newProfileAdmissionFixture(t, second)
	secondFixture.authenticator = successfulTokenReviewAuthenticator("system:serviceaccount:nvt:review-producer")
	response := secondFixture.serve(t, profiledAdmissionBody(t, "second-producer", nil, nil), "Bearer projected-token")
	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, http.StatusCreated, &decoded)
	run := secondFixture.run(t, decoded.AgentRun.Name)
	if run.Spec.ProfileProvenance.SelectedProfile != "codex-default" ||
		run.Spec.ProfileProvenance.SelectedWorkflow != "review-pr" {
		t.Fatalf("second producer did not reuse execution profile with its workflow: %#v", run.Spec.ProfileProvenance)
	}
}

func TestWorkflowSelectionAndConfigurationFailClosed(t *testing.T) {
	for _, workflow := range []string{"unknown", " review-pr", ""} {
		schedule := testWorkflowProfiledAgentSchedule()
		fixture := newProfileAdmissionFixture(t, schedule)
		body := profiledAdmissionPayload("denied-"+strings.ReplaceAll(workflow, " ", "-"), nil, nil)
		body["workflow"] = workflow
		response := fixture.serve(t, mustJSON(t, body), "Bearer projected-token")
		if response.Code != http.StatusForbidden && response.Code != http.StatusBadRequest {
			t.Fatalf("workflow %q status=%d body=%q", workflow, response.Code, response.Body.String())
		}
		runs := &nvtv1alpha1.AgentRunList{}
		if err := fixture.client.List(context.Background(), runs, client.InNamespace(schedule.Namespace)); err != nil || len(runs.Items) != 0 {
			t.Fatalf("denied workflow created runs: err=%v runs=%#v", err, runs.Items)
		}
	}

	unauthorized := testWorkflowProfiledAgentSchedule()
	fixture := newProfileAdmissionFixture(t, unauthorized)
	fixture.authenticator = successfulTokenReviewAuthenticator("system:serviceaccount:nvt:spoofed-producer")
	response := fixture.serve(t, profiledAdmissionBody(t, "spoofed-producer", nil, nil), "Bearer projected-token")
	if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), "spoofed-producer") {
		t.Fatalf("producer authorization was not sanitized: status=%d body=%q", response.Code, response.Body.String())
	}

	mutations := []struct {
		name   string
		mutate func(*nvtv1alpha1.AgentSchedule)
	}{
		{name: "duplicate workflow", mutate: func(s *nvtv1alpha1.AgentSchedule) {
			s.Spec.WorkflowProfiles = append(s.Spec.WorkflowProfiles, s.Spec.WorkflowProfiles[0])
		}},
		{name: "duplicate producer", mutate: func(s *nvtv1alpha1.AgentSchedule) {
			s.Spec.ProducerPolicies = append(s.Spec.ProducerPolicies, s.Spec.ProducerPolicies[0])
		}},
		{name: "duplicate allowed workflow", mutate: func(s *nvtv1alpha1.AgentSchedule) {
			s.Spec.ProducerPolicies[0].Workflows = append(s.Spec.ProducerPolicies[0].Workflows, "review-pr")
		}},
		{name: "unknown workflow reference", mutate: func(s *nvtv1alpha1.AgentSchedule) { s.Spec.ProducerPolicies[0].Workflows[0] = "missing" }},
		{name: "invalid default", mutate: func(s *nvtv1alpha1.AgentSchedule) {
			s.Spec.ProducerPolicies[0].DefaultWorkflow = "review-pr"
			s.Spec.ProducerPolicies[0].Workflows = []string{"implement-pr"}
		}},
		{name: "oversized instructions", mutate: func(s *nvtv1alpha1.AgentSchedule) {
			s.Spec.WorkflowProfiles[0].WorkspaceInstructions = strings.Repeat("x", maxWorkspaceInstructionsBytes+1)
		}},
		{name: "mixed legacy allowlist", mutate: func(s *nvtv1alpha1.AgentSchedule) {
			s.Spec.AllowedProducers = []string{"system:serviceaccount:nvt:legacy"}
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			schedule := testWorkflowProfiledAgentSchedule()
			test.mutate(schedule)
			if _, err := validateExecutionProfileSchedule(schedule); !errors.Is(err, errInvalidExecutionProfileConfiguration) {
				t.Fatalf("invalid workflow configuration accepted: %v", err)
			}
		})
	}

	invalid := testWorkflowProfiledAgentSchedule()
	invalid.Spec.WorkflowProfiles[0].WorkspaceInstructions = strings.Repeat("x", maxWorkspaceInstructionsBytes) + "instruction-secret-canary"
	invalidFixture := newProfileAdmissionFixture(t, invalid)
	invalidResponse := invalidFixture.serve(t, profiledAdmissionBody(t, "invalid-workflow-config", nil, nil), "Bearer projected-token")
	if invalidResponse.Code != http.StatusBadRequest ||
		!strings.Contains(invalidResponse.Body.String(), "invalid-execution-profile-configuration") ||
		strings.Contains(invalidResponse.Body.String(), "instruction-secret-canary") {
		t.Fatalf("invalid workflow configuration response was unsafe: status=%d body=%q", invalidResponse.Code, invalidResponse.Body.String())
	}
	invalidRuns := &nvtv1alpha1.AgentRunList{}
	if err := invalidFixture.client.List(context.Background(), invalidRuns, client.InNamespace(invalid.Namespace)); err != nil || len(invalidRuns.Items) != 0 {
		t.Fatalf("invalid workflow configuration created runs: err=%v runs=%#v", err, invalidRuns.Items)
	}
}

func TestProfiledScheduleRejectsPersistentFileBundleBeforeCreate(t *testing.T) {
	schedule := testProfiledAgentSchedule()
	size := resource.MustParse("5Gi")
	schedule.Spec.Template.Workspace = nvtv1alpha1.AgentRunWorkspace{
		Mode: nvtv1alpha1.AgentRunWorkspacePersistent, Size: &size, StorageClassName: "managed-csi",
	}
	fixture := newProfileAdmissionFixture(t, schedule)
	response := fixture.serve(t, profiledAdmissionBody(t, "persistent-file-bundle", nil, nil), "Bearer projected-token")
	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, http.StatusBadRequest, &decoded)
	if decoded.Scheduled || decoded.Reason != "invalid-execution-profile-configuration" || strings.Contains(response.Body.String(), "github") {
		t.Fatalf("unsafe or unexpected response: %q", response.Body.String())
	}
	runs := &nvtv1alpha1.AgentRunList{}
	if err := fixture.client.List(context.Background(), runs, client.InNamespace(schedule.Namespace)); err != nil {
		t.Fatal(err)
	}
	if len(runs.Items) != 0 {
		t.Fatalf("invalid profile created AgentRuns: %#v", runs.Items)
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
			name: "template workspace instructions",
			mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
				schedule.Spec.Template.Agent.WorkspaceInstructions = "producer-owned template instructions"
			},
		},
		{
			name: "template workflow instructions",
			mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
				schedule.Spec.Template.Agent.WorkflowInstructions = "template workflow instructions"
			},
		},
		{
			name: "oversized profile workspace instructions",
			mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
				schedule.Spec.Profiles[0].WorkspaceInstructions = strings.Repeat("x", maxWorkspaceInstructionsBytes+1)
			},
		},
		{
			name: "excessive tunnel capacity",
			mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
				schedule.Spec.Profiles[0].EgressMaxConcurrentTunnels = 4097
			},
		},
		{
			name: "tunnel capacity on direct default redirect",
			mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
				schedule.Spec.Profiles[0].EgressMaxConcurrentTunnels = 256
			},
		},
		{
			name: "tunnel capacity on mediated redirect",
			mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
				profile := &schedule.Spec.Profiles[0]
				profile.Egress = nvtv1alpha1.AgentRunEgressMediated
				profile.EgressAllowInsecureBroker = true
				profile.EgressEnforcement = true
				profile.EgressTransport = nvtv1alpha1.AgentRunEgressTransportRedirect
				profile.EgressMaxConcurrentTunnels = 256
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

func TestProfileConfigurationRejectsRemovedEgressForwardProxy(t *testing.T) {
	for _, value := range []bool{true, false} {
		t.Run(fmt.Sprintf("value-%t", value), func(t *testing.T) {
			schedule := testProfiledAgentSchedule()
			schedule.Spec.Profiles[0].EgressForwardProxy = ptrTo(value)
			_, err := validateExecutionProfileSchedule(schedule)
			if err == nil || !strings.Contains(err.Error(), "egressForwardProxy is removed; use egressTransport") {
				t.Fatalf("legacy profile value %t was not rejected explicitly: %v", value, err)
			}
		})
	}
}

func TestProfiledAdmissionRejectsProducerSecurityFields(t *testing.T) {
	for _, extra := range []map[string]any{
		{"agentRun": map[string]any{"spec": map[string]any{"broker": map[string]any{}}}},
		{"agentRun": map[string]any{"spec": map[string]any{"runtime": map[string]any{
			"container": map[string]any{"capabilities": map[string]any{"add": []any{"SYS_PTRACE"}}},
		}}}},
		{"broker": map[string]any{"grants": []any{}}},
		{"profile": "claude-john"},
		{"producer": "system:serviceaccount:nvt:spoofed"},
		{"workspaceInstructions": "producer instructions"},
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

	body := profiledAdmissionPayload("instruction-override", nil, map[string]any{
		"prompt": "work", "workspaceInstructions": "producer override",
	})
	fixture := newProfileAdmissionFixture(t, testProfiledAgentSchedule())
	response := fixture.serve(t, mustJSON(t, body), "Bearer projected-token")
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "only work and input") {
		t.Fatalf("producer workspace instructions accepted: status=%d body=%q", response.Code, response.Body.String())
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

func TestProfiledAdmissionSnapshotsContainerCapabilities(t *testing.T) {
	schedule := testProfiledAgentSchedule()
	schedule.Spec.Profiles[0].Runtime.Container = &nvtv1alpha1.AgentRunRuntimeContainer{
		Capabilities: &nvtv1alpha1.AgentRunRuntimeCapabilities{Add: []corev1.Capability{"SYS_PTRACE"}},
	}
	scheduleCopy := schedule.DeepCopyObject().(*nvtv1alpha1.AgentSchedule)
	scheduleCopy.Spec.Profiles[0].Runtime.Container.Capabilities.Add[0] = "NET_ADMIN"
	if schedule.Spec.Profiles[0].Runtime.Container.Capabilities.Add[0] != "SYS_PTRACE" {
		t.Fatal("AgentSchedule capability configuration was not deep-copied")
	}
	fixture := newProfileAdmissionFixture(t, schedule)
	response := fixture.serve(t, profiledAdmissionBody(t, "capabilities", nil, nil), "Bearer projected-token")
	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, http.StatusCreated, &decoded)
	run := fixture.run(t, decoded.AgentRun.Name)
	if run.Spec.Runtime.Container == nil || run.Spec.Runtime.Container.Capabilities == nil ||
		!reflect.DeepEqual(run.Spec.Runtime.Container.Capabilities.Add, []corev1.Capability{"SYS_PTRACE"}) {
		t.Fatalf("profile capabilities were not snapshotted: %#v", run.Spec.Runtime)
	}
	raw, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	var roundTripped nvtv1alpha1.AgentRun
	if err := json.Unmarshal(raw, &roundTripped); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(roundTripped.Spec.Runtime.Container, run.Spec.Runtime.Container) {
		t.Fatalf("capability configuration did not round-trip: %#v", roundTripped.Spec.Runtime.Container)
	}
	schedule.Spec.Profiles[0].Runtime.Container.Capabilities.Add[0] = "NET_ADMIN"
	if run.Spec.Runtime.Container.Capabilities.Add[0] != "SYS_PTRACE" {
		t.Fatal("resolved AgentRun aliases profile capability configuration")
	}
}

func TestProfiledCapabilityConfigurationFailsClosed(t *testing.T) {
	for _, add := range [][]corev1.Capability{{"NOT_A_CAPABILITY"}, {"SYS_PTRACE", "SYS_PTRACE"}} {
		schedule := testProfiledAgentSchedule()
		schedule.Spec.Profiles[0].Runtime.Container = &nvtv1alpha1.AgentRunRuntimeContainer{
			Capabilities: &nvtv1alpha1.AgentRunRuntimeCapabilities{Add: add},
		}
		fixture := newProfileAdmissionFixture(t, schedule)
		response := fixture.serve(t, profiledAdmissionBody(t, "invalid-capability", nil, nil), "Bearer projected-token")
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid-execution-profile-configuration") ||
			strings.Contains(response.Body.String(), string(add[0])) {
			t.Fatalf("invalid capability response was not sanitized: status=%d body=%q", response.Code, response.Body.String())
		}
		runs := &nvtv1alpha1.AgentRunList{}
		if err := fixture.client.List(context.Background(), runs, client.InNamespace(schedule.Namespace)); err != nil || len(runs.Items) != 0 {
			t.Fatalf("invalid capability configuration created runs: err=%v runs=%#v", err, runs.Items)
		}
	}
}

func TestProfiledEnforcedZeroSecretLifecycleComposition(t *testing.T) {
	setTLSBrokerEnv(t)
	schedule := testProfiledAgentSchedule()
	profile := &schedule.Spec.Profiles[0]
	profile.Egress = nvtv1alpha1.AgentRunEgressMediated
	profile.EgressEnforcement = true
	profile.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "codex-default", Repositories: []string{"example/repo"},
		Materialization: nvtv1alpha1.AgentRunGrantHeaderInject,
		EgressHosts:     []string{"api.example.test"},
	}}}

	fixture := newProfileAdmissionFixture(t, schedule)
	response := fixture.serve(t, profiledAdmissionBody(t, "enforced-lifecycle", nil, nil), "Bearer projected-token")
	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, http.StatusCreated, &decoded)
	run := fixture.run(t, decoded.AgentRun.Name)

	if !AgentRunLiteralZeroSecret(&run) || run.Spec.ProfileProvenance.SelectedProfile != "codex-default" ||
		len(run.Spec.Broker.Grants) != 1 || run.Spec.Broker.Grants[0].Provider != "codex-default" {
		t.Fatalf("profiled enforced run lost selected security configuration: %#v", run.Spec)
	}
	storedConfig := map[string]any{}
	if err := json.Unmarshal(run.Spec.Agent.Config.Raw, &storedConfig); err != nil {
		t.Fatal(err)
	}
	for _, raw := range storedConfig["plugins"].([]any) {
		if raw.(map[string]any)["name"] == "event-webhook" {
			t.Fatalf("enforced profile stored legacy event-webhook callback: %#v", storedConfig)
		}
	}

	rendered, err := RenderAgentConfigYAML(&run)
	if err != nil {
		t.Fatalf("render enforced profiled config: %v", err)
	}
	renderedConfig := map[string]any{}
	if err := yaml.Unmarshal([]byte(rendered), &renderedConfig); err != nil {
		t.Fatalf("decode rendered config: %v", err)
	}
	plugins := renderedConfig["plugins"].([]any)
	var reporter map[string]any
	for _, raw := range plugins {
		plugin := raw.(map[string]any)
		switch plugin["name"] {
		case "event-webhook":
			t.Fatalf("enforced profile rendered legacy event-webhook callback: %#v", plugins)
		case lifecycleReporterPlugin:
			reporter = plugin
		}
	}
	if reporter == nil {
		t.Fatalf("enforced lifecycle reporter missing: %#v", plugins)
	}
	reporterConfig := reporter["config"].(map[string]any)
	if fmt.Sprint(reporterConfig["completeOn"]) != "[plugin.work.completed]" ||
		fmt.Sprint(reporterConfig["failOn"]) != "[plugin.work.failed]" ||
		reporterConfig["terminationMessagePath"] != "/dev/termination-log" {
		t.Fatalf("enforced lifecycle filters changed: %#v", reporterConfig)
	}
	runtimeConfig := renderedConfig["runtime"].(map[string]any)
	proxy := runtimeConfig["proxy"].(map[string]any)
	egress := renderedConfig["egress"].(map[string]any)
	grants := egress["grants"].([]any)
	if proxy["provider"] != "codex-default" || egress["enforcement"] != true || len(grants) != 1 ||
		grants[0].(map[string]any)["provider"] != "codex-default" {
		t.Fatalf("enforced rendering changed profile proxy/grants: %#v", renderedConfig)
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
	schedule.Spec.Profiles[0].Broker.Grants[0].Preparations = []nvtv1alpha1.AgentRunBrokerPreparation{{Operation: nvtv1alpha1.AgentRunBrokerPreparationIdentity}}
	tolerationSeconds := int64(30)
	schedule.Spec.Template.Tolerations = []corev1.Toleration{{Key: "dedicated", TolerationSeconds: &tolerationSeconds}}
	copy := schedule.DeepCopyObject().(*nvtv1alpha1.AgentSchedule)
	copy.Spec.Profiles[0].Broker.Grants[0].Repositories[0] = "changed/repo"
	copy.Spec.Profiles[0].Broker.Grants[0].Preparations[0].Operation = "changed"
	copy.Spec.ProfileSelection.Rules[0].Subject = "changed"
	copy.Spec.AllowedProducers[0] = "changed"
	copy.Spec.Template.Lifecycle.CompleteOn[0] = "changed"
	copy.Spec.Template.Tolerations[0].Key = "changed"
	*copy.Spec.Template.Tolerations[0].TolerationSeconds = 1
	if schedule.Spec.Profiles[0].Broker.Grants[0].Repositories[0] == "changed/repo" ||
		schedule.Spec.Profiles[0].Broker.Grants[0].Preparations[0].Operation == "changed" ||
		schedule.Spec.ProfileSelection.Rules[0].Subject == "changed" || schedule.Spec.AllowedProducers[0] == "changed" ||
		schedule.Spec.Template.Lifecycle.CompleteOn[0] == "changed" ||
		schedule.Spec.Template.Tolerations[0].Key == "changed" || *schedule.Spec.Template.Tolerations[0].TolerationSeconds == 1 {
		t.Fatal("AgentSchedule deepcopy shares profiled fields")
	}

	run := testAgentRun()
	run.Spec.Tolerations = []corev1.Toleration{{Key: "dedicated", TolerationSeconds: &tolerationSeconds}}
	run.Spec.ProfileProvenance = &nvtv1alpha1.AgentRunProfileProvenance{
		AuthenticatedProducer: "producer", Principal: &nvtv1alpha1.AgentRunPrincipal{Issuer: "issuer", Subject: "subject"},
	}
	runCopy := run.DeepCopyObject().(*nvtv1alpha1.AgentRun)
	runCopy.Spec.ProfileProvenance.Principal.Subject = "changed"
	runCopy.Spec.Tolerations[0].Key = "changed"
	*runCopy.Spec.Tolerations[0].TolerationSeconds = 1
	if run.Spec.ProfileProvenance.Principal.Subject == "changed" {
		t.Fatal("AgentRun provenance deepcopy shares principal")
	}
	if run.Spec.Tolerations[0].Key == "changed" || *run.Spec.Tolerations[0].TolerationSeconds == 1 {
		t.Fatal("AgentRun deepcopy shares tolerations")
	}
}

func TestProfiledScheduleSnapshotsProviderPreparations(t *testing.T) {
	schedule := testProfiledAgentSchedule()
	schedule.Spec.Profiles[0].Broker.Grants[0].Preparations = []nvtv1alpha1.AgentRunBrokerPreparation{{Operation: nvtv1alpha1.AgentRunBrokerPreparationIdentity}}
	fixture := newProfileAdmissionFixture(t, schedule)
	response := fixture.serve(t, profiledAdmissionBody(t, "prepared-profile", nil, nil), "Bearer projected-token")
	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, http.StatusCreated, &decoded)
	run := fixture.run(t, decoded.AgentRun.Name)
	if got := run.Spec.Broker.Grants[0].Preparations; len(got) != 1 || got[0].Operation != nvtv1alpha1.AgentRunBrokerPreparationIdentity {
		t.Fatalf("profile preparation was not snapshotted: %#v", got)
	}
	schedule.Spec.Profiles[0].Broker.Grants[0].Preparations[0].Operation = "changed"
	if run.Spec.Broker.Grants[0].Preparations[0].Operation != nvtv1alpha1.AgentRunBrokerPreparationIdentity {
		t.Fatal("resolved preparation aliases the schedule profile")
	}
}

func TestProfiledScheduleRejectsInvalidProviderPreparation(t *testing.T) {
	schedule := testProfiledAgentSchedule()
	schedule.Spec.Profiles[0].Broker.Grants[0].Preparations = []nvtv1alpha1.AgentRunBrokerPreparation{{Operation: "token"}}
	fixture := newProfileAdmissionFixture(t, schedule)
	response := fixture.serve(t, profiledAdmissionBody(t, "invalid-preparation", nil, nil), "Bearer projected-token")
	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, http.StatusBadRequest, &decoded)
	if decoded.Reason != "invalid-execution-profile-configuration" {
		t.Fatalf("unexpected invalid preparation response: %#v", decoded)
	}
	runs := &nvtv1alpha1.AgentRunList{}
	if err := fixture.client.List(context.Background(), runs, client.InNamespace(schedule.Namespace)); err != nil {
		t.Fatal(err)
	}
	if len(runs.Items) != 0 {
		t.Fatalf("invalid preparation created AgentRuns: %#v", runs.Items)
	}
}

func TestAgentRunBrokerGrantDeepCopyPreservesEmptySlices(t *testing.T) {
	grant := nvtv1alpha1.AgentRunBrokerGrant{
		Provider:     "codex-main",
		Repositories: []string{},
		EgressHosts:  []string{},
		Preparations: []nvtv1alpha1.AgentRunBrokerPreparation{},
	}

	copy := grant.DeepCopy()
	if copy.Repositories == nil {
		t.Fatal("deep copy changed explicit empty repositories into nil")
	}
	if copy.EgressHosts == nil {
		t.Fatal("deep copy changed explicit empty egress hosts into nil")
	}
	if copy.Preparations == nil {
		t.Fatal("deep copy changed explicit empty preparations into nil")
	}
}

func TestTolerationDeepCopyPreservesNilAndExplicitEmpty(t *testing.T) {
	run := testAgentRun()
	if run.DeepCopyObject().(*nvtv1alpha1.AgentRun).Spec.Tolerations != nil {
		t.Fatal("deep copy changed nil AgentRun tolerations into an empty slice")
	}
	run.Spec.Tolerations = []corev1.Toleration{}
	if copied := run.DeepCopyObject().(*nvtv1alpha1.AgentRun).Spec.Tolerations; copied == nil || len(copied) != 0 {
		t.Fatalf("deep copy did not preserve explicit-empty AgentRun tolerations: %#v", copied)
	}
	tolerationSeconds := int64(45)
	run.Spec.Tolerations = []corev1.Toleration{{
		Key: "purpose", Operator: corev1.TolerationOpEqual, Value: "nvt-agent",
		Effect: corev1.TaintEffectNoExecute, TolerationSeconds: &tolerationSeconds,
	}}
	raw, err := json.Marshal(run)
	if err != nil {
		t.Fatalf("marshal AgentRun: %v", err)
	}
	var roundTripped nvtv1alpha1.AgentRun
	if err := json.Unmarshal(raw, &roundTripped); err != nil {
		t.Fatalf("unmarshal AgentRun: %v", err)
	}
	if !reflect.DeepEqual(roundTripped.Spec.Tolerations, run.Spec.Tolerations) {
		t.Fatalf("AgentRun tolerations changed across API round trip: %#v", roundTripped.Spec.Tolerations)
	}

	schedule := testProfiledAgentSchedule()
	schedule.Spec.Template.Tolerations = []corev1.Toleration{}
	if copied := schedule.DeepCopyObject().(*nvtv1alpha1.AgentSchedule).Spec.Template.Tolerations; copied == nil || len(copied) != 0 {
		t.Fatalf("deep copy did not preserve explicit-empty schedule tolerations: %#v", copied)
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
		crdPath(t, provenance, "principal", "properties", "subject", "type") != "string" ||
		crdPath(t, provenance, "selectedWorkflow", "type") != "string" {
		t.Fatalf("profile provenance schema incomplete: %#v", provenance)
	}
	validations := crdPath(t, crd,
		"spec", "versions", 0, "schema", "openAPIV3Schema", "properties",
		"spec", "x-kubernetes-validations",
	).([]any)
	foundProvenanceImmutability := false
	for _, validation := range validations {
		if strings.Contains(validation.(map[string]any)["rule"].(string), "oldSelf.profileProvenance") {
			foundProvenanceImmutability = true
		}
	}
	if !foundProvenanceImmutability {
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
	identity := ""
	if len(schedule.Spec.AllowedProducers) != 0 {
		identity = schedule.Spec.AllowedProducers[0]
	} else if len(schedule.Spec.ProducerPolicies) != 0 {
		identity = schedule.Spec.ProducerPolicies[0].Identity
	}
	return &profileAdmissionFixture{
		client: k8sClient, schedule: schedule, scheme: scheme,
		authenticator: fakeScheduleProducerAuthenticator{identity: identity},
	}
}

func testWorkflowProfiledAgentSchedule() *nvtv1alpha1.AgentSchedule {
	schedule := testProfiledAgentSchedule()
	schedule.Spec.AllowedProducers = nil
	schedule.Spec.WorkflowProfiles = []nvtv1alpha1.AgentScheduleWorkflowProfile{
		{Name: "implement-pr", WorkspaceInstructions: "Implement and create a pull request.\n"},
		{Name: "review-pr", WorkspaceInstructions: "Review and report findings first.\n"},
	}
	schedule.Spec.ProducerPolicies = []nvtv1alpha1.AgentScheduleProducerPolicy{
		{
			Identity: "system:serviceaccount:nvt:nvt-github-comments-producer", Workflows: []string{"implement-pr", "review-pr"},
			DefaultWorkflow: "implement-pr",
		},
		{
			Identity: "system:serviceaccount:nvt:review-producer", Workflows: []string{"review-pr"}, DefaultWorkflow: "review-pr",
		},
	}
	return schedule
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
