package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"github.com/mirkoSekulic/nvt-agent/operator/principalaccounts"
)

const (
	dynamicIssuer   = "https://identity.example/tenant"
	dynamicSubject  = "immutable-principal-42"
	dynamicProvider = "dpa_0123456789abcdef0123456789abcdef"
	secretNeedle    = "DYNAMIC-CREDENTIAL-SECRET-NEEDLE"
)

type fakePrincipalAccountResolver struct {
	mu         sync.Mutex
	resolution principalaccounts.Resolution
	err        error
	calls      []principalaccounts.Principal
}

func (f *fakePrincipalAccountResolver) Resolve(_ context.Context, principal principalaccounts.Principal) (principalaccounts.Resolution, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, principal)
	return f.resolution, f.err
}

func (f *fakePrincipalAccountResolver) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func testDynamicPrincipalSchedule() *nvtv1alpha1.AgentSchedule {
	schedule := testWorkflowProfiledAgentSchedule()
	schedule.Name = "dynamic-principal"
	schedule.UID = "dynamic-principal-uid"
	schedule.Spec.ProfileSelection = nil
	schedule.Spec.Profiles[0].Name = "dynamic-work"
	schedule.Spec.PrincipalCredentialSelection = &nvtv1alpha1.AgentSchedulePrincipalCredentialSelection{
		Enabled: true, OnNoMatch: nvtv1alpha1.AgentScheduleOnNoMatchDeny,
		TemplateProfiles: []nvtv1alpha1.AgentSchedulePrincipalCredentialTemplateProfile{{Template: "work", Profile: "dynamic-work"}},
	}
	schedule.Spec.ProducerPolicies[0].AllowedPrincipalIssuers = []string{dynamicIssuer}
	schedule.Spec.ProducerPolicies[1].AllowedPrincipalIssuers = []string{dynamicIssuer}
	profile := &schedule.Spec.Profiles[0]
	profile.Egress = nvtv1alpha1.AgentRunEgressMediated
	profile.EgressAllowInsecureBroker = true
	profile.EgressEnforcement = true
	profile.EgressTransport = nvtv1alpha1.AgentRunEgressTransportForwardProxy
	profile.Broker.Grants = []nvtv1alpha1.AgentRunBrokerGrant{
		{
			Provider: principalAccountProviderPlaceholder, Repositories: []string{"example/*"},
			Materialization: nvtv1alpha1.AgentRunGrantHeaderInject, EgressHosts: []string{"provider.example"},
		},
		{
			Provider: "source-control", Repositories: []string{"example/*"},
			Materialization: nvtv1alpha1.AgentRunGrantHeaderInject, EgressHosts: []string{"source.example"}, Git: true,
		},
	}
	profile.AgentRuntimeConfig = rawJSON(`{"command":"agent","proxy":{"provider":"$principal-account"},"literal":"prefix-$principal-account"}`)
	return schedule
}

func dynamicPrincipal() *scheduleAdmissionPrincipal {
	return &scheduleAdmissionPrincipal{Issuer: dynamicIssuer, Subject: dynamicSubject, DisplayName: "Display only"}
}

func readyFakeResolver() *fakePrincipalAccountResolver {
	return &fakePrincipalAccountResolver{resolution: principalaccounts.Resolution{
		Template: "work", ProviderInstanceID: dynamicProvider, Generation: 9,
	}}
}

func TestDynamicPrincipalAdmissionFreezesBrokerResolution(t *testing.T) {
	setTLSBrokerEnv(t)
	schedule := testDynamicPrincipalSchedule()
	resolver := readyFakeResolver()
	fixture := newProfileAdmissionFixture(t, schedule)
	fixture.principalAccounts = resolver

	response := fixture.serve(t, profiledAdmissionBody(t, "dynamic-ready", dynamicPrincipal(), map[string]any{"prompt": "perform work"}), "Bearer projected-token")
	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, http.StatusCreated, &decoded)
	run := fixture.run(t, decoded.AgentRun.Name)

	if resolver.callCount() != 1 || len(resolver.calls) != 1 || resolver.calls[0] != (principalaccounts.Principal{Issuer: dynamicIssuer, Subject: dynamicSubject}) {
		t.Fatalf("broker resolution did not use exact immutable principal: %#v", resolver.calls)
	}
	provenance := run.Spec.ProfileProvenance
	if provenance == nil || provenance.SelectedProfile != "dynamic-work" || provenance.Principal == nil ||
		provenance.Principal.Issuer != dynamicIssuer || provenance.Principal.Subject != dynamicSubject ||
		provenance.PrincipalCredential == nil || provenance.PrincipalCredential.Template != "work" ||
		provenance.PrincipalCredential.ProviderInstanceID != dynamicProvider || provenance.PrincipalCredential.Generation != 9 {
		t.Fatalf("dynamic provenance was not frozen: %#v", provenance)
	}
	if len(run.Spec.Broker.Grants) != 2 || run.Spec.Broker.Grants[0].Provider != dynamicProvider ||
		run.Spec.Broker.Grants[1].Provider != "source-control" {
		t.Fatalf("provider binding changed unrelated grants: %#v", run.Spec.Broker)
	}
	var config map[string]any
	if err := json.Unmarshal(run.Spec.Agent.Config.Raw, &config); err != nil {
		t.Fatal(err)
	}
	runtimeConfig := config["runtime"].(map[string]any)
	if runtimeConfig["proxy"].(map[string]any)["provider"] != dynamicProvider || runtimeConfig["literal"] != "prefix-$principal-account" {
		t.Fatalf("runtime provider placeholder binding was not exact-scalar: %#v", runtimeConfig)
	}
	raw, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secretNeedle) {
		t.Fatal("credential needle entered AgentRun")
	}
}

func TestDynamicPrincipalAdmissionReservationWrapsResolveAndCreate(t *testing.T) {
	setTLSBrokerEnv(t)
	schedule := testDynamicPrincipalSchedule()
	resolver := readyFakeResolver()
	coordinator := &recordingPrincipalCoordinator{}
	fixture := newProfileAdmissionFixture(t, schedule)
	fixture.principalAccounts = resolver
	fixture.principalCoordination = coordinator

	response := fixture.serve(
		t,
		profiledAdmissionBody(t, "coordinated", dynamicPrincipal(), nil),
		"Bearer projected-token",
	)
	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, http.StatusCreated, &decoded)
	calls := coordinator.snapshot()
	if len(calls) != 2 || !strings.HasPrefix(calls[0], "begin-admission:") ||
		!strings.HasPrefix(calls[1], "end-admission:") {
		t.Fatalf("admission reservation did not wrap create: %#v", calls)
	}
	beginParts, endParts := strings.Split(calls[0], ":"), strings.Split(calls[1], ":")
	if len(beginParts) != 3 || len(endParts) != 3 || beginParts[1] != endParts[1] ||
		beginParts[2] != dynamicSubject || endParts[2] != dynamicSubject {
		t.Fatalf("admission reservation was not exact-principal/idempotent: %#v", calls)
	}

	failedSchedule := testDynamicPrincipalSchedule()
	failedSchedule.Name = "coordination-failed"
	failed := newProfileAdmissionFixture(t, failedSchedule)
	failed.principalAccounts = readyFakeResolver()
	failed.principalCoordination = &recordingPrincipalCoordinator{beginErr: principalaccounts.ErrCoordination}
	denied := failed.serve(
		t,
		profiledAdmissionBody(t, "coordination-failed", dynamicPrincipal(), nil),
		"Bearer projected-token",
	)
	var deniedResponse scheduleAdmissionResponse
	decodeAdmissionResponse(t, denied, http.StatusServiceUnavailable, &deniedResponse)
	if deniedResponse.Reason != "credential-resolution-unavailable" || failed.principalAccounts.(*fakePrincipalAccountResolver).callCount() != 0 {
		t.Fatalf("failed reservation did not fail before resolution: %q", denied.Body.String())
	}
}

func TestDynamicPrincipalAdmissionStableFailClosedReasons(t *testing.T) {
	setTLSBrokerEnv(t)
	tests := []struct {
		name   string
		err    error
		result principalaccounts.Resolution
		status int
		reason string
	}{
		{name: "not-enrolled", err: principalaccounts.ErrNotEnrolled, status: http.StatusForbidden, reason: "principal-not-enrolled"},
		{name: "eligibility-expired", err: principalaccounts.ErrNotEligible, status: http.StatusForbidden, reason: "principal-not-eligible"},
		{name: "unready", err: principalaccounts.ErrNotReady, status: http.StatusConflict, reason: "credential-not-ready"},
		{name: "broker-unavailable", err: errors.New("TLS SECRET-NEEDLE internal"), status: http.StatusServiceUnavailable, reason: "credential-resolution-unavailable"},
		{name: "unknown-template", result: principalaccounts.Resolution{Template: "unmapped-secret-template", ProviderInstanceID: dynamicProvider, Generation: 4}, status: http.StatusServiceUnavailable, reason: "credential-resolution-unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schedule := testDynamicPrincipalSchedule()
			resolver := &fakePrincipalAccountResolver{resolution: test.result, err: test.err}
			fixture := newProfileAdmissionFixture(t, schedule)
			fixture.principalAccounts = resolver
			response := fixture.serve(t, profiledAdmissionBody(t, test.name, dynamicPrincipal(), nil), "Bearer projected-token")
			var decoded scheduleAdmissionResponse
			decodeAdmissionResponse(t, response, test.status, &decoded)
			if decoded.Scheduled || decoded.Reason != test.reason || strings.Contains(response.Body.String(), "SECRET") ||
				strings.Contains(response.Body.String(), "unmapped") || strings.Contains(response.Body.String(), dynamicProvider) {
				t.Fatalf("unstable or sensitive failure: status=%d response=%q", response.Code, response.Body.String())
			}
			runs := &nvtv1alpha1.AgentRunList{}
			if err := fixture.client.List(context.Background(), runs, client.InNamespace(schedule.Namespace)); err != nil || len(runs.Items) != 0 {
				t.Fatalf("failed resolution created a run: err=%v runs=%#v", err, runs.Items)
			}
		})
	}
}

func TestDynamicPrincipalAdmissionRequiresEligibleIssuerBeforeBroker(t *testing.T) {
	setTLSBrokerEnv(t)
	for _, principal := range []*scheduleAdmissionPrincipal{
		nil,
		{Issuer: "https://other-issuer.example", Subject: dynamicSubject},
		{Issuer: dynamicIssuer, Subject: " subject"},
	} {
		schedule := testDynamicPrincipalSchedule()
		resolver := readyFakeResolver()
		fixture := newProfileAdmissionFixture(t, schedule)
		fixture.principalAccounts = resolver
		response := fixture.serve(t, profiledAdmissionBody(t, "ineligible", principal, nil), "Bearer projected-token")
		var decoded scheduleAdmissionResponse
		decodeAdmissionResponse(t, response, http.StatusForbidden, &decoded)
		if decoded.Reason != "principal-not-eligible" || resolver.callCount() != 0 {
			t.Fatalf("ineligible principal reached broker: response=%q calls=%d", response.Body.String(), resolver.callCount())
		}
	}
}

func TestDynamicPrincipalProducerCannotOverrideTrustedSelection(t *testing.T) {
	for _, field := range []string{"template", "provider", "providerInstanceID", "credentialGeneration", "profile", "grants", "capabilities", "runtime", "egress"} {
		schedule := testDynamicPrincipalSchedule()
		resolver := readyFakeResolver()
		fixture := newProfileAdmissionFixture(t, schedule)
		fixture.principalAccounts = resolver
		payload := profiledAdmissionPayload("override-"+field, dynamicPrincipal(), nil)
		payload[field] = map[string]any{"value": secretNeedle}
		response := fixture.serve(t, mustJSON(t, payload), "Bearer projected-token")
		if response.Code != http.StatusBadRequest || resolver.callCount() != 0 || strings.Contains(response.Body.String(), secretNeedle) {
			t.Fatalf("trusted field %q was accepted or leaked: status=%d body=%q calls=%d", field, response.Code, response.Body.String(), resolver.callCount())
		}
	}
}

func TestDynamicPrincipalRetryDoesNotReresolveOrRewriteRun(t *testing.T) {
	setTLSBrokerEnv(t)
	schedule := testDynamicPrincipalSchedule()
	resolver := readyFakeResolver()
	fixture := newProfileAdmissionFixture(t, schedule)
	fixture.principalAccounts = resolver
	body := profiledAdmissionBody(t, "idempotent-work", dynamicPrincipal(), nil)
	first := fixture.serve(t, body, "Bearer projected-token")
	var firstDecoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, first, http.StatusCreated, &firstDecoded)
	before := fixture.run(t, firstDecoded.AgentRun.Name)

	resolver.mu.Lock()
	resolver.resolution = principalaccounts.Resolution{Template: "work", ProviderInstanceID: "dpa_abcdef0123456789abcdef0123456789", Generation: 10}
	resolver.err = principalaccounts.ErrNotReady
	resolver.mu.Unlock()
	retry := fixture.serve(t, body, "Bearer projected-token")
	var retryDecoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, retry, http.StatusAccepted, &retryDecoded)
	if retryDecoded.Reason != "duplicate-work" || resolver.callCount() != 1 {
		t.Fatalf("retry re-resolved broker state: response=%q calls=%d", retry.Body.String(), resolver.callCount())
	}
	after := fixture.run(t, before.Name)
	if after.Spec.ProfileProvenance.PrincipalCredential.ProviderInstanceID != dynamicProvider ||
		after.Spec.ProfileProvenance.PrincipalCredential.Generation != 9 || after.Spec.Broker.Grants[0].Provider != dynamicProvider {
		t.Fatalf("existing AgentRun changed after account reconnect/revoke: %#v", after.Spec)
	}
}

func TestDynamicPrincipalConfigurationFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*nvtv1alpha1.AgentSchedule)
	}{
		{name: "static-and-dynamic", mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
			schedule.Spec.ProfileSelection = &nvtv1alpha1.AgentScheduleProfileSelection{OnNoMatch: nvtv1alpha1.AgentScheduleOnNoMatchDeny}
		}},
		{name: "unknown-profile", mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
			schedule.Spec.PrincipalCredentialSelection.TemplateProfiles[0].Profile = "missing"
		}},
		{name: "duplicate-template", mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
			schedule.Spec.PrincipalCredentialSelection.TemplateProfiles = append(schedule.Spec.PrincipalCredentialSelection.TemplateProfiles, schedule.Spec.PrincipalCredentialSelection.TemplateProfiles[0])
		}},
		{name: "direct-egress", mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
			schedule.Spec.Profiles[0].Egress = nvtv1alpha1.AgentRunEgressDirect
		}},
		{name: "file-bundle", mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
			schedule.Spec.Profiles[0].Broker.Grants[0].Materialization = nvtv1alpha1.AgentRunGrantFileBundle
		}},
		{name: "missing-placeholder", mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
			schedule.Spec.Profiles[0].Broker.Grants[0].Provider = "static"
		}},
		{name: "missing-issuer-policy", mutate: func(schedule *nvtv1alpha1.AgentSchedule) {
			schedule.Spec.ProducerPolicies[0].AllowedPrincipalIssuers = nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schedule := testDynamicPrincipalSchedule()
			test.mutate(schedule)
			if _, err := validateExecutionProfileSchedule(schedule); !errors.Is(err, errInvalidExecutionProfileConfiguration) {
				t.Fatalf("invalid dynamic configuration accepted: %v", err)
			}
		})
	}
}

func TestDynamicPrincipalDeepCopyIsolation(t *testing.T) {
	schedule := testDynamicPrincipalSchedule()
	copy := schedule.DeepCopyObject().(*nvtv1alpha1.AgentSchedule)
	copy.Spec.PrincipalCredentialSelection.TemplateProfiles[0].Template = "changed"
	copy.Spec.ProducerPolicies[0].AllowedPrincipalIssuers[0] = "https://changed.example"
	if schedule.Spec.PrincipalCredentialSelection.TemplateProfiles[0].Template != "work" ||
		schedule.Spec.ProducerPolicies[0].AllowedPrincipalIssuers[0] != dynamicIssuer {
		t.Fatal("dynamic AgentSchedule fields were not deep-copied")
	}
	run := testAgentRun()
	run.Spec.ProfileProvenance = &nvtv1alpha1.AgentRunProfileProvenance{PrincipalCredential: &nvtv1alpha1.AgentRunPrincipalCredentialProvenance{
		Template: "work", ProviderInstanceID: dynamicProvider, Generation: 9,
	}}
	runCopy := run.DeepCopyObject().(*nvtv1alpha1.AgentRun)
	runCopy.Spec.ProfileProvenance.PrincipalCredential.Generation = 10
	if run.Spec.ProfileProvenance.PrincipalCredential.Generation != 9 {
		t.Fatal("dynamic AgentRun provenance was not deep-copied")
	}
}

func TestStaticProfileAdmissionDoesNotRequirePrincipalAccountResolver(t *testing.T) {
	schedule := testWorkflowProfiledAgentSchedule()
	fixture := newProfileAdmissionFixture(t, schedule)
	response := fixture.serve(t, profiledAdmissionBody(t, "static-compatible", nil, nil), "Bearer projected-token")
	if response.Code != http.StatusCreated {
		t.Fatalf("static profile admission changed: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestDynamicPrincipalProvenanceCarriesScheduleGeneration(t *testing.T) {
	schedule := testDynamicPrincipalSchedule()
	resolved := &ResolvedExecutionProfile{
		Profile: schedule.Spec.Profiles[0], Execution: &nvtv1alpha1.AgentRunExecution{Kind: nvtv1alpha1.AgentRunExecutionPod, Driver: "kubernetes"},
		PrincipalCredential: &nvtv1alpha1.AgentRunPrincipalCredentialProvenance{Template: "work", ProviderInstanceID: dynamicProvider, Generation: 9},
	}
	run, err := buildProfiledAgentRun(schedule, resolved, schedule.Spec.ProducerPolicies[0].Identity,
		&nvtv1alpha1.AgentRunPrincipal{Issuer: dynamicIssuer, Subject: dynamicSubject}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if run.Spec.ProfileProvenance.ScheduleGeneration != schedule.Generation || run.Spec.ProfileProvenance.ScheduleUID != string(schedule.UID) {
		t.Fatalf("profile provenance lost schedule source: %#v", run.Spec.ProfileProvenance)
	}
	// Mutating the resolver result after construction cannot alias the run.
	resolved.PrincipalCredential.Generation = 10
	if run.Spec.ProfileProvenance.PrincipalCredential.Generation != 9 {
		t.Fatal("built run aliases mutable resolution provenance")
	}
}
