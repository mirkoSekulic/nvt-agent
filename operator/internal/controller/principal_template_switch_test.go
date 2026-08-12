package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"github.com/mirkoSekulic/nvt-agent/operator/principalaccounts"
)

type recordingPrincipalCoordinator struct {
	principal principalaccounts.Principal
	beginErr  error
	mu        sync.Mutex
	calls     []string
}

func (c *recordingPrincipalCoordinator) BeginAdmission(
	_ context.Context,
	principal principalaccounts.Principal,
	operationID string,
) (principalaccounts.Reservation, error) {
	c.record("begin-admission:" + operationID + ":" + principal.Subject)
	return principalaccounts.Reservation{ExpiresAt: time.Now().Add(time.Minute)}, c.beginErr
}

func (c *recordingPrincipalCoordinator) EndAdmission(_ context.Context, principal principalaccounts.Principal, operationID string) error {
	c.record("end-admission:" + operationID + ":" + principal.Subject)
	return nil
}

func (c *recordingPrincipalCoordinator) BeginTemplateSwitch(
	_ context.Context,
	requestID, operationID string,
) (principalaccounts.Principal, principalaccounts.Reservation, error) {
	c.record("begin-switch:" + requestID + ":" + operationID)
	return c.principal, principalaccounts.Reservation{ExpiresAt: time.Now().Add(time.Minute)}, c.beginErr
}

func (c *recordingPrincipalCoordinator) CommitTemplateSwitch(_ context.Context, principal principalaccounts.Principal, operationID string) error {
	c.record("commit-switch:" + operationID + ":" + principal.Subject)
	return nil
}

func (c *recordingPrincipalCoordinator) AbortTemplateSwitch(_ context.Context, principal principalaccounts.Principal, operationID string) error {
	c.record("abort-switch:" + operationID + ":" + principal.Subject)
	return nil
}

func (c *recordingPrincipalCoordinator) record(value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, value)
}

func (c *recordingPrincipalCoordinator) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.calls...)
}

func TestPrincipalTemplateSwitchDeniesActiveExactPrincipalAndCommitsAfterTerminal(t *testing.T) {
	scheme := testScheme(t)
	principal := principalaccounts.Principal{Issuer: dynamicIssuer, Subject: dynamicSubject}
	active := ownedSwitchRun("active", principal, nvtv1alpha1.AgentRunPhaseRunning)
	other := ownedSwitchRun(
		"other", principalaccounts.Principal{Issuer: dynamicIssuer, Subject: "other"},
		nvtv1alpha1.AgentRunPhaseRunning,
	)
	coordinator := &recordingPrincipalCoordinator{principal: principal}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(active, other).Build()
	handler := NewPrincipalTemplateSwitchHandler(client, coordinator, "nvt")

	denied := serveTemplateSwitch(t, handler, `{"request_id":"opaque-request"}`)
	if denied.Code != http.StatusConflict || denied.Body.String() != "{\"authorized\":false,\"reason\":\"active-agentruns\"}\n" {
		t.Fatalf("active run was not denied: %d %q", denied.Code, denied.Body.String())
	}
	if calls := strings.Join(coordinator.snapshot(), ","); calls !=
		"begin-switch:opaque-request:opaque-request,abort-switch:opaque-request:"+dynamicSubject {
		t.Fatalf("unexpected denied coordination calls: %s", calls)
	}

	active.Status.Phase = nvtv1alpha1.AgentRunPhaseCompleted
	if err := client.Update(t.Context(), active); err != nil {
		t.Fatal(err)
	}
	coordinator.calls = nil
	allowed := serveTemplateSwitch(t, handler, `{"request_id":"opaque-request"}`)
	if allowed.Code != http.StatusOK || allowed.Body.String() != "{\"authorized\":true}\n" {
		t.Fatalf("terminal-only owner was not authorized: %d %q", allowed.Code, allowed.Body.String())
	}
	if calls := strings.Join(coordinator.snapshot(), ","); calls !=
		"begin-switch:opaque-request:opaque-request,commit-switch:opaque-request:"+dynamicSubject {
		t.Fatalf("unexpected successful coordination calls: %s", calls)
	}
}

func TestPrincipalTemplateSwitchFailsClosedForMalformedAndDependencyErrors(t *testing.T) {
	scheme := testScheme(t)
	coordinator := &recordingPrincipalCoordinator{
		principal: principalaccounts.Principal{Issuer: dynamicIssuer, Subject: dynamicSubject},
		beginErr:  principalaccounts.ErrCoordination,
	}
	handler := NewPrincipalTemplateSwitchHandler(
		fake.NewClientBuilder().WithScheme(scheme).Build(), coordinator, "nvt",
	)
	for _, body := range []string{
		`{}`, `{"request_id":"a","request_id":"b"}`, `{"request_id":"a","template":"SECRET-NEEDLE"}`,
	} {
		response := serveTemplateSwitch(t, handler, body)
		if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "SECRET") {
			t.Fatalf("malformed request was not safely rejected: %d %q", response.Code, response.Body.String())
		}
	}
	response := serveTemplateSwitch(t, handler, `{"request_id":"opaque"}`)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), dynamicSubject) {
		t.Fatalf("dependency failure leaked identity: %d %q", response.Code, response.Body.String())
	}
}

func TestPrincipalTemplateSwitchFailsClosedForAmbiguousDynamicRunOwnership(t *testing.T) {
	scheme := testScheme(t)
	principal := principalaccounts.Principal{Issuer: dynamicIssuer, Subject: dynamicSubject}
	ambiguous := ownedSwitchRun("ambiguous", principal, nvtv1alpha1.AgentRunPhaseRunning)
	ambiguous.Spec.ProfileProvenance.Principal = nil
	coordinator := &recordingPrincipalCoordinator{principal: principal}
	handler := NewPrincipalTemplateSwitchHandler(
		fake.NewClientBuilder().WithScheme(scheme).WithObjects(ambiguous).Build(), coordinator, "nvt",
	)
	response := serveTemplateSwitch(t, handler, `{"request_id":"opaque-request"}`)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), dynamicSubject) {
		t.Fatalf("ambiguous ownership did not fail closed: %d %q", response.Code, response.Body.String())
	}
}

func ownedSwitchRun(
	name string,
	principal principalaccounts.Principal,
	phase nvtv1alpha1.AgentRunPhase,
) *nvtv1alpha1.AgentRun {
	return &nvtv1alpha1.AgentRun{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "nvt"},
		Spec: nvtv1alpha1.AgentRunSpec{ProfileProvenance: &nvtv1alpha1.AgentRunProfileProvenance{
			Principal: &nvtv1alpha1.AgentRunPrincipal{Issuer: principal.Issuer, Subject: principal.Subject},
			PrincipalCredential: &nvtv1alpha1.AgentRunPrincipalCredentialProvenance{
				Template: "approved", ProviderInstanceID: dynamicProvider, Generation: 1,
			},
		}},
		Status: nvtv1alpha1.AgentRunStatus{Phase: phase},
	}
}

func serveTemplateSwitch(t *testing.T, handler http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, principalTemplateSwitchPath, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
