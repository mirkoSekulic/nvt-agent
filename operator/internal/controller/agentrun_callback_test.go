package controller

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

func TestCallbackRejectsMissingAuthorization(t *testing.T) {
	response, _ := serveCallback(t, callbackFixture(t), "", `{"event":{"event":"plugin.agent.signal.done"}}`)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%q", response.Code, response.Body.String())
	}
}

func TestCallbackRejectsMalformedAuthorization(t *testing.T) {
	response, _ := serveCallback(t, callbackFixture(t), "Basic callback-token", `{"event":{"event":"plugin.agent.signal.done"}}`)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%q", response.Code, response.Body.String())
	}
}

func TestCallbackRejectsWrongTokenWithoutLeakingToken(t *testing.T) {
	response, _ := serveCallback(t, callbackFixture(t), "Bearer wrong-token", `{"event":{"event":"plugin.agent.signal.done"}}`)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%q", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "wrong-token") || strings.Contains(response.Body.String(), "callback-token") {
		t.Fatalf("response leaked token material: %q", response.Body.String())
	}
}

func TestCallbackRejectsMalformedJSON(t *testing.T) {
	response, _ := serveCallback(t, callbackFixture(t), "Bearer callback-token", `{"event":`)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%q", response.Code, response.Body.String())
	}
}

func TestCallbackMissingAgentRunReturnsNotFound(t *testing.T) {
	fixture := callbackFixture(t)
	fixture.objects = []client.Object{}

	response, _ := serveCallback(t, fixture, "Bearer callback-token", `{"event":{"event":"plugin.agent.signal.done"}}`)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%q", response.Code, response.Body.String())
	}
}

func TestCallbackCompleteEventUpdatesStatus(t *testing.T) {
	fixture := callbackFixture(t)
	response, k8sClient := serveCallback(t, fixture, "Bearer callback-token", `{"agent":"example","event":{"event":"plugin.agent.signal.done"}}`)

	if response.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%q", response.Code, response.Body.String())
	}
	updated := getAgentRun(t, k8sClient, fixture.agentRun)
	if updated.Status.Phase != nvtv1alpha1.AgentRunPhaseCompleted {
		t.Fatalf("expected Completed, got %q", updated.Status.Phase)
	}
	if updated.Status.FinishedAt == nil || !updated.Status.FinishedAt.Equal(&fixture.now) {
		t.Fatalf("expected finishedAt %s, got %#v", fixture.now, updated.Status.FinishedAt)
	}
	if updated.Status.Reason != "Completed by lifecycle event plugin.agent.signal.done" {
		t.Fatalf("unexpected reason %q", updated.Status.Reason)
	}
}

func TestCallbackFailEventUpdatesStatus(t *testing.T) {
	fixture := callbackFixture(t)
	response, k8sClient := serveCallback(t, fixture, "Bearer callback-token", `{"event":{"event":"plugin.agent.failed"}}`)

	if response.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%q", response.Code, response.Body.String())
	}
	updated := getAgentRun(t, k8sClient, fixture.agentRun)
	if updated.Status.Phase != nvtv1alpha1.AgentRunPhaseFailed {
		t.Fatalf("expected Failed, got %q", updated.Status.Phase)
	}
	if updated.Status.FinishedAt == nil || !updated.Status.FinishedAt.Equal(&fixture.now) {
		t.Fatalf("expected finishedAt %s, got %#v", fixture.now, updated.Status.FinishedAt)
	}
	if updated.Status.Reason != "Failed by lifecycle event plugin.agent.failed" {
		t.Fatalf("unexpected reason %q", updated.Status.Reason)
	}
}

func TestCallbackPluginEventWinsOverEvent(t *testing.T) {
	fixture := callbackFixture(t)
	body := `{"event":{"event":"plugin.agent.failed","plugin_event":"plugin.agent.signal.done"}}`

	response, k8sClient := serveCallback(t, fixture, "Bearer callback-token", body)

	if response.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%q", response.Code, response.Body.String())
	}
	updated := getAgentRun(t, k8sClient, fixture.agentRun)
	if updated.Status.Phase != nvtv1alpha1.AgentRunPhaseCompleted {
		t.Fatalf("expected plugin_event to win and complete, got %q", updated.Status.Phase)
	}
}

func TestCallbackOrdinaryEventMatchesWhenPluginEventEmpty(t *testing.T) {
	fixture := callbackFixture(t)
	response, k8sClient := serveCallback(t, fixture, "Bearer callback-token", `{"event":{"event":"plugin.agent.signal.done","plugin_event":""}}`)

	if response.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%q", response.Code, response.Body.String())
	}
	updated := getAgentRun(t, k8sClient, fixture.agentRun)
	if updated.Status.Phase != nvtv1alpha1.AgentRunPhaseCompleted {
		t.Fatalf("expected ordinary event to complete, got %q", updated.Status.Phase)
	}
}

func TestCallbackUnknownEventIsAcceptedNoOp(t *testing.T) {
	fixture := callbackFixture(t)
	response, k8sClient := serveCallback(t, fixture, "Bearer callback-token", `{"event":{"event":"plugin.unmatched"}}`)

	if response.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%q", response.Code, response.Body.String())
	}
	updated := getAgentRun(t, k8sClient, fixture.agentRun)
	if updated.Status.Phase != nvtv1alpha1.AgentRunPhaseRunning || updated.Status.FinishedAt != nil || updated.Status.Reason != "running" {
		t.Fatalf("expected no status change, got %#v", updated.Status)
	}
}

func TestCallbackMissingEventNameIsBadRequest(t *testing.T) {
	response, _ := serveCallback(t, callbackFixture(t), "Bearer callback-token", `{"event":{"payload":{}}}`)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%q", response.Code, response.Body.String())
	}
}

func TestCallbackDoesNotOverwriteTerminalPhase(t *testing.T) {
	fixture := callbackFixture(t)
	agentRun := fixture.agentRun.DeepCopyObject().(*nvtv1alpha1.AgentRun)
	agentRun.Status.Phase = nvtv1alpha1.AgentRunPhaseCompleted
	agentRun.Status.Reason = "already complete"
	fixture.agentRun = agentRun
	fixture.objects[0] = agentRun

	response, k8sClient := serveCallback(t, fixture, "Bearer callback-token", `{"event":{"event":"plugin.agent.failed"}}`)

	if response.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%q", response.Code, response.Body.String())
	}
	updated := getAgentRun(t, k8sClient, fixture.agentRun)
	if updated.Status.Phase != nvtv1alpha1.AgentRunPhaseCompleted || updated.Status.Reason != "already complete" {
		t.Fatalf("expected terminal status not to change, got %#v", updated.Status)
	}
}

func TestCallbackRejectsMissingSecretAsNotFound(t *testing.T) {
	fixture := callbackFixture(t)
	fixture.objects = []client.Object{fixture.agentRun}

	response, _ := serveCallback(t, fixture, "Bearer callback-token", `{"event":{"event":"plugin.agent.signal.done"}}`)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%q", response.Code, response.Body.String())
	}
}

type callbackTestFixture struct {
	agentRun *nvtv1alpha1.AgentRun
	now      metav1.Time
	objects  []client.Object
}

func callbackFixture(t *testing.T) callbackTestFixture {
	t.Helper()

	agentRun := testAgentRun()
	agentRun.Spec.Agent.Config = apiextensionsv1.JSON{Raw: []byte("{}")}
	agentRun.Spec.Lifecycle = &nvtv1alpha1.AgentRunLifecycle{
		CompleteOn: []string{"plugin.agent.signal.done"},
		FailOn:     []string{"plugin.agent.failed"},
	}
	agentRun.Status.Phase = nvtv1alpha1.AgentRunPhaseRunning
	agentRun.Status.Reason = "running"
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CallbackTokenSecretName(agentRun.Name),
			Namespace: agentRun.Namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{callbackTokenKey: []byte("callback-token")},
	}

	return callbackTestFixture{
		agentRun: agentRun,
		now:      metav1.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC),
		objects:  []client.Object{agentRun, secret},
	}
}

func serveCallback(t *testing.T, fixture callbackTestFixture, authorization string, body string) (*httptest.ResponseRecorder, client.Client) {
	t.Helper()

	scheme := testScheme(t)
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(fixture.objects...).
		Build()
	handler := &agentRunCallbackHandler{
		client: k8sClient,
		now:    func() metav1.Time { return fixture.now },
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/agentruns/default/example/events", bytes.NewBufferString(body))
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	return response, k8sClient
}

func getAgentRun(t *testing.T, k8sClient client.Client, agentRun *nvtv1alpha1.AgentRun) nvtv1alpha1.AgentRun {
	t.Helper()

	var updated nvtv1alpha1.AgentRun
	if err := k8sClient.Get(context.Background(), clientKey(agentRun), &updated); err != nil {
		t.Fatalf("get AgentRun: %v", err)
	}
	return updated
}
