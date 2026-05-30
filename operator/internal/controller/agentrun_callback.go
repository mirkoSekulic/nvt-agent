package controller

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

const agentRunCallbackPathPrefix = "/v1/agentruns/"

type agentRunCallbackHandler struct {
	client client.Client
	now    func() metav1.Time
}

type agentRunEventCallback struct {
	Agent string                    `json:"agent,omitempty"`
	Event agentRunEventCallbackBody `json:"event"`
}

type agentRunEventCallbackBody struct {
	ID          string         `json:"id,omitempty"`
	Event       string         `json:"event,omitempty"`
	PluginEvent string         `json:"plugin_event,omitempty"`
	Source      string         `json:"source,omitempty"`
	Payload     map[string]any `json:"payload,omitempty"`
}

// NewAgentRunCallbackHandler returns the cluster-internal AgentRun event callback handler.
func NewAgentRunCallbackHandler(k8sClient client.Client) http.Handler {
	return &agentRunCallbackHandler{
		client: k8sClient,
		now:    metav1.Now,
	}
}

func (h *agentRunCallbackHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(response, "method not allowed\n", http.StatusMethodNotAllowed)
		return
	}

	namespace, name, ok := parseAgentRunCallbackPath(request.URL.Path)
	if !ok {
		http.Error(response, "bad callback path\n", http.StatusBadRequest)
		return
	}

	ctx := request.Context()
	agentRun := &nvtv1alpha1.AgentRun{}
	if err := h.client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, agentRun); err != nil {
		if errors.IsNotFound(err) {
			http.Error(response, "AgentRun not found\n", http.StatusNotFound)
			return
		}
		http.Error(response, "get AgentRun failed\n", http.StatusInternalServerError)
		return
	}

	authenticated, authStatus := h.authenticate(ctx, namespace, name, request.Header.Get("Authorization"))
	if !authenticated {
		http.Error(response, http.StatusText(authStatus)+"\n", authStatus)
		return
	}

	var callback agentRunEventCallback
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, 1<<20))
	if err := decoder.Decode(&callback); err != nil {
		http.Error(response, "malformed JSON\n", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		http.Error(response, "malformed JSON\n", http.StatusBadRequest)
		return
	}

	eventName := ResolveAgentRunLifecycleEventName(callback.Event)
	if eventName == "" {
		http.Error(response, "missing event name\n", http.StatusBadRequest)
		return
	}

	if err := h.applyLifecycleEvent(ctx, agentRun, eventName); err != nil {
		http.Error(response, "update AgentRun status failed\n", http.StatusInternalServerError)
		return
	}

	response.WriteHeader(http.StatusAccepted)
}

func (h *agentRunCallbackHandler) authenticate(ctx context.Context, namespace, name, authorization string) (bool, int) {
	token, ok := bearerToken(authorization)
	if !ok {
		return false, http.StatusUnauthorized
	}

	secret := &corev1.Secret{}
	key := types.NamespacedName{Namespace: namespace, Name: CallbackTokenSecretName(name)}
	if err := h.client.Get(ctx, key, secret); err != nil {
		if errors.IsNotFound(err) {
			return false, http.StatusNotFound
		}
		return false, http.StatusInternalServerError
	}
	expected := secret.Data[callbackTokenKey]
	if len(expected) == 0 {
		return false, http.StatusUnauthorized
	}

	if subtle.ConstantTimeCompare([]byte(token), expected) != 1 {
		return false, http.StatusUnauthorized
	}
	return true, http.StatusAccepted
}

func (h *agentRunCallbackHandler) applyLifecycleEvent(ctx context.Context, agentRun *nvtv1alpha1.AgentRun, eventName string) error {
	key := client.ObjectKeyFromObject(agentRun)
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &nvtv1alpha1.AgentRun{}
		if err := h.client.Get(ctx, key, current); err != nil {
			return err
		}
		nextPhase, reason, matched := AgentRunLifecycleTransition(current.Spec.Lifecycle, eventName)
		if !matched || IsTerminalAgentRunPhase(current.Status.Phase) {
			return nil
		}

		current.Status.Phase = nextPhase
		now := h.now()
		current.Status.FinishedAt = &now
		current.Status.Reason = reason
		return h.client.Status().Update(ctx, current)
	}); err != nil {
		return fmt.Errorf("update AgentRun lifecycle status: %w", err)
	}

	return nil
}

func parseAgentRunCallbackPath(path string) (string, string, bool) {
	remainder, ok := strings.CutPrefix(path, agentRunCallbackPathPrefix)
	if !ok {
		return "", "", false
	}
	parts := strings.Split(remainder, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] != "events" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func bearerToken(authorization string) (string, bool) {
	token, ok := strings.CutPrefix(authorization, "Bearer ")
	if !ok {
		return "", false
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	return token, true
}

// ResolveAgentRunLifecycleEventName returns the lifecycle event name used for matching.
func ResolveAgentRunLifecycleEventName(event agentRunEventCallbackBody) string {
	if event.PluginEvent != "" {
		return event.PluginEvent
	}
	return event.Event
}

// AgentRunLifecycleTransition returns the terminal phase for a matched lifecycle event.
func AgentRunLifecycleTransition(lifecycle *nvtv1alpha1.AgentRunLifecycle, eventName string) (nvtv1alpha1.AgentRunPhase, string, bool) {
	if lifecycle == nil {
		return "", "", false
	}
	if stringInSlice(eventName, lifecycle.CompleteOn) {
		return nvtv1alpha1.AgentRunPhaseCompleted, "Completed by lifecycle event " + eventName, true
	}
	if stringInSlice(eventName, lifecycle.FailOn) {
		return nvtv1alpha1.AgentRunPhaseFailed, "Failed by lifecycle event " + eventName, true
	}
	return "", "", false
}

func stringInSlice(value string, values []string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
