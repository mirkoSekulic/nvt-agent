package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"github.com/mirkoSekulic/nvt-agent/operator/principalaccounts"
)

const (
	principalTemplateSwitchPath = "/v1/principal-accounts/authorize-template-switch"
	maxTemplateSwitchAgentRuns  = 1000
)

type principalTemplateSwitchHandler struct {
	client      client.Reader
	coordinator principalaccounts.Coordinator
	namespace   string
	capacity    chan struct{}
}

// NewPrincipalTemplateSwitchHandler returns the target-free trusted switch coordinator.
func NewPrincipalTemplateSwitchHandler(
	k8sClient client.Reader,
	coordinator principalaccounts.Coordinator,
	namespace string,
) http.Handler {
	return &principalTemplateSwitchHandler{
		client: k8sClient, coordinator: coordinator, namespace: namespace, capacity: make(chan struct{}, 16),
	}
}

func (h *principalTemplateSwitchHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if request.Method != http.MethodPost || request.URL.Path != principalTemplateSwitchPath || request.URL.RawQuery != "" {
		http.NotFound(response, request)
		return
	}
	if h.coordinator == nil || h.client == nil || h.namespace == "" {
		writeTemplateSwitchResponse(response, http.StatusServiceUnavailable, false, "coordination-unavailable")
		return
	}
	select {
	case h.capacity <- struct{}{}:
		defer func() { <-h.capacity }()
	default:
		writeTemplateSwitchResponse(response, http.StatusServiceUnavailable, false, "coordination-unavailable")
		return
	}
	requestID, ok := decodeTemplateSwitchRequest(response, request)
	if !ok {
		return
	}
	principal, reservation, err := h.coordinator.BeginTemplateSwitch(request.Context(), requestID, requestID)
	if errors.Is(err, principalaccounts.ErrSwitchRequestNotFound) {
		writeTemplateSwitchResponse(response, http.StatusNotFound, false, "switch-request-not-found")
		return
	}
	if err != nil {
		writeTemplateSwitchResponse(response, http.StatusServiceUnavailable, false, "coordination-unavailable")
		return
	}
	coordinationContext, cancel := context.WithDeadline(
		request.Context(), reservation.ExpiresAt.Add(-time.Second),
	)
	defer cancel()
	committed := false
	defer func() {
		if committed {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.coordinator.AbortTemplateSwitch(ctx, principal, requestID)
	}()

	var runs nvtv1alpha1.AgentRunList
	if err := h.client.List(
		coordinationContext, &runs, client.InNamespace(h.namespace), client.Limit(maxTemplateSwitchAgentRuns+1),
	); err != nil || len(runs.Items) > maxTemplateSwitchAgentRuns || runs.Continue != "" {
		writeTemplateSwitchResponse(response, http.StatusServiceUnavailable, false, "coordination-unavailable")
		return
	}
	for index := range runs.Items {
		owned, valid := activeRunOwnedBy(&runs.Items[index], principal)
		if !valid {
			writeTemplateSwitchResponse(response, http.StatusServiceUnavailable, false, "coordination-unavailable")
			return
		}
		if owned {
			writeTemplateSwitchResponse(response, http.StatusConflict, false, "active-agentruns")
			return
		}
	}
	if err := h.coordinator.CommitTemplateSwitch(coordinationContext, principal, requestID); err != nil {
		writeTemplateSwitchResponse(response, http.StatusServiceUnavailable, false, "coordination-unavailable")
		return
	}
	committed = true
	writeTemplateSwitchResponse(response, http.StatusOK, true, "")
}

func decodeTemplateSwitchRequest(response http.ResponseWriter, request *http.Request) (string, bool) {
	if request.Header.Get("Content-Type") != "application/json" {
		http.Error(response, "malformed request", http.StatusBadRequest)
		return "", false
	}
	body, err := io.ReadAll(http.MaxBytesReader(response, request.Body, 4096))
	if err != nil || len(body) == 0 || !json.Valid(body) || duplicateJSONKey(body) {
		http.Error(response, "malformed request", http.StatusBadRequest)
		return "", false
	}
	var payload struct {
		RequestID string `json:"request_id"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&payload) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		payload.RequestID == "" || len(payload.RequestID) > 128 ||
		strings.TrimSpace(payload.RequestID) != payload.RequestID || strings.ContainsAny(payload.RequestID, "\x00\r\n") {
		http.Error(response, "malformed request", http.StatusBadRequest)
		return "", false
	}
	return payload.RequestID, true
}

func duplicateJSONKey(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() bool
	walk = func() bool {
		token, err := decoder.Token()
		if err != nil {
			return true
		}
		delimiter, container := token.(json.Delim)
		if !container {
			return false
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				key, valid := keyToken.(string)
				if keyErr != nil || !valid {
					return true
				}
				if _, exists := seen[key]; exists {
					return true
				}
				seen[key] = struct{}{}
				if walk() {
					return true
				}
			}
		case '[':
			for decoder.More() {
				if walk() {
					return true
				}
			}
		default:
			return true
		}
		_, err = decoder.Token()
		return err != nil
	}
	return walk()
}

func activeRunOwnedBy(run *nvtv1alpha1.AgentRun, principal principalaccounts.Principal) (bool, bool) {
	if IsTerminalAgentRunPhase(run.Status.Phase) || run.Spec.ProfileProvenance == nil ||
		run.Spec.ProfileProvenance.PrincipalCredential == nil {
		return false, true
	}
	owner := run.Spec.ProfileProvenance.Principal
	if owner == nil || owner.Issuer == "" || owner.Subject == "" {
		return false, false
	}
	return owner.Issuer == principal.Issuer && owner.Subject == principal.Subject, true
}

func writeTemplateSwitchResponse(response http.ResponseWriter, status int, authorized bool, reason string) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(struct {
		Authorized bool   `json:"authorized"`
		Reason     string `json:"reason,omitempty"`
	}{Authorized: authorized, Reason: reason})
}
