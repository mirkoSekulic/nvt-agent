package controller

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"github.com/mirkoSekulic/nvt-agent/operator/principalaccounts"
)

const (
	scheduleAdmissionPathPrefix                = "/v1/schedules/"
	invalidExecutionProfileConfigurationReason = "invalid-execution-profile-configuration"
	maxParallelismReachedReason                = "max-parallelism-reached"
	principalMaxParallelismReachedReason       = "principal-max-parallelism-reached"
)

type agentScheduleAdmissionHandler struct {
	client                client.Client
	reader                client.Reader
	scheme                *runtime.Scheme
	authenticator         ScheduleProducerAuthenticator
	profileResolver       ExecutionProfileResolver
	principalAccounts     principalaccounts.Resolver
	principalCoordination principalaccounts.Coordinator
	now                   func() metav1.Time
	admissionLocks        *scheduleAdmissionLocks
}

type scheduleAdmissionRequest struct {
	Workflow string                  `json:"workflow,omitempty"`
	Work     scheduleAdmissionWork   `json:"work"`
	Input    *scheduleAdmissionInput `json:"input,omitempty"`
	AgentRun *nvtv1alpha1.AgentRun   `json:"agentRun,omitempty"`
}

type scheduleAdmissionWork struct {
	ID         string                      `json:"id"`
	Group      string                      `json:"group,omitempty"`
	Title      string                      `json:"title,omitempty"`
	URL        string                      `json:"url,omitempty"`
	Repository string                      `json:"repository,omitempty"`
	Principal  *scheduleAdmissionPrincipal `json:"principal,omitempty"`
}

type scheduleAdmissionPrincipal struct {
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	DisplayName string `json:"displayName,omitempty"`
}

type scheduleAdmissionInput struct {
	Prompt string `json:"prompt,omitempty"`
}

type scheduleAdmissionResponse struct {
	Scheduled bool                       `json:"scheduled"`
	Reason    string                     `json:"reason,omitempty"`
	AgentRun  *scheduleAdmissionAgentRun `json:"agentRun,omitempty"`
}

type scheduleAdmissionAgentRun struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// NewAgentScheduleAdmissionHandler returns the cluster-internal schedule admission handler.
func NewAgentScheduleAdmissionHandler(k8sClient client.Client, scheme *runtime.Scheme) http.Handler {
	return NewAgentScheduleAdmissionHandlerWithPrincipalAccounts(k8sClient, k8sClient, scheme, nil)
}

// NewAgentScheduleAdmissionHandlerWithPrincipalAccounts adds the optional
// trusted dynamic principal-account resolver without changing static admission.
func NewAgentScheduleAdmissionHandlerWithPrincipalAccounts(
	k8sClient client.Client,
	reader client.Reader,
	scheme *runtime.Scheme,
	accounts principalaccounts.Resolver,
) http.Handler {
	coordination, _ := accounts.(principalaccounts.Coordinator)
	if enabled, ok := accounts.(interface{ CoordinationEnabled() bool }); !ok || !enabled.CoordinationEnabled() {
		coordination = nil
	}
	return &agentScheduleAdmissionHandler{
		client:                k8sClient,
		reader:                reader,
		scheme:                scheme,
		authenticator:         NewKubernetesTokenReviewProducerAuthenticator(k8sClient),
		profileResolver:       StaticExecutionProfileResolver{},
		principalAccounts:     accounts,
		principalCoordination: coordination,
		now:                   metav1.Now,
		admissionLocks:        newScheduleAdmissionLocks(),
	}
}

func (h *agentScheduleAdmissionHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(response, "method not allowed\n", http.StatusMethodNotAllowed)
		return
	}

	namespace, name, ok := parseScheduleAdmissionPath(request.URL.Path)
	if !ok {
		http.Error(response, "bad schedule admission path\n", http.StatusBadRequest)
		return
	}

	var rawAdmission map[string]json.RawMessage
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, 1<<20))
	if err := decoder.Decode(&rawAdmission); err != nil || rawAdmission == nil {
		http.Error(response, "malformed JSON\n", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		http.Error(response, "malformed JSON\n", http.StatusBadRequest)
		return
	}
	encodedAdmission, err := json.Marshal(rawAdmission)
	if err != nil {
		http.Error(response, "malformed JSON\n", http.StatusBadRequest)
		return
	}
	var admission scheduleAdmissionRequest
	if err := json.Unmarshal(encodedAdmission, &admission); err != nil {
		http.Error(response, "malformed JSON\n", http.StatusBadRequest)
		return
	}

	ctx := request.Context()
	unlock := h.lockScheduleAdmission(namespace, name)
	defer unlock()

	reader := h.reader
	if reader == nil {
		reader = h.client
	}
	schedule := &nvtv1alpha1.AgentSchedule{}
	if getErr := reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, schedule); getErr != nil {
		if apierrors.IsNotFound(getErr) {
			http.Error(response, "AgentSchedule not found\n", http.StatusNotFound)
			return
		}
		http.Error(response, "get AgentSchedule failed\n", http.StatusInternalServerError)
		return
	}

	profiled := ScheduleUsesExecutionProfiles(schedule)
	producer := ""
	var resolvedWorkflow *ResolvedWorkflowProfile
	var principal *nvtv1alpha1.AgentRunPrincipal
	if profiled {
		token, ok := bearerToken(request.Header.Get("Authorization"))
		if !ok || h.authenticator == nil {
			http.Error(response, "producer authentication failed\n", http.StatusUnauthorized)
			return
		}
		producer, err = h.authenticator.Authenticate(ctx, token)
		if err != nil {
			http.Error(response, "producer authentication failed\n", http.StatusUnauthorized)
			return
		}
		if err := validateProfiledAdmissionShape(rawAdmission); err != nil {
			http.Error(response, "profiled admission accepts only work and input plus optional workflow\n", http.StatusBadRequest)
			return
		}
		if _, present := rawAdmission["workflow"]; present &&
			(strings.TrimSpace(admission.Workflow) == "" || admission.Workflow != strings.TrimSpace(admission.Workflow)) {
			http.Error(response, "invalid workflow selection\n", http.StatusBadRequest)
			return
		}
		resolvedWorkflow, err = resolveWorkflowForProducer(schedule, producer, admission.Workflow)
		switch {
		case errors.Is(err, errProducerNotAllowed):
			http.Error(response, "producer is not allowed\n", http.StatusForbidden)
			return
		case errors.Is(err, errWorkflowSelectionDenied):
			h.recordRejected(ctx, schedule, "workflow-selection-denied")
			writeScheduleAdmissionJSON(response, http.StatusForbidden, scheduleAdmissionResponse{
				Scheduled: false, Reason: "workflow-selection-denied",
			})
			return
		case err != nil:
			h.recordRejected(ctx, schedule, invalidExecutionProfileConfigurationReason)
			writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
				Scheduled: false, Reason: invalidExecutionProfileConfigurationReason,
			})
			return
		}
		principal = admissionPrincipal(admission.Work.Principal)
		if ScheduleUsesPrincipalCredentials(schedule) && !producerAllowsDynamicPrincipal(schedule, producer, principal) {
			h.recordRejected(ctx, schedule, "principal-not-eligible")
			writeScheduleAdmissionJSON(response, http.StatusForbidden, scheduleAdmissionResponse{
				Scheduled: false, Reason: "principal-not-eligible",
			})
			return
		}
	}

	workID := strings.TrimSpace(admission.Work.ID)
	if workID == "" {
		http.Error(response, "missing work.id\n", http.StatusBadRequest)
		return
	}
	workGroup := strings.TrimSpace(admission.Work.Group)
	if admission.Work.Group != workGroup || workGroup != "" && !validAdmissionWorkKey(workGroup) {
		http.Error(response, "invalid work.group\n", http.StatusBadRequest)
		return
	}

	runs, err := ListScheduledRuns(ctx, reader, schedule)
	if err != nil {
		http.Error(response, "list scheduled AgentRuns failed\n", http.StatusInternalServerError)
		return
	}
	if retainedWorkExists(runs, workID) || activeWorkGroupExists(runs, workGroup) {
		h.recordRejected(ctx, schedule, "duplicate-work")
		writeScheduleAdmissionJSON(response, http.StatusAccepted, scheduleAdmissionResponse{
			Scheduled: false,
			Reason:    "duplicate-work",
		})
		return
	}

	if schedule.Spec.Suspend {
		h.recordRejected(ctx, schedule, "schedule-suspended")
		writeScheduleAdmissionJSON(response, http.StatusAccepted, scheduleAdmissionResponse{
			Scheduled: false,
			Reason:    "schedule-suspended",
		})
		return
	}
	principalLimit := int32(0)
	if schedule.Spec.PrincipalParallelism != nil {
		if !profiled {
			h.recordRejected(ctx, schedule, invalidExecutionProfileConfigurationReason)
			writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
				Scheduled: false, Reason: invalidExecutionProfileConfigurationReason,
			})
			return
		}
		var limitErr error
		principalLimit, limitErr = principalParallelismLimit(schedule.Spec.PrincipalParallelism, principal)
		if errors.Is(limitErr, errPrincipalRequired) {
			h.recordRejected(ctx, schedule, "principal-required")
			writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
				Scheduled: false, Reason: "principal-required",
			})
			return
		}
		if limitErr != nil {
			h.recordRejected(ctx, schedule, invalidExecutionProfileConfigurationReason)
			writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
				Scheduled: false, Reason: invalidExecutionProfileConfigurationReason,
			})
			return
		}
	}

	activeRuns := countActiveScheduledRuns(runs)
	if activeRuns >= EffectiveMaxParallelism(schedule) {
		h.recordRejected(ctx, schedule, maxParallelismReachedReason)
		writeScheduleAdmissionJSON(response, http.StatusTooManyRequests, scheduleAdmissionResponse{
			Scheduled: false,
			Reason:    maxParallelismReachedReason,
		})
		return
	}
	if principalLimit > 0 && countActiveScheduledRunsForPrincipal(runs, principal) >= principalLimit {
		h.recordRejected(ctx, schedule, principalMaxParallelismReachedReason)
		writeScheduleAdmissionJSON(response, http.StatusTooManyRequests, scheduleAdmissionResponse{
			Scheduled: false,
			Reason:    principalMaxParallelismReachedReason,
		})
		return
	}
	var run nvtv1alpha1.AgentRun
	if profiled {
		if h.profileResolver == nil {
			h.profileResolver = StaticExecutionProfileResolver{}
		}
		if principal == nil {
			principal = admissionPrincipal(admission.Work.Principal)
		}
		if principal != nil && (strings.TrimSpace(principal.Issuer) == "" || strings.TrimSpace(principal.Subject) == "") {
			http.Error(response, "principal issuer and subject are required\n", http.StatusBadRequest)
			return
		}
		var resolved *ResolvedExecutionProfile
		var resolveErr error
		if ScheduleUsesPrincipalCredentials(schedule) {
			var coordinationOperation string
			if h.principalCoordination != nil {
				coordinationOperation, resolveErr = newPrincipalCoordinationOperationID()
				if resolveErr == nil {
					var reservation principalaccounts.Reservation
					reservation, resolveErr = h.principalCoordination.BeginAdmission(
						ctx,
						principalaccounts.Principal{Issuer: principal.Issuer, Subject: principal.Subject},
						coordinationOperation,
					)
					if resolveErr == nil {
						var cancel context.CancelFunc
						ctx, cancel = context.WithDeadline(ctx, reservation.ExpiresAt.Add(-time.Second))
						defer cancel()
					}
				}
				if resolveErr != nil {
					switch {
					case errors.Is(resolveErr, principalaccounts.ErrNotEnrolled):
						resolveErr = errPrincipalNotEnrolled
					case errors.Is(resolveErr, principalaccounts.ErrNotEligible):
						resolveErr = errPrincipalNotEligible
					default:
						resolveErr = errPrincipalCredentialResolution
					}
				}
				if resolveErr == nil {
					defer h.releasePrincipalAdmission(principal, coordinationOperation)
				}
			}
			if resolveErr == nil {
				resolved, resolveErr = resolvePrincipalCredentialProfile(ctx, schedule, principal, h.principalAccounts)
			}
		} else {
			resolved, resolveErr = h.profileResolver.Resolve(schedule, principal)
		}
		if resolveErr != nil {
			switch {
			case errors.Is(resolveErr, errExecutionProfileSelectionDenied):
				h.recordRejected(ctx, schedule, "profile-selection-denied")
				writeScheduleAdmissionJSON(response, http.StatusForbidden, scheduleAdmissionResponse{
					Scheduled: false, Reason: "profile-selection-denied",
				})
				return
			case errors.Is(resolveErr, errPrincipalNotEnrolled):
				h.recordRejected(ctx, schedule, "principal-not-enrolled")
				writeScheduleAdmissionJSON(response, http.StatusForbidden, scheduleAdmissionResponse{
					Scheduled: false, Reason: "principal-not-enrolled",
				})
				return
			case errors.Is(resolveErr, errPrincipalNotEligible):
				h.recordRejected(ctx, schedule, "principal-not-eligible")
				writeScheduleAdmissionJSON(response, http.StatusForbidden, scheduleAdmissionResponse{
					Scheduled: false, Reason: "principal-not-eligible",
				})
				return
			case errors.Is(resolveErr, errPrincipalCredentialNotReady):
				h.recordRejected(ctx, schedule, "credential-not-ready")
				writeScheduleAdmissionJSON(response, http.StatusConflict, scheduleAdmissionResponse{
					Scheduled: false, Reason: "credential-not-ready",
				})
				return
			case errors.Is(resolveErr, errPrincipalCredentialResolution):
				h.recordRejected(ctx, schedule, "credential-resolution-unavailable")
				writeScheduleAdmissionJSON(response, http.StatusServiceUnavailable, scheduleAdmissionResponse{
					Scheduled: false, Reason: "credential-resolution-unavailable",
				})
				return
			}
			h.recordRejected(ctx, schedule, invalidExecutionProfileConfigurationReason)
			writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
				Scheduled: false, Reason: invalidExecutionProfileConfigurationReason,
			})
			return
		}
		prompt := ""
		if admission.Input != nil {
			prompt = admission.Input.Prompt
		}
		profiledRun, buildErr := buildProfiledAgentRun(schedule, resolved, producer, principal, resolvedWorkflow, prompt)
		if buildErr != nil {
			h.recordRejected(ctx, schedule, invalidExecutionProfileConfigurationReason)
			writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
				Scheduled: false, Reason: invalidExecutionProfileConfigurationReason,
			})
			return
		}
		run = *profiledRun
	} else if admission.AgentRun != nil {
		if admission.AgentRun.Spec.Execution != nil || admission.AgentRun.Spec.Runtime.Container != nil || admission.AgentRun.Spec.Runtime.Docker != nil {
			h.recordRejected(ctx, schedule, "legacy producer cannot configure profile-owned runtime controls")
			writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
				Scheduled: false, Reason: "legacy producer cannot configure spec.execution, spec.runtime.container, or spec.runtime.docker; use an execution profile",
			})
			return
		}
		run = *admission.AgentRun
		run.ObjectMeta = *admission.AgentRun.ObjectMeta.DeepCopy()
		run.Spec = *admission.AgentRun.Spec.DeepCopy()
	}
	// Apply the cluster's default egress mode before validation and creation,
	// so the stored spec.egress is always explicit and a later knob change can
	// never reclassify this run. Never overrides an explicit mode.
	ApplyDefaultEgressMode(&run)
	if err := ValidateAgentRunExecution(&run); err != nil {
		if profiled {
			h.recordRejected(ctx, schedule, invalidExecutionProfileConfigurationReason)
			writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
				Scheduled: false, Reason: invalidExecutionProfileConfigurationReason,
			})
			return
		}
		reason := err.Error()
		h.recordRejected(ctx, schedule, reason)
		writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
			Scheduled: false, Reason: reason,
		})
		return
	}
	if err := ValidateAgentRunRuntimeCapabilities(&run); err != nil {
		if profiled {
			h.recordRejected(ctx, schedule, invalidExecutionProfileConfigurationReason)
			writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
				Scheduled: false, Reason: invalidExecutionProfileConfigurationReason,
			})
			return
		}
		reason := err.Error()
		h.recordRejected(ctx, schedule, reason)
		writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
			Scheduled: false, Reason: reason,
		})
		return
	}
	if err := ValidateAgentRunDockerNetworks(&run); err != nil {
		if profiled {
			h.recordRejected(ctx, schedule, invalidExecutionProfileConfigurationReason)
			writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
				Scheduled: false, Reason: invalidExecutionProfileConfigurationReason,
			})
			return
		}
		reason := err.Error()
		h.recordRejected(ctx, schedule, reason)
		writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
			Scheduled: false, Reason: reason,
		})
		return
	}
	if err := ValidateAgentRunEgressMode(&run); err != nil {
		if profiled {
			h.recordRejected(ctx, schedule, invalidExecutionProfileConfigurationReason)
			writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
				Scheduled: false, Reason: invalidExecutionProfileConfigurationReason,
			})
			return
		}
		reason := err.Error()
		h.recordRejected(ctx, schedule, reason)
		writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
			Scheduled: false,
			Reason:    reason,
		})
		return
	}
	if err := ValidateAgentRunWorkspace(&run); err != nil {
		if profiled {
			h.recordRejected(ctx, schedule, invalidExecutionProfileConfigurationReason)
			writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
				Scheduled: false, Reason: invalidExecutionProfileConfigurationReason,
			})
			return
		}
		reason := err.Error()
		h.recordRejected(ctx, schedule, reason)
		writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
			Scheduled: false,
			Reason:    reason,
		})
		return
	}
	if err := ValidateAgentRunWorkspaceInstructions(&run); err != nil {
		if profiled {
			h.recordRejected(ctx, schedule, invalidExecutionProfileConfigurationReason)
			writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
				Scheduled: false, Reason: invalidExecutionProfileConfigurationReason,
			})
			return
		}
		reason := err.Error()
		h.recordRejected(ctx, schedule, reason)
		writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
			Scheduled: false, Reason: reason,
		})
		return
	}
	if err := PrepareScheduledAgentRun(schedule, &run, scheduleAdmissionWorkMetadata{
		ID:         workID,
		Group:      workGroup,
		Title:      admission.Work.Title,
		URL:        admission.Work.URL,
		Repository: admission.Work.Repository,
	}, h.scheme); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "prepare scheduled AgentRun", "schedule", client.ObjectKeyFromObject(schedule))
		http.Error(response, "prepare AgentRun failed\n", http.StatusInternalServerError)
		return
	}
	if profiled {
		if err := injectProfiledLifecycleCallback(&run); err != nil {
			h.recordRejected(ctx, schedule, invalidExecutionProfileConfigurationReason)
			writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
				Scheduled: false, Reason: invalidExecutionProfileConfigurationReason,
			})
			return
		}
	}
	if err := h.client.Create(ctx, &run); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "create scheduled AgentRun", "schedule", client.ObjectKeyFromObject(schedule), "agentrun", client.ObjectKeyFromObject(&run))
		http.Error(response, "create AgentRun failed\n", http.StatusInternalServerError)
		return
	}
	h.recordAccepted(ctx, schedule)
	writeScheduleAdmissionJSON(response, http.StatusCreated, scheduleAdmissionResponse{
		Scheduled: true,
		AgentRun: &scheduleAdmissionAgentRun{
			Namespace: run.Namespace,
			Name:      run.Name,
		},
	})
}

func newPrincipalCoordinationOperationID() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (h *agentScheduleAdmissionHandler) releasePrincipalAdmission(
	principal *nvtv1alpha1.AgentRunPrincipal,
	operationID string,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = h.principalCoordination.EndAdmission(
		ctx,
		principalaccounts.Principal{Issuer: principal.Issuer, Subject: principal.Subject},
		operationID,
	)
}

func admissionPrincipal(input *scheduleAdmissionPrincipal) *nvtv1alpha1.AgentRunPrincipal {
	if input == nil {
		return nil
	}
	return &nvtv1alpha1.AgentRunPrincipal{
		Issuer: input.Issuer, Subject: input.Subject, DisplayName: input.DisplayName,
	}
}

func validateProfiledAdmissionShape(raw map[string]json.RawMessage) error {
	if err := validateJSONKeys(raw, "workflow", "work", "input"); err != nil {
		return err
	}
	work, err := rawJSONObject(raw["work"])
	if err != nil {
		return err
	}
	if err := validateJSONKeys(work, "id", "group", "title", "url", "repository", "principal"); err != nil {
		return err
	}
	if principalRaw, present := work["principal"]; present {
		principal, err := rawJSONObject(principalRaw)
		if err != nil {
			return err
		}
		if err := validateJSONKeys(principal, "issuer", "subject", "displayName"); err != nil {
			return err
		}
	}
	if inputRaw, present := raw["input"]; present {
		input, err := rawJSONObject(inputRaw)
		if err != nil {
			return err
		}
		if err := validateJSONKeys(input, "prompt"); err != nil {
			return err
		}
	}
	return nil
}

func validAdmissionWorkKey(value string) bool {
	if len(value) < 16 || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e || strings.ContainsRune("%\\?#", character) {
			return false
		}
	}
	return true
}

func rawJSONObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &object) != nil || object == nil {
		return nil, errors.New("expected JSON object")
	}
	return object, nil
}

func validateJSONKeys(object map[string]json.RawMessage, allowed ...string) error {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	for key := range object {
		if _, ok := allowedSet[key]; !ok {
			return errors.New("unexpected request field")
		}
	}
	return nil
}

func (h *agentScheduleAdmissionHandler) lockScheduleAdmission(namespace, name string) func() {
	if h.admissionLocks == nil {
		h.admissionLocks = newScheduleAdmissionLocks()
	}
	return h.admissionLocks.lock(types.NamespacedName{Namespace: namespace, Name: name})
}

func (h *agentScheduleAdmissionHandler) recordAccepted(ctx context.Context, schedule *nvtv1alpha1.AgentSchedule) {
	_ = h.updateAdmissionStatus(ctx, schedule, func(status *nvtv1alpha1.AgentScheduleStatus) {
		now := h.now()
		status.LastAcceptedAt = &now
		status.LastRejectionReason = ""
	})
}

func (h *agentScheduleAdmissionHandler) recordRejected(ctx context.Context, schedule *nvtv1alpha1.AgentSchedule, reason string) {
	_ = h.updateAdmissionStatus(ctx, schedule, func(status *nvtv1alpha1.AgentScheduleStatus) {
		now := h.now()
		status.LastRejectedAt = &now
		status.LastRejectionReason = reason
	})
}

func (h *agentScheduleAdmissionHandler) updateAdmissionStatus(
	ctx context.Context,
	schedule *nvtv1alpha1.AgentSchedule,
	mutate func(*nvtv1alpha1.AgentScheduleStatus),
) error {
	key := client.ObjectKeyFromObject(schedule)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &nvtv1alpha1.AgentSchedule{}
		if err := h.client.Get(ctx, key, current); err != nil {
			return err
		}
		mutate(&current.Status)
		return h.client.Status().Update(ctx, current)
	})
}

func parseScheduleAdmissionPath(path string) (string, string, bool) {
	remainder, ok := strings.CutPrefix(path, scheduleAdmissionPathPrefix)
	if !ok {
		return "", "", false
	}
	parts := strings.Split(remainder, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || (parts[2] != "admissions" && parts[2] != "runs") {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func writeScheduleAdmissionJSON(response http.ResponseWriter, status int, body scheduleAdmissionResponse) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(body); err != nil {
		fmt.Fprintf(response, `{"scheduled":false,"reason":"response-encode-failed"}`+"\n")
	}
}

func countActiveScheduledRuns(runs *nvtv1alpha1.AgentRunList) int32 {
	var active int32
	for i := range runs.Items {
		if IsActiveScheduledRun(&runs.Items[i]) {
			active++
		}
	}
	return active
}

func countActiveScheduledRunsForPrincipal(
	runs *nvtv1alpha1.AgentRunList,
	principal *nvtv1alpha1.AgentRunPrincipal,
) int32 {
	if !validPrincipalIdentity(principal) {
		return 0
	}
	var active int32
	for i := range runs.Items {
		run := &runs.Items[i]
		if !IsActiveScheduledRun(run) || run.Spec.ProfileProvenance == nil ||
			run.Spec.ProfileProvenance.Principal == nil {
			continue
		}
		owner := run.Spec.ProfileProvenance.Principal
		if owner.Issuer == principal.Issuer && owner.Subject == principal.Subject {
			active++
		}
	}
	return active
}

func validPrincipalIdentity(principal *nvtv1alpha1.AgentRunPrincipal) bool {
	return principal != nil && canonicalPrincipalIssuer(principal.Issuer) && validPrincipalSubject(principal.Subject)
}

var errPrincipalRequired = errors.New("principal required")

func principalParallelismLimit(
	configuration *nvtv1alpha1.AgentSchedulePrincipalParallelism,
	principal *nvtv1alpha1.AgentRunPrincipal,
) (int32, error) {
	if configuration == nil {
		return 0, nil
	}
	if configuration.DefaultMaxParallelism < 1 || len(configuration.Overrides) > 256 {
		return 0, errInvalidExecutionProfileConfiguration
	}

	type principalKey struct {
		issuer  string
		subject string
	}
	overrides := make(map[principalKey]int32, len(configuration.Overrides))
	for _, override := range configuration.Overrides {
		if !canonicalPrincipalIssuer(override.Issuer) || !validPrincipalSubject(override.Subject) ||
			override.MaxParallelism < 1 {
			return 0, errInvalidExecutionProfileConfiguration
		}
		key := principalKey{issuer: override.Issuer, subject: override.Subject}
		if _, duplicate := overrides[key]; duplicate {
			return 0, errInvalidExecutionProfileConfiguration
		}
		overrides[key] = override.MaxParallelism
	}

	if !validPrincipalIdentity(principal) {
		return 0, errPrincipalRequired
	}
	if limit, overridden := overrides[principalKey{issuer: principal.Issuer, subject: principal.Subject}]; overridden {
		return limit, nil
	}
	return configuration.DefaultMaxParallelism, nil
}

type scheduleAdmissionLocks struct {
	mu    sync.Mutex
	locks map[types.NamespacedName]*scheduleAdmissionLock
}

type scheduleAdmissionLock struct {
	mu       sync.Mutex
	refCount int
}

func newScheduleAdmissionLocks() *scheduleAdmissionLocks {
	return &scheduleAdmissionLocks{locks: map[types.NamespacedName]*scheduleAdmissionLock{}}
}

func (l *scheduleAdmissionLocks) lock(key types.NamespacedName) func() {
	l.mu.Lock()
	lock := l.locks[key]
	if lock == nil {
		lock = &scheduleAdmissionLock{}
		l.locks[key] = lock
	}
	lock.refCount++
	l.mu.Unlock()

	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()
		l.mu.Lock()
		lock.refCount--
		if lock.refCount == 0 {
			delete(l.locks, key)
		}
		l.mu.Unlock()
	}
}
