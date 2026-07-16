package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

const scheduleAdmissionPathPrefix = "/v1/schedules/"

type agentScheduleAdmissionHandler struct {
	client          client.Client
	scheme          *runtime.Scheme
	authenticator   ScheduleProducerAuthenticator
	profileResolver ExecutionProfileResolver
	now             func() metav1.Time
	admissionLocks  *scheduleAdmissionLocks
}

type scheduleAdmissionRequest struct {
	Work     scheduleAdmissionWork   `json:"work"`
	Input    *scheduleAdmissionInput `json:"input,omitempty"`
	AgentRun *nvtv1alpha1.AgentRun   `json:"agentRun,omitempty"`
}

type scheduleAdmissionWork struct {
	ID         string                      `json:"id"`
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
	return &agentScheduleAdmissionHandler{
		client:          k8sClient,
		scheme:          scheme,
		authenticator:   NewKubernetesTokenReviewProducerAuthenticator(k8sClient),
		profileResolver: StaticExecutionProfileResolver{},
		now:             metav1.Now,
		admissionLocks:  newScheduleAdmissionLocks(),
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

	schedule := &nvtv1alpha1.AgentSchedule{}
	if err := h.client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, schedule); err != nil {
		if apierrors.IsNotFound(err) {
			http.Error(response, "AgentSchedule not found\n", http.StatusNotFound)
			return
		}
		http.Error(response, "get AgentSchedule failed\n", http.StatusInternalServerError)
		return
	}

	profiled := ScheduleUsesExecutionProfiles(schedule)
	producer := ""
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
		if !containsString(schedule.Spec.AllowedProducers, producer) {
			http.Error(response, "producer is not allowed\n", http.StatusForbidden)
			return
		}
		if err := validateProfiledAdmissionShape(rawAdmission); err != nil {
			http.Error(response, "profiled admission accepts only work and input\n", http.StatusBadRequest)
			return
		}
	}

	workID := strings.TrimSpace(admission.Work.ID)
	if workID == "" {
		http.Error(response, "missing work.id\n", http.StatusBadRequest)
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

	runs, err := ListScheduledRuns(ctx, h.client, schedule)
	if err != nil {
		http.Error(response, "list scheduled AgentRuns failed\n", http.StatusInternalServerError)
		return
	}
	activeRuns := countActiveScheduledRuns(runs)
	if activeRuns >= EffectiveMaxParallelism(schedule) {
		h.recordRejected(ctx, schedule, "max-parallelism-reached")
		writeScheduleAdmissionJSON(response, http.StatusTooManyRequests, scheduleAdmissionResponse{
			Scheduled: false,
			Reason:    "max-parallelism-reached",
		})
		return
	}
	if retainedWorkExists(runs, workID) {
		h.recordRejected(ctx, schedule, "duplicate-work")
		writeScheduleAdmissionJSON(response, http.StatusAccepted, scheduleAdmissionResponse{
			Scheduled: false,
			Reason:    "duplicate-work",
		})
		return
	}

	var run nvtv1alpha1.AgentRun
	if profiled {
		if h.profileResolver == nil {
			h.profileResolver = StaticExecutionProfileResolver{}
		}
		principal := admissionPrincipal(admission.Work.Principal)
		if principal != nil && (strings.TrimSpace(principal.Issuer) == "" || strings.TrimSpace(principal.Subject) == "") {
			http.Error(response, "principal issuer and subject are required\n", http.StatusBadRequest)
			return
		}
		resolved, resolveErr := h.profileResolver.Resolve(schedule, principal)
		if resolveErr != nil {
			if errors.Is(resolveErr, errExecutionProfileSelectionDenied) {
				h.recordRejected(ctx, schedule, "profile-selection-denied")
				writeScheduleAdmissionJSON(response, http.StatusForbidden, scheduleAdmissionResponse{
					Scheduled: false, Reason: "profile-selection-denied",
				})
				return
			}
			h.recordRejected(ctx, schedule, "invalid-execution-profile-configuration")
			writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
				Scheduled: false, Reason: "invalid-execution-profile-configuration",
			})
			return
		}
		prompt := ""
		if admission.Input != nil {
			prompt = admission.Input.Prompt
		}
		profiledRun, buildErr := buildProfiledAgentRun(schedule, resolved, producer, principal, prompt)
		if buildErr != nil {
			h.recordRejected(ctx, schedule, "invalid-execution-profile-configuration")
			writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
				Scheduled: false, Reason: "invalid-execution-profile-configuration",
			})
			return
		}
		run = *profiledRun
	} else if admission.AgentRun != nil {
		run = *admission.AgentRun
		run.ObjectMeta = *admission.AgentRun.ObjectMeta.DeepCopy()
		run.Spec = *admission.AgentRun.Spec.DeepCopy()
	}
	// Apply the cluster's default egress mode before validation and creation,
	// so the stored spec.egress is always explicit and a later knob change can
	// never reclassify this run. Never overrides an explicit mode.
	ApplyDefaultEgressMode(&run)
	if err := ValidateAgentRunEgressMode(&run); err != nil {
		if profiled {
			h.recordRejected(ctx, schedule, "invalid-execution-profile-configuration")
			writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
				Scheduled: false, Reason: "invalid-execution-profile-configuration",
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
			h.recordRejected(ctx, schedule, "invalid-execution-profile-configuration")
			writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
				Scheduled: false, Reason: "invalid-execution-profile-configuration",
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
	if err := PrepareScheduledAgentRun(schedule, &run, scheduleAdmissionWorkMetadata{
		ID:         workID,
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
			h.recordRejected(ctx, schedule, "invalid-execution-profile-configuration")
			writeScheduleAdmissionJSON(response, http.StatusBadRequest, scheduleAdmissionResponse{
				Scheduled: false, Reason: "invalid-execution-profile-configuration",
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

func admissionPrincipal(input *scheduleAdmissionPrincipal) *nvtv1alpha1.AgentRunPrincipal {
	if input == nil {
		return nil
	}
	return &nvtv1alpha1.AgentRunPrincipal{
		Issuer: input.Issuer, Subject: input.Subject, DisplayName: input.DisplayName,
	}
}

func validateProfiledAdmissionShape(raw map[string]json.RawMessage) error {
	if err := validateJSONKeys(raw, "work", "input"); err != nil {
		return err
	}
	work, err := rawJSONObject(raw["work"])
	if err != nil {
		return err
	}
	if err := validateJSONKeys(work, "id", "title", "url", "repository", "principal"); err != nil {
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
