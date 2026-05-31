package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

const scheduleAdmissionPathPrefix = "/v1/schedules/"

type agentScheduleAdmissionHandler struct {
	client         client.Client
	scheme         *runtime.Scheme
	now            func() metav1.Time
	admissionLocks *scheduleAdmissionLocks
}

type scheduleAdmissionRequest struct {
	Work     scheduleAdmissionWork `json:"work"`
	AgentRun nvtv1alpha1.AgentRun  `json:"agentRun"`
}

type scheduleAdmissionWork struct {
	ID    string `json:"id"`
	Title string `json:"title,omitempty"`
	URL   string `json:"url,omitempty"`
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
		client:         k8sClient,
		scheme:         scheme,
		now:            metav1.Now,
		admissionLocks: newScheduleAdmissionLocks(),
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

	var admission scheduleAdmissionRequest
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, 1<<20))
	if err := decoder.Decode(&admission); err != nil {
		http.Error(response, "malformed JSON\n", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		http.Error(response, "malformed JSON\n", http.StatusBadRequest)
		return
	}

	workID := strings.TrimSpace(admission.Work.ID)
	if workID == "" {
		http.Error(response, "missing work.id\n", http.StatusBadRequest)
		return
	}

	ctx := request.Context()
	unlock := h.lockScheduleAdmission(namespace, name)
	defer unlock()

	schedule := &nvtv1alpha1.AgentSchedule{}
	if err := h.client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, schedule); err != nil {
		if errors.IsNotFound(err) {
			http.Error(response, "AgentSchedule not found\n", http.StatusNotFound)
			return
		}
		http.Error(response, "get AgentSchedule failed\n", http.StatusInternalServerError)
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
	if activeWorkExists(runs, workID) {
		h.recordRejected(ctx, schedule, "duplicate-work")
		writeScheduleAdmissionJSON(response, http.StatusAccepted, scheduleAdmissionResponse{
			Scheduled: false,
			Reason:    "duplicate-work",
		})
		return
	}

	run := admission.AgentRun
	if err := PrepareScheduledAgentRun(schedule, &run, workID, admission.Work.URL, h.scheme); err != nil {
		http.Error(response, "prepare AgentRun failed\n", http.StatusInternalServerError)
		return
	}
	if err := h.client.Create(ctx, &run); err != nil {
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
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] != "runs" {
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
