package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver/host"
)

const (
	ConditionExecutionBackendAvailable  = "ExecutionBackendAvailable"
	ConditionExternalExecutionReady     = "ExternalExecutionReady"
	executionSelectionInvalidReason     = "ExecutionSelectionInvalid"
	executionDriverUnavailableReason    = "ExecutionDriverUnavailable"
	executionDriverRejectedReason       = "ExecutionDriverRejected"
	executionDriverReadyReason          = "ExternalExecutionReady"
	externalExecutionFinalizer          = "nvt.dev/agentrun-external-execution"
	externalExecutionDefaultRequeue     = 10 * time.Second
	externalExecutionMinimumRequeue     = 2 * time.Second
	externalExecutionMaximumRequeue     = 5 * time.Minute
	externalExecutionCleanupRetry       = time.Minute
	externalExecutionMaxConcurrentCalls = 2
)

var errExternalExecutionCapacity = errors.New("external execution call capacity is occupied")

type executionBackendKey struct {
	kind   nvtv1alpha1.AgentRunExecutionKind
	driver string
}

type executionDriverClientRegistry interface {
	Client(string) (host.Client, bool)
}

// agentRunExecutionBackend is the operator-owned execution selection boundary.
// The built-in implementation delegates to the existing Kubernetes reconciler;
// the external implementation satisfies the same lifecycle boundary without
// teaching the portable driver protocol about Pod internals.
type agentRunExecutionBackend interface {
	Reconcile(context.Context, *AgentRunReconciler, nvtv1alpha1.AgentRun) (ctrl.Result, error)
	Delete(context.Context, *AgentRunReconciler, *nvtv1alpha1.AgentRun) (ctrl.Result, error)
}

type kubernetesExecutionBackend struct{}

type externalExecutionBackend struct {
	client host.Client
}

func (kubernetesExecutionBackend) Reconcile(
	ctx context.Context,
	reconciler *AgentRunReconciler,
	agentRun nvtv1alpha1.AgentRun,
) (ctrl.Result, error) {
	return reconciler.reconcileKubernetesAgentRun(ctx, agentRun)
}

func (kubernetesExecutionBackend) Delete(
	ctx context.Context,
	reconciler *AgentRunReconciler,
	agentRun *nvtv1alpha1.AgentRun,
) (ctrl.Result, error) {
	if err := reconciler.finalizeAgentRun(ctx, agentRun); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func builtInExecutionBackends() map[executionBackendKey]agentRunExecutionBackend {
	return map[executionBackendKey]agentRunExecutionBackend{
		{kind: nvtv1alpha1.AgentRunExecutionPod, driver: builtInKubernetesDriver}: kubernetesExecutionBackend{},
	}
}

func (r *AgentRunReconciler) executionBackendFor(selection effectiveExecutionSelection) (agentRunExecutionBackend, bool) {
	backend, exists := builtInExecutionBackends()[executionBackendKey{kind: selection.Kind, driver: selection.Driver}]
	if exists {
		return backend, true
	}
	if selection.Driver == builtInKubernetesDriver || r.ExecutionDrivers == nil {
		return nil, false
	}
	client, exists := r.ExecutionDrivers.Client(selection.Driver)
	if !exists {
		return nil, false
	}
	return externalExecutionBackend{client: client}, true
}

func (backend externalExecutionBackend) Reconcile(
	ctx context.Context,
	reconciler *AgentRunReconciler,
	agentRun nvtv1alpha1.AgentRun,
) (ctrl.Result, error) {
	if IsTerminalAgentRunPhase(agentRun.Status.Phase) {
		return backend.reconcileTerminalLifecycle(ctx, reconciler, &agentRun)
	}
	desired, err := desiredExternalExecution(&agentRun)
	if err != nil {
		return reconciler.recordExecutionSelectionFailure(ctx, &agentRun, executionSelectionInvalidReason, "resolved external execution state is invalid")
	}
	// No mutating provider call occurs until the cleanup obligation is durable.
	if controllerutil.AddFinalizer(&agentRun, externalExecutionFinalizer) {
		if err := reconciler.Update(ctx, &agentRun); err != nil {
			return ctrl.Result{}, fmt.Errorf("add external execution finalizer: %w", err)
		}
		return ctrl.Result{Requeue: true}, nil
	}
	deadlineResult, deadlineExceeded, err := reconciler.reconcileExternalActiveDeadline(ctx, &agentRun)
	if err != nil {
		return ctrl.Result{}, err
	}
	if deadlineExceeded {
		return backend.reconcileTerminalLifecycle(ctx, reconciler, &agentRun)
	}

	status, err := backend.reconcile(ctx, reconciler, desired)
	if err != nil {
		var driverError *host.DriverError
		if errors.As(err, &driverError) && !driverError.Failure.Retryable {
			if err := reconciler.recordExternalExecutionRejected(ctx, &agentRun); err != nil {
				return ctrl.Result{}, err
			}
			return backend.reconcileTerminalLifecycle(ctx, reconciler, &agentRun)
		}
		return reconciler.recordExternalExecutionCallFailure(ctx, &agentRun, err, false)
	}
	if executiondriver.ValidateReconcileStatus(status) != nil || status.ObservedGeneration > desired.Generation {
		return reconciler.recordExternalExecutionCallFailure(ctx, &agentRun, fmt.Errorf("invalid observed generation"), false)
	}
	if staleTerminalExternalStatus(status, desired.Generation) {
		return reconciler.recordExternalStaleTerminalStatus(ctx, &agentRun)
	}
	result, err := reconciler.recordExternalExecutionStatus(ctx, &agentRun, status, desired.Generation)
	if err != nil {
		return ctrl.Result{}, err
	}
	if IsTerminalAgentRunPhase(agentRun.Status.Phase) {
		return backend.reconcileTerminalLifecycle(ctx, reconciler, &agentRun)
	}
	deadlineResult, deadlineExceeded, err = reconciler.reconcileExternalActiveDeadline(ctx, &agentRun)
	if err != nil {
		return ctrl.Result{}, err
	}
	if deadlineExceeded {
		return backend.reconcileTerminalLifecycle(ctx, reconciler, &agentRun)
	}
	return earliestRequeue(result, deadlineResult), nil
}

func (backend externalExecutionBackend) Delete(
	ctx context.Context,
	reconciler *AgentRunReconciler,
	agentRun *nvtv1alpha1.AgentRun,
) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(agentRun, externalExecutionFinalizer) {
		if err := reconciler.finalizeAgentRun(ctx, agentRun); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	return backend.reconcileOperationalCleanup(ctx, reconciler, agentRun, true)
}

func (backend externalExecutionBackend) reconcileTerminalLifecycle(
	ctx context.Context,
	reconciler *AgentRunReconciler,
	agentRun *nvtv1alpha1.AgentRun,
) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(agentRun, externalExecutionFinalizer) {
		return reconciler.reconcileTerminalAgentRunRetention(ctx, agentRun)
	}
	if agentRun.Status.Phase != nvtv1alpha1.AgentRunPhaseDeadlineExceeded {
		now := reconciler.now()
		resourceRemaining, resourceDue := TerminalOperationalCleanupDelay(agentRun, now)
		retentionRemaining, retentionDue := RunRetentionDelay(agentRun, now)
		if resourceDue {
			return backend.reconcileOperationalCleanup(ctx, reconciler, agentRun, false)
		}
		if retentionDue {
			return reconciler.reconcileTerminalAgentRunRetention(ctx, agentRun)
		}
		result := earliestRequeue(
			ctrl.Result{RequeueAfter: resourceRemaining},
			ctrl.Result{RequeueAfter: retentionRemaining},
		)
		if result.RequeueAfter > 0 {
			return result, nil
		}
		return ctrl.Result{}, nil
	}
	return backend.reconcileOperationalCleanup(ctx, reconciler, agentRun, false)
}

func (backend externalExecutionBackend) reconcileOperationalCleanup(
	ctx context.Context,
	reconciler *AgentRunReconciler,
	agentRun *nvtv1alpha1.AgentRun,
	deletingAgentRun bool,
) (ctrl.Result, error) {
	executionID, err := externalExecutionID(agentRun.UID)
	if err != nil {
		return reconciler.recordExecutionSelectionFailure(ctx, agentRun, executionSelectionInvalidReason, "resolved external execution state is invalid")
	}
	status, err := backend.delete(ctx, reconciler, executionID)
	if err != nil {
		return reconciler.recordExternalExecutionCallFailure(ctx, agentRun, err, true)
	}
	if executiondriver.ValidateDeleteStatus(status) != nil {
		return reconciler.recordExternalExecutionCallFailure(ctx, agentRun, fmt.Errorf("invalid delete status"), true)
	}
	if status.Phase != executiondriver.PhaseDeleted {
		return reconciler.recordExternalCleanupProgress(ctx, agentRun, status)
	}
	if err := reconciler.finalizeExternalAgentRun(ctx, agentRun); err != nil {
		return ctrl.Result{}, err
	}
	if !deletingAgentRun {
		return reconciler.reconcileTerminalAgentRunRetention(ctx, agentRun)
	}
	return ctrl.Result{}, nil
}

func (backend externalExecutionBackend) reconcile(
	ctx context.Context,
	reconciler *AgentRunReconciler,
	desired executiondriver.DesiredExecution,
) (executiondriver.Status, error) {
	release, acquired := reconciler.tryAcquireExternalExecutionCall()
	if !acquired {
		return executiondriver.Status{}, errExternalExecutionCapacity
	}
	defer release()
	return backend.client.Reconcile(ctx, desired)
}

func (backend externalExecutionBackend) delete(
	ctx context.Context,
	reconciler *AgentRunReconciler,
	executionID string,
) (executiondriver.Status, error) {
	release, acquired := reconciler.tryAcquireExternalExecutionCall()
	if !acquired {
		return executiondriver.Status{}, errExternalExecutionCapacity
	}
	defer release()
	return backend.client.Delete(ctx, executionID)
}

func (r *AgentRunReconciler) tryAcquireExternalExecutionCall() (func(), bool) {
	r.externalExecutionCallsMu.Lock()
	if r.externalExecutionCalls == nil {
		r.externalExecutionCalls = make(chan struct{}, externalExecutionMaxConcurrentCalls)
	}
	slots := r.externalExecutionCalls
	r.externalExecutionCallsMu.Unlock()
	select {
	case slots <- struct{}{}:
		return func() { <-slots }, true
	default:
		return nil, false
	}
}

func staleTerminalExternalStatus(status executiondriver.Status, desiredGeneration int64) bool {
	if status.ObservedGeneration == desiredGeneration {
		return false
	}
	if status.Phase == executiondriver.PhaseSucceeded {
		return true
	}
	return status.Phase == executiondriver.PhaseFailed && status.Failure != nil && !status.Failure.Retryable
}

func desiredExternalExecution(agentRun *nvtv1alpha1.AgentRun) (executiondriver.DesiredExecution, error) {
	if agentRun.Spec.Execution == nil || agentRun.Spec.Execution.Driver == builtInKubernetesDriver {
		return executiondriver.DesiredExecution{}, fmt.Errorf("external execution selection is absent")
	}
	executionID, err := externalExecutionID(agentRun.UID)
	if err != nil {
		return executiondriver.DesiredExecution{}, err
	}
	configuration, err := canonicalExecutionConfiguration(agentRun.Spec.Execution.Configuration.Raw)
	if err != nil {
		return executiondriver.DesiredExecution{}, err
	}
	workloadKind := executiondriver.WorkloadKind(agentRun.Spec.Execution.Kind)
	generation := agentRun.Generation
	if generation < 1 {
		generation = 1
	}
	desired := executiondriver.DesiredExecution{
		ExecutionID: executionID, Generation: generation,
		DesiredFingerprint: externalDesiredFingerprint(workloadKind, agentRun.Spec.Execution.ClassRef, configuration),
		WorkloadKind:       workloadKind, ClassName: agentRun.Spec.Execution.ClassRef,
		Configuration: configuration,
	}
	if err := executiondriver.ValidateReconcileParams(executiondriver.ReconcileParams{Desired: desired}); err != nil {
		return executiondriver.DesiredExecution{}, err
	}
	return desired, nil
}

func externalExecutionID(uid types.UID) (string, error) {
	if uid == "" {
		return "", fmt.Errorf("AgentRun UID is unavailable")
	}
	digest := sha256.Sum256([]byte(uid))
	return "nvt-agentrun-" + hex.EncodeToString(digest[:]), nil
}

func canonicalExecutionConfiguration(raw []byte) (json.RawMessage, error) {
	var strict map[string]any
	if executiondriver.DecodeStrictJSON(raw, &strict) != nil || strict == nil {
		return nil, fmt.Errorf("configuration is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("configuration is invalid")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("configuration is invalid")
	}
	return canonical, nil
}

func externalDesiredFingerprint(kind executiondriver.WorkloadKind, className string, configuration []byte) string {
	hash := sha256.New()
	for _, value := range [][]byte{[]byte("nvt.external-desired/v1"), []byte(kind), []byte(className), configuration} {
		_, _ = fmt.Fprintf(hash, "%d:", len(value))
		_, _ = hash.Write(value)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func (r *AgentRunReconciler) recordExternalExecutionCallFailure(
	ctx context.Context,
	agentRun *nvtv1alpha1.AgentRun,
	callError error,
	cleanupRequired bool,
) (ctrl.Result, error) {
	reason := executionDriverUnavailableReason
	requeue := externalExecutionDefaultRequeue
	var driverError *host.DriverError
	if errors.As(callError, &driverError) && !driverError.Failure.Retryable {
		reason = executionDriverRejectedReason
		if cleanupRequired {
			requeue = externalExecutionCleanupRetry
		}
	}
	if cleanupRequired {
		return r.recordExternalCleanupFailure(ctx, agentRun, reason, requeue)
	}
	result, err := r.recordExecutionSelectionFailure(ctx, agentRun, reason, "selected execution driver could not converge the run")
	if err == nil {
		result.RequeueAfter = requeue
	}
	return result, err
}

func (r *AgentRunReconciler) recordExternalExecutionStatus(
	ctx context.Context,
	agentRun *nvtv1alpha1.AgentRun,
	status executiondriver.Status,
	desiredGeneration int64,
) (ctrl.Result, error) {
	previous := agentRun.Status.DeepCopy()
	InitializeAgentRunStatus(agentRun)
	r.setRunCondition(agentRun, ConditionExecutionBackendAvailable, metav1.ConditionTrue, "ExecutionDriverAvailable", "selected execution driver host responded with a valid status")
	ready := status.Ready && status.ObservedGeneration == desiredGeneration
	reason := "ExternalExecutionPending"
	phase := nvtv1alpha1.AgentRunPhasePending
	conditionStatus := metav1.ConditionFalse
	switch status.Phase {
	case executiondriver.PhaseProvisioning:
		reason = "ExternalExecutionProvisioning"
	case executiondriver.PhaseRunning:
		phase = nvtv1alpha1.AgentRunPhaseRunning
		if agentRun.Status.StartedAt == nil {
			now := r.now()
			agentRun.Status.StartedAt = &now
		}
		if ready {
			reason = executionDriverReadyReason
			conditionStatus = metav1.ConditionTrue
		} else {
			reason = "ExternalExecutionNotReady"
		}
	case executiondriver.PhaseSucceeded:
		phase = nvtv1alpha1.AgentRunPhaseCompleted
		reason = "ExternalExecutionSucceeded"
	case executiondriver.PhaseFailed:
		if status.Failure != nil && status.Failure.Retryable {
			reason = "ExternalExecutionRetrying"
		} else {
			phase = nvtv1alpha1.AgentRunPhaseFailed
			reason = "ExternalExecutionFailed"
		}
	case executiondriver.PhaseDeleting:
		reason = "ExternalExecutionDeleting"
	case executiondriver.PhaseDeleted:
		reason = "ExternalExecutionDeleted"
	case executiondriver.PhaseUnknown:
		reason = "ExternalExecutionUnknown"
	}
	agentRun.Status.Phase = phase
	agentRun.Status.PodName = ""
	agentRun.Status.Reason = reason
	if phase == nvtv1alpha1.AgentRunPhaseCompleted || phase == nvtv1alpha1.AgentRunPhaseFailed {
		if agentRun.Status.FinishedAt == nil {
			now := r.now()
			agentRun.Status.FinishedAt = &now
		}
	}
	r.setRunCondition(agentRun, ConditionExternalExecutionReady, conditionStatus, reason, "external execution state is not a gateway routing assertion")
	if !reflect.DeepEqual(*previous, agentRun.Status) {
		if err := r.Status().Update(ctx, agentRun); err != nil {
			return ctrl.Result{}, fmt.Errorf("update external execution status: %w", err)
		}
	}
	return ctrl.Result{RequeueAfter: externalExecutionRequeue(status)}, nil
}

func (r *AgentRunReconciler) recordExternalExecutionRejected(
	ctx context.Context,
	agentRun *nvtv1alpha1.AgentRun,
) error {
	previous := agentRun.Status.DeepCopy()
	InitializeAgentRunStatus(agentRun)
	now := r.now()
	agentRun.Status.Phase = nvtv1alpha1.AgentRunPhaseFailed
	agentRun.Status.PodName = ""
	agentRun.Status.FinishedAt = &now
	agentRun.Status.Reason = executionDriverRejectedReason
	r.setRunCondition(agentRun, ConditionExecutionBackendAvailable, metav1.ConditionFalse, executionDriverRejectedReason, "selected execution driver rejected the resolved run")
	r.setRunCondition(agentRun, ConditionExternalExecutionReady, metav1.ConditionFalse, executionDriverRejectedReason, "external execution is not ready")
	if reflect.DeepEqual(*previous, agentRun.Status) {
		return nil
	}
	if err := r.Status().Update(ctx, agentRun); err != nil {
		return fmt.Errorf("record external execution rejection: %w", err)
	}
	return nil
}

func (r *AgentRunReconciler) recordExternalStaleTerminalStatus(
	ctx context.Context,
	agentRun *nvtv1alpha1.AgentRun,
) (ctrl.Result, error) {
	previous := agentRun.Status.DeepCopy()
	InitializeAgentRunStatus(agentRun)
	agentRun.Status.PodName = ""
	agentRun.Status.Reason = "ExternalExecutionStaleObservation"
	r.setRunCondition(agentRun, ConditionExecutionBackendAvailable, metav1.ConditionTrue, "ExecutionDriverAvailable", "selected execution driver host responded with a valid status")
	r.setRunCondition(agentRun, ConditionExternalExecutionReady, metav1.ConditionFalse, "ExternalExecutionStaleObservation", "external execution has not observed the current desired generation")
	if !reflect.DeepEqual(*previous, agentRun.Status) {
		if err := r.Status().Update(ctx, agentRun); err != nil {
			return ctrl.Result{}, fmt.Errorf("record stale external execution observation: %w", err)
		}
	}
	return ctrl.Result{RequeueAfter: externalExecutionDefaultRequeue}, nil
}

func (r *AgentRunReconciler) recordExternalCleanupProgress(
	ctx context.Context,
	agentRun *nvtv1alpha1.AgentRun,
	status executiondriver.Status,
) (ctrl.Result, error) {
	previous := agentRun.Status.DeepCopy()
	r.setRunCondition(agentRun, ConditionExecutionBackendAvailable, metav1.ConditionTrue, "ExecutionDriverAvailable", "selected execution driver host responded with a valid status")
	r.setRunCondition(agentRun, ConditionExternalExecutionReady, metav1.ConditionFalse, "ExternalExecutionDeleting", "external execution cleanup is converging")
	if !reflect.DeepEqual(*previous, agentRun.Status) {
		if err := r.Status().Update(ctx, agentRun); err != nil {
			return ctrl.Result{}, fmt.Errorf("record external execution cleanup: %w", err)
		}
	}
	requeue := externalExecutionRequeue(status)
	if requeue == 0 {
		requeue = externalExecutionDefaultRequeue
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

func (r *AgentRunReconciler) recordExternalCleanupFailure(
	ctx context.Context,
	agentRun *nvtv1alpha1.AgentRun,
	reason string,
	requeue time.Duration,
) (ctrl.Result, error) {
	previous := agentRun.Status.DeepCopy()
	r.setRunCondition(agentRun, ConditionExecutionBackendAvailable, metav1.ConditionFalse, reason, "selected execution driver could not complete cleanup")
	r.setRunCondition(agentRun, ConditionExternalExecutionReady, metav1.ConditionFalse, reason, "external execution cleanup is incomplete")
	if !reflect.DeepEqual(*previous, agentRun.Status) {
		if err := r.Status().Update(ctx, agentRun); err != nil {
			return ctrl.Result{}, fmt.Errorf("record external execution cleanup failure: %w", err)
		}
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

func (r *AgentRunReconciler) reconcileExternalActiveDeadline(
	ctx context.Context,
	agentRun *nvtv1alpha1.AgentRun,
) (ctrl.Result, bool, error) {
	now := r.now()
	remaining, exceeded := ActiveDeadlineDelay(agentRun, now)
	if remaining > 0 {
		return ctrl.Result{RequeueAfter: remaining}, false, nil
	}
	if !exceeded {
		return ctrl.Result{}, false, nil
	}
	previous := agentRun.Status.DeepCopy()
	agentRun.Status.Phase = nvtv1alpha1.AgentRunPhaseDeadlineExceeded
	agentRun.Status.FinishedAt = &now
	agentRun.Status.Reason = activeDeadlineReason
	r.setRunCondition(agentRun, ConditionExternalExecutionReady, metav1.ConditionFalse, "ExternalExecutionDeadlineExceeded", "external execution exceeded its active deadline")
	if !reflect.DeepEqual(*previous, agentRun.Status) {
		if err := r.Status().Update(ctx, agentRun); err != nil {
			return ctrl.Result{}, true, fmt.Errorf("mark external AgentRun active deadline exceeded: %w", err)
		}
	}
	return ctrl.Result{}, true, nil
}

func externalExecutionRequeue(status executiondriver.Status) time.Duration {
	if status.RetryAfterSeconds == nil {
		if status.Phase == executiondriver.PhaseFailed && status.Failure != nil && status.Failure.Retryable {
			return externalExecutionDefaultRequeue
		}
		switch status.Phase {
		case executiondriver.PhasePending, executiondriver.PhaseProvisioning, executiondriver.PhaseRunning,
			executiondriver.PhaseDeleting, executiondriver.PhaseUnknown:
			return externalExecutionDefaultRequeue
		default:
			return 0
		}
	}
	value := time.Duration(*status.RetryAfterSeconds) * time.Second
	if value < externalExecutionMinimumRequeue {
		return externalExecutionMinimumRequeue
	}
	if value > externalExecutionMaximumRequeue {
		return externalExecutionMaximumRequeue
	}
	return value
}

func (r *AgentRunReconciler) finalizeExternalAgentRun(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) error {
	if controllerutil.ContainsFinalizer(agentRun, agentRunFinalizer) {
		if err := r.removeBrokerAgentsPolicyEntry(ctx, agentRun); err != nil {
			return err
		}
	}
	controllerutil.RemoveFinalizer(agentRun, agentRunFinalizer)
	controllerutil.RemoveFinalizer(agentRun, externalExecutionFinalizer)
	if err := r.Update(ctx, agentRun); err != nil {
		return fmt.Errorf("remove external execution finalizer: %w", err)
	}
	return nil
}

func (r *AgentRunReconciler) recordExecutionSelectionFailure(
	ctx context.Context,
	agentRun *nvtv1alpha1.AgentRun,
	reason string,
	message string,
) (ctrl.Result, error) {
	changed := InitializeAgentRunStatus(agentRun)
	if agentRun.Status.Reason != reason {
		agentRun.Status.Reason = reason
		changed = true
	}
	if r.setRunCondition(agentRun, ConditionExecutionBackendAvailable, metav1.ConditionFalse, reason, message) {
		changed = true
	}
	if agentRun.Spec.Execution != nil && agentRun.Spec.Execution.Driver != builtInKubernetesDriver {
		if r.setRunCondition(agentRun, ConditionExternalExecutionReady, metav1.ConditionFalse, reason, "external execution is not ready") {
			changed = true
		}
	}
	if changed {
		if err := r.Status().Update(ctx, agentRun); err != nil {
			return ctrl.Result{}, fmt.Errorf("update AgentRun execution selection status: %w", err)
		}
	}
	result := ctrl.Result{}
	if controllerutil.ContainsFinalizer(agentRun, externalExecutionFinalizer) {
		result.RequeueAfter = externalExecutionDefaultRequeue
	}
	return result, nil
}
