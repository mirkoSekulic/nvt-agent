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
	ConditionExecutionBackendAvailable = "ExecutionBackendAvailable"
	ConditionExternalExecutionReady    = "ExternalExecutionReady"
	executionSelectionInvalidReason    = "ExecutionSelectionInvalid"
	executionDriverUnavailableReason   = "ExecutionDriverUnavailable"
	executionDriverRejectedReason      = "ExecutionDriverRejected"
	executionDriverReadyReason         = "ExternalExecutionReady"
	externalExecutionFinalizer         = "nvt.dev/agentrun-external-execution"
	externalExecutionDefaultRequeue    = 10 * time.Second
	externalExecutionMinimumRequeue    = 2 * time.Second
	externalExecutionMaximumRequeue    = 5 * time.Minute
)

type executionBackendKey struct {
	kind   nvtv1alpha1.AgentRunExecutionKind
	driver string
}

type executionDriverClientRegistry interface {
	Client(string) (host.Client, bool)
}

// agentRunExecutionBackend is the operator-owned execution selection boundary.
// The built-in implementation delegates to the existing Kubernetes reconciler;
// future external implementations can satisfy the same lifecycle boundary
// without teaching the portable driver protocol about Pod internals.
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
		return reconciler.reconcileTerminalAgentRunRetention(ctx, &agentRun)
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
	status, err := backend.client.Reconcile(ctx, desired)
	if err != nil {
		return reconciler.recordExternalExecutionCallFailure(ctx, &agentRun, err)
	}
	if executiondriver.ValidateReconcileStatus(status) != nil || status.ObservedGeneration > desired.Generation {
		return reconciler.recordExternalExecutionCallFailure(ctx, &agentRun, fmt.Errorf("invalid observed generation"))
	}
	return reconciler.recordExternalExecutionStatus(ctx, &agentRun, status, desired.Generation, false)
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
	executionID, err := externalExecutionID(agentRun.UID)
	if err != nil {
		return reconciler.recordExecutionSelectionFailure(ctx, agentRun, executionSelectionInvalidReason, "resolved external execution state is invalid")
	}
	status, err := backend.client.Delete(ctx, executionID)
	if err != nil {
		return reconciler.recordExternalExecutionCallFailure(ctx, agentRun, err)
	}
	if executiondriver.ValidateDeleteStatus(status) != nil {
		return reconciler.recordExternalExecutionCallFailure(ctx, agentRun, fmt.Errorf("invalid delete status"))
	}
	if status.Phase != executiondriver.PhaseDeleted {
		return reconciler.recordExternalExecutionStatus(ctx, agentRun, status, 0, true)
	}
	if err := reconciler.finalizeExternalAgentRun(ctx, agentRun); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
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
) (ctrl.Result, error) {
	reason := executionDriverUnavailableReason
	requeue := externalExecutionDefaultRequeue
	var driverError *host.DriverError
	if errors.As(callError, &driverError) && !driverError.Failure.Retryable {
		reason = executionDriverRejectedReason
		requeue = 0
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
	deleting bool,
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
		if ready {
			reason = executionDriverReadyReason
			conditionStatus = metav1.ConditionTrue
			if agentRun.Status.StartedAt == nil {
				now := r.now()
				agentRun.Status.StartedAt = &now
			}
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
	result := ctrl.Result{RequeueAfter: externalExecutionRequeue(status)}
	if deleting && result.RequeueAfter == 0 {
		result.RequeueAfter = externalExecutionDefaultRequeue
	}
	return result, nil
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
	if !agentRun.DeletionTimestamp.IsZero() && controllerutil.ContainsFinalizer(agentRun, externalExecutionFinalizer) {
		result.RequeueAfter = externalExecutionDefaultRequeue
	}
	return result, nil
}
