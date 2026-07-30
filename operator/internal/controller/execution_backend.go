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

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver/host"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

const (
	ConditionExecutionBackendAvailable  = "ExecutionBackendAvailable"
	ConditionExternalExecutionReady     = "ExternalExecutionReady"
	executionSelectionInvalidReason     = "ExecutionSelectionInvalid"
	executionDriverUnavailableReason    = "ExecutionDriverUnavailable"
	executionDriverRejectedReason       = "ExecutionDriverRejected"
	executionDriverReadyReason          = "ExternalExecutionReady"
	externalExecutionFinalizer          = "nvt.dev/agentrun-external-execution"
	guestEnrollmentFinalizer            = "nvt.dev/agentrun-guest-enrollment"
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

type guestEnrollmentIssuer interface {
	EnabledFor(string) bool
	Issue(context.Context, guestenrollment.IssueRequest) (guestenrollment.BootstrapEnvelope, error)
	RevokeBinding(context.Context, guestenrollment.RevokeBindingRequest) error
	RevokeExecution(context.Context, guestenrollment.RevokeExecutionRequest) error
	CompleteExecutionCleanup(context.Context, guestenrollment.CompleteExecutionCleanupRequest) error
	TTLSeconds() int32
	HandoffTimeout() time.Duration
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
	registration string
	client       host.Client
	kind         nvtv1alpha1.AgentRunExecutionKind
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
	return externalExecutionBackend{registration: selection.Driver, client: client, kind: selection.Kind}, true
}

func (backend externalExecutionBackend) Reconcile(
	ctx context.Context,
	reconciler *AgentRunReconciler,
	agentRun nvtv1alpha1.AgentRun,
) (ctrl.Result, error) {
	if IsTerminalAgentRunPhase(agentRun.Status.Phase) {
		return backend.reconcileTerminalLifecycle(ctx, reconciler, &agentRun)
	}
	if nativeMediatedExternalRun(&agentRun) {
		changed, attachmentErr := reconciler.ensureNativeEgressAttachment(ctx, &agentRun)
		if attachmentErr != nil {
			return reconciler.recordExecutionSelectionFailure(ctx, &agentRun, executionSelectionInvalidReason, "native mediated egress attachment is unavailable")
		}
		if changed {
			return ctrl.Result{Requeue: true}, nil
		}
	}
	desired, err := desiredExternalExecution(&agentRun, reconciler.NativeEgressAttachment)
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
	if backend.kind == nvtv1alpha1.AgentRunExecutionVM && reconciler.GuestEnrollment != nil && reconciler.GuestEnrollment.EnabledFor(backend.registration) && controllerutil.AddFinalizer(&agentRun, guestEnrollmentFinalizer) {
		if err := reconciler.Update(ctx, &agentRun); err != nil {
			return ctrl.Result{}, fmt.Errorf("add guest enrollment finalizer: %w", err)
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
	if backend.kind == nvtv1alpha1.AgentRunExecutionVM && status.ObservedGeneration == desired.Generation && controllerutil.ContainsFinalizer(&agentRun, guestEnrollmentFinalizer) {
		enrollmentResult, enrollmentErr := backend.reconcileGuestEnrollment(ctx, reconciler, &agentRun, desired)
		if enrollmentErr != nil {
			return ctrl.Result{}, enrollmentErr
		}
		result = earliestRequeue(result, enrollmentResult)
	}
	if nativeMediatedExternalRun(&agentRun) {
		nativeEgressResult, nativeEgressErr := reconciler.reconcileNativeEgress(ctx, &agentRun, status)
		if nativeEgressErr != nil {
			return ctrl.Result{}, nativeEgressErr
		}
		result = earliestRequeue(result, nativeEgressResult)
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
	if !controllerutil.ContainsFinalizer(agentRun, externalExecutionFinalizer) && !controllerutil.ContainsFinalizer(agentRun, guestEnrollmentFinalizer) {
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
	if cleared, err := reconciler.clearNativeGuestBindingStatus(ctx, agentRun); err != nil || cleared {
		return ctrl.Result{Requeue: cleared}, err
	}
	if !controllerutil.ContainsFinalizer(agentRun, externalExecutionFinalizer) && !controllerutil.ContainsFinalizer(agentRun, guestEnrollmentFinalizer) {
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
	if cleared, err := reconciler.clearNativeGuestBindingStatus(ctx, agentRun); err != nil || cleared {
		return ctrl.Result{Requeue: cleared}, err
	}
	if nativeMediatedExternalRun(agentRun) {
		if err := reconciler.cleanupNativeEgressResources(ctx, agentRun); err != nil {
			return reconciler.recordExternalCleanupFailure(ctx, agentRun, "NativeEgressCleanupPending", externalExecutionCleanupRetry)
		}
	}
	executionID, err := externalExecutionID(agentRun.UID)
	if err != nil {
		return reconciler.recordExecutionSelectionFailure(ctx, agentRun, executionSelectionInvalidReason, "resolved external execution state is invalid")
	}
	if controllerutil.ContainsFinalizer(agentRun, guestEnrollmentFinalizer) {
		if result, complete, revokeErr := reconciler.revokeGuestEnrollmentScope(ctx, agentRun, backend.registration); revokeErr != nil || !complete {
			return result, revokeErr
		}
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
	if controllerutil.ContainsFinalizer(agentRun, guestEnrollmentFinalizer) {
		if result, complete, completionErr := reconciler.completeGuestEnrollmentCleanup(ctx, agentRun, backend.registration); completionErr != nil || !complete {
			return result, completionErr
		}
	}
	if err := reconciler.finalizeExternalAgentRun(ctx, agentRun); err != nil {
		return ctrl.Result{}, err
	}
	if !deletingAgentRun {
		return reconciler.reconcileTerminalAgentRunRetention(ctx, agentRun)
	}
	return ctrl.Result{}, nil
}

func externalTerminalCleanupDue(agentRun *nvtv1alpha1.AgentRun, now metav1.Time) bool {
	if !IsTerminalAgentRunPhase(agentRun.Status.Phase) {
		return false
	}
	if agentRun.Status.Phase == nvtv1alpha1.AgentRunPhaseDeadlineExceeded {
		return true
	}
	_, due := TerminalOperationalCleanupDelay(agentRun, now)
	return due
}

func (r *AgentRunReconciler) revokeGuestEnrollmentScope(
	ctx context.Context,
	agentRun *nvtv1alpha1.AgentRun,
	driverRegistration string,
) (ctrl.Result, bool, error) {
	if r.GuestEnrollment == nil {
		result, err := r.recordExternalCleanupFailure(ctx, agentRun, "GuestEnrollmentUnavailable", externalExecutionCleanupRetry)
		return result, false, err
	}
	release, acquired := r.tryAcquireExternalExecutionCall()
	if !acquired {
		return ctrl.Result{RequeueAfter: externalExecutionDefaultRequeue}, false, nil
	}
	defer release()
	executionID, err := externalExecutionID(agentRun.UID)
	if err != nil {
		result, recordErr := r.recordExternalCleanupFailure(ctx, agentRun, "GuestEnrollmentRevocationPending", externalExecutionCleanupRetry)
		return result, false, recordErr
	}
	scope := guestenrollment.ExecutionScope{AgentRunUID: string(agentRun.UID), ExecutionID: executionID, DriverRegistration: driverRegistration}
	if err := r.GuestEnrollment.RevokeExecution(ctx, guestenrollment.RevokeExecutionRequest{ContractVersion: guestenrollment.Version, ExecutionScope: scope}); err != nil {
		result, recordErr := r.recordExternalCleanupFailure(ctx, agentRun, "GuestEnrollmentRevocationPending", externalExecutionCleanupRetry)
		return result, false, recordErr
	}
	return ctrl.Result{}, true, nil
}

func (r *AgentRunReconciler) completeGuestEnrollmentCleanup(
	ctx context.Context,
	agentRun *nvtv1alpha1.AgentRun,
	driverRegistration string,
) (ctrl.Result, bool, error) {
	if r.GuestEnrollment == nil {
		result, err := r.recordExternalCleanupFailure(ctx, agentRun, "GuestEnrollmentCleanupCompletionPending", externalExecutionCleanupRetry)
		return result, false, err
	}
	release, acquired := r.tryAcquireExternalExecutionCall()
	if !acquired {
		return ctrl.Result{RequeueAfter: externalExecutionDefaultRequeue}, false, nil
	}
	defer release()
	executionID, err := externalExecutionID(agentRun.UID)
	if err != nil {
		result, recordErr := r.recordExternalCleanupFailure(ctx, agentRun, "GuestEnrollmentCleanupCompletionPending", externalExecutionCleanupRetry)
		return result, false, recordErr
	}
	scope := guestenrollment.ExecutionScope{AgentRunUID: string(agentRun.UID), ExecutionID: executionID, DriverRegistration: driverRegistration}
	if err := r.GuestEnrollment.CompleteExecutionCleanup(ctx, guestenrollment.CompleteExecutionCleanupRequest{ContractVersion: guestenrollment.Version, ExecutionScope: scope}); err != nil {
		result, recordErr := r.recordExternalCleanupFailure(ctx, agentRun, "GuestEnrollmentCleanupCompletionPending", externalExecutionCleanupRetry)
		return result, false, recordErr
	}
	return ctrl.Result{}, true, nil
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

func (backend externalExecutionBackend) reconcileGuestEnrollment(
	ctx context.Context,
	reconciler *AgentRunReconciler,
	agentRun *nvtv1alpha1.AgentRun,
	desired executiondriver.DesiredExecution,
) (ctrl.Result, error) {
	issuer := reconciler.GuestEnrollment
	handoff, ok := backend.client.(guestenrollment.Handoff)
	if issuer == nil || !ok {
		return reconciler.recordGuestEnrollmentCondition(ctx, agentRun, nil, "ExternalBootstrapHandoffUnavailable")
	}
	handoffTimeout := issuer.HandoffTimeout()
	if handoffTimeout <= 0 || handoffTimeout > guestenrollment.MaxOperationDuration {
		return reconciler.recordGuestEnrollmentCondition(ctx, agentRun, nil, "ExternalBootstrapInvalid")
	}
	release, acquired := reconciler.tryAcquireExternalExecutionCall()
	if !acquired {
		return ctrl.Result{RequeueAfter: externalExecutionDefaultRequeue}, nil
	}
	defer release()
	scope := guestenrollment.ExecutionScope{AgentRunUID: string(agentRun.UID), ExecutionID: desired.ExecutionID, DriverRegistration: backend.registration}
	if guestenrollment.ValidateExecutionScope(scope) != nil {
		return reconciler.recordGuestEnrollmentCondition(ctx, agentRun, nil, "ExternalBootstrapInvalid")
	}
	var publishedBinding *guestenrollment.Binding
	if agentRun.Status.NativeGuestBinding != nil {
		published, publishedErr := nativeGuestBindingFromStatus(agentRun.Status.NativeGuestBinding)
		if publishedErr != nil || published.ExecutionScope() != scope || published.DesiredGeneration != desired.Generation {
			return reconciler.recordGuestEnrollmentCondition(ctx, agentRun, nil, "ExternalBootstrapPending")
		}
		publishedBinding = &published
	}
	handoffContext, cancelHandoff := context.WithTimeout(ctx, handoffTimeout)
	prepared, err := handoff.Prepare(handoffContext, guestenrollment.HandoffPrepareRequest{
		ContractVersion: guestenrollment.HandoffVersion, ExecutionScope: scope, DesiredGeneration: desired.Generation,
	})
	cancelHandoff()
	if err != nil || guestenrollment.ValidateHandoffPrepareResult(prepared) != nil {
		return reconciler.recordGuestEnrollmentCondition(ctx, agentRun, nil, "ExternalBootstrapHandoffUnavailable")
	}
	binding := guestenrollment.Binding{
		AgentRunUID: scope.AgentRunUID, ExecutionID: scope.ExecutionID, DriverRegistration: scope.DriverRegistration,
		DesiredGeneration: desired.Generation, GuestInstanceID: prepared.GuestInstanceID,
	}
	if guestenrollment.ValidateBinding(binding) != nil {
		return reconciler.recordGuestEnrollmentCondition(ctx, agentRun, nil, "ExternalBootstrapInvalid")
	}
	if prepared.State == guestenrollment.HandoffStateAccepted {
		if publishedBinding != nil && *publishedBinding != binding {
			return reconciler.recordGuestEnrollmentCondition(ctx, agentRun, nil, "ExternalBootstrapReplacementPending")
		}
		return reconciler.recordGuestEnrollmentCondition(ctx, agentRun, &binding, "ExternalBootstrapAccepted")
	}
	if agentRun.Status.NativeGuestBinding != nil {
		return reconciler.recordGuestEnrollmentCondition(ctx, agentRun, nil, "ExternalBootstrapReplacementPending")
	}
	if !prepared.NewlyPrepared {
		if err := issuer.RevokeBinding(ctx, guestenrollment.RevokeBindingRequest{ContractVersion: guestenrollment.Version, Binding: binding}); err != nil {
			return reconciler.recordGuestEnrollmentCondition(ctx, agentRun, nil, "ExternalBootstrapRevocationPending")
		}
		handoffContext, cancelHandoff = context.WithTimeout(ctx, handoffTimeout)
		replacement, err := handoff.Replace(handoffContext, guestenrollment.HandoffReplaceRequest{ContractVersion: guestenrollment.HandoffVersion, Binding: binding})
		cancelHandoff()
		if err != nil || guestenrollment.ValidateHandoffPrepareResult(replacement) != nil || replacement.State != guestenrollment.HandoffStatePrepared ||
			!replacement.NewlyPrepared || replacement.GuestInstanceID == binding.GuestInstanceID {
			return reconciler.recordGuestEnrollmentCondition(ctx, agentRun, nil, "ExternalBootstrapReplacementPending")
		}
		binding.GuestInstanceID = replacement.GuestInstanceID
	}
	envelope, err := issuer.Issue(ctx, guestenrollment.IssueRequest{
		ContractVersion: guestenrollment.Version, Binding: binding, TTLSeconds: issuer.TTLSeconds(),
	})
	if err != nil || guestenrollment.ValidateBootstrapEnvelope(envelope) != nil || envelope.Binding != binding {
		clearBootstrapEnvelope(&envelope)
		return reconciler.recordGuestEnrollmentCondition(ctx, agentRun, nil, "ExternalBootstrapIssuePending")
	}
	defer clearBootstrapEnvelope(&envelope)
	handoffContext, cancelHandoff = context.WithTimeout(ctx, handoffTimeout)
	err = handoff.Deliver(handoffContext, guestenrollment.HandoffDeliverRequest{ContractVersion: guestenrollment.HandoffVersion, Envelope: envelope})
	cancelHandoff()
	if err != nil {
		return reconciler.recordGuestEnrollmentCondition(ctx, agentRun, nil, "ExternalBootstrapDeliveryUncertain")
	}
	return reconciler.recordGuestEnrollmentCondition(ctx, agentRun, &binding, "ExternalBootstrapAccepted")
}

func clearBootstrapEnvelope(envelope *guestenrollment.BootstrapEnvelope) {
	envelope.Token = ""
	envelope.ExchangeURL = ""
	envelope.IssuedAt = ""
	envelope.ExpiresAt = ""
	envelope.Binding = guestenrollment.Binding{}
	envelope.ContractVersion = ""
}

func (r *AgentRunReconciler) recordGuestEnrollmentCondition(
	ctx context.Context,
	agentRun *nvtv1alpha1.AgentRun,
	binding *guestenrollment.Binding,
	reason string,
) (ctrl.Result, error) {
	if binding == nil && agentRun.Status.NativeGuestBinding != nil {
		if err := r.withdrawNativeEgressTarget(ctx, agentRun); err != nil {
			return ctrl.Result{}, err
		}
	}
	previous := agentRun.Status.DeepCopy()
	conditionStatus := metav1.ConditionFalse
	message := "external guest bootstrap has not completed"
	if binding != nil {
		agentRun.Status.NativeGuestBinding = nativeGuestBindingStatus(*binding)
		conditionStatus = metav1.ConditionTrue
		message = "the exact selected driver accepted the external guest bootstrap handoff"
	} else {
		agentRun.Status.NativeGuestBinding = nil
	}
	r.setRunCondition(agentRun, ConditionExecutionBackendAvailable, conditionStatus, reason, message)
	if !reflect.DeepEqual(*previous, agentRun.Status) {
		if err := r.Status().Update(ctx, agentRun); err != nil {
			return ctrl.Result{}, fmt.Errorf("update guest enrollment status: %w", err)
		}
	}
	if binding != nil {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{RequeueAfter: externalExecutionDefaultRequeue}, nil
}

func nativeGuestBindingStatus(binding guestenrollment.Binding) *nvtv1alpha1.AgentRunNativeGuestBinding {
	return &nvtv1alpha1.AgentRunNativeGuestBinding{
		AgentRunUID:        binding.AgentRunUID,
		ExecutionID:        binding.ExecutionID,
		DriverRegistration: binding.DriverRegistration,
		DesiredGeneration:  binding.DesiredGeneration,
		GuestInstanceID:    binding.GuestInstanceID,
	}
}

func nativeGuestBindingFromStatus(status *nvtv1alpha1.AgentRunNativeGuestBinding) (guestenrollment.Binding, error) {
	if status == nil {
		return guestenrollment.Binding{}, fmt.Errorf("native guest binding is unavailable")
	}
	binding := guestenrollment.Binding{
		AgentRunUID:        status.AgentRunUID,
		ExecutionID:        status.ExecutionID,
		DriverRegistration: status.DriverRegistration,
		DesiredGeneration:  status.DesiredGeneration,
		GuestInstanceID:    status.GuestInstanceID,
	}
	if err := guestenrollment.ValidateBinding(binding); err != nil {
		return guestenrollment.Binding{}, fmt.Errorf("native guest binding is invalid")
	}
	return binding, nil
}

func (r *AgentRunReconciler) clearNativeGuestBindingStatus(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) (bool, error) {
	if agentRun.Status.NativeGuestBinding == nil {
		return false, nil
	}
	if err := r.withdrawNativeEgressTarget(ctx, agentRun); err != nil {
		return false, err
	}
	agentRun.Status.NativeGuestBinding = nil
	if err := r.Status().Update(ctx, agentRun); err != nil {
		return false, fmt.Errorf("clear native guest routing binding: %w", err)
	}
	return true, nil
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

func desiredExternalExecution(agentRun *nvtv1alpha1.AgentRun, configured *executiondriver.NativeEgressAttachment) (executiondriver.DesiredExecution, error) {
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
	var attachment *executiondriver.NativeEgressAttachment
	if nativeMediatedExternalRun(agentRun) {
		if configured == nil || !nativeEgressAttachmentCurrent(agentRun, configured) {
			return executiondriver.DesiredExecution{}, fmt.Errorf("native egress attachment is unavailable")
		}
		copy := *configured
		copy.RequiredDestinations = append([]executiondriver.NativeEgressRequiredDestination(nil), configured.RequiredDestinations...)
		attachment = &copy
	}
	attachmentGeneration := int64(0)
	if attachment != nil {
		attachmentGeneration = attachment.Generation
	}
	generation, err := executiondriver.NativeEgressDesiredGeneration(agentRun.Generation, attachmentGeneration)
	if err != nil {
		return executiondriver.DesiredExecution{}, err
	}
	desired := executiondriver.DesiredExecution{
		ExecutionID: executionID, Generation: generation,
		DesiredFingerprint: externalDesiredFingerprint(workloadKind, agentRun.Spec.Execution.ClassRef, configuration, attachment),
		WorkloadKind:       workloadKind, ClassName: agentRun.Spec.Execution.ClassRef,
		Configuration: configuration, NativeEgressAttachment: attachment,
	}
	if err := executiondriver.ValidateReconcileParams(executiondriver.ReconcileParams{Desired: desired}); err != nil {
		return executiondriver.DesiredExecution{}, err
	}
	return desired, nil
}

func externalExecutionID(uid types.UID) (string, error) {
	return executiondriver.AgentRunExecutionID(string(uid))
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

func externalDesiredFingerprint(kind executiondriver.WorkloadKind, className string, configuration []byte, attachment *executiondriver.NativeEgressAttachment) string {
	hash := sha256.New()
	values := [][]byte{[]byte("nvt.external-desired/v1"), []byte(kind), []byte(className), configuration}
	if attachment != nil {
		encoded, err := json.Marshal(attachment)
		if err != nil {
			return ""
		}
		values = append(values, encoded)
	}
	for _, value := range values {
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
	willClearBinding := status.ObservedGeneration != desiredGeneration || status.Phase == executiondriver.PhaseSucceeded ||
		(status.Phase == executiondriver.PhaseFailed && (status.Failure == nil || !status.Failure.Retryable))
	if willClearBinding && agentRun.Status.NativeGuestBinding != nil {
		if err := r.withdrawNativeEgressTarget(ctx, agentRun); err != nil {
			return ctrl.Result{}, err
		}
	}
	previous := agentRun.Status.DeepCopy()
	InitializeAgentRunStatus(agentRun)
	// When the guest-bootstrap cleanup obligation is present, the separate
	// sensitive handoff owns this aggregate backend-availability condition.
	// Avoid writing a transient driver-only success between every prepare and
	// accepted observation, which would otherwise churn status indefinitely.
	if !controllerutil.ContainsFinalizer(agentRun, guestEnrollmentFinalizer) {
		r.setRunCondition(agentRun, ConditionExecutionBackendAvailable, metav1.ConditionTrue, "ExecutionDriverAvailable", "selected execution driver host responded with a valid status")
	}
	ready := status.Ready && status.ObservedGeneration == desiredGeneration
	if nativeMediatedExternalRun(agentRun) {
		attachment := agentRun.Status.NativeEgressAttachment
		ready = ready && attachment != nil && status.EgressConfinement != nil &&
			status.EgressConfinement.Boundary == executiondriver.EgressConfinementBoundaryInfrastructure && status.EgressConfinement.Ready &&
			status.EgressConfinement.AttachmentGeneration == attachment.Generation && status.EgressConfinement.AttachmentDigest == attachment.Digest
	}
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
	if status.ObservedGeneration != desiredGeneration {
		agentRun.Status.NativeGuestBinding = nil
	}
	if phase == nvtv1alpha1.AgentRunPhaseCompleted || phase == nvtv1alpha1.AgentRunPhaseFailed {
		agentRun.Status.NativeGuestBinding = nil
		if agentRun.Status.FinishedAt == nil {
			now := r.now()
			agentRun.Status.FinishedAt = &now
		}
	}
	if nativeMediatedExternalRun(agentRun) {
		if ready && phase == nvtv1alpha1.AgentRunPhaseRunning && meta.IsStatusConditionTrue(agentRun.Status.Conditions, ConditionNativeEgressReady) {
			conditionStatus = metav1.ConditionTrue
			reason = executionDriverReadyReason
		} else {
			conditionStatus = metav1.ConditionFalse
			reason = nativeEgressPendingReason
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
	if agentRun.Status.NativeGuestBinding != nil {
		if err := r.withdrawNativeEgressTarget(ctx, agentRun); err != nil {
			return err
		}
	}
	previous := agentRun.Status.DeepCopy()
	InitializeAgentRunStatus(agentRun)
	now := r.now()
	agentRun.Status.Phase = nvtv1alpha1.AgentRunPhaseFailed
	agentRun.Status.PodName = ""
	agentRun.Status.FinishedAt = &now
	agentRun.Status.Reason = executionDriverRejectedReason
	agentRun.Status.NativeGuestBinding = nil
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
	if agentRun.Status.NativeGuestBinding != nil {
		if err := r.withdrawNativeEgressTarget(ctx, agentRun); err != nil {
			return ctrl.Result{}, err
		}
	}
	previous := agentRun.Status.DeepCopy()
	InitializeAgentRunStatus(agentRun)
	agentRun.Status.PodName = ""
	agentRun.Status.Reason = "ExternalExecutionStaleObservation"
	agentRun.Status.NativeGuestBinding = nil
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
	if agentRun.Status.NativeGuestBinding != nil {
		if err := r.withdrawNativeEgressTarget(ctx, agentRun); err != nil {
			return ctrl.Result{}, err
		}
	}
	previous := agentRun.Status.DeepCopy()
	agentRun.Status.NativeGuestBinding = nil
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
	if agentRun.Status.NativeGuestBinding != nil {
		if err := r.withdrawNativeEgressTarget(ctx, agentRun); err != nil {
			return ctrl.Result{}, err
		}
	}
	previous := agentRun.Status.DeepCopy()
	agentRun.Status.NativeGuestBinding = nil
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
	if agentRun.Status.NativeGuestBinding != nil {
		if err := r.withdrawNativeEgressTarget(ctx, agentRun); err != nil {
			return ctrl.Result{}, true, err
		}
	}
	previous := agentRun.Status.DeepCopy()
	agentRun.Status.Phase = nvtv1alpha1.AgentRunPhaseDeadlineExceeded
	agentRun.Status.FinishedAt = &now
	agentRun.Status.Reason = activeDeadlineReason
	agentRun.Status.NativeGuestBinding = nil
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
	controllerutil.RemoveFinalizer(agentRun, guestEnrollmentFinalizer)
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
	if agentRun.Status.NativeGuestBinding != nil {
		if err := r.withdrawNativeEgressTarget(ctx, agentRun); err != nil {
			return ctrl.Result{}, err
		}
	}
	changed := InitializeAgentRunStatus(agentRun)
	if agentRun.Status.NativeGuestBinding != nil {
		agentRun.Status.NativeGuestBinding = nil
		changed = true
	}
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
