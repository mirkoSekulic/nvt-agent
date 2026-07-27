package controller

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

const (
	ConditionExecutionBackendAvailable = "ExecutionBackendAvailable"
	executionSelectionInvalidReason    = "ExecutionSelectionInvalid"
	executionDriverUnavailableReason   = "ExecutionDriverUnavailable"
)

type executionBackendKey struct {
	kind   nvtv1alpha1.AgentRunExecutionKind
	driver string
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

func executionBackendFor(selection effectiveExecutionSelection) (agentRunExecutionBackend, bool) {
	backend, exists := builtInExecutionBackends()[executionBackendKey{kind: selection.Kind, driver: selection.Driver}]
	return backend, exists
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
	if changed {
		if err := r.Status().Update(ctx, agentRun); err != nil {
			return ctrl.Result{}, fmt.Errorf("update AgentRun execution selection status: %w", err)
		}
	}
	return ctrl.Result{}, nil
}
