package controller

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

func TestInitializeAgentRunStatusSetsPendingForEmptyPhase(t *testing.T) {
	agentRun := &nvtv1alpha1.AgentRun{}

	changed := InitializeAgentRunStatus(agentRun)

	if !changed {
		t.Fatal("expected status to change")
	}
	if agentRun.Status.Phase != nvtv1alpha1.AgentRunPhasePending {
		t.Fatalf("expected phase %q, got %q", nvtv1alpha1.AgentRunPhasePending, agentRun.Status.Phase)
	}
}

func TestInitializeAgentRunStatusKeepsExistingPhase(t *testing.T) {
	agentRun := &nvtv1alpha1.AgentRun{
		Status: nvtv1alpha1.AgentRunStatus{Phase: nvtv1alpha1.AgentRunPhaseRunning},
	}

	changed := InitializeAgentRunStatus(agentRun)

	if changed {
		t.Fatal("expected status to remain unchanged")
	}
	if agentRun.Status.Phase != nvtv1alpha1.AgentRunPhaseRunning {
		t.Fatalf("expected phase %q, got %q", nvtv1alpha1.AgentRunPhaseRunning, agentRun.Status.Phase)
	}
}

func TestReconcileSetsPendingForEmptyPhase(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := nvtv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add scheme: %v", err)
	}

	key := types.NamespacedName{Name: "example", Namespace: "default"}
	agentRun := &nvtv1alpha1.AgentRun{
		ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
	}
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var updated nvtv1alpha1.AgentRun
	if err := k8sClient.Get(ctx, key, &updated); err != nil {
		t.Fatalf("get updated AgentRun: %v", err)
	}
	if updated.Status.Phase != nvtv1alpha1.AgentRunPhasePending {
		t.Fatalf("expected phase %q, got %q", nvtv1alpha1.AgentRunPhasePending, updated.Status.Phase)
	}
}
