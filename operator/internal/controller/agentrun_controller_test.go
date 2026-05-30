package controller

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	scheme := testScheme(t)

	agentRun := testAgentRun()
	key := clientKey(agentRun)
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

func TestReconcileCreatesAgentConfigMap(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	configMap := getAgentConfigMap(ctx, t, k8sClient, agentRun)
	if len(configMap.Data) != 1 {
		t.Fatalf("expected exactly one data key, got %#v", configMap.Data)
	}
	agentConfig := configMap.Data[agentConfigKey]
	for _, expected := range []string{
		"plugins:",
		"name: checkout-repos",
		"repository: github.com/mirkoSekulic/nvt-agent",
	} {
		if !strings.Contains(agentConfig, expected) {
			t.Fatalf("expected rendered config to contain %q, got:\n%s", expected, agentConfig)
		}
	}
}

func TestReconcileCreatesOwnedAgentConfigMap(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	configMap := getAgentConfigMap(ctx, t, k8sClient, agentRun)
	owners := configMap.GetOwnerReferences()
	if len(owners) != 1 {
		t.Fatalf("expected one owner reference, got %#v", owners)
	}
	owner := owners[0]
	if owner.APIVersion != nvtv1alpha1.GroupVersion.String() ||
		owner.Kind != "AgentRun" ||
		owner.Name != agentRun.Name ||
		owner.UID != agentRun.UID {
		t.Fatalf("unexpected owner reference: %#v", owner)
	}
	if owner.Controller == nil || !*owner.Controller {
		t.Fatalf("expected controller owner reference, got %#v", owner)
	}
}

func TestReconcileUpdatesAgentConfigMapWhenConfigChanges(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var updatedAgentRun nvtv1alpha1.AgentRun
	if getErr := k8sClient.Get(ctx, clientKey(agentRun), &updatedAgentRun); getErr != nil {
		t.Fatalf("get AgentRun: %v", getErr)
	}
	updatedAgentRun.Spec.Agent.Config = apiextensionsv1.JSON{Raw: []byte(`{
		"plugins": [
			{
				"name": "checkout-repos",
				"config": {
					"repository": "github.com/mirkoSekulic/nvt-agent-updated"
				}
			}
		]
	}`)}
	if updateErr := k8sClient.Update(ctx, &updatedAgentRun); updateErr != nil {
		t.Fatalf("update AgentRun: %v", updateErr)
	}

	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile updated config: %v", err)
	}

	configMap := getAgentConfigMap(ctx, t, k8sClient, agentRun)
	agentConfig := configMap.Data[agentConfigKey]
	if strings.Contains(agentConfig, "repository: github.com/mirkoSekulic/nvt-agent\n") {
		t.Fatalf("expected previous config to be replaced, got:\n%s", agentConfig)
	}
	if !strings.Contains(agentConfig, "repository: github.com/mirkoSekulic/nvt-agent-updated") {
		t.Fatalf("expected updated config, got:\n%s", agentConfig)
	}
	if len(configMap.Data) != 1 {
		t.Fatalf("expected exactly one data key, got %#v", configMap.Data)
	}
}

func TestRenderAgentConfigYAMLRejectsMalformedConfig(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Spec.Agent.Config = apiextensionsv1.JSON{Raw: []byte(`{"plugins": [`)}

	_, err := RenderAgentConfigYAML(agentRun)
	if err == nil {
		t.Fatal("expected malformed config to fail")
	}
	if !strings.Contains(err.Error(), "render AgentRun agent config") {
		t.Fatalf("expected render error context, got %v", err)
	}
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add core scheme: %v", err)
	}
	if err := nvtv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add AgentRun scheme: %v", err)
	}
	return scheme
}

func testAgentRun() *nvtv1alpha1.AgentRun {
	return &nvtv1alpha1.AgentRun{
		TypeMeta: metav1.TypeMeta{
			APIVersion: nvtv1alpha1.GroupVersion.String(),
			Kind:       "AgentRun",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "example",
			Namespace: "default",
			UID:       "agentrun-uid",
		},
		Spec: nvtv1alpha1.AgentRunSpec{
			Agent: nvtv1alpha1.AgentRunAgent{
				Config: apiextensionsv1.JSON{Raw: []byte(`{
					"plugins": [
						{
							"name": "checkout-repos",
							"config": {
								"repository": "github.com/mirkoSekulic/nvt-agent"
							}
						}
					]
				}`)},
			},
		},
	}
}

func clientKey(agentRun *nvtv1alpha1.AgentRun) types.NamespacedName {
	return types.NamespacedName{Name: agentRun.Name, Namespace: agentRun.Namespace}
}

func getAgentConfigMap(
	ctx context.Context,
	t *testing.T,
	k8sClient client.Reader,
	agentRun *nvtv1alpha1.AgentRun,
) corev1.ConfigMap {
	t.Helper()

	var configMap corev1.ConfigMap
	key := types.NamespacedName{Name: AgentConfigMapName(agentRun.Name), Namespace: agentRun.Namespace}
	if err := k8sClient.Get(ctx, key, &configMap); err != nil {
		t.Fatalf("get ConfigMap: %v", err)
	}
	return configMap
}
