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

func TestReconcileCreatesAgentPod(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	runtimeClassName := "kata-vm-isolation"
	agentRun.Spec.RuntimeClassName = &runtimeClassName
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

	pod := getAgentPod(ctx, t, k8sClient, agentRun)
	if pod.Name != AgentPodName(agentRun.Name) {
		t.Fatalf("expected Pod name %q, got %q", AgentPodName(agentRun.Name), pod.Name)
	}
	assertOwnedByAgentRun(t, pod.GetOwnerReferences(), agentRun)
	expectedLabels := map[string]string{
		"app.kubernetes.io/name":      "nvt-agent",
		"app.kubernetes.io/component": "agentrun",
		"nvt.dev/agentrun":            agentRun.Name,
	}
	for key, value := range expectedLabels {
		if pod.Labels[key] != value {
			t.Fatalf("expected label %s=%s, got %#v", key, value, pod.Labels)
		}
	}
	if pod.Spec.RuntimeClassName == nil || *pod.Spec.RuntimeClassName != runtimeClassName {
		t.Fatalf("expected runtimeClassName %q, got %#v", runtimeClassName, pod.Spec.RuntimeClassName)
	}
	if pod.Spec.RestartPolicy != corev1.RestartPolicyNever {
		t.Fatalf("expected restartPolicy Never, got %q", pod.Spec.RestartPolicy)
	}

	agentContainer := requireContainer(t, pod, "agent")
	if agentContainer.Image != agentRun.Spec.Image {
		t.Fatalf("expected agent image %q, got %q", agentRun.Spec.Image, agentContainer.Image)
	}
	if agentContainer.WorkingDir != workspaceMountPath {
		t.Fatalf("expected agent working directory %q, got %q", workspaceMountPath, agentContainer.WorkingDir)
	}
	if envValue(agentContainer, "DOCKER_HOST") != "tcp://127.0.0.1:2375" {
		t.Fatalf("expected DOCKER_HOST tcp://127.0.0.1:2375, got %#v", agentContainer.Env)
	}
	if envValue(agentContainer, "NVT_AGENT_CONFIG_FILE") != agentConfigMountPath {
		t.Fatalf("expected NVT_AGENT_CONFIG_FILE %q, got %#v", agentConfigMountPath, agentContainer.Env)
	}
	if envValue(agentContainer, "NVT_BROKER_URL") != brokerURL {
		t.Fatalf("expected NVT_BROKER_URL %q, got %#v", brokerURL, agentContainer.Env)
	}
	assertSecretKeyEnv(t, agentContainer, brokerTokenKey, BrokerTokenSecretName(agentRun.Name), brokerTokenKey)
	assertSecretKeyEnv(t, agentContainer, callbackTokenKey, CallbackTokenSecretName(agentRun.Name), callbackTokenKey)
	assertVolumeMount(t, agentContainer, "agent-config", agentConfigVolumeDir, "", true)
	assertVolumeMount(t, agentContainer, "workspace", workspaceMountPath, "", false)

	dindContainer := requireInitContainer(t, pod, "docker")
	if dindContainer.Image != "docker:27-dind" {
		t.Fatalf("expected DinD image docker:27-dind, got %q", dindContainer.Image)
	}
	if dindContainer.RestartPolicy == nil || *dindContainer.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatalf("expected DinD init sidecar restartPolicy Always, got %#v", dindContainer.RestartPolicy)
	}
	if strings.Join(append(dindContainer.Command, dindContainer.Args...), " ") !=
		"dockerd --host=unix:///var/run/docker.sock --host=tcp://127.0.0.1:2375 --tls=false" {
		t.Fatalf("unexpected DinD command/args: command=%#v args=%#v", dindContainer.Command, dindContainer.Args)
	}
	if dindContainer.StartupProbe == nil ||
		dindContainer.StartupProbe.Exec == nil ||
		strings.Join(dindContainer.StartupProbe.Exec.Command, " ") != "docker info" {
		t.Fatalf("expected DinD startupProbe to run docker info, got %#v", dindContainer.StartupProbe)
	}
	if dindContainer.SecurityContext == nil || dindContainer.SecurityContext.Privileged == nil || !*dindContainer.SecurityContext.Privileged {
		t.Fatalf("expected privileged DinD sidecar, got %#v", dindContainer.SecurityContext)
	}
	assertVolumeMount(t, dindContainer, "workspace", workspaceMountPath, "", false)

	workspaceVolume := requireVolume(t, pod, "workspace")
	if workspaceVolume.EmptyDir == nil {
		t.Fatalf("expected workspace emptyDir volume, got %#v", workspaceVolume.VolumeSource)
	}
	configVolume := requireVolume(t, pod, "agent-config")
	if configVolume.ConfigMap == nil {
		t.Fatalf("expected ConfigMap volume, got %#v", configVolume.VolumeSource)
	}
	if configVolume.ConfigMap.Name != AgentConfigMapName(agentRun.Name) {
		t.Fatalf("expected ConfigMap %q, got %q", AgentConfigMapName(agentRun.Name), configVolume.ConfigMap.Name)
	}
	if len(configVolume.ConfigMap.Items) != 1 ||
		configVolume.ConfigMap.Items[0].Key != agentConfigKey ||
		configVolume.ConfigMap.Items[0].Path != agentConfigKey {
		t.Fatalf("expected agent.yaml ConfigMap item, got %#v", configVolume.ConfigMap.Items)
	}
}

func TestReconcileCreatesTokenSecrets(t *testing.T) {
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

	brokerSecret := getSecret(ctx, t, k8sClient, agentRun.Namespace, BrokerTokenSecretName(agentRun.Name))
	assertTokenSecret(t, brokerSecret, agentRun, brokerTokenKey)
	callbackSecret := getSecret(ctx, t, k8sClient, agentRun.Namespace, CallbackTokenSecretName(agentRun.Name))
	assertTokenSecret(t, callbackSecret, agentRun, callbackTokenKey)

	pod := getAgentPod(ctx, t, k8sClient, agentRun)
	agentContainer := requireContainer(t, pod, "agent")
	assertSecretKeyEnv(t, agentContainer, brokerTokenKey, brokerSecret.Name, brokerTokenKey)
	assertSecretKeyEnv(t, agentContainer, callbackTokenKey, callbackSecret.Name, callbackTokenKey)
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
	assertOwnedByAgentRun(t, configMap.GetOwnerReferences(), agentRun)
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

func TestReconcileDoesNotUpdateExistingAgentPodSpec(t *testing.T) {
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
	if err := k8sClient.Get(ctx, clientKey(agentRun), &updatedAgentRun); err != nil {
		t.Fatalf("get AgentRun: %v", err)
	}
	updatedAgentRun.Spec.Image = "nvt-agent-runtime:updated"
	if err := k8sClient.Update(ctx, &updatedAgentRun); err != nil {
		t.Fatalf("update AgentRun: %v", err)
	}

	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile updated image: %v", err)
	}

	pod := getAgentPod(ctx, t, k8sClient, agentRun)
	agentContainer := requireContainer(t, pod, "agent")
	if agentContainer.Image != "nvt-agent-runtime:test" {
		t.Fatalf("expected existing Pod image to remain unchanged, got %q", agentContainer.Image)
	}
}

func TestReconcileRejectsExistingUnownedAgentPod(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      AgentPodName(agentRun.Name),
			Namespace: agentRun.Namespace,
		},
	}
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, pod).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err == nil {
		t.Fatal("expected reconcile to reject an unowned same-name Pod")
	}
	if !strings.Contains(err.Error(), "exists but is not controlled by AgentRun") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReconcileReusesExistingOwnedTokenSecrets(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	brokerSecret := mustDesiredTokenSecret(t, agentRun, scheme, BrokerTokenSecretName(agentRun.Name), brokerTokenKey, []byte("existing-broker-token"))
	callbackSecret := mustDesiredTokenSecret(t, agentRun, scheme, CallbackTokenSecretName(agentRun.Name), callbackTokenKey, []byte("existing-callback-token"))
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, brokerSecret, callbackSecret).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	updatedBrokerSecret := getSecret(ctx, t, k8sClient, agentRun.Namespace, BrokerTokenSecretName(agentRun.Name))
	if string(updatedBrokerSecret.Data[brokerTokenKey]) != "existing-broker-token" {
		t.Fatalf("expected existing broker token to be reused, got %q", updatedBrokerSecret.Data[brokerTokenKey])
	}
	updatedCallbackSecret := getSecret(ctx, t, k8sClient, agentRun.Namespace, CallbackTokenSecretName(agentRun.Name))
	if string(updatedCallbackSecret.Data[callbackTokenKey]) != "existing-callback-token" {
		t.Fatalf("expected existing callback token to be reused, got %q", updatedCallbackSecret.Data[callbackTokenKey])
	}

	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile again: %v", err)
	}
	updatedBrokerSecret = getSecret(ctx, t, k8sClient, agentRun.Namespace, BrokerTokenSecretName(agentRun.Name))
	if string(updatedBrokerSecret.Data[brokerTokenKey]) != "existing-broker-token" {
		t.Fatalf("expected broker token not to rotate, got %q", updatedBrokerSecret.Data[brokerTokenKey])
	}
	updatedCallbackSecret = getSecret(ctx, t, k8sClient, agentRun.Namespace, CallbackTokenSecretName(agentRun.Name))
	if string(updatedCallbackSecret.Data[callbackTokenKey]) != "existing-callback-token" {
		t.Fatalf("expected callback token not to rotate, got %q", updatedCallbackSecret.Data[callbackTokenKey])
	}
}

func TestReconcileRejectsExistingUnownedBrokerTokenSecret(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: BrokerTokenSecretName(agentRun.Name), Namespace: agentRun.Namespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{brokerTokenKey: []byte("broker-token")},
	}
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, secret).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err == nil {
		t.Fatal("expected reconcile to reject unowned broker token Secret")
	}
	if !strings.Contains(err.Error(), "exists but is not controlled by AgentRun") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReconcileRejectsExistingUnownedCallbackTokenSecret(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	brokerSecret := mustDesiredTokenSecret(t, agentRun, scheme, BrokerTokenSecretName(agentRun.Name), brokerTokenKey, []byte("broker-token"))
	callbackSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: CallbackTokenSecretName(agentRun.Name), Namespace: agentRun.Namespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{callbackTokenKey: []byte("callback-token")},
	}
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, brokerSecret, callbackSecret).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err == nil {
		t.Fatal("expected reconcile to reject unowned callback token Secret")
	}
	if !strings.Contains(err.Error(), "exists but is not controlled by AgentRun") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGenerateTokenUsesReaderEntropy(t *testing.T) {
	token, err := GenerateToken(strings.NewReader(strings.Repeat("a", generatedTokenByteLength)))
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}
	if len(token) < 40 {
		t.Fatalf("expected token to encode at least 256 bits of entropy, got %d chars", len(token))
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

func TestReconcileSetsPodNameAfterPodExists(t *testing.T) {
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

	var updated nvtv1alpha1.AgentRun
	if err := k8sClient.Get(ctx, clientKey(agentRun), &updated); err != nil {
		t.Fatalf("get AgentRun: %v", err)
	}
	if updated.Status.PodName != AgentPodName(agentRun.Name) {
		t.Fatalf("expected podName %q, got %q", AgentPodName(agentRun.Name), updated.Status.PodName)
	}
	if updated.Status.Phase != nvtv1alpha1.AgentRunPhasePending {
		t.Fatalf("expected Pending phase, got %q", updated.Status.Phase)
	}
}

func TestReconcileSetsRunningAndStartedAtWhenPodRuns(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	pod := getAgentPod(ctx, t, k8sClient, agentRun)
	pod.Status.Phase = corev1.PodRunning
	if err := k8sClient.Status().Update(ctx, &pod); err != nil {
		t.Fatalf("update Pod status: %v", err)
	}

	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile running Pod: %v", err)
	}

	var updated nvtv1alpha1.AgentRun
	if err := k8sClient.Get(ctx, clientKey(agentRun), &updated); err != nil {
		t.Fatalf("get AgentRun: %v", err)
	}
	if updated.Status.Phase != nvtv1alpha1.AgentRunPhaseRunning {
		t.Fatalf("expected Running phase, got %q", updated.Status.Phase)
	}
	if updated.Status.StartedAt == nil {
		t.Fatal("expected startedAt to be set")
	}
	startedAt := updated.Status.StartedAt.DeepCopy()

	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile running Pod again: %v", err)
	}
	if err := k8sClient.Get(ctx, clientKey(agentRun), &updated); err != nil {
		t.Fatalf("get AgentRun again: %v", err)
	}
	if !updated.Status.StartedAt.Equal(startedAt) {
		t.Fatalf("expected startedAt to remain %s, got %s", startedAt, updated.Status.StartedAt)
	}
}

func TestReconcileSetsFailedWhenPodFails(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	pod := getAgentPod(ctx, t, k8sClient, agentRun)
	pod.Status.Phase = corev1.PodFailed
	if err := k8sClient.Status().Update(ctx, &pod); err != nil {
		t.Fatalf("update Pod status: %v", err)
	}

	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile failed Pod: %v", err)
	}

	var updated nvtv1alpha1.AgentRun
	if err := k8sClient.Get(ctx, clientKey(agentRun), &updated); err != nil {
		t.Fatalf("get AgentRun: %v", err)
	}
	if updated.Status.Phase != nvtv1alpha1.AgentRunPhaseFailed {
		t.Fatalf("expected Failed phase, got %q", updated.Status.Phase)
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
			Image: "nvt-agent-runtime:test",
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

func getSecret(
	ctx context.Context,
	t *testing.T,
	k8sClient client.Reader,
	namespace string,
	name string,
) corev1.Secret {
	t.Helper()

	var secret corev1.Secret
	key := types.NamespacedName{Name: name, Namespace: namespace}
	if err := k8sClient.Get(ctx, key, &secret); err != nil {
		t.Fatalf("get Secret %s/%s: %v", namespace, name, err)
	}
	return secret
}

func getAgentPod(
	ctx context.Context,
	t *testing.T,
	k8sClient client.Reader,
	agentRun *nvtv1alpha1.AgentRun,
) corev1.Pod {
	t.Helper()

	var pod corev1.Pod
	key := types.NamespacedName{Name: AgentPodName(agentRun.Name), Namespace: agentRun.Namespace}
	if err := k8sClient.Get(ctx, key, &pod); err != nil {
		t.Fatalf("get Pod: %v", err)
	}
	return pod
}

func assertTokenSecret(t *testing.T, secret corev1.Secret, agentRun *nvtv1alpha1.AgentRun, tokenKey string) {
	t.Helper()

	assertOwnedByAgentRun(t, secret.GetOwnerReferences(), agentRun)
	if secret.Type != corev1.SecretTypeOpaque {
		t.Fatalf("expected Opaque Secret, got %q", secret.Type)
	}
	expectedLabels := agentRunLabels(agentRun.Name)
	for key, value := range expectedLabels {
		if secret.Labels[key] != value {
			t.Fatalf("expected Secret label %s=%s, got %#v", key, value, secret.Labels)
		}
	}
	token := secret.Data[tokenKey]
	if len(token) < 40 {
		t.Fatalf("expected non-empty high-entropy-looking token at %s, got length %d", tokenKey, len(token))
	}
}

func mustDesiredTokenSecret(
	t *testing.T,
	agentRun *nvtv1alpha1.AgentRun,
	scheme *runtime.Scheme,
	name string,
	key string,
	token []byte,
) *corev1.Secret {
	t.Helper()

	secret, err := DesiredTokenSecret(agentRun, scheme, name, key, token)
	if err != nil {
		t.Fatalf("desired token Secret: %v", err)
	}
	return secret
}

func assertOwnedByAgentRun(t *testing.T, owners []metav1.OwnerReference, agentRun *nvtv1alpha1.AgentRun) {
	t.Helper()

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

func requireContainer(t *testing.T, pod corev1.Pod, name string) corev1.Container {
	t.Helper()

	for _, container := range pod.Spec.Containers {
		if container.Name == name {
			return container
		}
	}
	t.Fatalf("container %q not found in %#v", name, pod.Spec.Containers)
	return corev1.Container{}
}

func requireInitContainer(t *testing.T, pod corev1.Pod, name string) corev1.Container {
	t.Helper()

	for _, container := range pod.Spec.InitContainers {
		if container.Name == name {
			return container
		}
	}
	t.Fatalf("init container %q not found in %#v", name, pod.Spec.InitContainers)
	return corev1.Container{}
}

func envValue(container corev1.Container, name string) string {
	env := findEnvVar(container, name)
	if env == nil {
		return ""
	}
	return env.Value
}

func findEnvVar(container corev1.Container, name string) *corev1.EnvVar {
	for i := range container.Env {
		if container.Env[i].Name == name {
			return &container.Env[i]
		}
	}
	return nil
}

func assertSecretKeyEnv(t *testing.T, container corev1.Container, envName, secretName, key string) {
	t.Helper()

	env := findEnvVar(container, envName)
	if env == nil {
		t.Fatalf("env %q not found in %#v", envName, container.Env)
	}
	if env.Value != "" {
		t.Fatalf("expected env %q to use valueFrom, got literal value %q", envName, env.Value)
	}
	if env.ValueFrom == nil || env.ValueFrom.SecretKeyRef == nil {
		t.Fatalf("expected env %q to use secretKeyRef, got %#v", envName, env.ValueFrom)
	}
	ref := env.ValueFrom.SecretKeyRef
	if ref.Name != secretName || ref.Key != key {
		t.Fatalf("expected env %q to reference %s/%s, got %#v", envName, secretName, key, ref)
	}
}

func assertVolumeMount(t *testing.T, container corev1.Container, name, mountPath, subPath string, readOnly bool) {
	t.Helper()

	for _, mount := range container.VolumeMounts {
		if mount.Name == name {
			if mount.MountPath != mountPath || mount.SubPath != subPath || mount.ReadOnly != readOnly {
				t.Fatalf("unexpected volume mount %q: %#v", name, mount)
			}
			return
		}
	}
	t.Fatalf("volume mount %q not found in %#v", name, container.VolumeMounts)
}

func requireVolume(t *testing.T, pod corev1.Pod, name string) corev1.Volume {
	t.Helper()

	for _, volume := range pod.Spec.Volumes {
		if volume.Name == name {
			return volume
		}
	}
	t.Fatalf("volume %q not found in %#v", name, pod.Spec.Volumes)
	return corev1.Volume{}
}
