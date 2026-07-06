package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/yaml"

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
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
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
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
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
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
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
	if agentContainer.ImagePullPolicy != corev1.PullIfNotPresent {
		t.Fatalf("expected agent imagePullPolicy IfNotPresent, got %q", agentContainer.ImagePullPolicy)
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
	assertNoVolumeMount(t, dindContainer, runtimeAuthSourceName)
	assertNoVolumeMount(t, dindContainer, runtimeAuthHomeName)

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

func TestDesiredAgentPodSeedsRuntimeAuthSecretAtCodexDefaultPath(t *testing.T) {
	scheme := testScheme(t)
	agentRun := testAgentRun()
	agentRun.Spec.RuntimeAuth = &nvtv1alpha1.AgentRunRuntimeAuth{SecretName: "codex-auth"}

	pod, err := DesiredAgentPod(agentRun, scheme)
	if err != nil {
		t.Fatalf("desired AgentRun Pod: %v", err)
	}

	agentContainer := requireContainer(t, *pod, "agent")
	assertVolumeMount(t, agentContainer, runtimeAuthHomeName, "/root/.codex", "", false)
	assertNoVolumeMount(t, agentContainer, runtimeAuthSourceName)

	copyContainer := requireInitContainer(t, *pod, "runtime-auth-copy")
	assertVolumeMount(t, copyContainer, runtimeAuthSourceName, runtimeAuthSourcePath, "", true)
	assertVolumeMount(t, copyContainer, runtimeAuthHomeName, runtimeAuthHomePath, "", false)
	if strings.Join(append(copyContainer.Command, copyContainer.Args...), " ") !=
		"sh -c cp -a /nvt-agent/runtime-auth-source/. /nvt-agent/runtime-auth-home/ && chmod -R u+rwX /nvt-agent/runtime-auth-home" {
		t.Fatalf("unexpected runtime auth copy command/args: command=%#v args=%#v", copyContainer.Command, copyContainer.Args)
	}

	dindContainer := requireInitContainer(t, *pod, "docker")
	assertNoVolumeMount(t, dindContainer, runtimeAuthSourceName)
	assertNoVolumeMount(t, dindContainer, runtimeAuthHomeName)

	runtimeAuthSourceVolume := requireVolume(t, *pod, runtimeAuthSourceName)
	if runtimeAuthSourceVolume.Secret == nil {
		t.Fatalf("expected runtime auth source Secret volume, got %#v", runtimeAuthSourceVolume.VolumeSource)
	}
	if runtimeAuthSourceVolume.Secret.SecretName != "codex-auth" {
		t.Fatalf("expected runtime auth Secret %q, got %q", "codex-auth", runtimeAuthSourceVolume.Secret.SecretName)
	}
	runtimeAuthHomeVolume := requireVolume(t, *pod, runtimeAuthHomeName)
	if runtimeAuthHomeVolume.EmptyDir == nil {
		t.Fatalf("expected runtime auth home emptyDir volume, got %#v", runtimeAuthHomeVolume.VolumeSource)
	}
}

func TestDesiredAgentPodMountsRuntimeAuthSecretAtClaudeDefaultPath(t *testing.T) {
	scheme := testScheme(t)
	agentRun := testAgentRun()
	agentRun.Spec.Runtime.Type = "claude"
	agentRun.Spec.RuntimeAuth = &nvtv1alpha1.AgentRunRuntimeAuth{SecretName: "claude-auth"}

	pod, err := DesiredAgentPod(agentRun, scheme)
	if err != nil {
		t.Fatalf("desired AgentRun Pod: %v", err)
	}

	agentContainer := requireContainer(t, *pod, "agent")
	assertVolumeMount(t, agentContainer, runtimeAuthHomeName, "/root/.claude", "", false)
}

func TestDesiredAgentPodMountsRuntimeAuthHomeAtExplicitPath(t *testing.T) {
	scheme := testScheme(t)
	agentRun := testAgentRun()
	agentRun.Spec.Runtime.Type = "future-runtime"
	agentRun.Spec.RuntimeAuth = &nvtv1alpha1.AgentRunRuntimeAuth{
		SecretName: "future-auth",
		MountPath:  "/var/lib/future-auth",
	}

	pod, err := DesiredAgentPod(agentRun, scheme)
	if err != nil {
		t.Fatalf("desired AgentRun Pod: %v", err)
	}

	agentContainer := requireContainer(t, *pod, "agent")
	assertVolumeMount(t, agentContainer, runtimeAuthHomeName, "/var/lib/future-auth", "", false)
	runtimeAuthSourceVolume := requireVolume(t, *pod, runtimeAuthSourceName)
	if runtimeAuthSourceVolume.Secret == nil || runtimeAuthSourceVolume.Secret.SecretName != "future-auth" {
		t.Fatalf("expected future-auth Secret source volume, got %#v", runtimeAuthSourceVolume.VolumeSource)
	}
	runtimeAuthHomeVolume := requireVolume(t, *pod, runtimeAuthHomeName)
	if runtimeAuthHomeVolume.EmptyDir == nil {
		t.Fatalf("expected runtime auth home emptyDir volume, got %#v", runtimeAuthHomeVolume.VolumeSource)
	}
}

func TestDesiredAgentPodRejectsRuntimeAuthWithoutSecretName(t *testing.T) {
	scheme := testScheme(t)
	agentRun := testAgentRun()
	agentRun.Spec.RuntimeAuth = &nvtv1alpha1.AgentRunRuntimeAuth{}

	_, err := DesiredAgentPod(agentRun, scheme)
	if err == nil {
		t.Fatal("expected missing runtimeAuth secretName to fail")
	}
	if !strings.Contains(err.Error(), "spec.runtimeAuth.secretName is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDesiredAgentPodRejectsRuntimeAuthUnknownRuntimeWithoutMountPath(t *testing.T) {
	scheme := testScheme(t)
	agentRun := testAgentRun()
	agentRun.Spec.Runtime.Type = "future-runtime"
	agentRun.Spec.RuntimeAuth = &nvtv1alpha1.AgentRunRuntimeAuth{SecretName: "future-auth"}

	_, err := DesiredAgentPod(agentRun, scheme)
	if err == nil {
		t.Fatal("expected unknown runtime without runtimeAuth mountPath to fail")
	}
	if !strings.Contains(err.Error(), `spec.runtimeAuth.mountPath is required for runtime type "future-runtime"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDesiredAgentPodRejectsRelativeRuntimeAuthMountPath(t *testing.T) {
	scheme := testScheme(t)
	agentRun := testAgentRun()
	agentRun.Spec.RuntimeAuth = &nvtv1alpha1.AgentRunRuntimeAuth{
		SecretName: "codex-auth",
		MountPath:  "relative/path",
	}

	_, err := DesiredAgentPod(agentRun, scheme)
	if err == nil {
		t.Fatal("expected relative runtimeAuth mountPath to fail")
	}
	if !strings.Contains(err.Error(), `spec.runtimeAuth.mountPath must be an absolute path, got "relative/path"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReconcileCreatesTokenSecrets(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
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

func TestReconcileWritesBrokerAgentsPolicy(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	agentRun.Spec.Broker = &nvtv1alpha1.AgentRunBroker{
		Grants: []nvtv1alpha1.AgentRunBrokerGrant{
			{Provider: "github-main-app", Repositories: []string{"mirkoSekulic/nvt-agent"}},
		},
	}
	brokerSecret := mustDesiredTokenSecret(t, agentRun, scheme, BrokerTokenSecretName(agentRun.Name), brokerTokenKey, []byte("raw-broker-token"))
	callbackSecret := mustDesiredTokenSecret(t, agentRun, scheme, CallbackTokenSecretName(agentRun.Name), callbackTokenKey, []byte("callback-token"))
	brokerAgentsConfigMap := testBrokerAgentsConfigMap(agentRun.Namespace)
	brokerAgentsConfigMap.Data[brokerAgentsConfigKey] = `agents:
- id: kube-system/existing
  token-sha256: ` + validTestTokenHash("existing") + `
  grants:
  - provider: github-main-app
    repositories:
    - mirkoSekulic/other
`
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, brokerSecret, callbackSecret, brokerAgentsConfigMap).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	configMap := getBrokerAgentsConfigMap(ctx, t, k8sClient, agentRun.Namespace)
	if strings.Contains(configMap.Data[brokerAgentsConfigKey], "raw-broker-token") {
		t.Fatalf("raw token leaked into broker agents policy:\n%s", configMap.Data[brokerAgentsConfigKey])
	}
	policy := mustParseBrokerAgentsPolicy(t, configMap.Data[brokerAgentsConfigKey])
	if len(policy.Agents) != 2 {
		t.Fatalf("expected two broker agent entries, got %#v", policy.Agents)
	}
	if policy.Agents[0].ID != AgentRunBrokerID(agentRun.Namespace, agentRun.Name) ||
		policy.Agents[1].ID != "kube-system/existing" {
		t.Fatalf("expected deterministic id order with existing entry preserved, got %#v", policy.Agents)
	}
	entry := policy.Agents[0]
	if entry.TokenSHA256 != expectedSHA256TokenHash("raw-broker-token") {
		t.Fatalf("expected token hash %q, got %q", expectedSHA256TokenHash("raw-broker-token"), entry.TokenSHA256)
	}
	if len(entry.Grants) != 1 ||
		entry.Grants[0].Provider != "github-main-app" ||
		entry.Grants[0].Materialization != "file-bundle" ||
		len(entry.Grants[0].Repositories) != 1 ||
		entry.Grants[0].Repositories[0] != "mirkoSekulic/nvt-agent" {
		t.Fatalf("unexpected grants: %#v", entry.Grants)
	}
}

func TestDirectAgentRunPodDoesNotRenderMediatedSidecar(t *testing.T) {
	agentRun := testAgentRun()
	pod, err := DesiredAgentPod(agentRun, testScheme(t))
	if err != nil {
		t.Fatalf("desired pod: %v", err)
	}
	if len(pod.Spec.Containers) != 1 {
		t.Fatalf("direct mode must render only the agent container, got %#v", pod.Spec.Containers)
	}
	agent := requireContainer(t, *pod, "agent")
	if findEnvVar(agent, "NVT_EGRESS_MODE") != nil || findEnvVar(agent, egressTokenKey) != nil {
		t.Fatalf("direct agent container has mediated env: %#v", agent.Env)
	}
	if _, found := findContainer(pod.Spec.Containers, "egressd"); found {
		t.Fatalf("direct mode rendered egressd sidecar: %#v", pod.Spec.Containers)
	}
}

func TestMediatedAgentRunRendersEgressdWithoutEgressTokenInAgent(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	agentRun.Spec.EgressAllowInsecureBroker = true
	agentRun.Spec.Broker = &nvtv1alpha1.AgentRunBroker{
		Grants: []nvtv1alpha1.AgentRunBrokerGrant{
			{Provider: "api-main", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject, Repositories: []string{}, EgressHosts: []string{"api.example.test:443"}},
		},
	}
	pod, err := DesiredAgentPod(agentRun, testScheme(t))
	if err != nil {
		t.Fatalf("desired pod: %v", err)
	}
	agent := requireContainer(t, *pod, "agent")
	if findEnvVar(agent, egressTokenKey) != nil {
		t.Fatalf("agent container must not receive egress broker token: %#v", agent.Env)
	}
	if envValue(agent, "NVT_EGRESS_MODE") != "mediated" {
		t.Fatalf("expected mediated env on agent, got %#v", agent.Env)
	}
	egressd := requireContainer(t, *pod, "egressd")
	if egressd.Image != defaultEgressdImage {
		t.Fatalf("unexpected egressd image %q", egressd.Image)
	}
	assertSecretKeyEnv(t, egressd, "NVT_BROKER_TOKEN", EgressTokenSecretName(agentRun.Name), egressTokenKey)
	assertVolumeMount(t, egressd, "egressd-config", egressdConfigPath, egressdConfigKey, true)
}

func TestReconcileWritesMediatedBrokerAgentsPolicy(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	agentRun.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	agentRun.Spec.EgressAllowInsecureBroker = true
	agentRun.Spec.Broker = &nvtv1alpha1.AgentRunBroker{
		Grants: []nvtv1alpha1.AgentRunBrokerGrant{
			{Provider: "api-main", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject, Repositories: []string{}, EgressHosts: []string{"api.example.test:443"}},
		},
	}
	brokerSecret := mustDesiredTokenSecret(t, agentRun, scheme, BrokerTokenSecretName(agentRun.Name), brokerTokenKey, []byte("agent-token"))
	egressSecret := mustDesiredTokenSecret(t, agentRun, scheme, EgressTokenSecretName(agentRun.Name), egressTokenKey, []byte("egress-token"))
	callbackSecret := mustDesiredTokenSecret(t, agentRun, scheme, CallbackTokenSecretName(agentRun.Name), callbackTokenKey, []byte("callback-token"))
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, brokerSecret, egressSecret, callbackSecret, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	policy := mustParseBrokerAgentsPolicy(t, getBrokerAgentsConfigMap(ctx, t, k8sClient, agentRun.Namespace).Data[brokerAgentsConfigKey])
	agentEntry := requireBrokerAgentEntry(t, policy, AgentRunBrokerID(agentRun.Namespace, agentRun.Name))
	egressEntry := requireBrokerAgentEntry(t, policy, AgentRunEgressBrokerID(agentRun.Namespace, agentRun.Name))
	if agentEntry.Role != "" || len(agentEntry.Grants) != 1 || agentEntry.Grants[0].Materialization != "header-inject" {
		t.Fatalf("unexpected mediated agent entry: %#v", agentEntry)
	}
	if len(agentEntry.Grants[0].EgressHosts) != 1 || agentEntry.Grants[0].EgressHosts[0] != "api.example.test:443" {
		t.Fatalf("unexpected mediated egress hosts: %#v", agentEntry.Grants[0])
	}
	if egressEntry.Role != "egress" || egressEntry.PairedAgent != agentEntry.ID || len(egressEntry.Grants) != 0 {
		t.Fatalf("unexpected egress entry: %#v", egressEntry)
	}
}

func TestValidateAgentRunEgressModeRejectsMismatches(t *testing.T) {
	direct := testAgentRun()
	direct.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "api-main", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject, Repositories: []string{},
	}}}
	if err := ValidateAgentRunEgressMode(direct); err == nil || !strings.Contains(err.Error(), "api-main") {
		t.Fatalf("expected direct/header-inject mismatch naming provider, got %v", err)
	}

	mediated := testAgentRun()
	mediated.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	mediated.Spec.EgressAllowInsecureBroker = true
	mediated.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "bundle-main", Repositories: []string{},
	}}}
	if err := ValidateAgentRunEgressMode(mediated); err == nil || !strings.Contains(err.Error(), "bundle-main") {
		t.Fatalf("expected mediated/file-bundle mismatch naming provider, got %v", err)
	}
}

func TestValidateAgentRunEgressModeRejectsMediatedRuntimeAuth(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	agentRun.Spec.EgressAllowInsecureBroker = true
	agentRun.Spec.RuntimeAuth = &nvtv1alpha1.AgentRunRuntimeAuth{SecretName: "codex-auth"}
	agentRun.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "api-main", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject, EgressHosts: []string{"api.example.test:443"},
	}}}

	err := ValidateAgentRunEgressMode(agentRun)
	if err == nil || !strings.Contains(err.Error(), "runtimeAuth") {
		t.Fatalf("expected mediated runtimeAuth rejection, got %v", err)
	}
}

func TestValidateAgentRunEgressModeRejectsMissingRouteAndMultipleGrants(t *testing.T) {
	missingRoute := testAgentRun()
	missingRoute.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	missingRoute.Spec.EgressAllowInsecureBroker = true
	missingRoute.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "api-main", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject,
	}}}
	if err := ValidateAgentRunEgressMode(missingRoute); err == nil || !strings.Contains(err.Error(), "egressHosts") {
		t.Fatalf("expected missing egressHosts rejection, got %v", err)
	}

	// Phase 4 lifts the exactly-one-grant limit: a realistic mediated run
	// carries an LLM grant and a git grant, each with its own route.
	multiple := testAgentRun()
	multiple.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	multiple.Spec.EgressAllowInsecureBroker = true
	multiple.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{
		{Provider: "api-main", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject, EgressHosts: []string{"api.example.test:443"}},
		{Provider: "git-app", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject, EgressHosts: []string{"github.com:443"}, Git: true},
	}}
	if err := ValidateAgentRunEgressMode(multiple); err != nil {
		t.Fatalf("multiple header-inject grants must be accepted, got %v", err)
	}

	unsafeLocal := testAgentRun()
	unsafeLocal.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	unsafeLocal.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "api-main", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject, EgressHosts: []string{"api.example.test:443"},
	}}}
	if err := ValidateAgentRunEgressMode(unsafeLocal); err == nil || !strings.Contains(err.Error(), "egressAllowInsecureBroker") {
		t.Fatalf("expected unsafe local broker rejection, got %v", err)
	}
}

func TestRenderEgressdConfigUsesConfiguredRouteHost(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	agentRun.Spec.EgressAllowInsecureBroker = true
	agentRun.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "api-main", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject, EgressHosts: []string{"api.example.test:443"},
	}}}

	rendered, err := RenderEgressdConfigJSON(agentRun)
	if err != nil {
		t.Fatalf("render egressd config: %v", err)
	}
	if !strings.Contains(rendered, `"upstream": "api.example.test:443"`) || strings.Contains(rendered, "placeholder.local") {
		t.Fatalf("unexpected egressd config:\n%s", rendered)
	}
	if !strings.Contains(rendered, `"allow_insecure_broker": true`) {
		t.Fatalf("expected explicit local insecure broker flag:\n%s", rendered)
	}
	if strings.Contains(rendered, `"listen_tls"`) || strings.Contains(rendered, `"ca"`) {
		t.Fatalf("non-git route must not render TLS or CA config:\n%s", rendered)
	}
}

func multiGrantMediatedAgentRun() *nvtv1alpha1.AgentRun {
	agentRun := testAgentRun()
	agentRun.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	agentRun.Spec.EgressAllowInsecureBroker = true
	agentRun.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{
		{Provider: "api-main", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject, Repositories: []string{}, EgressHosts: []string{"api.example.test:443"}},
		{
			Provider:        "git-app",
			Materialization: nvtv1alpha1.AgentRunGrantHeaderInject,
			Repositories:    []string{"my-user/my-repo"},
			EgressHosts:     []string{"github.com:443"},
			Git:             true,
			Permissions:     map[string]string{"contents": "write"},
		},
	}}
	return agentRun
}

func TestValidateAgentRunEgressModeRejectsInvalidGitAndPermissions(t *testing.T) {
	gitBundle := testAgentRun()
	gitBundle.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "git-app", Repositories: []string{}, Git: true,
	}}}
	if err := ValidateAgentRunEgressMode(gitBundle); err == nil || !strings.Contains(err.Error(), "git requires materialization header-inject") {
		t.Fatalf("expected git/file-bundle rejection, got %v", err)
	}

	badPermission := testAgentRun()
	badPermission.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	badPermission.Spec.EgressAllowInsecureBroker = true
	badPermission.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "git-app", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject, Repositories: []string{},
		EgressHosts: []string{"github.com:443"}, Git: true, Permissions: map[string]string{"contents": "admin"},
	}}}
	if err := ValidateAgentRunEgressMode(badPermission); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("expected invalid permission rejection, got %v", err)
	}
}

func TestRenderEgressdConfigMultiGrantRendersGitTLSRoute(t *testing.T) {
	rendered, err := RenderEgressdConfigJSON(multiGrantMediatedAgentRun())
	if err != nil {
		t.Fatalf("render egressd config: %v", err)
	}
	var config struct {
		Routes []map[string]any `json:"routes"`
		CA     map[string]any   `json:"ca"`
	}
	if err := json.Unmarshal([]byte(rendered), &config); err != nil {
		t.Fatalf("parse rendered config: %v\n%s", err, rendered)
	}
	if len(config.Routes) != 2 {
		t.Fatalf("expected one route per header-inject grant, got:\n%s", rendered)
	}
	api, git := config.Routes[0], config.Routes[1]
	if api["listen"] != "127.0.0.1:8471" || api["capability"] != "api-main" || api["listen_tls"] != nil {
		t.Fatalf("unexpected api route: %v", api)
	}
	if git["listen"] != "127.0.0.1:8472" || git["capability"] != "git-app" || git["upstream"] != "github.com:443" {
		t.Fatalf("unexpected git route: %v", git)
	}
	if git["listen_tls"] != "ca" {
		t.Fatalf("git route must terminate TLS under the CA: %v", git)
	}
	if config.CA["publish_dir"] != egressCAMountPath {
		t.Fatalf("expected CA publish dir %s, got %v", egressCAMountPath, config.CA)
	}
}

func TestRenderAgentConfigGitGrantGetsHTTPSBaseURL(t *testing.T) {
	rendered, err := RenderAgentConfigYAML(multiGrantMediatedAgentRun())
	if err != nil {
		t.Fatalf("render agent config: %v", err)
	}
	if !strings.Contains(rendered, "base-url: http://127.0.0.1:8471") {
		t.Fatalf("api grant must keep plain-HTTP base URL:\n%s", rendered)
	}
	if !strings.Contains(rendered, "base-url: https://127.0.0.1:8472") {
		t.Fatalf("git grant must get an https base URL:\n%s", rendered)
	}
}

func TestDesiredAgentPodMountsEgressCAForGitGrant(t *testing.T) {
	pod, err := DesiredAgentPod(multiGrantMediatedAgentRun(), testScheme(t))
	if err != nil {
		t.Fatalf("desired pod: %v", err)
	}
	var caVolume *corev1.Volume
	for index := range pod.Spec.Volumes {
		if pod.Spec.Volumes[index].Name == egressCAVolumeName {
			caVolume = &pod.Spec.Volumes[index]
		}
	}
	if caVolume == nil || caVolume.EmptyDir == nil {
		t.Fatalf("expected emptyDir CA volume, got %#v", pod.Spec.Volumes)
	}

	agent := requireContainer(t, *pod, "agent")
	var agentMount *corev1.VolumeMount
	for index := range agent.VolumeMounts {
		if agent.VolumeMounts[index].Name == egressCAVolumeName {
			agentMount = &agent.VolumeMounts[index]
		}
	}
	if agentMount == nil || !agentMount.ReadOnly || agentMount.MountPath != egressCAMountPath {
		t.Fatalf("agent CA mount must be read-only at %s, got %#v", egressCAMountPath, agent.VolumeMounts)
	}
	if envValue(agent, "NVT_EGRESS_CA_FILE") != egressCAFilePath {
		t.Fatalf("agent env missing NVT_EGRESS_CA_FILE: %#v", agent.Env)
	}

	egressd := requireContainer(t, *pod, "egressd")
	var egressdMount *corev1.VolumeMount
	for index := range egressd.VolumeMounts {
		if egressd.VolumeMounts[index].Name == egressCAVolumeName {
			egressdMount = &egressd.VolumeMounts[index]
		}
	}
	if egressdMount == nil || egressdMount.ReadOnly || egressdMount.MountPath != egressCAMountPath {
		t.Fatalf("egressd CA mount must be writable at %s, got %#v", egressCAMountPath, egressd.VolumeMounts)
	}
}

func TestDesiredAgentPodWithoutGitGrantHasNoCAVolume(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	agentRun.Spec.EgressAllowInsecureBroker = true
	agentRun.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "api-main", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject, Repositories: []string{}, EgressHosts: []string{"api.example.test:443"},
	}}}
	pod, err := DesiredAgentPod(agentRun, testScheme(t))
	if err != nil {
		t.Fatalf("desired pod: %v", err)
	}
	for _, volume := range pod.Spec.Volumes {
		if volume.Name == egressCAVolumeName {
			t.Fatalf("non-git mediated run must not mount a CA volume: %#v", pod.Spec.Volumes)
		}
	}
	agent := requireContainer(t, *pod, "agent")
	if findEnvVar(agent, "NVT_EGRESS_CA_FILE") != nil {
		t.Fatalf("non-git agent must not carry NVT_EGRESS_CA_FILE: %#v", agent.Env)
	}
}

func TestReconcileRejectsEgressMismatchBeforePodAndSecrets(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	agentRun.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	agentRun.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "bundle-main", Repositories: []string{},
	}}}
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	assertAgentPodMissing(ctx, t, k8sClient, agentRun)
	assertAgentRunPhase(ctx, t, k8sClient, agentRun, nvtv1alpha1.AgentRunPhaseFailed)
	var brokerSecret corev1.Secret
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: BrokerTokenSecretName(agentRun.Name)}, &brokerSecret); !errors.IsNotFound(err) {
		t.Fatalf("expected no broker token Secret, got %v", err)
	}
}

func TestReconcileRejectsMediatedRuntimeAuthBeforePodAndSecrets(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	agentRun.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	agentRun.Spec.EgressAllowInsecureBroker = true
	agentRun.Spec.RuntimeAuth = &nvtv1alpha1.AgentRunRuntimeAuth{SecretName: "codex-auth"}
	agentRun.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "api-main", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject, EgressHosts: []string{"api.example.test:443"},
	}}}
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	assertAgentPodMissing(ctx, t, k8sClient, agentRun)
	assertAgentRunPhase(ctx, t, k8sClient, agentRun, nvtv1alpha1.AgentRunPhaseFailed)
	for _, name := range []string{BrokerTokenSecretName(agentRun.Name), EgressTokenSecretName(agentRun.Name), AgentConfigMapName(agentRun.Name), EgressdConfigMapName(agentRun.Name)} {
		var secret corev1.Secret
		if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: name}, &secret); err == nil {
			t.Fatalf("expected no Secret side effect %s", name)
		}
		var configMap corev1.ConfigMap
		if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: name}, &configMap); err == nil {
			t.Fatalf("expected no ConfigMap side effect %s", name)
		}
	}
}

func TestReconcileUpdatesBrokerAgentsPolicyGrants(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	agentRun.Spec.Broker = &nvtv1alpha1.AgentRunBroker{
		Grants: []nvtv1alpha1.AgentRunBrokerGrant{
			{Provider: "github-main-app", Repositories: []string{"mirkoSekulic/nvt-agent"}},
		},
	}
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
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
	updatedAgentRun.Spec.Broker.Grants = []nvtv1alpha1.AgentRunBrokerGrant{
		{Provider: "github-main-app", Repositories: []string{"mirkoSekulic/nvt-agent", "mirkoSekulic/nvt-runtime"}},
	}
	if err := k8sClient.Update(ctx, &updatedAgentRun); err != nil {
		t.Fatalf("update AgentRun grants: %v", err)
	}

	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile updated grants: %v", err)
	}

	policy := mustParseBrokerAgentsPolicy(t, getBrokerAgentsConfigMap(ctx, t, k8sClient, agentRun.Namespace).Data[brokerAgentsConfigKey])
	entry := requireBrokerAgentEntry(t, policy, AgentRunBrokerID(agentRun.Namespace, agentRun.Name))
	if len(entry.Grants) != 1 || len(entry.Grants[0].Repositories) != 2 {
		t.Fatalf("expected updated repositories, got %#v", entry.Grants)
	}
	if entry.Grants[0].Repositories[1] != "mirkoSekulic/nvt-runtime" {
		t.Fatalf("expected updated grant repositories, got %#v", entry.Grants[0].Repositories)
	}
}

func TestReconcileRejectsDuplicateBrokerTokenHash(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	brokerSecret := mustDesiredTokenSecret(t, agentRun, scheme, BrokerTokenSecretName(agentRun.Name), brokerTokenKey, []byte("shared-token"))
	callbackSecret := mustDesiredTokenSecret(t, agentRun, scheme, CallbackTokenSecretName(agentRun.Name), callbackTokenKey, []byte("callback-token"))
	brokerAgentsConfigMap := testBrokerAgentsConfigMap(agentRun.Namespace)
	brokerAgentsConfigMap.Data[brokerAgentsConfigKey] = `agents:
- id: default/other
  token-sha256: ` + expectedSHA256TokenHash("shared-token") + `
  grants: []
`
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, brokerSecret, callbackSecret, brokerAgentsConfigMap).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err == nil {
		t.Fatal("expected duplicate token hash to fail")
	}
	if !strings.Contains(err.Error(), "duplicate token hash") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpsertBrokerAgentRemovesDuplicateExistingID(t *testing.T) {
	policy := brokerAgentsPolicy{
		Agents: []brokerAgentEntry{
			{ID: "default/example", TokenSHA256: validTestTokenHash("old-a"), Grants: []brokerAgentGrantEntry{}},
			{ID: "default/other", TokenSHA256: validTestTokenHash("other"), Grants: []brokerAgentGrantEntry{}},
			{ID: "default/example", TokenSHA256: validTestTokenHash("old-b"), Grants: []brokerAgentGrantEntry{}},
		},
	}

	updated := UpsertBrokerAgent(policy, brokerAgentEntry{
		ID:          "default/example",
		TokenSHA256: validTestTokenHash("new"),
		Grants:      []brokerAgentGrantEntry{},
	})

	if len(updated.Agents) != 2 {
		t.Fatalf("expected duplicate id entries to be collapsed, got %#v", updated.Agents)
	}
	entry := requireBrokerAgentEntry(t, updated, "default/example")
	if entry.TokenSHA256 != validTestTokenHash("new") {
		t.Fatalf("expected replacement token hash, got %#v", entry)
	}
}

func TestReconcileRejectsMalformedBrokerAgentsPolicy(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	brokerAgentsConfigMap := testBrokerAgentsConfigMap(agentRun.Namespace)
	brokerAgentsConfigMap.Data[brokerAgentsConfigKey] = "agents: ["
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, brokerAgentsConfigMap).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err == nil {
		t.Fatal("expected malformed broker agents policy to fail")
	}
	if !strings.Contains(err.Error(), "parse broker agents ConfigMap") {
		t.Fatalf("expected parse error context, got %v", err)
	}
}

func TestReconcileRejectsBrokerIncompatibleAgentsPolicy(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	brokerAgentsConfigMap := testBrokerAgentsConfigMap(agentRun.Namespace)
	brokerAgentsConfigMap.Data[brokerAgentsConfigKey] = `agents:
- id: default/other
  token-sha256: sha256:not-valid
  grants: []
`
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, brokerAgentsConfigMap).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err == nil {
		t.Fatal("expected broker-incompatible agents policy to fail")
	}
	if !strings.Contains(err.Error(), "token-sha256 must be sha256:<hex>") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReconcileRequiresBrokerAgentsConfigMap(t *testing.T) {
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
	if err == nil {
		t.Fatal("expected missing broker agents ConfigMap to fail")
	}
	if !strings.Contains(err.Error(), "broker agents ConfigMap default/nvt-broker-agents is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReconcileAddsAgentRunFinalizer(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
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
	if !controllerutil.ContainsFinalizer(&updated, agentRunFinalizer) {
		t.Fatalf("expected finalizer %q, got %#v", agentRunFinalizer, updated.Finalizers)
	}
}

func TestFinalizeRemovesBrokerAgentsPolicyEntry(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	agentRun.Finalizers = []string{agentRunFinalizer}
	brokerAgentsConfigMap := testBrokerAgentsConfigMap(agentRun.Namespace)
	brokerAgentsConfigMap.Data[brokerAgentsConfigKey] = `agents:
- id: default/example
  token-sha256: ` + validTestTokenHash("example") + `
  grants: []
- id: default/other
  token-sha256: ` + validTestTokenHash("other") + `
  grants: []
`
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, brokerAgentsConfigMap).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	if err := reconciler.finalizeAgentRun(ctx, agentRun); err != nil {
		t.Fatalf("finalize AgentRun: %v", err)
	}

	configMap := getBrokerAgentsConfigMap(ctx, t, k8sClient, agentRun.Namespace)
	policy := mustParseBrokerAgentsPolicy(t, configMap.Data[brokerAgentsConfigKey])
	if len(policy.Agents) != 1 || policy.Agents[0].ID != "default/other" {
		t.Fatalf("expected only unrelated broker agent entry to remain, got %#v", policy.Agents)
	}
	if controllerutil.ContainsFinalizer(agentRun, agentRunFinalizer) {
		t.Fatalf("expected finalizer to be removed, got %#v", agentRun.Finalizers)
	}
}

func TestReconcileDeletionRemovesBrokerPolicyEntryAndFinalizer(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	now := metav1.Now()
	agentRun := testAgentRun()
	agentRun.Finalizers = []string{agentRunFinalizer}
	agentRun.DeletionTimestamp = &now
	brokerAgentsConfigMap := testBrokerAgentsConfigMap(agentRun.Namespace)
	brokerAgentsConfigMap.Data[brokerAgentsConfigKey] = `agents:
- id: default/example
  token-sha256: ` + validTestTokenHash("example") + `
  grants: []
- id: default/other
  token-sha256: ` + validTestTokenHash("other") + `
  grants: []
`
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, brokerAgentsConfigMap).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile deleting AgentRun: %v", err)
	}

	var updated nvtv1alpha1.AgentRun
	if err := k8sClient.Get(ctx, clientKey(agentRun), &updated); err == nil {
		if controllerutil.ContainsFinalizer(&updated, agentRunFinalizer) {
			t.Fatalf("expected persisted finalizer to be removed, got %#v", updated.Finalizers)
		}
	} else if !errors.IsNotFound(err) {
		t.Fatalf("get AgentRun: %v", err)
	}
	policy := mustParseBrokerAgentsPolicy(t, getBrokerAgentsConfigMap(ctx, t, k8sClient, agentRun.Namespace).Data[brokerAgentsConfigKey])
	if len(policy.Agents) != 1 || policy.Agents[0].ID != "default/other" {
		t.Fatalf("expected only unrelated broker agent entry to remain, got %#v", policy.Agents)
	}
}

func TestFinalizeIgnoresMissingBrokerAgentsConfigMap(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	agentRun.Finalizers = []string{agentRunFinalizer}
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	if err := reconciler.finalizeAgentRun(ctx, agentRun); err != nil {
		t.Fatalf("finalize with missing broker agents ConfigMap: %v", err)
	}
	if controllerutil.ContainsFinalizer(agentRun, agentRunFinalizer) {
		t.Fatalf("expected finalizer to be removed, got %#v", agentRun.Finalizers)
	}
}

func TestRenderBrokerAgentsYAMLIsDeterministic(t *testing.T) {
	policy := brokerAgentsPolicy{
		Agents: []brokerAgentEntry{
			{ID: "z/run", TokenSHA256: validTestTokenHash("z"), Grants: nil},
			{
				ID:          "a/run",
				TokenSHA256: validTestTokenHash("a"),
				Grants: []brokerAgentGrantEntry{
					{Provider: "github-z", Repositories: nil},
					{Provider: "github-a", Repositories: []string{"repo-b"}},
				},
			},
		},
	}

	rendered, err := RenderBrokerAgentsYAML(policy)
	if err != nil {
		t.Fatalf("render broker agents YAML: %v", err)
	}
	expected := `agents:
- grants:
  - materialization: file-bundle
    provider: github-a
    repositories:
    - repo-b
  - materialization: file-bundle
    provider: github-z
    repositories: []
  id: a/run
  token-sha256: ` + validTestTokenHash("a") + `
- grants: []
  id: z/run
  token-sha256: ` + validTestTokenHash("z") + `
`
	if rendered != expected {
		t.Fatalf("unexpected rendered policy:\n%s", rendered)
	}
}

func TestAgentRunsForBrokerAgentsConfigMap(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	first := testAgentRun()
	first.Name = "b-run"
	second := testAgentRun()
	second.Name = "a-run"
	otherNamespace := testAgentRun()
	otherNamespace.Name = "other"
	otherNamespace.Namespace = "other"
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(first, second, otherNamespace).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	requests := reconciler.agentRunsForBrokerAgentsConfigMap(ctx, testBrokerAgentsConfigMap("default"))

	if len(requests) != 2 {
		t.Fatalf("expected two requests, got %#v", requests)
	}
	if requests[0].Name != "a-run" || requests[1].Name != "b-run" {
		t.Fatalf("expected deterministic namespace-local requests, got %#v", requests)
	}
}

func TestReconcileCreatesOwnedAgentConfigMap(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
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
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
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
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
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
		WithObjects(agentRun, pod, testBrokerAgentsConfigMap(agentRun.Namespace)).
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
		WithObjects(agentRun, brokerSecret, callbackSecret, testBrokerAgentsConfigMap(agentRun.Namespace)).
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
		WithObjects(agentRun, brokerSecret, callbackSecret, testBrokerAgentsConfigMap(agentRun.Namespace)).
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

func TestRenderAgentConfigYAMLInjectsInitialPromptPlugin(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Spec.Prompt = &nvtv1alpha1.AgentRunPrompt{Text: "Start this run.\nThen report back."}

	rendered, err := RenderAgentConfigYAML(agentRun)
	if err != nil {
		t.Fatalf("render AgentRun agent config: %v", err)
	}

	config := parseAgentConfigYAML(t, rendered)
	plugins, ok := config["plugins"].([]any)
	if !ok || len(plugins) != 2 {
		t.Fatalf("expected two plugins, got %#v\n%s", config["plugins"], rendered)
	}
	plugin, ok := plugins[0].(map[string]any)
	if !ok {
		t.Fatalf("expected injected plugin object, got %#v", plugins[0])
	}
	if plugin["name"] != "initial-prompt" ||
		plugin["source"] != "builtin" ||
		plugin["when"] != "after-agent" ||
		plugin["restart"] != "never" {
		t.Fatalf("unexpected injected plugin: %#v", plugin)
	}
	configValue, ok := plugin["config"].(map[string]any)
	if !ok || configValue["text"] != agentRun.Spec.Prompt.Text {
		t.Fatalf("unexpected injected config: %#v", plugin["config"])
	}
	existingPlugin, ok := plugins[1].(map[string]any)
	if !ok || existingPlugin["name"] != "checkout-repos" {
		t.Fatalf("expected existing plugin after injected plugin, got %#v", plugins[1])
	}
}

func TestRenderAgentConfigYAMLInjectsInitialPromptPluginWhenPluginsMissing(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Spec.Agent.Config = apiextensionsv1.JSON{Raw: []byte(`{"codeServer": {"enabled": true}}`)}
	agentRun.Spec.Prompt = &nvtv1alpha1.AgentRunPrompt{Text: "Run without configured plugins."}

	rendered, err := RenderAgentConfigYAML(agentRun)
	if err != nil {
		t.Fatalf("render AgentRun agent config: %v", err)
	}

	config := parseAgentConfigYAML(t, rendered)
	plugins, ok := config["plugins"].([]any)
	if !ok || len(plugins) != 1 {
		t.Fatalf("expected injected plugin list, got %#v\n%s", config["plugins"], rendered)
	}
	if config["codeServer"] == nil {
		t.Fatalf("expected existing config keys to be preserved, got %#v", config)
	}
}

func TestRenderAgentConfigYAMLNoPromptRendersUnchanged(t *testing.T) {
	agentRun := testAgentRun()

	rendered, err := RenderAgentConfigYAML(agentRun)
	if err != nil {
		t.Fatalf("render AgentRun agent config: %v", err)
	}

	if strings.Contains(rendered, "initial-prompt") {
		t.Fatalf("expected no injected plugin, got:\n%s", rendered)
	}
}

func TestRenderAgentConfigYAMLEmptyPromptRendersUnchanged(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Spec.Prompt = &nvtv1alpha1.AgentRunPrompt{Text: ""}

	rendered, err := RenderAgentConfigYAML(agentRun)
	if err != nil {
		t.Fatalf("render AgentRun agent config: %v", err)
	}

	if strings.Contains(rendered, "initial-prompt") {
		t.Fatalf("expected no injected plugin, got:\n%s", rendered)
	}
}

func TestRenderAgentConfigYAMLRejectsInitialPromptPluginConflict(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Spec.Agent.Config = apiextensionsv1.JSON{Raw: []byte(`{
		"plugins": [
			{
				"name": "initial-prompt",
				"source": "builtin"
			}
		]
	}`)}
	agentRun.Spec.Prompt = &nvtv1alpha1.AgentRunPrompt{Text: "ambiguous"}

	_, err := RenderAgentConfigYAML(agentRun)
	if err == nil {
		t.Fatal("expected initial-prompt conflict to fail")
	}
	if !strings.Contains(err.Error(), `already contains plugin "initial-prompt"`) {
		t.Fatalf("expected clear conflict error, got %v", err)
	}
}

func TestAgentRunCRDSchemaIncludesPromptText(t *testing.T) {
	data, err := os.ReadFile("../../config/crd/bases/nvt.dev_agentruns.yaml")
	if err != nil {
		t.Fatalf("read AgentRun CRD: %v", err)
	}
	var crd map[string]any
	if err := yaml.Unmarshal(data, &crd); err != nil {
		t.Fatalf("parse AgentRun CRD: %v", err)
	}

	prompt, ok := crdPath(t, crd,
		"spec", "versions", 0, "schema", "openAPIV3Schema", "properties",
		"spec", "properties", "prompt",
	).(map[string]any)
	if !ok {
		t.Fatalf("expected spec.prompt schema object, got %#v", prompt)
	}
	textType := crdPath(t, prompt, "properties", "text", "type")
	if textType != "string" {
		t.Fatalf("expected spec.prompt.text string schema, got %#v", textType)
	}
}

func TestAgentRunCRDSchemaIncludesRuntimeAuthSecretName(t *testing.T) {
	data, err := os.ReadFile("../../config/crd/bases/nvt.dev_agentruns.yaml")
	if err != nil {
		t.Fatalf("read AgentRun CRD: %v", err)
	}
	var crd map[string]any
	if err := yaml.Unmarshal(data, &crd); err != nil {
		t.Fatalf("parse AgentRun CRD: %v", err)
	}

	runtimeAuth, ok := crdPath(t, crd,
		"spec", "versions", 0, "schema", "openAPIV3Schema", "properties",
		"spec", "properties", "runtimeAuth",
	).(map[string]any)
	if !ok {
		t.Fatalf("expected spec.runtimeAuth schema object, got %#v", runtimeAuth)
	}
	required, ok := runtimeAuth["required"].([]any)
	if !ok || len(required) != 1 || required[0] != "secretName" {
		t.Fatalf("expected runtimeAuth.secretName to be required, got %#v", runtimeAuth["required"])
	}
	secretNameType := crdPath(t, runtimeAuth, "properties", "secretName", "type")
	if secretNameType != "string" {
		t.Fatalf("expected spec.runtimeAuth.secretName string schema, got %#v", secretNameType)
	}
	mountPathType := crdPath(t, runtimeAuth, "properties", "mountPath", "type")
	if mountPathType != "string" {
		t.Fatalf("expected spec.runtimeAuth.mountPath string schema, got %#v", mountPathType)
	}
}

func TestReconcileSetsPodNameAfterPodExists(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
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

func TestAgentRunCRDSchemaIncludesEgressAndMaterialization(t *testing.T) {
	data, err := os.ReadFile("../../config/crd/bases/nvt.dev_agentruns.yaml")
	if err != nil {
		t.Fatalf("read AgentRun CRD: %v", err)
	}
	var crd map[string]any
	if err := yaml.Unmarshal(data, &crd); err != nil {
		t.Fatalf("parse AgentRun CRD: %v", err)
	}
	spec := crdPath(t, crd,
		"spec", "versions", 0, "schema", "openAPIV3Schema",
		"properties", "spec", "properties").(map[string]any)
	if crdPath(t, spec, "egress", "default") != "direct" {
		t.Fatalf("expected egress default direct, got %#v", crdPath(t, spec, "egress"))
	}
	if crdPath(t, spec, "egressAllowInsecureBroker", "default") != false {
		t.Fatalf("expected egressAllowInsecureBroker default false, got %#v", crdPath(t, spec, "egressAllowInsecureBroker"))
	}
	materialization := crdPath(t, spec, "broker", "properties", "grants", "items", "properties", "materialization").(map[string]any)
	if materialization["default"] != "file-bundle" {
		t.Fatalf("expected materialization default file-bundle, got %#v", materialization)
	}
	egressHosts := crdPath(t, spec, "broker", "properties", "grants", "items", "properties", "egressHosts").(map[string]any)
	if egressHosts["type"] != "array" {
		t.Fatalf("expected egressHosts array schema, got %#v", egressHosts)
	}
}

func TestReconcileSetsRunningAndStartedAtWhenPodRuns(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
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
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	scheme := testScheme(t)
	agentRun := testAgentRun()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{
		Client: k8sClient,
		Scheme: scheme,
		Now:    func() metav1.Time { return now },
	}

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
	if updated.Status.FinishedAt == nil || !updated.Status.FinishedAt.Equal(&now) {
		t.Fatalf("expected finishedAt %s, got %#v", now, updated.Status.FinishedAt)
	}
	if updated.Status.Reason != "Pod failed" {
		t.Fatalf("expected Pod failed reason, got %q", updated.Status.Reason)
	}
}

func TestSyncAgentRunStatusFromPodDoesNotDowngradeCompleted(t *testing.T) {
	finishedAt := metav1.Now()
	agentRun := testAgentRun()
	agentRun.Status.Phase = nvtv1alpha1.AgentRunPhaseCompleted
	agentRun.Status.FinishedAt = &finishedAt
	agentRun.Status.Reason = "Completed by lifecycle event plugin.agent.signal.done"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: AgentPodName(agentRun.Name)},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}

	changed := SyncAgentRunStatusFromPod(agentRun, pod, metav1.Now())

	if !changed {
		t.Fatal("expected podName sync to be recorded")
	}
	if agentRun.Status.PodName != pod.Name {
		t.Fatalf("expected podName %q, got %q", pod.Name, agentRun.Status.PodName)
	}
	if agentRun.Status.Phase != nvtv1alpha1.AgentRunPhaseCompleted {
		t.Fatalf("expected Completed phase to remain terminal, got %q", agentRun.Status.Phase)
	}
	if !agentRun.Status.FinishedAt.Equal(&finishedAt) ||
		agentRun.Status.Reason != "Completed by lifecycle event plugin.agent.signal.done" {
		t.Fatalf("terminal status details changed: %#v", agentRun.Status)
	}
}

func TestReconcileCompletedRunBeforeTTLKeepsPodAndRequeues(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	finishedAt := metav1.Date(2026, 5, 31, 11, 59, 30, 0, time.UTC)
	agentRun := terminalAgentRun(nvtv1alpha1.AgentRunPhaseCompleted, finishedAt)
	agentRun.Spec.TTL.CompletedTTLSeconds = ptrTo[int64](60)
	k8sClient, reconciler := terminalCleanupFixture(t, agentRun, now, true)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 30*time.Second {
		t.Fatalf("expected requeue after 30s, got %s", result.RequeueAfter)
	}
	assertAgentPodExists(ctx, t, k8sClient, agentRun)
}

func TestReconcileCompletedRunAfterTTLDeletesPod(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	finishedAt := metav1.Date(2026, 5, 31, 11, 58, 0, 0, time.UTC)
	agentRun := terminalAgentRun(nvtv1alpha1.AgentRunPhaseCompleted, finishedAt)
	agentRun.Spec.TTL.CompletedTTLSeconds = ptrTo[int64](60)
	k8sClient, reconciler := terminalCleanupFixture(t, agentRun, now, true)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %s", result.RequeueAfter)
	}
	assertAgentPodMissing(ctx, t, k8sClient, agentRun)
}

func TestReconcileFailedRunBeforeTTLKeepsPodAndRequeues(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	finishedAt := metav1.Date(2026, 5, 31, 11, 59, 45, 0, time.UTC)
	agentRun := terminalAgentRun(nvtv1alpha1.AgentRunPhaseFailed, finishedAt)
	agentRun.Spec.TTL.FailedTTLSeconds = ptrTo[int64](60)
	k8sClient, reconciler := terminalCleanupFixture(t, agentRun, now, true)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 45*time.Second {
		t.Fatalf("expected requeue after 45s, got %s", result.RequeueAfter)
	}
	assertAgentPodExists(ctx, t, k8sClient, agentRun)
}

func TestReconcileFailedRunAfterTTLDeletesPod(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	finishedAt := metav1.Date(2026, 5, 31, 11, 58, 0, 0, time.UTC)
	agentRun := terminalAgentRun(nvtv1alpha1.AgentRunPhaseFailed, finishedAt)
	agentRun.Spec.TTL.FailedTTLSeconds = ptrTo[int64](60)
	k8sClient, reconciler := terminalCleanupFixture(t, agentRun, now, true)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %s", result.RequeueAfter)
	}
	assertAgentPodMissing(ctx, t, k8sClient, agentRun)
}

func TestReconcilePodStatusFailedRunAfterTTLDeletesPod(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	failedAt := metav1.Date(2026, 5, 31, 11, 58, 0, 0, time.UTC)
	agentRun := terminalAgentRun(nvtv1alpha1.AgentRunPhaseFailed, failedAt)
	agentRun.Status.Reason = "Pod failed"
	agentRun.Spec.TTL.FailedTTLSeconds = ptrTo[int64](60)
	k8sClient, reconciler := terminalCleanupFixture(t, agentRun, now, true)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %s", result.RequeueAfter)
	}
	assertAgentPodMissing(ctx, t, k8sClient, agentRun)
}

func TestReconcileSetsFinishedAtWhenPodFails(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	agentRun := testAgentRun()
	agentRun.Spec.TTL = &nvtv1alpha1.AgentRunTTL{FailedTTLSeconds: ptrTo[int64](60)}
	scheme := testScheme(t)
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{
		Client: k8sClient,
		Scheme: scheme,
		Now:    func() metav1.Time { return now },
	}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	pod := &corev1.Pod{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: AgentPodName(agentRun.Name)}, pod); err != nil {
		t.Fatalf("get pod: %v", err)
	}
	pod.Status.Phase = corev1.PodFailed
	if err := k8sClient.Status().Update(ctx, pod); err != nil {
		t.Fatalf("update Pod status: %v", err)
	}

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile failed Pod: %v", err)
	}

	if result.RequeueAfter != 60*time.Second {
		t.Fatalf("expected failed TTL requeue, got %s", result.RequeueAfter)
	}
	updated := &nvtv1alpha1.AgentRun{}
	if err := k8sClient.Get(ctx, clientKey(agentRun), updated); err != nil {
		t.Fatalf("get AgentRun: %v", err)
	}
	if updated.Status.Phase != nvtv1alpha1.AgentRunPhaseFailed {
		t.Fatalf("expected Failed phase, got %q", updated.Status.Phase)
	}
	if updated.Status.FinishedAt == nil || !updated.Status.FinishedAt.Equal(&now) {
		t.Fatalf("expected finishedAt %s, got %#v", now, updated.Status.FinishedAt)
	}
	if updated.Status.Reason != "Pod failed" {
		t.Fatalf("expected Pod failed reason, got %q", updated.Status.Reason)
	}
	assertAgentPodExists(ctx, t, k8sClient, agentRun)
}

func TestReconcileTerminalRunWithNilTTLKeepsPodAndDoesNotRequeue(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	finishedAt := metav1.Date(2026, 5, 31, 11, 0, 0, 0, time.UTC)
	agentRun := terminalAgentRun(nvtv1alpha1.AgentRunPhaseCompleted, finishedAt)
	agentRun.Spec.TTL.CompletedTTLSeconds = nil
	k8sClient, reconciler := terminalCleanupFixture(t, agentRun, now, true)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %s", result.RequeueAfter)
	}
	assertAgentPodExists(ctx, t, k8sClient, agentRun)
}

func TestReconcileTerminalRunMissingPodAfterTTLSucceeds(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	finishedAt := metav1.Date(2026, 5, 31, 11, 58, 0, 0, time.UTC)
	agentRun := terminalAgentRun(nvtv1alpha1.AgentRunPhaseCompleted, finishedAt)
	agentRun.Spec.TTL.CompletedTTLSeconds = ptrTo[int64](60)
	k8sClient, reconciler := terminalCleanupFixture(t, agentRun, now, false)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %s", result.RequeueAfter)
	}
	assertAgentPodMissing(ctx, t, k8sClient, agentRun)
}

func TestReconcileNonTerminalRunDoesNotCleanupPod(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	finishedAt := metav1.Date(2026, 5, 31, 11, 0, 0, 0, time.UTC)
	agentRun := terminalAgentRun(nvtv1alpha1.AgentRunPhaseRunning, finishedAt)
	agentRun.Spec.TTL.CompletedTTLSeconds = ptrTo[int64](60)
	k8sClient, reconciler := terminalCleanupFixture(t, agentRun, now, true)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %s", result.RequeueAfter)
	}
	assertAgentPodExists(ctx, t, k8sClient, agentRun)
}

func TestReconcileActiveDeadlineOmittedDoesNotTimeout(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	startedAt := metav1.Date(2026, 5, 31, 10, 0, 0, 0, time.UTC)
	agentRun := activeDeadlineAgentRun(startedAt, nil)
	k8sClient, reconciler := terminalCleanupFixture(t, agentRun, now, true)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %s", result.RequeueAfter)
	}
	assertAgentRunPhase(ctx, t, k8sClient, agentRun, nvtv1alpha1.AgentRunPhaseRunning)
	assertAgentPodExists(ctx, t, k8sClient, agentRun)
}

func TestReconcileActiveDeadlineWithNilStartedAtDoesNotTimeout(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	agentRun := testAgentRun()
	agentRun.Status.Phase = nvtv1alpha1.AgentRunPhaseRunning
	agentRun.Spec.TTL = &nvtv1alpha1.AgentRunTTL{ActiveDeadlineSeconds: ptrTo[int64](60)}
	k8sClient, reconciler := terminalCleanupFixture(t, agentRun, now, true)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %s", result.RequeueAfter)
	}
	assertAgentRunPhase(ctx, t, k8sClient, agentRun, nvtv1alpha1.AgentRunPhaseRunning)
	assertAgentPodExists(ctx, t, k8sClient, agentRun)
}

func TestReconcileActiveDeadlineBeforeDeadlineKeepsPodAndRequeues(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	startedAt := metav1.Date(2026, 5, 31, 11, 59, 30, 0, time.UTC)
	agentRun := activeDeadlineAgentRun(startedAt, ptrTo[int64](60))
	k8sClient, reconciler := terminalCleanupFixture(t, agentRun, now, true)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 30*time.Second {
		t.Fatalf("expected requeue after 30s, got %s", result.RequeueAfter)
	}
	assertAgentRunPhase(ctx, t, k8sClient, agentRun, nvtv1alpha1.AgentRunPhaseRunning)
	assertAgentPodExists(ctx, t, k8sClient, agentRun)
}

func TestReconcileActiveDeadlineBeforeDeadlineCreatesMissingPodAndRequeues(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	startedAt := metav1.Date(2026, 5, 31, 11, 59, 30, 0, time.UTC)
	agentRun := activeDeadlineAgentRun(startedAt, ptrTo[int64](60))
	k8sClient, reconciler := terminalCleanupFixture(t, agentRun, now, false)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 30*time.Second {
		t.Fatalf("expected requeue after 30s, got %s", result.RequeueAfter)
	}
	assertAgentRunPhase(ctx, t, k8sClient, agentRun, nvtv1alpha1.AgentRunPhaseRunning)
	assertAgentPodExists(ctx, t, k8sClient, agentRun)
}

func TestReconcileActiveDeadlineAfterDeadlineMarksExceededAndDeletesPod(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	startedAt := metav1.Date(2026, 5, 31, 11, 58, 0, 0, time.UTC)
	agentRun := activeDeadlineAgentRun(startedAt, ptrTo[int64](60))
	k8sClient, reconciler := terminalCleanupFixture(t, agentRun, now, true)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %s", result.RequeueAfter)
	}
	updated := assertAgentRunPhase(ctx, t, k8sClient, agentRun, nvtv1alpha1.AgentRunPhaseDeadlineExceeded)
	if updated.Status.FinishedAt == nil || !updated.Status.FinishedAt.Equal(&now) {
		t.Fatalf("expected finishedAt %s, got %#v", now, updated.Status.FinishedAt)
	}
	if updated.Status.Reason != activeDeadlineReason {
		t.Fatalf("expected reason %q, got %q", activeDeadlineReason, updated.Status.Reason)
	}
	assertAgentPodMissing(ctx, t, k8sClient, agentRun)
}

func TestReconcileActiveDeadlineDoesNotChangeCompletedOrFailedRuns(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	startedAt := metav1.Date(2026, 5, 31, 10, 0, 0, 0, time.UTC)
	finishedAt := metav1.Date(2026, 5, 31, 11, 0, 0, 0, time.UTC)

	tests := []struct {
		name  string
		phase nvtv1alpha1.AgentRunPhase
	}{
		{name: "completed", phase: nvtv1alpha1.AgentRunPhaseCompleted},
		{name: "failed", phase: nvtv1alpha1.AgentRunPhaseFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agentRun := terminalAgentRun(tt.phase, finishedAt)
			agentRun.Status.StartedAt = &startedAt
			agentRun.Status.Reason = string(tt.phase)
			agentRun.Spec.TTL.ActiveDeadlineSeconds = ptrTo[int64](60)
			k8sClient, reconciler := terminalCleanupFixture(t, agentRun, now, true)

			result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
			if err != nil {
				t.Fatalf("reconcile: %v", err)
			}

			if result.RequeueAfter != 0 {
				t.Fatalf("expected no active deadline requeue, got %s", result.RequeueAfter)
			}
			updated := assertAgentRunPhase(ctx, t, k8sClient, agentRun, tt.phase)
			if !updated.Status.FinishedAt.Equal(&finishedAt) {
				t.Fatalf("expected finishedAt to remain %s, got %#v", finishedAt, updated.Status.FinishedAt)
			}
			assertAgentPodExists(ctx, t, k8sClient, agentRun)
		})
	}
}

func TestReconcileActiveDeadlineMissingPodAfterDeadlineSucceeds(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	startedAt := metav1.Date(2026, 5, 31, 11, 58, 0, 0, time.UTC)
	agentRun := activeDeadlineAgentRun(startedAt, ptrTo[int64](60))
	k8sClient, reconciler := terminalCleanupFixture(t, agentRun, now, false)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %s", result.RequeueAfter)
	}
	assertAgentRunPhase(ctx, t, k8sClient, agentRun, nvtv1alpha1.AgentRunPhaseDeadlineExceeded)
	assertAgentPodMissing(ctx, t, k8sClient, agentRun)
}

func TestReconcileActiveDeadlineAfterDeadlineDoesNotRequireBrokerPolicyConfigMap(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	startedAt := metav1.Date(2026, 5, 31, 11, 58, 0, 0, time.UTC)
	agentRun := activeDeadlineAgentRun(startedAt, ptrTo[int64](60))
	scheme := testScheme(t)
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun).
		Build()
	persistAgentRunStatus(ctx, t, k8sClient, agentRun)
	reconciler := &AgentRunReconciler{
		Client: k8sClient,
		Scheme: scheme,
		Now:    func() metav1.Time { return now },
	}

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %s", result.RequeueAfter)
	}
	assertAgentRunPhase(ctx, t, k8sClient, agentRun, nvtv1alpha1.AgentRunPhaseDeadlineExceeded)
}

func TestReconcileDeadlineExceededRunDeletesPod(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	startedAt := metav1.Date(2026, 5, 31, 11, 58, 0, 0, time.UTC)
	finishedAt := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	agentRun := terminalAgentRun(nvtv1alpha1.AgentRunPhaseDeadlineExceeded, finishedAt)
	agentRun.Status.StartedAt = &startedAt
	agentRun.Status.Reason = activeDeadlineReason
	k8sClient, reconciler := terminalCleanupFixture(t, agentRun, now, true)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %s", result.RequeueAfter)
	}
	assertAgentRunPhase(ctx, t, k8sClient, agentRun, nvtv1alpha1.AgentRunPhaseDeadlineExceeded)
	assertAgentPodMissing(ctx, t, k8sClient, agentRun)
}

func TestReconcileDefaultRunRetentionDeletesOldTerminalAgentRun(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	finishedAt := metav1.Date(2026, 5, 31, 11, 59, 59, 0, time.UTC)
	agentRun := terminalAgentRunWithRunRetention(nvtv1alpha1.AgentRunPhaseCompleted, finishedAt, nil)
	k8sClient, reconciler := terminalCleanupFixture(t, agentRun, now, false)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %s", result.RequeueAfter)
	}
	assertAgentRunDeleting(ctx, t, k8sClient, agentRun)
}

func TestReconcileDefaultRunRetentionKeepsRecentTerminalAgentRunAndRequeues(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	finishedAt := metav1.Date(2026, 5, 31, 12, 0, 30, 0, time.UTC)
	agentRun := terminalAgentRunWithRunRetention(nvtv1alpha1.AgentRunPhaseCompleted, finishedAt, nil)
	k8sClient, reconciler := terminalCleanupFixture(t, agentRun, now, false)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 30*time.Second {
		t.Fatalf("expected requeue after 30s, got %s", result.RequeueAfter)
	}
	assertAgentRunPhase(ctx, t, k8sClient, agentRun, nvtv1alpha1.AgentRunPhaseCompleted)
}

func TestReconcileZeroRunRetentionKeepsTerminalAgentRunForever(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	finishedAt := metav1.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	agentRun := terminalAgentRunWithRunRetention(nvtv1alpha1.AgentRunPhaseFailed, finishedAt, ptrTo[int64](0))
	k8sClient, reconciler := terminalCleanupFixture(t, agentRun, now, false)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %s", result.RequeueAfter)
	}
	assertAgentRunPhase(ctx, t, k8sClient, agentRun, nvtv1alpha1.AgentRunPhaseFailed)
}

func TestReconcilePositiveRunRetentionDeletesExpiredTerminalAgentRun(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	finishedAt := metav1.Date(2026, 5, 31, 11, 58, 0, 0, time.UTC)
	agentRun := terminalAgentRunWithRunRetention(nvtv1alpha1.AgentRunPhaseDeadlineExceeded, finishedAt, ptrTo[int64](60))
	k8sClient, reconciler := terminalCleanupFixture(t, agentRun, now, false)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %s", result.RequeueAfter)
	}
	assertAgentRunDeleting(ctx, t, k8sClient, agentRun)
}

func TestReconcilePositiveRunRetentionKeepsTerminalAgentRunBeforeExpiryAndRequeues(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	finishedAt := metav1.Date(2026, 5, 31, 11, 59, 30, 0, time.UTC)
	agentRun := terminalAgentRunWithRunRetention(nvtv1alpha1.AgentRunPhaseDeadlineExceeded, finishedAt, ptrTo[int64](60))
	k8sClient, reconciler := terminalCleanupFixture(t, agentRun, now, false)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 30*time.Second {
		t.Fatalf("expected requeue after 30s, got %s", result.RequeueAfter)
	}
	assertAgentRunPhase(ctx, t, k8sClient, agentRun, nvtv1alpha1.AgentRunPhaseDeadlineExceeded)
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
			Runtime: nvtv1alpha1.AgentRunRuntime{
				Type:     "codex",
				Autonomy: "trusted-local",
			},
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

func terminalAgentRun(phase nvtv1alpha1.AgentRunPhase, finishedAt metav1.Time) *nvtv1alpha1.AgentRun {
	return terminalAgentRunWithRunRetention(phase, finishedAt, ptrTo[int64](0))
}

func terminalAgentRunWithRunRetention(
	phase nvtv1alpha1.AgentRunPhase,
	finishedAt metav1.Time,
	runRetentionSeconds *int64,
) *nvtv1alpha1.AgentRun {
	agentRun := testAgentRun()
	agentRun.Status.Phase = phase
	agentRun.Status.FinishedAt = &finishedAt
	agentRun.Spec.TTL = &nvtv1alpha1.AgentRunTTL{RunRetentionSeconds: runRetentionSeconds}
	return agentRun
}

func activeDeadlineAgentRun(startedAt metav1.Time, activeDeadlineSeconds *int64) *nvtv1alpha1.AgentRun {
	agentRun := testAgentRun()
	agentRun.Status.Phase = nvtv1alpha1.AgentRunPhaseRunning
	agentRun.Status.StartedAt = &startedAt
	if activeDeadlineSeconds != nil {
		agentRun.Spec.TTL = &nvtv1alpha1.AgentRunTTL{
			ActiveDeadlineSeconds: activeDeadlineSeconds,
			RunRetentionSeconds:   ptrTo[int64](0),
		}
	}
	return agentRun
}

func terminalCleanupFixture(
	t *testing.T,
	agentRun *nvtv1alpha1.AgentRun,
	now metav1.Time,
	includePod bool,
) (client.Client, *AgentRunReconciler) {
	t.Helper()

	scheme := testScheme(t)
	objects := []client.Object{agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)}
	if includePod {
		pod, err := DesiredAgentPod(agentRun, scheme)
		if err != nil {
			t.Fatalf("desired AgentRun Pod: %v", err)
		}
		objects = append(objects, pod)
	}
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(objects...).
		Build()
	if agentRun.Status.Phase != "" || agentRun.Status.FinishedAt != nil || agentRun.Status.Reason != "" {
		persistAgentRunStatus(context.Background(), t, k8sClient, agentRun)
	}
	reconciler := &AgentRunReconciler{
		Client: k8sClient,
		Scheme: scheme,
		Now:    func() metav1.Time { return now },
	}

	return k8sClient, reconciler
}

func persistAgentRunStatus(ctx context.Context, t *testing.T, k8sClient client.Client, agentRun *nvtv1alpha1.AgentRun) {
	t.Helper()

	current := &nvtv1alpha1.AgentRun{}
	if err := k8sClient.Get(ctx, clientKey(agentRun), current); err != nil {
		t.Fatalf("get AgentRun for status seed: %v", err)
	}
	current.Status = agentRun.Status
	if err := k8sClient.Status().Update(ctx, current); err != nil {
		t.Fatalf("seed AgentRun status: %v", err)
	}
}

func parseAgentConfigYAML(t *testing.T, rendered string) map[string]any {
	t.Helper()

	var config map[string]any
	if err := yaml.Unmarshal([]byte(rendered), &config); err != nil {
		t.Fatalf("parse rendered agent config: %v\n%s", err, rendered)
	}
	return config
}

func crdPath(t *testing.T, value any, path ...any) any {
	t.Helper()

	current := value
	for _, segment := range path {
		switch key := segment.(type) {
		case string:
			object, ok := current.(map[string]any)
			if !ok {
				t.Fatalf("expected object at %q, got %#v", key, current)
			}
			current = object[key]
		case int:
			list, ok := current.([]any)
			if !ok {
				t.Fatalf("expected list at %d, got %#v", key, current)
			}
			if key < 0 || key >= len(list) {
				t.Fatalf("index %d out of bounds for %#v", key, list)
			}
			current = list[key]
		default:
			t.Fatalf("unsupported path segment %#v", segment)
		}
	}
	return current
}

func assertAgentRunPhase(
	ctx context.Context,
	t *testing.T,
	k8sClient client.Client,
	agentRun *nvtv1alpha1.AgentRun,
	phase nvtv1alpha1.AgentRunPhase,
) *nvtv1alpha1.AgentRun {
	t.Helper()

	updated := &nvtv1alpha1.AgentRun{}
	if err := k8sClient.Get(ctx, clientKey(agentRun), updated); err != nil {
		t.Fatalf("get AgentRun: %v", err)
	}
	if updated.Status.Phase != phase {
		t.Fatalf("expected phase %q, got %q", phase, updated.Status.Phase)
	}
	return updated
}

func assertAgentRunDeleting(ctx context.Context, t *testing.T, k8sClient client.Client, agentRun *nvtv1alpha1.AgentRun) {
	t.Helper()

	updated := &nvtv1alpha1.AgentRun{}
	err := k8sClient.Get(ctx, clientKey(agentRun), updated)
	if errors.IsNotFound(err) {
		return
	}
	if err != nil {
		t.Fatalf("get AgentRun: %v", err)
	}
	if updated.DeletionTimestamp.IsZero() {
		t.Fatalf("expected AgentRun to be deleting, got deletion timestamp %v", updated.DeletionTimestamp)
	}
}

func testBrokerAgentsConfigMap(namespace string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      brokerAgentsConfigMapName,
			Namespace: namespace,
		},
		Data: map[string]string{
			brokerAgentsConfigKey: "agents: []\n",
		},
	}
}

func clientKey(agentRun *nvtv1alpha1.AgentRun) types.NamespacedName {
	return types.NamespacedName{Name: agentRun.Name, Namespace: agentRun.Namespace}
}

func assertAgentPodExists(ctx context.Context, t *testing.T, k8sClient client.Reader, agentRun *nvtv1alpha1.AgentRun) {
	t.Helper()

	var pod corev1.Pod
	key := types.NamespacedName{Name: AgentPodName(agentRun.Name), Namespace: agentRun.Namespace}
	if err := k8sClient.Get(ctx, key, &pod); err != nil {
		t.Fatalf("expected AgentRun Pod to exist: %v", err)
	}
}

func assertAgentPodMissing(ctx context.Context, t *testing.T, k8sClient client.Reader, agentRun *nvtv1alpha1.AgentRun) {
	t.Helper()

	var pod corev1.Pod
	key := types.NamespacedName{Name: AgentPodName(agentRun.Name), Namespace: agentRun.Namespace}
	if err := k8sClient.Get(ctx, key, &pod); err == nil {
		t.Fatalf("expected AgentRun Pod to be missing")
	} else if !errors.IsNotFound(err) {
		t.Fatalf("get AgentRun Pod: %v", err)
	}
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

func getBrokerAgentsConfigMap(
	ctx context.Context,
	t *testing.T,
	k8sClient client.Reader,
	namespace string,
) corev1.ConfigMap {
	t.Helper()

	var configMap corev1.ConfigMap
	key := types.NamespacedName{Name: brokerAgentsConfigMapName, Namespace: namespace}
	if err := k8sClient.Get(ctx, key, &configMap); err != nil {
		t.Fatalf("get broker agents ConfigMap: %v", err)
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

func mustParseBrokerAgentsPolicy(t *testing.T, raw string) brokerAgentsPolicy {
	t.Helper()

	policy, err := ParseBrokerAgentsYAML(raw)
	if err != nil {
		t.Fatalf("parse broker agents policy:\n%s\nerror: %v", raw, err)
	}
	return policy
}

func requireBrokerAgentEntry(t *testing.T, policy brokerAgentsPolicy, id string) brokerAgentEntry {
	t.Helper()

	for _, entry := range policy.Agents {
		if entry.ID == id {
			return entry
		}
	}
	t.Fatalf("broker agent entry %q not found in %#v", id, policy.Agents)
	return brokerAgentEntry{}
}

func expectedSHA256TokenHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validTestTokenHash(seed string) string {
	return expectedSHA256TokenHash("test-token-" + seed)
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

	if container, ok := findContainer(pod.Spec.Containers, name); ok {
		return container
	}
	t.Fatalf("container %q not found in %#v", name, pod.Spec.Containers)
	return corev1.Container{}
}

func findContainer(containers []corev1.Container, name string) (corev1.Container, bool) {
	for _, container := range containers {
		if container.Name == name {
			return container, true
		}
	}
	return corev1.Container{}, false
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

func assertNoVolumeMount(t *testing.T, container corev1.Container, name string) {
	t.Helper()

	for _, mount := range container.VolumeMounts {
		if mount.Name == name {
			t.Fatalf("unexpected volume mount %q in %#v", name, container.VolumeMounts)
		}
	}
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
