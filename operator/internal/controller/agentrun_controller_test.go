package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
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
	t.Setenv("NVT_BROKER_URL", "")
	t.Setenv("NVT_BROKER_CA_SECRET", "")

	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	runtimeClassName := "kata-vm-isolation"
	agentRun.Spec.RuntimeClassName = &runtimeClassName
	agentRun.Spec.Resources = corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2"), corev1.ResourceMemory: resource.MustParse("8Gi")},
		Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2"), corev1.ResourceMemory: resource.MustParse("8Gi")},
	}
	tolerationSeconds := int64(120)
	agentRun.Spec.Tolerations = []corev1.Toleration{{
		Key: "purpose", Operator: corev1.TolerationOpEqual, Value: "nvt-agent",
		Effect: corev1.TaintEffectNoExecute, TolerationSeconds: &tolerationSeconds,
	}}
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
	if !reflect.DeepEqual(pod.Spec.Tolerations, agentRun.Spec.Tolerations) {
		t.Fatalf("expected agent tolerations %#v, got %#v", agentRun.Spec.Tolerations, pod.Spec.Tolerations)
	}
	pod.Spec.Tolerations[0].TolerationSeconds = ptrTo(int64(1))
	if *agentRun.Spec.Tolerations[0].TolerationSeconds != tolerationSeconds {
		t.Fatal("desired Pod tolerations alias AgentRun API storage")
	}
	if pod.Spec.RestartPolicy != corev1.RestartPolicyNever {
		t.Fatalf("expected restartPolicy Never, got %q", pod.Spec.RestartPolicy)
	}

	agentContainer := requireContainer(t, pod, "agent")
	if !reflect.DeepEqual(agentContainer.Resources, agentRun.Spec.Resources) {
		t.Fatalf("expected agent resources %#v, got %#v", agentRun.Spec.Resources, agentContainer.Resources)
	}
	agentContainer.Resources.Limits[corev1.ResourceMemory] = resource.MustParse("1Gi")
	if agentRun.Spec.Resources.Limits.Memory().Cmp(resource.MustParse("8Gi")) != 0 {
		t.Fatal("desired Pod resources alias AgentRun API storage")
	}
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
	if envValue(agentContainer, "NVT_BROKER_URL") != defaultBrokerURL {
		t.Fatalf("expected NVT_BROKER_URL %q, got %#v", defaultBrokerURL, agentContainer.Env)
	}
	assertSecretKeyEnv(t, agentContainer, brokerTokenKey, BrokerTokenSecretName(agentRun.Name), brokerTokenKey)
	assertSecretKeyEnv(t, agentContainer, callbackTokenKey, CallbackTokenSecretName(agentRun.Name), callbackTokenKey)
	assertVolumeMount(t, agentContainer, "agent-config", agentConfigVolumeDir, "", true)
	assertVolumeMount(t, agentContainer, "workspace", workspaceMountPath, "", false)

	dindContainer := requireInitContainer(t, pod, "docker")
	if dindContainer.Image != defaultDindImage || dindContainer.ImagePullPolicy != corev1.PullIfNotPresent {
		t.Fatalf("unexpected coordinated DinD image: %#v", dindContainer)
	}
	if dindContainer.RestartPolicy == nil || *dindContainer.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatalf("expected DinD init sidecar restartPolicy Always, got %#v", dindContainer.RestartPolicy)
	}
	if strings.Join(append(dindContainer.Command, dindContainer.Args...), " ") !=
		dindEntrypoint+" --host=unix:///var/run/docker.sock --host=tcp://127.0.0.1:2375 --tls=false" {
		t.Fatalf("unexpected DinD command/args: command=%#v args=%#v", dindContainer.Command, dindContainer.Args)
	}
	if dindContainer.StartupProbe == nil ||
		dindContainer.StartupProbe.Exec == nil ||
		strings.Join(dindContainer.StartupProbe.Exec.Command, " ") != dindReady {
		t.Fatalf("expected DinD startupProbe to enforce storage readiness, got %#v", dindContainer.StartupProbe)
	}
	if dindContainer.StartupProbe.PeriodSeconds*int32(dindContainer.StartupProbe.FailureThreshold) != dindStartupBudgetSeconds ||
		dindContainer.StartupProbe.TimeoutSeconds != 2 || dindContainer.LivenessProbe != nil {
		t.Fatalf("unexpected bounded DinD recovery budget: %#v", dindContainer.StartupProbe)
	}
	if dindContainer.SecurityContext == nil || dindContainer.SecurityContext.Privileged == nil || !*dindContainer.SecurityContext.Privileged {
		t.Fatalf("expected privileged DinD sidecar, got %#v", dindContainer.SecurityContext)
	}
	assertVolumeMount(t, dindContainer, "workspace", workspaceMountPath, "", false)
	assertVolumeMount(t, dindContainer, dindStorageVolumeName, dindStorageMountPath, "", false)
	assertNoVolumeMount(t, dindContainer, runtimeAuthSourceName)
	assertNoVolumeMount(t, dindContainer, runtimeAuthHomeName)
	if envValue(dindContainer, "NVT_DIND_IMAGE_SIZE_BYTES") != strconv.FormatInt(defaultDockerPVCSizeBytes*dindImageCapacityPercent/100, 10) {
		t.Fatalf("unexpected ephemeral Docker image size: %#v", dindContainer.Env)
	}
	assertNoVolumeMount(t, agentContainer, dindStorageVolumeName)
	assertNoVolumeMountPath(t, agentContainer, dindStorageMountPath)
	if agentContainer.SecurityContext != nil && agentContainer.SecurityContext.Capabilities != nil && len(agentContainer.SecurityContext.Capabilities.Add) != 0 {
		t.Fatalf("Docker storage added capabilities to the agent: %#v", agentContainer.SecurityContext)
	}
	for _, container := range append(append([]corev1.Container(nil), pod.Spec.InitContainers...), pod.Spec.Containers...) {
		privileged := container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged
		if container.Name == "docker" {
			if !privileged {
				t.Fatal("Docker sidecar is not privileged")
			}
			continue
		}
		if privileged {
			t.Fatalf("non-Docker container %q became privileged", container.Name)
		}
	}

	workspaceVolume := requireVolume(t, pod, "workspace")
	if workspaceVolume.EmptyDir == nil {
		t.Fatalf("expected workspace emptyDir volume, got %#v", workspaceVolume.VolumeSource)
	}
	dindStorageVolume := requireVolume(t, pod, dindStorageVolumeName)
	if dindStorageVolume.EmptyDir == nil || dindStorageVolume.HostPath != nil || dindStorageVolume.EmptyDir.SizeLimit == nil ||
		dindStorageVolume.EmptyDir.SizeLimit.Cmp(resource.MustParse("20Gi")) != 0 {
		t.Fatalf("ephemeral Docker storage must be a sidecar-only emptyDir: %#v", dindStorageVolume.VolumeSource)
	}
	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath != nil {
			t.Fatalf("AgentRun Pod must not mount a node path for Docker: %#v", volume)
		}
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

func TestDesiredAgentPodOmittedTolerationsRemainNil(t *testing.T) {
	run := testAgentRun()
	if AgentRunEgressMode(run) != nvtv1alpha1.AgentRunEgressDirect || run.Spec.Tolerations != nil {
		t.Fatalf("invalid direct-mode fixture: %#v", run.Spec)
	}
	pod, err := DesiredAgentPod(run, testScheme(t))
	if err != nil {
		t.Fatalf("build direct agent Pod: %v", err)
	}
	if pod.Spec.Tolerations != nil {
		t.Fatalf("omitted tolerations defaulted unexpectedly: %#v", pod.Spec.Tolerations)
	}
}

func TestAgentTolerationsDoNotMoveSeparateEgressdPod(t *testing.T) {
	run := transparentAgentRun(t)
	run.Spec.Tolerations = []corev1.Toleration{{
		Key: "purpose", Operator: corev1.TolerationOpEqual, Value: "nvt-agent", Effect: corev1.TaintEffectNoSchedule,
	}}
	agentPod, err := DesiredAgentPod(run, testScheme(t))
	if err != nil {
		t.Fatalf("build agent Pod: %v", err)
	}
	if !reflect.DeepEqual(agentPod.Spec.Tolerations, run.Spec.Tolerations) {
		t.Fatalf("agent Pod tolerations=%#v, want %#v", agentPod.Spec.Tolerations, run.Spec.Tolerations)
	}
	egressdPod, err := DesiredEgressdPod(run, testScheme(t))
	if err != nil {
		t.Fatalf("build separate egressd Pod: %v", err)
	}
	if egressdPod.Spec.Tolerations != nil {
		t.Fatalf("separate egressd Pod inherited agent tolerations: %#v", egressdPod.Spec.Tolerations)
	}
}

func TestWorkspaceValidation(t *testing.T) {
	tests := []struct {
		name      string
		workspace nvtv1alpha1.AgentRunWorkspace
		wantError string
	}{
		{name: "omitted defaults ephemeral"},
		{name: "explicit ephemeral", workspace: nvtv1alpha1.AgentRunWorkspace{Mode: nvtv1alpha1.AgentRunWorkspaceEphemeral}},
		{name: "persistent", workspace: persistentWorkspace("20Gi", "managed-csi")},
		{name: "persistent bounded docker", workspace: persistentWorkspaceWithDocker("20Gi", "30Gi", "managed-csi")},
		{name: "unknown mode", workspace: nvtv1alpha1.AgentRunWorkspace{Mode: "Shared"}, wantError: "Ephemeral or Persistent"},
		{name: "missing size", workspace: nvtv1alpha1.AgentRunWorkspace{Mode: nvtv1alpha1.AgentRunWorkspacePersistent}, wantError: "positive"},
		{name: "zero size", workspace: persistentWorkspace("0", ""), wantError: "positive"},
		{name: "ephemeral size", workspace: persistentWorkspace("1Gi", ""), wantError: ""},
		{name: "unnormalized class", workspace: persistentWorkspace("1Gi", " managed-csi"), wantError: "normalized"},
		{name: "invalid class", workspace: persistentWorkspace("1Gi", "Managed_CSI"), wantError: "DNS subdomain"},
		{name: "docker too small", workspace: persistentWorkspaceWithDocker("5Gi", "512Mi", ""), wantError: "between 1Gi and 1Ti"},
		{name: "docker too large", workspace: persistentWorkspaceWithDocker("5Gi", "2Ti", ""), wantError: "between 1Gi and 1Ti"},
	}
	// Convert the dedicated ephemeral-size case after constructing a quantity.
	for index := range tests {
		if tests[index].name == "ephemeral size" {
			tests[index].workspace.Mode = nvtv1alpha1.AgentRunWorkspaceEphemeral
			tests[index].wantError = "require mode Persistent"
		}
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			run := testAgentRun()
			run.Spec.Workspace = test.workspace
			err := ValidateAgentRunWorkspace(run)
			if test.wantError == "" && err != nil {
				t.Fatalf("validate workspace: %v", err)
			}
			if test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestPersistentWorkspaceDeepCopyDoesNotAliasQuantity(t *testing.T) {
	run := testAgentRun()
	run.Spec.Workspace = persistentWorkspaceWithDocker("5Gi", "8Gi", "")
	run.Spec.Resources = corev1.ResourceRequirements{
		Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("8Gi")},
	}
	copy := run.DeepCopyObject().(*nvtv1alpha1.AgentRun)
	copy.Spec.Workspace.Size.Add(resource.MustParse("1Gi"))
	copy.Spec.Workspace.DockerSize.Add(resource.MustParse("1Gi"))
	copy.Spec.Resources.Limits[corev1.ResourceMemory] = resource.MustParse("1Gi")
	if run.Spec.Workspace.Size.Cmp(resource.MustParse("5Gi")) != 0 || copy.Spec.Workspace.Size.Cmp(resource.MustParse("6Gi")) != 0 {
		t.Fatalf("workspace quantity was aliased: original=%s copy=%s", run.Spec.Workspace.Size, copy.Spec.Workspace.Size)
	}
	if run.Spec.Workspace.DockerSize.Cmp(resource.MustParse("8Gi")) != 0 || copy.Spec.Workspace.DockerSize.Cmp(resource.MustParse("9Gi")) != 0 {
		t.Fatalf("Docker quantity was aliased: original=%s copy=%s", run.Spec.Workspace.DockerSize, copy.Spec.Workspace.DockerSize)
	}
	if run.Spec.Resources.Limits.Memory().Cmp(resource.MustParse("8Gi")) != 0 {
		t.Fatal("resource requirements were aliased")
	}
}

func TestEphemeralWorkspaceCreatesNoPVC(t *testing.T) {
	for _, mode := range []nvtv1alpha1.AgentRunWorkspaceMode{"", nvtv1alpha1.AgentRunWorkspaceEphemeral} {
		t.Run(string(mode), func(t *testing.T) {
			ctx := context.Background()
			scheme := testScheme(t)
			run := testAgentRun()
			run.Spec.Workspace.Mode = mode
			k8sClient := fake.NewClientBuilder().WithScheme(scheme).
				WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
				WithObjects(run, testBrokerAgentsConfigMap(run.Namespace)).Build()
			reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
			if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(run)}); err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			claims := &corev1.PersistentVolumeClaimList{}
			if err := k8sClient.List(ctx, claims, client.InNamespace(run.Namespace)); err != nil {
				t.Fatalf("list PVCs: %v", err)
			}
			if len(claims.Items) != 0 {
				t.Fatalf("ephemeral run created PVCs: %#v", claims.Items)
			}
			pod := getAgentPod(ctx, t, k8sClient, run)
			volume := requireVolume(t, pod, workspaceVolumeName)
			if volume.EmptyDir == nil || volume.PersistentVolumeClaim != nil {
				t.Fatalf("ephemeral workspace shape changed: %#v", volume.VolumeSource)
			}
		})
	}
}

func TestDesiredPersistentWorkspacePVC(t *testing.T) {
	run := testAgentRun()
	run.Spec.Workspace = persistentWorkspace("20Gi", "managed-csi")
	claim, err := DesiredWorkspacePVC(run, testScheme(t))
	if err != nil {
		t.Fatalf("desired PVC: %v", err)
	}
	if claim.Name != WorkspacePVCName(run.Name) || claim.Namespace != run.Namespace {
		t.Fatalf("unexpected PVC identity: %s/%s", claim.Namespace, claim.Name)
	}
	assertOwnedByAgentRun(t, claim.OwnerReferences, run)
	if !reflect.DeepEqual(claim.Spec.AccessModes, []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}) {
		t.Fatalf("access modes = %#v", claim.Spec.AccessModes)
	}
	if claim.Spec.VolumeMode == nil || *claim.Spec.VolumeMode != corev1.PersistentVolumeFilesystem {
		t.Fatalf("volume mode = %#v", claim.Spec.VolumeMode)
	}
	if claim.Spec.StorageClassName == nil || *claim.Spec.StorageClassName != "managed-csi" {
		t.Fatalf("storage class = %#v", claim.Spec.StorageClassName)
	}
	if got := claim.Spec.Resources.Requests[corev1.ResourceStorage]; got.Cmp(resource.MustParse("20Gi")) != 0 {
		t.Fatalf("storage request = %s", got.String())
	}
	dockerClaim, err := DesiredDockerPVC(run, testScheme(t))
	if err != nil {
		t.Fatalf("desired Docker PVC: %v", err)
	}
	if dockerClaim.Name != DockerPVCName(run.Name) || dockerClaim.Namespace != run.Namespace {
		t.Fatalf("unexpected Docker PVC identity: %s/%s", dockerClaim.Namespace, dockerClaim.Name)
	}
	assertOwnedByAgentRun(t, dockerClaim.OwnerReferences, run)
	if dockerClaim.Spec.StorageClassName == nil || *dockerClaim.Spec.StorageClassName != "managed-csi" {
		t.Fatalf("Docker storage class = %#v", dockerClaim.Spec.StorageClassName)
	}
	if got := dockerClaim.Spec.Resources.Requests[corev1.ResourceStorage]; got.Cmp(resource.MustParse("20Gi")) != 0 {
		t.Fatalf("default Docker storage request = %s", got.String())
	}
	run.Spec.Workspace = persistentWorkspaceWithDocker("20Gi", "30Gi", "managed-csi")
	dockerClaim, err = DesiredDockerPVC(run, testScheme(t))
	if err != nil {
		t.Fatalf("desired explicit Docker PVC: %v", err)
	}
	if got := dockerClaim.Spec.Resources.Requests[corev1.ResourceStorage]; got.Cmp(resource.MustParse("30Gi")) != 0 {
		t.Fatalf("explicit Docker storage request = %s", got.String())
	}
	run.Spec.Workspace.StorageClassName = ""
	dockerClaim, err = DesiredDockerPVC(run, testScheme(t))
	if err != nil {
		t.Fatalf("desired default-class Docker PVC: %v", err)
	}
	actual := dockerClaim.DeepCopy()
	actual.Spec.StorageClassName = ptrTo("cluster-default")
	if err := validateDockerPVCSpec(actual, dockerClaim); err != nil {
		t.Fatalf("cluster-defaulted Docker StorageClass was rejected: %v", err)
	}
}

func TestDindImageOverridePullPolicyAndBoundedBackingSize(t *testing.T) {
	t.Setenv("NVT_DIND_IMAGE", "registry.example/nvt-dind:release")
	if got := DindImage(); got != "registry.example/nvt-dind:release" {
		t.Fatalf("DinD image override = %q", got)
	}
	t.Setenv("NVT_DIND_IMAGE_PULL_POLICY", "Never")
	if got, err := DindImagePullPolicy(); err != nil || got != corev1.PullNever {
		t.Fatalf("DinD pull policy = %q, %v", got, err)
	}
	pod, err := DesiredAgentPod(testAgentRun(), testScheme(t))
	if err != nil {
		t.Fatalf("render Pod with configured DinD pull policy: %v", err)
	}
	if got := requireInitContainer(t, *pod, "docker").ImagePullPolicy; got != corev1.PullNever {
		t.Fatalf("rendered DinD pull policy = %q", got)
	}
	t.Setenv("NVT_DIND_IMAGE_PULL_POLICY", "sometimes")
	if _, err := DindImagePullPolicy(); err == nil || !strings.Contains(err.Error(), "Always, IfNotPresent, or Never") {
		t.Fatalf("invalid DinD pull policy error = %v", err)
	}
	t.Setenv("NVT_DIND_IMAGE_PULL_POLICY", "")

	ephemeral := testAgentRun()
	if got := dindImageSizeBytes(ephemeral); got != defaultDockerPVCSizeBytes*dindImageCapacityPercent/100 {
		t.Fatalf("ephemeral DinD image size = %d", got)
	}
	persistent := testAgentRun()
	persistent.Spec.Workspace = persistentWorkspaceWithDocker("5Gi", "40Gi", "")
	if got := dindImageSizeBytes(persistent); got != 36*1024*1024*1024 {
		t.Fatalf("persistent DinD image size = %d", got)
	}
}

func TestDesiredAgentPodPersistentWorkspaceAndHome(t *testing.T) {
	for _, test := range []struct {
		name     string
		user     nvtv1alpha1.AgentRunRuntimeUser
		home     string
		ownerArg string
	}{
		{name: "root", home: "/root", ownerArg: "0:0"},
		{name: "non-root", user: nvtv1alpha1.AgentRunUserNonRoot, home: agentNonRootHome, ownerArg: "1000:1000"},
	} {
		t.Run(test.name, func(t *testing.T) {
			run := testAgentRun()
			run.Spec.Runtime.User = test.user
			run.Spec.Workspace = persistentWorkspaceWithDocker("5Gi", "8Gi", "")
			pod, err := DesiredAgentPod(run, testScheme(t))
			if err != nil {
				t.Fatalf("desired Pod: %v", err)
			}
			volume := requireVolume(t, *pod, workspaceVolumeName)
			if volume.PersistentVolumeClaim == nil || volume.PersistentVolumeClaim.ClaimName != WorkspacePVCName(run.Name) {
				t.Fatalf("workspace volume = %#v", volume.VolumeSource)
			}
			for _, podVolume := range pod.Spec.Volumes {
				if podVolume.HostPath != nil {
					t.Fatalf("persistent Docker storage must not use hostPath: %#v", podVolume)
				}
			}
			agent := requireContainer(t, *pod, "agent")
			assertVolumeMountAt(t, agent, workspaceVolumeName, workspaceMountPath, persistentWorkspaceSubPath, false)
			assertVolumeMountAt(t, agent, workspaceVolumeName, test.home, persistentHomeSubPath, false)
			dind := requireInitContainer(t, *pod, "docker")
			assertVolumeMount(t, dind, workspaceVolumeName, workspaceMountPath, persistentWorkspaceSubPath, false)
			assertVolumeMount(t, dind, dindStorageVolumeName, dindStorageMountPath, "", false)
			dockerVolume := requireVolume(t, *pod, dindStorageVolumeName)
			if dockerVolume.PersistentVolumeClaim == nil || dockerVolume.PersistentVolumeClaim.ClaimName != DockerPVCName(run.Name) {
				t.Fatalf("Docker volume = %#v", dockerVolume.VolumeSource)
			}
			assertNoVolumeMount(t, agent, dindStorageVolumeName)
			assertNoVolumeMountPath(t, agent, dindStorageMountPath)
			if envValue(dind, "NVT_DIND_IMAGE_SIZE_BYTES") != strconv.FormatInt(8*1024*1024*1024*dindImageCapacityPercent/100, 10) {
				t.Fatalf("persistent Docker image does not reserve PVC headroom: %#v", dind.Env)
			}
			initializer := requireInitContainer(t, *pod, "persistent-storage-init")
			assertVolumeMount(t, initializer, workspaceVolumeName, persistentStorageInitMountPath, "", false)
			command := strings.Join(append(initializer.Command, initializer.Args...), " ")
			for _, expected := range []string{"mkdir -p", "/workspace", "/home", "chown " + test.ownerArg, "chmod 0770", "chmod 0700"} {
				if !strings.Contains(command, expected) {
					t.Fatalf("initializer command %q missing %q", command, expected)
				}
			}
			if strings.Contains(command, "/docker") {
				t.Fatalf("workspace initializer still owns Docker storage: %q", command)
			}
		})
	}
}

func TestPersistentWorkspaceKeepsSecurityMaterialOnSeparateVolumes(t *testing.T) {
	run := testAgentRun()
	run.Spec.Workspace = persistentWorkspace("5Gi", "")
	run.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	run.Spec.EgressEnforcement = true
	run.Spec.EgressAllowInsecureBroker = true
	run.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "api-main", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject, EgressHosts: []string{"api.example.test:443"},
	}}}
	pod, err := DesiredAgentPod(run, testScheme(t))
	if err != nil {
		t.Fatalf("desired Pod: %v", err)
	}
	for _, volume := range pod.Spec.Volumes {
		if volume.Name == workspaceVolumeName || volume.Name == dindStorageVolumeName {
			continue
		}
		if volume.PersistentVolumeClaim != nil {
			t.Fatalf("security/config volume %q unexpectedly uses persistent claim: %#v", volume.Name, volume.VolumeSource)
		}
	}
	agent := requireContainer(t, *pod, "agent")
	assertVolumeMount(t, agent, "agent-config", agentConfigVolumeDir, "", true)
	assertVolumeMount(t, agent, egressCAVolumeName, egressCAMountPath, "", true)
	if findEnvVar(agent, brokerTokenKey) != nil {
		t.Fatalf("literal-zero-secret agent unexpectedly received broker token: %#v", agent.Env)
	}
}

func TestPersistentHomeCannotOverrideRefreshedRuntimeAuth(t *testing.T) {
	run := testAgentRun()
	run.Spec.Workspace = persistentWorkspace("5Gi", "")
	run.Spec.RuntimeAuth = &nvtv1alpha1.AgentRunRuntimeAuth{SecretName: "current-codex-auth"}
	pod, err := DesiredAgentPod(run, testScheme(t))
	if err != nil {
		t.Fatalf("desired Pod: %v", err)
	}
	agent := requireContainer(t, *pod, "agent")
	assertVolumeMountAt(t, agent, workspaceVolumeName, "/root", persistentHomeSubPath, false)
	assertVolumeMount(t, agent, runtimeAuthHomeName, "/root/.codex", "", false)
	authSource := requireVolume(t, *pod, runtimeAuthSourceName)
	if authSource.Secret == nil || authSource.Secret.SecretName != "current-codex-auth" {
		t.Fatalf("runtime auth source = %#v", authSource.VolumeSource)
	}
	if requireVolume(t, *pod, runtimeAuthHomeName).EmptyDir == nil {
		t.Fatal("runtime auth home must remain a fresh emptyDir overlay")
	}
	if len(pod.Spec.InitContainers) < 2 || pod.Spec.InitContainers[0].Name != "persistent-storage-init" || pod.Spec.InitContainers[1].Name != "runtime-auth-copy" {
		t.Fatalf("storage/auth initialization order = %#v", pod.Spec.InitContainers)
	}
}

func TestReconcilePersistentWorkspaceSupportsWaitForFirstConsumerAndReusesPVC(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	run := testAgentRun()
	run.Spec.Workspace = persistentWorkspace("5Gi", "managed-csi")
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}, &corev1.PersistentVolumeClaim{}).
		WithObjects(run, testBrokerAgentsConfigMap(run.Namespace)).Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(run)})
	if err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	if result.RequeueAfter != workspacePVCReadyRequeue {
		t.Fatalf("requeue = %s", result.RequeueAfter)
	}
	updatedRun := &nvtv1alpha1.AgentRun{}
	if err := k8sClient.Get(ctx, clientKey(run), updatedRun); err != nil {
		t.Fatal(err)
	}
	pending := meta.FindStatusCondition(updatedRun.Status.Conditions, ConditionWorkspaceReady)
	if updatedRun.Status.Phase != nvtv1alpha1.AgentRunPhasePending || pending == nil || pending.Status != metav1.ConditionFalse || pending.Reason != "WorkspacePending" {
		t.Fatalf("pending workspace status not surfaced: %#v", updatedRun.Status)
	}
	claim := getWorkspacePVC(ctx, t, k8sClient, run)
	dockerClaim := getDockerPVC(ctx, t, k8sClient, run)
	pod := getAgentPod(ctx, t, k8sClient, run)
	volume := requireVolume(t, pod, workspaceVolumeName)
	if volume.PersistentVolumeClaim == nil || volume.PersistentVolumeClaim.ClaimName != claim.Name {
		t.Fatalf("Pending WaitForFirstConsumer claim is not referenced by Pod: %#v", volume.VolumeSource)
	}
	dockerVolume := requireVolume(t, pod, dindStorageVolumeName)
	if dockerVolume.PersistentVolumeClaim == nil || dockerVolume.PersistentVolumeClaim.ClaimName != dockerClaim.Name {
		t.Fatalf("Pending Docker claim is not referenced by Pod: %#v", dockerVolume.VolumeSource)
	}
	claim.Annotations = map[string]string{"test.nvt.dev/preserved": "true"}
	if err := k8sClient.Update(ctx, claim); err != nil {
		t.Fatalf("mark PVC: %v", err)
	}
	dockerClaim.Annotations = map[string]string{"test.nvt.dev/preserved": "true"}
	if err := k8sClient.Update(ctx, dockerClaim); err != nil {
		t.Fatalf("mark Docker PVC: %v", err)
	}
	claim = getWorkspacePVC(ctx, t, k8sClient, run)
	claim.Status.Phase = corev1.ClaimBound
	if err := k8sClient.Status().Update(ctx, claim); err != nil {
		t.Fatalf("bind PVC: %v", err)
	}
	dockerClaim = getDockerPVC(ctx, t, k8sClient, run)
	dockerClaim.Status.Phase = corev1.ClaimBound
	if err := k8sClient.Status().Update(ctx, dockerClaim); err != nil {
		t.Fatalf("bind Docker PVC: %v", err)
	}
	if result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(run)}); err != nil {
		t.Fatalf("bound reconcile: %v", err)
	} else if result.RequeueAfter == workspacePVCReadyRequeue {
		t.Fatalf("bound PVC was still treated as pending: %#v", getWorkspacePVC(ctx, t, k8sClient, run).Status)
	}
	if err := k8sClient.Delete(ctx, &pod); err != nil {
		t.Fatalf("delete agent Pod: %v", err)
	}
	// A fresh reconciler models an operator restart; it must reuse the claim.
	reconciler = &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(run)}); err != nil {
		t.Fatalf("replacement reconcile: %v", err)
	}
	reused := getWorkspacePVC(ctx, t, k8sClient, run)
	reusedDocker := getDockerPVC(ctx, t, k8sClient, run)
	if reused.Annotations["test.nvt.dev/preserved"] != "true" {
		t.Fatalf("PVC was replaced or lost its marker: %#v", reused.Annotations)
	}
	if reusedDocker.Annotations["test.nvt.dev/preserved"] != "true" {
		t.Fatalf("Docker PVC was replaced or lost its marker: %#v", reusedDocker.Annotations)
	}
	replacement := getAgentPod(ctx, t, k8sClient, run)
	volume = requireVolume(t, replacement, workspaceVolumeName)
	if volume.PersistentVolumeClaim == nil || volume.PersistentVolumeClaim.ClaimName != reused.Name {
		t.Fatalf("replacement Pod does not reuse claim: %#v", volume.VolumeSource)
	}
	replacementDind := requireInitContainer(t, replacement, "docker")
	assertVolumeMount(t, replacementDind, dindStorageVolumeName, dindStorageMountPath, "", false)
	replacementDockerVolume := requireVolume(t, replacement, dindStorageVolumeName)
	if replacementDockerVolume.PersistentVolumeClaim == nil || replacementDockerVolume.PersistentVolumeClaim.ClaimName != reusedDocker.Name {
		t.Fatalf("replacement Pod does not reuse Docker claim: %#v", replacementDockerVolume.VolumeSource)
	}
	if envValue(replacementDind, "NVT_DIND_IMAGE_SIZE_BYTES") != strconv.FormatInt(defaultDockerPVCSizeBytes*dindImageCapacityPercent/100, 10) {
		t.Fatalf("replacement Pod changed persistent Docker backing contract: %#v", replacementDind.Env)
	}
	if err := k8sClient.Get(ctx, clientKey(run), updatedRun); err != nil {
		t.Fatal(err)
	}
	ready := meta.FindStatusCondition(updatedRun.Status.Conditions, ConditionWorkspaceReady)
	if ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("bound workspace readiness not surfaced: %#v", updatedRun.Status.Conditions)
	}
}

func TestReconcileRecreatesMissingPersistentClaimsBeforeReplacementPod(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	run := testAgentRun()
	run.Spec.Workspace = persistentWorkspace("5Gi", "")
	claim, err := DesiredWorkspacePVC(run, scheme)
	if err != nil {
		t.Fatal(err)
	}
	claim.Status.Phase = corev1.ClaimBound
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}, &corev1.PersistentVolumeClaim{}).
		WithObjects(run, claim, testBrokerAgentsConfigMap(run.Namespace)).Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
	if err := k8sClient.Delete(ctx, claim); err != nil {
		t.Fatalf("delete PVC: %v", err)
	}
	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(run)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if result.RequeueAfter != workspacePVCReadyRequeue {
		t.Fatalf("requeue = %s", result.RequeueAfter)
	}
	_ = getWorkspacePVC(ctx, t, k8sClient, run)
	_ = getDockerPVC(ctx, t, k8sClient, run)
	replacement := getAgentPod(ctx, t, k8sClient, run)
	volume := requireVolume(t, replacement, workspaceVolumeName)
	if volume.PersistentVolumeClaim == nil || volume.PersistentVolumeClaim.ClaimName != WorkspacePVCName(run.Name) {
		t.Fatalf("replacement Pod does not reference recreated Pending PVC: %#v", volume.VolumeSource)
	}
	dockerVolume := requireVolume(t, replacement, dindStorageVolumeName)
	if dockerVolume.PersistentVolumeClaim == nil || dockerVolume.PersistentVolumeClaim.ClaimName != DockerPVCName(run.Name) {
		t.Fatalf("replacement Pod does not reference recreated Pending Docker PVC: %#v", dockerVolume.VolumeSource)
	}
}

func TestReconcilePersistentWorkspaceRejectsOwnershipAndSpecDrift(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*corev1.PersistentVolumeClaim)
		want   string
	}{
		{name: "foreign owner", mutate: func(claim *corev1.PersistentVolumeClaim) { claim.OwnerReferences = nil }, want: "not controlled"},
		{name: "size drift", mutate: func(claim *corev1.PersistentVolumeClaim) {
			claim.Spec.Resources.Requests[corev1.ResourceStorage] = resource.MustParse("6Gi")
		}, want: "size differs"},
		{name: "lost claim", mutate: func(claim *corev1.PersistentVolumeClaim) { claim.Status.Phase = corev1.ClaimLost }, want: "is Lost"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			scheme := testScheme(t)
			run := testAgentRun()
			run.Spec.Workspace = persistentWorkspace("5Gi", "managed-csi")
			claim, err := DesiredWorkspacePVC(run, scheme)
			if err != nil {
				t.Fatal(err)
			}
			claim.Status.Phase = corev1.ClaimBound
			test.mutate(claim)
			k8sClient := fake.NewClientBuilder().WithScheme(scheme).
				WithStatusSubresource(&nvtv1alpha1.AgentRun{}, &corev1.PersistentVolumeClaim{}).
				WithObjects(run, claim, testBrokerAgentsConfigMap(run.Namespace)).Build()
			reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
			_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(run)})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
			pod := &corev1.Pod{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: run.Namespace, Name: AgentPodName(run.Name)}, pod); !errors.IsNotFound(err) {
				t.Fatalf("invalid workspace created Pod: %#v, get error=%v", pod, err)
			}
		})
	}
}

func TestReconcilePersistentDockerClaimRejectsOwnershipAndSpecDrift(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*corev1.PersistentVolumeClaim)
		want   string
	}{
		{name: "foreign owner", mutate: func(claim *corev1.PersistentVolumeClaim) { claim.OwnerReferences = nil }, want: "not controlled"},
		{name: "size drift", mutate: func(claim *corev1.PersistentVolumeClaim) {
			claim.Spec.Resources.Requests[corev1.ResourceStorage] = resource.MustParse("21Gi")
		}, want: "size differs"},
		{name: "storage class drift", mutate: func(claim *corev1.PersistentVolumeClaim) {
			claim.Spec.StorageClassName = ptrTo("other-csi")
		}, want: "immutable storage settings"},
		{name: "lost claim", mutate: func(claim *corev1.PersistentVolumeClaim) { claim.Status.Phase = corev1.ClaimLost }, want: "is Lost"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			scheme := testScheme(t)
			run := testAgentRun()
			run.Spec.Workspace = persistentWorkspaceWithDocker("5Gi", "20Gi", "managed-csi")
			workspaceClaim, err := DesiredWorkspacePVC(run, scheme)
			if err != nil {
				t.Fatal(err)
			}
			workspaceClaim.Status.Phase = corev1.ClaimBound
			dockerClaim, err := DesiredDockerPVC(run, scheme)
			if err != nil {
				t.Fatal(err)
			}
			dockerClaim.Status.Phase = corev1.ClaimBound
			test.mutate(dockerClaim)
			k8sClient := fake.NewClientBuilder().WithScheme(scheme).
				WithStatusSubresource(&nvtv1alpha1.AgentRun{}, &corev1.PersistentVolumeClaim{}).
				WithObjects(run, workspaceClaim, dockerClaim, testBrokerAgentsConfigMap(run.Namespace)).Build()
			reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
			_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(run)})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
			pod := &corev1.Pod{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: run.Namespace, Name: AgentPodName(run.Name)}, pod); !errors.IsNotFound(err) {
				t.Fatalf("invalid Docker claim created Pod: %#v, get error=%v", pod, err)
			}
		})
	}
}

func TestPersistentWorkspaceRejectsFileBundleCredentials(t *testing.T) {
	run := testAgentRun()
	run.Spec.Workspace = persistentWorkspace("5Gi", "")
	run.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{Provider: "token-main"}}}
	err := ValidateAgentRunWorkspace(run)
	if err == nil || !strings.Contains(err.Error(), "file-bundle") {
		t.Fatalf("error = %v, want file-bundle persistence rejection", err)
	}
}

// TestDesiredAgentPodDefaultUserIsRootUnchanged pins that the default run adds
// no non-root securityContext, no HOME, and no pod fsGroup — root, as today.
func TestDesiredAgentPodDefaultUserIsRootUnchanged(t *testing.T) {
	pod, err := DesiredAgentPod(testAgentRun(), testScheme(t))
	if err != nil {
		t.Fatalf("desired pod: %v", err)
	}
	agent := requireContainer(t, *pod, "agent")
	if agent.SecurityContext != nil {
		t.Fatalf("default agent container must have no SecurityContext, got %#v", agent.SecurityContext)
	}
	if envValue(agent, "HOME") != "" {
		t.Fatalf("default agent must not set HOME, got %q", envValue(agent, "HOME"))
	}
	if pod.Spec.SecurityContext != nil {
		t.Fatalf("default pod must have no SecurityContext/fsGroup, got %#v", pod.Spec.SecurityContext)
	}
}

func TestDesiredAgentPodAddsCapabilitiesOnlyToAgentAndComposesWithUser(t *testing.T) {
	for _, test := range []struct {
		name string
		user nvtv1alpha1.AgentRunRuntimeUser
	}{
		{name: "root"},
		{name: "non-root", user: nvtv1alpha1.AgentRunUserNonRoot},
	} {
		t.Run(test.name, func(t *testing.T) {
			run := testAgentRun()
			run.Spec.Runtime.User = test.user
			run.Spec.Runtime.Container = &nvtv1alpha1.AgentRunRuntimeContainer{
				Capabilities: &nvtv1alpha1.AgentRunRuntimeCapabilities{Add: []corev1.Capability{"SYS_PTRACE", "NET_ADMIN"}},
			}
			run.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
			run.Spec.EgressAllowInsecureBroker = true
			run.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
				Provider: "api-main", Materialization: nvtv1alpha1.AgentRunGrantPlaceholderFile,
				EgressHosts: []string{"api.example.test:443"},
			}}}

			pod, err := DesiredAgentPod(run, testScheme(t))
			if err != nil {
				t.Fatal(err)
			}
			agent := requireContainer(t, *pod, "agent")
			if agent.SecurityContext == nil || agent.SecurityContext.Capabilities == nil ||
				!reflect.DeepEqual(agent.SecurityContext.Capabilities.Add, []corev1.Capability{"SYS_PTRACE", "NET_ADMIN"}) {
				t.Fatalf("agent capabilities = %#v", agent.SecurityContext)
			}
			if test.user == nvtv1alpha1.AgentRunUserNonRoot {
				if agent.SecurityContext.RunAsUser == nil || *agent.SecurityContext.RunAsUser != agentNonRootUID ||
					agent.SecurityContext.RunAsGroup == nil || *agent.SecurityContext.RunAsGroup != agentNonRootGID {
					t.Fatalf("non-root user/group were lost: %#v", agent.SecurityContext)
				}
			} else if agent.SecurityContext.RunAsUser != nil || agent.SecurityContext.RunAsGroup != nil {
				t.Fatalf("root capability request added user overrides: %#v", agent.SecurityContext)
			}
			for _, container := range append(append([]corev1.Container(nil), pod.Spec.InitContainers...), pod.Spec.Containers...) {
				if container.Name == "agent" || container.SecurityContext == nil || container.SecurityContext.Capabilities == nil {
					continue
				}
				for _, added := range container.SecurityContext.Capabilities.Add {
					if added == "SYS_PTRACE" {
						t.Fatalf("agent capability leaked to container %q: %#v", container.Name, container.SecurityContext)
					}
				}
			}
		})
	}
}

func TestAgentRunRuntimeCapabilitiesValidationAndDeepCopy(t *testing.T) {
	run := testAgentRun()
	run.Spec.Runtime.Container = &nvtv1alpha1.AgentRunRuntimeContainer{
		Capabilities: &nvtv1alpha1.AgentRunRuntimeCapabilities{Add: []corev1.Capability{"SYS_PTRACE"}},
	}
	copy := run.DeepCopyObject().(*nvtv1alpha1.AgentRun)
	copy.Spec.Runtime.Container.Capabilities.Add[0] = "NET_ADMIN"
	if run.Spec.Runtime.Container.Capabilities.Add[0] != "SYS_PTRACE" {
		t.Fatal("runtime capabilities were not deep-copied")
	}
	empty := testAgentRun()
	empty.Spec.Runtime.Container = &nvtv1alpha1.AgentRunRuntimeContainer{
		Capabilities: &nvtv1alpha1.AgentRunRuntimeCapabilities{Add: []corev1.Capability{}},
	}
	emptyCopy := empty.DeepCopyObject().(*nvtv1alpha1.AgentRun)
	if emptyCopy.Spec.Runtime.Container.Capabilities.Add == nil || len(emptyCopy.Spec.Runtime.Container.Capabilities.Add) != 0 {
		t.Fatalf("explicit-empty capability list was not preserved: %#v", emptyCopy.Spec.Runtime.Container.Capabilities.Add)
	}
	for _, test := range []struct {
		name string
		add  []corev1.Capability
	}{
		{name: "unknown", add: []corev1.Capability{"CAP_SYS_PTRACE"}},
		{name: "malformed lowercase", add: []corev1.Capability{"sys_ptrace"}},
		{name: "duplicate", add: []corev1.Capability{"SYS_PTRACE", "SYS_PTRACE"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := testAgentRun()
			invalid.Spec.Runtime.Container = &nvtv1alpha1.AgentRunRuntimeContainer{
				Capabilities: &nvtv1alpha1.AgentRunRuntimeCapabilities{Add: test.add},
			}
			if err := ValidateAgentRunRuntimeCapabilities(invalid); err == nil {
				t.Fatal("invalid capability list was accepted")
			}
			if _, err := DesiredAgentPod(invalid, testScheme(t)); err == nil {
				t.Fatal("invalid capability list reached Pod rendering")
			}
		})
	}
}

func TestAgentCapabilityDoesNotReachTransparentOrEgressContainers(t *testing.T) {
	run := transparentAgentRun(t)
	run.Spec.Runtime.Container = &nvtv1alpha1.AgentRunRuntimeContainer{
		Capabilities: &nvtv1alpha1.AgentRunRuntimeCapabilities{Add: []corev1.Capability{"SYS_PTRACE"}},
	}
	agentPod, err := DesiredAgentPod(run, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, container := range append(append([]corev1.Container(nil), agentPod.Spec.InitContainers...), agentPod.Spec.Containers...) {
		if container.Name == "agent" {
			continue
		}
		assertContainerLacksCapability(t, container, "SYS_PTRACE")
	}
	egressdPod, err := DesiredEgressdPod(run, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, container := range egressdPod.Spec.Containers {
		assertContainerLacksCapability(t, container, "SYS_PTRACE")
	}
}

func assertContainerLacksCapability(t *testing.T, container corev1.Container, capability corev1.Capability) {
	t.Helper()
	if container.SecurityContext == nil || container.SecurityContext.Capabilities == nil {
		return
	}
	for _, added := range container.SecurityContext.Capabilities.Add {
		if added == capability {
			t.Fatalf("capability %q leaked to container %q: %#v", capability, container.Name, container.SecurityContext)
		}
	}
}

// TestDesiredAgentPodNonRootUser pins the opt-in non-root shape: uid/gid 1000,
// HOME + state under /home/agent, pod fsGroup 1000, and the codex auth path +
// group-writable seed under /home/agent.
func TestDesiredAgentPodNonRootUser(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Spec.Runtime.User = nvtv1alpha1.AgentRunUserNonRoot
	agentRun.Spec.RuntimeAuth = &nvtv1alpha1.AgentRunRuntimeAuth{SecretName: "codex-auth"}

	pod, err := DesiredAgentPod(agentRun, testScheme(t))
	if err != nil {
		t.Fatalf("desired pod: %v", err)
	}
	agent := requireContainer(t, *pod, "agent")
	sc := agent.SecurityContext
	if sc == nil || sc.RunAsUser == nil || *sc.RunAsUser != 1000 || sc.RunAsGroup == nil || *sc.RunAsGroup != 1000 {
		t.Fatalf("non-root agent must run as 1000:1000, got %#v", sc)
	}
	if envValue(agent, "HOME") != "/home/agent" {
		t.Fatalf("HOME = %q, want /home/agent", envValue(agent, "HOME"))
	}
	if envValue(agent, "NVT_STATE_DIR") != "/home/agent/.nvt-agent" {
		t.Fatalf("NVT_STATE_DIR = %q", envValue(agent, "NVT_STATE_DIR"))
	}
	if pod.Spec.SecurityContext == nil || pod.Spec.SecurityContext.FSGroup == nil || *pod.Spec.SecurityContext.FSGroup != 1000 {
		t.Fatalf("non-root pod must set fsGroup 1000, got %#v", pod.Spec.SecurityContext)
	}
	assertVolumeMount(t, agent, runtimeAuthHomeName, "/home/agent/.codex", "", false)
	copyContainer := requireInitContainer(t, *pod, "runtime-auth-copy")
	if !strings.Contains(strings.Join(copyContainer.Args, " "), "chmod -R ug+rwX") {
		t.Fatalf("non-root runtime-auth seed must be group-writable, got %#v", copyContainer.Args)
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

func TestRemovedEgressForwardProxyIsRejectedBeforeReconcile(t *testing.T) {
	for _, value := range []bool{true, false} {
		t.Run(fmt.Sprintf("value-%t", value), func(t *testing.T) {
			ctx := context.Background()
			run := testAgentRun()
			run.Spec.EgressForwardProxy = ptrTo(value)
			k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).
				WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
				WithObjects(run).Build()
			reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: testScheme(t)}
			if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(run)}); err == nil ||
				!strings.Contains(err.Error(), "egressForwardProxy is removed; use spec.egressTransport") {
				t.Fatalf("legacy value %t was not rejected explicitly: %v", value, err)
			}
			pods := &corev1.PodList{}
			if err := k8sClient.List(ctx, pods, client.InNamespace(run.Namespace)); err != nil {
				t.Fatal(err)
			}
			if len(pods.Items) != 0 {
				t.Fatalf("legacy value %t created a Pod: %#v", value, pods.Items)
			}
		})
	}
}

func TestEgressTransportAloneSelectsRuntimeTransport(t *testing.T) {
	t.Setenv("NVT_NETWORK_POLICY_CAPABLE", "true")
	redirect := multiGrantMediatedAgentRun()
	redirect.Spec.EgressTransport = nvtv1alpha1.AgentRunEgressTransportRedirect
	forwardProxy := forwardProxyAgentRun()
	transparent := forwardProxyAgentRun()
	transparent.Spec.EgressTransport = nvtv1alpha1.AgentRunEgressTransportTransparent

	tests := []struct {
		name         string
		run          *nvtv1alpha1.AgentRun
		want         nvtv1alpha1.AgentRunEgressTransport
		forwardProxy bool
	}{
		{name: "redirect", run: redirect, want: nvtv1alpha1.AgentRunEgressTransportRedirect},
		{name: "forward proxy", run: forwardProxy, want: nvtv1alpha1.AgentRunEgressTransportForwardProxy, forwardProxy: true},
		{name: "transparent", run: transparent, want: nvtv1alpha1.AgentRunEgressTransportTransparent, forwardProxy: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateAgentRunEgressMode(test.run); err != nil {
				t.Fatalf("transport-only AgentRun rejected: %v", err)
			}
			if got := AgentRunEgressTransport(test.run); got != test.want {
				t.Fatalf("transport = %q, want %q", got, test.want)
			}
			if got := AgentRunEgressForwardProxy(test.run); got != test.forwardProxy {
				t.Fatalf("forward-proxy behavior = %v, want %v", got, test.forwardProxy)
			}
			config := InjectMediatedEgressConfig(map[string]any{}, test.run)
			egress := config["egress"].(map[string]any)
			if got := egress["transport"]; got != string(test.want) {
				t.Fatalf("generated transport = %#v, want %q", got, test.want)
			}
			if _, exists := egress["forward-proxy"]; exists {
				t.Fatalf("generated runtime config retained legacy forward-proxy selector: %#v", egress)
			}
			encoded, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"sidecar", "same-pod", "own-pod", "placement"} {
				if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
					t.Fatalf("generated runtime config contains deployment-topology term %q: %s", forbidden, encoded)
				}
			}
		})
	}

	direct := testAgentRun()
	if got := AgentRunEgressTransport(direct); got != nvtv1alpha1.AgentRunEgressTransportRedirect {
		t.Fatalf("direct default transport changed: %q", got)
	}
	rendered, err := RenderAgentConfigYAML(direct)
	if err != nil {
		t.Fatalf("render direct config: %v", err)
	}
	if strings.Contains(rendered, "\negress:") {
		t.Fatalf("direct mode unexpectedly gained mediated runtime config:\n%s", rendered)
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

// TestReconcileWritesPlaceholderFileBrokerPolicy pins that a placeholder-file
// grant survives broker-policy reconciliation: admission accepts it and
// BrokerAgentGrants serializes it, so ValidateBrokerAgentsPolicy must accept it
// too — otherwise a forward-proxy placeholder-file run is admitted then fails
// to reconcile.
func TestReconcileWritesPlaceholderFileBrokerPolicy(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	agentRun.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	agentRun.Spec.EgressEnforcement = true
	agentRun.Spec.EgressTransport = nvtv1alpha1.AgentRunEgressTransportForwardProxy
	agentRun.Spec.EgressAllowInsecureBroker = true
	agentRun.Spec.Broker = &nvtv1alpha1.AgentRunBroker{
		Grants: []nvtv1alpha1.AgentRunBrokerGrant{
			{Provider: "codex-main", Materialization: nvtv1alpha1.AgentRunGrantPlaceholderFile, Repositories: []string{}, EgressHosts: []string{"chatgpt.com:443"}},
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
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer agent-token" {
			t.Fatal("operator placeholder request did not use the control-plane token")
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"ok":true,"files":[{"path":".codex/auth.json","content":"{\"access_token\":\"NVT-PLACEHOLDER-NOT-A-KEY\"}\n","mode":"0600"}]}`))
	}))
	defer server.Close()
	t.Setenv("NVT_BROKER_URL", server.URL)
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme, BrokerHTTPClient: server.Client()}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("reconcile with placeholder-file grant: %v", err)
	}
	policy := mustParseBrokerAgentsPolicy(t, getBrokerAgentsConfigMap(ctx, t, k8sClient, agentRun.Namespace).Data[brokerAgentsConfigKey])
	agentEntry := requireBrokerAgentEntry(t, policy, AgentRunBrokerID(agentRun.Namespace, agentRun.Name))
	if len(agentEntry.Grants) != 1 || agentEntry.Grants[0].Materialization != "placeholder-file" {
		t.Fatalf("broker policy did not carry the placeholder-file grant: %#v", agentEntry)
	}

	// Direct validation of the serialized policy shape.
	if err := ValidateBrokerAgentsPolicy(policy); err != nil {
		t.Fatalf("ValidateBrokerAgentsPolicy rejected a placeholder-file grant: %v", err)
	}
	configMap := &corev1.ConfigMap{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: AgentConfigMapName(agentRun.Name)}, configMap); err != nil {
		t.Fatal(err)
	}
	rendered := configMap.Data[agentConfigKey]
	if !strings.Contains(rendered, "operator-prepared: true") || !strings.Contains(rendered, "$HOME/.codex/auth.json") || !strings.Contains(rendered, "NVT-PLACEHOLDER-NOT-A-KEY") {
		t.Fatalf("operator did not precompute inert placeholder inputs:\n%s", rendered)
	}
	if strings.Contains(rendered, "agent-token") {
		t.Fatalf("operator embedded its preparation token in agent config:\n%s", rendered)
	}
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

func TestValidateAgentRunEgressModePlaceholderFile(t *testing.T) {
	// Mediated: a placeholder-file grant alongside the header-inject route is
	// accepted (zero-possession materialization).
	mediated := testAgentRun()
	mediated.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	mediated.Spec.EgressAllowInsecureBroker = true
	mediated.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{
		{Provider: "api-main", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject, EgressHosts: []string{"api.example.test:443"}},
		{Provider: "codex-main", Materialization: nvtv1alpha1.AgentRunGrantPlaceholderFile},
	}}
	if err := ValidateAgentRunEgressMode(mediated); err != nil {
		t.Fatalf("mediated placeholder-file grant must be accepted, got %v", err)
	}

	// Direct: a placeholder-file grant is rejected like header-inject — it is a
	// zero-possession mediated mode with no edge to inject at.
	direct := testAgentRun()
	direct.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "codex-main", Materialization: nvtv1alpha1.AgentRunGrantPlaceholderFile,
	}}}
	if err := ValidateAgentRunEgressMode(direct); err == nil ||
		!strings.Contains(err.Error(), "codex-main") || !strings.Contains(err.Error(), "placeholder-file") {
		t.Fatalf("direct placeholder-file grant must be rejected naming the provider, got %v", err)
	}
}

// TestInjectMediatedEgressConfigPlaceholderFile pins that a placeholder-file
// grant reaches the agent egress config (materialization only, no base-url) so
// bootstrap materializes the placeholder auth file.
func TestInjectMediatedEgressConfigPlaceholderFile(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	agentRun.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{
		{Provider: "api-main", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject, EgressHosts: []string{"api.example.test:443"}},
		{Provider: "codex-main", Materialization: nvtv1alpha1.AgentRunGrantPlaceholderFile},
	}}
	config := InjectMediatedEgressConfig(map[string]any{}, agentRun)
	egress := config["egress"].(map[string]any)
	grants := egress["grants"].([]any)
	var placeholder map[string]any
	for _, raw := range grants {
		grant := raw.(map[string]any)
		if grant["provider"] == "codex-main" {
			placeholder = grant
		}
	}
	if placeholder == nil {
		t.Fatalf("placeholder-file grant missing from agent egress config: %#v", grants)
	}
	if placeholder["materialization"] != "placeholder-file" {
		t.Fatalf("unexpected materialization: %#v", placeholder)
	}
	if _, hasBaseURL := placeholder["base-url"]; hasBaseURL {
		t.Fatalf("placeholder-file grant must not carry a base-url: %#v", placeholder)
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

	// A realistic mediated run
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

func TestRenderEgressdConfigAllowInsecureUpstream(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	agentRun.Spec.EgressAllowInsecureBroker = true
	agentRun.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "echo-main", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject,
		EgressHosts: []string{"nvt-smoke-echo.nvt.svc.cluster.local:443"}, AllowInsecureUpstream: true,
	}}}

	rendered, err := RenderEgressdConfigJSON(agentRun)
	if err != nil {
		t.Fatalf("render egressd config: %v", err)
	}
	if !strings.Contains(rendered, `"allow_insecure_upstream": true`) {
		t.Fatalf("expected allow_insecure_upstream true for the grant:\n%s", rendered)
	}

	// The default (unset) stays false — no accidental plaintext upstream.
	agentRun.Spec.Broker.Grants[0].AllowInsecureUpstream = false
	rendered, err = RenderEgressdConfigJSON(agentRun)
	if err != nil {
		t.Fatalf("render egressd config: %v", err)
	}
	if !strings.Contains(rendered, `"allow_insecure_upstream": false`) {
		t.Fatalf("expected allow_insecure_upstream false by default:\n%s", rendered)
	}
}

func TestRenderEgressdConfigQuota(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	agentRun.Spec.EgressAllowInsecureBroker = true
	agentRun.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "api-main", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject,
		EgressHosts: []string{"api.example.test:443"}, Quota: &nvtv1alpha1.AgentRunGrantQuota{Requests: 42},
	}}}

	rendered, err := RenderEgressdConfigJSON(agentRun)
	if err != nil {
		t.Fatalf("render egressd config: %v", err)
	}
	if !strings.Contains(rendered, `"max_requests": 42`) {
		t.Fatalf("expected max_requests 42:\n%s", rendered)
	}

	// Absent quota renders no max_requests (unlimited).
	agentRun.Spec.Broker.Grants[0].Quota = nil
	rendered, err = RenderEgressdConfigJSON(agentRun)
	if err != nil {
		t.Fatalf("render egressd config: %v", err)
	}
	if strings.Contains(rendered, "max_requests") {
		t.Fatalf("absent quota must omit max_requests:\n%s", rendered)
	}
}

func TestValidateAgentRunEgressModeRejectsInvalidQuota(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	agentRun.Spec.EgressAllowInsecureBroker = true
	agentRun.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "api-main", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject,
		EgressHosts: []string{"api.example.test:443"}, Quota: &nvtv1alpha1.AgentRunGrantQuota{Requests: 0},
	}}}
	if err := ValidateAgentRunEgressMode(agentRun); err == nil || !strings.Contains(err.Error(), "api-main") || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("expected quota rejection naming the grant, got %v", err)
	}
}

func insecureUpstreamAgentRun() *nvtv1alpha1.AgentRun {
	agentRun := testAgentRun()
	agentRun.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	agentRun.Spec.EgressAllowInsecureBroker = true
	agentRun.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "echo-main", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject,
		EgressHosts: []string{"nvt-smoke-echo.nvt.svc.cluster.local:443"}, AllowInsecureUpstream: true,
	}}}
	return agentRun
}

func TestValidateAllowInsecureUpstreamRequiresOptIn(t *testing.T) {
	// Without the operator opt-in, an allowInsecureUpstream grant is rejected
	// so a bad spec cannot silently downgrade the provider leg to plaintext.
	run := insecureUpstreamAgentRun()
	if err := ValidateAgentRunEgressMode(run); err == nil ||
		!strings.Contains(err.Error(), "NVT_ALLOW_INSECURE_UPSTREAMS") || !strings.Contains(err.Error(), "echo-main") {
		t.Fatalf("expected opt-in rejection naming the grant, got %v", err)
	}

	// With the cluster/test opt-in it is allowed for a non-git grant.
	t.Setenv("NVT_ALLOW_INSECURE_UPSTREAMS", "1")
	if err := ValidateAgentRunEgressMode(insecureUpstreamAgentRun()); err != nil {
		t.Fatalf("allowInsecureUpstream must be accepted under the opt-in, got %v", err)
	}
}

func TestValidateAllowInsecureUpstreamRejectedForGit(t *testing.T) {
	t.Setenv("NVT_ALLOW_INSECURE_UPSTREAMS", "1")
	run := insecureUpstreamAgentRun()
	run.Spec.Broker.Grants[0].Git = true
	if err := ValidateAgentRunEgressMode(run); err == nil || !strings.Contains(err.Error(), "git") {
		t.Fatalf("allowInsecureUpstream must never be allowed for a git grant even with the opt-in, got %v", err)
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

func setTLSBrokerEnv(t *testing.T) {
	t.Helper()
	t.Setenv("NVT_BROKER_URL", "https://nvt-broker:7347")
	t.Setenv("NVT_BROKER_CA_SECRET", "nvt-broker-tls")
}

func TestTLSBrokerMediatedPodMountsBrokerCA(t *testing.T) {
	setTLSBrokerEnv(t)
	pod, err := DesiredAgentPod(multiGrantMediatedAgentRun(), testScheme(t))
	if err != nil {
		t.Fatalf("desired pod: %v", err)
	}
	caVolume := requireVolume(t, *pod, brokerCAVolumeName)
	if caVolume.Secret == nil || caVolume.Secret.SecretName != "nvt-broker-tls" {
		t.Fatalf("expected broker CA Secret volume, got %#v", caVolume)
	}
	// Only the public certificate may be projected — never the serving key.
	if len(caVolume.Secret.Items) != 1 || caVolume.Secret.Items[0].Key != brokerCAKey {
		t.Fatalf("broker CA volume must project only %s, got %#v", brokerCAKey, caVolume.Secret.Items)
	}

	agent := requireContainer(t, *pod, "agent")
	assertVolumeMount(t, agent, brokerCAVolumeName, agentBrokerCAMount, "", true)
	if envValue(agent, "NVT_BROKER_URL") != "https://nvt-broker:7347" {
		t.Fatalf("expected https broker URL on agent, got %#v", agent.Env)
	}
	if envValue(agent, "NVT_BROKER_CA_FILE") != agentBrokerCAFile {
		t.Fatalf("agent env missing NVT_BROKER_CA_FILE: %#v", agent.Env)
	}

	egressd := requireContainer(t, *pod, "egressd")
	assertVolumeMount(t, egressd, brokerCAVolumeName, egressdBrokerCAMount, "", true)
	// egressd takes the broker URL from its JSON config, not the environment.
	if findEnvVar(egressd, "NVT_BROKER_URL") != nil {
		t.Fatalf("egressd must not carry NVT_BROKER_URL env: %#v", egressd.Env)
	}
}

func TestTLSBrokerDirectPodGetsAgentCAOnly(t *testing.T) {
	setTLSBrokerEnv(t)
	pod, err := DesiredAgentPod(testAgentRun(), testScheme(t))
	if err != nil {
		t.Fatalf("desired pod: %v", err)
	}
	// Direct runs still talk to the broker via brokerctl, so the CA rides
	// along even without the egressd sidecar.
	requireVolume(t, *pod, brokerCAVolumeName)
	agent := requireContainer(t, *pod, "agent")
	assertVolumeMount(t, agent, brokerCAVolumeName, agentBrokerCAMount, "", true)
	if envValue(agent, "NVT_BROKER_CA_FILE") != agentBrokerCAFile {
		t.Fatalf("agent env missing NVT_BROKER_CA_FILE: %#v", agent.Env)
	}
	if _, found := findContainer(pod.Spec.Containers, "egressd"); found {
		t.Fatalf("direct mode rendered egressd sidecar: %#v", pod.Spec.Containers)
	}
}

func TestDefaultBrokerPodHasNoBrokerCAVolume(t *testing.T) {
	pod, err := DesiredAgentPod(multiGrantMediatedAgentRun(), testScheme(t))
	if err != nil {
		t.Fatalf("desired pod: %v", err)
	}
	for _, volume := range pod.Spec.Volumes {
		if volume.Name == brokerCAVolumeName {
			t.Fatalf("plaintext broker must not mount a broker CA volume: %#v", pod.Spec.Volumes)
		}
	}
	agent := requireContainer(t, *pod, "agent")
	if findEnvVar(agent, "NVT_BROKER_CA_FILE") != nil {
		t.Fatalf("plaintext broker agent must not carry NVT_BROKER_CA_FILE: %#v", agent.Env)
	}
}

func TestTLSBrokerRenderEgressdConfigPinsCA(t *testing.T) {
	setTLSBrokerEnv(t)
	agentRun := multiGrantMediatedAgentRun()
	// The spec-level escape hatch must not weaken a CA-pinned broker leg.
	agentRun.Spec.EgressAllowInsecureBroker = true
	rendered, err := RenderEgressdConfigJSON(agentRun)
	if err != nil {
		t.Fatalf("render egressd config: %v", err)
	}
	if !strings.Contains(rendered, `"broker_url": "https://nvt-broker:7347"`) {
		t.Fatalf("expected https broker_url:\n%s", rendered)
	}
	if !strings.Contains(rendered, `"broker_ca_file": "`+egressdBrokerCAFile+`"`) {
		t.Fatalf("expected pinned broker_ca_file:\n%s", rendered)
	}
	if !strings.Contains(rendered, `"allow_insecure_broker": false`) {
		t.Fatalf("CA-pinned broker leg must not allow insecure broker:\n%s", rendered)
	}
}

func TestTLSBrokerValidationAcceptsMediatedWithoutInsecureFlag(t *testing.T) {
	setTLSBrokerEnv(t)
	agentRun := multiGrantMediatedAgentRun()
	agentRun.Spec.EgressAllowInsecureBroker = false
	if err := ValidateAgentRunEgressMode(agentRun); err != nil {
		t.Fatalf("mediated over TLS broker must not require egressAllowInsecureBroker, got %v", err)
	}
}

func TestValidateAgentRunEgressModeEnforcementRequiresMediated(t *testing.T) {
	direct := testAgentRun()
	direct.Spec.EgressEnforcement = true
	if err := ValidateAgentRunEgressMode(direct); err == nil || !strings.Contains(err.Error(), "egressEnforcement") {
		t.Fatalf("expected direct+enforcement rejection naming the field, got %v", err)
	}

	enforced := multiGrantMediatedAgentRun()
	enforced.Spec.EgressEnforcement = true
	if err := ValidateAgentRunEgressMode(enforced); err != nil {
		t.Fatalf("mediated enforcement run must validate, got %v", err)
	}
}

func TestBrokerTLSConfigRejectsHTTPSWithoutCASecret(t *testing.T) {
	t.Setenv("NVT_BROKER_URL", "https://nvt-broker:7347")
	t.Setenv("NVT_BROKER_CA_SECRET", "")
	if err := ValidateBrokerTLSConfig(); err == nil || !strings.Contains(err.Error(), "NVT_BROKER_CA_SECRET") {
		t.Fatalf("expected https-without-CA-secret rejection, got %v", err)
	}
	if err := ValidateAgentRunEgressMode(testAgentRun()); err == nil || !strings.Contains(err.Error(), "NVT_BROKER_CA_SECRET") {
		t.Fatalf("expected validation rejection, got %v", err)
	}
	if _, err := RenderEgressdConfigJSON(multiGrantMediatedAgentRun()); err == nil || !strings.Contains(err.Error(), "NVT_BROKER_CA_SECRET") {
		t.Fatalf("expected egressd render rejection, got %v", err)
	}
	if _, err := DesiredAgentPod(testAgentRun(), testScheme(t)); err == nil || !strings.Contains(err.Error(), "NVT_BROKER_CA_SECRET") {
		t.Fatalf("expected pod render rejection, got %v", err)
	}
}

func testBrokerCASecret(namespace string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "nvt-broker-tls", Namespace: namespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       data,
	}
}

func TestReconcileRejectsMissingBrokerCASecret(t *testing.T) {
	setTLSBrokerEnv(t)
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := multiGrantMediatedAgentRun()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err == nil || !strings.Contains(err.Error(), "broker CA Secret") || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected missing broker CA Secret error, got %v", err)
	}
	assertAgentPodMissing(ctx, t, k8sClient, agentRun)
}

func TestReconcileRejectsBrokerCASecretWithoutCACrt(t *testing.T) {
	setTLSBrokerEnv(t)
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := multiGrantMediatedAgentRun()
	caSecret := testBrokerCASecret(agentRun.Namespace, map[string][]byte{
		"tls.crt": []byte("fixture-cert"),
		"tls.key": []byte("fixture-key"),
	})
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, caSecret, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err == nil || !strings.Contains(err.Error(), "missing key ca.crt") {
		t.Fatalf("expected ca.crt-missing error naming the key, got %v", err)
	}
	assertAgentPodMissing(ctx, t, k8sClient, agentRun)
}

func TestReconcileTLSBrokerCreatesPodWhenCASecretValid(t *testing.T) {
	setTLSBrokerEnv(t)
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := multiGrantMediatedAgentRun()
	caSecret := testBrokerCASecret(agentRun.Namespace, map[string][]byte{brokerCAKey: []byte("fixture-ca")})
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, caSecret, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var pod corev1.Pod
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: AgentPodName(agentRun.Name)}, &pod); err != nil {
		t.Fatalf("expected agent Pod, got %v", err)
	}
	requireVolume(t, pod, brokerCAVolumeName)
}

func enforcedAgentRun() *nvtv1alpha1.AgentRun {
	agentRun := multiGrantMediatedAgentRun()
	agentRun.Spec.EgressEnforcement = true
	return agentRun
}

func markPodReady(ctx context.Context, t *testing.T, k8sClient client.Client, namespace, name string) {
	t.Helper()
	var pod corev1.Pod
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &pod); err != nil {
		t.Fatalf("get pod %s: %v", name, err)
	}
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := k8sClient.Status().Update(ctx, &pod); err != nil {
		t.Fatalf("mark pod %s ready: %v", name, err)
	}
}

func runCondition(agentRun *nvtv1alpha1.AgentRun, conditionType string) *metav1.Condition {
	for index := range agentRun.Status.Conditions {
		if agentRun.Status.Conditions[index].Type == conditionType {
			return &agentRun.Status.Conditions[index]
		}
	}
	return nil
}

func containsIPNet(ranges []*net.IPNet, cidr string) bool {
	_, want, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	for _, got := range ranges {
		if got.String() == want.String() {
			return true
		}
	}
	return false
}

// TestEnforcementReconcileProgression drives the full condition machine:
// egressd Pod/Service first (never behind the broker policy), agent Pod only
// after EgressdReady and EgressCAPublished, CA ConfigMap bytes exactly what
// the durable CA Secret contains.
func TestEnforcementReconcileProgression(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := enforcedAgentRun()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	// Pass 1: egressd Pod + Service exist, agent Pod does not; the machine
	// waits on egressd readiness.
	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile pass 1: %v", err)
	}
	if result.RequeueAfter == 0 {
		t.Fatal("expected requeue while egressd is not ready")
	}
	var egressdPod corev1.Pod
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: EgressdPodName(agentRun.Name)}, &egressdPod); err != nil {
		t.Fatalf("expected egressd Pod, got %v", err)
	}
	if egressdPod.Labels[agentRunLabelKey] != agentRun.Name || egressdPod.Labels[roleLabelKey] != roleLabelEgressd {
		t.Fatalf("egressd Pod missing pairing labels: %#v", egressdPod.Labels)
	}
	var service corev1.Service
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: EgressdServiceName(agentRun.Name)}, &service); err != nil {
		t.Fatalf("expected egressd Service, got %v", err)
	}
	if len(service.Spec.Ports) != 3 {
		t.Fatalf("expected CA port + 2 route ports, got %#v", service.Spec.Ports)
	}
	var caSecret corev1.Secret
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: EgressCASecretName(agentRun.Name)}, &caSecret); err != nil {
		t.Fatalf("expected egress CA Secret, got %v", err)
	}
	if caSecret.Name == EgressCAConfigMapName(agentRun.Name) {
		t.Fatalf("private CA Secret must not share name with public ConfigMap %q", caSecret.Name)
	}
	if err := validateCACertificatePEM(caSecret.Data[egressCACertKey]); err != nil {
		t.Fatalf("generated egress CA certificate is invalid: %v", err)
	}
	certs, err := parseCACertificatesPEM(caSecret.Data[egressCACertKey])
	if err != nil {
		t.Fatal(err)
	}
	if !containsIPNet(certs[0].PermittedIPRanges, "127.0.0.0/8") ||
		!containsIPNet(certs[0].PermittedIPRanges, "::1/128") ||
		len(certs[0].PermittedIPRanges) != 2 {
		t.Fatalf("egress CA permitted IP ranges = %v", certs[0].PermittedIPRanges)
	}
	if !strings.Contains(string(caSecret.Data[egressCAKeyKey]), "PRIVATE KEY") {
		t.Fatal("egress CA Secret missing private key material")
	}
	egressd := requireContainer(t, egressdPod, "egressd")
	mountedCASecret := false
	for _, mount := range egressd.VolumeMounts {
		if mount.Name == egressCASecretVolume {
			mountedCASecret = true
		}
	}
	if !mountedCASecret {
		t.Fatalf("egressd Pod does not mount CA Secret volume: %#v", egressd.VolumeMounts)
	}
	assertAgentPodMissing(ctx, t, k8sClient, agentRun)
	var afterFirst nvtv1alpha1.AgentRun
	if err := k8sClient.Get(ctx, clientKey(agentRun), &afterFirst); err != nil {
		t.Fatal(err)
	}
	for conditionType, want := range map[string]metav1.ConditionStatus{
		ConditionEgressdCreated:    metav1.ConditionTrue,
		ConditionBrokerPolicyReady: metav1.ConditionTrue,
		ConditionEgressdReady:      metav1.ConditionFalse,
	} {
		condition := runCondition(&afterFirst, conditionType)
		if condition == nil || condition.Status != want {
			t.Fatalf("after pass 1 condition %s = %#v, want %s", conditionType, condition, want)
		}
	}
	if runCondition(&afterFirst, ConditionEgressCAPublished) != nil {
		t.Fatal("EgressCAPublished must not be set before egressd is ready")
	}
	// Pass 2: egressd ready -> CA published from Secret, agent Pod created.
	markPodReady(ctx, t, k8sClient, agentRun.Namespace, EgressdPodName(agentRun.Name))
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("reconcile pass 2: %v", err)
	}
	var caConfigMap corev1.ConfigMap
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: EgressCAConfigMapName(agentRun.Name)}, &caConfigMap); err != nil {
		t.Fatalf("expected egress CA ConfigMap, got %v", err)
	}
	if caConfigMap.Data[egressCACertKey] != string(caSecret.Data[egressCACertKey]) {
		t.Fatal("published ConfigMap bytes differ from the CA Secret certificate")
	}
	if strings.Contains(fmt.Sprint(caConfigMap.Data), "PRIVATE KEY") {
		t.Fatal("published CA ConfigMap leaked private key material")
	}
	agentPod := getAgentPod(ctx, t, k8sClient, agentRun)
	if agentPod.Labels[agentRunLabelKey] != agentRun.Name || agentPod.Labels[roleLabelKey] != roleLabelAgent {
		t.Fatalf("agent Pod missing pairing labels: %#v", agentPod.Labels)
	}
	if _, found := findContainer(agentPod.Spec.Containers, "egressd"); found {
		t.Fatal("enforcement agent Pod rendered a same-Pod egressd sidecar")
	}
	caVolume := requireVolume(t, agentPod, egressCAVolumeName)
	if caVolume.ConfigMap == nil || caVolume.ConfigMap.Name != EgressCAConfigMapName(agentRun.Name) {
		t.Fatalf("agent CA volume must come from the published ConfigMap: %#v", caVolume)
	}
	for _, volume := range agentPod.Spec.Volumes {
		if volume.Secret != nil && volume.Secret.SecretName == EgressCASecretName(agentRun.Name) {
			t.Fatal("agent Pod must not mount the private egress CA Secret")
		}
	}
	agent := requireContainer(t, agentPod, "agent")
	if envValue(agent, "NVT_EGRESS_CA_FILE") != egressCAFilePath {
		t.Fatalf("agent env missing NVT_EGRESS_CA_FILE: %#v", agent.Env)
	}
	var final nvtv1alpha1.AgentRun
	if err := k8sClient.Get(ctx, clientKey(agentRun), &final); err != nil {
		t.Fatal(err)
	}
	for _, conditionType := range []string{ConditionBrokerPolicyReady, ConditionEgressdCreated, ConditionEgressdReady, ConditionEgressCAPublished} {
		condition := runCondition(&final, conditionType)
		if condition == nil || condition.Status != metav1.ConditionTrue {
			t.Fatalf("final condition %s = %#v, want True", conditionType, condition)
		}
	}
}

// TestEnforcementEgressdNeverReady pins the stuck state: without egressd
// readiness the machine keeps requeuing and never creates the agent Pod.
func TestEnforcementEgressdNeverReady(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := enforcedAgentRun()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
	for pass := 0; pass < 3; pass++ {
		result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
		if err != nil {
			t.Fatalf("reconcile pass %d: %v", pass, err)
		}
		if result.RequeueAfter == 0 {
			t.Fatalf("pass %d: expected requeue while egressd is not ready", pass)
		}
	}
	assertAgentPodMissing(ctx, t, k8sClient, agentRun)
}

// TestEnforcementCASecretInvalid pins the loud CA failure: invalid Secret
// material is never published, the condition carries the reason, and the agent
// Pod is not created.
func TestEnforcementCASecretInvalid(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := enforcedAgentRun()
	keyPEM := "-----BEGIN EC PRIVATE KEY-----\nZml4dHVyZQ==\n-----END EC PRIVATE KEY-----\n"
	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      EgressCASecretName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    agentRunLabels(agentRun.Name),
		},
		Data: map[string][]byte{
			egressCACertKey: []byte(keyPEM),
			egressCAKeyKey:  []byte(keyPEM),
		},
	}
	if err := controllerutil.SetControllerReference(agentRun, caSecret, scheme); err != nil {
		t.Fatal(err)
	}
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, caSecret, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("expected invalid CA material error, got %v", err)
	}
	var caConfigMap corev1.ConfigMap
	if getErr := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: EgressCAConfigMapName(agentRun.Name)}, &caConfigMap); !errors.IsNotFound(getErr) {
		t.Fatalf("non-certificate material must not be published, got %v", getErr)
	}
	assertAgentPodMissing(ctx, t, k8sClient, agentRun)
}

func TestEnforcementCASecretMismatchedKey(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := enforcedAgentRun()
	certData, err := generateEgressCASecretData(egressdLeafDNSNames(agentRun))
	if err != nil {
		t.Fatal(err)
	}
	keyData, err := generateEgressCASecretData(egressdLeafDNSNames(agentRun))
	if err != nil {
		t.Fatal(err)
	}
	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      EgressCASecretName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    agentRunLabels(agentRun.Name),
		},
		Data: map[string][]byte{
			egressCACertKey: certData[egressCACertKey],
			egressCAKeyKey:  keyData[egressCAKeyKey],
		},
	}
	if err := controllerutil.SetControllerReference(agentRun, caSecret, scheme); err != nil {
		t.Fatal(err)
	}
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, caSecret, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected mismatched CA keypair error, got %v", err)
	}
	assertAgentPodMissing(ctx, t, k8sClient, agentRun)
}

// TestEnforcementRenderedConfigs pins the own-Pod rendering: all routes on
// the Pod network with TLS, CA served from a durable mounted keypair, leaf
// names scoped to the per-run Service, base-urls through the Service.
func TestEnforcementRenderedConfigs(t *testing.T) {
	agentRun := enforcedAgentRun()
	rendered, err := RenderEgressdConfigJSON(agentRun)
	if err != nil {
		t.Fatalf("render egressd config: %v", err)
	}
	for _, want := range []string{
		`"listen": "0.0.0.0:8471"`,
		`"listen": "0.0.0.0:8472"`,
		`"serve_addr": "0.0.0.0:8470"`,
		fmt.Sprintf("%q", egressCASecretCert),
		fmt.Sprintf("%q", egressCASecretKeyFile),
		fmt.Sprintf("%q", EgressdServiceName(agentRun.Name)),
		fmt.Sprintf("%q", EgressdServiceName(agentRun.Name)+"."+agentRun.Namespace+".svc"),
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("enforcement egressd config missing %s:\n%s", want, rendered)
		}
	}
	if strings.Count(rendered, `"listen_tls": "ca"`) != 2 {
		t.Fatalf("every enforcement route must terminate TLS:\n%s", rendered)
	}
	if strings.Contains(rendered, "publish_dir") || strings.Contains(rendered, "127.0.0.1") {
		t.Fatalf("enforcement config must not publish to an agent volume or bind loopback:\n%s", rendered)
	}

	injected := InjectMediatedEgressConfig(map[string]any{}, agentRun)
	egress := injected["egress"].(map[string]any)
	grants := egress["grants"].([]any)
	if len(grants) != 2 {
		t.Fatalf("expected 2 injected grants, got %#v", grants)
	}
	first := grants[0].(map[string]any)
	if first["base-url"] != fmt.Sprintf("https://%s:8471", EgressdServiceName(agentRun.Name)) {
		t.Fatalf("enforcement base-url must use the Service name over https, got %#v", first)
	}
}

// TestEnforcementNetworkPolicyShape pins the fence: agent default-deny
// egress with exactly DNS/paired-egressd, egressd ingress
// only from the paired agent, and mirrored public HTTP/HTTPS upstream rules.
func TestEnforcementNetworkPolicyShape(t *testing.T) {
	agentRun := enforcedAgentRun()
	scheme := testScheme(t)
	agentPolicy, err := DesiredAgentNetworkPolicy(agentRun, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if agentPolicy.Spec.PodSelector.MatchLabels[agentRunLabelKey] != agentRun.Name ||
		agentPolicy.Spec.PodSelector.MatchLabels[roleLabelKey] != roleLabelAgent {
		t.Fatalf("agent policy selector must pin the paired agent Pod: %#v", agentPolicy.Spec.PodSelector)
	}
	if len(agentPolicy.Spec.PolicyTypes) != 1 || agentPolicy.Spec.PolicyTypes[0] != networkingv1.PolicyTypeEgress {
		t.Fatalf("agent policy must be egress-only (ingress unrestricted this PR): %#v", agentPolicy.Spec.PolicyTypes)
	}
	if len(agentPolicy.Spec.Egress) != 2 {
		t.Fatalf("agent policy must allow exactly DNS and paired egressd: %#v", agentPolicy.Spec.Egress)
	}
	for _, rule := range agentPolicy.Spec.Egress {
		for _, peer := range rule.To {
			if peer.IPBlock != nil {
				t.Fatalf("agent policy must not carry any internet CIDR: %#v", peer)
			}
		}
	}
	pairedRule := agentPolicy.Spec.Egress[1]
	if pairedRule.To[0].PodSelector.MatchLabels[agentRunLabelKey] != agentRun.Name ||
		pairedRule.To[0].PodSelector.MatchLabels[roleLabelKey] != roleLabelEgressd {
		t.Fatalf("agent policy egressd peer must pin the paired run: %#v", pairedRule.To[0])
	}

	egressdPolicy, err := DesiredEgressdNetworkPolicy(agentRun, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if len(egressdPolicy.Spec.Ingress) != 2 ||
		egressdPolicy.Spec.Ingress[0].From[0].PodSelector.MatchLabels[agentRunLabelKey] != agentRun.Name ||
		egressdPolicy.Spec.Ingress[0].From[0].PodSelector.MatchLabels[roleLabelKey] != roleLabelAgent {
		t.Fatalf("egressd ingress[0] must come from the paired agent: %#v", egressdPolicy.Spec.Ingress)
	}
	// The operator reaches only the CA port, never the route ports.
	operatorIngress := egressdPolicy.Spec.Ingress[1]
	if operatorIngress.From[0].PodSelector.MatchLabels["app.kubernetes.io/name"] != "nvt-operator" {
		t.Fatalf("egressd ingress[1] must admit the operator: %#v", operatorIngress)
	}
	if len(operatorIngress.Ports) != 1 || operatorIngress.Ports[0].Port.IntValue() != egressCAPort {
		t.Fatalf("operator ingress must be the CA port only: %#v", operatorIngress.Ports)
	}
	upstream := egressdPolicy.Spec.Egress[len(egressdPolicy.Spec.Egress)-2]
	if upstream.To[0].IPBlock == nil || upstream.To[0].IPBlock.CIDR != "0.0.0.0/0" {
		t.Fatalf("egressd upstream rule must be the documented coarse fence: %#v", upstream)
	}
	if len(upstream.Ports) != 2 || upstream.Ports[0].Port.IntValue() != 80 || upstream.Ports[1].Port.IntValue() != 443 {
		t.Fatalf("egressd upstream rule must use the shared HTTP/HTTPS ports: %#v", upstream.Ports)
	}
	excepts := strings.Join(upstream.To[0].IPBlock.Except, ",")
	for _, want := range []string{"10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4"} {
		if !strings.Contains(excepts, want) {
			t.Fatalf("IPv4 egress policy missing %s: %v", want, upstream.To[0].IPBlock.Except)
		}
	}
	ipv6 := egressdPolicy.Spec.Egress[len(egressdPolicy.Spec.Egress)-1]
	if ipv6.To[0].IPBlock == nil || ipv6.To[0].IPBlock.CIDR != "::/0" {
		t.Fatalf("missing IPv6 external TCP policy: %#v", ipv6)
	}
	ipv6Excepts := strings.Join(ipv6.To[0].IPBlock.Except, ",")
	for _, want := range []string{"64:ff9b::/96", "2002::/16", "fc00::/7", "fe80::/10", "fec0::/10"} {
		if !strings.Contains(ipv6Excepts, want) {
			t.Fatalf("IPv6 egress policy missing %s: %v", want, ipv6.To[0].IPBlock.Except)
		}
	}
	if strings.Contains(ipv6Excepts, "::ffff:") {
		t.Fatalf("Kubernetes rejects mapped IPv6 prefixes in ipBlock.except: %v", ipv6.To[0].IPBlock.Except)
	}
}

// TestNonEnforcementRendersZeroPolicies pins that direct mode and same-Pod
// mediated mode render exactly today's shape — no NetworkPolicies at all.
func TestNonEnforcementRendersZeroPolicies(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	for _, agentRun := range []*nvtv1alpha1.AgentRun{testAgentRun(), multiGrantMediatedAgentRun()} {
		k8sClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithStatusSubresource(&corev1.Pod{}, &nvtv1alpha1.AgentRun{}).
			WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
			Build()
		reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
		if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
			t.Fatalf("reconcile %s: %v", agentRun.Name, err)
		}
		var policies networkingv1.NetworkPolicyList
		if err := k8sClient.List(ctx, &policies, client.InNamespace(agentRun.Namespace)); err != nil {
			t.Fatal(err)
		}
		if len(policies.Items) != 0 {
			t.Fatalf("%s mode rendered NetworkPolicies: %#v", agentRun.Spec.Egress, policies.Items)
		}
		var pods corev1.PodList
		if err := k8sClient.List(ctx, &pods, client.InNamespace(agentRun.Namespace)); err != nil {
			t.Fatal(err)
		}
		if len(pods.Items) != 1 {
			t.Fatalf("%s mode must render exactly the agent Pod, got %d pods", agentRun.Spec.Egress, len(pods.Items))
		}
	}
}

// TestEnforcementObjectsAllOwned pins GC: every per-run enforcement object
// carries the AgentRun controller reference, so deleting the run leaves no
// orphans (the kind smoke asserts the end-to-end deletion).
func TestEnforcementObjectsAllOwned(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := enforcedAgentRun()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatal(err)
	}
	markPodReady(ctx, t, k8sClient, agentRun.Namespace, EgressdPodName(agentRun.Name))
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatal(err)
	}

	var fetched nvtv1alpha1.AgentRun
	if err := k8sClient.Get(ctx, clientKey(agentRun), &fetched); err != nil {
		t.Fatal(err)
	}
	assertControlled := func(object client.Object, description string) {
		t.Helper()
		if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: object.GetName()}, object); err != nil {
			t.Fatalf("get %s: %v", description, err)
		}
		if !metav1.IsControlledBy(object, &fetched) {
			t.Fatalf("%s is not owned by the AgentRun; it would orphan on deletion", description)
		}
	}
	assertControlled(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: AgentPodName(agentRun.Name)}}, "agent Pod")
	assertControlled(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: EgressdPodName(agentRun.Name)}}, "egressd Pod")
	assertControlled(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: EgressdServiceName(agentRun.Name)}}, "egressd Service")
	assertControlled(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: EgressCAConfigMapName(agentRun.Name)}}, "egress CA ConfigMap")
	assertControlled(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: EgressdConfigMapName(agentRun.Name)}}, "egressd config ConfigMap")
	assertControlled(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: AgentConfigMapName(agentRun.Name)}}, "agent config ConfigMap")
	assertControlled(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: BrokerTokenSecretName(agentRun.Name)}}, "broker token Secret")
	assertControlled(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: EgressTokenSecretName(agentRun.Name)}}, "egress token Secret")
	assertControlled(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: EgressCASecretName(agentRun.Name)}}, "egress CA Secret")
	callbackSecret := &corev1.Secret{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: CallbackTokenSecretName(agentRun.Name)}, callbackSecret); !errors.IsNotFound(err) {
		t.Fatalf("literal zero-secret run unexpectedly created callback Secret: %v", err)
	}
	assertControlled(&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: AgentNetworkPolicyName(agentRun.Name)}}, "agent NetworkPolicy")
	assertControlled(&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: EgressdNetworkPolicyName(agentRun.Name)}}, "egressd NetworkPolicy")
}

func TestEnforcementRepairsActiveNetworkPolicyAndEgressdObjects(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := enforcedAgentRun()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatal(err)
	}
	markPodReady(ctx, t, k8sClient, agentRun.Namespace, EgressdPodName(agentRun.Name))
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatal(err)
	}

	var caSecretBefore corev1.Secret
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: EgressCASecretName(agentRun.Name)}, &caSecretBefore); err != nil {
		t.Fatal(err)
	}
	var caConfigMapBefore corev1.ConfigMap
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: EgressCAConfigMapName(agentRun.Name)}, &caConfigMapBefore); err != nil {
		t.Fatal(err)
	}
	var agentPod corev1.Pod
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: AgentPodName(agentRun.Name)}, &agentPod); err != nil {
		t.Fatal(err)
	}
	agentPod.Labels = map[string]string{"mutated": "true", roleLabelKey: "wrong"}
	if err := k8sClient.Update(ctx, &agentPod); err != nil {
		t.Fatal(err)
	}

	var policy networkingv1.NetworkPolicy
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: AgentNetworkPolicyName(agentRun.Name)}, &policy); err != nil {
		t.Fatal(err)
	}
	policy.Spec.Egress = nil
	policy.Labels = map[string]string{"mutated": "true"}
	if err := k8sClient.Update(ctx, &policy); err != nil {
		t.Fatal(err)
	}
	if err := k8sClient.Delete(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: agentRun.Namespace, Name: EgressdPodName(agentRun.Name)}}); err != nil {
		t.Fatal(err)
	}
	if err := k8sClient.Delete(ctx, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: agentRun.Namespace, Name: EgressdServiceName(agentRun.Name)}}); err != nil {
		t.Fatal(err)
	}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatal(err)
	}
	var repairedPolicy networkingv1.NetworkPolicy
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: AgentNetworkPolicyName(agentRun.Name)}, &repairedPolicy); err != nil {
		t.Fatal(err)
	}
	desiredPolicy, err := DesiredAgentNetworkPolicy(agentRun, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(repairedPolicy.Labels, desiredPolicy.Labels) || !reflect.DeepEqual(repairedPolicy.Spec, desiredPolicy.Spec) {
		t.Fatalf("agent NetworkPolicy was not repaired:\nlabels=%#v\nspec=%#v", repairedPolicy.Labels, repairedPolicy.Spec)
	}
	var repairedAgentPod corev1.Pod
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: AgentPodName(agentRun.Name)}, &repairedAgentPod); err != nil {
		t.Fatal(err)
	}
	if repairedAgentPod.Labels[agentRunLabelKey] != agentRun.Name || repairedAgentPod.Labels[roleLabelKey] != roleLabelAgent {
		t.Fatalf("agent Pod pairing labels were not repaired: %#v", repairedAgentPod.Labels)
	}
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: EgressdPodName(agentRun.Name)}, &corev1.Pod{}); err != nil {
		t.Fatalf("egressd Pod was not recreated: %v", err)
	}
	var repairedService corev1.Service
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: EgressdServiceName(agentRun.Name)}, &repairedService); err != nil {
		t.Fatalf("egressd Service was not recreated: %v", err)
	}
	desiredService, err := DesiredEgressdService(agentRun, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(repairedService.Spec.Selector, desiredService.Spec.Selector) || !reflect.DeepEqual(repairedService.Spec.Ports, desiredService.Spec.Ports) {
		t.Fatalf("egressd Service was not repaired: %#v", repairedService.Spec)
	}
	var caSecretAfter corev1.Secret
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: EgressCASecretName(agentRun.Name)}, &caSecretAfter); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(caSecretBefore.Data, caSecretAfter.Data) {
		t.Fatal("egress CA Secret changed across egressd Pod recreation")
	}
	var caConfigMapAfter corev1.ConfigMap
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: EgressCAConfigMapName(agentRun.Name)}, &caConfigMapAfter); err != nil {
		t.Fatal(err)
	}
	if caConfigMapAfter.Data[egressCACertKey] != caConfigMapBefore.Data[egressCACertKey] ||
		strings.Contains(fmt.Sprint(caConfigMapAfter.Data), "PRIVATE KEY") {
		t.Fatalf("published CA changed or leaked key material: %#v", caConfigMapAfter.Data)
	}
}

func TestReconcileKeepsRunningRunWhenBrokerFlipsToPlaintext(t *testing.T) {
	setTLSBrokerEnv(t)
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := multiGrantMediatedAgentRun()
	agentRun.Spec.EgressAllowInsecureBroker = false
	caSecret := testBrokerCASecret(agentRun.Namespace, map[string][]byte{brokerCAKey: []byte("fixture-ca")})
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, caSecret, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("reconcile under TLS broker: %v", err)
	}
	pod := getAgentPod(ctx, t, k8sClient, agentRun)
	pod.Status.Phase = corev1.PodRunning
	if err := k8sClient.Status().Update(ctx, &pod); err != nil {
		t.Fatalf("update pod status: %v", err)
	}

	// The operator broker env flips back to plaintext: without the insecure
	// flag this spec would no longer pass admission, but the running run must
	// not be retroactively failed.
	t.Setenv("NVT_BROKER_URL", "")
	t.Setenv("NVT_BROKER_CA_SECRET", "")
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("reconcile after plaintext flip: %v", err)
	}
	var updated nvtv1alpha1.AgentRun
	if err := k8sClient.Get(ctx, clientKey(agentRun), &updated); err != nil {
		t.Fatalf("get AgentRun: %v", err)
	}
	if updated.Status.Phase != nvtv1alpha1.AgentRunPhaseRunning {
		t.Fatalf("broker env flip retroactively changed phase to %s", updated.Status.Phase)
	}
}

func TestReconcileDoesNotRetroactivelyRewriteRunningRuns(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := multiGrantMediatedAgentRun()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}
	// First reconcile on the plaintext broker: creates Pod and egressd config.
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var before corev1.ConfigMap
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: EgressdConfigMapName(agentRun.Name)}, &before); err != nil {
		t.Fatalf("expected egressd ConfigMap, got %v", err)
	}

	// Operator broker env flips to TLS (even half-configured, with no CA
	// Secret): the running run must be left alone — no failure, no config
	// rewrite, no pod churn.
	setTLSBrokerEnv(t)
	t.Setenv("NVT_BROKER_CA_SECRET", "")
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("reconcile after broker env change: %v", err)
	}
	var updated nvtv1alpha1.AgentRun
	if err := k8sClient.Get(ctx, clientKey(agentRun), &updated); err != nil {
		t.Fatalf("get AgentRun: %v", err)
	}
	if updated.Status.Phase == nvtv1alpha1.AgentRunPhaseFailed {
		t.Fatalf("broker env change retroactively failed a running run")
	}
	var after corev1.ConfigMap
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: EgressdConfigMapName(agentRun.Name)}, &after); err != nil {
		t.Fatalf("get egressd ConfigMap: %v", err)
	}
	if !reflect.DeepEqual(before.Data, after.Data) {
		t.Fatalf("egressd config rewritten under an existing Pod:\nbefore: %v\nafter: %v", before.Data, after.Data)
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
		{
			Provider:     "github-main-app",
			Repositories: []string{"mirkoSekulic/nvt-agent", "mirkoSekulic/nvt-runtime"},
			Permissions:  map[string]string{"contents": "read"},
			Quota:        &nvtv1alpha1.AgentRunGrantQuota{Requests: 7},
		},
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
	if entry.Grants[0].Permissions["contents"] != "read" {
		t.Fatalf("expected updated grant permissions, got %#v", entry.Grants[0].Permissions)
	}
	if entry.Grants[0].Quota == nil || entry.Grants[0].Quota.Requests != 7 {
		t.Fatalf("expected updated grant quota, got %#v", entry.Grants[0].Quota)
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

func TestLiteralZeroSecretReconcileUpdatesAgentConfigMapWhenConfigChanges(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := enforcedAgentRun()
	agentRun.Spec.Broker.Grants = append(agentRun.Spec.Broker.Grants, nvtv1alpha1.AgentRunBrokerGrant{
		Provider:        "codex-main",
		Materialization: nvtv1alpha1.AgentRunGrantPlaceholderFile,
	})
	brokerRequests := 0
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		brokerRequests++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"files": []map[string]any{{
				"path":    ".codex/auth.json",
				"content": "{\n  \"access_token\": \"NVT-PLACEHOLDER-NOT-A-KEY\"\n}\n",
				"mode":    "0600",
			}},
		})
	}))
	t.Cleanup(broker.Close)
	t.Setenv("NVT_BROKER_URL", broker.URL)
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme, BrokerHTTPClient: broker.Client()}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("first reconcile: %v", err)
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
					"repository": "github.com/mirkoSekulic/nvt-agent-zero-secret-updated"
				}
			}
		]
	}`)}
	if updateErr := k8sClient.Update(ctx, &updatedAgentRun); updateErr != nil {
		t.Fatalf("update AgentRun: %v", updateErr)
	}

	_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}

	configMap := getAgentConfigMap(ctx, t, k8sClient, agentRun)
	agentConfig := configMap.Data[agentConfigKey]
	if strings.Contains(agentConfig, "repository: github.com/mirkoSekulic/nvt-agent\n") {
		t.Fatalf("expected previous zero-secret config to be replaced, got:\n%s", agentConfig)
	}
	if !strings.Contains(agentConfig, "repository: github.com/mirkoSekulic/nvt-agent-zero-secret-updated") {
		t.Fatalf("expected updated zero-secret config, got:\n%s", agentConfig)
	}
	if !strings.Contains(agentConfig, "$HOME/.codex/auth.json") || !strings.Contains(agentConfig, "NVT-PLACEHOLDER-NOT-A-KEY") {
		t.Fatalf("expected placeholder preseed to remain intact, got:\n%s", agentConfig)
	}
	if len(configMap.Data) != 2 {
		t.Fatalf("expected agent config and cached placeholder payload, got %#v", configMap.Data)
	}
	if brokerRequests != 2 {
		t.Fatalf("expected config change to invalidate the placeholder cache, got %d broker requests", brokerRequests)
	}
}

func TestLiteralZeroSecretPlaceholderPreparationIsCachedAcrossReconciles(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := enforcedAgentRun()
	agentRun.Spec.Broker.Grants = append(agentRun.Spec.Broker.Grants, nvtv1alpha1.AgentRunBrokerGrant{
		Provider:        "codex-main",
		Materialization: nvtv1alpha1.AgentRunGrantPlaceholderFile,
	})
	brokerRequests := 0
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		brokerRequests++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"files": []map[string]any{{
				"path":    ".codex/auth.json",
				"content": "{\n  \"access_token\": \"NVT-PLACEHOLDER-NOT-A-KEY\"\n}\n",
				"mode":    "0600",
			}},
		})
	}))
	t.Cleanup(broker.Close)
	t.Setenv("NVT_BROKER_URL", broker.URL)
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme, BrokerHTTPClient: broker.Client()}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	desiredPod, err := DesiredAgentPod(agentRun, scheme)
	if err != nil {
		t.Fatalf("render existing agent Pod: %v", err)
	}
	if err := k8sClient.Create(ctx, desiredPod); err != nil {
		t.Fatalf("create existing agent Pod: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("reconcile with existing agent Pod: %v", err)
	}

	if brokerRequests != 1 {
		t.Fatalf("expected placeholder preparation to be cached across reconciles, got %d broker requests", brokerRequests)
	}
	configMap := getAgentConfigMap(ctx, t, k8sClient, agentRun)
	if configMap.Data[preparedPlaceholderFilesKey] == "" || !strings.Contains(configMap.Data[agentConfigKey], "$HOME/.codex/auth.json") {
		t.Fatalf("existing agent Pod reconcile removed prepared placeholder files: %#v", configMap.Data)
	}
}

func TestLiteralZeroSecretMissingPlaceholderCacheIsRebuilt(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := enforcedAgentRun()
	agentRun.Spec.Broker.Grants = append(agentRun.Spec.Broker.Grants, nvtv1alpha1.AgentRunBrokerGrant{
		Provider:        "codex-main",
		Materialization: nvtv1alpha1.AgentRunGrantPlaceholderFile,
	})
	brokerSecret := mustDesiredTokenSecret(t, agentRun, scheme, BrokerTokenSecretName(agentRun.Name), brokerTokenKey, []byte("agent-token"))
	configMap, err := DesiredAgentConfigMap(agentRun, scheme)
	if err != nil {
		t.Fatalf("render stale agent config: %v", err)
	}
	configMap.Annotations = map[string]string{agentConfigPlaceholderCacheAnnotation: agentConfigPlaceholderCacheKey(agentRun)}
	brokerRequests := 0
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		brokerRequests++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"files": []map[string]any{{
				"path":    ".codex/auth.json",
				"content": "{\n  \"access_token\": \"NVT-PLACEHOLDER-NOT-A-KEY\"\n}\n",
				"mode":    "0600",
			}},
		})
	}))
	t.Cleanup(broker.Close)
	t.Setenv("NVT_BROKER_URL", broker.URL)
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(agentRun, brokerSecret, configMap).Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme, BrokerHTTPClient: broker.Client()}

	files, err := reconciler.preparePlaceholderFiles(ctx, agentRun)
	if err != nil {
		t.Fatalf("rebuild missing placeholder cache: %v", err)
	}
	if brokerRequests != 1 || len(files) != 1 || files[0].Path != ".codex/auth.json" {
		t.Fatalf("missing placeholder cache was not rebuilt: requests=%d files=%#v", brokerRequests, files)
	}
}

func mediatedProviderIdentityAgentRun() *nvtv1alpha1.AgentRun {
	run := enforcedAgentRun()
	run.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider:        "github-main-app",
		Materialization: nvtv1alpha1.AgentRunGrantHeaderInject,
		Repositories:    []string{"my-user/project"},
		EgressHosts:     []string{"github.com:443"},
		Git:             true,
		Preparations: []nvtv1alpha1.AgentRunBrokerPreparation{{
			Operation: nvtv1alpha1.AgentRunBrokerPreparationIdentity,
		}},
	}}}
	run.Spec.Agent.Config = apiextensionsv1.JSON{Raw: []byte(`{
  "plugins": [
    {
      "name": "arbitrary-language-plugin",
      "config": {
        "opaque-setting": "must-remain-unchanged"
      }
    }
  ]
}`)}
	return run
}

func TestLiteralZeroSecretPreparesProviderIdentityWithoutAgentCredentialCapability(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := mediatedProviderIdentityAgentRun()
	requests := 0
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Path != "/v1/identity" || !strings.HasPrefix(request.Header.Get("Authorization"), "Bearer ") {
			t.Fatalf("unexpected preparation request: %s", request.URL.Path)
		}
		var payload map[string]any
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["provider"] != "github-main-app" || payload["target"] != nil || len(payload) != 1 {
			t.Fatalf("operator guessed or sent extra identity context: %#v", payload)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "name": "Staging App Bot", "email": "123456789+staging-app[bot]@users.noreply.github.com",
		})
	}))
	t.Cleanup(broker.Close)
	t.Setenv("NVT_BROKER_URL", broker.URL)
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme, BrokerHTTPClient: broker.Client()}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("reconcile provider identity: %v", err)
	}
	if requests != 1 {
		t.Fatalf("expected one exact provider identity request, got %d", requests)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("reconcile cached provider identity: %v", err)
	}
	if requests != 1 {
		t.Fatalf("unchanged provider identity was not cached: %d requests", requests)
	}
	changedGrant := agentRun.DeepCopyObject().(*nvtv1alpha1.AgentRun)
	changedGrant.Spec.Broker.Grants[0].Repositories = []string{"my-user/other-project"}
	if _, err := reconciler.prepareProviderMetadata(ctx, changedGrant); err != nil {
		t.Fatalf("reprepare changed grant metadata: %v", err)
	}
	if requests != 2 {
		t.Fatalf("changed preparation grant reused stale metadata cache: %d requests", requests)
	}
	configMap := getAgentConfigMap(ctx, t, k8sClient, agentRun)
	rendered := configMap.Data[agentConfigKey]
	if strings.Contains(rendered, "operator-prepared-identity") || !strings.Contains(rendered, "opaque-setting: must-remain-unchanged") {
		t.Fatalf("operator rewrote plugin-specific configuration:\n%s", rendered)
	}
	var renderedConfig map[string]any
	if err := yaml.Unmarshal([]byte(rendered), &renderedConfig); err != nil {
		t.Fatal(err)
	}
	plugins := renderedConfig["plugins"].([]any)
	opaqueConfig := plugins[0].(map[string]any)["config"].(map[string]any)
	if !reflect.DeepEqual(opaqueConfig, map[string]any{"opaque-setting": "must-remain-unchanged"}) {
		t.Fatalf("arbitrary plugin config changed: %#v", opaqueConfig)
	}
	metadata, err := loadPreparedProviderMetadata(configMap.Data[preparedProviderMetadataKey], []requestedProviderPreparation{{
		Provider: "github-main-app", Operation: nvtv1alpha1.AgentRunBrokerPreparationIdentity,
	}})
	if err != nil {
		t.Fatalf("load prepared provider metadata: %v", err)
	}
	identity := metadata.Providers["github-main-app"].Identity
	if identity == nil || identity.Name != "Staging App Bot" || identity.Email != "123456789+staging-app[bot]@users.noreply.github.com" {
		t.Fatalf("unexpected prepared provider metadata: %#v", metadata)
	}
	for _, forbidden := range []string{"NVT_BROKER_TOKEN", "NVT_EGRESS_BROKER_TOKEN", "secret-response-canary"} {
		if strings.Contains(rendered, forbidden) || strings.Contains(configMap.Data[preparedProviderMetadataKey], forbidden) {
			t.Fatalf("agent configuration contains credential capability %q", forbidden)
		}
	}
	pod, err := DesiredAgentPod(agentRun, scheme)
	if err != nil {
		t.Fatal(err)
	}
	agent := pod.Spec.Containers[0]
	metadataEnv := false
	for _, env := range agent.Env {
		if strings.Contains(env.Name, "BROKER_TOKEN") || env.Name == "NVT_EGRESS_BROKER_TOKEN" || env.ValueFrom != nil {
			t.Fatalf("agent received credential-bearing environment: %#v", env)
		}
		if env.Name == preparedProviderMetadataEnv && env.Value == preparedProviderMetadataPath {
			metadataEnv = true
		}
	}
	if !metadataEnv {
		t.Fatalf("agent did not receive generic prepared metadata path: %#v", agent.Env)
	}
	metadataProjected := false
	for _, volume := range pod.Spec.Volumes {
		if volume.Secret != nil && (volume.Secret.SecretName == BrokerTokenSecretName(agentRun.Name) || volume.Secret.SecretName == EgressTokenSecretName(agentRun.Name)) {
			t.Fatalf("agent Pod projects broker/egress identity: %#v", volume)
		}
		if volume.Name == "agent-config" && volume.ConfigMap != nil {
			for _, item := range volume.ConfigMap.Items {
				if item.Key == preparedProviderMetadataKey && item.Path == preparedProviderMetadataKey {
					metadataProjected = true
				}
			}
		}
	}
	if !metadataProjected {
		t.Fatalf("agent Pod did not project generic metadata document: %#v", pod.Spec.Volumes)
	}
	podJSON, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"operator-only-token", "secret-response-canary", "NVT_BROKER_TOKEN", "NVT_EGRESS_BROKER_TOKEN"} {
		if strings.Contains(string(podJSON), forbidden) {
			t.Fatalf("agent Pod contains credential material or capability %q", forbidden)
		}
	}
}

func TestProfileWorkspaceInstructionsProjection(t *testing.T) {
	scheme := testScheme(t)
	run := testAgentRun()
	run.Spec.Agent.WorkspaceInstructions = "# Team workflow\n\nPreserve this Markdown exactly.\n"
	run.Spec.Agent.WorkflowInstructions = "# Requested workflow\n\nReview before editing.\n"

	configMap, err := DesiredAgentConfigMap(run, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if got := configMap.Data[profileWorkspaceInstructionsKey]; got != run.Spec.Agent.WorkspaceInstructions {
		t.Fatalf("projected instructions = %q", got)
	}
	if got := configMap.Data[workflowWorkspaceInstructionsKey]; got != run.Spec.Agent.WorkflowInstructions {
		t.Fatalf("projected workflow instructions = %q", got)
	}
	pod, err := DesiredAgentPod(run, scheme)
	if err != nil {
		t.Fatal(err)
	}
	foundItem := false
	foundWorkflowItem := false
	for _, item := range pod.Spec.Volumes[1].ConfigMap.Items {
		if item.Key == profileWorkspaceInstructionsKey && item.Path == profileWorkspaceInstructionsKey {
			foundItem = true
		}
		if item.Key == workflowWorkspaceInstructionsKey && item.Path == workflowWorkspaceInstructionsKey {
			foundWorkflowItem = true
		}
	}
	foundEnv := false
	foundWorkflowEnv := false
	for _, env := range pod.Spec.Containers[0].Env {
		if env.Name == profileWorkspaceInstructionsEnv && env.Value == profileWorkspaceInstructionsPath {
			foundEnv = true
		}
		if env.Name == workflowWorkspaceInstructionsEnv && env.Value == workflowWorkspaceInstructionsPath {
			foundWorkflowEnv = true
		}
	}
	if !foundItem || !foundWorkflowItem || !foundEnv || !foundWorkflowEnv || !pod.Spec.Containers[0].VolumeMounts[1].ReadOnly {
		t.Fatalf("instructions projection is incomplete: profileItem=%t workflowItem=%t profileEnv=%t workflowEnv=%t pod=%#v",
			foundItem, foundWorkflowItem, foundEnv, foundWorkflowEnv, pod.Spec)
	}
	podJSON, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(podJSON), "Preserve this Markdown exactly") || strings.Contains(string(podJSON), "Review before editing") {
		t.Fatal("workspace instruction content was duplicated into the Pod spec")
	}

	run.Spec.Agent.WorkspaceInstructions = ""
	run.Spec.Agent.WorkflowInstructions = ""
	configMap, err = DesiredAgentConfigMap(run, scheme)
	if err != nil {
		t.Fatal(err)
	}
	pod, err = DesiredAgentPod(run, scheme)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := configMap.Data[profileWorkspaceInstructionsKey]; exists {
		t.Fatal("empty workspace instructions created a ConfigMap item")
	}
	if _, exists := configMap.Data[workflowWorkspaceInstructionsKey]; exists {
		t.Fatal("empty workflow instructions created a ConfigMap item")
	}
	for _, env := range pod.Spec.Containers[0].Env {
		if env.Name == profileWorkspaceInstructionsEnv || env.Name == workflowWorkspaceInstructionsEnv {
			t.Fatal("empty workspace instructions created an environment variable")
		}
	}
	for _, item := range pod.Spec.Volumes[1].ConfigMap.Items {
		if item.Key == profileWorkspaceInstructionsKey || item.Key == workflowWorkspaceInstructionsKey {
			t.Fatal("empty workspace instructions created a projected item")
		}
	}

	run.Spec.Agent.WorkspaceInstructions = strings.Repeat("x", maxWorkspaceInstructionsBytes) + "secret-canary"
	if _, err := DesiredAgentConfigMap(run, scheme); err == nil || strings.Contains(err.Error(), "secret-canary") {
		t.Fatalf("oversized instructions did not fail with a sanitized error: %v", err)
	}
	run.Spec.Agent.WorkspaceInstructions = ""
	run.Spec.Agent.WorkflowInstructions = strings.Repeat("x", maxWorkspaceInstructionsBytes) + "secret-canary"
	if _, err := DesiredAgentConfigMap(run, scheme); err == nil || strings.Contains(err.Error(), "secret-canary") {
		t.Fatalf("oversized workflow instructions did not fail with a sanitized error: %v", err)
	}
}

func TestProviderIdentityPreparationFailsClosedForMissingMappingAndMalformedBrokerResult(t *testing.T) {
	agentRun := mediatedProviderIdentityAgentRun()
	agentRun.Spec.Broker.Grants[0].Preparations[0].Operation = "token"
	if _, err := requestedProviderPreparations(agentRun); err == nil || !strings.Contains(err.Error(), "must be identity") {
		t.Fatalf("unsupported preparation did not fail loudly: %v", err)
	}

	ctx := context.Background()
	scheme := testScheme(t)
	agentRun = mediatedProviderIdentityAgentRun()
	brokerSecret := mustDesiredTokenSecret(t, agentRun, scheme, BrokerTokenSecretName(agentRun.Name), brokerTokenKey, []byte("operator-only-token"))
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"name":"secret-response-canary`))
	}))
	t.Cleanup(broker.Close)
	t.Setenv("NVT_BROKER_URL", broker.URL)
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(agentRun, brokerSecret).Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme, BrokerHTTPClient: broker.Client()}
	_, err := reconciler.prepareProviderMetadata(ctx, agentRun)
	if err == nil || !strings.Contains(err.Error(), "broker returned an invalid response") || strings.Contains(err.Error(), "secret-response-canary") {
		t.Fatalf("malformed broker result was not sanitized: %v", err)
	}
}

func TestUnsupportedProviderPreparationFailsBeforeAgentPod(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := mediatedProviderIdentityAgentRun()
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": false, "error": "identity-not-supported", "message": "secret-response-canary",
		})
	}))
	t.Cleanup(broker.Close)
	t.Setenv("NVT_BROKER_URL", broker.URL)
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme, BrokerHTTPClient: broker.Client()}
	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err == nil || !strings.Contains(err.Error(), "identity-not-supported") || strings.Contains(err.Error(), "secret-response-canary") {
		t.Fatalf("unsupported preparation was not sanitized: %v", err)
	}
	pod := &corev1.Pod{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: agentRun.Namespace, Name: AgentPodName(agentRun.Name)}, pod); !errors.IsNotFound(err) {
		t.Fatalf("agent Pod exists after failed preparation: err=%v pod=%#v", err, pod)
	}
}

func TestProviderMetadataPreparationsMapMultipleProvidersExactly(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := mediatedProviderIdentityAgentRun()
	agentRun.Spec.Broker.Grants = append(agentRun.Spec.Broker.Grants, nvtv1alpha1.AgentRunBrokerGrant{
		Provider: "company-app", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject,
		Repositories: []string{"example/repo"}, EgressHosts: []string{"example.test:443"},
		Preparations: []nvtv1alpha1.AgentRunBrokerPreparation{{Operation: nvtv1alpha1.AgentRunBrokerPreparationIdentity}},
	})
	brokerSecret := mustDesiredTokenSecret(t, agentRun, scheme, BrokerTokenSecretName(agentRun.Name), brokerTokenKey, []byte("operator-only-token"))
	seen := map[string]int{}
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var payload map[string]string
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		provider := payload["provider"]
		seen[provider]++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "name": provider + " Bot", "email": provider + "@example.test",
		})
	}))
	t.Cleanup(broker.Close)
	t.Setenv("NVT_BROKER_URL", broker.URL)
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(agentRun, brokerSecret).Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme, BrokerHTTPClient: broker.Client()}

	metadata, err := reconciler.prepareProviderMetadata(ctx, agentRun)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.Providers) != 2 || seen["company-app"] != 1 || seen["github-main-app"] != 1 {
		t.Fatalf("preparations did not map exactly: metadata=%#v requests=%#v", metadata, seen)
	}
	for _, provider := range []string{"company-app", "github-main-app"} {
		identity := metadata.Providers[provider].Identity
		if identity == nil || identity.Name != provider+" Bot" || identity.Email != provider+"@example.test" {
			t.Fatalf("provider %s collided: %#v", provider, identity)
		}
	}
}

func TestPreparedProviderMetadataCacheRejectsMalformedOrStaleDocuments(t *testing.T) {
	requested := []requestedProviderPreparation{{Provider: "github-main-app", Operation: nvtv1alpha1.AgentRunBrokerPreparationIdentity}}
	tests := []string{
		`{"version":1,"providers":{"other-provider":{"identity":{"name":"Safe Bot","email":"safe@example.test"}}}}`,
		`{"version":1,"providers":{"github-main-app":{"identity":{"name":" bad","email":"safe@example.test"}}}}`,
		`{"version":1,"providers":{"github-main-app":{"identity":{"name":"Safe Bot","email":"safe@example.test"}}}} trailing`,
	}
	for _, raw := range tests {
		if _, err := loadPreparedProviderMetadata(raw, requested); err == nil {
			t.Fatalf("malformed or stale metadata was accepted: %s", raw)
		}
	}
}

func TestProviderPreparationValidationAndOmittedPodBehavior(t *testing.T) {
	scheme := testScheme(t)
	omitted := testAgentRun()
	pod, err := DesiredAgentPod(omitted, scheme)
	if err != nil {
		t.Fatal(err)
	}
	for _, env := range pod.Spec.Containers[0].Env {
		if env.Name == preparedProviderMetadataEnv {
			t.Fatalf("run without preparations received metadata path: %#v", env)
		}
	}
	for _, item := range pod.Spec.Volumes[1].ConfigMap.Items {
		if item.Key == preparedProviderMetadataKey {
			t.Fatalf("run without preparations projected metadata: %#v", item)
		}
	}

	invalid := testAgentRun()
	invalid.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "identity-main", Repositories: []string{"example/repo"}, Materialization: nvtv1alpha1.AgentRunGrantFileBundle,
	}}}
	invalid.Spec.Broker.Grants[0].Preparations = []nvtv1alpha1.AgentRunBrokerPreparation{{Operation: "headers"}}
	if err := ValidateAgentRunEgressMode(invalid); err == nil || !strings.Contains(err.Error(), "must be identity") {
		t.Fatalf("unsupported preparation was not rejected: %v", err)
	}
	duplicate := testAgentRun()
	duplicate.Spec.Broker = invalid.Spec.Broker.DeepCopy()
	duplicate.Spec.Broker.Grants[0].Preparations = []nvtv1alpha1.AgentRunBrokerPreparation{
		{Operation: nvtv1alpha1.AgentRunBrokerPreparationIdentity},
		{Operation: nvtv1alpha1.AgentRunBrokerPreparationIdentity},
	}
	if err := ValidateAgentRunEgressMode(duplicate); err == nil || !strings.Contains(err.Error(), "is duplicated") {
		t.Fatalf("duplicate preparation was not rejected: %v", err)
	}
}

func TestAgentRunMaxConcurrentReconcilesUsesMultipleWorkers(t *testing.T) {
	if got := agentRunMaxConcurrentReconciles(); got < 2 {
		t.Fatalf("expected multiple reconcile workers, got %d", got)
	}
}

func TestLiteralZeroSecretPlaceholderRenderingKeepsUserAndBrokerEntriesUnique(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := enforcedAgentRun()
	agentRun.Spec.Agent.Config = apiextensionsv1.JSON{Raw: []byte(`{
		"preseed": {
			"files": [
				{
					"path": ".codex/user.json",
					"content": "{\n  \"note\": \"NVT-PLACEHOLDER-NOT-A-KEY\"\n}\n",
					"mode": "0600"
				}
			]
		}
	}`)}
	agentRun.Spec.Broker.Grants = append(agentRun.Spec.Broker.Grants, nvtv1alpha1.AgentRunBrokerGrant{
		Provider:        "codex-main",
		Materialization: nvtv1alpha1.AgentRunGrantPlaceholderFile,
	})
	brokerRequests := 0
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		brokerRequests++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"files": []map[string]any{{
				"path":    ".codex/auth.json",
				"content": "{\n  \"access_token\": \"NVT-PLACEHOLDER-NOT-A-KEY\"\n}\n",
				"mode":    "0600",
			}},
		})
	}))
	t.Cleanup(broker.Close)
	t.Setenv("NVT_BROKER_URL", broker.URL)
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme, BrokerHTTPClient: broker.Client()}

	for pass := 0; pass < 2; pass++ {
		_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
		if err != nil {
			t.Fatalf("reconcile pass %d: %v", pass+1, err)
		}
	}

	configMap := getAgentConfigMap(ctx, t, k8sClient, agentRun)
	agentConfig := configMap.Data[agentConfigKey]
	if strings.Count(agentConfig, ".codex/user.json") != 1 {
		t.Fatalf("expected user preseed entry once, got:\n%s", agentConfig)
	}
	if strings.Count(agentConfig, "$HOME/.codex/auth.json") != 1 {
		t.Fatalf("expected broker placeholder entry once, got:\n%s", agentConfig)
	}
	if brokerRequests != 1 {
		t.Fatalf("expected cached placeholder prep to avoid duplicate broker calls, got %d", brokerRequests)
	}
}

func TestReconcileAdoptsServerDefaultedLegacyAgentPod(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	runtimeAuth := &nvtv1alpha1.AgentRunRuntimeAuth{SecretName: "runtime-auth"}
	agentRun.Spec.RuntimeAuth = runtimeAuth
	desiredPod, err := DesiredAgentPod(agentRun, scheme)
	if err != nil {
		t.Fatalf("desired AgentRun Pod: %v", err)
	}
	applyServerAdmissionDefaults(desiredPod, true)
	expectedAnnotation, err := podCredentialProjectionSignature(agentRun, desiredPod)
	if err != nil {
		t.Fatalf("desired AgentRun Pod security signature: %v", err)
	}
	delete(desiredPod.Annotations, agentPodSecurityStateAnnotation)
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace), desiredPod).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("reconcile legacy Pod: %v", err)
	}

	pod := getAgentPod(ctx, t, k8sClient, agentRun)
	if pod.Annotations[agentPodSecurityStateAnnotation] == "" {
		t.Fatalf("expected legacy Pod to be annotated after adoption, got %#v", pod.Annotations)
	}
	if pod.Annotations[agentPodSecurityStateAnnotation] != expectedAnnotation {
		t.Fatalf("expected adopted annotation %q, got %q", expectedAnnotation, pod.Annotations[agentPodSecurityStateAnnotation])
	}
	if pod.Spec.ServiceAccountName != "default" {
		t.Fatalf("expected admitted serviceAccountName default, got %q", pod.Spec.ServiceAccountName)
	}
	if pod.Spec.SecurityContext == nil {
		t.Fatal("expected admitted empty securityContext to be preserved")
	}
	if volume := requireVolume(t, pod, "kube-api-access-server-default"); volume.Projected == nil || volume.Projected.DefaultMode == nil || *volume.Projected.DefaultMode != defaultProjectedVolumeMode {
		t.Fatalf("expected admitted service-account projection with defaultMode 420, got %#v", volume.VolumeSource)
	}
	if volume := requireVolume(t, pod, runtimeAuthSourceName); volume.Secret == nil || volume.Secret.DefaultMode == nil || *volume.Secret.DefaultMode != defaultProjectedVolumeMode {
		t.Fatalf("expected admitted runtime-auth Secret defaultMode 420, got %#v", volume.VolumeSource)
	}
}

func TestReconcileRejectsInjectedServiceAccountTokenProjectionForLiteralZeroSecretPod(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := enforcedAgentRun()
	desiredPod, err := DesiredAgentPod(agentRun, scheme)
	if err != nil {
		t.Fatalf("desired literal-zero-secret Pod: %v", err)
	}
	applyServerAdmissionDefaults(desiredPod, true)
	delete(desiredPod.Annotations, agentPodSecurityStateAnnotation)
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace), desiredPod).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		if !strings.Contains(err.Error(), "service-account token volume") {
			t.Fatalf("expected service-account token rejection, got %v", err)
		}
	} else {
		t.Fatal("expected literal-zero-secret Pod with injected service-account token projection to fail")
	}
	assertAgentPodMissing(ctx, t, k8sClient, agentRun)
}

func TestReconcileRejectsMixedServiceAccountAndSecretProjectionDrift(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	desiredPod, err := DesiredAgentPod(agentRun, scheme)
	if err != nil {
		t.Fatalf("desired AgentRun Pod: %v", err)
	}
	applyServerAdmissionDefaults(desiredPod, true)
	mixedPod := desiredPod.DeepCopy()
	mixedPod.Annotations = map[string]string{}
	mixedPod.Spec.Volumes = append(mixedPod.Spec.Volumes, corev1.Volume{
		Name: "extra-secret-projection",
		VolumeSource: corev1.VolumeSource{
			Projected: &corev1.ProjectedVolumeSource{
				DefaultMode: ptrTo(defaultProjectedVolumeMode),
				Sources: []corev1.VolumeProjection{
					{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Audience: "https://kubernetes.default.svc", Path: "token"}},
					{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "kube-root-ca.crt"}}},
					{DownwardAPI: &corev1.DownwardAPIProjection{}},
					{Secret: &corev1.SecretProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "operator-extra-secret"}, Optional: ptrTo(true)}},
				},
			},
		},
	})
	mixedPod.Spec.Containers[0].VolumeMounts = append(mixedPod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
		Name:      "extra-secret-projection",
		MountPath: "/var/run/secrets/extra",
		ReadOnly:  true,
	})
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace), mixedPod).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err == nil || !strings.Contains(err.Error(), "security-sensitive AgentRun fields changed") {
		t.Fatalf("expected mixed projected volume drift rejection, got %v", err)
	}
	assertAgentPodMissing(ctx, t, k8sClient, agentRun)
}

func TestReconcileRejectsUnannotatedLegacyPodSecurityMismatch(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	legacyPod, err := DesiredAgentPod(agentRun, scheme)
	if err != nil {
		t.Fatalf("desired AgentRun Pod: %v", err)
	}
	delete(legacyPod.Annotations, agentPodSecurityStateAnnotation)
	legacyPod.Spec.ServiceAccountName = "legacy-mismatch"
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace), legacyPod).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err == nil || !strings.Contains(err.Error(), "security-sensitive AgentRun fields changed") {
		t.Fatalf("expected security mismatch rejection, got %v", err)
	}
	assertAgentPodMissing(ctx, t, k8sClient, agentRun)
}

func TestReconcileKeepsRunningPodWhenGrantIsRemoved(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := multiGrantMediatedAgentRun()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	var pod corev1.Pod
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: AgentPodName(agentRun.Name)}, &pod); err != nil {
		t.Fatalf("get agent Pod: %v", err)
	}
	pod.Status.Phase = corev1.PodRunning
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := k8sClient.Status().Update(ctx, &pod); err != nil {
		t.Fatalf("mark agent Pod running: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}

	var updatedAgentRun nvtv1alpha1.AgentRun
	if err := k8sClient.Get(ctx, clientKey(agentRun), &updatedAgentRun); err != nil {
		t.Fatalf("get AgentRun: %v", err)
	}
	updatedAgentRun.Spec.Broker.Grants = updatedAgentRun.Spec.Broker.Grants[:1]
	if err := k8sClient.Update(ctx, &updatedAgentRun); err != nil {
		t.Fatalf("update AgentRun grants: %v", err)
	}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("reconcile after grant removal: %v", err)
	}
	assertAgentPodExists(ctx, t, k8sClient, agentRun)
	assertAgentRunPhase(ctx, t, k8sClient, agentRun, nvtv1alpha1.AgentRunPhaseRunning)
	policy := mustParseBrokerAgentsPolicy(t, getBrokerAgentsConfigMap(ctx, t, k8sClient, agentRun.Namespace).Data[brokerAgentsConfigKey])
	entry := requireBrokerAgentEntry(t, policy, AgentRunBrokerID(agentRun.Namespace, agentRun.Name))
	if len(entry.Grants) != 1 {
		t.Fatalf("expected one remaining grant after revocation, got %#v", entry.Grants)
	}
	if entry.Grants[0].Provider != "api-main" {
		t.Fatalf("expected api-main grant to remain, got %#v", entry.Grants)
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

func TestReconcileRejectsDirectToEnforcedSecurityModeMutation(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := testAgentRun()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("direct reconcile: %v", err)
	}

	var updatedAgentRun nvtv1alpha1.AgentRun
	if err := k8sClient.Get(ctx, clientKey(agentRun), &updatedAgentRun); err != nil {
		t.Fatalf("get AgentRun: %v", err)
	}
	updatedAgentRun.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	updatedAgentRun.Spec.EgressEnforcement = true
	updatedAgentRun.Spec.EgressAllowInsecureBroker = true
	updatedAgentRun.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider:        "api-main",
		Materialization: nvtv1alpha1.AgentRunGrantHeaderInject,
		EgressHosts:     []string{"api.example.test:443"},
	}}}
	if err := k8sClient.Update(ctx, &updatedAgentRun); err != nil {
		t.Fatalf("update AgentRun: %v", err)
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err == nil || !strings.Contains(err.Error(), "security-sensitive AgentRun fields changed") {
		t.Fatalf("expected security transition rejection, got %v", err)
	}
	assertAgentPodMissing(ctx, t, k8sClient, agentRun)
}

func TestReconcileRejectsEnforcedToDirectSecurityModeMutation(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	agentRun := enforcedAgentRun()
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&corev1.Pod{}, &nvtv1alpha1.AgentRun{}).
		WithObjects(agentRun, testBrokerAgentsConfigMap(agentRun.Namespace)).
		Build()
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("first enforced reconcile: %v", err)
	}
	markPodReady(ctx, t, k8sClient, agentRun.Namespace, EgressdPodName(agentRun.Name))
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("second enforced reconcile: %v", err)
	}

	var updatedAgentRun nvtv1alpha1.AgentRun
	if err := k8sClient.Get(ctx, clientKey(agentRun), &updatedAgentRun); err != nil {
		t.Fatalf("get AgentRun: %v", err)
	}
	updatedAgentRun.Spec = testAgentRun().Spec
	if err := k8sClient.Update(ctx, &updatedAgentRun); err != nil {
		t.Fatalf("update AgentRun: %v", err)
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err == nil || !strings.Contains(err.Error(), "security-sensitive AgentRun fields changed") {
		t.Fatalf("expected security transition rejection, got %v", err)
	}
	assertAgentPodMissing(ctx, t, k8sClient, agentRun)
	assertEgressdPodMissing(ctx, t, k8sClient, agentRun)
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

func TestRenderAgentConfigYAMLInjectsRuntimeInitialPrompt(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Spec.Prompt = &nvtv1alpha1.AgentRunPrompt{Text: "Start this run.\nThen report back."}

	rendered, err := RenderAgentConfigYAML(agentRun)
	if err != nil {
		t.Fatalf("render AgentRun agent config: %v", err)
	}

	config := parseAgentConfigYAML(t, rendered)
	runtimeConfig, ok := config["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("expected runtime config, got %#v\n%s", config["runtime"], rendered)
	}
	initialPrompt, ok := runtimeConfig["initial-prompt"].(map[string]any)
	if !ok || initialPrompt["delivery"] != "argument" || initialPrompt["text"] != agentRun.Spec.Prompt.Text {
		t.Fatalf("unexpected runtime initial prompt: %#v", runtimeConfig["initial-prompt"])
	}
	if !reflect.DeepEqual(runtimeConfig["args"], []any{"--sandbox", "danger-full-access", "--ask-for-approval", "never"}) {
		t.Fatalf("initial prompt changed runtime autonomy args: %#v", runtimeConfig["args"])
	}
	plugins, ok := config["plugins"].([]any)
	if !ok || len(plugins) != 1 {
		t.Fatalf("expected existing plugin to remain unchanged, got %#v\n%s", config["plugins"], rendered)
	}
	existingPlugin, ok := plugins[0].(map[string]any)
	if !ok || existingPlugin["name"] != "checkout-repos" {
		t.Fatalf("expected existing plugin to remain, got %#v", plugins[0])
	}
}

func TestRenderAgentConfigYAMLInitialPromptPreservesClaudeAutonomyArgs(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Spec.Runtime = nvtv1alpha1.AgentRunRuntime{Type: "claude", Autonomy: "trusted-local"}
	agentRun.Spec.Prompt = &nvtv1alpha1.AgentRunPrompt{Text: "Start with this task."}

	rendered, err := RenderAgentConfigYAML(agentRun)
	if err != nil {
		t.Fatalf("render AgentRun agent config: %v", err)
	}

	config := parseAgentConfigYAML(t, rendered)
	runtimeConfig := config["runtime"].(map[string]any)
	if runtimeConfig["command"] != "claude" || !reflect.DeepEqual(runtimeConfig["args"], []any{"--dangerously-skip-permissions"}) {
		t.Fatalf("initial prompt changed Claude launch config: %#v", runtimeConfig)
	}
	initialPrompt := runtimeConfig["initial-prompt"].(map[string]any)
	if initialPrompt["delivery"] != "argument" || initialPrompt["text"] != agentRun.Spec.Prompt.Text {
		t.Fatalf("unexpected Claude initial prompt: %#v", initialPrompt)
	}
}

func TestRenderAgentConfigYAMLAppliesRuntimeAutonomy(t *testing.T) {
	tests := []struct {
		name     string
		runtime  nvtv1alpha1.AgentRunRuntime
		config   string
		command  string
		wantArgs []any
	}{
		{
			name:     "codex trusted local",
			runtime:  nvtv1alpha1.AgentRunRuntime{Type: "codex", Autonomy: "trusted-local"},
			config:   `{}`,
			command:  "codex",
			wantArgs: []any{"--sandbox", "danger-full-access", "--ask-for-approval", "never"},
		},
		{
			name:     "claude trusted local",
			runtime:  nvtv1alpha1.AgentRunRuntime{Type: "claude", Autonomy: "trusted-local"},
			config:   `{"runtime":{"command":"claude"}}`,
			command:  "claude",
			wantArgs: []any{"--dangerously-skip-permissions"},
		},
		{
			name:     "interactive",
			runtime:  nvtv1alpha1.AgentRunRuntime{Type: "codex", Autonomy: "interactive"},
			config:   `{"runtime":{"command":"codex"}}`,
			command:  "codex",
			wantArgs: []any{},
		},
		{
			name:     "explicit args are complete override",
			runtime:  nvtv1alpha1.AgentRunRuntime{Type: "codex", Autonomy: "trusted-local"},
			config:   `{"runtime":{"command":"custom-codex-wrapper","args":["--model","gpt-test","--ask-for-approval","on-request"]}}`,
			command:  "custom-codex-wrapper",
			wantArgs: []any{"--model", "gpt-test", "--ask-for-approval", "on-request"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			agentRun := testAgentRun()
			agentRun.Spec.Runtime = test.runtime
			agentRun.Spec.Agent.Config = apiextensionsv1.JSON{Raw: []byte(test.config)}
			rendered, err := RenderAgentConfigYAML(agentRun)
			if err != nil {
				t.Fatal(err)
			}
			config := parseAgentConfigYAML(t, rendered)
			runtimeConfig, ok := config["runtime"].(map[string]any)
			if !ok || runtimeConfig["command"] != test.command || !reflect.DeepEqual(runtimeConfig["args"], test.wantArgs) {
				t.Fatalf("unexpected runtime config: %#v\n%s", runtimeConfig, rendered)
			}
		})
	}
}

func TestDesiredAgentPodUsesRuntimeHealthReadinessProbe(t *testing.T) {
	pod, err := DesiredAgentPod(testAgentRun(), testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	agent := pod.Spec.Containers[0]
	probe := agent.ReadinessProbe
	if probe == nil || probe.Exec == nil || !reflect.DeepEqual(probe.Exec.Command, []string{"/usr/local/bin/health"}) {
		t.Fatalf("agent readiness probe does not use runtime health: %#v", probe)
	}
	if probe.InitialDelaySeconds != 5 || probe.PeriodSeconds != 5 || probe.TimeoutSeconds != 2 || probe.FailureThreshold != 12 {
		t.Fatalf("unexpected bounded readiness timing: %#v", probe)
	}
	if agent.LivenessProbe != nil || pod.Spec.RestartPolicy != corev1.RestartPolicyNever {
		t.Fatalf("readiness must not restart a slow or failed agent: liveness=%#v restart=%s", agent.LivenessProbe, pod.Spec.RestartPolicy)
	}
}

func TestRenderAgentConfigYAMLInjectsRuntimeInitialPromptWhenPluginsMissing(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Spec.Agent.Config = apiextensionsv1.JSON{Raw: []byte(`{"codeServer": {"enabled": true}}`)}
	agentRun.Spec.Prompt = &nvtv1alpha1.AgentRunPrompt{Text: "Run without configured plugins."}

	rendered, err := RenderAgentConfigYAML(agentRun)
	if err != nil {
		t.Fatalf("render AgentRun agent config: %v", err)
	}

	config := parseAgentConfigYAML(t, rendered)
	runtimeConfig, ok := config["runtime"].(map[string]any)
	if !ok || runtimeConfig["initial-prompt"] == nil {
		t.Fatalf("expected runtime initial prompt, got %#v\n%s", config["runtime"], rendered)
	}
	if _, exists := config["plugins"]; exists {
		t.Fatalf("initial prompt unexpectedly added a plugin: %#v", config["plugins"])
	}
	if config["codeServer"] == nil {
		t.Fatalf("expected existing config keys to be preserved, got %#v", config)
	}
}

func TestRenderAgentConfigYAMLNoPromptDoesNotInjectInitialPrompt(t *testing.T) {
	agentRun := testAgentRun()

	rendered, err := RenderAgentConfigYAML(agentRun)
	if err != nil {
		t.Fatalf("render AgentRun agent config: %v", err)
	}

	if strings.Contains(rendered, "initial-prompt") {
		t.Fatalf("expected no injected plugin, got:\n%s", rendered)
	}
}

func TestRenderAgentConfigYAMLDoesNotInjectPreseedForNonCodex(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Spec.Agent.Config = apiextensionsv1.JSON{Raw: []byte(`{"tools": {"packages": []}}`)}
	agentRun.Spec.Runtime.Type = "claude"

	rendered, err := RenderAgentConfigYAML(agentRun)
	if err != nil {
		t.Fatalf("render AgentRun agent config: %v", err)
	}

	if strings.Contains(rendered, "preseed") || strings.Contains(rendered, "check_for_update_on_startup") {
		t.Fatalf("operator injected runtime preseed for non-codex run:\n%s", rendered)
	}
}

func TestRenderAgentConfigYAMLInjectsCodexPreseed(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Spec.Agent.Config = apiextensionsv1.JSON{Raw: []byte(`{"tools": {"packages": []}}`)}
	agentRun.Spec.Runtime.Type = "codex"

	rendered, err := RenderAgentConfigYAML(agentRun)
	if err != nil {
		t.Fatalf("render AgentRun agent config: %v", err)
	}

	config := parseAgentConfigYAML(t, rendered)
	preseed, ok := config["preseed"].(map[string]any)
	if !ok {
		t.Fatalf("expected codex preseed block, got %#v\n%s", config["preseed"], rendered)
	}
	files, ok := preseed["files"].([]any)
	if !ok || len(files) != 1 {
		t.Fatalf("expected one preseed file, got %#v\n%s", preseed["files"], rendered)
	}
	file, ok := files[0].(map[string]any)
	if !ok {
		t.Fatalf("expected preseed file object, got %#v", files[0])
	}
	if file["path"] != "$HOME/.codex/config.toml" ||
		file["mode"] != "0600" ||
		file["overwrite"] != false ||
		file["content"] != "check_for_update_on_startup = false\n" {
		t.Fatalf("unexpected codex preseed file: %#v\n%s", file, rendered)
	}
}

func TestRenderAgentConfigYAMLPreservesUserPreseed(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Spec.Agent.Config = apiextensionsv1.JSON{Raw: []byte(`{
		"preseed": {
			"files": [
				{
					"path": "$HOME/.custom/config.json",
					"json": {"enabled": true}
				}
			]
		}
	}`)}
	agentRun.Spec.Runtime.Type = "codex"

	rendered, err := RenderAgentConfigYAML(agentRun)
	if err != nil {
		t.Fatalf("render AgentRun agent config: %v", err)
	}

	if strings.Contains(rendered, "check_for_update_on_startup") {
		t.Fatalf("operator overwrote user preseed:\n%s", rendered)
	}
	config := parseAgentConfigYAML(t, rendered)
	preseed := config["preseed"].(map[string]any)
	files := preseed["files"].([]any)
	file := files[0].(map[string]any)
	if file["path"] != "$HOME/.custom/config.json" {
		t.Fatalf("expected user preseed to be preserved, got %#v\n%s", file, rendered)
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

func TestRenderAgentConfigYAMLRejectsRuntimeInitialPromptConflict(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Spec.Agent.Config = apiextensionsv1.JSON{Raw: []byte(`{
		"runtime": {
			"initial-prompt": {
				"delivery": "argument",
				"text": "configured"
			}
		}
	}`)}
	agentRun.Spec.Prompt = &nvtv1alpha1.AgentRunPrompt{Text: "ambiguous"}

	_, err := RenderAgentConfigYAML(agentRun)
	if err == nil {
		t.Fatal("expected runtime initial-prompt conflict to fail")
	}
	if !strings.Contains(err.Error(), "runtime.initial-prompt is already configured") {
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

func TestAgentRunCRDSchemaBoundsWorkspaceInstructions(t *testing.T) {
	data, err := os.ReadFile("../../config/crd/bases/nvt.dev_agentruns.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var crd map[string]any
	if err := yaml.Unmarshal(data, &crd); err != nil {
		t.Fatal(err)
	}
	if got := crdPath(t, crd,
		"spec", "versions", 0, "schema", "openAPIV3Schema", "properties",
		"spec", "properties", "agent", "properties", "workspaceInstructions", "maxLength",
	); fmt.Sprint(got) != "65536" {
		t.Fatalf("workspaceInstructions maxLength = %#v", got)
	}
	if got := crdPath(t, crd,
		"spec", "versions", 0, "schema", "openAPIV3Schema", "properties",
		"spec", "properties", "agent", "properties", "workflowInstructions", "maxLength",
	); fmt.Sprint(got) != "65536" {
		t.Fatalf("workflowInstructions maxLength = %#v", got)
	}
}

func TestAgentRunCRDSchemaIncludesPersistentWorkspace(t *testing.T) {
	data, err := os.ReadFile("../../config/crd/bases/nvt.dev_agentruns.yaml")
	if err != nil {
		t.Fatalf("read AgentRun CRD: %v", err)
	}
	var crd map[string]any
	if err := yaml.Unmarshal(data, &crd); err != nil {
		t.Fatalf("parse AgentRun CRD: %v", err)
	}
	workspace, ok := crdPath(t, crd,
		"spec", "versions", 0, "schema", "openAPIV3Schema", "properties",
		"spec", "properties", "workspace",
	).(map[string]any)
	if !ok {
		t.Fatalf("workspace schema = %#v", workspace)
	}
	mode := crdPath(t, workspace, "properties", "mode").(map[string]any)
	if mode["default"] != "Ephemeral" || !reflect.DeepEqual(mode["enum"], []any{"Ephemeral", "Persistent"}) {
		t.Fatalf("workspace mode schema = %#v", mode)
	}
	if crdPath(t, workspace, "properties", "size", "x-kubernetes-int-or-string") != true {
		t.Fatal("workspace size must use Kubernetes quantity schema")
	}
	if crdPath(t, workspace, "properties", "dockerSize", "x-kubernetes-int-or-string") != true {
		t.Fatal("workspace dockerSize must use Kubernetes quantity schema")
	}
	if crdPath(t, workspace, "properties", "storageClassName", "type") != "string" {
		t.Fatal("workspace storageClassName must be a string")
	}
	validations, ok := workspace["x-kubernetes-validations"].([]any)
	if !ok || len(validations) < 4 {
		t.Fatalf("workspace validations = %#v", workspace["x-kubernetes-validations"])
	}
	if !hasCRDValidation(validations, "self.mode == 'Persistent' ? has(self.size) : !has(self.size) && !has(self.dockerSize) && !has(self.storageClassName)", "forbidden for Ephemeral") ||
		!hasCRDValidation(validations, "!has(self.dockerSize) || !quantity('1Gi').isGreaterThan(quantity(string(self.dockerSize)))", "at least 1Gi") ||
		!hasCRDValidation(validations, "!has(self.dockerSize) || !quantity(string(self.dockerSize)).isGreaterThan(quantity('1Ti'))", "at most 1Ti") {
		t.Fatalf("workspace Docker-size CEL validations are incomplete: %#v", validations)
	}
}

func TestAgentRunCRDSchemaIncludesTolerations(t *testing.T) {
	data, err := os.ReadFile("../../config/crd/bases/nvt.dev_agentruns.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var crd map[string]any
	if err := yaml.Unmarshal(data, &crd); err != nil {
		t.Fatal(err)
	}
	tolerations := crdPath(t, crd,
		"spec", "versions", 0, "schema", "openAPIV3Schema", "properties",
		"spec", "properties", "tolerations",
	).(map[string]any)
	if tolerations["type"] != "array" || crdPath(t, tolerations, "items", "properties", "tolerationSeconds", "format") != "int64" {
		t.Fatalf("AgentRun tolerations schema incomplete: %#v", tolerations)
	}
}

func TestAgentRunCRDSchemaIncludesContainerCapabilities(t *testing.T) {
	data, err := os.ReadFile("../../config/crd/bases/nvt.dev_agentruns.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var crd map[string]any
	if err := yaml.Unmarshal(data, &crd); err != nil {
		t.Fatal(err)
	}
	add := crdPath(t, crd,
		"spec", "versions", 0, "schema", "openAPIV3Schema", "properties", "spec", "properties",
		"runtime", "properties", "container", "properties", "capabilities", "properties", "add",
	).(map[string]any)
	values := crdPath(t, add, "items", "enum").([]any)
	if add["x-kubernetes-list-type"] != "set" || !containsAny(values, "SYS_PTRACE") || !containsAny(values, "CHECKPOINT_RESTORE") {
		t.Fatalf("AgentRun container capability schema incomplete: %#v", add)
	}
}

func TestAuthoritativeCRDCapabilityEnumsMatchRuntimeRegistry(t *testing.T) {
	tests := []struct {
		name string
		path string
		keys []any
	}{
		{
			name: "AgentRun",
			path: "../../config/crd/bases/nvt.dev_agentruns.yaml",
			keys: []any{"spec", "properties", "runtime", "properties", "container", "properties", "capabilities", "properties", "add"},
		},
		{
			name: "AgentSchedule",
			path: "../../config/crd/bases/nvt.dev_agentschedules.yaml",
			keys: []any{"spec", "properties", "profiles", "items", "properties", "runtime", "properties", "container", "properties", "capabilities", "properties", "add"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := os.ReadFile(test.path)
			if err != nil {
				t.Fatal(err)
			}
			var crd map[string]any
			if err := yaml.Unmarshal(data, &crd); err != nil {
				t.Fatal(err)
			}
			path := []any{"spec", "versions", 0, "schema", "openAPIV3Schema", "properties"}
			path = append(path, test.keys...)
			add := crdPath(t, crd, path...).(map[string]any)
			got := make(map[corev1.Capability]struct{})
			for _, value := range crdPath(t, add, "items", "enum").([]any) {
				name, ok := value.(string)
				if !ok {
					t.Fatalf("capability enum contains non-string value %#v", value)
				}
				capability := corev1.Capability(name)
				if _, duplicate := got[capability]; duplicate {
					t.Fatalf("capability enum contains duplicate %q", capability)
				}
				got[capability] = struct{}{}
			}
			if !reflect.DeepEqual(got, linuxCapabilityNames) {
				t.Fatalf("%s capability enum differs from runtime registry: got=%v want=%v", test.name, got, linuxCapabilityNames)
			}
		})
	}
}

func TestAgentRunCRDSchemaBoundsProviderPreparations(t *testing.T) {
	data, err := os.ReadFile("../../config/crd/bases/nvt.dev_agentruns.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var crd map[string]any
	if err := yaml.Unmarshal(data, &crd); err != nil {
		t.Fatal(err)
	}
	operation := crdPath(t, crd,
		"spec", "versions", 0, "schema", "openAPIV3Schema", "properties", "spec", "properties",
		"broker", "properties", "grants", "items", "properties", "preparations", "items", "properties", "operation",
	).(map[string]any)
	if operation["type"] != "string" || !reflect.DeepEqual(operation["enum"], []any{"identity"}) {
		t.Fatalf("provider preparation operation is not bounded: %#v", operation)
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
	assertStrictCRDSchema(t, data)
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
	if crdPath(t, spec, "egressEnforcement", "default") != false {
		t.Fatalf("expected egressEnforcement default false, got %#v", crdPath(t, spec, "egressEnforcement"))
	}
	legacy := crdPath(t, spec, "egressForwardProxy").(map[string]any)
	if legacy["type"] != "boolean" || !strings.Contains(fmt.Sprint(legacy["description"]), "Deprecated:") {
		t.Fatalf("legacy egressForwardProxy must remain only as a deprecated tombstone: %#v", legacy)
	}
	validations := crdPath(t, crd,
		"spec", "versions", 0, "schema", "openAPIV3Schema",
		"properties", "spec", "x-kubernetes-validations").([]any)
	if !hasCRDValidation(validations, "!has(self.egressForwardProxy)", "use spec.egressTransport") {
		t.Fatalf("missing rejection CEL for legacy egressForwardProxy: %#v", validations)
	}
	transport := crdPath(t, spec, "egressTransport").(map[string]any)
	if !reflect.DeepEqual(transport["enum"], []any{"redirect", "forward-proxy", "transparent"}) {
		t.Fatalf("expected egressTransport to be the sole transport selector, got %#v", transport)
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
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{
			{Name: roleLabelAgent, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1}}},
			{Name: roleLabelEgressd, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
		}},
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

func TestSyncAgentRunStatusFromPodFailsWhenAgentContainerTerminates(t *testing.T) {
	now := metav1.NewTime(time.Unix(123, 0))
	agentRun := testAgentRun()
	agentRun.Status.Phase = nvtv1alpha1.AgentRunPhaseRunning
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: AgentPodName(agentRun.Name)},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{
			{Name: roleLabelAgent, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1, Message: "untrusted diagnostic"}}},
			{Name: roleLabelEgressd, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
		}},
	}

	if !SyncAgentRunStatusFromPod(agentRun, pod, now) {
		t.Fatal("expected terminated agent container to update AgentRun status")
	}
	if agentRun.Status.Phase != nvtv1alpha1.AgentRunPhaseFailed {
		t.Fatalf("expected Failed phase, got %q", agentRun.Status.Phase)
	}
	if agentRun.Status.FinishedAt == nil || !agentRun.Status.FinishedAt.Equal(&now) {
		t.Fatalf("expected finishedAt %s, got %#v", now, agentRun.Status.FinishedAt)
	}
	if agentRun.Status.Reason != unexpectedAgentExitReason || strings.Contains(agentRun.Status.Reason, "untrusted") {
		t.Fatalf("unexpected or unsanitized reason %q", agentRun.Status.Reason)
	}
}

func TestSyncAgentRunLifecycleFromPodTerminationWinsAgentContainerFailure(t *testing.T) {
	tests := []struct {
		name           string
		event          string
		expectedPhase  nvtv1alpha1.AgentRunPhase
		expectedReason string
	}{
		{name: "completed", event: "plugin.smoke.completed", expectedPhase: nvtv1alpha1.AgentRunPhaseCompleted, expectedReason: "Completed by lifecycle event plugin.smoke.completed"},
		{name: "failed", event: "plugin.smoke.failed", expectedPhase: nvtv1alpha1.AgentRunPhaseFailed, expectedReason: "Failed by lifecycle event plugin.smoke.failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := metav1.NewTime(time.Unix(123, 0))
			agentRun := transparentAgentRun(t)
			agentRun.Spec.Lifecycle = &nvtv1alpha1.AgentRunLifecycle{
				CompleteOn: []string{"plugin.smoke.completed"},
				FailOn:     []string{"plugin.smoke.failed"},
			}
			agentRun.Status.Phase = nvtv1alpha1.AgentRunPhaseRunning
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: AgentPodName(agentRun.Name)},
				Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
					Name: roleLabelAgent,
					State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
						ExitCode: 1,
						Message:  fmt.Sprintf(`{"nvtLifecycleEvent":%q,"outcome":%q}`, test.event, test.name),
					}},
				}}},
			}

			if !SyncAgentRunLifecycleFromPodTermination(agentRun, pod, now) {
				t.Fatal("expected lifecycle transition")
			}
			SyncAgentRunStatusFromPod(agentRun, pod, now)
			if agentRun.Status.Phase != test.expectedPhase || agentRun.Status.Reason != test.expectedReason {
				t.Fatalf("lifecycle transition was overwritten: %#v", agentRun.Status)
			}
		})
	}
}

func TestSyncAgentRunStatusFromPodIgnoresRunningAgentAndTerminatedEgressd(t *testing.T) {
	agentRun := testAgentRun()
	agentRun.Status.Phase = nvtv1alpha1.AgentRunPhaseRunning
	agentRun.Status.PodName = AgentPodName(agentRun.Name)
	startedAt := metav1.Now()
	agentRun.Status.StartedAt = &startedAt
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: AgentPodName(agentRun.Name)},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{
			{Name: roleLabelAgent, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
			{Name: roleLabelEgressd, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1}}},
		}},
	}

	if SyncAgentRunStatusFromPod(agentRun, pod, metav1.Now()) {
		t.Fatal("running agent container unexpectedly changed AgentRun status")
	}
	if agentRun.Status.Phase != nvtv1alpha1.AgentRunPhaseRunning || agentRun.Status.FinishedAt != nil {
		t.Fatalf("running agent was marked terminal: %#v", agentRun.Status)
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

func TestReconcileCompletedRunOperationalCleanupTimingAndScope(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)

	t.Run("before TTL retains every resource", func(t *testing.T) {
		finishedAt := metav1.Date(2026, 5, 31, 11, 59, 30, 0, time.UTC)
		agentRun := terminalAgentRun(nvtv1alpha1.AgentRunPhaseCompleted, finishedAt)
		agentRun.Spec.TTL.CompletedTTLSeconds = ptrTo[int64](60)
		k8sClient, reconciler, resources := terminalOperationalCleanupFixture(t, agentRun, now, true)

		result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
		if err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		if result.RequeueAfter != 30*time.Second {
			t.Fatalf("requeue = %s, want 30s", result.RequeueAfter)
		}
		assertTerminalOperationalResources(t, ctx, k8sClient, resources, true)
		assertTerminalBrokerEntries(t, ctx, k8sClient, agentRun, true)
	})

	t.Run("after TTL removes operations and retains metadata", func(t *testing.T) {
		finishedAt := metav1.Date(2026, 5, 31, 11, 58, 0, 0, time.UTC)
		agentRun := terminalAgentRun(nvtv1alpha1.AgentRunPhaseCompleted, finishedAt)
		agentRun.Spec.TTL.CompletedTTLSeconds = ptrTo[int64](60)
		k8sClient, reconciler, resources := terminalOperationalCleanupFixture(t, agentRun, now, true)

		if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		assertTerminalOperationalResources(t, ctx, k8sClient, resources, false)
		assertTerminalBrokerEntries(t, ctx, k8sClient, agentRun, false)
		assertAgentRunPhase(ctx, t, k8sClient, agentRun, nvtv1alpha1.AgentRunPhaseCompleted)

		// A later terminal reconcile is idempotent and cannot recreate resources.
		if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
			t.Fatalf("idempotent reconcile: %v", err)
		}
		assertTerminalOperationalResources(t, ctx, k8sClient, resources, false)
	})
}

func TestReconcileFailedAndDeadlineExceededOperationalCleanup(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		phase nvtv1alpha1.AgentRunPhase
		ttl   *int64
	}{
		{name: "failed after TTL", phase: nvtv1alpha1.AgentRunPhaseFailed, ttl: ptrTo[int64](60)},
		{name: "deadline exceeded immediately", phase: nvtv1alpha1.AgentRunPhaseDeadlineExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			finishedAt := metav1.Date(2026, 5, 31, 11, 58, 0, 0, time.UTC)
			agentRun := terminalAgentRun(test.phase, finishedAt)
			agentRun.Spec.TTL.FailedTTLSeconds = test.ttl
			k8sClient, reconciler, resources := terminalOperationalCleanupFixture(t, agentRun, now, false)

			if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			assertTerminalOperationalResources(t, ctx, k8sClient, resources, false)
			assertTerminalBrokerEntries(t, ctx, k8sClient, agentRun, false)
			assertAgentRunPhase(ctx, t, k8sClient, agentRun, test.phase)
		})
	}
}

func TestReconcileActiveDeadlineImmediatelyCleansAllOperationalResources(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	startedAt := metav1.Date(2026, 5, 31, 11, 58, 0, 0, time.UTC)
	agentRun := activeDeadlineAgentRun(startedAt, ptrTo[int64](60))
	k8sClient, reconciler, resources := terminalOperationalCleanupFixture(t, agentRun, now, true)
	if err := k8sClient.Delete(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: AgentPodName(agentRun.Name), Namespace: agentRun.Namespace}}); err != nil {
		t.Fatal(err)
	}
	validPod, err := DesiredAgentPod(agentRun, reconciler.Scheme)
	if err != nil {
		t.Fatalf("render active Pod: %v", err)
	}
	if err := k8sClient.Create(ctx, validPod); err != nil {
		t.Fatalf("replace active Pod fixture: %v", err)
	}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	assertAgentRunPhase(ctx, t, k8sClient, agentRun, nvtv1alpha1.AgentRunPhaseDeadlineExceeded)
	assertTerminalOperationalResources(t, ctx, k8sClient, resources, false)
	assertTerminalBrokerEntries(t, ctx, k8sClient, agentRun, false)
}

func TestReconcileTerminalCleanupEphemeralRunHasNoWorkspacePVC(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	finishedAt := metav1.Date(2026, 5, 31, 11, 58, 0, 0, time.UTC)
	agentRun := terminalAgentRun(nvtv1alpha1.AgentRunPhaseCompleted, finishedAt)
	agentRun.Spec.TTL.CompletedTTLSeconds = ptrTo[int64](60)
	k8sClient, reconciler, resources := terminalOperationalCleanupFixture(t, agentRun, now, false)

	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: WorkspacePVCName(agentRun.Name)}, &corev1.PersistentVolumeClaim{}); !errors.IsNotFound(err) {
		t.Fatalf("ephemeral run unexpectedly has workspace PVC: %v", err)
	}
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: DockerPVCName(agentRun.Name)}, &corev1.PersistentVolumeClaim{}); !errors.IsNotFound(err) {
		t.Fatalf("ephemeral run unexpectedly has Docker PVC: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	assertTerminalOperationalResources(t, ctx, k8sClient, resources, false)
	assertAgentRunPhase(ctx, t, k8sClient, agentRun, nvtv1alpha1.AgentRunPhaseCompleted)
}

func TestReconcileTerminalCleanupRejectsForeignObjectButContinues(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	finishedAt := metav1.Date(2026, 5, 31, 11, 58, 0, 0, time.UTC)
	agentRun := terminalAgentRun(nvtv1alpha1.AgentRunPhaseCompleted, finishedAt)
	agentRun.Spec.TTL.CompletedTTLSeconds = ptrTo[int64](60)
	k8sClient, reconciler, resources := terminalOperationalCleanupFixture(t, agentRun, now, true)

	foreign := &corev1.ConfigMap{}
	key := types.NamespacedName{Namespace: agentRun.Namespace, Name: AgentConfigMapName(agentRun.Name)}
	if err := k8sClient.Get(ctx, key, foreign); err != nil {
		t.Fatal(err)
	}
	foreign.OwnerReferences = nil
	if err := k8sClient.Update(ctx, foreign); err != nil {
		t.Fatal(err)
	}

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err == nil || !strings.Contains(err.Error(), "agent config ConfigMap") || !strings.Contains(err.Error(), "not controlled") {
		t.Fatalf("error = %v, want foreign ownership failure", err)
	}
	if err := k8sClient.Get(ctx, key, &corev1.ConfigMap{}); err != nil {
		t.Fatalf("foreign ConfigMap was deleted: %v", err)
	}
	for _, object := range resources {
		if object.GetName() == key.Name {
			continue
		}
		assertTerminalOperationalResources(t, ctx, k8sClient, []client.Object{object}, false)
	}
	assertTerminalBrokerEntries(t, ctx, k8sClient, agentRun, false)
}

func TestReconcileTerminalCleanupRetriesPartialDeletionAndNotFound(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	finishedAt := metav1.Date(2026, 5, 31, 11, 58, 0, 0, time.UTC)
	agentRun := terminalAgentRun(nvtv1alpha1.AgentRunPhaseCompleted, finishedAt)
	agentRun.Spec.TTL.CompletedTTLSeconds = ptrTo[int64](60)
	baseClient, _, resources := terminalOperationalCleanupFixture(t, agentRun, now, true)
	failingClient := &failDeleteOnceClient{
		Client: baseClient,
		key:    client.ObjectKey{Namespace: agentRun.Namespace, Name: CallbackTokenSecretName(agentRun.Name)},
	}
	reconciler := &AgentRunReconciler{Client: failingClient, Scheme: testScheme(t), Now: func() metav1.Time { return now }}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err == nil || !strings.Contains(err.Error(), "injected delete failure") {
		t.Fatalf("first reconcile error = %v", err)
	}
	if err := baseClient.Get(ctx, failingClient.key, &corev1.Secret{}); err != nil {
		t.Fatalf("failed resource was not retained for retry: %v", err)
	}
	if err := baseClient.Get(ctx, client.ObjectKey{Namespace: agentRun.Namespace, Name: BrokerTokenSecretName(agentRun.Name)}, &corev1.Secret{}); !errors.IsNotFound(err) {
		t.Fatalf("cleanup stopped after partial failure: %v", err)
	}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("NotFound idempotency reconcile: %v", err)
	}
	assertTerminalOperationalResources(t, ctx, baseClient, resources, false)
	assertTerminalBrokerEntries(t, ctx, baseClient, agentRun, false)
}

func TestReconcileTerminalCleanupContinuesWhenBrokerRevocationFails(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	finishedAt := metav1.Date(2026, 5, 31, 11, 58, 0, 0, time.UTC)
	agentRun := terminalAgentRun(nvtv1alpha1.AgentRunPhaseCompleted, finishedAt)
	agentRun.Spec.TTL.CompletedTTLSeconds = ptrTo[int64](60)
	baseClient, _, resources := terminalOperationalCleanupFixture(t, agentRun, now, true)
	failingClient := &failBrokerUpdateOnceClient{Client: baseClient}
	reconciler := &AgentRunReconciler{Client: failingClient, Scheme: testScheme(t), Now: func() metav1.Time { return now }}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err == nil || !strings.Contains(err.Error(), "injected broker update failure") {
		t.Fatalf("first reconcile error = %v", err)
	}
	assertTerminalOperationalResources(t, ctx, baseClient, resources, false)
	assertTerminalBrokerEntries(t, ctx, baseClient, agentRun, true)

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("broker retry reconcile: %v", err)
	}
	assertTerminalBrokerEntries(t, ctx, baseClient, agentRun, false)
}

func TestReconcileTerminalCleanupKeepsFenceUntilDeletingPodsDisappear(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	finishedAt := metav1.Date(2026, 5, 31, 11, 58, 0, 0, time.UTC)
	agentRun := terminalAgentRun(nvtv1alpha1.AgentRunPhaseCompleted, finishedAt)
	agentRun.Spec.TTL.CompletedTTLSeconds = ptrTo[int64](60)
	baseClient, _, resources := terminalOperationalCleanupFixture(t, agentRun, now, true)
	delayedClient := &delayedPodDeleteClient{Client: baseClient, deleting: map[client.ObjectKey]bool{}, attempts: map[client.ObjectKey]int{}}
	reconciler := &AgentRunReconciler{Client: delayedClient, Scheme: testScheme(t), Now: func() metav1.Time { return now }}

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("delayed deletion reconcile: %v", err)
	}
	if result.RequeueAfter != terminalResourceCleanupRequeue {
		t.Fatalf("requeue = %s, want %s", result.RequeueAfter, terminalResourceCleanupRequeue)
	}
	for _, name := range []string{AgentPodName(agentRun.Name), EgressdPodName(agentRun.Name)} {
		key := client.ObjectKey{Namespace: agentRun.Namespace, Name: name}
		pod := &corev1.Pod{}
		if err := delayedClient.Get(ctx, key, pod); err != nil {
			t.Fatalf("get terminating Pod %s: %v", name, err)
		}
		if pod.DeletionTimestamp.IsZero() || delayedClient.attempts[key] != 1 {
			t.Fatalf("Pod %s deletion state timestamp=%v attempts=%d", name, pod.DeletionTimestamp, delayedClient.attempts[key])
		}
	}
	assertTerminalOperationalResources(t, ctx, delayedClient, nonPodOperationalResources(resources), true)
	assertTerminalBrokerEntries(t, ctx, delayedClient, agentRun, false)

	for _, name := range []string{AgentPodName(agentRun.Name), EgressdPodName(agentRun.Name)} {
		if err := baseClient.Delete(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: agentRun.Namespace, Name: name}}); err != nil {
			t.Fatalf("simulate kubelet removal of %s: %v", name, err)
		}
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("post-termination reconcile: %v", err)
	}
	assertTerminalOperationalResources(t, ctx, baseClient, resources, false)
}

func TestReconcileTerminalCleanupPodDeleteFailureKeepsFenceAndAttemptsPeer(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	finishedAt := metav1.Date(2026, 5, 31, 11, 58, 0, 0, time.UTC)
	agentRun := terminalAgentRun(nvtv1alpha1.AgentRunPhaseCompleted, finishedAt)
	agentRun.Spec.TTL.CompletedTTLSeconds = ptrTo[int64](60)
	baseClient, _, resources := terminalOperationalCleanupFixture(t, agentRun, now, true)
	agentKey := client.ObjectKey{Namespace: agentRun.Namespace, Name: AgentPodName(agentRun.Name)}
	egressdKey := client.ObjectKey{Namespace: agentRun.Namespace, Name: EgressdPodName(agentRun.Name)}
	failingClient := &failPodDeleteOnceClient{Client: baseClient, key: agentKey, attempts: map[client.ObjectKey]int{}}
	reconciler := &AgentRunReconciler{Client: failingClient, Scheme: testScheme(t), Now: func() metav1.Time { return now }}

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err == nil || !strings.Contains(err.Error(), "injected Pod delete failure") {
		t.Fatalf("first reconcile error = %v", err)
	}
	if result.RequeueAfter != terminalResourceCleanupRequeue || failingClient.attempts[agentKey] != 1 || failingClient.attempts[egressdKey] != 1 {
		t.Fatalf("result=%#v attempts=%#v", result, failingClient.attempts)
	}
	if err := baseClient.Get(ctx, agentKey, &corev1.Pod{}); err != nil {
		t.Fatalf("failed agent Pod deletion did not retain Pod: %v", err)
	}
	if err := baseClient.Get(ctx, egressdKey, &corev1.Pod{}); !errors.IsNotFound(err) {
		t.Fatalf("peer egressd Pod deletion was not attempted: %v", err)
	}
	assertTerminalOperationalResources(t, ctx, baseClient, nonPodOperationalResources(resources), true)
	assertTerminalBrokerEntries(t, ctx, baseClient, agentRun, false)

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)}); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	assertTerminalOperationalResources(t, ctx, baseClient, resources, false)
}

func TestReconcileTerminalCleanupForeignPodLeavesCompleteFence(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	finishedAt := metav1.Date(2026, 5, 31, 11, 58, 0, 0, time.UTC)
	agentRun := terminalAgentRun(nvtv1alpha1.AgentRunPhaseCompleted, finishedAt)
	agentRun.Spec.TTL.CompletedTTLSeconds = ptrTo[int64](60)
	k8sClient, reconciler, resources := terminalOperationalCleanupFixture(t, agentRun, now, true)

	agentKey := client.ObjectKey{Namespace: agentRun.Namespace, Name: AgentPodName(agentRun.Name)}
	foreign := &corev1.Pod{}
	if err := k8sClient.Get(ctx, agentKey, foreign); err != nil {
		t.Fatal(err)
	}
	foreign.OwnerReferences = nil
	if err := k8sClient.Update(ctx, foreign); err != nil {
		t.Fatal(err)
	}

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err == nil || !strings.Contains(err.Error(), "agent Pod") || !strings.Contains(err.Error(), "not controlled") {
		t.Fatalf("error = %v, want foreign Pod ownership failure", err)
	}
	if result.RequeueAfter != terminalResourceCleanupRequeue {
		t.Fatalf("requeue = %s", result.RequeueAfter)
	}
	assertTerminalOperationalResources(t, ctx, k8sClient, resources, true)
	assertTerminalBrokerEntries(t, ctx, k8sClient, agentRun, false)
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
	agentRun.Spec.TTL.FailedTTLSeconds = ptrTo[int64](60)
	k8sClient, reconciler, resources := terminalOperationalCleanupFixture(t, agentRun, now, true)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: clientKey(agentRun)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %s", result.RequeueAfter)
	}
	assertAgentRunPhase(ctx, t, k8sClient, agentRun, nvtv1alpha1.AgentRunPhaseFailed)
	assertTerminalOperationalResources(t, ctx, k8sClient, resources, false)
	assertTerminalBrokerEntries(t, ctx, k8sClient, agentRun, false)
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
	if err := networkingv1.AddToScheme(scheme); err != nil {
		t.Fatalf("add networking scheme: %v", err)
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

func persistentWorkspace(size, storageClass string) nvtv1alpha1.AgentRunWorkspace {
	quantity := resource.MustParse(size)
	return nvtv1alpha1.AgentRunWorkspace{
		Mode:             nvtv1alpha1.AgentRunWorkspacePersistent,
		Size:             &quantity,
		StorageClassName: storageClass,
	}
}

func persistentWorkspaceWithDocker(size, dockerSize, storageClass string) nvtv1alpha1.AgentRunWorkspace {
	workspace := persistentWorkspace(size, storageClass)
	quantity := resource.MustParse(dockerSize)
	workspace.DockerSize = &quantity
	return workspace
}

func getWorkspacePVC(ctx context.Context, t *testing.T, k8sClient client.Client, agentRun *nvtv1alpha1.AgentRun) *corev1.PersistentVolumeClaim {
	t.Helper()
	claim := &corev1.PersistentVolumeClaim{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: WorkspacePVCName(agentRun.Name)}, claim); err != nil {
		t.Fatalf("get workspace PVC: %v", err)
	}
	return claim
}

func getDockerPVC(ctx context.Context, t *testing.T, k8sClient client.Client, agentRun *nvtv1alpha1.AgentRun) *corev1.PersistentVolumeClaim {
	t.Helper()
	claim := &corev1.PersistentVolumeClaim{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentRun.Namespace, Name: DockerPVCName(agentRun.Name)}, claim); err != nil {
		t.Fatalf("get Docker PVC: %v", err)
	}
	return claim
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

func terminalOperationalCleanupFixture(
	t *testing.T,
	agentRun *nvtv1alpha1.AgentRun,
	now metav1.Time,
	persistent bool,
) (client.Client, *AgentRunReconciler, []client.Object) {
	t.Helper()
	if persistent {
		size := resource.MustParse("5Gi")
		agentRun.Spec.Workspace = nvtv1alpha1.AgentRunWorkspace{Mode: nvtv1alpha1.AgentRunWorkspacePersistent, Size: &size}
	}

	scheme := testScheme(t)
	owner := *metav1.NewControllerRef(agentRun, nvtv1alpha1.GroupVersion.WithKind("AgentRun"))
	metadata := func(name string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: name, Namespace: agentRun.Namespace, OwnerReferences: []metav1.OwnerReference{owner}}
	}
	resources := []client.Object{
		&corev1.Pod{ObjectMeta: metadata(AgentPodName(agentRun.Name))},
		&corev1.Pod{ObjectMeta: metadata(EgressdPodName(agentRun.Name))},
		&corev1.Service{ObjectMeta: metadata(EgressdServiceName(agentRun.Name))},
		&networkingv1.NetworkPolicy{ObjectMeta: metadata(AgentNetworkPolicyName(agentRun.Name))},
		&networkingv1.NetworkPolicy{ObjectMeta: metadata(EgressdNetworkPolicyName(agentRun.Name))},
		&corev1.ConfigMap{ObjectMeta: metadata(AgentConfigMapName(agentRun.Name))},
		&corev1.ConfigMap{ObjectMeta: metadata(EgressdConfigMapName(agentRun.Name))},
		&corev1.ConfigMap{ObjectMeta: metadata(EgressCAConfigMapName(agentRun.Name))},
		&corev1.Secret{ObjectMeta: metadata(BrokerTokenSecretName(agentRun.Name))},
		&corev1.Secret{ObjectMeta: metadata(EgressTokenSecretName(agentRun.Name))},
		&corev1.Secret{ObjectMeta: metadata(CallbackTokenSecretName(agentRun.Name))},
		&corev1.Secret{ObjectMeta: metadata(EgressCASecretName(agentRun.Name))},
	}
	if persistent {
		resources = append(resources,
			&corev1.PersistentVolumeClaim{ObjectMeta: metadata(WorkspacePVCName(agentRun.Name))},
			&corev1.PersistentVolumeClaim{ObjectMeta: metadata(DockerPVCName(agentRun.Name))},
		)
	}

	renderedPolicy, err := RenderBrokerAgentsYAML(brokerAgentsPolicy{Agents: []brokerAgentEntry{
		{ID: AgentRunBrokerID(agentRun.Namespace, agentRun.Name), TokenSHA256: validTestTokenHash("agent"), Grants: []brokerAgentGrantEntry{}},
		{ID: AgentRunEgressBrokerID(agentRun.Namespace, agentRun.Name), TokenSHA256: validTestTokenHash("egress"), Role: "egress", PairedAgent: AgentRunBrokerID(agentRun.Namespace, agentRun.Name), Grants: []brokerAgentGrantEntry{}},
		{ID: AgentRunBrokerID(agentRun.Namespace, "unrelated"), TokenSHA256: validTestTokenHash("unrelated"), Grants: []brokerAgentGrantEntry{}},
	}})
	if err != nil {
		t.Fatalf("render terminal broker fixture: %v", err)
	}
	brokerConfig := testBrokerAgentsConfigMap(agentRun.Namespace)
	brokerConfig.Data[brokerAgentsConfigKey] = renderedPolicy
	objects := append([]client.Object{agentRun, brokerConfig}, resources...)
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(objects...).
		Build()
	persistAgentRunStatus(context.Background(), t, k8sClient, agentRun)
	reconciler := &AgentRunReconciler{Client: k8sClient, Scheme: scheme, Now: func() metav1.Time { return now }}
	return k8sClient, reconciler, resources
}

func assertTerminalOperationalResources(t *testing.T, ctx context.Context, reader client.Reader, resources []client.Object, present bool) {
	t.Helper()
	for _, expected := range resources {
		actual := expected.DeepCopyObject().(client.Object)
		err := reader.Get(ctx, client.ObjectKeyFromObject(expected), actual)
		if present && err != nil {
			t.Fatalf("expected %T %s/%s to remain: %v", expected, expected.GetNamespace(), expected.GetName(), err)
		}
		if !present && !errors.IsNotFound(err) {
			t.Fatalf("expected %T %s/%s to be deleted, got %v", expected, expected.GetNamespace(), expected.GetName(), err)
		}
	}
}

func nonPodOperationalResources(resources []client.Object) []client.Object {
	filtered := make([]client.Object, 0, len(resources))
	for _, object := range resources {
		if _, isPod := object.(*corev1.Pod); !isPod {
			filtered = append(filtered, object)
		}
	}
	return filtered
}

func assertTerminalBrokerEntries(t *testing.T, ctx context.Context, reader client.Reader, agentRun *nvtv1alpha1.AgentRun, present bool) {
	t.Helper()
	configMap := &corev1.ConfigMap{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: agentRun.Namespace, Name: brokerAgentsConfigMapName}, configMap); err != nil {
		t.Fatal(err)
	}
	policy := mustParseBrokerAgentsPolicy(t, configMap.Data[brokerAgentsConfigKey])
	foundAgent := false
	foundEgress := false
	foundUnrelated := false
	for _, entry := range policy.Agents {
		switch entry.ID {
		case AgentRunBrokerID(agentRun.Namespace, agentRun.Name):
			foundAgent = true
		case AgentRunEgressBrokerID(agentRun.Namespace, agentRun.Name):
			foundEgress = true
		case AgentRunBrokerID(agentRun.Namespace, "unrelated"):
			foundUnrelated = true
		}
	}
	if foundAgent != present || foundEgress != present || !foundUnrelated {
		t.Fatalf("broker entries agent=%t egress=%t unrelated=%t, want run entries present=%t: %#v", foundAgent, foundEgress, foundUnrelated, present, policy.Agents)
	}
}

type failDeleteOnceClient struct {
	client.Client
	key    client.ObjectKey
	failed bool
}

func (c *failDeleteOnceClient) Delete(ctx context.Context, object client.Object, options ...client.DeleteOption) error {
	if !c.failed && client.ObjectKeyFromObject(object) == c.key {
		c.failed = true
		return fmt.Errorf("injected delete failure")
	}
	return c.Client.Delete(ctx, object, options...)
}

type failBrokerUpdateOnceClient struct {
	client.Client
	failed bool
}

func (c *failBrokerUpdateOnceClient) Update(ctx context.Context, object client.Object, options ...client.UpdateOption) error {
	if !c.failed && object.GetName() == brokerAgentsConfigMapName {
		if _, ok := object.(*corev1.ConfigMap); ok {
			c.failed = true
			return fmt.Errorf("injected broker update failure")
		}
	}
	return c.Client.Update(ctx, object, options...)
}

type delayedPodDeleteClient struct {
	client.Client
	deleting map[client.ObjectKey]bool
	attempts map[client.ObjectKey]int
}

func (c *delayedPodDeleteClient) Delete(ctx context.Context, object client.Object, options ...client.DeleteOption) error {
	if _, isPod := object.(*corev1.Pod); isPod {
		key := client.ObjectKeyFromObject(object)
		c.deleting[key] = true
		c.attempts[key]++
		return nil
	}
	return c.Client.Delete(ctx, object, options...)
}

func (c *delayedPodDeleteClient) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	if err := c.Client.Get(ctx, key, object, options...); err != nil {
		return err
	}
	if pod, isPod := object.(*corev1.Pod); isPod && c.deleting[key] {
		deletionTimestamp := metav1.Now()
		pod.DeletionTimestamp = &deletionTimestamp
	}
	return nil
}

type failPodDeleteOnceClient struct {
	client.Client
	key      client.ObjectKey
	attempts map[client.ObjectKey]int
	failed   bool
}

func (c *failPodDeleteOnceClient) Delete(ctx context.Context, object client.Object, options ...client.DeleteOption) error {
	if _, isPod := object.(*corev1.Pod); isPod {
		key := client.ObjectKeyFromObject(object)
		c.attempts[key]++
		if key == c.key && !c.failed {
			c.failed = true
			return fmt.Errorf("injected Pod delete failure")
		}
	}
	return c.Client.Delete(ctx, object, options...)
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

func hasCRDValidation(validations []any, rule, messageFragment string) bool {
	for _, raw := range validations {
		validation, ok := raw.(map[string]any)
		if ok && validation["rule"] == rule && strings.Contains(fmt.Sprint(validation["message"]), messageFragment) {
			return true
		}
	}
	return false
}

func containsAny(values []any, expected any) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func assertStrictCRDSchema(t *testing.T, data []byte) {
	t.Helper()
	var crd apiextensionsv1.CustomResourceDefinition
	if err := yaml.UnmarshalStrict(data, &crd); err != nil {
		t.Fatalf("CRD contains a field unsupported by Kubernetes: %v", err)
	}
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

func assertEgressdPodMissing(ctx context.Context, t *testing.T, k8sClient client.Reader, agentRun *nvtv1alpha1.AgentRun) {
	t.Helper()

	var pod corev1.Pod
	key := types.NamespacedName{Name: EgressdPodName(agentRun.Name), Namespace: agentRun.Namespace}
	if err := k8sClient.Get(ctx, key, &pod); err == nil {
		t.Fatalf("expected egressd Pod to be missing")
	} else if !errors.IsNotFound(err) {
		t.Fatalf("get egressd Pod: %v", err)
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

func getEgressdPod(
	ctx context.Context,
	t *testing.T,
	k8sClient client.Reader,
	agentRun *nvtv1alpha1.AgentRun,
) corev1.Pod {
	t.Helper()

	var pod corev1.Pod
	key := types.NamespacedName{Name: EgressdPodName(agentRun.Name), Namespace: agentRun.Namespace}
	if err := k8sClient.Get(ctx, key, &pod); err != nil {
		t.Fatalf("get egressd Pod: %v", err)
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

func assertVolumeMountAt(t *testing.T, container corev1.Container, name, mountPath, subPath string, readOnly bool) {
	t.Helper()
	for _, mount := range container.VolumeMounts {
		if mount.Name == name && mount.MountPath == mountPath {
			if mount.SubPath != subPath || mount.ReadOnly != readOnly {
				t.Fatalf("unexpected volume mount %q at %q: %#v", name, mountPath, mount)
			}
			return
		}
	}
	t.Fatalf("volume mount %q at %q not found in %#v", name, mountPath, container.VolumeMounts)
}

func assertNoVolumeMount(t *testing.T, container corev1.Container, name string) {
	t.Helper()

	for _, mount := range container.VolumeMounts {
		if mount.Name == name {
			t.Fatalf("unexpected volume mount %q in %#v", name, container.VolumeMounts)
		}
	}
}

func assertNoVolumeMountPath(t *testing.T, container corev1.Container, mountPath string) {
	t.Helper()
	for _, mount := range container.VolumeMounts {
		if mount.MountPath == mountPath {
			t.Fatalf("container %q unexpectedly mounts %q: %#v", container.Name, mountPath, mount)
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

func applyServerAdmissionDefaults(pod *corev1.Pod, injectServiceAccountProjection bool) {
	pod.Spec.ServiceAccountName = "default"
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{}
	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Secret != nil && pod.Spec.Volumes[i].Secret.DefaultMode == nil {
			pod.Spec.Volumes[i].Secret.DefaultMode = ptrTo(defaultProjectedVolumeMode)
		}
		if pod.Spec.Volumes[i].Projected != nil && pod.Spec.Volumes[i].Projected.DefaultMode == nil {
			pod.Spec.Volumes[i].Projected.DefaultMode = ptrTo(defaultProjectedVolumeMode)
		}
	}
	for i := range pod.Spec.InitContainers {
		if pod.Spec.InitContainers[i].SecurityContext == nil {
			pod.Spec.InitContainers[i].SecurityContext = &corev1.SecurityContext{}
		}
	}
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].SecurityContext == nil {
			pod.Spec.Containers[i].SecurityContext = &corev1.SecurityContext{}
		}
	}
	if !injectServiceAccountProjection {
		return
	}
	saVolumeName := "kube-api-access-server-default"
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name: saVolumeName,
		VolumeSource: corev1.VolumeSource{
			Projected: &corev1.ProjectedVolumeSource{
				DefaultMode: ptrTo(defaultProjectedVolumeMode),
				Sources: []corev1.VolumeProjection{
					{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Audience: "https://kubernetes.default.svc", Path: "token"}},
					{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "kube-root-ca.crt"}}},
					{DownwardAPI: &corev1.DownwardAPIProjection{}},
				},
			},
		},
	})
	if len(pod.Spec.Containers) > 0 {
		pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
			Name:      saVolumeName,
			MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
			ReadOnly:  true,
		})
	}
}

func forwardProxyAgentRun() *nvtv1alpha1.AgentRun {
	agentRun := testAgentRun()
	agentRun.Spec.Egress = nvtv1alpha1.AgentRunEgressMediated
	agentRun.Spec.EgressEnforcement = true
	agentRun.Spec.EgressTransport = nvtv1alpha1.AgentRunEgressTransportForwardProxy
	agentRun.Spec.EgressAllowInsecureBroker = true
	agentRun.Spec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "codex-main", Materialization: nvtv1alpha1.AgentRunGrantPlaceholderFile,
		EgressHosts: []string{"chatgpt.com:443", "auth.openai.com:443"},
	}}}
	return agentRun
}

func transparentAgentRun(t *testing.T) *nvtv1alpha1.AgentRun {
	t.Helper()
	t.Setenv("NVT_NETWORK_POLICY_CAPABLE", "true")
	run := forwardProxyAgentRun()
	run.Spec.EgressTransport = nvtv1alpha1.AgentRunEgressTransportTransparent
	return run
}

func TestTransparentAdmissionAndPodTransportBoundary(t *testing.T) {
	run := transparentAgentRun(t)
	if err := ValidateAgentRunEgressMode(run); err != nil {
		t.Fatalf("transparent run rejected: %v", err)
	}
	pod, err := DesiredAgentPod(run, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, container := range pod.Spec.InitContainers {
		names = append(names, container.Name)
	}
	if strings.Join(names, ",") != "captured,docker,net-init" {
		t.Fatalf("native sidecar/init order = %v", names)
	}
	captured := pod.Spec.InitContainers[0]
	if captured.RestartPolicy == nil || *captured.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatal("captured must be a native sidecar")
	}
	for _, env := range captured.Env {
		if strings.Contains(env.Name, "TOKEN") || env.ValueFrom != nil {
			t.Fatalf("captured received credential-bearing env: %#v", env)
		}
	}
	netInit := pod.Spec.InitContainers[2]
	if netInit.SecurityContext == nil || netInit.SecurityContext.Privileged != nil ||
		len(netInit.SecurityContext.Capabilities.Add) != 1 || netInit.SecurityContext.Capabilities.Add[0] != "NET_ADMIN" {
		t.Fatalf("net-init capability boundary = %#v", netInit.SecurityContext)
	}
	if !strings.Contains(netInit.Args[0], "iptables") || !strings.Contains(netInit.Args[0], "ip6tables") || !strings.Contains(netInit.Args[0], "docker0") {
		t.Fatalf("net-init rules incomplete: %q", netInit.Args)
	}
	if strings.Contains(netInit.Args[0], "NVT_CAPTURE_EXCLUDE_CIDRS") || !strings.Contains(netInit.Args[0], "getent ahosts") {
		t.Fatalf("net-init must resolve only narrow control-plane exceptions: %q", netInit.Args)
	}
	if got := envValue(netInit, "NVT_CAPTURE_EXCLUDE_HOSTS"); got != EgressdServiceName(run.Name)+" kubernetes.default.svc kube-dns.kube-system.svc" {
		t.Fatalf("net-init control-plane exceptions = %q", got)
	}
	proxyEnv := map[string]string{}
	for _, env := range pod.Spec.Containers[0].Env {
		proxyEnv[env.Name] = env.Value
	}
	if proxyEnv["HTTPS_PROXY"] != "http://127.0.0.1:15002" {
		t.Fatalf("agent explicit proxy does not point to captured: %q", proxyEnv["HTTPS_PROXY"])
	}
	for _, name := range []string{"HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		if proxyEnv[name] != "" {
			t.Fatalf("transparent agent must clear %s: %#v", name, proxyEnv)
		}
	}
	config := InjectMediatedEgressConfig(map[string]any{}, run)
	egress, _ := config["egress"].(map[string]any)
	if got := egress["forward-proxy-url"]; got != "http://127.0.0.1:15002" {
		t.Fatalf("bootstrap proxy URL bypasses captured: %v", got)
	}
	if got := egress["transport"]; got != string(nvtv1alpha1.AgentRunEgressTransportTransparent) {
		t.Fatalf("bootstrap egress transport = %v", got)
	}
}

func TestLiteralZeroSecretPodHasNoReusableCredentialProjection(t *testing.T) {
	run := transparentAgentRun(t)
	pod, err := DesiredAgentPod(run, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		t.Fatal("Agent Pod must disable service-account token projection")
	}
	for _, volume := range pod.Spec.Volumes {
		if volume.Secret != nil || volume.Projected != nil {
			t.Fatalf("Agent Pod projected a Secret/service-account volume: %#v", volume)
		}
	}
	allContainers := append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...)
	for _, container := range allContainers {
		for _, env := range container.Env {
			if env.ValueFrom != nil || env.Name == brokerTokenKey || env.Name == callbackTokenKey || env.Name == egressTokenKey {
				t.Fatalf("untrusted container %s received credential env %#v", container.Name, env)
			}
		}
		serialized, _ := json.Marshal(container)
		for _, forbidden := range []string{BrokerTokenSecretName(run.Name), CallbackTokenSecretName(run.Name), EgressTokenSecretName(run.Name), EgressCASecretName(run.Name)} {
			if strings.Contains(string(serialized), forbidden) {
				t.Fatalf("untrusted container %s references Secret %s", container.Name, forbidden)
			}
		}
	}
	egressd, err := DesiredEgressdPod(run, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	if egressd.Spec.AutomountServiceAccountToken == nil || *egressd.Spec.AutomountServiceAccountToken {
		t.Fatal("egressd Pod must disable unnecessary service-account projection")
	}
	assertSecretKeyEnv(t, egressd.Spec.Containers[0], "NVT_BROKER_TOKEN", EgressTokenSecretName(run.Name), egressTokenKey)
}

func TestLiteralZeroSecretTLSBrokerCATrustStaysWithTrustedComponents(t *testing.T) {
	setTLSBrokerEnv(t)
	run := transparentAgentRun(t)
	agentPod, err := DesiredAgentPod(run, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, volume := range agentPod.Spec.Volumes {
		if volume.Name == brokerCAVolumeName {
			t.Fatalf("literal zero-secret Agent Pod mounted broker CA Secret: %#v", volume)
		}
	}
	egressdPod, err := DesiredEgressdPod(run, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	volume := requireVolume(t, *egressdPod, brokerCAVolumeName)
	if volume.Secret == nil || volume.Secret.SecretName != BrokerCASecretName() {
		t.Fatalf("trusted egressd lost broker CA trust: %#v", volume)
	}
}

func TestRedirectCAConstraintsDoNotIncludeForwardProxyUpstreams(t *testing.T) {
	if hosts := forwardProxyUpstreamHosts(enforcedAgentRun()); len(hosts) != 0 {
		t.Fatalf("redirect run widened durable CA for forward-proxy hosts: %v", hosts)
	}
	if hosts := forwardProxyUpstreamHosts(forwardProxyAgentRun()); len(hosts) == 0 {
		t.Fatal("forward-proxy run omitted its MITM upstream CA constraints")
	}
}

func TestLiteralZeroSecretLifecycleUsesTerminationMessage(t *testing.T) {
	run := transparentAgentRun(t)
	run.Spec.Lifecycle = &nvtv1alpha1.AgentRunLifecycle{CompleteOn: []string{"plugin.smoke.completed"}, FailOn: []string{"plugin.smoke.failed"}}
	run.Spec.Agent.Config = apiextensionsv1.JSON{Raw: []byte(`{"plugins":[{"name":"event-webhook","source":"builtin","when":"after-agent","restart":"always","config":{"url":"http://nvt-operator:8082/v1/agentruns/default/example/events","auth":{"type":"bearer-env","env":"NVT_OPERATOR_CALLBACK_TOKEN"}}},{"name":"smoke-complete","source":"builtin","when":"after-agent","config":{}}]}`)}
	rendered, err := RenderAgentConfigYAML(run)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rendered, "NVT_OPERATOR_CALLBACK_TOKEN") || strings.Contains(rendered, "/v1/agentruns/") {
		t.Fatalf("rendered zero-secret config retained callback bearer wiring:\n%s", rendered)
	}
	if !strings.Contains(rendered, "name: lifecycle-termination") || !strings.Contains(rendered, "waitForPlugin: lifecycle-termination") {
		t.Fatalf("rendered config did not install termination lifecycle path:\n%s", rendered)
	}

	now := metav1.NewTime(time.Unix(123, 0))
	pod := &corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
		Name: "agent", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Message: `{"nvtLifecycleEvent":"plugin.smoke.completed","outcome":"completed"}`}},
	}}}}
	if !SyncAgentRunLifecycleFromPodTermination(run, pod, now) {
		t.Fatal("operator did not consume lifecycle termination message")
	}
	if run.Status.Phase != nvtv1alpha1.AgentRunPhaseCompleted || run.Status.Reason != "Completed by lifecycle event plugin.smoke.completed" {
		t.Fatalf("unexpected lifecycle status: %#v", run.Status)
	}
}

func TestDirectAndNonEnforcedMediatedKeepLegacyBearerCompatibility(t *testing.T) {
	for _, run := range []*nvtv1alpha1.AgentRun{testAgentRun(), multiGrantMediatedAgentRun()} {
		pod, err := DesiredAgentPod(run, testScheme(t))
		if err != nil {
			t.Fatal(err)
		}
		agent := requireContainer(t, *pod, "agent")
		assertSecretKeyEnv(t, agent, brokerTokenKey, BrokerTokenSecretName(run.Name), brokerTokenKey)
		assertSecretKeyEnv(t, agent, callbackTokenKey, CallbackTokenSecretName(run.Name), callbackTokenKey)
		if pod.Spec.AutomountServiceAccountToken != nil {
			t.Fatalf("compatibility mode changed service-account automount default: %#v", pod.Spec.AutomountServiceAccountToken)
		}
	}
}

func TestTransparentAdmissionRequiresDeploymentCapability(t *testing.T) {
	t.Setenv("NVT_NETWORK_POLICY_CAPABLE", "false")
	run := forwardProxyAgentRun()
	run.Spec.EgressTransport = nvtv1alpha1.AgentRunEgressTransportTransparent
	if err := ValidateAgentRunEgressMode(run); err == nil || !strings.Contains(err.Error(), "NetworkPolicy-capable") {
		t.Fatalf("transparent admission should fail before Pod creation: %v", err)
	}
}

func TestAdmissionRejectsInvalidDeploymentEgressPolicy(t *testing.T) {
	run := transparentAgentRun(t)
	t.Run("cidr", func(t *testing.T) {
		t.Setenv("NVT_EGRESS_DENY_CIDRS", "not-a-cidr")
		if err := ValidateAgentRunEgressMode(run); err == nil || !strings.Contains(err.Error(), "invalid egress deny CIDR") {
			t.Fatalf("invalid deployment CIDR was not rejected: %v", err)
		}
	})
	t.Run("port", func(t *testing.T) {
		t.Setenv("NVT_EGRESS_ALLOWED_TCP_PORTS", "80,70000")
		if err := ValidateAgentRunEgressMode(run); err == nil || !strings.Contains(err.Error(), "invalid external TCP port") {
			t.Fatalf("invalid external port was not rejected: %v", err)
		}
	})
}

func TestConfiguredExternalPortsStayAligned(t *testing.T) {
	t.Setenv("NVT_EGRESS_ALLOWED_TCP_PORTS", "8443,80,8443")
	run := transparentAgentRun(t)
	rendered, err := RenderEgressdConfigJSON(run)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		ForwardProxy struct {
			TransparentMode bool  `json:"transparent_mode"`
			AllowPorts      []int `json:"allow_ports"`
		} `json:"forward_proxy"`
	}
	if err := json.Unmarshal([]byte(rendered), &config); err != nil {
		t.Fatal(err)
	}
	policy, err := DesiredEgressdNetworkPolicy(run, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []int{80, 8443}
	if !reflect.DeepEqual(config.ForwardProxy.AllowPorts, want) {
		t.Fatalf("egressd ports = %v, want %v", config.ForwardProxy.AllowPorts, want)
	}
	if !config.ForwardProxy.TransparentMode {
		t.Fatal("transparent run did not render transparent_mode")
	}
	publicRule := policy.Spec.Egress[len(policy.Spec.Egress)-2]
	got := []int{publicRule.Ports[0].Port.IntValue(), publicRule.Ports[1].Port.IntValue()}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NetworkPolicy ports = %v, want %v", got, want)
	}
}

func TestEgressdPolicyAllowsOnlyExplicitlyLabelledExternalFixture(t *testing.T) {
	run := transparentAgentRun(t)
	run.Spec.Broker.Grants[0].AllowInsecureUpstream = true
	run.Spec.Broker.Grants[0].EgressHosts = []string{"echo.nvt-fixture.test:443"}
	policy, err := DesiredEgressdNetworkPolicy(run, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	want := egressHostLabel("echo.nvt-fixture.test")
	for _, rule := range policy.Spec.Egress {
		for _, peer := range rule.To {
			if peer.PodSelector != nil && peer.PodSelector.MatchLabels["nvt.dev/egress-host"] == want {
				return
			}
		}
	}
	t.Fatalf("egressd policy has no fixture selector nvt.dev/egress-host=%s", want)
}

// TestValidateForwardProxyAdmission pins the gates: forward-proxy requires
// enforcement, admits a placeholder-file-only run (routable via the proxy),
// and rejects forward-proxy without enforcement.
func TestValidateForwardProxyAdmission(t *testing.T) {
	if err := ValidateAgentRunEgressMode(forwardProxyAgentRun()); err != nil {
		t.Fatalf("forward-proxy placeholder-file run must be admitted, got %v", err)
	}

	noEnforce := forwardProxyAgentRun()
	noEnforce.Spec.EgressEnforcement = false
	if err := ValidateAgentRunEgressMode(noEnforce); err == nil || !strings.Contains(err.Error(), "egressTransport forward-proxy requires spec.egress mediated and spec.egressEnforcement") {
		t.Fatalf("forward-proxy without enforcement must be rejected, got %v", err)
	}

	noHosts := forwardProxyAgentRun()
	noHosts.Spec.Broker.Grants[0].EgressHosts = nil
	if err := ValidateAgentRunEgressMode(noHosts); err == nil || !strings.Contains(err.Error(), "egressHosts") {
		t.Fatalf("forward-proxy with no injectable egressHosts must be rejected, got %v", err)
	}
}

// TestRenderForwardProxyEgressdConfig pins the egressd config: a forward_proxy
// block with an inject route per egressHost, no redirect routes, and the CA.
func TestRenderForwardProxyEgressdConfig(t *testing.T) {
	rendered, err := RenderEgressdConfigJSON(forwardProxyAgentRun())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var config struct {
		Routes       []map[string]any `json:"routes"`
		ForwardProxy *struct {
			Listen              string           `json:"listen"`
			TransparentMode     bool             `json:"transparent_mode"`
			AllowUnmatchedHosts bool             `json:"allow_unmatched_hosts"`
			AllowPorts          []int            `json:"allow_ports"`
			DenyCIDRs           []string         `json:"deny_cidrs"`
			InjectRoutes        []map[string]any `json:"inject_routes"`
		} `json:"forward_proxy"`
		CA *struct {
			CertFile string `json:"cert_file"`
		} `json:"ca"`
	}
	if err := json.Unmarshal([]byte(rendered), &config); err != nil {
		t.Fatalf("unmarshal rendered config: %v\n%s", err, rendered)
	}
	if len(config.Routes) != 0 {
		t.Fatalf("forward-proxy mode must render no redirect routes, got %v", config.Routes)
	}
	if config.ForwardProxy == nil || len(config.ForwardProxy.InjectRoutes) != 2 {
		t.Fatalf("expected two inject routes, got %#v", config.ForwardProxy)
	}
	if !config.ForwardProxy.AllowUnmatchedHosts {
		t.Fatalf("forward-proxy mode must blind-tunnel unmatched hosts: %#v", config.ForwardProxy)
	}
	if config.ForwardProxy.TransparentMode {
		t.Fatal("existing forward-proxy mode must not be reclassified as transparent")
	}
	if len(config.ForwardProxy.AllowPorts) != 2 || config.ForwardProxy.AllowPorts[0] != 80 || config.ForwardProxy.AllowPorts[1] != 443 {
		t.Fatalf("forward proxy ports = %v", config.ForwardProxy.AllowPorts)
	}
	if len(config.ForwardProxy.DenyCIDRs) == 0 {
		t.Fatal("forward proxy config must receive the same normalized deny ranges as NetworkPolicy")
	}
	hosts := map[string]any{}
	for _, route := range config.ForwardProxy.InjectRoutes {
		hosts[route["host"].(string)] = route["capability"]
		if route["capability"] != "codex-main" {
			t.Fatalf("inject route capability = %v", route["capability"])
		}
	}
	if _, ok := hosts["auth.openai.com"]; !ok {
		t.Fatalf("inject routes must include the refresh host auth.openai.com, got %v", hosts)
	}
	if config.CA == nil || config.CA.CertFile == "" {
		t.Fatal("forward-proxy egressd config must load the durable CA")
	}
}

// TestForwardProxyAgentPodEnv pins the agent proxy env: HTTP(S)_PROXY points at
// egressd and NO_PROXY covers broker/callback/DNS/localhost.
func TestForwardProxyAgentPodEnv(t *testing.T) {
	pod, err := DesiredAgentPod(forwardProxyAgentRun(), testScheme(t))
	if err != nil {
		t.Fatalf("desired pod: %v", err)
	}
	agent := requireContainer(t, *pod, "agent")
	proxy := envValue(agent, "HTTPS_PROXY")
	if !strings.Contains(proxy, EgressdServiceName(forwardProxyAgentRun().Name)) || !strings.Contains(proxy, "8473") {
		t.Fatalf("HTTPS_PROXY = %q, want the egressd forward-proxy Service", proxy)
	}
	config := InjectMediatedEgressConfig(map[string]any{}, forwardProxyAgentRun())
	egress, _ := config["egress"].(map[string]any)
	proxyURL, _ := egress["forward-proxy-url"].(string)
	if proxyURL != proxy {
		t.Fatalf("forward-proxy-url = %q, want %q", proxyURL, proxy)
	}
	noProxy := envValue(agent, "NO_PROXY")
	for _, want := range []string{"localhost", ".svc.cluster.local", "nvt-operator"} {
		if !strings.Contains(noProxy, want) {
			t.Fatalf("NO_PROXY = %q, missing %q", noProxy, want)
		}
	}
}

func TestForwardProxyHeaderInjectGrantIsRenderedForRuntimeProxyValidation(t *testing.T) {
	agentRun := forwardProxyAgentRun()
	agentRun.Spec.Broker.Grants = []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "static-bearer-main", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject,
		EgressHosts: []string{"api.example.test:443"},
	}}
	config := InjectMediatedEgressConfig(map[string]any{}, agentRun)
	egress, _ := config["egress"].(map[string]any)
	grants, _ := egress["grants"].([]any)
	if len(grants) != 1 {
		t.Fatalf("expected one rendered egress grant, got %#v", grants)
	}
	grant, _ := grants[0].(map[string]any)
	if grant["provider"] != "static-bearer-main" || grant["materialization"] != string(nvtv1alpha1.AgentRunGrantHeaderInject) {
		t.Fatalf("unexpected rendered grant: %#v", grant)
	}
	if _, ok := grant["base-url"]; ok {
		t.Fatalf("forward-proxy header-inject grant must not render redirect base-url: %#v", grant)
	}
}

func TestRenderForwardProxyGitAndSharedHostsRequireCapabilityHint(t *testing.T) {
	agentRun := forwardProxyAgentRun()
	agentRun.Spec.Broker.Grants = []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "azdo-infra-pat", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject, Git: true,
		EgressHosts: []string{"dev.azure.com:443"},
	}, {
		Provider: "github-main-app", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject, Git: true,
		EgressHosts: []string{"github.com:443"},
	}, {
		Provider: "github-altinn-app", Materialization: nvtv1alpha1.AgentRunGrantHeaderInject, Git: true,
		EgressHosts: []string{"github.com:443"},
	}}
	rendered, err := RenderEgressdConfigJSON(agentRun)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var config struct {
		ForwardProxy *struct {
			InjectRoutes []map[string]any `json:"inject_routes"`
		} `json:"forward_proxy"`
	}
	if err := json.Unmarshal([]byte(rendered), &config); err != nil {
		t.Fatalf("unmarshal rendered config: %v\n%s", err, rendered)
	}
	if config.ForwardProxy == nil || len(config.ForwardProxy.InjectRoutes) != 3 {
		t.Fatalf("expected git inject routes, got %#v", config.ForwardProxy)
	}
	for _, route := range config.ForwardProxy.InjectRoutes {
		switch route["host"] {
		case "dev.azure.com":
			if route["require_capability_hint"] != true {
				t.Fatalf("git host must require an explicit capability hint: %#v", route)
			}
		case "github.com":
			if route["require_capability_hint"] != true {
				t.Fatalf("shared host must require explicit capability hint: %#v", route)
			}
		default:
			t.Fatalf("unexpected route: %#v", route)
		}
	}
}

// TestValidateForwardProxyMirrorsEgressdRules pins that the operator rejects
// forward-proxy configs that egressd's config.Validate would reject at boot
// (duplicate host+capability, IP-literal hosts), so a bad spec fails loudly at
// admission instead of CrashLooping egressd.
func TestValidateForwardProxyMirrorsEgressdRules(t *testing.T) {
	// Duplicate normalized host for the same grant/capability.
	dupWithinGrant := forwardProxyAgentRun()
	dupWithinGrant.Spec.Broker.Grants[0].EgressHosts = []string{"chatgpt.com:443", "chatgpt.com:8443"}
	if err := ValidateAgentRunEgressMode(dupWithinGrant); err == nil || !strings.Contains(err.Error(), "chatgpt.com") {
		t.Fatalf("duplicate inject host for one capability must be rejected, got %v", err)
	}

	// Same host claimed by two different grants is valid: egressd requires an
	// explicit non-secret capability hint on CONNECT and fails closed without
	// one.
	dupAcrossGrants := forwardProxyAgentRun()
	dupAcrossGrants.Spec.Broker.Grants = append(dupAcrossGrants.Spec.Broker.Grants, nvtv1alpha1.AgentRunBrokerGrant{
		Provider: "other-provider", Materialization: nvtv1alpha1.AgentRunGrantPlaceholderFile,
		EgressHosts: []string{"chatgpt.com:443"},
	})
	if err := ValidateAgentRunEgressMode(dupAcrossGrants); err != nil {
		t.Fatalf("host claimed by two grants should be admitted for explicit selection, got %v", err)
	}

	// IP-literal egressHost is rejected for forward-proxy (MITM needs a name).
	ipHost := forwardProxyAgentRun()
	ipHost.Spec.Broker.Grants[0].EgressHosts = []string{"10.0.0.5:443"}
	if err := ValidateAgentRunEgressMode(ipHost); err == nil || !strings.Contains(err.Error(), "DNS name") {
		t.Fatalf("IP-literal forward-proxy host must be rejected, got %v", err)
	}
}
