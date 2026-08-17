package controller

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

func DesiredAgentPod(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme) (*corev1.Pod, error) {
	return buildDesiredAgentPod(agentRun, scheme, false)
}

func buildDesiredAgentPod(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme, projectionOnly bool) (*corev1.Pod, error) {
	if !projectionOnly {
		if err := ValidateBrokerTLSConfig(); err != nil {
			return nil, err
		}
	}
	if err := ValidateAgentRunWorkspace(agentRun); err != nil {
		return nil, err
	}
	if err := ValidateAgentRunWorkspaceInstructions(agentRun); err != nil {
		return nil, err
	}
	if err := ValidateAgentRunRuntimeCapabilities(agentRun); err != nil {
		return nil, err
	}
	if err := ValidateBrandingConfig(); err != nil {
		return nil, err
	}
	requiredDockerNetworks, err := requiredDockerNetworksJSON(agentRun)
	if err != nil {
		return nil, err
	}
	runtimeAuthMountPath, err := RuntimeAuthMountPath(agentRun)
	if err != nil {
		return nil, err
	}
	dindPullPolicy, err := DindImagePullPolicy()
	if err != nil {
		return nil, err
	}

	agentVolumeMounts := []corev1.VolumeMount{
		{Name: workspaceVolumeName, MountPath: workspaceMountPath},
		{Name: "agent-config", MountPath: agentConfigVolumeDir, ReadOnly: true},
	}
	workspaceVolumeSource := corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}
	if AgentRunWorkspaceMode(agentRun) == nvtv1alpha1.AgentRunWorkspacePersistent {
		workspaceVolumeSource = corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
			ClaimName: WorkspacePVCName(agentRun.Name),
		}}
		agentVolumeMounts[0].SubPath = persistentWorkspaceSubPath
		agentVolumeMounts = append(agentVolumeMounts, corev1.VolumeMount{
			Name: workspaceVolumeName, MountPath: agentHomePath(agentRun), SubPath: persistentHomeSubPath,
		})
	}
	volumes := []corev1.Volume{
		{
			Name:         workspaceVolumeName,
			VolumeSource: workspaceVolumeSource,
		},
		{
			Name: "agent-config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: AgentConfigMapName(agentRun.Name)},
					Items: []corev1.KeyToPath{
						{Key: agentConfigKey, Path: agentConfigKey},
					},
				},
			},
		},
	}
	if brandingConfigMap := BrandingConfigMapName(); brandingConfigMap != "" {
		volumes = append(volumes, corev1.Volume{
			Name: brandingVolumeName,
			VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: brandingConfigMap},
				Items: []corev1.KeyToPath{
					{Key: "nvt-agent-mark.svg", Path: "nvt-agent-mark.svg"},
					{Key: "favicon.ico", Path: "favicon.ico"},
					{Key: "nvt-agent-mark-64.png", Path: "nvt-agent-mark-64.png"},
					{Key: "nvt-agent-mark-192.png", Path: "nvt-agent-mark-192.png"},
					{Key: "nvt-agent-mark-512.png", Path: "nvt-agent-mark-512.png"},
				},
			}},
		})
		agentVolumeMounts = append(agentVolumeMounts, corev1.VolumeMount{
			Name: brandingVolumeName, MountPath: brandingMountPath, ReadOnly: true,
		})
	}
	dindStorageLimit := dockerPVCSize(agentRun)
	dindStorageVolumeSource := corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &dindStorageLimit}}
	if AgentRunWorkspaceMode(agentRun) == nvtv1alpha1.AgentRunWorkspacePersistent {
		dindStorageVolumeSource = corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
			ClaimName: DockerPVCName(agentRun.Name),
		}}
	}
	volumes = append(volumes, corev1.Volume{Name: dindStorageVolumeName, VolumeSource: dindStorageVolumeSource})
	if agentRunHasProviderPreparations(agentRun) {
		volumes[1].ConfigMap.Items = append(volumes[1].ConfigMap.Items, corev1.KeyToPath{
			Key: preparedProviderMetadataKey, Path: preparedProviderMetadataKey,
		})
	}
	if agentRun.Spec.Agent.WorkspaceInstructions != "" {
		volumes[1].ConfigMap.Items = append(volumes[1].ConfigMap.Items, corev1.KeyToPath{
			Key: profileWorkspaceInstructionsKey, Path: profileWorkspaceInstructionsKey,
		})
	}
	if agentRun.Spec.Agent.WorkflowInstructions != "" {
		volumes[1].ConfigMap.Items = append(volumes[1].ConfigMap.Items, corev1.KeyToPath{
			Key: workflowWorkspaceInstructionsKey, Path: workflowWorkspaceInstructionsKey,
		})
	}
	hasGitGrant := agentRunHasGitGrant(agentRun)
	if !projectionOnly && brokerCADistributed() && !AgentRunLiteralZeroSecret(agentRun) {
		volumes = append(volumes, corev1.Volume{
			Name: brokerCAVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: BrokerCASecretName(),
					Items: []corev1.KeyToPath{
						{Key: brokerCAKey, Path: brokerCAKey},
					},
				},
			},
		})
		agentVolumeMounts = append(agentVolumeMounts, corev1.VolumeMount{
			Name:      brokerCAVolumeName,
			MountPath: agentBrokerCAMount,
			ReadOnly:  true,
		})
	}
	enforced := AgentRunEgressEnforced(agentRun)
	if enforced {
		volumes = append(volumes, corev1.Volume{
			Name: egressCAVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: EgressCAConfigMapName(agentRun.Name)},
					Items: []corev1.KeyToPath{
						{Key: egressCACertKey, Path: egressCACertKey},
					},
				},
			},
		})
		agentVolumeMounts = append(agentVolumeMounts, corev1.VolumeMount{
			Name:      egressCAVolumeName,
			MountPath: egressCAMountPath,
			ReadOnly:  true,
		})
	} else if AgentRunEgressMode(agentRun) == nvtv1alpha1.AgentRunEgressMediated {
		volumes = append(volumes, corev1.Volume{
			Name: egressdConfigName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: EgressdConfigMapName(agentRun.Name)},
					Items: []corev1.KeyToPath{
						{Key: egressdConfigKey, Path: egressdConfigKey},
					},
				},
			},
		})
		if hasGitGrant {
			volumes = append(volumes, corev1.Volume{
				Name: egressCAVolumeName,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			})
			agentVolumeMounts = append(agentVolumeMounts, corev1.VolumeMount{
				Name:      egressCAVolumeName,
				MountPath: egressCAMountPath,
				ReadOnly:  true,
			})
		}
	}
	if agentRun.Spec.RuntimeAuth != nil {
		agentVolumeMounts = append(agentVolumeMounts, corev1.VolumeMount{
			Name:      runtimeAuthHomeName,
			MountPath: runtimeAuthMountPath,
		})
		volumes = append(volumes, corev1.Volume{
			Name: runtimeAuthSourceName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: agentRun.Spec.RuntimeAuth.SecretName,
				},
			},
		}, corev1.Volume{
			Name: runtimeAuthHomeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		})
	}

	initContainers := []corev1.Container{}
	if AgentRunWorkspaceMode(agentRun) == nvtv1alpha1.AgentRunWorkspacePersistent {
		owner := "0:0"
		if AgentRunNonRoot(agentRun) {
			owner = "1000:1000"
		}
		initContainers = append(initContainers, corev1.Container{
			Name:    "persistent-storage-init",
			Image:   "docker:27-dind",
			Command: []string{"sh", "-c"},
			Args: []string{fmt.Sprintf(
				"set -eu; mkdir -p %[1]s/%[2]s %[1]s/%[3]s; chown %[4]s %[1]s/%[2]s %[1]s/%[3]s; chmod 0770 %[1]s/%[2]s; chmod 0700 %[1]s/%[3]s",
				persistentStorageInitMountPath, persistentWorkspaceSubPath, persistentHomeSubPath, owner,
			)},
			SecurityContext: &corev1.SecurityContext{
				RunAsUser:  ptrTo(int64(0)),
				RunAsGroup: ptrTo(int64(0)),
			},
			VolumeMounts: []corev1.VolumeMount{{
				Name: workspaceVolumeName, MountPath: persistentStorageInitMountPath,
			}},
		})
	}
	if agentRun.Spec.RuntimeAuth != nil {
		initContainers = append(initContainers, corev1.Container{
			Name:    "runtime-auth-copy",
			Image:   "docker:27-dind",
			Command: []string{"sh", "-c"},
			Args: []string{
				"cp -a " + runtimeAuthSourcePath + "/. " + runtimeAuthHomePath + "/ && chmod -R " + runtimeAuthChmod(agentRun) + " " + runtimeAuthHomePath,
			},
			VolumeMounts: []corev1.VolumeMount{
				{Name: runtimeAuthSourceName, MountPath: runtimeAuthSourcePath, ReadOnly: true},
				{Name: runtimeAuthHomeName, MountPath: runtimeAuthHomePath},
			},
		})
	}
	if AgentRunEgressTransparent(agentRun) {
		initContainers = append(initContainers, corev1.Container{
			Name:            "captured",
			Image:           CapturedImage(),
			ImagePullPolicy: corev1.PullIfNotPresent,
			RestartPolicy:   ptrTo(corev1.ContainerRestartPolicyAlways),
			Env: []corev1.EnvVar{
				{Name: "NVT_CAPTURED_EXPLICIT_LISTEN", Value: fmt.Sprintf("[::]:%d", capturedExplicitPort)},
				{Name: "NVT_CAPTURED_TRANSPARENT_LISTEN", Value: fmt.Sprintf("[::]:%d", capturedTransparentPort)},
				{Name: "NVT_EGRESS_PROXY", Value: fmt.Sprintf("%s:%d", EgressdServiceName(agentRun.Name), egressForwardProxyPort)},
			},
			SecurityContext: &corev1.SecurityContext{
				RunAsNonRoot:             ptrTo(true),
				RunAsUser:                ptrTo(capturedUID),
				RunAsGroup:               ptrTo(capturedUID),
				AllowPrivilegeEscalation: ptrTo(false),
				ReadOnlyRootFilesystem:   ptrTo(true),
				Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
		})
	}
	dindVolumeMounts := []corev1.VolumeMount{
		{Name: workspaceVolumeName, MountPath: workspaceMountPath, SubPath: workspaceSubPath(agentRun)},
		{Name: dindStorageVolumeName, MountPath: dindStorageMountPath},
	}
	dindEnv := []corev1.EnvVar{
		{Name: "DOCKER_TLS_CERTDIR", Value: ""},
		{Name: "NVT_DIND_BACKING_DIR", Value: dindStorageMountPath},
		{Name: "NVT_DIND_DATA_ROOT", Value: dindDataRoot},
		{Name: "NVT_DIND_IMAGE_SIZE_BYTES", Value: strconv.FormatInt(dindImageSizeBytes(agentRun), 10)},
		{Name: "NVT_DIND_PERSISTENT_STORAGE", Value: strconv.FormatBool(AgentRunWorkspaceMode(agentRun) == nvtv1alpha1.AgentRunWorkspacePersistent)},
		{Name: "NVT_DIND_TRANSPARENT", Value: strconv.FormatBool(AgentRunEgressTransparent(agentRun))},
	}
	if AgentRunDockerKernelLogDevice(agentRun) {
		dindEnv = append(dindEnv, corev1.EnvVar{Name: "NVT_DIND_KERNEL_LOG_DEVICE", Value: "true"})
	}
	initContainers = append(initContainers, corev1.Container{
		Name:            "docker",
		Image:           DindImage(),
		ImagePullPolicy: dindPullPolicy,
		RestartPolicy:   ptrTo(corev1.ContainerRestartPolicyAlways),
		Command:         []string{dindEntrypoint},
		Args: []string{
			"--host=unix:///var/run/docker.sock",
			"--host=tcp://127.0.0.1:2375",
			"--tls=false",
		},
		Env: dindEnv,
		SecurityContext: &corev1.SecurityContext{
			Privileged: ptrTo(true),
		},
		StartupProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{Command: []string{dindReady}},
			},
			PeriodSeconds:    5,
			TimeoutSeconds:   2,
			FailureThreshold: dindStartupBudgetSeconds / 5,
		},
		VolumeMounts: dindVolumeMounts,
	})
	if AgentRunEgressTransparent(agentRun) {
		const dockerNetworkCIDR = "172.30.0.0/15"
		const rules = `set -eu
exclude_v4=""
exclude_v6=""
reject_managed_overlap() {
  case "$1" in 172.30.*|172.31.*) echo "managed Docker pool overlaps protected address $1" >&2; exit 1 ;; esac
}
/usr/local/bin/nvt-validate-managed-cidrs "$NVT_DIND_NETWORK_CIDR"
for ip in $(hostname -i); do reject_managed_overlap "$ip"; done
for host in $NVT_CAPTURE_EXCLUDE_HOSTS; do
  for ip in $(getent ahosts "$host" | awk '{print $1}' | sort -u); do
    reject_managed_overlap "$ip"
    case "$ip" in *:*) exclude_v6="$exclude_v6 $ip" ;; *) exclude_v4="$exclude_v4 $ip" ;; esac
  done
done
/usr/local/bin/nvt-disable-bridge-netfilter
iptables -t nat -N NVT_CAPTURE 2>/dev/null || iptables -t nat -F NVT_CAPTURE
iptables -t nat -A NVT_CAPTURE -d 127.0.0.0/8 -j RETURN
for ip in $exclude_v4; do iptables -t nat -A NVT_CAPTURE -d "$ip/32" -j RETURN; done
iptables -t nat -A NVT_CAPTURE -m owner --uid-owner 65532 -j RETURN
# Pod-side connections to locally published DinD services leave through a
# Docker bridge after docker-proxy/DNAT. Interface-prefix matching covers
# Compose bridges created after this init container has exited. Container-
# originated traffic enters PREROUTING instead and remains captured below.
iptables -t nat -A NVT_CAPTURE -o docker0 -j RETURN
iptables -t nat -A NVT_CAPTURE -o br-+ -j RETURN
iptables -t nat -A NVT_CAPTURE -p tcp -j REDIRECT --to-ports 15001
iptables -t nat -C OUTPUT -j NVT_CAPTURE 2>/dev/null || iptables -t nat -I OUTPUT 1 -j NVT_CAPTURE
iptables -t nat -N NVT_DIND 2>/dev/null || iptables -t nat -F NVT_DIND
for ip in $exclude_v4; do iptables -t nat -A NVT_DIND -d "$ip/32" -j RETURN; done
	iptables -t nat -A NVT_DIND -d "$NVT_DIND_NETWORK_CIDR" -j RETURN
iptables -t nat -A NVT_DIND -i docker0 -p tcp -j REDIRECT --to-ports 15001
iptables -t nat -A NVT_DIND -i br-+ -p tcp -j REDIRECT --to-ports 15001
iptables -t nat -C PREROUTING -j NVT_DIND 2>/dev/null || iptables -t nat -I PREROUTING 1 -j NVT_DIND
ip6tables -t nat -N NVT_CAPTURE 2>/dev/null || ip6tables -t nat -F NVT_CAPTURE
ip6tables -t nat -A NVT_CAPTURE -d ::1/128 -j RETURN
for ip in $exclude_v6; do ip6tables -t nat -A NVT_CAPTURE -d "$ip/128" -j RETURN; done
ip6tables -t nat -A NVT_CAPTURE -m owner --uid-owner 65532 -j RETURN
ip6tables -t nat -A NVT_CAPTURE -o docker0 -j RETURN
ip6tables -t nat -A NVT_CAPTURE -o br-+ -j RETURN
ip6tables -t nat -A NVT_CAPTURE -p tcp -j REDIRECT --to-ports 15001
ip6tables -t nat -C OUTPUT -j NVT_CAPTURE 2>/dev/null || ip6tables -t nat -I OUTPUT 1 -j NVT_CAPTURE
ip6tables -t nat -N NVT_DIND 2>/dev/null || ip6tables -t nat -F NVT_DIND
for ip in $exclude_v6; do ip6tables -t nat -A NVT_DIND -d "$ip/128" -j RETURN; done
	# Docker's managed pool is IPv4; IPv6 remains captured by the redirect.
ip6tables -t nat -A NVT_DIND -i docker0 -p tcp -j REDIRECT --to-ports 15001
ip6tables -t nat -A NVT_DIND -i br-+ -p tcp -j REDIRECT --to-ports 15001
ip6tables -t nat -C PREROUTING -j NVT_DIND 2>/dev/null || ip6tables -t nat -I PREROUTING 1 -j NVT_DIND`
		initContainers = append(initContainers, corev1.Container{
			Name:            "net-init",
			Image:           DindImage(),
			ImagePullPolicy: dindPullPolicy,
			Command:         []string{"sh", "-c"},
			Args:            []string{rules},
			Env: []corev1.EnvVar{{
				Name: "NVT_CAPTURE_EXCLUDE_HOSTS",
				Value: strings.Join([]string{
					EgressdServiceName(agentRun.Name),
					"kubernetes.default.svc", "kube-dns.kube-system.svc",
				}, " "),
			}, {Name: "NVT_DIND_NETWORK_CIDR", Value: dockerNetworkCIDR}, {
				Name: "NVT_DIND_PROTECTED_CIDRS", Value: strings.Join(append([]string{"127.0.0.0/8", "169.254.0.0/16"}, strings.Fields(strings.ReplaceAll(os.Getenv("NVT_DIND_PROTECTED_CIDRS"), ",", " "))...), " "),
			}},
			SecurityContext: &corev1.SecurityContext{
				RunAsUser:                ptrTo(int64(0)),
				AllowPrivilegeEscalation: ptrTo(false),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
					Add:  []corev1.Capability{"NET_ADMIN"},
				},
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
		})
	}

	agentEnv := []corev1.EnvVar{
		{Name: "DOCKER_HOST", Value: "tcp://127.0.0.1:2375"},
		{Name: "NVT_WORKSPACE", Value: workspaceMountPath},
		{Name: "NVT_AGENT_CONFIG_FILE", Value: agentConfigMountPath},
	}
	if requiredDockerNetworks != "" {
		agentEnv = append(agentEnv, corev1.EnvVar{Name: "NVT_DOCKER_REQUIRED_NETWORKS", Value: requiredDockerNetworks})
	}
	if agentRunHasProviderPreparations(agentRun) {
		agentEnv = append(agentEnv, corev1.EnvVar{Name: preparedProviderMetadataEnv, Value: preparedProviderMetadataPath})
	}
	if agentRun.Spec.Agent.WorkspaceInstructions != "" {
		agentEnv = append(agentEnv, corev1.EnvVar{
			Name: profileWorkspaceInstructionsEnv, Value: profileWorkspaceInstructionsPath,
		})
	}
	if agentRun.Spec.Agent.WorkflowInstructions != "" {
		agentEnv = append(agentEnv, corev1.EnvVar{
			Name: workflowWorkspaceInstructionsEnv, Value: workflowWorkspaceInstructionsPath,
		})
	}
	if !AgentRunLiteralZeroSecret(agentRun) {
		agentEnv = append(agentEnv,
			corev1.EnvVar{Name: "NVT_BROKER_URL", Value: BrokerURL()},
			corev1.EnvVar{
				Name: brokerTokenKey,
				ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: BrokerTokenSecretName(agentRun.Name)}, Key: brokerTokenKey,
				}},
			},
			corev1.EnvVar{
				Name: callbackTokenKey,
				ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: CallbackTokenSecretName(agentRun.Name)}, Key: callbackTokenKey,
				}},
			},
		)
	}
	containers := []corev1.Container{
		{
			Name:            "agent",
			Image:           agentRun.Spec.Image,
			ImagePullPolicy: corev1.PullIfNotPresent,
			Resources:       *agentRun.Spec.Resources.DeepCopy(),
			WorkingDir:      workspaceMountPath,
			Env:             agentEnv,
			VolumeMounts:    agentVolumeMounts,
			ReadinessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{
					Command: []string{"/usr/local/bin/health"},
				}},
				InitialDelaySeconds: 5,
				PeriodSeconds:       5,
				TimeoutSeconds:      2,
				FailureThreshold:    12,
			},
		},
	}
	if AgentRunEgressMode(agentRun) == nvtv1alpha1.AgentRunEgressMediated {
		containers[0].Env = append(containers[0].Env, corev1.EnvVar{Name: "NVT_EGRESS_MODE", Value: string(nvtv1alpha1.AgentRunEgressMediated)})
		if enforced || hasGitGrant {
			containers[0].Env = append(containers[0].Env, corev1.EnvVar{Name: "NVT_EGRESS_CA_FILE", Value: egressCAFilePath})
		}
		if AgentRunEgressForwardProxy(agentRun) {
			containers[0].Env = append(containers[0].Env, forwardProxyEnv(agentRun)...)
		}
	}
	if !projectionOnly && brokerCADistributed() && !AgentRunLiteralZeroSecret(agentRun) {
		containers[0].Env = append(containers[0].Env, corev1.EnvVar{Name: "NVT_BROKER_CA_FILE", Value: agentBrokerCAFile})
	}
	if AgentRunNonRoot(agentRun) {
		containers[0].SecurityContext = &corev1.SecurityContext{
			RunAsUser:  ptrTo(agentNonRootUID),
			RunAsGroup: ptrTo(agentNonRootGID),
		}
		containers[0].Env = append(containers[0].Env,
			corev1.EnvVar{Name: "HOME", Value: agentNonRootHome},
			corev1.EnvVar{Name: "NVT_STATE_DIR", Value: agentNonRootHome + "/.nvt-agent"},
		)
	}
	if capabilities := agentRuntimeCapabilities(agentRun); len(capabilities) != 0 {
		if containers[0].SecurityContext == nil {
			containers[0].SecurityContext = &corev1.SecurityContext{}
		}
		containers[0].SecurityContext.Capabilities = &corev1.Capabilities{Add: capabilities}
	}
	if AgentRunEgressMode(agentRun) == nvtv1alpha1.AgentRunEgressMediated && !enforced {
		egressdVolumeMounts := []corev1.VolumeMount{
			{Name: egressdConfigName, MountPath: egressdConfigPath, SubPath: egressdConfigKey, ReadOnly: true},
		}
		if !projectionOnly && brokerCADistributed() {
			egressdVolumeMounts = append(egressdVolumeMounts, corev1.VolumeMount{
				Name:      brokerCAVolumeName,
				MountPath: egressdBrokerCAMount,
				ReadOnly:  true,
			})
		}
		if hasGitGrant {
			egressdVolumeMounts = append(egressdVolumeMounts, corev1.VolumeMount{
				Name:      egressCAVolumeName,
				MountPath: egressCAMountPath,
			})
		}
		containers = append(containers, corev1.Container{
			Name:            "egressd",
			Image:           EgressdImage(),
			ImagePullPolicy: corev1.PullIfNotPresent,
			Env: []corev1.EnvVar{
				{Name: "NVT_EGRESSD_CONFIG", Value: egressdConfigPath},
				{
					Name: "NVT_BROKER_TOKEN",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: EgressTokenSecretName(agentRun.Name)},
							Key:                  egressTokenKey,
						},
					},
				},
			},
			VolumeMounts: egressdVolumeMounts,
		})
	}

	podLabels := agentRunLabels(agentRun.Name)
	if enforced {
		podLabels = enforcementLabels(agentRun.Name, roleLabelAgent)
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      AgentPodName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    podLabels,
		},
		Spec: corev1.PodSpec{
			RuntimeClassName: agentRun.Spec.RuntimeClassName,
			Tolerations:      copyTolerations(agentRun.Spec.Tolerations),
			RestartPolicy:    corev1.RestartPolicyNever,
			InitContainers:   initContainers,
			Containers:       containers,
			Volumes:          volumes,
		},
	}
	if AgentRunLiteralZeroSecret(agentRun) {
		pod.Spec.AutomountServiceAccountToken = ptrTo(false)
	}
	if AgentRunNonRoot(agentRun) {
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{FSGroup: ptrTo(agentNonRootGID)}
	}
	desiredState, err := podCredentialProjectionSignature(agentRun, pod)
	if err != nil {
		return nil, err
	}
	pod.Annotations = map[string]string{
		agentPodSecurityStateAnnotation: desiredState,
	}
	if err := controllerutil.SetControllerReference(agentRun, pod, scheme); err != nil {
		return nil, fmt.Errorf("set AgentRun Pod owner: %w", err)
	}

	return pod, nil
}

// runtimeAuthChmod is the mode bump applied to seeded runtime-auth files: user
// only for root (unchanged), user+group for non-root (paired with fsGroup 1000).
func runtimeAuthChmod(agentRun *nvtv1alpha1.AgentRun) string {
	if AgentRunNonRoot(agentRun) {
		return "ug+rwX"
	}
	return "u+rwX"
}

// AgentRunNonRoot reports whether the agent container runs as the non-root
// `agent` user (uid/gid 1000, HOME=/home/agent). Default is root (unchanged).
func AgentRunNonRoot(agentRun *nvtv1alpha1.AgentRun) bool {
	return agentRun.Spec.Runtime.User == nvtv1alpha1.AgentRunUserNonRoot
}

// agentHomePath is the agent container's HOME: /home/agent for non-root, /root
// otherwise (matching the image's baked default).
func agentHomePath(agentRun *nvtv1alpha1.AgentRun) string {
	if AgentRunNonRoot(agentRun) {
		return agentNonRootHome
	}
	return "/root"
}

func workspaceSubPath(agentRun *nvtv1alpha1.AgentRun) string {
	if AgentRunWorkspaceMode(agentRun) == nvtv1alpha1.AgentRunWorkspacePersistent {
		return persistentWorkspaceSubPath
	}
	return ""
}

// RuntimeAuthMountPath resolves the Secret mount path for the AgentRun runtime auth reference.
func RuntimeAuthMountPath(agentRun *nvtv1alpha1.AgentRun) (string, error) {
	runtimeAuth := agentRun.Spec.RuntimeAuth
	if runtimeAuth == nil {
		return "", nil
	}
	if runtimeAuth.SecretName == "" {
		return "", fmt.Errorf("spec.runtimeAuth.secretName is required when runtimeAuth is present")
	}
	if runtimeAuth.MountPath != "" {
		if !path.IsAbs(runtimeAuth.MountPath) {
			return "", fmt.Errorf("spec.runtimeAuth.mountPath must be an absolute path, got %q", runtimeAuth.MountPath)
		}
		return runtimeAuth.MountPath, nil
	}
	switch agentRun.Spec.Runtime.Type {
	case "codex":
		return agentHomePath(agentRun) + "/.codex", nil
	case "claude":
		return agentHomePath(agentRun) + "/.claude", nil
	default:
		return "", fmt.Errorf("spec.runtimeAuth.mountPath is required for runtime type %q", agentRun.Spec.Runtime.Type)
	}
}

// AgentConfigMapName returns the deterministic ConfigMap name for an AgentRun.
func AgentConfigMapName(agentRunName string) string {
	return agentRunName + "-agent-config"
}

// AgentPodName returns the deterministic Pod name for an AgentRun.
func AgentPodName(agentRunName string) string {
	return agentRunName + "-agent"
}

// BrokerTokenSecretName returns the deterministic broker token Secret name for an AgentRun.
func BrokerTokenSecretName(agentRunName string) string {
	return agentRunName + "-broker-token"
}

// CallbackTokenSecretName returns the deterministic callback token Secret name for an AgentRun.
func CallbackTokenSecretName(agentRunName string) string {
	return agentRunName + "-callback-token"
}

func EgressTokenSecretName(agentRunName string) string {
	return agentRunName + "-egress-token"
}

func EgressdConfigMapName(agentRunName string) string {
	return agentRunName + "-egressd-config"
}

func EgressdImage() string {
	if image := strings.TrimSpace(os.Getenv("NVT_EGRESSD_IMAGE")); image != "" {
		return image
	}
	return defaultEgressdImage
}

func CapturedImage() string {
	if image := strings.TrimSpace(os.Getenv("NVT_CAPTURED_IMAGE")); image != "" {
		return image
	}
	return defaultCapturedImage
}

func DindImage() string {
	if image := strings.TrimSpace(os.Getenv("NVT_DIND_IMAGE")); image != "" {
		return image
	}
	return defaultDindImage
}

func DindImagePullPolicy() (corev1.PullPolicy, error) {
	value := strings.TrimSpace(os.Getenv("NVT_DIND_IMAGE_PULL_POLICY"))
	if value == "" {
		return corev1.PullIfNotPresent, nil
	}
	switch corev1.PullPolicy(value) {
	case corev1.PullAlways, corev1.PullIfNotPresent, corev1.PullNever:
		return corev1.PullPolicy(value), nil
	default:
		return "", fmt.Errorf("NVT_DIND_IMAGE_PULL_POLICY must be Always, IfNotPresent, or Never")
	}
}

func dockerPVCSize(agentRun *nvtv1alpha1.AgentRun) resource.Quantity {
	if agentRun.Spec.Workspace.DockerSize != nil {
		return agentRun.Spec.Workspace.DockerSize.DeepCopy()
	}
	return *resource.NewQuantity(defaultDockerPVCSizeBytes, resource.BinarySI)
}

func dindImageSizeBytes(agentRun *nvtv1alpha1.AgentRun) int64 {
	// The loopback filesystem deliberately advertises less capacity than its
	// dedicated outer PVC. This leaves enforced headroom for the outer
	// filesystem's allocation and metadata rather than thin-overcommitting it.
	size := dockerPVCSize(agentRun)
	return size.Value() * dindImageCapacityPercent / 100
}
