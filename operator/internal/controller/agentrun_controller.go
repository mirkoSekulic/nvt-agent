package controller

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/yaml"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

const (
	agentConfigKey       = "agent.yaml"
	agentConfigMountPath = "/nvt-agent/agent.yaml"
	agentConfigVolumeDir = "/nvt-agent"
	workspaceMountPath   = "/workspace"

	brokerURL                = "http://nvt-broker:7347"
	brokerTokenKey           = "NVT_BROKER_TOKEN"
	callbackTokenKey         = "NVT_OPERATOR_CALLBACK_TOKEN"
	generatedTokenByteLength = 32
)

// AgentRunReconciler reconciles AgentRun resources.
type AgentRunReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// Reconcile renders the AgentRun config, creates the agent Pod, and syncs basic Pod-phase status.
func (r *AgentRunReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var agentRun nvtv1alpha1.AgentRun
	if err := r.Get(ctx, req.NamespacedName, &agentRun); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get AgentRun: %w", err)
	}

	if err := r.reconcileAgentConfigMap(ctx, &agentRun); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.reconcileBrokerTokenSecret(ctx, &agentRun); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.reconcileCallbackTokenSecret(ctx, &agentRun); err != nil {
		return ctrl.Result{}, err
	}

	pod, err := r.reconcileAgentPod(ctx, &agentRun)
	if err != nil {
		return ctrl.Result{}, err
	}

	statusChanged := InitializeAgentRunStatus(&agentRun)
	if SyncAgentRunStatusFromPod(&agentRun, pod) {
		statusChanged = true
	}
	if statusChanged {
		if err := r.Status().Update(ctx, &agentRun); err != nil {
			return ctrl.Result{}, fmt.Errorf("update AgentRun status: %w", err)
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager registers the AgentRun controller with the manager.
func (r *AgentRunReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := ctrl.NewControllerManagedBy(mgr).
		For(&nvtv1alpha1.AgentRun{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.Pod{}).
		Complete(r); err != nil {
		return fmt.Errorf("build AgentRun controller: %w", err)
	}

	return nil
}

func (r *AgentRunReconciler) reconcileAgentConfigMap(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) error {
	desired, err := DesiredAgentConfigMap(agentRun, r.Scheme)
	if err != nil {
		return err
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      desired.Name,
			Namespace: desired.Namespace,
		},
	}
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, configMap, func() error {
		configMap.Labels = desired.Labels
		configMap.OwnerReferences = desired.OwnerReferences
		configMap.Data = desired.Data
		return nil
	})
	if err != nil {
		return fmt.Errorf("reconcile AgentRun config ConfigMap: %w", err)
	}

	return nil
}

func (r *AgentRunReconciler) reconcileBrokerTokenSecret(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) error {
	return r.reconcileTokenSecret(ctx, agentRun, BrokerTokenSecretName(agentRun.Name), brokerTokenKey)
}

func (r *AgentRunReconciler) reconcileCallbackTokenSecret(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) error {
	return r.reconcileTokenSecret(ctx, agentRun, CallbackTokenSecretName(agentRun.Name), callbackTokenKey)
}

func (r *AgentRunReconciler) reconcileTokenSecret(ctx context.Context, agentRun *nvtv1alpha1.AgentRun, name, key string) error {
	secret := &corev1.Secret{}
	secretKey := client.ObjectKey{Namespace: agentRun.Namespace, Name: name}
	if err := r.Get(ctx, secretKey, secret); err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("get AgentRun token Secret %s/%s: %w", secretKey.Namespace, secretKey.Name, err)
		}
		desired, desiredErr := DesiredTokenSecret(agentRun, r.Scheme, name, key, nil)
		if desiredErr != nil {
			return desiredErr
		}
		if createErr := r.Create(ctx, desired); createErr != nil {
			return fmt.Errorf("create AgentRun token Secret %s/%s: %w", secretKey.Namespace, secretKey.Name, createErr)
		}
		return nil
	}
	if !metav1.IsControlledBy(secret, agentRun) {
		return fmt.Errorf("AgentRun token Secret %s/%s exists but is not controlled by AgentRun %s", secret.Namespace, secret.Name, agentRun.Name)
	}

	token := secret.Data[key]
	desired, err := DesiredTokenSecret(agentRun, r.Scheme, name, key, token)
	if err != nil {
		return err
	}
	if secret.Type == desired.Type &&
		reflect.DeepEqual(secret.Labels, desired.Labels) &&
		reflect.DeepEqual(secret.OwnerReferences, desired.OwnerReferences) &&
		reflect.DeepEqual(secret.Data, desired.Data) {
		return nil
	}

	secret.Labels = desired.Labels
	secret.OwnerReferences = desired.OwnerReferences
	secret.Type = desired.Type
	secret.Data = desired.Data
	if err := r.Update(ctx, secret); err != nil {
		return fmt.Errorf("update AgentRun token Secret %s/%s: %w", secret.Namespace, secret.Name, err)
	}

	return nil
}

func (r *AgentRunReconciler) reconcileAgentPod(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) (*corev1.Pod, error) {
	desired, err := DesiredAgentPod(agentRun, r.Scheme)
	if err != nil {
		return nil, err
	}

	// Pods are create-once for this slice because most spec fields are immutable.
	// A future replacement policy can decide how to handle spec changes.
	pod := &corev1.Pod{}
	key := client.ObjectKeyFromObject(desired)
	if err := r.Get(ctx, key, pod); err != nil {
		if !errors.IsNotFound(err) {
			return nil, fmt.Errorf("get AgentRun Pod: %w", err)
		}
		if createErr := r.Create(ctx, desired); createErr != nil {
			return nil, fmt.Errorf("create AgentRun Pod: %w", createErr)
		}
		return desired, nil
	}
	if !metav1.IsControlledBy(pod, agentRun) {
		return nil, fmt.Errorf("AgentRun Pod %s/%s exists but is not controlled by AgentRun %s", pod.Namespace, pod.Name, agentRun.Name)
	}

	return pod, nil
}

// DesiredTokenSecret returns an owned token Secret, preserving an existing token when present.
func DesiredTokenSecret(
	agentRun *nvtv1alpha1.AgentRun,
	scheme *runtime.Scheme,
	name string,
	key string,
	existingToken []byte,
) (*corev1.Secret, error) {
	token := existingToken
	if len(token) == 0 {
		generated, err := GenerateToken(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate AgentRun token Secret %s token: %w", name, err)
		}
		token = []byte(generated)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: agentRun.Namespace,
			Labels:    agentRunLabels(agentRun.Name),
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			key: append([]byte(nil), token...),
		},
	}
	if err := controllerutil.SetControllerReference(agentRun, secret, scheme); err != nil {
		return nil, fmt.Errorf("set AgentRun token Secret owner: %w", err)
	}

	return secret, nil
}

// DesiredAgentConfigMap renders the AgentRun agent config into its owned ConfigMap.
func DesiredAgentConfigMap(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme) (*corev1.ConfigMap, error) {
	rendered, err := RenderAgentConfigYAML(agentRun)
	if err != nil {
		return nil, err
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      AgentConfigMapName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    agentRunLabels(agentRun.Name),
		},
		Data: map[string]string{
			agentConfigKey: rendered,
		},
	}
	if err := controllerutil.SetControllerReference(agentRun, configMap, scheme); err != nil {
		return nil, fmt.Errorf("set AgentRun config ConfigMap owner: %w", err)
	}

	return configMap, nil
}

// DesiredAgentPod returns the create-once Pod spec for an AgentRun.
func DesiredAgentPod(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme) (*corev1.Pod, error) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      AgentPodName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    agentRunLabels(agentRun.Name),
		},
		Spec: corev1.PodSpec{
			RuntimeClassName: agentRun.Spec.RuntimeClassName,
			RestartPolicy:    corev1.RestartPolicyNever,
			InitContainers: []corev1.Container{
				{
					Name:          "docker",
					Image:         "docker:27-dind",
					RestartPolicy: ptrTo(corev1.ContainerRestartPolicyAlways),
					Command:       []string{"dockerd"},
					Args: []string{
						"--host=unix:///var/run/docker.sock",
						"--host=tcp://127.0.0.1:2375",
						"--tls=false",
					},
					Env: []corev1.EnvVar{
						{Name: "DOCKER_TLS_CERTDIR", Value: ""},
					},
					SecurityContext: &corev1.SecurityContext{
						Privileged: ptrTo(true),
					},
					StartupProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							Exec: &corev1.ExecAction{Command: []string{"docker", "info"}},
						},
						PeriodSeconds:    2,
						FailureThreshold: 30,
					},
					VolumeMounts: []corev1.VolumeMount{
						{Name: "workspace", MountPath: workspaceMountPath},
					},
				},
			},
			Containers: []corev1.Container{
				{
					Name:       "agent",
					Image:      agentRun.Spec.Image,
					WorkingDir: workspaceMountPath,
					Env: []corev1.EnvVar{
						{Name: "DOCKER_HOST", Value: "tcp://127.0.0.1:2375"},
						{Name: "NVT_WORKSPACE", Value: workspaceMountPath},
						{Name: "NVT_AGENT_CONFIG_FILE", Value: agentConfigMountPath},
						{Name: "NVT_BROKER_URL", Value: brokerURL},
						{
							Name: brokerTokenKey,
							ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: BrokerTokenSecretName(agentRun.Name)},
									Key:                  brokerTokenKey,
								},
							},
						},
						{
							Name: callbackTokenKey,
							ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: CallbackTokenSecretName(agentRun.Name)},
									Key:                  callbackTokenKey,
								},
							},
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{Name: "workspace", MountPath: workspaceMountPath},
						{Name: "agent-config", MountPath: agentConfigVolumeDir, ReadOnly: true},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "workspace",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
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
			},
		},
	}
	if err := controllerutil.SetControllerReference(agentRun, pod, scheme); err != nil {
		return nil, fmt.Errorf("set AgentRun Pod owner: %w", err)
	}

	return pod, nil
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

func agentRunLabels(agentRunName string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      "nvt-agent",
		"app.kubernetes.io/component": "agentrun",
		"nvt.dev/agentrun":            agentRunName,
	}
}

// GenerateToken returns a URL-safe token with 256 bits of cryptographic entropy.
func GenerateToken(reader io.Reader) (string, error) {
	randomBytes := make([]byte, generatedTokenByteLength)
	if _, err := io.ReadFull(reader, randomBytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

// RenderAgentConfigYAML converts the preserved AgentRun agent config payload to YAML.
func RenderAgentConfigYAML(agentRun *nvtv1alpha1.AgentRun) (string, error) {
	rawConfig := agentRun.Spec.Agent.Config.Raw
	if len(rawConfig) == 0 {
		rawConfig = []byte("{}")
	}

	rendered, err := yaml.JSONToYAML(rawConfig)
	if err != nil {
		return "", fmt.Errorf("render AgentRun agent config: %w", err)
	}

	return string(rendered), nil
}

// InitializeAgentRunStatus sets the initial phase when a run has no observed phase yet.
func InitializeAgentRunStatus(agentRun *nvtv1alpha1.AgentRun) bool {
	if agentRun.Status.Phase != "" {
		return false
	}

	agentRun.Status.Phase = nvtv1alpha1.AgentRunPhasePending
	return true
}

// SyncAgentRunStatusFromPod reflects the small Pod-phase status surface owned by this controller slice.
func SyncAgentRunStatusFromPod(agentRun *nvtv1alpha1.AgentRun, pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}

	changed := false
	if agentRun.Status.PodName != pod.Name {
		agentRun.Status.PodName = pod.Name
		changed = true
	}

	switch pod.Status.Phase {
	case corev1.PodRunning:
		if agentRun.Status.Phase != nvtv1alpha1.AgentRunPhaseRunning {
			agentRun.Status.Phase = nvtv1alpha1.AgentRunPhaseRunning
			changed = true
		}
		if agentRun.Status.StartedAt == nil {
			now := metav1.Now()
			agentRun.Status.StartedAt = &now
			changed = true
		}
	case corev1.PodFailed:
		if agentRun.Status.Phase != nvtv1alpha1.AgentRunPhaseFailed {
			agentRun.Status.Phase = nvtv1alpha1.AgentRunPhaseFailed
			changed = true
		}
	}

	return changed
}

func ptrTo[T any](value T) *T {
	return &value
}
