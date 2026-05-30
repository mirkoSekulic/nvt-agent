package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/yaml"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

const (
	agentConfigKey       = "agent.yaml"
	agentConfigMountPath = "/nvt-agent/agent.yaml"
	agentConfigVolumeDir = "/nvt-agent"
	workspaceMountPath   = "/workspace"

	brokerURL                 = "http://nvt-broker:7347"
	brokerAgentsConfigMapName = "nvt-broker-agents"
	brokerAgentsConfigKey     = "agents.yaml"
	brokerTokenKey            = "NVT_BROKER_TOKEN"
	callbackTokenKey          = "NVT_OPERATOR_CALLBACK_TOKEN"
	agentRunFinalizer         = "nvt.dev/agentrun-broker-policy"
	generatedTokenByteLength  = 32
)

type brokerAgentsPolicy struct {
	Agents []brokerAgentEntry `json:"agents"`
}

type brokerAgentEntry struct {
	ID          string                  `json:"id"`
	TokenSHA256 string                  `json:"token-sha256"`
	Grants      []brokerAgentGrantEntry `json:"grants"`
}

type brokerAgentGrantEntry struct {
	Provider     string   `json:"provider"`
	Repositories []string `json:"repositories"`
}

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

	if !agentRun.DeletionTimestamp.IsZero() {
		if err := r.finalizeAgentRun(ctx, &agentRun); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if controllerutil.AddFinalizer(&agentRun, agentRunFinalizer) {
		if err := r.Update(ctx, &agentRun); err != nil {
			return ctrl.Result{}, fmt.Errorf("add AgentRun finalizer: %w", err)
		}
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
	if err := r.reconcileBrokerAgentsPolicy(ctx, &agentRun); err != nil {
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
		Watches(
			&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.agentRunsForBrokerAgentsConfigMap),
			builder.WithPredicates(predicate.NewPredicateFuncs(isBrokerAgentsConfigMap)),
		).
		Complete(r); err != nil {
		return fmt.Errorf("build AgentRun controller: %w", err)
	}

	return nil
}

func (r *AgentRunReconciler) agentRunsForBrokerAgentsConfigMap(ctx context.Context, object client.Object) []reconcile.Request {
	if !isBrokerAgentsConfigMap(object) {
		return nil
	}

	var agentRuns nvtv1alpha1.AgentRunList
	if err := r.List(ctx, &agentRuns, client.InNamespace(object.GetNamespace())); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "list AgentRuns for broker agents ConfigMap", "namespace", object.GetNamespace())
		return nil
	}

	requests := make([]reconcile.Request, 0, len(agentRuns.Items))
	for _, agentRun := range agentRuns.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{Namespace: agentRun.Namespace, Name: agentRun.Name},
		})
	}
	sort.Slice(requests, func(i, j int) bool {
		if requests[i].Namespace != requests[j].Namespace {
			return requests[i].Namespace < requests[j].Namespace
		}
		return requests[i].Name < requests[j].Name
	})

	return requests
}

func isBrokerAgentsConfigMap(object client.Object) bool {
	return object.GetName() == brokerAgentsConfigMapName
}

func (r *AgentRunReconciler) finalizeAgentRun(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) error {
	if !controllerutil.ContainsFinalizer(agentRun, agentRunFinalizer) {
		return nil
	}

	if err := r.removeBrokerAgentsPolicyEntry(ctx, agentRun); err != nil {
		return err
	}
	controllerutil.RemoveFinalizer(agentRun, agentRunFinalizer)
	if err := r.Update(ctx, agentRun); err != nil {
		return fmt.Errorf("remove AgentRun finalizer: %w", err)
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

func (r *AgentRunReconciler) reconcileBrokerAgentsPolicy(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) error {
	secret := &corev1.Secret{}
	secretKey := client.ObjectKey{Namespace: agentRun.Namespace, Name: BrokerTokenSecretName(agentRun.Name)}
	if err := r.Get(ctx, secretKey, secret); err != nil {
		return fmt.Errorf("get AgentRun broker token Secret %s/%s for broker policy: %w", secretKey.Namespace, secretKey.Name, err)
	}
	token := secret.Data[brokerTokenKey]
	if len(token) == 0 {
		return fmt.Errorf("AgentRun broker token Secret %s/%s is missing %s", secret.Namespace, secret.Name, brokerTokenKey)
	}

	entry := brokerAgentEntry{
		ID:          AgentRunBrokerID(agentRun.Namespace, agentRun.Name),
		TokenSHA256: BrokerTokenHash(token),
		Grants:      BrokerAgentGrants(agentRun.Spec.Broker),
	}

	if err := r.updateBrokerAgentsPolicy(ctx, agentRun.Namespace, func(policy brokerAgentsPolicy) (brokerAgentsPolicy, error) {
		return UpsertBrokerAgent(policy, entry), nil
	}); err != nil {
		if errors.IsNotFound(err) {
			return fmt.Errorf("broker agents ConfigMap %s/%s is required before reconciling AgentRun broker policy: %w", agentRun.Namespace, brokerAgentsConfigMapName, err)
		}
		return err
	}

	return nil
}

func (r *AgentRunReconciler) removeBrokerAgentsPolicyEntry(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) error {
	err := r.updateBrokerAgentsPolicy(ctx, agentRun.Namespace, func(policy brokerAgentsPolicy) (brokerAgentsPolicy, error) {
		return RemoveBrokerAgent(policy, AgentRunBrokerID(agentRun.Namespace, agentRun.Name)), nil
	})
	if errors.IsNotFound(err) {
		// Fail open on deletion so AgentRun cleanup is not blocked if broker
		// infrastructure was removed first in a local/kind POC cluster.
		return nil
	}
	return err
}

func (r *AgentRunReconciler) updateBrokerAgentsPolicy(
	ctx context.Context,
	namespace string,
	mutate func(brokerAgentsPolicy) (brokerAgentsPolicy, error),
) error {
	key := client.ObjectKey{Namespace: namespace, Name: brokerAgentsConfigMapName}
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		configMap := &corev1.ConfigMap{}
		if err := r.Get(ctx, key, configMap); err != nil {
			return err
		}
		rawPolicy, ok := configMap.Data[brokerAgentsConfigKey]
		if !ok {
			return fmt.Errorf("broker agents ConfigMap %s/%s is missing %s", key.Namespace, key.Name, brokerAgentsConfigKey)
		}
		policy, err := ParseBrokerAgentsYAML(rawPolicy)
		if err != nil {
			return fmt.Errorf("parse broker agents ConfigMap %s/%s %s: %w", key.Namespace, key.Name, brokerAgentsConfigKey, err)
		}
		updatedPolicy, err := mutate(policy)
		if err != nil {
			return err
		}
		if err := ValidateBrokerAgentsPolicy(updatedPolicy); err != nil {
			return fmt.Errorf("validate broker agents ConfigMap %s/%s %s: %w", key.Namespace, key.Name, brokerAgentsConfigKey, err)
		}
		rendered, err := RenderBrokerAgentsYAML(updatedPolicy)
		if err != nil {
			return fmt.Errorf("render broker agents ConfigMap %s/%s %s: %w", key.Namespace, key.Name, brokerAgentsConfigKey, err)
		}
		if configMap.Data[brokerAgentsConfigKey] == rendered {
			return nil
		}
		if configMap.Data == nil {
			configMap.Data = map[string]string{}
		}
		configMap.Data[brokerAgentsConfigKey] = rendered
		if err := r.Update(ctx, configMap); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		if errors.IsNotFound(err) {
			return err
		}
		return fmt.Errorf("update broker agents ConfigMap %s/%s: %w", key.Namespace, key.Name, err)
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

// AgentRunBrokerID returns the broker identity for an AgentRun.
func AgentRunBrokerID(namespace, name string) string {
	return namespace + "/" + name
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

// BrokerTokenHash returns the broker policy hash for a raw token.
func BrokerTokenHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// BrokerAgentGrants converts AgentRun grants into broker policy grants.
func BrokerAgentGrants(broker *nvtv1alpha1.AgentRunBroker) []brokerAgentGrantEntry {
	if broker == nil || broker.Grants == nil {
		return []brokerAgentGrantEntry{}
	}

	grants := make([]brokerAgentGrantEntry, 0, len(broker.Grants))
	for _, grant := range broker.Grants {
		repositories := []string{}
		if grant.Repositories != nil {
			repositories = append(repositories, grant.Repositories...)
		}
		grants = append(grants, brokerAgentGrantEntry{
			Provider:     grant.Provider,
			Repositories: repositories,
		})
	}
	sort.SliceStable(grants, func(i, j int) bool {
		if grants[i].Provider != grants[j].Provider {
			return grants[i].Provider < grants[j].Provider
		}
		return stringsLess(grants[i].Repositories, grants[j].Repositories)
	})

	return grants
}

// ParseBrokerAgentsYAML parses broker agents policy YAML.
func ParseBrokerAgentsYAML(raw string) (brokerAgentsPolicy, error) {
	if raw == "" {
		raw = "agents: []"
	}

	var policy brokerAgentsPolicy
	if err := yaml.Unmarshal([]byte(raw), &policy); err != nil {
		return brokerAgentsPolicy{}, err
	}
	if policy.Agents == nil {
		policy.Agents = []brokerAgentEntry{}
	}
	normalizeBrokerAgentsPolicy(&policy)

	return policy, nil
}

// RenderBrokerAgentsYAML renders deterministic broker agents policy YAML.
func RenderBrokerAgentsYAML(policy brokerAgentsPolicy) (string, error) {
	normalizeBrokerAgentsPolicy(&policy)
	if err := ValidateBrokerAgentsPolicy(policy); err != nil {
		return "", err
	}
	rendered, err := yaml.Marshal(policy)
	if err != nil {
		return "", err
	}
	return string(rendered), nil
}

// UpsertBrokerAgent inserts or replaces one broker agent entry.
func UpsertBrokerAgent(policy brokerAgentsPolicy, entry brokerAgentEntry) brokerAgentsPolicy {
	normalizeBrokerAgentEntry(&entry)
	agents := make([]brokerAgentEntry, 0, len(policy.Agents)+1)
	for i := range policy.Agents {
		if policy.Agents[i].ID == entry.ID {
			continue
		}
		agents = append(agents, policy.Agents[i])
	}
	agents = append(agents, entry)
	policy.Agents = agents
	normalizeBrokerAgentsPolicy(&policy)
	return policy
}

// RemoveBrokerAgent removes one broker agent entry by id.
func RemoveBrokerAgent(policy brokerAgentsPolicy, id string) brokerAgentsPolicy {
	agents := make([]brokerAgentEntry, 0, len(policy.Agents))
	for _, agent := range policy.Agents {
		if agent.ID == id {
			continue
		}
		agents = append(agents, agent)
	}
	policy.Agents = agents
	normalizeBrokerAgentsPolicy(&policy)
	return policy
}

// ValidateBrokerAgentsPolicy checks the policy shape accepted by the broker.
func ValidateBrokerAgentsPolicy(policy brokerAgentsPolicy) error {
	seenIDs := map[string]struct{}{}
	seenHashes := map[string]string{}
	for agentIndex, agent := range policy.Agents {
		if agent.ID == "" {
			return fmt.Errorf("agents[%d].id is required", agentIndex)
		}
		if _, exists := seenIDs[agent.ID]; exists {
			return fmt.Errorf("duplicate agent id: %s", agent.ID)
		}
		seenIDs[agent.ID] = struct{}{}
		if !validBrokerTokenHash(agent.TokenSHA256) {
			return fmt.Errorf("agents[%d].token-sha256 must be sha256:<hex>", agentIndex)
		}
		if existingID, exists := seenHashes[agent.TokenSHA256]; exists {
			return fmt.Errorf("duplicate token hash for agents %s and %s", existingID, agent.ID)
		}
		seenHashes[agent.TokenSHA256] = agent.ID
		for grantIndex, grant := range agent.Grants {
			if grant.Provider == "" {
				return fmt.Errorf("agents[%d].grants[%d].provider is required", agentIndex, grantIndex)
			}
			for repoIndex, repository := range grant.Repositories {
				if repository == "" {
					return fmt.Errorf("agents[%d].grants[%d].repositories[%d] must be a non-empty string", agentIndex, grantIndex, repoIndex)
				}
			}
		}
	}

	return nil
}

func validBrokerTokenHash(value string) bool {
	if !strings.HasPrefix(value, "sha256:") {
		return false
	}
	encoded := strings.TrimPrefix(value, "sha256:")
	if len(encoded) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(encoded)
	return err == nil
}

func normalizeBrokerAgentsPolicy(policy *brokerAgentsPolicy) {
	if policy.Agents == nil {
		policy.Agents = []brokerAgentEntry{}
	}
	for i := range policy.Agents {
		normalizeBrokerAgentEntry(&policy.Agents[i])
	}
	sort.SliceStable(policy.Agents, func(i, j int) bool {
		return policy.Agents[i].ID < policy.Agents[j].ID
	})
}

func normalizeBrokerAgentEntry(entry *brokerAgentEntry) {
	if entry.Grants == nil {
		entry.Grants = []brokerAgentGrantEntry{}
	}
	for i := range entry.Grants {
		if entry.Grants[i].Repositories == nil {
			entry.Grants[i].Repositories = []string{}
		}
	}
	sort.SliceStable(entry.Grants, func(i, j int) bool {
		if entry.Grants[i].Provider != entry.Grants[j].Provider {
			return entry.Grants[i].Provider < entry.Grants[j].Provider
		}
		return stringsLess(entry.Grants[i].Repositories, entry.Grants[j].Repositories)
	})
}

func stringsLess(left, right []string) bool {
	for i := 0; i < len(left) && i < len(right); i++ {
		if left[i] != right[i] {
			return left[i] < right[i]
		}
	}
	return len(left) < len(right)
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
