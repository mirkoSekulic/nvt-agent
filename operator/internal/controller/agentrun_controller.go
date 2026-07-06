package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"reflect"
	"sort"
	"strings"
	"time"

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
	agentConfigKey        = "agent.yaml"
	agentConfigMountPath  = "/nvt-agent/agent.yaml"
	agentConfigVolumeDir  = "/nvt-agent"
	runtimeAuthSourcePath = "/nvt-agent/runtime-auth-source"
	runtimeAuthHomePath   = "/nvt-agent/runtime-auth-home"
	runtimeAuthSourceName = "runtime-auth-source"
	runtimeAuthHomeName   = "runtime-auth-home"
	egressdConfigKey      = "egressd.json"
	egressdConfigPath     = "/etc/nvt-egressd/config.json"
	egressCAVolumeName    = "egress-ca"
	egressCAMountPath     = "/nvt-egress-ca"
	egressCAFilePath      = egressCAMountPath + "/ca.crt"
	workspaceMountPath    = "/workspace"
	initialPromptPlugin   = "initial-prompt"

	brokerURL                  = "http://nvt-broker:7347"
	brokerAgentsConfigMapName  = "nvt-broker-agents"
	brokerAgentsConfigKey      = "agents.yaml"
	brokerTokenKey             = "NVT_BROKER_TOKEN"
	egressTokenKey             = "NVT_EGRESS_BROKER_TOKEN"
	defaultEgressdImage        = "nvt-egressd:latest"
	callbackTokenKey           = "NVT_OPERATOR_CALLBACK_TOKEN"
	agentRunFinalizer          = "nvt.dev/agentrun-broker-policy"
	completedLifecycleReason   = "Completed by lifecycle event "
	failedLifecycleReason      = "Failed by lifecycle event "
	activeDeadlineReason       = "Active deadline exceeded"
	generatedTokenByteLength   = 32
	defaultRunRetentionSeconds = 30 * 24 * 60 * 60
)

type brokerAgentsPolicy struct {
	Agents []brokerAgentEntry `json:"agents"`
}

type brokerAgentEntry struct {
	ID          string                  `json:"id"`
	TokenSHA256 string                  `json:"token-sha256"`
	Role        string                  `json:"role,omitempty"`
	PairedAgent string                  `json:"paired-agent,omitempty"`
	Grants      []brokerAgentGrantEntry `json:"grants"`
}

type brokerAgentGrantEntry struct {
	Provider        string            `json:"provider"`
	Repositories    []string          `json:"repositories"`
	Materialization string            `json:"materialization,omitempty"`
	EgressHosts     []string          `json:"egress-hosts,omitempty"`
	Permissions     map[string]string `json:"permissions,omitempty"`
}

// AgentRunReconciler reconciles AgentRun resources.
type AgentRunReconciler struct {
	client.Client

	Scheme *runtime.Scheme
	Now    func() metav1.Time
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

	if IsTerminalAgentRunPhase(agentRun.Status.Phase) {
		return r.reconcileTerminalPodCleanup(ctx, &agentRun)
	}
	if err := ValidateAgentRunEgressMode(&agentRun); err != nil {
		if setErr := r.setAgentRunFailed(ctx, &agentRun, err.Error()); setErr != nil {
			return ctrl.Result{}, setErr
		}
		return ctrl.Result{}, nil
	}
	deadlineResult, deadlineExceeded, err := r.reconcileActiveDeadline(ctx, &agentRun)
	if deadlineExceeded || err != nil {
		return deadlineResult, err
	}

	if err := r.reconcileAgentConfigMap(ctx, &agentRun); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.reconcileBrokerTokenSecret(ctx, &agentRun); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.reconcileEgressTokenSecret(ctx, &agentRun); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.reconcileCallbackTokenSecret(ctx, &agentRun); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.reconcileEgressdConfigMap(ctx, &agentRun); err != nil {
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
	if SyncAgentRunStatusFromPod(&agentRun, pod, r.now()) {
		statusChanged = true
	}
	if statusChanged {
		if err := r.Status().Update(ctx, &agentRun); err != nil {
			return ctrl.Result{}, fmt.Errorf("update AgentRun status: %w", err)
		}
	}

	if IsTerminalAgentRunPhase(agentRun.Status.Phase) {
		return r.reconcileTerminalPodCleanup(ctx, &agentRun)
	}
	deadlineResult, deadlineExceeded, err = r.reconcileActiveDeadline(ctx, &agentRun)
	if deadlineExceeded || err != nil {
		return deadlineResult, err
	}
	return deadlineResult, nil
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

func (r *AgentRunReconciler) reconcileTerminalPodCleanup(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) (ctrl.Result, error) {
	if agentRun.Status.Phase == nvtv1alpha1.AgentRunPhaseDeadlineExceeded {
		if err := r.deleteOwnedAgentPod(ctx, agentRun, "deadline-exceeded AgentRun Pod"); err != nil {
			return ctrl.Result{}, err
		}
		return r.reconcileTerminalAgentRunRetention(ctx, agentRun)
	}

	remaining, shouldDelete := TerminalPodCleanupDelay(agentRun, r.now())
	if remaining > 0 {
		return ctrl.Result{RequeueAfter: remaining}, nil
	}
	if !shouldDelete {
		return r.reconcileTerminalAgentRunRetention(ctx, agentRun)
	}

	if err := r.deleteOwnedAgentPod(ctx, agentRun, "terminal AgentRun Pod"); err != nil {
		return ctrl.Result{}, err
	}

	return r.reconcileTerminalAgentRunRetention(ctx, agentRun)
}

func (r *AgentRunReconciler) reconcileTerminalAgentRunRetention(
	ctx context.Context,
	agentRun *nvtv1alpha1.AgentRun,
) (ctrl.Result, error) {
	remaining, shouldDelete := RunRetentionDelay(agentRun, r.now())
	if remaining > 0 {
		return ctrl.Result{RequeueAfter: remaining}, nil
	}
	if !shouldDelete {
		return ctrl.Result{}, nil
	}
	if err := r.Delete(ctx, agentRun); err != nil {
		return ctrl.Result{}, fmt.Errorf("delete retained AgentRun: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *AgentRunReconciler) reconcileActiveDeadline(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) (ctrl.Result, bool, error) {
	now := r.now()
	remaining, exceeded := ActiveDeadlineDelay(agentRun, now)
	if remaining > 0 {
		return ctrl.Result{RequeueAfter: remaining}, false, nil
	}
	if !exceeded {
		return ctrl.Result{}, false, nil
	}

	agentRun.Status.Phase = nvtv1alpha1.AgentRunPhaseDeadlineExceeded
	agentRun.Status.FinishedAt = &now
	agentRun.Status.Reason = activeDeadlineReason
	if err := r.Status().Update(ctx, agentRun); err != nil {
		return ctrl.Result{}, true, fmt.Errorf("mark AgentRun active deadline exceeded: %w", err)
	}
	if err := r.deleteOwnedAgentPod(ctx, agentRun, "active deadline AgentRun Pod"); err != nil {
		return ctrl.Result{}, true, err
	}

	return ctrl.Result{}, true, nil
}

func (r *AgentRunReconciler) deleteOwnedAgentPod(ctx context.Context, agentRun *nvtv1alpha1.AgentRun, description string) error {
	pod := &corev1.Pod{}
	key := client.ObjectKey{Namespace: agentRun.Namespace, Name: AgentPodName(agentRun.Name)}
	if err := r.Get(ctx, key, pod); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("get %s for cleanup: %w", description, err)
	}
	if !metav1.IsControlledBy(pod, agentRun) {
		return fmt.Errorf("%s %s/%s exists but is not controlled by AgentRun %s", description, pod.Namespace, pod.Name, agentRun.Name)
	}
	if err := r.Delete(ctx, pod); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("delete %s: %w", description, err)
	}
	return nil
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

func (r *AgentRunReconciler) now() metav1.Time {
	if r.Now != nil {
		return r.Now()
	}
	return metav1.Now()
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

func (r *AgentRunReconciler) reconcileEgressdConfigMap(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) error {
	if AgentRunEgressMode(agentRun) != nvtv1alpha1.AgentRunEgressMediated {
		return nil
	}
	desired, err := DesiredEgressdConfigMap(agentRun, r.Scheme)
	if err != nil {
		return err
	}
	configMap := &corev1.ConfigMap{}
	err = r.Get(ctx, client.ObjectKeyFromObject(desired), configMap)
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("get AgentRun egressd config ConfigMap: %w", err)
		}
		if createErr := r.Create(ctx, desired); createErr != nil {
			return fmt.Errorf("create AgentRun egressd config ConfigMap: %w", createErr)
		}
		return nil
	}
	if !metav1.IsControlledBy(configMap, agentRun) {
		return fmt.Errorf("AgentRun egressd config ConfigMap %s/%s exists but is not controlled by AgentRun %s", configMap.Namespace, configMap.Name, agentRun.Name)
	}
	if reflect.DeepEqual(configMap.Data, desired.Data) &&
		reflect.DeepEqual(configMap.Labels, desired.Labels) &&
		reflect.DeepEqual(configMap.OwnerReferences, desired.OwnerReferences) {
		return nil
	}
	configMap.Labels = desired.Labels
	configMap.OwnerReferences = desired.OwnerReferences
	configMap.Data = desired.Data
	if err := r.Update(ctx, configMap); err != nil {
		return fmt.Errorf("update AgentRun egressd config ConfigMap: %w", err)
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
	entries := []brokerAgentEntry{entry}
	if AgentRunEgressMode(agentRun) == nvtv1alpha1.AgentRunEgressMediated {
		egressSecret := &corev1.Secret{}
		egressSecretKey := client.ObjectKey{Namespace: agentRun.Namespace, Name: EgressTokenSecretName(agentRun.Name)}
		if err := r.Get(ctx, egressSecretKey, egressSecret); err != nil {
			return fmt.Errorf("get AgentRun egress token Secret %s/%s for broker policy: %w", egressSecretKey.Namespace, egressSecretKey.Name, err)
		}
		egressToken := egressSecret.Data[egressTokenKey]
		if len(egressToken) == 0 {
			return fmt.Errorf("AgentRun egress token Secret %s/%s is missing %s", egressSecret.Namespace, egressSecret.Name, egressTokenKey)
		}
		entries = append(entries, brokerAgentEntry{
			ID:          AgentRunEgressBrokerID(agentRun.Namespace, agentRun.Name),
			TokenSHA256: BrokerTokenHash(egressToken),
			Role:        "egress",
			PairedAgent: AgentRunBrokerID(agentRun.Namespace, agentRun.Name),
			Grants:      []brokerAgentGrantEntry{},
		})
	}

	if err := r.updateBrokerAgentsPolicy(ctx, agentRun.Namespace, func(policy brokerAgentsPolicy) (brokerAgentsPolicy, error) {
		for _, entry := range entries {
			policy = UpsertBrokerAgent(policy, entry)
		}
		return policy, nil
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
		policy = RemoveBrokerAgent(policy, AgentRunBrokerID(agentRun.Namespace, agentRun.Name))
		policy = RemoveBrokerAgent(policy, AgentRunEgressBrokerID(agentRun.Namespace, agentRun.Name))
		return policy, nil
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

func (r *AgentRunReconciler) reconcileEgressTokenSecret(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) error {
	if AgentRunEgressMode(agentRun) != nvtv1alpha1.AgentRunEgressMediated {
		return nil
	}
	return r.reconcileTokenSecret(ctx, agentRun, EgressTokenSecretName(agentRun.Name), egressTokenKey)
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

func (r *AgentRunReconciler) setAgentRunFailed(ctx context.Context, agentRun *nvtv1alpha1.AgentRun, reason string) error {
	key := client.ObjectKeyFromObject(agentRun)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &nvtv1alpha1.AgentRun{}
		if err := r.Get(ctx, key, current); err != nil {
			return err
		}
		now := r.now()
		current.Status.Phase = nvtv1alpha1.AgentRunPhaseFailed
		current.Status.Reason = reason
		if current.Status.FinishedAt == nil {
			current.Status.FinishedAt = &now
		}
		return r.Status().Update(ctx, current)
	})
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

// DesiredEgressdConfigMap renders the mediated egressd config for an AgentRun.
func DesiredEgressdConfigMap(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme) (*corev1.ConfigMap, error) {
	rendered, err := RenderEgressdConfigJSON(agentRun)
	if err != nil {
		return nil, err
	}
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      EgressdConfigMapName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    agentRunLabels(agentRun.Name),
		},
		Data: map[string]string{
			egressdConfigKey: rendered,
		},
	}
	if err := controllerutil.SetControllerReference(agentRun, configMap, scheme); err != nil {
		return nil, fmt.Errorf("set AgentRun egressd config ConfigMap owner: %w", err)
	}
	return configMap, nil
}

func RenderEgressdConfigJSON(agentRun *nvtv1alpha1.AgentRun) (string, error) {
	type egressdRoute struct {
		Listen                string `json:"listen"`
		Capability            string `json:"capability"`
		Upstream              string `json:"upstream"`
		AllowInsecureUpstream bool   `json:"allow_insecure_upstream"`
		ListenTLS             string `json:"listen_tls,omitempty"`
	}
	type egressdCA struct {
		PublishDir string `json:"publish_dir"`
	}
	type egressdConfig struct {
		BrokerURL           string         `json:"broker_url"`
		AllowInsecureBroker bool           `json:"allow_insecure_broker"`
		Routes              []egressdRoute `json:"routes"`
		CA                  *egressdCA     `json:"ca,omitempty"`
	}
	grants := AgentRunBrokerGrants(agentRun.Spec.Broker)
	routes := make([]egressdRoute, 0, len(grants))
	routeIndex := 0
	needCA := false
	for _, grant := range grants {
		if AgentRunGrantMaterialization(grant) != nvtv1alpha1.AgentRunGrantHeaderInject {
			continue
		}
		if len(grant.EgressHosts) == 0 {
			return "", fmt.Errorf("broker grant %s egressHosts is required for mediated egress", grant.Provider)
		}
		route := egressdRoute{
			Listen:                fmt.Sprintf("127.0.0.1:%d", 8471+routeIndex),
			Capability:            grant.Provider,
			Upstream:              grant.EgressHosts[0],
			AllowInsecureUpstream: false,
		}
		if grant.Git {
			// git clients require an https base URL; the route terminates
			// TLS with a leaf signed by the boot-generated per-agent CA.
			route.ListenTLS = "ca"
			needCA = true
		}
		routes = append(routes, route)
		routeIndex++
	}
	config := egressdConfig{
		BrokerURL:           brokerURL,
		AllowInsecureBroker: agentRun.Spec.EgressAllowInsecureBroker,
		Routes:              routes,
	}
	if needCA {
		config.CA = &egressdCA{PublishDir: egressCAMountPath}
	}
	rendered, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", fmt.Errorf("render egressd config: %w", err)
	}
	return string(rendered) + "\n", nil
}

// DesiredAgentPod returns the create-once Pod spec for an AgentRun.
func DesiredAgentPod(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme) (*corev1.Pod, error) {
	runtimeAuthMountPath, err := RuntimeAuthMountPath(agentRun)
	if err != nil {
		return nil, err
	}

	agentVolumeMounts := []corev1.VolumeMount{
		{Name: "workspace", MountPath: workspaceMountPath},
		{Name: "agent-config", MountPath: agentConfigVolumeDir, ReadOnly: true},
	}
	volumes := []corev1.Volume{
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
	}
	hasGitGrant := agentRunHasGitGrant(agentRun)
	if AgentRunEgressMode(agentRun) == nvtv1alpha1.AgentRunEgressMediated {
		volumes = append(volumes, corev1.Volume{
			Name: "egressd-config",
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
			// Shared emptyDir carrying only ca.crt: egressd publishes the
			// CA certificate into it; the agent mounts it read-only. The CA
			// private key never touches this volume — it lives only in
			// egressd process memory.
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
	if agentRun.Spec.RuntimeAuth != nil {
		initContainers = append(initContainers, corev1.Container{
			Name:    "runtime-auth-copy",
			Image:   "docker:27-dind",
			Command: []string{"sh", "-c"},
			Args: []string{
				"cp -a " + runtimeAuthSourcePath + "/. " + runtimeAuthHomePath + "/ && chmod -R u+rwX " + runtimeAuthHomePath,
			},
			VolumeMounts: []corev1.VolumeMount{
				{Name: runtimeAuthSourceName, MountPath: runtimeAuthSourcePath, ReadOnly: true},
				{Name: runtimeAuthHomeName, MountPath: runtimeAuthHomePath},
			},
		})
	}
	initContainers = append(initContainers, corev1.Container{
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
	})

	containers := []corev1.Container{
		{
			Name:            "agent",
			Image:           agentRun.Spec.Image,
			ImagePullPolicy: corev1.PullIfNotPresent,
			WorkingDir:      workspaceMountPath,
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
			VolumeMounts: agentVolumeMounts,
		},
	}
	if AgentRunEgressMode(agentRun) == nvtv1alpha1.AgentRunEgressMediated {
		containers[0].Env = append(containers[0].Env, corev1.EnvVar{Name: "NVT_EGRESS_MODE", Value: string(nvtv1alpha1.AgentRunEgressMediated)})
		if hasGitGrant {
			containers[0].Env = append(containers[0].Env, corev1.EnvVar{Name: "NVT_EGRESS_CA_FILE", Value: egressCAFilePath})
		}
	}
	if AgentRunEgressMode(agentRun) == nvtv1alpha1.AgentRunEgressMediated {
		egressdVolumeMounts := []corev1.VolumeMount{
			{Name: "egressd-config", MountPath: egressdConfigPath, SubPath: egressdConfigKey, ReadOnly: true},
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
				{Name: "NVT_BROKER_URL", Value: brokerURL},
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

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      AgentPodName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    agentRunLabels(agentRun.Name),
		},
		Spec: corev1.PodSpec{
			RuntimeClassName: agentRun.Spec.RuntimeClassName,
			RestartPolicy:    corev1.RestartPolicyNever,
			InitContainers:   initContainers,
			Containers:       containers,
			Volumes:          volumes,
		},
	}
	if err := controllerutil.SetControllerReference(agentRun, pod, scheme); err != nil {
		return nil, fmt.Errorf("set AgentRun Pod owner: %w", err)
	}

	return pod, nil
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
		return "/root/.codex", nil
	case "claude":
		return "/root/.claude", nil
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

// AgentRunBrokerID returns the broker identity for an AgentRun.
func AgentRunBrokerID(namespace, name string) string {
	return namespace + "/" + name
}

func AgentRunEgressBrokerID(namespace, name string) string {
	return namespace + "/" + name + "-egress"
}

func AgentRunEgressMode(agentRun *nvtv1alpha1.AgentRun) nvtv1alpha1.AgentRunEgressMode {
	if agentRun.Spec.Egress == "" {
		return nvtv1alpha1.AgentRunEgressDirect
	}
	return agentRun.Spec.Egress
}

func AgentRunBrokerGrants(broker *nvtv1alpha1.AgentRunBroker) []nvtv1alpha1.AgentRunBrokerGrant {
	if broker == nil || broker.Grants == nil {
		return []nvtv1alpha1.AgentRunBrokerGrant{}
	}
	return broker.Grants
}

func AgentRunGrantMaterialization(grant nvtv1alpha1.AgentRunBrokerGrant) nvtv1alpha1.AgentRunGrantMaterialization {
	if grant.Materialization == "" {
		return nvtv1alpha1.AgentRunGrantFileBundle
	}
	return grant.Materialization
}

func ValidateAgentRunEgressMode(agentRun *nvtv1alpha1.AgentRun) error {
	mode := AgentRunEgressMode(agentRun)
	if mode != nvtv1alpha1.AgentRunEgressDirect && mode != nvtv1alpha1.AgentRunEgressMediated {
		return fmt.Errorf("spec.egress must be direct or mediated, got %q", mode)
	}
	headerInjectGrants := 0
	if mode == nvtv1alpha1.AgentRunEgressMediated {
		if agentRun.Spec.RuntimeAuth != nil {
			return fmt.Errorf("egress mediated is incompatible with spec.runtimeAuth")
		}
		if strings.HasPrefix(brokerURL, "http://") && !agentRun.Spec.EgressAllowInsecureBroker {
			return fmt.Errorf("egress mediated with plaintext broker requires spec.egressAllowInsecureBroker=true for local/dev use")
		}
	}
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		materialization := AgentRunGrantMaterialization(grant)
		switch materialization {
		case nvtv1alpha1.AgentRunGrantFileBundle, nvtv1alpha1.AgentRunGrantHeaderInject:
		default:
			return fmt.Errorf("broker grant %s materialization must be file-bundle or header-inject, got %q", grant.Provider, materialization)
		}
		if mode == nvtv1alpha1.AgentRunEgressDirect && materialization == nvtv1alpha1.AgentRunGrantHeaderInject {
			return fmt.Errorf("egress direct is incompatible with broker grant %s materialization header-inject", grant.Provider)
		}
		if mode == nvtv1alpha1.AgentRunEgressMediated && materialization == nvtv1alpha1.AgentRunGrantFileBundle {
			return fmt.Errorf("egress mediated is incompatible with broker grant %s materialization file-bundle", grant.Provider)
		}
		if grant.Git && materialization != nvtv1alpha1.AgentRunGrantHeaderInject {
			return fmt.Errorf("broker grant %s git requires materialization header-inject", grant.Provider)
		}
		for key, value := range grant.Permissions {
			if key == "" || (value != "read" && value != "write") {
				return fmt.Errorf("broker grant %s permissions must map permission names to read or write", grant.Provider)
			}
		}
		if mode == nvtv1alpha1.AgentRunEgressMediated && materialization == nvtv1alpha1.AgentRunGrantHeaderInject {
			headerInjectGrants++
			if len(grant.EgressHosts) == 0 {
				return fmt.Errorf("egress mediated broker grant %s requires egressHosts", grant.Provider)
			}
			for _, host := range grant.EgressHosts {
				if !validEgressHost(host) {
					return fmt.Errorf("egress mediated broker grant %s has invalid egressHosts entry %q", grant.Provider, host)
				}
			}
		}
	}
	if mode == nvtv1alpha1.AgentRunEgressMediated && headerInjectGrants == 0 {
		return fmt.Errorf("egress mediated requires at least one header-inject broker grant with egressHosts")
	}
	return nil
}

// agentRunHasGitGrant reports whether any header-inject grant is git-typed,
// which requires the per-agent CA volume and a TLS route.
func agentRunHasGitGrant(agentRun *nvtv1alpha1.AgentRun) bool {
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		if grant.Git && AgentRunGrantMaterialization(grant) == nvtv1alpha1.AgentRunGrantHeaderInject {
			return true
		}
	}
	return false
}

func validEgressHost(value string) bool {
	if value == "" || strings.Contains(value, "://") || strings.Contains(value, "/") || strings.Contains(value, "@") {
		return false
	}
	host := value
	if before, after, ok := strings.Cut(value, ":"); ok {
		if before == "" || after == "" {
			return false
		}
		host = before
	}
	return strings.TrimSpace(host) == host && host != "" && !strings.HasPrefix(host, ".") && !strings.HasSuffix(host, ".")
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
		var permissions map[string]string
		if len(grant.Permissions) > 0 {
			permissions = make(map[string]string, len(grant.Permissions))
			for key, value := range grant.Permissions {
				permissions[key] = value
			}
		}
		grants = append(grants, brokerAgentGrantEntry{
			Provider:        grant.Provider,
			Repositories:    repositories,
			Materialization: string(AgentRunGrantMaterialization(grant)),
			EgressHosts:     append([]string{}, grant.EgressHosts...),
			Permissions:     permissions,
		})
	}
	sort.SliceStable(grants, func(i, j int) bool {
		if grants[i].Provider != grants[j].Provider {
			return grants[i].Provider < grants[j].Provider
		}
		if grants[i].Materialization != grants[j].Materialization {
			return grants[i].Materialization < grants[j].Materialization
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
	pairedAgents := map[string]string{}
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
		switch agent.Role {
		case "", "agent":
			if agent.PairedAgent != "" {
				return fmt.Errorf("agents[%d].paired-agent is valid only for egress identities", agentIndex)
			}
		case "egress":
			if agent.PairedAgent == "" {
				return fmt.Errorf("agents[%d].paired-agent is required for egress identities", agentIndex)
			}
			if existingEgress, exists := pairedAgents[agent.PairedAgent]; exists {
				return fmt.Errorf("agents[%d].paired-agent duplicates egress identity %s", agentIndex, existingEgress)
			}
			pairedAgents[agent.PairedAgent] = agent.ID
			if len(agent.Grants) != 0 {
				return fmt.Errorf("agents[%d].grants must be empty for egress identities", agentIndex)
			}
		default:
			return fmt.Errorf("agents[%d].role must be agent or egress", agentIndex)
		}
		for grantIndex, grant := range agent.Grants {
			if grant.Provider == "" {
				return fmt.Errorf("agents[%d].grants[%d].provider is required", agentIndex, grantIndex)
			}
			switch grant.Materialization {
			case "", string(nvtv1alpha1.AgentRunGrantFileBundle), string(nvtv1alpha1.AgentRunGrantHeaderInject):
			default:
				return fmt.Errorf("agents[%d].grants[%d].materialization must be file-bundle or header-inject", agentIndex, grantIndex)
			}
			for repoIndex, repository := range grant.Repositories {
				if repository == "" {
					return fmt.Errorf("agents[%d].grants[%d].repositories[%d] must be a non-empty string", agentIndex, grantIndex, repoIndex)
				}
			}
			for hostIndex, host := range grant.EgressHosts {
				if !validEgressHost(host) {
					return fmt.Errorf("agents[%d].grants[%d].egress-hosts[%d] must be a host or host:port, got %q", agentIndex, grantIndex, hostIndex, host)
				}
			}
			for key, value := range grant.Permissions {
				if key == "" || (value != "read" && value != "write") {
					return fmt.Errorf("agents[%d].grants[%d].permissions must map permission names to read or write", agentIndex, grantIndex)
				}
			}
		}
	}
	for pairedAgent, egressID := range pairedAgents {
		if _, exists := seenIDs[pairedAgent]; !exists {
			return fmt.Errorf("egress identity %s paired-agent %s does not exist", egressID, pairedAgent)
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
		if entry.Grants[i].EgressHosts == nil {
			entry.Grants[i].EgressHosts = []string{}
		}
		if entry.Grants[i].Materialization == "" {
			entry.Grants[i].Materialization = string(nvtv1alpha1.AgentRunGrantFileBundle)
		}
	}
	sort.SliceStable(entry.Grants, func(i, j int) bool {
		if entry.Grants[i].Provider != entry.Grants[j].Provider {
			return entry.Grants[i].Provider < entry.Grants[j].Provider
		}
		if entry.Grants[i].Materialization != entry.Grants[j].Materialization {
			return entry.Grants[i].Materialization < entry.Grants[j].Materialization
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

	if promptText := AgentRunPromptText(agentRun); promptText != "" || AgentRunEgressMode(agentRun) == nvtv1alpha1.AgentRunEgressMediated {
		config := map[string]any{}
		if err := yaml.Unmarshal(rawConfig, &config); err != nil {
			return "", fmt.Errorf("render AgentRun agent config: %w", err)
		}
		renderedConfig := config
		if promptText != "" {
			var err error
			renderedConfig, err = InjectInitialPromptPlugin(renderedConfig, promptText)
			if err != nil {
				return "", err
			}
		}
		if AgentRunEgressMode(agentRun) == nvtv1alpha1.AgentRunEgressMediated {
			renderedConfig = InjectMediatedEgressConfig(renderedConfig, agentRun)
		}
		rendered, err := yaml.Marshal(renderedConfig)
		if err != nil {
			return "", fmt.Errorf("render AgentRun agent config: %w", err)
		}
		return string(rendered), nil
	}

	rendered, err := yaml.JSONToYAML(rawConfig)
	if err != nil {
		return "", fmt.Errorf("render AgentRun agent config: %w", err)
	}

	return string(rendered), nil
}

func InjectMediatedEgressConfig(config map[string]any, agentRun *nvtv1alpha1.AgentRun) map[string]any {
	grants := []any{}
	routeIndex := 0
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		if AgentRunGrantMaterialization(grant) != nvtv1alpha1.AgentRunGrantHeaderInject {
			continue
		}
		scheme := "http"
		if grant.Git {
			scheme = "https"
		}
		grants = append(grants, map[string]any{
			"provider":        grant.Provider,
			"materialization": string(nvtv1alpha1.AgentRunGrantHeaderInject),
			"base-url":        fmt.Sprintf("%s://127.0.0.1:%d", scheme, 8471+routeIndex),
		})
		routeIndex++
	}
	updated := cloneStringAnyMap(config)
	updated["egress"] = map[string]any{
		"mode":        string(nvtv1alpha1.AgentRunEgressMediated),
		"placeholder": "NVT-PLACEHOLDER-NOT-A-KEY",
		"grants":      grants,
	}
	return updated
}

// AgentRunPromptText returns the configured prompt text when present and non-empty.
func AgentRunPromptText(agentRun *nvtv1alpha1.AgentRun) string {
	if agentRun.Spec.Prompt == nil {
		return ""
	}
	return agentRun.Spec.Prompt.Text
}

// InjectInitialPromptPlugin prepends the runtime plugin that delivers AgentRun prompt text.
func InjectInitialPromptPlugin(config map[string]any, promptText string) (map[string]any, error) {
	plugins, err := agentConfigPlugins(config)
	if err != nil {
		return nil, err
	}
	for _, plugin := range plugins {
		pluginMap, ok := plugin.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("render AgentRun agent config: plugins entries must be objects")
		}
		if pluginMap["name"] == initialPromptPlugin {
			return nil, fmt.Errorf("render AgentRun agent config: spec.prompt.text cannot be used when spec.agent.config.plugins already contains plugin %q", initialPromptPlugin)
		}
	}

	injected := map[string]any{
		"name":    initialPromptPlugin,
		"source":  "builtin",
		"when":    "after-agent",
		"restart": "never",
		"config": map[string]any{
			"text": promptText,
		},
	}
	updatedConfig := cloneStringAnyMap(config)
	updatedConfig["plugins"] = append([]any{injected}, plugins...)
	return updatedConfig, nil
}

func agentConfigPlugins(config map[string]any) ([]any, error) {
	rawPlugins, ok := config["plugins"]
	if !ok || rawPlugins == nil {
		return nil, nil
	}
	plugins, ok := rawPlugins.([]any)
	if !ok {
		return nil, fmt.Errorf("render AgentRun agent config: plugins must be a list")
	}
	return plugins, nil
}

func cloneStringAnyMap(input map[string]any) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

// InitializeAgentRunStatus sets the initial phase when a run has no observed phase yet.
func InitializeAgentRunStatus(agentRun *nvtv1alpha1.AgentRun) bool {
	if agentRun.Status.Phase != "" {
		return false
	}

	agentRun.Status.Phase = nvtv1alpha1.AgentRunPhasePending
	return true
}

// IsTerminalAgentRunPhase reports whether the phase must not be overwritten by non-terminal sync paths.
func IsTerminalAgentRunPhase(phase nvtv1alpha1.AgentRunPhase) bool {
	switch phase {
	case nvtv1alpha1.AgentRunPhaseCompleted, nvtv1alpha1.AgentRunPhaseFailed, nvtv1alpha1.AgentRunPhaseDeadlineExceeded:
		return true
	default:
		return false
	}
}

// TerminalPodCleanupDelay returns the remaining TTL and whether the owned Pod should be deleted now.
func TerminalPodCleanupDelay(agentRun *nvtv1alpha1.AgentRun, now metav1.Time) (time.Duration, bool) {
	if agentRun.Status.FinishedAt == nil || agentRun.Spec.TTL == nil {
		return 0, false
	}

	var ttlSeconds *int64
	switch agentRun.Status.Phase {
	case nvtv1alpha1.AgentRunPhaseCompleted:
		ttlSeconds = agentRun.Spec.TTL.CompletedTTLSeconds
	case nvtv1alpha1.AgentRunPhaseFailed:
		ttlSeconds = agentRun.Spec.TTL.FailedTTLSeconds
	default:
		return 0, false
	}
	if ttlSeconds == nil {
		return 0, false
	}

	deleteAt := agentRun.Status.FinishedAt.Add(time.Duration(*ttlSeconds) * time.Second)
	remaining := deleteAt.Sub(now.Time)
	if remaining > 0 {
		return remaining, false
	}
	return 0, true
}

// RunRetentionDelay returns the remaining AgentRun CR retention and whether it should be deleted now.
func RunRetentionDelay(agentRun *nvtv1alpha1.AgentRun, now metav1.Time) (time.Duration, bool) {
	if !IsTerminalAgentRunPhase(agentRun.Status.Phase) || agentRun.Status.FinishedAt == nil {
		return 0, false
	}

	ttlSeconds := int64(defaultRunRetentionSeconds)
	if agentRun.Spec.TTL != nil && agentRun.Spec.TTL.RunRetentionSeconds != nil {
		ttlSeconds = *agentRun.Spec.TTL.RunRetentionSeconds
	}
	if ttlSeconds == 0 {
		return 0, false
	}

	deleteAt := agentRun.Status.FinishedAt.Add(time.Duration(ttlSeconds) * time.Second)
	remaining := deleteAt.Sub(now.Time)
	if remaining > 0 {
		return remaining, false
	}
	return 0, true
}

// ActiveDeadlineDelay returns the remaining active deadline and whether the run has exceeded it.
func ActiveDeadlineDelay(agentRun *nvtv1alpha1.AgentRun, now metav1.Time) (time.Duration, bool) {
	if IsTerminalAgentRunPhase(agentRun.Status.Phase) ||
		agentRun.Spec.TTL == nil ||
		agentRun.Spec.TTL.ActiveDeadlineSeconds == nil ||
		agentRun.Status.StartedAt == nil {
		return 0, false
	}

	deadlineAt := agentRun.Status.StartedAt.Time.Add(time.Duration(*agentRun.Spec.TTL.ActiveDeadlineSeconds) * time.Second)
	remaining := deadlineAt.Sub(now.Time)
	if remaining > 0 {
		return remaining, false
	}
	return 0, true
}

// SyncAgentRunStatusFromPod reflects the small Pod-phase status surface owned by this controller slice.
func SyncAgentRunStatusFromPod(agentRun *nvtv1alpha1.AgentRun, pod *corev1.Pod, now metav1.Time) bool {
	if pod == nil {
		return false
	}

	changed := false
	if agentRun.Status.PodName != pod.Name {
		agentRun.Status.PodName = pod.Name
		changed = true
	}
	if IsTerminalAgentRunPhase(agentRun.Status.Phase) {
		return changed
	}

	switch pod.Status.Phase {
	case corev1.PodRunning:
		if agentRun.Status.Phase != nvtv1alpha1.AgentRunPhaseRunning {
			agentRun.Status.Phase = nvtv1alpha1.AgentRunPhaseRunning
			changed = true
		}
		if agentRun.Status.StartedAt == nil {
			agentRun.Status.StartedAt = &now
			changed = true
		}
	case corev1.PodFailed:
		if agentRun.Status.Phase != nvtv1alpha1.AgentRunPhaseFailed {
			agentRun.Status.Phase = nvtv1alpha1.AgentRunPhaseFailed
			changed = true
		}
		if agentRun.Status.FinishedAt == nil {
			agentRun.Status.FinishedAt = &now
			changed = true
		}
		if agentRun.Status.Reason == "" {
			agentRun.Status.Reason = "Pod failed"
			changed = true
		}
	}

	return changed
}

func ptrTo[T any](value T) *T {
	return &value
}
