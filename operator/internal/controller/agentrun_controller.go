package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path"
	"reflect"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
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
	egressCASecretVolume  = "egress-ca-keypair"
	egressCASecretMount   = "/etc/nvt-egressd/egress-ca"
	egressCASecretCert    = egressCASecretMount + "/ca.crt"
	egressCASecretKeyFile = egressCASecretMount + "/ca.key"
	workspaceMountPath    = "/workspace"
	initialPromptPlugin   = "initial-prompt"

	// Non-root runtime user (opt-in via spec.runtime.user: non-root). The
	// image ships an `agent` user at this uid/gid with HOME=agentNonRootHome.
	agentNonRootUID  int64 = 1000
	agentNonRootGID  int64 = 1000
	agentNonRootHome       = "/home/agent"

	defaultBrokerURL = "http://nvt-broker:7347"
	// brokerCAVolumeName carries the broker's CA certificate (public) into
	// the egressd and agent containers so both can verify the TLS broker leg.
	// Only the ca.crt item is projected from the TLS Secret — the serving key
	// never enters the agent Pod.
	brokerCAVolumeName   = "broker-ca"
	brokerCAKey          = "ca.crt"
	egressdBrokerCAMount = "/etc/nvt-egressd/broker-ca"
	egressdBrokerCAFile  = egressdBrokerCAMount + "/" + brokerCAKey
	agentBrokerCAMount   = "/etc/nvt-broker-ca"
	agentBrokerCAFile    = agentBrokerCAMount + "/" + brokerCAKey
	// Enforcement mode (docs/phase5-6a-enforcement-pr-plan.md): egressd runs
	// in its own Pod behind a per-run Service. The operator owns a durable
	// per-run CA Secret mounted only into egressd and publishes ca.crt only to
	// the agent ConfigMap.
	agentRunLabelKey       = "nvt.dev/agentrun"
	roleLabelKey           = "nvt.dev/role"
	roleLabelAgent         = "agent"
	roleLabelEgressd       = "egressd"
	egressCAPort           = 8470
	egressRouteBasePort    = 8471
	egressForwardProxyPort = 8473 // forward-proxy CONNECT listener (own-Pod)
	egressCACertKey        = "ca.crt"
	egressCAKeyKey         = "ca.key"
	egressdConfigName      = "egressd-config"
	egressdReadyRequeue    = 2 * time.Second

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

// Enforcement-mode status conditions, in machine order. The agent Pod is
// never created before ConditionBrokerPolicyReady and
// ConditionEgressCAPublished both hold.
const (
	ConditionBrokerPolicyReady = "BrokerPolicyReady"
	ConditionEgressdCreated    = "EgressdCreated"
	ConditionEgressdReady      = "EgressdReady"
	ConditionEgressCAPublished = "EgressCAPublished"
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
	Quota           *brokerAgentQuota `json:"quota,omitempty"`
}

type brokerAgentQuota struct {
	Requests int `json:"requests"`
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
	existingPod, err := r.getOwnedAgentPod(ctx, &agentRun)
	if err != nil {
		return ctrl.Result{}, err
	}
	if existingPod == nil {
		// Egress/TLS validation applies at creation time only: operator
		// broker env changes must not retroactively fail runs whose Pod
		// already exists with the old wiring.
		if err := ValidateAgentRunEgressMode(&agentRun); err != nil {
			if setErr := r.setAgentRunFailed(ctx, &agentRun, err.Error()); setErr != nil {
				return ctrl.Result{}, setErr
			}
			return ctrl.Result{}, nil
		}
		if err := r.validateBrokerCASecret(ctx, &agentRun); err != nil {
			return ctrl.Result{}, err
		}
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
	enforced := AgentRunEgressEnforced(&agentRun)
	if enforced && existingPod != nil {
		if err := r.repairOwnedPodLabels(ctx, existingPod, enforcementLabels(agentRun.Name, roleLabelAgent)); err != nil {
			return ctrl.Result{}, err
		}
	}
	var existingEgressdPod *corev1.Pod
	if enforced {
		existingEgressdPod, err = r.getOwnedEgressdPod(ctx, &agentRun)
		if err != nil {
			return ctrl.Result{}, err
		}
	}
	configFrozen := existingPod != nil || (enforced && existingEgressdPod != nil)
	if err := r.reconcileEgressdConfigMap(ctx, &agentRun, configFrozen); err != nil {
		return ctrl.Result{}, err
	}
	conditionsChanged := false
	if enforced {
		// Own-Pod egressd is created before (never behind) the broker
		// policy: egressd is broker-independent at startup — it fetches
		// injectable material lazily and fail-closed on the first proxied
		// request, and CA generation needs no broker at all.
		if err := r.reconcileEgressCASecret(ctx, &agentRun); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.reconcileNetworkPolicies(ctx, &agentRun); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.reconcileEgressdPod(ctx, &agentRun); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.reconcileEgressdService(ctx, &agentRun); err != nil {
			return ctrl.Result{}, err
		}
		if r.setRunCondition(&agentRun, ConditionEgressdCreated, metav1.ConditionTrue, "EgressdCreated", "egressd Pod and Service exist") {
			conditionsChanged = true
		}
	}
	if err := r.reconcileBrokerAgentsPolicy(ctx, &agentRun); err != nil {
		return ctrl.Result{}, err
	}
	if enforced {
		// This condition gates the agent Pod, not egressd; the #62 bootstrap
		// retry still absorbs the broker ConfigMap projection lag agent-side.
		if r.setRunCondition(&agentRun, ConditionBrokerPolicyReady, metav1.ConditionTrue, "BrokerPolicyReady", "broker agents policy reconciled") {
			conditionsChanged = true
		}
	}
	if enforced && existingPod == nil {
		result, proceed, changed, gateErr := r.reconcileEnforcementGates(ctx, &agentRun)
		conditionsChanged = conditionsChanged || changed
		if gateErr != nil || !proceed {
			if conditionsChanged {
				if statusErr := r.Status().Update(ctx, &agentRun); statusErr != nil {
					return ctrl.Result{}, fmt.Errorf("update AgentRun status: %w", statusErr)
				}
			}
			return result, gateErr
		}
	}

	pod := existingPod
	if pod == nil {
		if enforced && !enforcementAgentPodGatesHold(&agentRun) {
			// Belt-and-braces: no reconcile path may create the agent Pod
			// before BrokerPolicyReady and EgressCAPublished both hold.
			return ctrl.Result{}, fmt.Errorf("refusing to create agent Pod before BrokerPolicyReady and EgressCAPublished hold")
		}
		pod, err = r.createAgentPod(ctx, &agentRun)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	statusChanged := conditionsChanged
	if InitializeAgentRunStatus(&agentRun) {
		statusChanged = true
	}
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
		Owns(&corev1.Service{}).
		Owns(&networkingv1.NetworkPolicy{}).
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
	if err := r.deleteOwnedPodByName(ctx, agentRun, AgentPodName(agentRun.Name), description); err != nil {
		return err
	}
	if AgentRunEgressEnforced(agentRun) {
		// The paired egressd Pod has no purpose past the run; the remaining
		// enforcement objects are garbage-collected with the AgentRun.
		return r.deleteOwnedPodByName(ctx, agentRun, EgressdPodName(agentRun.Name), description+" (egressd)")
	}
	return nil
}

func (r *AgentRunReconciler) deleteOwnedPodByName(ctx context.Context, agentRun *nvtv1alpha1.AgentRun, name, description string) error {
	pod := &corev1.Pod{}
	key := client.ObjectKey{Namespace: agentRun.Namespace, Name: name}
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

func (r *AgentRunReconciler) reconcileEgressdConfigMap(ctx context.Context, agentRun *nvtv1alpha1.AgentRun, podExists bool) error {
	if AgentRunEgressMode(agentRun) != nvtv1alpha1.AgentRunEgressMediated {
		return nil
	}
	configMap := &corev1.ConfigMap{}
	err := r.Get(ctx, client.ObjectKey{Namespace: agentRun.Namespace, Name: EgressdConfigMapName(agentRun.Name)}, configMap)
	if err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("get AgentRun egressd config ConfigMap: %w", err)
	}
	if err == nil && podExists {
		// Never rewrite egressd config under an existing Pod: the Pod's
		// mounts were rendered against this config, and operator broker env
		// changes must not retarget a running run.
		if !metav1.IsControlledBy(configMap, agentRun) {
			return fmt.Errorf("AgentRun egressd config ConfigMap %s/%s exists but is not controlled by AgentRun %s", configMap.Namespace, configMap.Name, agentRun.Name)
		}
		return nil
	}
	desired, err2 := DesiredEgressdConfigMap(agentRun, r.Scheme)
	if err2 != nil {
		return err2
	}
	if err != nil {
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

// createAgentPod renders and creates the AgentRun Pod; the caller has already
// established that no Pod exists.
func (r *AgentRunReconciler) createAgentPod(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) (*corev1.Pod, error) {
	// Pods are create-once for this slice because most spec fields are immutable.
	// A future replacement policy can decide how to handle spec changes.
	desired, err := DesiredAgentPod(agentRun, r.Scheme)
	if err != nil {
		return nil, err
	}
	if createErr := r.Create(ctx, desired); createErr != nil {
		return nil, fmt.Errorf("create AgentRun Pod: %w", createErr)
	}
	return desired, nil
}

// getOwnedAgentPod returns the AgentRun's Pod, nil when it does not exist yet.
func (r *AgentRunReconciler) getOwnedAgentPod(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) (*corev1.Pod, error) {
	pod := &corev1.Pod{}
	key := client.ObjectKey{Namespace: agentRun.Namespace, Name: AgentPodName(agentRun.Name)}
	if err := r.Get(ctx, key, pod); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get AgentRun Pod: %w", err)
	}
	if !metav1.IsControlledBy(pod, agentRun) {
		return nil, fmt.Errorf("AgentRun Pod %s/%s exists but is not controlled by AgentRun %s", pod.Namespace, pod.Name, agentRun.Name)
	}
	return pod, nil
}

func (r *AgentRunReconciler) getOwnedEgressdPod(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) (*corev1.Pod, error) {
	pod := &corev1.Pod{}
	key := client.ObjectKey{Namespace: agentRun.Namespace, Name: EgressdPodName(agentRun.Name)}
	if err := r.Get(ctx, key, pod); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get egressd Pod: %w", err)
	}
	if !metav1.IsControlledBy(pod, agentRun) {
		return nil, fmt.Errorf("egressd Pod %s/%s exists but is not controlled by AgentRun %s", pod.Namespace, pod.Name, agentRun.Name)
	}
	return pod, nil
}

func (r *AgentRunReconciler) repairOwnedPodLabels(ctx context.Context, pod *corev1.Pod, required map[string]string) error {
	changed := false
	if pod.Labels == nil {
		pod.Labels = map[string]string{}
		changed = true
	}
	for key, value := range required {
		if pod.Labels[key] != value {
			pod.Labels[key] = value
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := r.Update(ctx, pod); err != nil {
		return fmt.Errorf("repair Pod %s/%s labels: %w", pod.Namespace, pod.Name, err)
	}
	return nil
}

// validateBrokerCASecret ensures the configured broker CA Secret exists in
// the AgentRun namespace and carries ca.crt before any Pod mounts it: the
// Pod projects ca.crt non-optionally, so a bring-your-own TLS Secret without
// that key would wedge every agent Pod in FailedMount.
func (r *AgentRunReconciler) validateBrokerCASecret(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) error {
	if !brokerCADistributed() {
		return nil
	}
	name := BrokerCASecretName()
	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: agentRun.Namespace, Name: name}, secret); err != nil {
		if errors.IsNotFound(err) {
			return fmt.Errorf("broker CA Secret %s/%s not found: broker TLS requires a Secret carrying the CA certificate under key %s", agentRun.Namespace, name, brokerCAKey)
		}
		return fmt.Errorf("get broker CA Secret %s/%s: %w", agentRun.Namespace, name, err)
	}
	if len(secret.Data[brokerCAKey]) == 0 {
		return fmt.Errorf("broker CA Secret %s/%s is missing key %s: bring-your-own broker TLS Secrets must include the CA certificate", agentRun.Namespace, name, brokerCAKey)
	}
	return nil
}

// AgentRunEgressEnforced reports whether the run opted into network-enforced
// egress (own-Pod egressd + NetworkPolicies). Validation guarantees this
// implies mediated mode.
func AgentRunEgressEnforced(agentRun *nvtv1alpha1.AgentRun) bool {
	return agentRun.Spec.EgressEnforcement && AgentRunEgressMode(agentRun) == nvtv1alpha1.AgentRunEgressMediated
}

// AgentRunEgressForwardProxy reports whether the run uses forward-proxy mode.
// Validation guarantees this implies mediated + enforced egress.
func AgentRunEgressForwardProxy(agentRun *nvtv1alpha1.AgentRun) bool {
	return agentRun.Spec.EgressForwardProxy && AgentRunEgressEnforced(agentRun)
}

// forwardProxyInjectHosts returns the (host, capability) pairs egressd MITMs
// for a forward-proxy run: every egressHost of every injection-capable grant.
type forwardProxyInject struct {
	Host                  string
	Capability            string
	Upstream              string
	AllowInsecureUpstream bool
	MaxRequests           int
	RequireCapabilityHint bool
}

func forwardProxyInjects(agentRun *nvtv1alpha1.AgentRun) []forwardProxyInject {
	injects := []forwardProxyInject{}
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		materialization := AgentRunGrantMaterialization(grant)
		if materialization != nvtv1alpha1.AgentRunGrantHeaderInject && materialization != nvtv1alpha1.AgentRunGrantPlaceholderFile {
			continue
		}
		for _, upstream := range grant.EgressHosts {
			host := upstream
			if h, _, err := net.SplitHostPort(upstream); err == nil {
				host = h
			}
			maxRequests := 0
			if grant.Quota != nil {
				maxRequests = grant.Quota.Requests
			}
			injects = append(injects, forwardProxyInject{
				Host:                  host,
				Capability:            grant.Provider,
				Upstream:              upstream,
				AllowInsecureUpstream: grant.AllowInsecureUpstream,
				MaxRequests:           maxRequests,
				RequireCapabilityHint: grant.Git,
			})
		}
	}
	return injects
}

// forwardProxyUpstreamHosts is the set of MITM leaf names the CA must permit.
func forwardProxyUpstreamHosts(agentRun *nvtv1alpha1.AgentRun) []string {
	seen := map[string]bool{}
	hosts := []string{}
	for _, inject := range forwardProxyInjects(agentRun) {
		if !seen[inject.Host] {
			seen[inject.Host] = true
			hosts = append(hosts, inject.Host)
		}
	}
	return hosts
}

// forwardProxyEnv points the agent's proxy env at egressd and computes NO_PROXY.
// NO_PROXY is operator-rendered, never hand-authored, so a missed entry can't
// silently route infra (broker, callback, DNS) through the MITM.
func forwardProxyEnv(agentRun *nvtv1alpha1.AgentRun) []corev1.EnvVar {
	proxyURL := fmt.Sprintf("http://%s:%d", EgressdServiceName(agentRun.Name), egressForwardProxyPort)
	noProxy := forwardProxyNoProxy(agentRun)
	env := []corev1.EnvVar{}
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		env = append(env, corev1.EnvVar{Name: name, Value: proxyURL})
	}
	for _, name := range []string{"NO_PROXY", "no_proxy"} {
		env = append(env, corev1.EnvVar{Name: name, Value: noProxy})
	}
	return env
}

func forwardProxyNoProxy(agentRun *nvtv1alpha1.AgentRun) string {
	hosts := []string{
		"localhost", "127.0.0.1", "::1",
		"kubernetes.default.svc",
		".svc", ".svc.cluster.local", ".cluster.local",
		EgressdServiceName(agentRun.Name),
		"nvt-operator",
	}
	if parsed, err := url.Parse(BrokerURL()); err == nil && parsed.Hostname() != "" {
		hosts = append(hosts, parsed.Hostname())
	}
	return strings.Join(hosts, ",")
}

// EgressdPodName returns the own-Pod egressd Pod name for an AgentRun.
func EgressdPodName(agentRunName string) string {
	return agentRunName + "-egressd"
}

// EgressdServiceName returns the per-run egressd Service name.
func EgressdServiceName(agentRunName string) string {
	return agentRunName + "-egressd"
}

// EgressCAConfigMapName returns the operator-published CA ConfigMap name.
func EgressCAConfigMapName(agentRunName string) string {
	return agentRunName + "-egress-ca"
}

// EgressCASecretName returns the private per-run CA Secret mounted only into egressd.
func EgressCASecretName(agentRunName string) string {
	return agentRunName + "-egress-ca-keypair"
}

// enforcementLabels extends the run labels with the pairing selectors the
// NetworkPolicies match on.
func enforcementLabels(agentRunName, role string) map[string]string {
	labels := agentRunLabels(agentRunName)
	labels[roleLabelKey] = role
	return labels
}

// egressdLeafDNSNames are the synthetic Service names the per-agent CA may
// mint leafs for in own-Pod mode. Never upstream names — egressd refuses the
// overlap at config load.
func egressdLeafDNSNames(agentRun *nvtv1alpha1.AgentRun) []string {
	service := EgressdServiceName(agentRun.Name)
	return []string{
		service,
		service + "." + agentRun.Namespace,
		service + "." + agentRun.Namespace + ".svc",
	}
}

func headerInjectGrants(agentRun *nvtv1alpha1.AgentRun) []nvtv1alpha1.AgentRunBrokerGrant {
	grants := []nvtv1alpha1.AgentRunBrokerGrant{}
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		if AgentRunGrantMaterialization(grant) == nvtv1alpha1.AgentRunGrantHeaderInject {
			grants = append(grants, grant)
		}
	}
	return grants
}

func (r *AgentRunReconciler) setRunCondition(agentRun *nvtv1alpha1.AgentRun, conditionType string, status metav1.ConditionStatus, reason, message string) bool {
	return meta.SetStatusCondition(&agentRun.Status.Conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: agentRun.Generation,
	})
}

func enforcementAgentPodGatesHold(agentRun *nvtv1alpha1.AgentRun) bool {
	return meta.IsStatusConditionTrue(agentRun.Status.Conditions, ConditionBrokerPolicyReady) &&
		meta.IsStatusConditionTrue(agentRun.Status.Conditions, ConditionEgressCAPublished)
}

// reconcileEnforcementGates advances the own-Pod machine past egressd
// creation: wait for egressd Ready, then publish the validated Secret-backed
// CA. Returns proceed=true only when the agent Pod may be created this pass.
func (r *AgentRunReconciler) reconcileEnforcementGates(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) (ctrl.Result, bool, bool, error) {
	changed := false
	egressdPod := &corev1.Pod{}
	key := client.ObjectKey{Namespace: agentRun.Namespace, Name: EgressdPodName(agentRun.Name)}
	if err := r.Get(ctx, key, egressdPod); err != nil {
		return ctrl.Result{}, false, changed, fmt.Errorf("get egressd Pod: %w", err)
	}
	if !isPodReady(egressdPod) {
		changed = r.setRunCondition(agentRun, ConditionEgressdReady, metav1.ConditionFalse, "EgressdNotReady", "waiting for egressd Pod readiness (CA endpoint /healthz)") || changed
		return ctrl.Result{RequeueAfter: egressdReadyRequeue}, false, changed, nil
	}
	changed = r.setRunCondition(agentRun, ConditionEgressdReady, metav1.ConditionTrue, "EgressdReady", "egressd Pod is ready") || changed

	published, err := r.publishEgressCAConfigMap(ctx, agentRun)
	if err != nil {
		changed = r.setRunCondition(agentRun, ConditionEgressCAPublished, metav1.ConditionFalse, "CAPublishFailed", err.Error()) || changed
		return ctrl.Result{}, false, changed, err
	}
	if !published {
		return ctrl.Result{RequeueAfter: egressdReadyRequeue}, false, changed, nil
	}
	changed = r.setRunCondition(agentRun, ConditionEgressCAPublished, metav1.ConditionTrue, "EgressCAPublished", "CA certificate published to the per-run ConfigMap") || changed
	return ctrl.Result{}, true, changed, nil
}

func isPodReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

// publishEgressCAConfigMap publishes ca.crt from the operator-owned per-run CA
// Secret into the ConfigMap mounted by the agent. The private key stays only in
// the Secret mounted into egressd.
func (r *AgentRunReconciler) publishEgressCAConfigMap(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) (bool, error) {
	secret := &corev1.Secret{}
	secretKey := client.ObjectKey{Namespace: agentRun.Namespace, Name: EgressCASecretName(agentRun.Name)}
	if err := r.Get(ctx, secretKey, secret); err != nil {
		return false, fmt.Errorf("get egress CA Secret: %w", err)
	}
	if !metav1.IsControlledBy(secret, agentRun) {
		return false, fmt.Errorf("egress CA Secret %s/%s exists but is not controlled by AgentRun %s", secret.Namespace, secret.Name, agentRun.Name)
	}
	certPEM := secret.Data[egressCACertKey]
	if err := validateCAKeyPairPEM(certPEM, secret.Data[egressCAKeyKey]); err != nil {
		return false, fmt.Errorf("egress CA Secret contains invalid keypair: %w", err)
	}
	configMap := &corev1.ConfigMap{}
	key := client.ObjectKey{Namespace: agentRun.Namespace, Name: EgressCAConfigMapName(agentRun.Name)}
	err := r.Get(ctx, key, configMap)
	if err == nil {
		if !metav1.IsControlledBy(configMap, agentRun) {
			return false, fmt.Errorf("egress CA ConfigMap %s/%s exists but is not controlled by AgentRun %s", key.Namespace, key.Name, agentRun.Name)
		}
		if configMap.Data[egressCACertKey] == string(certPEM) &&
			reflect.DeepEqual(configMap.Labels, agentRunLabels(agentRun.Name)) {
			return true, nil
		}
		configMap.Labels = agentRunLabels(agentRun.Name)
		configMap.Data = map[string]string{egressCACertKey: string(certPEM)}
		if err := r.Update(ctx, configMap); err != nil {
			return false, fmt.Errorf("update egress CA ConfigMap: %w", err)
		}
		return true, nil
	}
	if !errors.IsNotFound(err) {
		return false, fmt.Errorf("get egress CA ConfigMap: %w", err)
	}
	desired, err := DesiredEgressCAConfigMap(agentRun, r.Scheme, certPEM)
	if err != nil {
		return false, err
	}
	if err := r.Create(ctx, desired); err != nil {
		return false, fmt.Errorf("create egress CA ConfigMap: %w", err)
	}
	return true, nil
}

// validateCACertificatePEM accepts only certificate PEM blocks: anything
// else — a private key above all — must never reach the published ConfigMap.
func validateCACertificatePEM(data []byte) error {
	_, err := parseCACertificatesPEM(data)
	return err
}

func parseCACertificatesPEM(data []byte) ([]*x509.Certificate, error) {
	rest := data
	certs := []*x509.Certificate{}
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate PEM block found")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("trailing non-PEM data after certificates")
	}
	return certs, nil
}

func validateCAKeyPairPEM(certPEM, keyPEM []byte) error {
	certs, err := parseCACertificatesPEM(certPEM)
	if err != nil {
		return err
	}
	if len(keyPEM) == 0 {
		return fmt.Errorf("missing key %s", egressCAKeyKey)
	}
	block, rest := pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("no EC private key PEM block found")
	}
	if block.Type != "EC PRIVATE KEY" {
		return fmt.Errorf("unexpected PEM block %q", block.Type)
	}
	if strings.TrimSpace(string(rest)) != "" {
		return fmt.Errorf("trailing non-PEM data after private key")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	certKey, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate public key is %T, want ECDSA", certs[0].PublicKey)
	}
	if certKey.Curve != key.Curve || certKey.X.Cmp(key.X) != 0 || certKey.Y.Cmp(key.Y) != 0 {
		return fmt.Errorf("%s does not match %s", egressCAKeyKey, egressCACertKey)
	}
	return nil
}

// DesiredEgressCAConfigMap wraps the public CA certificate for the agent Pod
// to mount read-only at the Phase 4 path.
func DesiredEgressCAConfigMap(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme, certPEM []byte) (*corev1.ConfigMap, error) {
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      EgressCAConfigMapName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    agentRunLabels(agentRun.Name),
		},
		Data: map[string]string{egressCACertKey: string(certPEM)},
	}
	if err := controllerutil.SetControllerReference(agentRun, configMap, scheme); err != nil {
		return nil, fmt.Errorf("set egress CA ConfigMap owner: %w", err)
	}
	return configMap, nil
}

func (r *AgentRunReconciler) reconcileEgressCASecret(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) error {
	secret := &corev1.Secret{}
	key := client.ObjectKey{Namespace: agentRun.Namespace, Name: EgressCASecretName(agentRun.Name)}
	err := r.Get(ctx, key, secret)
	if err == nil {
		if !metav1.IsControlledBy(secret, agentRun) {
			return fmt.Errorf("egress CA Secret %s/%s exists but is not controlled by AgentRun %s", secret.Namespace, secret.Name, agentRun.Name)
		}
		if err := validateCAKeyPairPEM(secret.Data[egressCACertKey], secret.Data[egressCAKeyKey]); err != nil {
			return fmt.Errorf("egress CA Secret %s/%s has invalid keypair: %w", secret.Namespace, secret.Name, err)
		}
		return nil
	}
	if !errors.IsNotFound(err) {
		return fmt.Errorf("get egress CA Secret: %w", err)
	}
	// In forward-proxy mode the durable CA must also permit the MITM upstream
	// hosts, or the agent's TLS verification of the minted upstream leaf fails
	// the CA name constraint.
	leafNames := append(egressdLeafDNSNames(agentRun), forwardProxyUpstreamHosts(agentRun)...)
	data, err := generateEgressCASecretData(leafNames)
	if err != nil {
		return err
	}
	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      EgressCASecretName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    agentRunLabels(agentRun.Name),
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}
	if err := controllerutil.SetControllerReference(agentRun, desired, r.Scheme); err != nil {
		return fmt.Errorf("set egress CA Secret owner: %w", err)
	}
	if err := r.Create(ctx, desired); err != nil {
		return fmt.Errorf("create egress CA Secret: %w", err)
	}
	return nil
}

func generateEgressCASecretData(leafDNSNames []string) (map[string][]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate egress CA key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("generate egress CA serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{CommonName: "nvt-egressd per-run CA"},
		NotBefore:                   time.Now().Add(-5 * time.Minute),
		NotAfter:                    time.Now().Add(30 * 24 * time.Hour),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLenZero:              true,
		KeyUsage:                    x509.KeyUsageCertSign,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         append([]string{"localhost"}, leafDNSNames...),
		PermittedIPRanges: []*net.IPNet{
			{IP: net.IPv4(127, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)},
			{IP: net.IPv6loopback, Mask: net.CIDRMask(128, 128)},
		},
		ExcludedDNSDomains:      nil,
		ExcludedIPRanges:        nil,
		PermittedEmailAddresses: nil,
		ExcludedEmailAddresses:  nil,
		PermittedURIDomains:     nil,
		ExcludedURIDomains:      nil,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create egress CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal egress CA key: %w", err)
	}
	return map[string][]byte{
		egressCACertKey: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		egressCAKeyKey:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

func (r *AgentRunReconciler) reconcileEgressdPod(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) error {
	pod := &corev1.Pod{}
	key := client.ObjectKey{Namespace: agentRun.Namespace, Name: EgressdPodName(agentRun.Name)}
	if err := r.Get(ctx, key, pod); err == nil {
		if !metav1.IsControlledBy(pod, agentRun) {
			return fmt.Errorf("egressd Pod %s/%s exists but is not controlled by AgentRun %s", pod.Namespace, pod.Name, agentRun.Name)
		}
		if err := r.repairOwnedPodLabels(ctx, pod, enforcementLabels(agentRun.Name, roleLabelEgressd)); err != nil {
			return err
		}
		return nil
	} else if !errors.IsNotFound(err) {
		return fmt.Errorf("get egressd Pod: %w", err)
	}
	desired, err := DesiredEgressdPod(agentRun, r.Scheme)
	if err != nil {
		return err
	}
	if err := r.Create(ctx, desired); err != nil {
		return fmt.Errorf("create egressd Pod: %w", err)
	}
	return nil
}

func (r *AgentRunReconciler) reconcileEgressdService(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) error {
	service := &corev1.Service{}
	key := client.ObjectKey{Namespace: agentRun.Namespace, Name: EgressdServiceName(agentRun.Name)}
	desired, err := DesiredEgressdService(agentRun, r.Scheme)
	if err != nil {
		return err
	}
	if err := r.Get(ctx, key, service); err == nil {
		if !metav1.IsControlledBy(service, agentRun) {
			return fmt.Errorf("egressd Service %s/%s exists but is not controlled by AgentRun %s", service.Namespace, service.Name, agentRun.Name)
		}
		if reflect.DeepEqual(service.Labels, desired.Labels) &&
			reflect.DeepEqual(service.OwnerReferences, desired.OwnerReferences) &&
			reflect.DeepEqual(service.Spec.Selector, desired.Spec.Selector) &&
			reflect.DeepEqual(service.Spec.Ports, desired.Spec.Ports) {
			return nil
		}
		service.Labels = desired.Labels
		service.OwnerReferences = desired.OwnerReferences
		service.Spec.Selector = desired.Spec.Selector
		service.Spec.Ports = desired.Spec.Ports
		if err := r.Update(ctx, service); err != nil {
			return fmt.Errorf("update egressd Service: %w", err)
		}
		return nil
	} else if !errors.IsNotFound(err) {
		return fmt.Errorf("get egressd Service: %w", err)
	}
	if err := r.Create(ctx, desired); err != nil {
		return fmt.Errorf("create egressd Service: %w", err)
	}
	return nil
}

// DesiredEgressdPod renders the own-Pod egressd for an enforcement run. It
// carries the same config/token/broker-CA wiring as the same-Pod sidecar,
// plus a readiness probe on the CA endpoint so EgressdReady is observable.
func DesiredEgressdPod(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme) (*corev1.Pod, error) {
	if err := ValidateBrokerTLSConfig(); err != nil {
		return nil, err
	}
	volumes := []corev1.Volume{{
		Name: egressdConfigName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: EgressdConfigMapName(agentRun.Name)},
				Items: []corev1.KeyToPath{
					{Key: egressdConfigKey, Path: egressdConfigKey},
				},
			},
		},
	}}
	volumeMounts := []corev1.VolumeMount{
		{Name: egressdConfigName, MountPath: egressdConfigPath, SubPath: egressdConfigKey, ReadOnly: true},
	}
	if AgentRunEgressEnforced(agentRun) {
		volumes = append(volumes, corev1.Volume{
			Name: egressCASecretVolume,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: EgressCASecretName(agentRun.Name),
					Items: []corev1.KeyToPath{
						{Key: egressCACertKey, Path: egressCACertKey},
						{Key: egressCAKeyKey, Path: egressCAKeyKey},
					},
				},
			},
		})
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      egressCASecretVolume,
			MountPath: egressCASecretMount,
			ReadOnly:  true,
		})
	}
	if brokerCADistributed() {
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
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      brokerCAVolumeName,
			MountPath: egressdBrokerCAMount,
			ReadOnly:  true,
		})
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      EgressdPodName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    enforcementLabels(agentRun.Name, roleLabelEgressd),
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyAlways,
			Containers: []corev1.Container{{
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
				ReadinessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						HTTPGet: &corev1.HTTPGetAction{
							Path: "/healthz",
							Port: intstr.FromInt32(egressCAPort),
						},
					},
					PeriodSeconds: 2,
				},
				VolumeMounts: volumeMounts,
			}},
			Volumes: volumes,
		},
	}
	if err := controllerutil.SetControllerReference(agentRun, pod, scheme); err != nil {
		return nil, fmt.Errorf("set egressd Pod owner: %w", err)
	}
	return pod, nil
}

// AgentNetworkPolicyName returns the per-run agent egress policy name.
func AgentNetworkPolicyName(agentRunName string) string {
	return agentRunName + "-agent"
}

// EgressdNetworkPolicyName returns the per-run egressd policy name.
func EgressdNetworkPolicyName(agentRunName string) string {
	return agentRunName + "-egressd"
}

func (r *AgentRunReconciler) reconcileNetworkPolicies(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) error {
	agentPolicy, err := DesiredAgentNetworkPolicy(agentRun, r.Scheme)
	if err != nil {
		return err
	}
	egressdPolicy, err := DesiredEgressdNetworkPolicy(agentRun, r.Scheme)
	if err != nil {
		return err
	}
	for _, desired := range []*networkingv1.NetworkPolicy{agentPolicy, egressdPolicy} {
		policy := &networkingv1.NetworkPolicy{}
		err := r.Get(ctx, client.ObjectKeyFromObject(desired), policy)
		if err == nil {
			if !metav1.IsControlledBy(policy, agentRun) {
				return fmt.Errorf("NetworkPolicy %s/%s exists but is not controlled by AgentRun %s", policy.Namespace, policy.Name, agentRun.Name)
			}
			if reflect.DeepEqual(policy.Labels, desired.Labels) &&
				reflect.DeepEqual(policy.OwnerReferences, desired.OwnerReferences) &&
				reflect.DeepEqual(policy.Spec, desired.Spec) {
				continue
			}
			policy.Labels = desired.Labels
			policy.OwnerReferences = desired.OwnerReferences
			policy.Spec = desired.Spec
			if err := r.Update(ctx, policy); err != nil {
				return fmt.Errorf("update NetworkPolicy %s: %w", desired.Name, err)
			}
			continue
		}
		if !errors.IsNotFound(err) {
			return fmt.Errorf("get NetworkPolicy %s: %w", desired.Name, err)
		}
		if createErr := r.Create(ctx, desired); createErr != nil {
			return fmt.Errorf("create NetworkPolicy %s: %w", desired.Name, createErr)
		}
	}
	return nil
}

func protocolPtr(protocol corev1.Protocol) *corev1.Protocol {
	return &protocol
}

func policyPort(protocol corev1.Protocol, port int) networkingv1.NetworkPolicyPort {
	value := intstr.FromInt32(int32(port))
	return networkingv1.NetworkPolicyPort{Protocol: protocolPtr(protocol), Port: &value}
}

func dnsPolicyEgressRule() networkingv1.NetworkPolicyEgressRule {
	return networkingv1.NetworkPolicyEgressRule{
		To: []networkingv1.NetworkPolicyPeer{{
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"},
			},
		}},
		Ports: []networkingv1.NetworkPolicyPort{
			policyPort(corev1.ProtocolUDP, 53),
			policyPort(corev1.ProtocolTCP, 53),
		},
	}
}

func brokerPolicyEgressRule() networkingv1.NetworkPolicyEgressRule {
	return networkingv1.NetworkPolicyEgressRule{
		To: []networkingv1.NetworkPolicyPeer{{
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app.kubernetes.io/name": "nvt-broker"},
			},
		}},
		Ports: []networkingv1.NetworkPolicyPort{policyPort(corev1.ProtocolTCP, 7347)},
	}
}

// egressdPolicyPorts are the CA endpoint plus every route port (and the
// forward-proxy port in forward-proxy mode). Feeds both the agent→egressd
// egress rule and the egressd ingress rule.
func egressdPolicyPorts(agentRun *nvtv1alpha1.AgentRun) []networkingv1.NetworkPolicyPort {
	ports := []networkingv1.NetworkPolicyPort{policyPort(corev1.ProtocolTCP, egressCAPort)}
	for index := range headerInjectGrants(agentRun) {
		ports = append(ports, policyPort(corev1.ProtocolTCP, egressRouteBasePort+index))
	}
	if AgentRunEgressForwardProxy(agentRun) {
		ports = append(ports, policyPort(corev1.ProtocolTCP, egressForwardProxyPort))
	}
	return ports
}

// DesiredAgentNetworkPolicy is the enforcement fence around the agent Pod:
// default-deny egress plus kube-dns, the broker, the paired egressd, and the
// operator callback. No internet CIDR at all — including traffic from
// dind-spawned containers, which still exits the Pod and hits the CNI.
// Ingress is left unrestricted this PR (gateway/code-server unaffected).
func DesiredAgentNetworkPolicy(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme) (*networkingv1.NetworkPolicy, error) {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      AgentNetworkPolicyName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    enforcementLabels(agentRun.Name, roleLabelAgent),
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					agentRunLabelKey: agentRun.Name,
					roleLabelKey:     roleLabelAgent,
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				dnsPolicyEgressRule(),
				brokerPolicyEgressRule(),
				{
					// Paired egressd only: the run label pins the pair, so
					// agent A can never reach egressd B.
					To: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								agentRunLabelKey: agentRun.Name,
								roleLabelKey:     roleLabelEgressd,
							},
						},
					}},
					Ports: egressdPolicyPorts(agentRun),
				},
				{
					To: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app.kubernetes.io/name": "nvt-operator"},
						},
					}},
					Ports: []networkingv1.NetworkPolicyPort{policyPort(corev1.ProtocolTCP, 8082)},
				},
			},
		},
	}
	if err := controllerutil.SetControllerReference(agentRun, policy, scheme); err != nil {
		return nil, fmt.Errorf("set agent NetworkPolicy owner: %w", err)
	}
	return policy, nil
}

// DesiredEgressdNetworkPolicy fences the own-Pod egressd: ingress only from
// the paired agent; egress to DNS, the broker, and upstream :443.
//
// The 0.0.0.0/0:443 egress is a deliberately coarse fence: vanilla
// NetworkPolicy selects by CIDR/port, not hostname. The semantic per-host
// allowlist lives in egressd itself (pinned route upstreams, capability
// injection-hosts, fail-closed CONNECT allowlist) — do not read this policy
// as host-scoped. Excluding cluster CIDRs via except blocks is a second-pass
// hardening, not this PR.
func DesiredEgressdNetworkPolicy(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme) (*networkingv1.NetworkPolicy, error) {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      EgressdNetworkPolicyName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    enforcementLabels(agentRun.Name, roleLabelEgressd),
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					agentRunLabelKey: agentRun.Name,
					roleLabelKey:     roleLabelEgressd,
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								agentRunLabelKey: agentRun.Name,
								roleLabelKey:     roleLabelAgent,
							},
						},
					}},
					Ports: egressdPolicyPorts(agentRun),
				},
				{
					// Operator probes may read the public CA endpoint across
					// the CNI. CA port only — never the route ports.
					From: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app.kubernetes.io/name": "nvt-operator"},
						},
					}},
					Ports: []networkingv1.NetworkPolicyPort{policyPort(corev1.ProtocolTCP, egressCAPort)},
				},
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				dnsPolicyEgressRule(),
				brokerPolicyEgressRule(),
				{
					To: []networkingv1.NetworkPolicyPeer{{
						IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"},
					}},
					Ports: []networkingv1.NetworkPolicyPort{policyPort(corev1.ProtocolTCP, 443)},
				},
			},
		},
	}
	if err := controllerutil.SetControllerReference(agentRun, policy, scheme); err != nil {
		return nil, fmt.Errorf("set egressd NetworkPolicy owner: %w", err)
	}
	return policy, nil
}

// DesiredEgressdService exposes the CA endpoint and every route port under
// the per-run Service name the agent's base-urls point at.
func DesiredEgressdService(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme) (*corev1.Service, error) {
	ports := []corev1.ServicePort{{Name: "ca", Port: egressCAPort}}
	for index := range headerInjectGrants(agentRun) {
		ports = append(ports, corev1.ServicePort{
			Name: fmt.Sprintf("route-%d", index),
			Port: int32(egressRouteBasePort + index),
		})
	}
	if AgentRunEgressForwardProxy(agentRun) {
		ports = append(ports, corev1.ServicePort{Name: "forward-proxy", Port: int32(egressForwardProxyPort)})
	}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      EgressdServiceName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    enforcementLabels(agentRun.Name, roleLabelEgressd),
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				agentRunLabelKey: agentRun.Name,
				roleLabelKey:     roleLabelEgressd,
			},
			Ports: ports,
		},
	}
	if err := controllerutil.SetControllerReference(agentRun, service, scheme); err != nil {
		return nil, fmt.Errorf("set egressd Service owner: %w", err)
	}
	return service, nil
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
		MaxRequests           int    `json:"max_requests,omitempty"`
	}
	type egressdCA struct {
		PublishDir   string   `json:"publish_dir,omitempty"`
		LeafDNSNames []string `json:"leaf_dns_names,omitempty"`
		ServeAddr    string   `json:"serve_addr,omitempty"`
		CertFile     string   `json:"cert_file,omitempty"`
		KeyFile      string   `json:"key_file,omitempty"`
	}
	type egressdForwardProxyRoute struct {
		Host                  string `json:"host"`
		Capability            string `json:"capability"`
		Upstream              string `json:"upstream"`
		AllowInsecureUpstream bool   `json:"allow_insecure_upstream,omitempty"`
		MaxRequests           int    `json:"max_requests,omitempty"`
		RequireCapabilityHint bool   `json:"require_capability_hint,omitempty"`
	}
	type egressdForwardProxy struct {
		Listen              string                     `json:"listen"`
		AllowUnmatchedHosts bool                       `json:"allow_unmatched_hosts"`
		InjectRoutes        []egressdForwardProxyRoute `json:"inject_routes"`
	}
	type egressdConfig struct {
		BrokerURL           string               `json:"broker_url"`
		AllowInsecureBroker bool                 `json:"allow_insecure_broker"`
		BrokerCAFile        string               `json:"broker_ca_file,omitempty"`
		Routes              []egressdRoute       `json:"routes"`
		ForwardProxy        *egressdForwardProxy `json:"forward_proxy,omitempty"`
		CA                  *egressdCA           `json:"ca,omitempty"`
	}
	if err := ValidateBrokerTLSConfig(); err != nil {
		return "", err
	}
	grants := AgentRunBrokerGrants(agentRun.Spec.Broker)
	routes := make([]egressdRoute, 0, len(grants))
	enforced := AgentRunEgressEnforced(agentRun)
	forwardProxy := AgentRunEgressForwardProxy(agentRun)
	routeIndex := 0
	needCA := false
	for _, grant := range grants {
		// In forward-proxy mode injectable grants are routed by the MITM proxy,
		// not per-route redirect base URLs, so no redirect routes are rendered.
		if forwardProxy || AgentRunGrantMaterialization(grant) != nvtv1alpha1.AgentRunGrantHeaderInject {
			continue
		}
		if len(grant.EgressHosts) == 0 {
			return "", fmt.Errorf("broker grant %s egressHosts is required for mediated egress", grant.Provider)
		}
		route := egressdRoute{
			Listen:                fmt.Sprintf("127.0.0.1:%d", egressRouteBasePort+routeIndex),
			Capability:            grant.Provider,
			Upstream:              grant.EgressHosts[0],
			AllowInsecureUpstream: grant.AllowInsecureUpstream,
		}
		if grant.Quota != nil {
			route.MaxRequests = grant.Quota.Requests
		}
		if enforced {
			// Own-Pod: the hop leaves localhost, so every route listens on
			// the Pod network and terminates TLS under the per-agent CA.
			route.Listen = fmt.Sprintf("0.0.0.0:%d", egressRouteBasePort+routeIndex)
			route.ListenTLS = "ca"
			needCA = true
		} else if grant.Git {
			// git clients require an https base URL; the route terminates
			// TLS with a leaf signed by the boot-generated per-agent CA.
			route.ListenTLS = "ca"
			needCA = true
		}
		routes = append(routes, route)
		routeIndex++
	}
	config := egressdConfig{
		BrokerURL:           BrokerURL(),
		AllowInsecureBroker: agentRun.Spec.EgressAllowInsecureBroker,
		Routes:              routes,
	}
	if forwardProxy {
		injects := forwardProxyInjects(agentRun)
		if len(injects) == 0 {
			return "", fmt.Errorf("forward-proxy egress requires at least one injectable grant with egressHosts")
		}
		fpRoutes := make([]egressdForwardProxyRoute, 0, len(injects))
		for _, inject := range injects {
			fpRoutes = append(fpRoutes, egressdForwardProxyRoute{
				Host:                  inject.Host,
				Capability:            inject.Capability,
				Upstream:              inject.Upstream,
				AllowInsecureUpstream: inject.AllowInsecureUpstream,
				MaxRequests:           inject.MaxRequests,
				RequireCapabilityHint: inject.RequireCapabilityHint,
			})
		}
		config.ForwardProxy = &egressdForwardProxy{
			Listen:              fmt.Sprintf("0.0.0.0:%d", egressForwardProxyPort),
			AllowUnmatchedHosts: true,
			InjectRoutes:        fpRoutes,
		}
	}
	if brokerCADistributed() {
		// TLS broker leg: pin the CA so egressd verifies the broker instead
		// of relying on the insecure flag.
		config.BrokerCAFile = egressdBrokerCAFile
		config.AllowInsecureBroker = false
	}
	if enforced {
		// The CA keypair is generated once by the operator and mounted only
		// into egressd; the agent receives only ca.crt via ConfigMap.
		config.CA = &egressdCA{
			LeafDNSNames: egressdLeafDNSNames(agentRun),
			ServeAddr:    fmt.Sprintf("0.0.0.0:%d", egressCAPort),
			CertFile:     egressCASecretCert,
			KeyFile:      egressCASecretKeyFile,
		}
	} else if needCA {
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
	if err := ValidateBrokerTLSConfig(); err != nil {
		return nil, err
	}
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
	if brokerCADistributed() {
		// The agent talks to the broker in both egress modes (brokerctl), so
		// the CA rides along whenever the broker leg is TLS.
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
		// Own-Pod mode: the agent's trust anchor is the operator-published
		// per-run ConfigMap, mounted read-only at the same Phase 4 path so
		// bootstrap is unchanged. No egressd sidecar and no shared emptyDir.
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
				// Non-root also needs group-writable auth files: fsGroup makes the
				// mount group 1000, so ug+rwX lets the agent write seeded tokens.
				"cp -a " + runtimeAuthSourcePath + "/. " + runtimeAuthHomePath + "/ && chmod -R " + runtimeAuthChmod(agentRun) + " " + runtimeAuthHomePath,
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
				{Name: "NVT_BROKER_URL", Value: BrokerURL()},
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
		if enforced || hasGitGrant {
			// Enforcement: every base-url is https, so bootstrap always
			// needs the CA (git wiring plus the container trust store).
			containers[0].Env = append(containers[0].Env, corev1.EnvVar{Name: "NVT_EGRESS_CA_FILE", Value: egressCAFilePath})
		}
		if AgentRunEgressForwardProxy(agentRun) {
			containers[0].Env = append(containers[0].Env, forwardProxyEnv(agentRun)...)
		}
	}
	if brokerCADistributed() {
		containers[0].Env = append(containers[0].Env, corev1.EnvVar{Name: "NVT_BROKER_CA_FILE", Value: agentBrokerCAFile})
	}
	if AgentRunNonRoot(agentRun) {
		// Run the agent as the image's `agent` user; set HOME + NVT_STATE_DIR so
		// $HOME-relative bootstrap/entrypoint target /home/agent (the baked
		// NVT_STATE_DIR=/root/... would otherwise be unwritable).
		containers[0].SecurityContext = &corev1.SecurityContext{
			RunAsUser:  ptrTo(agentNonRootUID),
			RunAsGroup: ptrTo(agentNonRootGID),
		}
		containers[0].Env = append(containers[0].Env,
			corev1.EnvVar{Name: "HOME", Value: agentNonRootHome},
			corev1.EnvVar{Name: "NVT_STATE_DIR", Value: agentNonRootHome + "/.nvt-agent"},
		)
	}
	if AgentRunEgressMode(agentRun) == nvtv1alpha1.AgentRunEgressMediated && !enforced {
		egressdVolumeMounts := []corev1.VolumeMount{
			{Name: egressdConfigName, MountPath: egressdConfigPath, SubPath: egressdConfigKey, ReadOnly: true},
		}
		if brokerCADistributed() {
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
				// egressd reads the broker URL from its JSON config
				// (broker_url), not from the environment.
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
		// Pairing labels the NetworkPolicies select on.
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
			RestartPolicy:    corev1.RestartPolicyNever,
			InitContainers:   initContainers,
			Containers:       containers,
			Volumes:          volumes,
		},
	}
	if AgentRunNonRoot(agentRun) {
		// fsGroup makes the workspace + runtime-auth emptyDir volumes group 1000
		// and group-writable, so the non-root agent can write them. The
		// privileged root dind container is unaffected (root ignores fsGroup).
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{FSGroup: ptrTo(agentNonRootGID)}
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

// BrokerURL is the broker base URL the operator wires into agent and egressd
// containers. The chart sets NVT_BROKER_URL=https://nvt-broker:7347 when
// broker TLS is enabled; the default stays plaintext so local/dev setups and
// existing deployments are unchanged.
func BrokerURL() string {
	if url := strings.TrimSpace(os.Getenv("NVT_BROKER_URL")); url != "" {
		return url
	}
	return defaultBrokerURL
}

// brokerIsTLS reports whether the broker leg is https, which requires the CA
// certificate to be distributed to egressd and the agent.
func brokerIsTLS() bool {
	return strings.HasPrefix(BrokerURL(), "https://")
}

// BrokerCASecretName is the Secret holding the broker's CA certificate
// (public material, key ca.crt). Empty means none configured.
func BrokerCASecretName() string {
	return strings.TrimSpace(os.Getenv("NVT_BROKER_CA_SECRET"))
}

// brokerCADistributed reports whether the operator both talks TLS to the
// broker and knows which Secret carries the CA — the precondition for
// mounting it and rendering broker_ca_file.
func brokerCADistributed() bool {
	return brokerIsTLS() && BrokerCASecretName() != ""
}

// ValidateBrokerTLSConfig rejects the half-configured TLS state: an https
// broker URL with no CA Secret would render Pods whose brokerctl/egressd
// calls all fail TLS verification at runtime. Checked at operator startup
// and again on every render/validation path as defense in depth.
func ValidateBrokerTLSConfig() error {
	if brokerIsTLS() && BrokerCASecretName() == "" {
		return fmt.Errorf(
			"NVT_BROKER_URL %s is https but NVT_BROKER_CA_SECRET is not set; agent Pods need the broker CA Secret (key %s) to verify the broker",
			BrokerURL(), brokerCAKey,
		)
	}
	return nil
}

// DefaultEgressMode is the cluster's creation-time default egress mode, read
// from NVT_DEFAULT_EGRESS_MODE (empty means direct). It is applied ONCE, at
// AgentRun creation on the nvt admission path (ApplyDefaultEgressMode) — never
// at reconcile time, so flipping the knob can never reclassify an existing
// run (the #62/#63 retroactive-reclassification hazard). AgentRunEgressMode
// deliberately does not read this env.
func DefaultEgressMode() nvtv1alpha1.AgentRunEgressMode {
	mode := strings.TrimSpace(os.Getenv("NVT_DEFAULT_EGRESS_MODE"))
	if mode == "" {
		return nvtv1alpha1.AgentRunEgressDirect
	}
	return nvtv1alpha1.AgentRunEgressMode(mode)
}

// ValidateDefaultEgressMode fails fast (operator startup) on a bad knob value.
func ValidateDefaultEgressMode() error {
	mode := DefaultEgressMode()
	if mode != nvtv1alpha1.AgentRunEgressDirect && mode != nvtv1alpha1.AgentRunEgressMediated {
		return fmt.Errorf("NVT_DEFAULT_EGRESS_MODE must be direct or mediated, got %q", mode)
	}
	return nil
}

// ApplyDefaultEgressMode stamps the cluster default into spec.egress when the
// incoming run leaves it empty, so the stored object is always explicit and a
// later knob change can never alter it. It never overrides an explicit mode.
func ApplyDefaultEgressMode(agentRun *nvtv1alpha1.AgentRun) {
	if agentRun.Spec.Egress == "" {
		agentRun.Spec.Egress = DefaultEgressMode()
	}
}

// AllowInsecureUpstreamsEnabled reports whether the cluster opted into the
// per-grant allowInsecureUpstream escape hatch via NVT_ALLOW_INSECURE_UPSTREAMS.
// It exists only so hermetic in-cluster test fixtures are reachable; a real
// deployment never sets it, so a plaintext upstream leg carrying an injected
// credential cannot be requested by an AgentRun spec.
func AllowInsecureUpstreamsEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("NVT_ALLOW_INSECURE_UPSTREAMS"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
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
	if err := ValidateBrokerTLSConfig(); err != nil {
		return err
	}
	mode := AgentRunEgressMode(agentRun)
	if mode != nvtv1alpha1.AgentRunEgressDirect && mode != nvtv1alpha1.AgentRunEgressMediated {
		return fmt.Errorf("spec.egress must be direct or mediated, got %q", mode)
	}
	if agentRun.Spec.EgressEnforcement && mode != nvtv1alpha1.AgentRunEgressMediated {
		return fmt.Errorf("spec.egressEnforcement requires spec.egress mediated, got %q", mode)
	}
	if agentRun.Spec.EgressForwardProxy && !agentRun.Spec.EgressEnforcement {
		// Without the CNI fence the agent can ignore the proxy env and reach
		// hosts directly, so forward-proxy without enforcement is coverage
		// theater (docs/phase6.2-forward-proxy-pr-plan.md decision 3).
		return fmt.Errorf("spec.egressForwardProxy requires spec.egressEnforcement")
	}
	headerInjectGrants := 0
	if mode == nvtv1alpha1.AgentRunEgressMediated {
		if agentRun.Spec.RuntimeAuth != nil {
			return fmt.Errorf("egress mediated is incompatible with spec.runtimeAuth")
		}
		if strings.HasPrefix(BrokerURL(), "http://") && !agentRun.Spec.EgressAllowInsecureBroker {
			return fmt.Errorf("egress mediated with plaintext broker requires spec.egressAllowInsecureBroker=true for local/dev use")
		}
	}
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		materialization := AgentRunGrantMaterialization(grant)
		switch materialization {
		case nvtv1alpha1.AgentRunGrantFileBundle, nvtv1alpha1.AgentRunGrantHeaderInject, nvtv1alpha1.AgentRunGrantPlaceholderFile:
		default:
			return fmt.Errorf("broker grant %s materialization must be file-bundle, header-inject, or placeholder-file, got %q", grant.Provider, materialization)
		}
		// header-inject and placeholder-file are zero-possession mediated modes:
		// both are rejected in direct mode (no edge to inject at) and file-bundle
		// is rejected in mediated mode (writes usable material into the container).
		if mode == nvtv1alpha1.AgentRunEgressDirect && materialization != nvtv1alpha1.AgentRunGrantFileBundle {
			return fmt.Errorf("egress direct is incompatible with broker grant %s materialization %s", grant.Provider, materialization)
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
		if grant.Quota != nil && grant.Quota.Requests <= 0 {
			return fmt.Errorf("broker grant %s quota.requests must be a positive integer", grant.Provider)
		}
		if grant.AllowInsecureUpstream {
			// A plaintext upstream leg carries the injected credential in the
			// clear, so this is gated to a cluster/test opt-in and never
			// allowed for git (git creds ride the TLS-terminated redirect).
			if grant.Git {
				return fmt.Errorf("broker grant %s must not set allowInsecureUpstream on a git grant", grant.Provider)
			}
			if !AllowInsecureUpstreamsEnabled() {
				return fmt.Errorf("broker grant %s sets allowInsecureUpstream, which requires the operator's NVT_ALLOW_INSECURE_UPSTREAMS opt-in (test/dev only)", grant.Provider)
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
		// In forward-proxy mode a placeholder-file grant's egressHosts become
		// MITM routes, so validate them too.
		if agentRun.Spec.EgressForwardProxy && materialization == nvtv1alpha1.AgentRunGrantPlaceholderFile {
			for _, host := range grant.EgressHosts {
				if !validEgressHost(host) {
					return fmt.Errorf("forward-proxy broker grant %s has invalid egressHosts entry %q", grant.Provider, host)
				}
			}
		}
	}
	if agentRun.Spec.EgressForwardProxy {
		// Forward-proxy makes every injection-capable grant's egressHosts
		// routable, so the run needs at least one such host — but no longer a
		// header-inject grant specifically.
		injects := forwardProxyInjects(agentRun)
		if len(injects) == 0 {
			return fmt.Errorf("spec.egressForwardProxy requires at least one header-inject or placeholder-file broker grant with egressHosts")
		}
		// Mirror egressd's inject-route rules at admission so a config egressd
		// would reject at boot fails loudly here instead of CrashLooping a
		// silently-broken run: MITM hosts must be DNS names (SNI/leaf need a
		// name), and each normalized host/capability pair is unique. A host may
		// map to more than one capability; egressd then requires an explicit
		// non-secret capability hint on the CONNECT request and fails closed
		// without one.
		claimedBy := map[string]bool{}
		for _, inject := range injects {
			if net.ParseIP(inject.Host) != nil {
				return fmt.Errorf("forward-proxy egressHost %q must be a DNS name, not an IP (TLS-MITM needs a name for SNI/leaf)", inject.Host)
			}
			key := inject.Host + "\x00" + inject.Capability
			if claimedBy[key] {
				return fmt.Errorf("forward-proxy host %q is duplicated for broker grant %s", inject.Host, inject.Capability)
			}
			claimedBy[key] = true
		}
		return nil
	}
	if mode == nvtv1alpha1.AgentRunEgressMediated && headerInjectGrants == 0 {
		// Non-forward-proxy mediated runs still need a header-inject route:
		// placeholder-file grants are materialized but not routed without the
		// forward proxy.
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
		agentRunLabelKey:              agentRunName,
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
		var quota *brokerAgentQuota
		if grant.Quota != nil {
			quota = &brokerAgentQuota{Requests: grant.Quota.Requests}
		}
		grants = append(grants, brokerAgentGrantEntry{
			Provider:        grant.Provider,
			Repositories:    repositories,
			Materialization: string(AgentRunGrantMaterialization(grant)),
			EgressHosts:     append([]string{}, grant.EgressHosts...),
			Permissions:     permissions,
			Quota:           quota,
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
			case "", string(nvtv1alpha1.AgentRunGrantFileBundle), string(nvtv1alpha1.AgentRunGrantHeaderInject), string(nvtv1alpha1.AgentRunGrantPlaceholderFile):
			default:
				return fmt.Errorf("agents[%d].grants[%d].materialization must be file-bundle, header-inject, or placeholder-file", agentIndex, grantIndex)
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

	if promptText := AgentRunPromptText(agentRun); promptText != "" ||
		AgentRunEgressMode(agentRun) == nvtv1alpha1.AgentRunEgressMediated ||
		AgentRunNeedsRuntimePreseed(agentRun) {
		config := map[string]any{}
		if err := yaml.Unmarshal(rawConfig, &config); err != nil {
			return "", fmt.Errorf("render AgentRun agent config: %w", err)
		}
		renderedConfig := config
		renderedConfig = InjectRuntimePreseed(renderedConfig, agentRun)
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

func AgentRunNeedsRuntimePreseed(agentRun *nvtv1alpha1.AgentRun) bool {
	return agentRun.Spec.Runtime.Type == "codex"
}

func InjectRuntimePreseed(config map[string]any, agentRun *nvtv1alpha1.AgentRun) map[string]any {
	if !AgentRunNeedsRuntimePreseed(agentRun) {
		return config
	}
	if _, ok := config["preseed"]; ok {
		return config
	}
	updated := cloneStringAnyMap(config)
	updated["preseed"] = map[string]any{
		"files": []any{
			map[string]any{
				"path":      "$HOME/.codex/config.toml",
				"mode":      "0600",
				"overwrite": false,
				"content":   "check_for_update_on_startup = false\n",
			},
		},
	}
	return updated
}

func InjectMediatedEgressConfig(config map[string]any, agentRun *nvtv1alpha1.AgentRun) map[string]any {
	enforced := AgentRunEgressEnforced(agentRun)
	forwardProxy := AgentRunEgressForwardProxy(agentRun)
	grants := []any{}
	routeIndex := 0
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		// In forward-proxy mode header-inject grants are reached through the
		// proxy (HTTP(S)_PROXY), not a per-route base URL. Still render the
		// grant metadata so runtime.proxy.provider can validate the selected
		// provider against egress.grants.
		if forwardProxy && AgentRunGrantMaterialization(grant) == nvtv1alpha1.AgentRunGrantHeaderInject {
			grants = append(grants, map[string]any{
				"provider":        grant.Provider,
				"materialization": string(nvtv1alpha1.AgentRunGrantHeaderInject),
			})
			continue
		}
		if AgentRunGrantMaterialization(grant) != nvtv1alpha1.AgentRunGrantHeaderInject {
			continue
		}
		baseURL := fmt.Sprintf("http://127.0.0.1:%d", egressRouteBasePort+routeIndex)
		if enforced {
			// Own-Pod egressd: every route is reached through the per-run
			// Service and terminates TLS under the per-agent CA.
			baseURL = fmt.Sprintf("https://%s:%d", EgressdServiceName(agentRun.Name), egressRouteBasePort+routeIndex)
		} else if grant.Git {
			baseURL = fmt.Sprintf("https://127.0.0.1:%d", egressRouteBasePort+routeIndex)
		}
		grants = append(grants, map[string]any{
			"provider":        grant.Provider,
			"materialization": string(nvtv1alpha1.AgentRunGrantHeaderInject),
			"base-url":        baseURL,
		})
		routeIndex++
	}
	// placeholder-file grants carry no egressd route (edge injection is Phase
	// 6.2); bootstrap only needs the provider + mode to materialize the inert
	// placeholder auth file.
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		if AgentRunGrantMaterialization(grant) != nvtv1alpha1.AgentRunGrantPlaceholderFile {
			continue
		}
		grants = append(grants, map[string]any{
			"provider":        grant.Provider,
			"materialization": string(nvtv1alpha1.AgentRunGrantPlaceholderFile),
		})
	}
	updated := cloneStringAnyMap(config)
	egress := map[string]any{
		"mode":        string(nvtv1alpha1.AgentRunEgressMediated),
		"placeholder": "NVT-PLACEHOLDER-NOT-A-KEY",
		"grants":      grants,
	}
	if enforced {
		egress["enforcement"] = true
	}
	if forwardProxy {
		// Signals bootstrap to install the CA trust store for proxy-env HTTPS
		// clients (the MITM leaf must be trusted system-wide).
		egress["forward-proxy"] = true
		egress["forward-proxy-url"] = fmt.Sprintf("http://%s:%d", EgressdServiceName(agentRun.Name), egressForwardProxyPort)
	}
	updated["egress"] = egress
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
