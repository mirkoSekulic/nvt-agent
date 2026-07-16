package controller

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
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
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/yaml"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

const (
	agentConfigKey                        = "agent.yaml"
	preparedPlaceholderFilesKey           = "prepared-placeholder-files.json"
	agentConfigMountPath                  = "/nvt-agent/agent.yaml"
	agentConfigVolumeDir                  = "/nvt-agent"
	runtimeAuthSourcePath                 = "/nvt-agent/runtime-auth-source"
	runtimeAuthHomePath                   = "/nvt-agent/runtime-auth-home"
	runtimeAuthSourceName                 = "runtime-auth-source"
	runtimeAuthHomeName                   = "runtime-auth-home"
	egressdConfigKey                      = "egressd.json"
	egressdConfigPath                     = "/etc/nvt-egressd/config.json"
	egressCAVolumeName                    = "egress-ca"
	egressCAMountPath                     = "/nvt-egress-ca"
	egressCAFilePath                      = egressCAMountPath + "/ca.crt"
	egressCASecretVolume                  = "egress-ca-keypair"
	egressCASecretMount                   = "/etc/nvt-egressd/egress-ca"
	egressCASecretCert                    = egressCASecretMount + "/ca.crt"
	egressCASecretKeyFile                 = egressCASecretMount + "/ca.key"
	workspaceMountPath                    = "/workspace"
	workspaceVolumeName                   = "workspace"
	persistentStorageInitMountPath        = "/nvt-agent/persistent-storage"
	persistentWorkspaceSubPath            = "workspace"
	persistentHomeSubPath                 = "home"
	workspacePVCReadyRequeue              = 2 * time.Second
	terminalResourceCleanupRequeue        = 2 * time.Second
	initialPromptPlugin                   = "initial-prompt"
	lifecycleReporterPlugin               = "lifecycle-termination"
	agentPodSecurityStateAnnotation       = "nvt.dev/pod-security-state"
	agentConfigPlaceholderCacheAnnotation = "nvt.dev/placeholder-cache-key"

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
	// Enforcement mode (docs/transparent-egress-architecture.md): egressd runs
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

	brokerAgentsConfigMapName        = "nvt-broker-agents"
	brokerAgentsConfigKey            = "agents.yaml"
	brokerTokenKey                   = "NVT_BROKER_TOKEN"
	egressTokenKey                   = "NVT_EGRESS_BROKER_TOKEN"
	defaultEgressdImage              = "nvt-egressd:latest"
	defaultCapturedImage             = "nvt-captured:latest"
	capturedTransparentPort          = 15001
	capturedExplicitPort             = 15002
	capturedUID                int64 = 65532
	callbackTokenKey                 = "NVT_OPERATOR_CALLBACK_TOKEN"
	agentRunFinalizer                = "nvt.dev/agentrun-broker-policy"
	completedLifecycleReason         = "Completed by lifecycle event "
	failedLifecycleReason            = "Failed by lifecycle event "
	activeDeadlineReason             = "Active deadline exceeded"
	generatedTokenByteLength         = 32
	defaultRunRetentionSeconds       = 30 * 24 * 60 * 60
)

var defaultExternalTCPPorts = []int{80, 443}

// builtInEgressDenyCIDRs mirrors egressd's IANA-derived destination policy.
// The same normalized result is rendered into egressd and NetworkPolicy, so
// the application and CNI defense use one operator-side source.
var builtInEgressDenyCIDRs = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"224.0.0.0/4", "240.0.0.0/4",
	// Kubernetes rejects IPv4-mapped IPv6 prefixes in ipBlock.except. Mapped
	// traffic is covered by the IPv4 exclusions, while egressd additionally
	// unmaps every address before applying its application policy.
	"::/96", "64:ff9b::/96", "64:ff9b:1::/48",
	"100::/64", "100:0:0:1::/64", "2001::/32", "2001:2::/48",
	"2001:10::/28", "2001:20::/28", "2001:db8::/32", "2002::/16",
	"3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
}

// Enforcement-mode status conditions, in machine order. The agent Pod is
// never created before ConditionBrokerPolicyReady and
// ConditionEgressCAPublished both hold.
const (
	ConditionBrokerPolicyReady = "BrokerPolicyReady"
	ConditionEgressdCreated    = "EgressdCreated"
	ConditionEgressdReady      = "EgressdReady"
	ConditionEgressCAPublished = "EgressCAPublished"
	ConditionWorkspaceReady    = "WorkspaceReady"
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

	Scheme           *runtime.Scheme
	Now              func() metav1.Time
	BrokerHTTPClient *http.Client
}

type preparedPlaceholderFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Mode    string `json:"mode"`
}

type placeholderFilesResponse struct {
	OK      bool                      `json:"ok"`
	Files   []preparedPlaceholderFile `json:"files"`
	Error   string                    `json:"error"`
	Message string                    `json:"message"`
}

type podCredentialProjectionState struct {
	AutomountServiceAccountToken *bool                         `json:"automountServiceAccountToken,omitempty"`
	ServiceAccountName           string                        `json:"serviceAccountName,omitempty"`
	SecurityContext              *corev1.PodSecurityContext    `json:"securityContext,omitempty"`
	Volumes                      []podCredentialVolumeState    `json:"volumes,omitempty"`
	InitContainers               []podCredentialContainerState `json:"initContainers,omitempty"`
	Containers                   []podCredentialContainerState `json:"containers,omitempty"`
}

type podCredentialContainerState struct {
	Name            string                          `json:"name"`
	Env             []podCredentialEnvState         `json:"env,omitempty"`
	VolumeMounts    []podCredentialVolumeMountState `json:"volumeMounts,omitempty"`
	SecurityContext *corev1.SecurityContext         `json:"securityContext,omitempty"`
	RestartPolicy   *corev1.ContainerRestartPolicy  `json:"restartPolicy,omitempty"`
}

type podCredentialEnvState struct {
	Name       string `json:"name"`
	SecretName string `json:"secretName,omitempty"`
	SecretKey  string `json:"secretKey,omitempty"`
	Optional   *bool  `json:"optional,omitempty"`
}

type podCredentialVolumeState struct {
	Name      string                        `json:"name"`
	Secret    *corev1.SecretVolumeSource    `json:"secret,omitempty"`
	Projected *corev1.ProjectedVolumeSource `json:"projected,omitempty"`
}

type podCredentialVolumeMountState struct {
	Name        string `json:"name"`
	MountPath   string `json:"mountPath"`
	ReadOnly    bool   `json:"readOnly,omitempty"`
	SubPath     string `json:"subPath,omitempty"`
	SubPathExpr string `json:"subPathExpr,omitempty"`
}

const defaultProjectedVolumeMode int32 = 420

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
		return r.reconcileTerminalResourceCleanup(ctx, &agentRun)
	}
	existingPod, err := r.getOwnedAgentPod(ctx, &agentRun)
	if err != nil {
		return ctrl.Result{}, err
	}
	if existingPod != nil {
		if err := r.ensureImmutablePodSecurityState(ctx, &agentRun, existingPod); err != nil {
			return ctrl.Result{}, err
		}
	}
	conditionsChanged := false
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
	if InitializeAgentRunStatus(&agentRun) {
		conditionsChanged = true
	}
	workspaceResult, workspaceReferenceable, workspaceChanged, err := r.reconcileWorkspacePVC(ctx, &agentRun)
	conditionsChanged = conditionsChanged || workspaceChanged
	if err != nil || !workspaceReferenceable {
		if conditionsChanged {
			if statusErr := r.Status().Update(ctx, &agentRun); statusErr != nil {
				return ctrl.Result{}, fmt.Errorf("update AgentRun workspace status: %w", statusErr)
			}
		}
		return workspaceResult, err
	}

	if err := r.reconcileBrokerTokenSecret(ctx, &agentRun); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.reconcileEgressTokenSecret(ctx, &agentRun); err != nil {
		return ctrl.Result{}, err
	}
	if !AgentRunLiteralZeroSecret(&agentRun) {
		if err := r.reconcileCallbackTokenSecret(ctx, &agentRun); err != nil {
			return ctrl.Result{}, err
		}
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
	var preparedFiles []preparedPlaceholderFile
	if AgentRunLiteralZeroSecret(&agentRun) {
		preparedFiles, err = r.preparePlaceholderFiles(ctx, &agentRun)
		if err != nil {
			return ctrl.Result{}, err
		}
	}
	if err := r.reconcileAgentConfigMap(ctx, &agentRun, preparedFiles); err != nil {
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
	if SyncAgentRunLifecycleFromPodTermination(&agentRun, pod, r.now()) {
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
		return r.reconcileTerminalResourceCleanup(ctx, &agentRun)
	}
	deadlineResult, deadlineExceeded, err = r.reconcileActiveDeadline(ctx, &agentRun)
	if deadlineExceeded || err != nil {
		return deadlineResult, err
	}
	return earliestRequeue(deadlineResult, workspaceResult), nil
}

func earliestRequeue(first, second ctrl.Result) ctrl.Result {
	if second.RequeueAfter > 0 && (first.RequeueAfter == 0 || second.RequeueAfter < first.RequeueAfter) {
		first.RequeueAfter = second.RequeueAfter
	}
	return first
}

// SetupWithManager registers the AgentRun controller with the manager.
func (r *AgentRunReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := ctrl.NewControllerManagedBy(mgr).
		For(&nvtv1alpha1.AgentRun{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.Pod{}).
		Owns(&corev1.PersistentVolumeClaim{}).
		Owns(&corev1.Service{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Watches(
			&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.agentRunsForBrokerAgentsConfigMap),
			builder.WithPredicates(predicate.NewPredicateFuncs(isBrokerAgentsConfigMap)),
		).
		WithOptions(controller.Options{MaxConcurrentReconciles: agentRunMaxConcurrentReconciles()}).
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

func (r *AgentRunReconciler) reconcileTerminalResourceCleanup(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) (ctrl.Result, error) {
	if agentRun.Status.Phase == nvtv1alpha1.AgentRunPhaseDeadlineExceeded {
		complete, err := r.deleteTerminalOperationalResources(ctx, agentRun)
		if err != nil || !complete {
			return ctrl.Result{RequeueAfter: terminalResourceCleanupRequeue}, err
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

	complete, err := r.deleteTerminalOperationalResources(ctx, agentRun)
	if err != nil || !complete {
		return ctrl.Result{RequeueAfter: terminalResourceCleanupRequeue}, err
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
	result, err := r.reconcileTerminalResourceCleanup(ctx, agentRun)
	return result, true, err
}

func (r *AgentRunReconciler) deleteTerminalOperationalResources(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) (bool, error) {
	cleanupErrors := []error{}
	if err := r.removeBrokerAgentsPolicyEntry(ctx, agentRun); err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("revoke terminal AgentRun broker policy: %w", err))
	}

	agentPod, agentPodErr := r.getOwnedTerminalPod(ctx, agentRun, AgentPodName(agentRun.Name), "terminal AgentRun agent Pod")
	if agentPodErr != nil {
		cleanupErrors = append(cleanupErrors, agentPodErr)
	}
	egressdPod, egressdPodErr := r.getOwnedTerminalPod(ctx, agentRun, EgressdPodName(agentRun.Name), "terminal AgentRun egressd Pod")
	if egressdPodErr != nil {
		cleanupErrors = append(cleanupErrors, egressdPodErr)
	}
	// Ownership must be known before deleting either Pod. A foreign same-name
	// Pod leaves the complete workload and its network fence untouched.
	if agentPodErr != nil || egressdPodErr != nil {
		return false, utilerrors.NewAggregate(cleanupErrors)
	}
	podDeleteFailed := false
	for _, pod := range []struct {
		object      *corev1.Pod
		description string
	}{
		{object: agentPod, description: "terminal AgentRun agent Pod"},
		{object: egressdPod, description: "terminal AgentRun egressd Pod"},
	} {
		if pod.object == nil || !pod.object.DeletionTimestamp.IsZero() {
			continue
		}
		if err := r.deleteOwnedObject(ctx, pod.object, pod.description); err != nil {
			cleanupErrors = append(cleanupErrors, err)
			podDeleteFailed = true
		}
	}

	agentPod, agentPodErr = r.getOwnedTerminalPod(ctx, agentRun, AgentPodName(agentRun.Name), "terminal AgentRun agent Pod")
	if agentPodErr != nil {
		cleanupErrors = append(cleanupErrors, agentPodErr)
	}
	egressdPod, egressdPodErr = r.getOwnedTerminalPod(ctx, agentRun, EgressdPodName(agentRun.Name), "terminal AgentRun egressd Pod")
	if egressdPodErr != nil {
		cleanupErrors = append(cleanupErrors, egressdPodErr)
	}
	if podDeleteFailed || agentPod != nil || egressdPod != nil || agentPodErr != nil || egressdPodErr != nil {
		return false, utilerrors.NewAggregate(cleanupErrors)
	}

	resources := []struct {
		object      client.Object
		name        string
		description string
	}{
		{object: &corev1.PersistentVolumeClaim{}, name: WorkspacePVCName(agentRun.Name), description: "terminal AgentRun workspace PVC"},
		{object: &corev1.Service{}, name: EgressdServiceName(agentRun.Name), description: "terminal AgentRun egressd Service"},
		{object: &networkingv1.NetworkPolicy{}, name: AgentNetworkPolicyName(agentRun.Name), description: "terminal AgentRun agent NetworkPolicy"},
		{object: &networkingv1.NetworkPolicy{}, name: EgressdNetworkPolicyName(agentRun.Name), description: "terminal AgentRun egressd NetworkPolicy"},
		{object: &corev1.ConfigMap{}, name: AgentConfigMapName(agentRun.Name), description: "terminal AgentRun agent config ConfigMap"},
		{object: &corev1.ConfigMap{}, name: EgressdConfigMapName(agentRun.Name), description: "terminal AgentRun egressd config ConfigMap"},
		{object: &corev1.ConfigMap{}, name: EgressCAConfigMapName(agentRun.Name), description: "terminal AgentRun egress CA ConfigMap"},
		{object: &corev1.Secret{}, name: BrokerTokenSecretName(agentRun.Name), description: "terminal AgentRun broker token Secret"},
		{object: &corev1.Secret{}, name: EgressTokenSecretName(agentRun.Name), description: "terminal AgentRun egress token Secret"},
		{object: &corev1.Secret{}, name: CallbackTokenSecretName(agentRun.Name), description: "terminal AgentRun callback token Secret"},
		{object: &corev1.Secret{}, name: EgressCASecretName(agentRun.Name), description: "terminal AgentRun egress CA keypair Secret"},
	}
	for _, resource := range resources {
		if err := r.deleteOwnedObjectByName(ctx, agentRun, resource.object, resource.name, resource.description); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}

	return true, utilerrors.NewAggregate(cleanupErrors)
}

func (r *AgentRunReconciler) getOwnedTerminalPod(
	ctx context.Context,
	agentRun *nvtv1alpha1.AgentRun,
	name string,
	description string,
) (*corev1.Pod, error) {
	pod := &corev1.Pod{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: agentRun.Namespace, Name: name}, pod); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get %s for cleanup: %w", description, err)
	}
	if !metav1.IsControlledBy(pod, agentRun) {
		return nil, fmt.Errorf("%s %s/%s exists but is not controlled by AgentRun %s", description, pod.Namespace, pod.Name, agentRun.Name)
	}
	return pod, nil
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
	return r.deleteOwnedObjectByName(ctx, agentRun, &corev1.Pod{}, name, description)
}

func (r *AgentRunReconciler) deleteOwnedObjectByName(
	ctx context.Context,
	agentRun *nvtv1alpha1.AgentRun,
	object client.Object,
	name string,
	description string,
) error {
	key := client.ObjectKey{Namespace: agentRun.Namespace, Name: name}
	if err := r.Get(ctx, key, object); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("get %s for cleanup: %w", description, err)
	}
	if !metav1.IsControlledBy(object, agentRun) {
		return fmt.Errorf("%s %s/%s exists but is not controlled by AgentRun %s", description, object.GetNamespace(), object.GetName(), agentRun.Name)
	}
	return r.deleteOwnedObject(ctx, object, description)
}

func (r *AgentRunReconciler) deleteOwnedObject(ctx context.Context, object client.Object, description string) error {
	deleteOptions := []client.DeleteOption{}
	if uid := object.GetUID(); uid != "" {
		deleteOptions = append(deleteOptions, client.Preconditions{UID: &uid})
	}
	if err := r.Delete(ctx, object, deleteOptions...); err != nil && !errors.IsNotFound(err) {
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

func (r *AgentRunReconciler) reconcileAgentConfigMap(ctx context.Context, agentRun *nvtv1alpha1.AgentRun, preparedFiles []preparedPlaceholderFile) error {
	desired, err := DesiredAgentConfigMap(agentRun, r.Scheme)
	if err != nil {
		return err
	}
	if AgentRunLiteralZeroSecret(agentRun) {
		if len(preparedFiles) > 0 {
			encodedPreparedFiles, marshalErr := json.Marshal(preparedFiles)
			if marshalErr != nil {
				return fmt.Errorf("marshal prepared placeholder files: %w", marshalErr)
			}
			if desired.Data == nil {
				desired.Data = map[string]string{}
			}
			desired.Data[preparedPlaceholderFilesKey] = string(encodedPreparedFiles)
		}
		if desired.Annotations == nil {
			desired.Annotations = map[string]string{}
		}
		desired.Annotations[agentConfigPlaceholderCacheAnnotation] = agentConfigPlaceholderCacheKey(agentRun)
		rendered, renderErr := InjectPreparedPlaceholderFiles(desired.Data[agentConfigKey], preparedFiles)
		if renderErr != nil {
			return renderErr
		}
		desired.Data[agentConfigKey] = rendered
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      desired.Name,
			Namespace: desired.Namespace,
		},
	}
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, configMap, func() error {
		configMap.Labels = desired.Labels
		configMap.Annotations = desired.Annotations
		configMap.OwnerReferences = desired.OwnerReferences
		configMap.Data = desired.Data
		return nil
	})
	if err != nil {
		return fmt.Errorf("reconcile AgentRun config ConfigMap: %w", err)
	}

	return nil
}

func (r *AgentRunReconciler) preparePlaceholderFiles(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) ([]preparedPlaceholderFile, error) {
	providers := []string{}
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		if AgentRunGrantMaterialization(grant) == nvtv1alpha1.AgentRunGrantPlaceholderFile {
			providers = append(providers, grant.Provider)
		}
	}
	if len(providers) == 0 {
		return nil, nil
	}
	cacheKey := agentConfigPlaceholderCacheKey(agentRun)
	existing := &corev1.ConfigMap{}
	configKey := client.ObjectKey{Namespace: agentRun.Namespace, Name: AgentConfigMapName(agentRun.Name)}
	if err := r.Get(ctx, configKey, existing); err == nil {
		if metav1.IsControlledBy(existing, agentRun) && existing.Annotations[agentConfigPlaceholderCacheAnnotation] == cacheKey {
			if raw := existing.Data[preparedPlaceholderFilesKey]; strings.TrimSpace(raw) != "" {
				files, loadErr := loadPreparedPlaceholderFiles(raw)
				if loadErr != nil {
					return nil, fmt.Errorf("load cached prepared placeholder files from ConfigMap %s/%s: %w", existing.Namespace, existing.Name, loadErr)
				}
				if len(files) == 0 {
					return nil, fmt.Errorf("cached AgentRun config ConfigMap %s/%s contains no prepared placeholder files", existing.Namespace, existing.Name)
				}
				return files, nil
			}
		}
	} else if !errors.IsNotFound(err) {
		return nil, fmt.Errorf("get AgentRun config ConfigMap for placeholder cache: %w", err)
	}
	secret := &corev1.Secret{}
	secretKey := client.ObjectKey{Namespace: agentRun.Namespace, Name: BrokerTokenSecretName(agentRun.Name)}
	if err := r.Get(ctx, secretKey, secret); err != nil {
		return nil, fmt.Errorf("get control-plane broker token for placeholder preparation: %w", err)
	}
	token := secret.Data[brokerTokenKey]
	if len(token) == 0 {
		return nil, fmt.Errorf("control-plane broker token Secret %s/%s is missing %s", secretKey.Namespace, secretKey.Name, brokerTokenKey)
	}
	httpClient, err := r.placeholderHTTPClient(ctx, agentRun.Namespace)
	if err != nil {
		return nil, err
	}
	prepCtx, cancel := context.WithTimeout(ctx, placeholderPreparationTimeout())
	defer cancel()
	prepared := []preparedPlaceholderFile{}
	seenPaths := map[string]string{}
	for _, provider := range providers {
		payload, err := json.Marshal(map[string]string{"provider": provider})
		if err != nil {
			return nil, fmt.Errorf("marshal placeholder request for %s: %w", provider, err)
		}
		request, err := http.NewRequestWithContext(prepCtx, http.MethodPost, strings.TrimRight(BrokerURL(), "/")+"/v1/placeholder-files", bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("create placeholder request for %s: %w", provider, err)
		}
		request.Header.Set("Authorization", "Bearer "+string(token))
		request.Header.Set("Content-Type", "application/json")
		response, err := httpClient.Do(request)
		if err != nil {
			return nil, fmt.Errorf("prepare inert placeholder files for %s: %w", provider, err)
		}
		var decoded placeholderFilesResponse
		decodeErr := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&decoded)
		response.Body.Close()
		if decodeErr != nil {
			return nil, fmt.Errorf("decode placeholder response for %s: %w", provider, decodeErr)
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 || !decoded.OK {
			reason := decoded.Error
			if decoded.Message != "" {
				reason = decoded.Message
			}
			return nil, fmt.Errorf("broker denied inert placeholder preparation for %s: %s", provider, reason)
		}
		if len(decoded.Files) == 0 {
			return nil, fmt.Errorf("broker returned no inert placeholder files for %s", provider)
		}
		for _, file := range decoded.Files {
			if err := validatePreparedPlaceholderFile(file); err != nil {
				return nil, fmt.Errorf("invalid inert placeholder file for %s: %w", provider, err)
			}
			if prior, exists := seenPaths[file.Path]; exists {
				return nil, fmt.Errorf("placeholder providers %s and %s both target %s", prior, provider, file.Path)
			}
			seenPaths[file.Path] = provider
			prepared = append(prepared, file)
		}
	}
	return prepared, nil
}

func agentConfigPlaceholderCacheKey(agentRun *nvtv1alpha1.AgentRun) string {
	payload := map[string]any{
		"agent-config": string(agentRun.Spec.Agent.Config.Raw),
		"egress": map[string]any{
			"mode":        string(AgentRunEgressMode(agentRun)),
			"enforcement": agentRun.Spec.EgressEnforcement,
			"transport":   string(AgentRunEgressTransport(agentRun)),
			"forward":     agentRun.Spec.EgressForwardProxy,
		},
		"grants": normalizePlaceholderCacheGrants(agentRun),
	}
	rendered, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(rendered)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func placeholderPreparationTimeout() time.Duration {
	return 4 * time.Second
}

func normalizePlaceholderCacheGrants(agentRun *nvtv1alpha1.AgentRun) []map[string]any {
	normalized := make([]map[string]any, 0, len(AgentRunBrokerGrants(agentRun.Spec.Broker)))
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		normalized = append(normalized, map[string]any{
			"provider":        grant.Provider,
			"materialization": string(AgentRunGrantMaterialization(grant)),
			"git":             grant.Git,
			"egress-hosts":    append([]string(nil), grant.EgressHosts...),
		})
	}
	return normalized
}

func loadPreparedPlaceholderFiles(raw string) ([]preparedPlaceholderFile, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	files := []preparedPlaceholderFile{}
	if err := json.Unmarshal([]byte(raw), &files); err != nil {
		return nil, fmt.Errorf("decode prepared placeholder files JSON: %w", err)
	}
	for _, file := range files {
		if err := validatePreparedPlaceholderFile(file); err != nil {
			return nil, err
		}
	}
	return files, nil
}

func (r *AgentRunReconciler) ensureImmutablePodSecurityState(ctx context.Context, agentRun *nvtv1alpha1.AgentRun, existingPod *corev1.Pod) error {
	desiredPod, err := desiredAgentPodForSecurityProjection(agentRun, r.Scheme)
	if err != nil {
		return err
	}
	desiredState, err := podCredentialProjectionSignature(agentRun, desiredPod)
	if err != nil {
		return err
	}
	actualState, err := podCredentialProjectionSignature(agentRun, existingPod)
	if err != nil {
		reason := err.Error()
		if setErr := r.setAgentRunFailed(ctx, agentRun, reason); setErr != nil {
			return setErr
		}
		if delErr := r.deleteOwnedPodByName(ctx, agentRun, AgentPodName(agentRun.Name), reason); delErr != nil {
			return delErr
		}
		if delErr := r.deleteOwnedPodByName(ctx, agentRun, EgressdPodName(agentRun.Name), reason+" (egressd)"); delErr != nil {
			return delErr
		}
		return fmt.Errorf("%s", reason)
	}
	if desiredState != actualState {
		reason := "security-sensitive AgentRun fields changed after Pod creation"
		if err := r.setAgentRunFailed(ctx, agentRun, reason); err != nil {
			return err
		}
		if err := r.deleteOwnedPodByName(ctx, agentRun, AgentPodName(agentRun.Name), reason); err != nil {
			return err
		}
		if err := r.deleteOwnedPodByName(ctx, agentRun, EgressdPodName(agentRun.Name), reason+" (egressd)"); err != nil {
			return err
		}
		return fmt.Errorf("security-sensitive AgentRun fields changed after Pod creation")
	}
	if existingPod.Annotations != nil && existingPod.Annotations[agentPodSecurityStateAnnotation] == desiredState {
		return nil
	}
	updated := existingPod.DeepCopy()
	if updated.Annotations == nil {
		updated.Annotations = map[string]string{}
	}
	updated.Annotations[agentPodSecurityStateAnnotation] = desiredState
	if err := r.Update(ctx, updated); err != nil {
		return fmt.Errorf("patch AgentRun Pod security annotation: %w", err)
	}
	return nil
}

func agentRunMaxConcurrentReconciles() int {
	return 2
}

func podCredentialProjectionSignature(agentRun *nvtv1alpha1.AgentRun, pod *corev1.Pod) (string, error) {
	state := podCredentialProjectionState{
		AutomountServiceAccountToken: pod.Spec.AutomountServiceAccountToken,
		ServiceAccountName:           canonicalServiceAccountName(pod.Spec.ServiceAccountName),
		SecurityContext:              pod.Spec.SecurityContext,
		Volumes:                      make([]podCredentialVolumeState, 0, len(pod.Spec.Volumes)),
		InitContainers:               make([]podCredentialContainerState, 0, len(pod.Spec.InitContainers)),
		Containers:                   make([]podCredentialContainerState, 0, len(pod.Spec.Containers)),
	}
	if emptyPodSecurityContext(state.SecurityContext) {
		state.SecurityContext = nil
	}
	credentialVolumes := map[string]bool{}
	for _, volume := range pod.Spec.Volumes {
		switch {
		case volume.Name == brokerCAVolumeName && volume.Secret != nil:
			continue
		case volume.Secret != nil:
			credentialVolumes[volume.Name] = true
			state.Volumes = append(state.Volumes, podCredentialVolumeState{Name: volume.Name, Secret: normalizeSecretVolumeSource(volume.Secret)})
		case volume.Projected != nil:
			if projectedVolumeHasServiceAccountToken(volume.Projected) && AgentRunLiteralZeroSecret(agentRun) {
				return "", fmt.Errorf("literal-zero-secret AgentRun Pod must not project a service-account token volume")
			}
			projected := normalizeProjectedVolumeSource(volume.Projected)
			if projected == nil {
				continue
			}
			credentialVolumes[volume.Name] = true
			state.Volumes = append(state.Volumes, podCredentialVolumeState{Name: volume.Name, Projected: projected})
		}
	}
	for _, container := range pod.Spec.InitContainers {
		state.InitContainers = append(state.InitContainers, podCredentialContainerState{
			Name:            container.Name,
			Env:             credentialEnvState(container.Env),
			VolumeMounts:    credentialVolumeMountState(container.VolumeMounts, credentialVolumes),
			SecurityContext: normalizeSecurityContext(container.SecurityContext),
			RestartPolicy:   container.RestartPolicy,
		})
	}
	for _, container := range pod.Spec.Containers {
		state.Containers = append(state.Containers, podCredentialContainerState{
			Name:            container.Name,
			Env:             credentialEnvState(container.Env),
			VolumeMounts:    credentialVolumeMountState(container.VolumeMounts, credentialVolumes),
			SecurityContext: normalizeSecurityContext(container.SecurityContext),
		})
	}
	rendered, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("marshal pod credential projection signature: %w", err)
	}
	sum := sha256.Sum256(rendered)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalServiceAccountName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "default"
	}
	return name
}

func emptyPodSecurityContext(sc *corev1.PodSecurityContext) bool {
	if sc == nil {
		return true
	}
	zero := corev1.PodSecurityContext{}
	return reflect.DeepEqual(*sc, zero)
}

func normalizeSecurityContext(sc *corev1.SecurityContext) *corev1.SecurityContext {
	if sc == nil {
		return nil
	}
	if reflect.DeepEqual(*sc, corev1.SecurityContext{}) {
		return nil
	}
	copy := sc.DeepCopy()
	return copy
}

func normalizeSecretVolumeSource(src *corev1.SecretVolumeSource) *corev1.SecretVolumeSource {
	if src == nil {
		return nil
	}
	copy := src.DeepCopy()
	if copy.DefaultMode == nil {
		copy.DefaultMode = ptrTo(defaultProjectedVolumeMode)
	}
	return copy
}

func normalizeProjectedVolumeSource(src *corev1.ProjectedVolumeSource) *corev1.ProjectedVolumeSource {
	if src == nil {
		return nil
	}
	copy := src.DeepCopy()
	copy.Sources = normalizeProjectedVolumeSources(copy.Sources)
	if len(copy.Sources) == 0 {
		return nil
	}
	if copy.DefaultMode == nil {
		copy.DefaultMode = ptrTo(defaultProjectedVolumeMode)
	}
	return copy
}

func normalizeProjectedVolumeSources(sources []corev1.VolumeProjection) []corev1.VolumeProjection {
	normalized := make([]corev1.VolumeProjection, 0, len(sources))
	for _, source := range sources {
		switch {
		case source.Secret != nil:
			copy := *source.Secret
			normalized = append(normalized, corev1.VolumeProjection{Secret: &copy})
		}
	}
	return normalized
}

func projectedVolumeHasServiceAccountToken(src *corev1.ProjectedVolumeSource) bool {
	if src == nil {
		return false
	}
	for _, source := range src.Sources {
		if source.ServiceAccountToken != nil {
			return true
		}
	}
	return false
}

func credentialEnvState(env []corev1.EnvVar) []podCredentialEnvState {
	state := []podCredentialEnvState{}
	for _, variable := range env {
		if variable.ValueFrom == nil || variable.ValueFrom.SecretKeyRef == nil {
			continue
		}
		ref := variable.ValueFrom.SecretKeyRef
		state = append(state, podCredentialEnvState{
			Name:       variable.Name,
			SecretName: ref.Name,
			SecretKey:  ref.Key,
			Optional:   ref.Optional,
		})
	}
	return state
}

func credentialVolumeMountState(volumeMounts []corev1.VolumeMount, credentialVolumes map[string]bool) []podCredentialVolumeMountState {
	state := []podCredentialVolumeMountState{}
	for _, mount := range volumeMounts {
		if !credentialVolumes[mount.Name] {
			continue
		}
		state = append(state, podCredentialVolumeMountState{
			Name:        mount.Name,
			MountPath:   mount.MountPath,
			ReadOnly:    mount.ReadOnly,
			SubPath:     mount.SubPath,
			SubPathExpr: mount.SubPathExpr,
		})
	}
	return state
}

func (r *AgentRunReconciler) placeholderHTTPClient(ctx context.Context, namespace string) (*http.Client, error) {
	if r.BrokerHTTPClient != nil {
		return r.BrokerHTTPClient, nil
	}
	client := &http.Client{}
	if !brokerIsTLS() {
		return client, nil
	}
	secret := &corev1.Secret{}
	if err := r.Get(ctx, clientKeyFor(namespace, BrokerCASecretName()), secret); err != nil {
		return nil, fmt.Errorf("get broker CA Secret for operator placeholder preparation: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(secret.Data[brokerCAKey]) {
		return nil, fmt.Errorf("broker CA Secret %s/%s has no valid %s", namespace, BrokerCASecretName(), brokerCAKey)
	}
	client.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	return client, nil
}

func clientKeyFor(namespace, name string) client.ObjectKey {
	return client.ObjectKey{Namespace: namespace, Name: name}
}

func validatePreparedPlaceholderFile(file preparedPlaceholderFile) error {
	if file.Path == "" || strings.HasPrefix(file.Path, "/") || strings.HasPrefix(file.Path, "\\") {
		return fmt.Errorf("path %q must be relative", file.Path)
	}
	for _, segment := range strings.Split(strings.ReplaceAll(file.Path, "\\", "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("path %q contains traversal", file.Path)
		}
	}
	if file.Mode == "" {
		file.Mode = "0600"
	}
	if len(file.Mode) != 4 || strings.Trim(file.Mode, "01234567") != "" {
		return fmt.Errorf("mode %q is not four-digit octal", file.Mode)
	}
	if !strings.Contains(file.Content, "NVT-PLACEHOLDER-NOT-A-KEY") {
		return fmt.Errorf("content for %s does not contain the inert placeholder", file.Path)
	}
	return nil
}

func InjectPreparedPlaceholderFiles(rendered string, files []preparedPlaceholderFile) (string, error) {
	config := map[string]any{}
	if err := yaml.Unmarshal([]byte(rendered), &config); err != nil {
		return "", fmt.Errorf("inject prepared placeholder files: %w", err)
	}
	if len(files) > 0 {
		preseed, _ := config["preseed"].(map[string]any)
		if preseed == nil {
			preseed = map[string]any{}
		}
		entries, _ := preseed["files"].([]any)
		for _, file := range files {
			mode := file.Mode
			if mode == "" {
				mode = "0600"
			}
			entries = append(entries, map[string]any{
				"path": "$HOME/" + file.Path, "content": file.Content, "mode": mode, "overwrite": true,
			})
		}
		preseed["files"] = entries
		config["preseed"] = preseed
	}
	output, err := yaml.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("render prepared placeholder files: %w", err)
	}
	return string(output), nil
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
	transport := AgentRunEgressTransport(agentRun)
	return (transport == nvtv1alpha1.AgentRunEgressTransportForwardProxy || transport == nvtv1alpha1.AgentRunEgressTransportTransparent) && AgentRunEgressEnforced(agentRun)
}

func AgentRunEgressTransport(agentRun *nvtv1alpha1.AgentRun) nvtv1alpha1.AgentRunEgressTransport {
	if agentRun.Spec.EgressTransport != "" {
		return agentRun.Spec.EgressTransport
	}
	if agentRun.Spec.EgressForwardProxy {
		return nvtv1alpha1.AgentRunEgressTransportForwardProxy
	}
	return nvtv1alpha1.AgentRunEgressTransportRedirect
}

func AgentRunEgressTransparent(agentRun *nvtv1alpha1.AgentRun) bool {
	return AgentRunEgressEnforced(agentRun) && AgentRunEgressTransport(agentRun) == nvtv1alpha1.AgentRunEgressTransportTransparent
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
	hostCounts := map[string]int{}
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
			hostCounts[strings.ToLower(host)]++
		}
	}
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
				RequireCapabilityHint: grant.Git || hostCounts[strings.ToLower(host)] > 1,
			})
		}
	}
	return injects
}

// forwardProxyUpstreamHosts is the set of MITM leaf names the CA must permit.
func forwardProxyUpstreamHosts(agentRun *nvtv1alpha1.AgentRun) []string {
	if !AgentRunEgressForwardProxy(agentRun) {
		return nil
	}
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
	if AgentRunEgressTransparent(agentRun) {
		proxyURL = fmt.Sprintf("http://127.0.0.1:%d", capturedExplicitPort)
	}
	noProxy := forwardProxyNoProxy(agentRun)
	proxyNames := []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"}
	if AgentRunEgressTransparent(agentRun) {
		// Plain HTTP must take the normal TCP path so iptables redirects it to
		// captured's transparent listener. egressd's explicit listener is
		// CONNECT-only; HTTPS keeps the explicit path and provider hints.
		proxyNames = []string{"HTTPS_PROXY", "https_proxy"}
	}
	env := []corev1.EnvVar{}
	for _, name := range proxyNames {
		env = append(env, corev1.EnvVar{Name: name, Value: proxyURL})
	}
	if AgentRunEgressTransparent(agentRun) {
		for _, name := range []string{"HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
			env = append(env, corev1.EnvVar{Name: name, Value: ""})
		}
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
// to mount read-only at the managed egress CA path.
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
			AutomountServiceAccountToken: ptrTo(false),
			RestartPolicy:                corev1.RestartPolicyAlways,
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
// default-deny egress plus kube-dns and the paired egressd. Literal zero-secret
// runs have no direct broker or callback path. No internet CIDR at all — including traffic from
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
			},
		},
	}
	if err := controllerutil.SetControllerReference(agentRun, policy, scheme); err != nil {
		return nil, fmt.Errorf("set agent NetworkPolicy owner: %w", err)
	}
	return policy, nil
}

// DesiredEgressdNetworkPolicy fences the own-Pod egressd: ingress only from
// the paired agent; egress to DNS, the broker, and configured external TCP
// ports (HTTP/HTTPS by default).
//
// The public-CIDR/port egress is a deliberately coarse fence: vanilla
// NetworkPolicy selects by CIDR/port, not hostname. The semantic per-host
// allowlist lives in egressd itself (pinned route upstreams, capability
// injection-hosts, fail-closed CONNECT allowlist) — do not read the public
// CIDR rules as host-scoped. Cluster CIDRs remain excluded; a test/dev-only
// allowInsecureUpstream can instead select an explicitly labelled fixture.
func DesiredEgressdNetworkPolicy(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme) (*networkingv1.NetworkPolicy, error) {
	denyCIDRs, err := DeploymentDenyCIDRs()
	if err != nil {
		return nil, err
	}
	externalPorts, err := ExternalTCPPorts()
	if err != nil {
		return nil, err
	}
	var ipv4Except, ipv6Except []string
	for _, cidr := range denyCIDRs {
		if strings.Contains(cidr, ":") {
			ipv6Except = append(ipv6Except, cidr)
		} else {
			ipv4Except = append(ipv4Except, cidr)
		}
	}
	egressRules := []networkingv1.NetworkPolicyEgressRule{dnsPolicyEgressRule(), brokerPolicyEgressRule()}
	// Test/dev-only explicitly configured in-cluster upstreams get a narrow
	// Pod-selector exception. External-looking fixture names must opt in by
	// carrying the hash label; blind tunnels never receive this exception.
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		if !grant.AllowInsecureUpstream {
			continue
		}
		for _, upstream := range grant.EgressHosts {
			host, portText, err := net.SplitHostPort(upstream)
			if err != nil {
				continue
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				continue
			}
			labels := map[string]string{"nvt.dev/egress-host": egressHostLabel(host)}
			if strings.HasSuffix(host, ".svc.cluster.local") {
				labels = map[string]string{"app.kubernetes.io/name": strings.Split(host, ".")[0]}
			}
			egressRules = append(egressRules, networkingv1.NetworkPolicyEgressRule{
				To:    []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: labels}}},
				Ports: []networkingv1.NetworkPolicyPort{policyPort(corev1.ProtocolTCP, port)},
			})
		}
	}
	externalPolicyPorts := make([]networkingv1.NetworkPolicyPort, 0, len(externalPorts))
	for _, port := range externalPorts {
		externalPolicyPorts = append(externalPolicyPorts, policyPort(corev1.ProtocolTCP, port))
	}
	egressRules = append(egressRules,
		networkingv1.NetworkPolicyEgressRule{
			To:    []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0", Except: ipv4Except}}},
			Ports: externalPolicyPorts,
		},
		networkingv1.NetworkPolicyEgressRule{
			To:    []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "::/0", Except: ipv6Except}}},
			Ports: externalPolicyPorts,
		},
	)
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
			Egress: egressRules,
		},
	}
	if err := controllerutil.SetControllerReference(agentRun, policy, scheme); err != nil {
		return nil, fmt.Errorf("set egressd NetworkPolicy owner: %w", err)
	}
	return policy, nil
}

func egressHostLabel(host string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(strings.TrimSuffix(host, "."))))
	return hex.EncodeToString(digest[:16])
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
		TransparentMode     bool                       `json:"transparent_mode,omitempty"`
		AllowUnmatchedHosts bool                       `json:"allow_unmatched_hosts"`
		AllowPorts          []int                      `json:"allow_ports"`
		DenyCIDRs           []string                   `json:"deny_cidrs,omitempty"`
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
		denyCIDRs, err := DeploymentDenyCIDRs()
		if err != nil {
			return "", err
		}
		externalPorts, err := ExternalTCPPorts()
		if err != nil {
			return "", err
		}
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
			TransparentMode:     AgentRunEgressTransparent(agentRun),
			AllowUnmatchedHosts: true,
			AllowPorts:          externalPorts,
			DenyCIDRs:           denyCIDRs,
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

func desiredAgentPodForSecurityProjection(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme) (*corev1.Pod, error) {
	return buildDesiredAgentPod(agentRun, scheme, true)
}

// AgentRunWorkspaceMode returns the effective workspace mode. An omitted mode
// retains the historical ephemeral behavior.
func AgentRunWorkspaceMode(agentRun *nvtv1alpha1.AgentRun) nvtv1alpha1.AgentRunWorkspaceMode {
	if agentRun.Spec.Workspace.Mode == "" {
		return nvtv1alpha1.AgentRunWorkspaceEphemeral
	}
	return agentRun.Spec.Workspace.Mode
}

// ValidateAgentRunWorkspace validates the intentionally narrow storage API.
// Persistent storage is incompatible with file-bundle grants: those grants
// materialize usable credentials in the container and must never survive a Pod.
func ValidateAgentRunWorkspace(agentRun *nvtv1alpha1.AgentRun) error {
	workspace := agentRun.Spec.Workspace
	switch AgentRunWorkspaceMode(agentRun) {
	case nvtv1alpha1.AgentRunWorkspaceEphemeral:
		if workspace.Size != nil || workspace.StorageClassName != "" {
			return fmt.Errorf("spec.workspace size and storageClassName require mode Persistent")
		}
	case nvtv1alpha1.AgentRunWorkspacePersistent:
		if workspace.Size == nil || workspace.Size.Sign() <= 0 {
			return fmt.Errorf("spec.workspace.size must be a positive Kubernetes resource quantity for mode Persistent")
		}
		if workspace.StorageClassName != "" {
			if strings.TrimSpace(workspace.StorageClassName) != workspace.StorageClassName {
				return fmt.Errorf("spec.workspace.storageClassName must be normalized")
			}
			if problems := utilvalidation.IsDNS1123Subdomain(workspace.StorageClassName); len(problems) != 0 {
				return fmt.Errorf("spec.workspace.storageClassName must be a valid DNS subdomain")
			}
		}
		for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
			if AgentRunGrantMaterialization(grant) == nvtv1alpha1.AgentRunGrantFileBundle {
				return fmt.Errorf("persistent workspace is incompatible with broker grant %s materialization file-bundle", grant.Provider)
			}
		}
	default:
		return fmt.Errorf("spec.workspace.mode must be Ephemeral or Persistent, got %q", workspace.Mode)
	}
	return nil
}

// WorkspacePVCName is the stable claim name for one persistent AgentRun.
func WorkspacePVCName(agentRunName string) string {
	return agentRunName + "-workspace"
}

// DesiredWorkspacePVC renders the single lifecycle-scoped persistent claim.
func DesiredWorkspacePVC(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme) (*corev1.PersistentVolumeClaim, error) {
	if err := ValidateAgentRunWorkspace(agentRun); err != nil {
		return nil, err
	}
	if AgentRunWorkspaceMode(agentRun) != nvtv1alpha1.AgentRunWorkspacePersistent {
		return nil, fmt.Errorf("persistent workspace PVC requested for non-persistent AgentRun")
	}
	volumeMode := corev1.PersistentVolumeFilesystem
	claim := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      WorkspacePVCName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    agentRunLabels(agentRun.Name),
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			VolumeMode:  &volumeMode,
			Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{
				corev1.ResourceStorage: agentRun.Spec.Workspace.Size.DeepCopy(),
			}},
		},
	}
	if agentRun.Spec.Workspace.StorageClassName != "" {
		claim.Spec.StorageClassName = ptrTo(agentRun.Spec.Workspace.StorageClassName)
	}
	if err := controllerutil.SetControllerReference(agentRun, claim, scheme); err != nil {
		return nil, fmt.Errorf("set workspace PVC owner: %w", err)
	}
	return claim, nil
}

func (r *AgentRunReconciler) reconcileWorkspacePVC(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) (ctrl.Result, bool, bool, error) {
	if err := ValidateAgentRunWorkspace(agentRun); err != nil {
		changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionFalse, "InvalidWorkspace", err.Error())
		return ctrl.Result{}, false, changed, err
	}
	if AgentRunWorkspaceMode(agentRun) == nvtv1alpha1.AgentRunWorkspaceEphemeral {
		return ctrl.Result{}, true, false, nil
	}

	desired, err := DesiredWorkspacePVC(agentRun, r.Scheme)
	if err != nil {
		return ctrl.Result{}, false, false, err
	}
	claim := &corev1.PersistentVolumeClaim{}
	key := client.ObjectKeyFromObject(desired)
	err = r.Get(ctx, key, claim)
	if errors.IsNotFound(err) {
		if err := r.Create(ctx, desired); err != nil {
			return ctrl.Result{}, false, false, fmt.Errorf("create workspace PVC: %w", err)
		}
		changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionFalse, "WorkspacePending", "waiting for persistent workspace claim to bind")
		// The claim now exists and is safe for a consuming Pod to reference.
		// This is required for WaitForFirstConsumer StorageClasses to provision.
		return ctrl.Result{RequeueAfter: workspacePVCReadyRequeue}, true, changed, nil
	}
	if err != nil {
		return ctrl.Result{}, false, false, fmt.Errorf("get workspace PVC: %w", err)
	}
	if !metav1.IsControlledBy(claim, agentRun) {
		err := fmt.Errorf("workspace PVC %s/%s exists but is not controlled by AgentRun %s", claim.Namespace, claim.Name, agentRun.Name)
		changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionFalse, "WorkspaceOwnershipConflict", err.Error())
		return ctrl.Result{}, false, changed, err
	}
	if err := validateWorkspacePVCSpec(claim, desired); err != nil {
		changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionFalse, "WorkspaceSpecConflict", err.Error())
		return ctrl.Result{}, false, changed, err
	}
	labelsChanged := false
	if claim.Labels == nil {
		claim.Labels = map[string]string{}
	}
	for key, value := range desired.Labels {
		if claim.Labels[key] != value {
			claim.Labels[key] = value
			labelsChanged = true
		}
	}
	if labelsChanged {
		if err := r.Update(ctx, claim); err != nil {
			return ctrl.Result{}, false, false, fmt.Errorf("update workspace PVC labels: %w", err)
		}
	}
	if claim.Status.Phase == corev1.ClaimLost {
		err := fmt.Errorf("workspace PVC %s/%s is Lost and will not be replaced automatically", claim.Namespace, claim.Name)
		changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionFalse, "WorkspaceLost", err.Error())
		return ctrl.Result{}, false, changed, err
	}
	if claim.Status.Phase != corev1.ClaimBound {
		changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionFalse, "WorkspacePending", "waiting for persistent workspace claim to bind")
		return ctrl.Result{RequeueAfter: workspacePVCReadyRequeue}, true, changed, nil
	}
	changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionTrue, "WorkspaceReady", "persistent workspace claim is bound")
	return ctrl.Result{}, true, changed, nil
}

func validateWorkspacePVCSpec(actual, desired *corev1.PersistentVolumeClaim) error {
	if !reflect.DeepEqual(actual.Spec.AccessModes, desired.Spec.AccessModes) ||
		!reflect.DeepEqual(actual.Spec.VolumeMode, desired.Spec.VolumeMode) ||
		actual.Spec.Selector != nil || actual.Spec.DataSource != nil || actual.Spec.DataSourceRef != nil ||
		len(actual.Spec.Resources.Limits) != 0 || len(actual.Spec.Resources.Requests) != 1 {
		return fmt.Errorf("workspace PVC %s/%s has immutable storage settings that differ from spec.workspace", actual.Namespace, actual.Name)
	}
	// When storageClassName is omitted, the cluster's defaulting admission may
	// populate the chosen class on the stored PVC. An explicitly requested class
	// must still match exactly.
	if desired.Spec.StorageClassName != nil && !reflect.DeepEqual(actual.Spec.StorageClassName, desired.Spec.StorageClassName) {
		return fmt.Errorf("workspace PVC %s/%s has immutable storage settings that differ from spec.workspace", actual.Namespace, actual.Name)
	}
	actualSize := actual.Spec.Resources.Requests[corev1.ResourceStorage]
	desiredSize := desired.Spec.Resources.Requests[corev1.ResourceStorage]
	if actualSize.Cmp(desiredSize) != 0 {
		return fmt.Errorf("workspace PVC %s/%s size differs from immutable spec.workspace.size", actual.Namespace, actual.Name)
	}
	return nil
}

// DesiredAgentPod returns the create-once Pod spec for an AgentRun.
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
	runtimeAuthMountPath, err := RuntimeAuthMountPath(agentRun)
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
			{Name: workspaceVolumeName, MountPath: workspaceMountPath, SubPath: workspaceSubPath(agentRun)},
		},
	})
	if AgentRunEgressTransparent(agentRun) {
		const rules = `set -eu
exclude_v4=""
exclude_v6=""
for host in $NVT_CAPTURE_EXCLUDE_HOSTS; do
  for ip in $(getent ahosts "$host" | awk '{print $1}' | sort -u); do
    case "$ip" in *:*) exclude_v6="$exclude_v6 $ip" ;; *) exclude_v4="$exclude_v4 $ip" ;; esac
  done
done
iptables -t nat -N NVT_CAPTURE 2>/dev/null || iptables -t nat -F NVT_CAPTURE
iptables -t nat -A NVT_CAPTURE -d 127.0.0.0/8 -j RETURN
for ip in $exclude_v4; do iptables -t nat -A NVT_CAPTURE -d "$ip/32" -j RETURN; done
iptables -t nat -A NVT_CAPTURE -m owner --uid-owner 65532 -j RETURN
iptables -t nat -A NVT_CAPTURE -p tcp -j REDIRECT --to-ports 15001
iptables -t nat -C OUTPUT -j NVT_CAPTURE 2>/dev/null || iptables -t nat -I OUTPUT 1 -j NVT_CAPTURE
iptables -t nat -N NVT_DIND 2>/dev/null || iptables -t nat -F NVT_DIND
for ip in $exclude_v4; do iptables -t nat -A NVT_DIND -d "$ip/32" -j RETURN; done
iptables -t nat -A NVT_DIND -i docker0 -p tcp -j REDIRECT --to-ports 15001
iptables -t nat -C PREROUTING -j NVT_DIND 2>/dev/null || iptables -t nat -I PREROUTING 1 -j NVT_DIND
ip6tables -t nat -N NVT_CAPTURE 2>/dev/null || ip6tables -t nat -F NVT_CAPTURE
ip6tables -t nat -A NVT_CAPTURE -d ::1/128 -j RETURN
for ip in $exclude_v6; do ip6tables -t nat -A NVT_CAPTURE -d "$ip/128" -j RETURN; done
ip6tables -t nat -A NVT_CAPTURE -m owner --uid-owner 65532 -j RETURN
ip6tables -t nat -A NVT_CAPTURE -p tcp -j REDIRECT --to-ports 15001
ip6tables -t nat -C OUTPUT -j NVT_CAPTURE 2>/dev/null || ip6tables -t nat -I OUTPUT 1 -j NVT_CAPTURE
ip6tables -t nat -N NVT_DIND 2>/dev/null || ip6tables -t nat -F NVT_DIND
for ip in $exclude_v6; do ip6tables -t nat -A NVT_DIND -d "$ip/128" -j RETURN; done
ip6tables -t nat -A NVT_DIND -i docker0 -p tcp -j REDIRECT --to-ports 15001
ip6tables -t nat -C PREROUTING -j NVT_DIND 2>/dev/null || ip6tables -t nat -I PREROUTING 1 -j NVT_DIND`
		initContainers = append(initContainers, corev1.Container{
			Name:    "net-init",
			Image:   "docker:27-dind",
			Command: []string{"sh", "-c"},
			Args:    []string{rules},
			Env: []corev1.EnvVar{{
				Name: "NVT_CAPTURE_EXCLUDE_HOSTS",
				Value: strings.Join([]string{
					EgressdServiceName(agentRun.Name),
					"kubernetes.default.svc", "kube-dns.kube-system.svc",
				}, " "),
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
			WorkingDir:      workspaceMountPath,
			Env:             agentEnv,
			VolumeMounts:    agentVolumeMounts,
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

func NetworkPolicyCapable() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("NVT_NETWORK_POLICY_CAPABLE")))
	return value == "1" || value == "true" || value == "yes"
}

// DeploymentDenyCIDRs combines the built-in IANA non-public/transition ranges
// with deployment-specific cluster, Pod, Service, node, and VNet ranges.
func DeploymentDenyCIDRs() ([]string, error) {
	values := append([]string(nil), builtInEgressDenyCIDRs...)
	if configured := strings.TrimSpace(os.Getenv("NVT_EGRESS_DENY_CIDRS")); configured != "" {
		for _, value := range strings.Split(configured, ",") {
			value = strings.TrimSpace(value)
			if value != "" {
				values = append(values, value)
			}
		}
	}
	return normalizeCIDRs(values)
}

func normalizeCIDRs(values []string) ([]string, error) {
	unique := map[string]netip.Prefix{}
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("invalid egress deny CIDR %q: %w", value, err)
		}
		prefix = prefix.Masked()
		unique[prefix.String()] = prefix
	}
	prefixes := make([]netip.Prefix, 0, len(unique))
	for _, prefix := range unique {
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].Addr().BitLen() != prefixes[j].Addr().BitLen() {
			return prefixes[i].Addr().BitLen() < prefixes[j].Addr().BitLen()
		}
		if prefixes[i].Bits() != prefixes[j].Bits() {
			return prefixes[i].Bits() < prefixes[j].Bits()
		}
		if prefixes[i].Addr() != prefixes[j].Addr() {
			return prefixes[i].Addr().Less(prefixes[j].Addr())
		}
		return false
	})
	normalized := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		covered := false
		for _, existing := range normalized {
			if existing.Contains(prefix.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			normalized = append(normalized, prefix)
		}
	}
	result := make([]string, 0, len(normalized))
	for _, prefix := range normalized {
		result = append(result, prefix.String())
	}
	return result, nil
}

// ExternalTCPPorts is the single operator-side port contract rendered into
// both egressd and its NetworkPolicy.
func ExternalTCPPorts() ([]int, error) {
	values := append([]int(nil), defaultExternalTCPPorts...)
	if configured := strings.TrimSpace(os.Getenv("NVT_EGRESS_ALLOWED_TCP_PORTS")); configured != "" {
		values = nil
		for _, raw := range strings.Split(configured, ",") {
			port, err := strconv.Atoi(strings.TrimSpace(raw))
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid external TCP port %q", raw)
			}
			values = append(values, port)
		}
	}
	seen := map[int]bool{}
	result := values[:0]
	for _, port := range values {
		if !seen[port] {
			seen[port] = true
			result = append(result, port)
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("external TCP ports must not be empty")
	}
	sort.Ints(result)
	return result, nil
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
			"NVT_BROKER_URL %s is https but NVT_BROKER_CA_SECRET is not set; trusted broker clients need the broker CA Secret (key %s) to verify the broker",
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
	if _, err := DeploymentDenyCIDRs(); err != nil {
		return err
	}
	if _, err := ExternalTCPPorts(); err != nil {
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
		return fmt.Errorf("spec.egressForwardProxy requires spec.egressEnforcement")
	}
	transport := AgentRunEgressTransport(agentRun)
	switch transport {
	case nvtv1alpha1.AgentRunEgressTransportRedirect,
		nvtv1alpha1.AgentRunEgressTransportForwardProxy,
		nvtv1alpha1.AgentRunEgressTransportTransparent:
	default:
		return fmt.Errorf("spec.egressTransport must be redirect, forward-proxy, or transparent, got %q", transport)
	}
	if agentRun.Spec.EgressTransport != "" && agentRun.Spec.EgressForwardProxy && transport != nvtv1alpha1.AgentRunEgressTransportForwardProxy {
		return fmt.Errorf("spec.egressTransport conflicts with compatibility field spec.egressForwardProxy")
	}
	if transport != nvtv1alpha1.AgentRunEgressTransportRedirect && (!agentRun.Spec.EgressEnforcement || mode != nvtv1alpha1.AgentRunEgressMediated) {
		return fmt.Errorf("spec.egressTransport %s requires spec.egress mediated and spec.egressEnforcement", transport)
	}
	if transport == nvtv1alpha1.AgentRunEgressTransportTransparent && !NetworkPolicyCapable() {
		return fmt.Errorf("spec.egressTransport transparent requires a NetworkPolicy-capable deployment")
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
		if AgentRunEgressForwardProxy(agentRun) && materialization == nvtv1alpha1.AgentRunGrantPlaceholderFile {
			for _, host := range grant.EgressHosts {
				if !validEgressHost(host) {
					return fmt.Errorf("forward-proxy broker grant %s has invalid egressHosts entry %q", grant.Provider, host)
				}
			}
		}
	}
	if AgentRunEgressForwardProxy(agentRun) {
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
		if AgentRunLiteralZeroSecret(agentRun) {
			var err error
			renderedConfig, err = InjectLifecycleTerminationPlugin(renderedConfig, agentRun)
			if err != nil {
				return "", err
			}
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
			"hosts":           append([]string(nil), grant.EgressHosts...),
			"git":             grant.Git,
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
		"transport":   string(AgentRunEgressTransport(agentRun)),
		"placeholder": "NVT-PLACEHOLDER-NOT-A-KEY",
		"grants":      grants,
	}
	if enforced {
		egress["enforcement"] = true
		egress["operator-prepared"] = true
	}
	if forwardProxy {
		// Signals bootstrap to install the CA trust store for proxy-env HTTPS
		// clients (the MITM leaf must be trusted system-wide).
		egress["forward-proxy"] = true
		proxyURL := fmt.Sprintf("http://%s:%d", EgressdServiceName(agentRun.Name), egressForwardProxyPort)
		if AgentRunEgressTransport(agentRun) == nvtv1alpha1.AgentRunEgressTransportTransparent {
			// Keep proxy-aware tools on the credential-less local transport too.
			// captured preserves explicit provider userinfo before relaying to the
			// paired egressd; bootstrap must not overwrite this with the Service.
			proxyURL = fmt.Sprintf("http://127.0.0.1:%d", capturedExplicitPort)
		}
		egress["forward-proxy-url"] = proxyURL
	}
	updated["egress"] = egress
	return updated
}

func AgentRunLiteralZeroSecret(agentRun *nvtv1alpha1.AgentRun) bool {
	return AgentRunEgressMode(agentRun) == nvtv1alpha1.AgentRunEgressMediated && AgentRunEgressEnforced(agentRun)
}

func InjectLifecycleTerminationPlugin(config map[string]any, agentRun *nvtv1alpha1.AgentRun) (map[string]any, error) {
	if agentRun.Spec.Lifecycle == nil || (len(agentRun.Spec.Lifecycle.CompleteOn) == 0 && len(agentRun.Spec.Lifecycle.FailOn) == 0) {
		return config, nil
	}
	plugins, err := agentConfigPlugins(config)
	if err != nil {
		return nil, err
	}
	updatedPlugins := make([]any, 0, len(plugins)+1)
	for _, raw := range plugins {
		plugin, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("render AgentRun agent config: plugins entries must be objects")
		}
		name, _ := plugin["name"].(string)
		if name == lifecycleReporterPlugin {
			return nil, fmt.Errorf("render AgentRun agent config: plugin %q is reserved for enforced zero-secret lifecycle reporting", lifecycleReporterPlugin)
		}
		if name == "event-webhook" && isOperatorLifecycleWebhook(plugin) {
			continue
		}
		if name == "smoke-complete" {
			plugin = cloneStringAnyMap(plugin)
			pluginConfig, _ := plugin["config"].(map[string]any)
			pluginConfig = cloneStringAnyMap(pluginConfig)
			if wait, present := pluginConfig["waitForPlugin"]; !present || wait == "event-webhook" {
				pluginConfig["waitForPlugin"] = lifecycleReporterPlugin
			}
			plugin["config"] = pluginConfig
		}
		updatedPlugins = append(updatedPlugins, plugin)
	}
	updatedPlugins = append(updatedPlugins, map[string]any{
		"name": lifecycleReporterPlugin, "source": "builtin", "when": "after-agent", "restart": "always",
		"config": map[string]any{
			"completeOn":             append([]string(nil), agentRun.Spec.Lifecycle.CompleteOn...),
			"failOn":                 append([]string(nil), agentRun.Spec.Lifecycle.FailOn...),
			"terminationMessagePath": "/dev/termination-log",
		},
	})
	updated := cloneStringAnyMap(config)
	updated["plugins"] = updatedPlugins
	return updated, nil
}

func isOperatorLifecycleWebhook(plugin map[string]any) bool {
	config, _ := plugin["config"].(map[string]any)
	urlValue, _ := config["url"].(string)
	auth, _ := config["auth"].(map[string]any)
	env, _ := auth["env"].(string)
	return strings.Contains(urlValue, "/v1/agentruns/") && strings.HasSuffix(urlValue, "/events") && env == callbackTokenKey
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

// SyncAgentRunLifecycleFromPodTermination consumes the credential-less,
// source-isolated lifecycle path: only this AgentRun's owned Pod status is
// observed, and the event must still match spec.lifecycle.
func SyncAgentRunLifecycleFromPodTermination(agentRun *nvtv1alpha1.AgentRun, pod *corev1.Pod, now metav1.Time) bool {
	if pod == nil || !AgentRunLiteralZeroSecret(agentRun) || IsTerminalAgentRunPhase(agentRun.Status.Phase) {
		return false
	}
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name != "agent" || status.State.Terminated == nil || status.State.Terminated.Message == "" {
			continue
		}
		message := struct {
			Event string `json:"nvtLifecycleEvent"`
		}{}
		if err := json.Unmarshal([]byte(status.State.Terminated.Message), &message); err != nil || message.Event == "" {
			return false
		}
		nextPhase, reason, matched := AgentRunLifecycleTransition(agentRun.Spec.Lifecycle, message.Event)
		if !matched {
			return false
		}
		agentRun.Status.Phase = nextPhase
		agentRun.Status.FinishedAt = &now
		agentRun.Status.Reason = reason
		return true
	}
	return false
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
