package controller

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

const (
	agentConfigKey                        = "agent.yaml"
	preparedPlaceholderFilesKey           = "prepared-placeholder-files.json"
	preparedProviderMetadataKey           = "prepared-provider-metadata.json"
	preparedProviderMetadataPath          = agentConfigVolumeDir + "/" + preparedProviderMetadataKey
	preparedProviderMetadataEnv           = "NVT_PREPARED_PROVIDER_METADATA_FILE"
	profileWorkspaceInstructionsKey       = "profile-workspace-instructions.md"
	profileWorkspaceInstructionsPath      = agentConfigVolumeDir + "/" + profileWorkspaceInstructionsKey
	profileWorkspaceInstructionsEnv       = "NVT_AGENT_PROFILE_INSTRUCTIONS_FILE"
	workflowWorkspaceInstructionsKey      = "workflow-workspace-instructions.md"
	workflowWorkspaceInstructionsPath     = agentConfigVolumeDir + "/" + workflowWorkspaceInstructionsKey
	workflowWorkspaceInstructionsEnv      = "NVT_AGENT_WORKFLOW_INSTRUCTIONS_FILE"
	brandingVolumeName                    = "nvt-branding"
	brandingMountPath                     = "/usr/local/share/nvt-agent/branding"
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
	dindStorageVolumeName                 = "docker-storage"
	dindStorageMountPath                  = "/var/lib/nvt-dind"
	dindDataRoot                          = "/var/lib/docker"
	dindEntrypoint                        = "/usr/local/bin/nvt-dind-entrypoint"
	dindReady                             = "/usr/local/bin/nvt-dind-ready"
	workspacePVCReadyRequeue              = 2 * time.Second
	terminalResourceCleanupRequeue        = 2 * time.Second
	lifecycleReporterPlugin               = "lifecycle-termination"
	agentPodSecurityStateAnnotation       = "nvt.dev/pod-security-state"
	agentConfigPlaceholderCacheAnnotation = "nvt.dev/placeholder-cache-key"
	providerMetadataCacheAnnotation       = "nvt.dev/provider-metadata-cache-key"

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

	brokerAgentsConfigMapName              = "nvt-broker-agents"
	brokerAgentsConfigKey                  = "agents.yaml"
	brokerTokenKey                         = "NVT_BROKER_TOKEN"
	egressTokenKey                         = "NVT_EGRESS_BROKER_TOKEN"
	defaultEgressdImage                    = "nvt-egressd:latest"
	defaultCapturedImage                   = "nvt-captured:latest"
	defaultDindImage                       = "nvt-dind:latest"
	minimumDockerPVCSizeBytes        int64 = 1024 * 1024 * 1024
	defaultDockerPVCSizeBytes        int64 = 20 * 1024 * 1024 * 1024
	maximumDockerPVCSizeBytes        int64 = 1024 * 1024 * 1024 * 1024
	dindImageCapacityPercent               = 90
	dindStartupBudgetSeconds               = 15 * 60
	capturedTransparentPort                = 15001
	capturedExplicitPort                   = 15002
	capturedUID                      int64 = 65532
	callbackTokenKey                       = "NVT_OPERATOR_CALLBACK_TOKEN"
	agentRunFinalizer                      = "nvt.dev/agentrun-broker-policy"
	legacyExternalExecutionFinalizer       = "nvt.dev/agentrun-external-execution"
	legacyGuestEnrollmentFinalizer         = "nvt.dev/agentrun-guest-enrollment"
	legacyExternalExecutionReason          = "spec.execution belongs to the removed external execution stack; delete and recreate this AgentRun"
	legacyExternalDeletionReason           = "legacy external resources require cleanup by the pre-0.8.70 operator or explicit administrator acknowledgement; cleanup finalizers were retained"
	completedLifecycleReason               = "Completed by lifecycle event "
	failedLifecycleReason                  = "Failed by lifecycle event "
	activeDeadlineReason                   = "Active deadline exceeded"
	unexpectedAgentExitReason              = "Agent container terminated unexpectedly"
	generatedTokenByteLength               = 32
	defaultRunRetentionSeconds             = 30 * 24 * 60 * 60
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

func (r *AgentRunReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var agentRun nvtv1alpha1.AgentRun
	if err := r.Get(ctx, req.NamespacedName, &agentRun); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get AgentRun: %w", err)
	}
	if agentRun.Spec.Execution != nil || hasLegacyExternalFinalizer(&agentRun) {
		if !agentRun.DeletionTimestamp.IsZero() {
			if err := r.finalizeLegacyBrokerPolicy(ctx, &agentRun); err != nil {
				return ctrl.Result{}, err
			}
			if err := r.setAgentRunFailed(ctx, &agentRun, legacyExternalDeletionReason); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		if err := r.setAgentRunFailed(ctx, &agentRun, legacyExternalExecutionReason); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if !agentRun.DeletionTimestamp.IsZero() {
		if err := r.finalizeAgentRun(ctx, &agentRun); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if !IsTerminalAgentRunPhase(agentRun.Status.Phase) {
		if err := ValidateRemovedEgressForwardProxy(&agentRun); err != nil {
			return ctrl.Result{}, err
		}
		if err := ValidateAgentRunRuntimeCapabilities(&agentRun); err != nil {
			return ctrl.Result{}, err
		}
		if err := ValidateAgentRunDockerNetworks(&agentRun); err != nil {
			return ctrl.Result{}, err
		}
		if err := ValidateAgentRunWorkspaceInstructions(&agentRun); err != nil {
			return ctrl.Result{}, err
		}
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
	workspaceResult, workspaceReferenceable, workspaceBound, workspaceChanged, err := r.reconcileWorkspacePVC(ctx, &agentRun)
	conditionsChanged = conditionsChanged || workspaceChanged
	if err != nil || !workspaceReferenceable {
		if conditionsChanged {
			if statusErr := r.Status().Update(ctx, &agentRun); statusErr != nil {
				return ctrl.Result{}, fmt.Errorf("update AgentRun workspace status: %w", statusErr)
			}
		}
		return workspaceResult, err
	}
	if AgentRunWorkspaceMode(&agentRun) == nvtv1alpha1.AgentRunWorkspacePersistent {
		if existingPod != nil && !podUsesDockerPVC(existingPod, DockerPVCName(agentRun.Name)) {
			// Pods created before the dedicated Docker claim contract are
			// create-once workloads. Preserve the live session and do not create
			// an unreferenced WaitForFirstConsumer claim. The next normal Pod
			// replacement takes the regular path below and consumes the claim.
			if err := r.reconcileLegacyDockerStorageMigration(ctx, &agentRun); err != nil {
				return ctrl.Result{}, err
			}
		} else {
			dockerResult, dockerReferenceable, dockerChanged, dockerErr := r.reconcileDockerPVC(ctx, &agentRun, workspaceBound)
			conditionsChanged = conditionsChanged || dockerChanged
			if dockerErr != nil || !dockerReferenceable {
				if conditionsChanged {
					if statusErr := r.Status().Update(ctx, &agentRun); statusErr != nil {
						return ctrl.Result{}, fmt.Errorf("update AgentRun persistent storage status: %w", statusErr)
					}
				}
				return dockerResult, dockerErr
			}
			if dockerResult.RequeueAfter > workspaceResult.RequeueAfter {
				workspaceResult = dockerResult
			}
		}
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
	preparedMetadata, err := r.prepareProviderMetadata(ctx, &agentRun)
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := r.reconcileAgentConfigMap(ctx, &agentRun, preparedFiles, preparedMetadata); err != nil {
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

func hasLegacyExternalFinalizer(agentRun *nvtv1alpha1.AgentRun) bool {
	return controllerutil.ContainsFinalizer(agentRun, legacyExternalExecutionFinalizer) ||
		controllerutil.ContainsFinalizer(agentRun, legacyGuestEnrollmentFinalizer)
}

// finalizeLegacyBrokerPolicy revokes the independently managed broker access
// without claiming that the removed external runtime has been cleaned up.
func (r *AgentRunReconciler) finalizeLegacyBrokerPolicy(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) error {
	if !controllerutil.ContainsFinalizer(agentRun, agentRunFinalizer) {
		return nil
	}
	if err := r.removeBrokerAgentsPolicyEntry(ctx, agentRun); err != nil {
		return err
	}
	controllerutil.RemoveFinalizer(agentRun, agentRunFinalizer)
	if err := r.Update(ctx, agentRun); err != nil {
		return fmt.Errorf("remove legacy AgentRun broker-policy finalizer: %w", err)
	}
	return nil
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
		{object: &corev1.PersistentVolumeClaim{}, name: DockerPVCName(agentRun.Name), description: "terminal AgentRun Docker PVC"},
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
func ptrTo[T any](value T) *T {
	return &value
}
