package controller

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
	agentRunLabelKey             = "nvt.dev/agentrun"
	roleLabelKey                 = "nvt.dev/role"
	roleLabelAgent               = "agent"
	roleLabelEgressd             = "egressd"
	egressCAPort                 = 8470
	egressRouteBasePort          = 8471
	egressForwardProxyPort       = 8473 // forward-proxy CONNECT listener (own-Pod)
	egressCACertKey              = "ca.crt"
	egressCAKeyKey               = "ca.key"
	egressCAGenerationAnnotation = "nvt.dev/egress-ca-generation"
	egressCADigestAnnotation     = "nvt.dev/egress-ca-sha256"
	egressCARenewalMargin        = 7 * 24 * time.Hour
	egressCAValidity             = 30 * 24 * time.Hour
	egressdConfigName            = "egressd-config"
	egressdReadyRequeue          = 2 * time.Second

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

var (
	errEgressCARotationInProgress = fmt.Errorf("egress CA rotation in progress")
	errEgressCAValidity           = fmt.Errorf("egress CA validity requires rotation")
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

// Reconcile renders the AgentRun config, creates the agent Pod, and syncs basic Pod-phase status.
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
		// Record a terminal workload before any maintenance path can replace its
		// Pod. In particular, CA rotation must never erase the only durable
		// lifecycle observation and re-execute a completed entrypoint.
		rotationOwnsTermination := egressCARotationIntent(&agentRun) && !existingPod.DeletionTimestamp.IsZero()
		if !rotationOwnsTermination {
			observed := agentRun
			SyncAgentRunLifecycleFromPodTermination(&observed, existingPod, r.now())
			SyncAgentRunStatusFromPod(&observed, existingPod, r.now())
			if IsTerminalAgentRunPhase(observed.Status.Phase) {
				agentRun.Status = observed.Status
				if err := r.Status().Update(ctx, &agentRun); err != nil {
					return ctrl.Result{}, fmt.Errorf("record terminal AgentRun Pod before maintenance: %w", err)
				}
				return r.reconcileTerminalResourceCleanup(ctx, &agentRun)
			}
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
			if err == errEgressCARotationInProgress {
				if r.setRunCondition(&agentRun, ConditionEgressCAPublished, metav1.ConditionFalse, "EgressCARotating", "rotating egress CA and recreating trust consumers") {
					if statusErr := r.Status().Update(ctx, &agentRun); statusErr != nil {
						return ctrl.Result{}, statusErr
					}
				}
				return ctrl.Result{RequeueAfter: egressdReadyRequeue}, nil
			}
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
	result := earliestRequeue(deadlineResult, workspaceResult)
	if enforced {
		caResult, caErr := r.egressCARenewalRequeue(ctx, &agentRun)
		if caErr != nil {
			return ctrl.Result{}, caErr
		}
		result = earliestRequeue(result, caResult)
	}
	return result, nil
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

func ptrTo[T any](value T) *T {
	return &value
}
