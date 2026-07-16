package v1alpha1

import (
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// AgentRunPhase describes the current lifecycle phase of an AgentRun.
type AgentRunPhase string
type AgentRunEgressMode string
type AgentRunEgressTransport string
type AgentRunGrantMaterialization string

const (
	// AgentRunPhasePending means the run has been accepted but no worker pod has started.
	AgentRunPhasePending AgentRunPhase = "Pending"
	// AgentRunPhaseRunning means the run is actively executing.
	AgentRunPhaseRunning AgentRunPhase = "Running"
	// AgentRunPhaseCompleted means the run finished successfully.
	AgentRunPhaseCompleted AgentRunPhase = "Completed"
	// AgentRunPhaseFailed means the run finished unsuccessfully.
	AgentRunPhaseFailed AgentRunPhase = "Failed"
	// AgentRunPhaseDeadlineExceeded means the run exceeded its active deadline.
	AgentRunPhaseDeadlineExceeded AgentRunPhase = "DeadlineExceeded"

	AgentRunEgressDirect                AgentRunEgressMode      = "direct"
	AgentRunEgressMediated              AgentRunEgressMode      = "mediated"
	AgentRunEgressTransportRedirect     AgentRunEgressTransport = "redirect"
	AgentRunEgressTransportForwardProxy AgentRunEgressTransport = "forward-proxy"
	AgentRunEgressTransportTransparent  AgentRunEgressTransport = "transparent"

	AgentRunGrantFileBundle   AgentRunGrantMaterialization = "file-bundle"
	AgentRunGrantHeaderInject AgentRunGrantMaterialization = "header-inject"
	// AgentRunGrantPlaceholderFile materializes an inert placeholder auth file
	// for the agent; the real credential stays broker-side and is injected at
	// the edge. Like header-inject, it is a zero-possession mediated mode.
	AgentRunGrantPlaceholderFile AgentRunGrantMaterialization = "placeholder-file"

	AgentRunWorkspaceEphemeral  AgentRunWorkspaceMode = "Ephemeral"
	AgentRunWorkspacePersistent AgentRunWorkspaceMode = "Persistent"

	// AgentRunUserRoot is the default: the agent container runs as root, HOME
	// is /root, exactly as today.
	AgentRunUserRoot AgentRunRuntimeUser = "root"
	// AgentRunUserNonRoot runs the agent container as uid/gid 1000 (the image's
	// `agent` user) with HOME=/home/agent and passwordless sudo — opt-in, for
	// tools that refuse to run privileged (e.g. Claude Code's bypass mode).
	AgentRunUserNonRoot AgentRunRuntimeUser = "non-root"
)

// AgentRunRuntimeUser selects the container user for the agent.
type AgentRunRuntimeUser string
type AgentRunWorkspaceMode string

// AgentRun represents one disposable nvt agent execution.
//
//nolint:govet,modernize // Kubernetes API types conventionally embed metadata and use omitempty tags.
type AgentRun struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AgentRunSpec   `json:"spec,omitempty"`
	Status AgentRunStatus `json:"status,omitempty"`
}

// AgentRunSpec describes how an agent execution should be started.
//
//nolint:govet // Field order follows the CRD schema for readability.
type AgentRunSpec struct {
	Runtime                   AgentRunRuntime      `json:"runtime"`
	RuntimeAuth               *AgentRunRuntimeAuth `json:"runtimeAuth,omitempty"`
	Image                     string               `json:"image"`
	RuntimeClassName          *string              `json:"runtimeClassName,omitempty"`
	Egress                    AgentRunEgressMode   `json:"egress,omitempty"`
	EgressAllowInsecureBroker bool                 `json:"egressAllowInsecureBroker,omitempty"`
	// EgressEnforcement opts a mediated run into network-enforced egress:
	// egressd moves to its own Pod and CNI-enforced NetworkPolicies fence the
	// agent Pod so it cannot reach arbitrary hosts
	// (docs/transparent-egress-architecture.md). Requires egress: mediated and a
	// NetworkPolicy-enforcing CNI; same-Pod remains the default mediated shape.
	EgressEnforcement bool `json:"egressEnforcement,omitempty"`
	// EgressForwardProxy opts a mediated+enforced run into forward-proxy mode:
	// the agent's HTTP(S)_PROXY points at egressd, which TLS-terminates CONNECT
	// under the per-agent CA and injects the broker credential, so unmodified
	// tools that honor proxy env are mediated with zero per-tool config
	// (docs/transparent-egress-architecture.md). Requires egressEnforcement.
	EgressForwardProxy bool `json:"egressForwardProxy,omitempty"`
	// EgressTransport selects redirect, forward-proxy, or transparent routing.
	// EgressForwardProxy remains a compatibility input during migration.
	EgressTransport   AgentRunEgressTransport    `json:"egressTransport,omitempty"`
	Workspace         AgentRunWorkspace          `json:"workspace"`
	Broker            *AgentRunBroker            `json:"broker,omitempty"`
	Prompt            *AgentRunPrompt            `json:"prompt,omitempty"`
	Agent             AgentRunAgent              `json:"agent"`
	Lifecycle         *AgentRunLifecycle         `json:"lifecycle,omitempty"`
	TTL               *AgentRunTTL               `json:"ttl,omitempty"`
	ProfileProvenance *AgentRunProfileProvenance `json:"profileProvenance,omitempty"`
}

// AgentRunProfileProvenance is the immutable record of a profiled schedule resolution.
type AgentRunProfileProvenance struct {
	AuthenticatedProducer string             `json:"authenticatedProducer"`
	ScheduleName          string             `json:"scheduleName"`
	ScheduleUID           string             `json:"scheduleUID"`
	ScheduleGeneration    int64              `json:"scheduleGeneration"`
	SelectedProfile       string             `json:"selectedProfile"`
	Principal             *AgentRunPrincipal `json:"principal,omitempty"`
}

// AgentRunPrincipal records immutable authorization keys and optional display data.
type AgentRunPrincipal struct {
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	DisplayName string `json:"displayName,omitempty"`
}

// AgentRunRuntime defines the selected runtime and autonomy mode.
type AgentRunRuntime struct {
	Type     string `json:"type"`
	Autonomy string `json:"autonomy"`
	// User selects the container user: root (default, unchanged) or non-root
	// (uid/gid 1000, HOME=/home/agent, passwordless sudo).
	User AgentRunRuntimeUser `json:"user,omitempty"`
}

// AgentRunRuntimeAuth references runtime-specific auth material from a Kubernetes Secret.
type AgentRunRuntimeAuth struct {
	SecretName string `json:"secretName"`
	MountPath  string `json:"mountPath,omitempty"`
}

// AgentRunWorkspace defines the workspace provisioning mode.
type AgentRunWorkspace struct {
	Mode             AgentRunWorkspaceMode `json:"mode,omitempty"`
	Size             *resource.Quantity    `json:"size,omitempty"`
	StorageClassName string                `json:"storageClassName,omitempty"`
}

// AgentRunBroker defines external credential grants requested for the run.
type AgentRunBroker struct {
	Grants []AgentRunBrokerGrant `json:"grants,omitempty"`
}

// AgentRunBrokerGrant defines repositories granted through a credential provider.
type AgentRunBrokerGrant struct {
	Provider     string   `json:"provider"`
	Repositories []string `json:"repositories"`
	// Materialization selects how the credential reaches the run: file-bundle
	// (direct only; writes usable material into the container), header-inject
	// or placeholder-file (both mediated-only, zero-possession — the real
	// credential is injected at the edge, never handed to the agent).
	Materialization AgentRunGrantMaterialization `json:"materialization,omitempty"`
	EgressHosts     []string                     `json:"egressHosts,omitempty"`
	// Git marks a git-over-HTTPS grant: its egressd route terminates TLS
	// under the per-agent CA and runtime bootstrap installs the git
	// redirect wiring (protocol/injection.md).
	Git bool `json:"git,omitempty"`
	// Permissions narrows the provider-level permission ceiling per grant,
	// mirroring GitHub App permission keys (values: read or write).
	Permissions map[string]string `json:"permissions,omitempty"`
	// AllowInsecureUpstream lets egressd reach this grant's upstream over
	// plain HTTP instead of re-originating TLS. Dev/test only — it exists so
	// hermetic in-cluster fixtures (which cannot present a publicly-trusted
	// cert) are reachable from the kind egress smokes. A plaintext upstream
	// leg carries the injected credential in the clear, so admission rejects
	// it unless the operator sets NVT_ALLOW_INSECURE_UPSTREAMS, and always
	// rejects it for git grants.
	AllowInsecureUpstream bool `json:"allowInsecureUpstream,omitempty"`
	// Quota bounds proxied requests for this grant's route. Absent means
	// unlimited. The count is per egressd process, not per run — an egressd
	// restart resets it — so it is a soft resource guard, not a security
	// boundary (protocol/injection.md).
	Quota *AgentRunGrantQuota `json:"quota,omitempty"`
}

// AgentRunGrantQuota bounds a grant's egress.
type AgentRunGrantQuota struct {
	// Requests is the maximum number of proxied requests on this route.
	// Must be positive when the quota block is present.
	Requests int `json:"requests"`
}

// AgentRunPrompt defines the optional initial prompt for disposable runs.
type AgentRunPrompt struct {
	Text string `json:"text,omitempty"`
}

// AgentRunAgent contains agent-specific configuration.
type AgentRunAgent struct {
	Config apiextensionsv1.JSON `json:"config"`
}

// AgentRunLifecycle defines event names that complete or fail a run.
type AgentRunLifecycle struct {
	CompleteOn []string `json:"completeOn,omitempty"`
	FailOn     []string `json:"failOn,omitempty"`
}

// AgentRunTTL defines runtime and cleanup deadlines.
type AgentRunTTL struct {
	ActiveDeadlineSeconds *int64 `json:"activeDeadlineSeconds,omitempty"`
	CompletedTTLSeconds   *int64 `json:"completedTTLSeconds,omitempty"`
	FailedTTLSeconds      *int64 `json:"failedTTLSeconds,omitempty"`
	RunRetentionSeconds   *int64 `json:"runRetentionSeconds,omitempty"`
}

// AgentRunStatus contains observed execution state.
type AgentRunStatus struct {
	Phase      AgentRunPhase `json:"phase,omitempty"`
	PodName    string        `json:"podName,omitempty"`
	StartedAt  *metav1.Time  `json:"startedAt,omitempty"`
	FinishedAt *metav1.Time  `json:"finishedAt,omitempty"`
	Reason     string        `json:"reason,omitempty"`
	// Conditions surfaces the enforcement-mode provisioning state machine
	// (BrokerPolicyReady, EgressdCreated, EgressdReady, EgressCAPublished):
	// each reconcile pass advances one observable step, and the agent Pod is
	// never created before BrokerPolicyReady and EgressCAPublished both hold.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// AgentRunList contains a list of AgentRun resources.
//
//nolint:modernize // Kubernetes API types conventionally use omitempty tags on metadata.
type AgentRunList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []AgentRun `json:"items"`
}

// DeepCopyObject returns a runtime.Object copy of the AgentRun.
func (in *AgentRun) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}

	out := new(AgentRun)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject returns a runtime.Object copy of the AgentRunList.
func (in *AgentRunList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}

	out := new(AgentRunList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *AgentRun) DeepCopyInto(out *AgentRun) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = *in.Spec.DeepCopy()
	out.Status = *in.Status.DeepCopy()
}

// DeepCopyInto copies the receiver into out.
func (in *AgentRunList) DeepCopyInto(out *AgentRunList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]AgentRun, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy returns a copy of the AgentRunSpec.
func (in *AgentRunSpec) DeepCopy() *AgentRunSpec {
	if in == nil {
		return nil
	}

	out := new(AgentRunSpec)
	*out = *in
	if in.RuntimeClassName != nil {
		out.RuntimeClassName = new(string)
		*out.RuntimeClassName = *in.RuntimeClassName
	}
	if in.RuntimeAuth != nil {
		out.RuntimeAuth = in.RuntimeAuth.DeepCopy()
	}
	out.Workspace = *in.Workspace.DeepCopy()
	if in.Broker != nil {
		out.Broker = in.Broker.DeepCopy()
	}
	if in.Prompt != nil {
		out.Prompt = in.Prompt.DeepCopy()
	}
	out.Agent.Config = *in.Agent.Config.DeepCopy()
	if in.Lifecycle != nil {
		out.Lifecycle = in.Lifecycle.DeepCopy()
	}
	if in.TTL != nil {
		out.TTL = in.TTL.DeepCopy()
	}
	if in.ProfileProvenance != nil {
		out.ProfileProvenance = in.ProfileProvenance.DeepCopy()
	}
	return out
}

// DeepCopy returns a copy of the AgentRunWorkspace.
func (in *AgentRunWorkspace) DeepCopy() *AgentRunWorkspace {
	if in == nil {
		return nil
	}
	out := new(AgentRunWorkspace)
	*out = *in
	if in.Size != nil {
		quantity := in.Size.DeepCopy()
		out.Size = &quantity
	}
	return out
}

func (in *AgentRunProfileProvenance) DeepCopy() *AgentRunProfileProvenance {
	if in == nil {
		return nil
	}
	out := new(AgentRunProfileProvenance)
	*out = *in
	if in.Principal != nil {
		out.Principal = &AgentRunPrincipal{
			Issuer: in.Principal.Issuer, Subject: in.Principal.Subject, DisplayName: in.Principal.DisplayName,
		}
	}
	return out
}

// DeepCopy returns a copy of the AgentRunRuntimeAuth.
func (in *AgentRunRuntimeAuth) DeepCopy() *AgentRunRuntimeAuth {
	if in == nil {
		return nil
	}

	out := new(AgentRunRuntimeAuth)
	*out = *in
	return out
}

// DeepCopy returns a copy of the AgentRunBroker.
func (in *AgentRunBroker) DeepCopy() *AgentRunBroker {
	if in == nil {
		return nil
	}

	out := new(AgentRunBroker)
	*out = *in
	if in.Grants != nil {
		out.Grants = make([]AgentRunBrokerGrant, len(in.Grants))
		for i := range in.Grants {
			out.Grants[i] = *in.Grants[i].DeepCopy()
		}
	}
	return out
}

// DeepCopy returns a copy of the AgentRunBrokerGrant.
func (in *AgentRunBrokerGrant) DeepCopy() *AgentRunBrokerGrant {
	if in == nil {
		return nil
	}

	out := new(AgentRunBrokerGrant)
	*out = *in
	if in.Repositories != nil {
		out.Repositories = append([]string{}, in.Repositories...)
	}
	if in.EgressHosts != nil {
		out.EgressHosts = append([]string{}, in.EgressHosts...)
	}
	if in.Permissions != nil {
		out.Permissions = make(map[string]string, len(in.Permissions))
		for key, value := range in.Permissions {
			out.Permissions[key] = value
		}
	}
	if in.Quota != nil {
		out.Quota = &AgentRunGrantQuota{Requests: in.Quota.Requests}
	}
	return out
}

// DeepCopy returns a copy of the AgentRunPrompt.
func (in *AgentRunPrompt) DeepCopy() *AgentRunPrompt {
	if in == nil {
		return nil
	}

	out := new(AgentRunPrompt)
	*out = *in
	return out
}

// DeepCopy returns a copy of the AgentRunLifecycle.
func (in *AgentRunLifecycle) DeepCopy() *AgentRunLifecycle {
	if in == nil {
		return nil
	}

	out := new(AgentRunLifecycle)
	*out = *in
	out.CompleteOn = append([]string(nil), in.CompleteOn...)
	out.FailOn = append([]string(nil), in.FailOn...)
	return out
}

// DeepCopy returns a copy of the AgentRunTTL.
func (in *AgentRunTTL) DeepCopy() *AgentRunTTL {
	if in == nil {
		return nil
	}

	out := new(AgentRunTTL)
	*out = *in
	if in.ActiveDeadlineSeconds != nil {
		out.ActiveDeadlineSeconds = new(int64)
		*out.ActiveDeadlineSeconds = *in.ActiveDeadlineSeconds
	}
	if in.CompletedTTLSeconds != nil {
		out.CompletedTTLSeconds = new(int64)
		*out.CompletedTTLSeconds = *in.CompletedTTLSeconds
	}
	if in.FailedTTLSeconds != nil {
		out.FailedTTLSeconds = new(int64)
		*out.FailedTTLSeconds = *in.FailedTTLSeconds
	}
	if in.RunRetentionSeconds != nil {
		out.RunRetentionSeconds = new(int64)
		*out.RunRetentionSeconds = *in.RunRetentionSeconds
	}
	return out
}

// DeepCopy returns a copy of the AgentRunStatus.
func (in *AgentRunStatus) DeepCopy() *AgentRunStatus {
	if in == nil {
		return nil
	}

	out := new(AgentRunStatus)
	*out = *in
	if in.StartedAt != nil {
		out.StartedAt = in.StartedAt.DeepCopy()
	}
	if in.FinishedAt != nil {
		out.FinishedAt = in.FinishedAt.DeepCopy()
	}
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&out.Conditions[i])
		}
	}
	return out
}
