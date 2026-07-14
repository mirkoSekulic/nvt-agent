package v1alpha1

import (
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// AgentSchedule represents a generic admission pool for disposable AgentRuns.
//
//nolint:govet,modernize // Kubernetes API types conventionally embed metadata and use omitempty tags.
type AgentSchedule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AgentScheduleSpec   `json:"spec,omitempty"`
	Status AgentScheduleStatus `json:"status,omitempty"`
}

// AgentScheduleSpec defines generic scheduling controls.
type AgentScheduleSpec struct {
	Suspend          bool                            `json:"suspend,omitempty"`
	MaxParallelism   int32                           `json:"maxParallelism,omitempty"`
	Template         *AgentScheduleTemplate          `json:"template,omitempty"`
	Profiles         []AgentScheduleExecutionProfile `json:"profiles,omitempty"`
	ProfileSelection *AgentScheduleProfileSelection  `json:"profileSelection,omitempty"`
	AllowedProducers []string                        `json:"allowedProducers,omitempty"`
}

// AgentScheduleTemplate contains the non-security-sensitive fields shared by
// every profiled admission. Prompt is supplied per request; runtime, egress,
// broker, and the top-level agent runtime config are profile-owned.
type AgentScheduleTemplate struct {
	Image            string             `json:"image"`
	RuntimeClassName *string            `json:"runtimeClassName,omitempty"`
	Workspace        AgentRunWorkspace  `json:"workspace"`
	Agent            AgentRunAgent      `json:"agent"`
	Lifecycle        *AgentRunLifecycle `json:"lifecycle,omitempty"`
	TTL              *AgentRunTTL       `json:"ttl,omitempty"`
}

// AgentScheduleExecutionProfile is one operator-owned execution identity and
// its complete runtime/broker/egress security configuration.
type AgentScheduleExecutionProfile struct {
	Name                      string                  `json:"name"`
	Runtime                   AgentRunRuntime         `json:"runtime"`
	RuntimeAuth               *AgentRunRuntimeAuth    `json:"runtimeAuth,omitempty"`
	AgentRuntimeConfig        apiextensionsv1.JSON    `json:"agentRuntimeConfig"`
	Egress                    AgentRunEgressMode      `json:"egress"`
	EgressAllowInsecureBroker bool                    `json:"egressAllowInsecureBroker,omitempty"`
	EgressEnforcement         bool                    `json:"egressEnforcement,omitempty"`
	EgressForwardProxy        bool                    `json:"egressForwardProxy,omitempty"`
	EgressTransport           AgentRunEgressTransport `json:"egressTransport,omitempty"`
	Broker                    *AgentRunBroker         `json:"broker,omitempty"`
}

// AgentScheduleProfileSelection defines deterministic static principal routing.
type AgentScheduleProfileSelection struct {
	DefaultProfile string                              `json:"defaultProfile,omitempty"`
	Rules          []AgentScheduleProfileSelectionRule `json:"rules,omitempty"`
	OnNoMatch      AgentScheduleOnNoMatch              `json:"onNoMatch"`
}

// AgentScheduleProfileSelectionRule maps one immutable external principal to one profile.
type AgentScheduleProfileSelectionRule struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
	Profile string `json:"profile"`
}

// AgentScheduleOnNoMatch controls unmatched or absent principals.
type AgentScheduleOnNoMatch string

const (
	AgentScheduleOnNoMatchUseDefault AgentScheduleOnNoMatch = "useDefault"
	AgentScheduleOnNoMatchDeny       AgentScheduleOnNoMatch = "deny"
)

// AgentScheduleStatus reports generic schedule admission state.
type AgentScheduleStatus struct {
	ObservedGeneration  int64        `json:"observedGeneration,omitempty"`
	ActiveRuns          int32        `json:"activeRuns,omitempty"`
	LastAcceptedAt      *metav1.Time `json:"lastAcceptedAt,omitempty"`
	LastRejectedAt      *metav1.Time `json:"lastRejectedAt,omitempty"`
	LastRejectionReason string       `json:"lastRejectionReason,omitempty"`
}

// AgentScheduleList contains a list of AgentSchedule resources.
//
//nolint:modernize // Kubernetes API types conventionally use omitempty tags on metadata.
type AgentScheduleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []AgentSchedule `json:"items"`
}

// DeepCopyObject returns a runtime.Object copy of the AgentSchedule.
func (in *AgentSchedule) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}

	out := new(AgentSchedule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject returns a runtime.Object copy of the AgentScheduleList.
func (in *AgentScheduleList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}

	out := new(AgentScheduleList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *AgentSchedule) DeepCopyInto(out *AgentSchedule) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = *in.Spec.DeepCopy()
	out.Status = *in.Status.DeepCopy()
}

// DeepCopy returns a copy of the AgentScheduleSpec.
func (in *AgentScheduleSpec) DeepCopy() *AgentScheduleSpec {
	if in == nil {
		return nil
	}
	out := new(AgentScheduleSpec)
	*out = *in
	if in.Template != nil {
		out.Template = in.Template.DeepCopy()
	}
	if in.Profiles != nil {
		out.Profiles = make([]AgentScheduleExecutionProfile, len(in.Profiles))
		for i := range in.Profiles {
			out.Profiles[i] = *in.Profiles[i].DeepCopy()
		}
	}
	if in.ProfileSelection != nil {
		out.ProfileSelection = in.ProfileSelection.DeepCopy()
	}
	out.AllowedProducers = append([]string(nil), in.AllowedProducers...)
	return out
}

func (in *AgentScheduleTemplate) DeepCopy() *AgentScheduleTemplate {
	if in == nil {
		return nil
	}
	out := new(AgentScheduleTemplate)
	*out = *in
	if in.RuntimeClassName != nil {
		out.RuntimeClassName = new(string)
		*out.RuntimeClassName = *in.RuntimeClassName
	}
	out.Agent.Config = *in.Agent.Config.DeepCopy()
	if in.Lifecycle != nil {
		out.Lifecycle = in.Lifecycle.DeepCopy()
	}
	if in.TTL != nil {
		out.TTL = in.TTL.DeepCopy()
	}
	return out
}

func (in *AgentScheduleExecutionProfile) DeepCopy() *AgentScheduleExecutionProfile {
	if in == nil {
		return nil
	}
	out := new(AgentScheduleExecutionProfile)
	*out = *in
	if in.RuntimeAuth != nil {
		out.RuntimeAuth = in.RuntimeAuth.DeepCopy()
	}
	out.AgentRuntimeConfig = *in.AgentRuntimeConfig.DeepCopy()
	if in.Broker != nil {
		out.Broker = in.Broker.DeepCopy()
	}
	return out
}

func (in *AgentScheduleProfileSelection) DeepCopy() *AgentScheduleProfileSelection {
	if in == nil {
		return nil
	}
	out := new(AgentScheduleProfileSelection)
	*out = *in
	out.Rules = append([]AgentScheduleProfileSelectionRule(nil), in.Rules...)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *AgentScheduleList) DeepCopyInto(out *AgentScheduleList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]AgentSchedule, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy returns a copy of the AgentScheduleStatus.
func (in *AgentScheduleStatus) DeepCopy() *AgentScheduleStatus {
	if in == nil {
		return nil
	}

	out := new(AgentScheduleStatus)
	*out = *in
	if in.LastAcceptedAt != nil {
		out.LastAcceptedAt = in.LastAcceptedAt.DeepCopy()
	}
	if in.LastRejectedAt != nil {
		out.LastRejectedAt = in.LastRejectedAt.DeepCopy()
	}
	return out
}
