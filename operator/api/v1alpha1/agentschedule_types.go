package v1alpha1

import (
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
	Suspend        bool  `json:"suspend,omitempty"`
	MaxParallelism int32 `json:"maxParallelism,omitempty"`
}

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
	out.Spec = in.Spec
	out.Status = *in.Status.DeepCopy()
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
