package controller

import (
	"encoding/json"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

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
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name != roleLabelAgent || status.State.Terminated == nil {
			continue
		}
		agentRun.Status.Phase = nvtv1alpha1.AgentRunPhaseFailed
		agentRun.Status.FinishedAt = &now
		agentRun.Status.Reason = unexpectedAgentExitReason
		return true
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
