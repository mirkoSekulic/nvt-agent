package controller

import (
	"context"
	"fmt"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// createAgentPod renders and creates the AgentRun Pod; the caller has already
// established that no Pod exists.
func (r *AgentRunReconciler) createAgentPod(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) (*corev1.Pod, error) {
	// Pods are create-once for this slice because most spec fields are immutable.
	// A future replacement policy can decide how to handle spec changes.
	desired, err := DesiredAgentPod(agentRun, r.Scheme)
	if err != nil {
		return nil, err
	}
	if AgentRunEgressEnforced(agentRun) {
		if err := r.applyEgressCAGeneration(ctx, agentRun, desired); err != nil {
			return nil, err
		}
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
