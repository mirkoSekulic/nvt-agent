package controller

import (
	"context"
	"fmt"
	"reflect"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

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
