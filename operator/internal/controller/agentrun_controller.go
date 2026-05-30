package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/yaml"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

const agentConfigKey = "agent.yaml"

// AgentRunReconciler reconciles AgentRun resources.
type AgentRunReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// Reconcile initializes empty AgentRun status and leaves all execution work to later controllers.
func (r *AgentRunReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var agentRun nvtv1alpha1.AgentRun
	if err := r.Get(ctx, req.NamespacedName, &agentRun); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get AgentRun: %w", err)
	}

	if err := r.reconcileAgentConfigMap(ctx, &agentRun); err != nil {
		return ctrl.Result{}, err
	}

	if InitializeAgentRunStatus(&agentRun) {
		if err := r.Status().Update(ctx, &agentRun); err != nil {
			return ctrl.Result{}, fmt.Errorf("update AgentRun status: %w", err)
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager registers the AgentRun controller with the manager.
func (r *AgentRunReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := ctrl.NewControllerManagedBy(mgr).
		For(&nvtv1alpha1.AgentRun{}).
		Owns(&corev1.ConfigMap{}).
		Complete(r); err != nil {
		return fmt.Errorf("build AgentRun controller: %w", err)
	}

	return nil
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
			Labels: map[string]string{
				"app.kubernetes.io/name":      "nvt-agent",
				"app.kubernetes.io/component": "agentrun",
				"nvt.dev/agentrun":            agentRun.Name,
			},
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

// AgentConfigMapName returns the deterministic ConfigMap name for an AgentRun.
func AgentConfigMapName(agentRunName string) string {
	return agentRunName + "-agent-config"
}

// RenderAgentConfigYAML converts the preserved AgentRun agent config payload to YAML.
func RenderAgentConfigYAML(agentRun *nvtv1alpha1.AgentRun) (string, error) {
	rawConfig := agentRun.Spec.Agent.Config.Raw
	if len(rawConfig) == 0 {
		rawConfig = []byte("{}")
	}

	rendered, err := yaml.JSONToYAML(rawConfig)
	if err != nil {
		return "", fmt.Errorf("render AgentRun agent config: %w", err)
	}

	return string(rendered), nil
}

// InitializeAgentRunStatus sets the initial phase when a run has no observed phase yet.
func InitializeAgentRunStatus(agentRun *nvtv1alpha1.AgentRun) bool {
	if agentRun.Status.Phase != "" {
		return false
	}

	agentRun.Status.Phase = nvtv1alpha1.AgentRunPhasePending
	return true
}
