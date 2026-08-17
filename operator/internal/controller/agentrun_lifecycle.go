package controller

import (
	"context"
	"fmt"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

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
