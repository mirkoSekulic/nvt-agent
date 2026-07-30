package controller

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sync"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	publicationclient "github.com/mirkoSekulic/nvt-agent/operator/nativeegresspublication"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

const (
	ConditionNativeEgressReady = "NativeEgressReady"
	nativeEgressReadyReason    = "NativeEgressPublished"
	nativeEgressPendingReason  = "NativeEgressPending"
)

type nativeEgressTargetPublication interface {
	Reconcile(context.Context, *nativeegress.PublishedTarget, string) error
}

// nativeEgressTargetCoordinator serializes complete-snapshot publication in
// one operator process. Relay status remains the generation authority across
// operator restarts; AgentRun status reconstructs the complete desired set.
type nativeEgressTargetCoordinator struct {
	client    client.Reader
	authority publicationclient.Interface
	mu        sync.Mutex
}

func newNativeEgressTargetCoordinator(kubernetes client.Reader, authority publicationclient.Interface) nativeEgressTargetPublication {
	if kubernetes == nil || authority == nil {
		return nil
	}
	return &nativeEgressTargetCoordinator{client: kubernetes, authority: authority}
}

// ConfigureNativeEgressTargetPublication installs the optional trusted relay
// publication boundary without exporting its reconciliation interface.
func ConfigureNativeEgressTargetPublication(reconciler *AgentRunReconciler, authority *publicationclient.Client, reader client.Reader) {
	if reconciler == nil || authority == nil {
		return
	}
	if reader == nil {
		reader = reconciler.Client
	}
	reconciler.nativeEgressTargets = newNativeEgressTargetCoordinator(reader, authority)
}

// BootstrapNativeEgressTargetPublication restores the relay's process-local
// snapshot before the operator manager can report readiness after restart.
func BootstrapNativeEgressTargetPublication(ctx context.Context, reconciler *AgentRunReconciler) error {
	if reconciler == nil || reconciler.nativeEgressTargets == nil {
		return nil
	}
	return reconciler.nativeEgressTargets.Reconcile(ctx, nil, "")
}

func (coordinator *nativeEgressTargetCoordinator) Reconcile(ctx context.Context, current *nativeegress.PublishedTarget, excludeUID string) error {
	if coordinator == nil || coordinator.client == nil || coordinator.authority == nil || ctx == nil {
		return errors.New("native egress publication is unavailable")
	}
	if current != nil && nativeegress.ValidatePublishedTarget(*current) != nil {
		return errors.New("native egress publication is invalid")
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	runs := &nvtv1alpha1.AgentRunList{}
	if err := coordinator.client.List(ctx, runs); err != nil {
		return errors.New("native egress publication is unavailable")
	}
	targets := make([]nativeegress.PublishedTarget, 0, len(runs.Items)+1)
	for index := range runs.Items {
		run := &runs.Items[index]
		if string(run.UID) == excludeUID || (current != nil && current.Binding.AgentRunUID == string(run.UID)) {
			continue
		}
		if !meta.IsStatusConditionTrue(run.Status.Conditions, ConditionNativeEgressReady) || !nativeMediatedExternalRun(run) || run.DeletionTimestamp != nil || run.Status.Phase != nvtv1alpha1.AgentRunPhaseRunning {
			continue
		}
		binding, err := exactNativeEgressBinding(run)
		if err != nil {
			continue
		}
		if !coordinator.targetReady(ctx, run) {
			continue
		}
		targets = append(targets, nativeEgressPublishedTarget(run, binding))
	}
	if current != nil {
		targets = append(targets, *current)
	}
	canonical, digest, err := nativeegress.CanonicalTargetSnapshot(targets)
	if err != nil {
		return errors.New("native egress publication is invalid")
	}
	for attempt := 0; attempt < 3; attempt++ {
		status, statusErr := coordinator.authority.Status(ctx)
		if statusErr != nil || nativeegress.ValidateTargetStatus(status) != nil {
			return errors.New("native egress publication is unavailable")
		}
		generation := uint64(1)
		if status.Published {
			if status.Digest == digest {
				if status.TargetCount != len(canonical) {
					return errors.New("native egress publication is unavailable")
				}
				generation = status.Generation
			} else {
				if status.Generation == math.MaxUint64 {
					return errors.New("native egress publication is unavailable")
				}
				generation = status.Generation + 1
			}
		}
		snapshot := nativeegress.TargetSnapshot{
			ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetSnapshotReplace,
			Generation: generation, Digest: digest, Targets: canonical,
		}
		ack, publishErr := coordinator.authority.Publish(ctx, snapshot)
		if publishErr == nil && ack.Generation == generation && ack.Digest == digest && ack.TargetCount == len(canonical) {
			return nil
		}
		if !errors.Is(publishErr, publicationclient.ErrConflict) && !errors.Is(publishErr, publicationclient.ErrUnavailable) {
			return errors.New("native egress publication is unavailable")
		}
	}
	return errors.New("native egress publication is unavailable")
}

func (coordinator *nativeEgressTargetCoordinator) targetReady(ctx context.Context, run *nvtv1alpha1.AgentRun) bool {
	pod := &corev1.Pod{}
	if err := coordinator.client.Get(ctx, client.ObjectKey{Namespace: run.Namespace, Name: EgressdPodName(run.Name)}, pod); err != nil || !metav1.IsControlledBy(pod, run) || !isPodReady(pod) {
		return false
	}
	service := &corev1.Service{}
	if err := coordinator.client.Get(ctx, client.ObjectKey{Namespace: run.Namespace, Name: EgressdServiceName(run.Name)}, service); err != nil || !metav1.IsControlledBy(service, run) {
		return false
	}
	if service.Spec.Selector[agentRunLabelKey] != run.Name || service.Spec.Selector[roleLabelKey] != roleLabelEgressd {
		return false
	}
	for _, port := range service.Spec.Ports {
		if port.Name == "forward-proxy" && port.Port == egressForwardProxyPort {
			return true
		}
	}
	return false
}

func nativeMediatedExternalRun(run *nvtv1alpha1.AgentRun) bool {
	return run != nil && run.Spec.Execution != nil && run.Spec.Execution.Kind == nvtv1alpha1.AgentRunExecutionVM &&
		run.Spec.Execution.Driver != "" && run.Spec.Execution.Driver != builtInKubernetesDriver && AgentRunEgressForwardProxy(run)
}

func exactNativeEgressBinding(run *nvtv1alpha1.AgentRun) (guestenrollment.Binding, error) {
	if run == nil || !nativeMediatedExternalRun(run) {
		return guestenrollment.Binding{}, errors.New("native egress binding is unavailable")
	}
	binding, err := nativeGuestBindingFromStatus(run.Status.NativeGuestBinding)
	if err != nil {
		return guestenrollment.Binding{}, err
	}
	executionID, err := externalExecutionID(run.UID)
	if err != nil || binding.AgentRunUID != string(run.UID) || binding.ExecutionID != executionID ||
		binding.DriverRegistration != run.Spec.Execution.Driver || binding.DesiredGeneration != run.Generation {
		return guestenrollment.Binding{}, errors.New("native egress binding is unavailable")
	}
	return binding, nil
}

func nativeEgressPublishedTarget(run *nvtv1alpha1.AgentRun, binding guestenrollment.Binding) nativeegress.PublishedTarget {
	host := fmt.Sprintf("%s.%s.svc.cluster.local", EgressdServiceName(run.Name), run.Namespace)
	return nativeegress.PublishedTarget{
		Binding: binding, TargetType: nativeegress.EgressdConnectTargetType,
		ConnectURL: fmt.Sprintf("http://%s:%d", host, egressForwardProxyPort),
	}
}

func (r *AgentRunReconciler) withdrawNativeEgressTarget(ctx context.Context, run *nvtv1alpha1.AgentRun) error {
	if run == nil || run.Status.NativeGuestBinding == nil || !nativeMediatedExternalRun(run) {
		return nil
	}
	if r.nativeEgressTargets == nil {
		return errors.New("native egress publication is unavailable")
	}
	if err := r.nativeEgressTargets.Reconcile(ctx, nil, string(run.UID)); err != nil {
		return err
	}
	changed := meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{
		Type: ConditionNativeEgressReady, Status: metav1.ConditionFalse, Reason: "NativeEgressWithdrawn",
		Message: "the exact native egress target is withdrawn", ObservedGeneration: run.Generation,
	})
	if changed {
		if err := r.Status().Update(ctx, run); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("withdraw native egress readiness: %w", err)
		}
	}
	return nil
}

func nativeEgressConfinementReady(statusConfinementReady bool, statusBoundary string) bool {
	return statusConfinementReady && statusBoundary == "infrastructure"
}

func nativeEgressCondition(run *nvtv1alpha1.AgentRun, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{
		Type: ConditionNativeEgressReady, Status: status, Reason: reason, Message: message, ObservedGeneration: run.Generation,
	})
}

func (r *AgentRunReconciler) reconcileNativeEgress(
	ctx context.Context,
	run *nvtv1alpha1.AgentRun,
	status executiondriver.Status,
) (ctrl.Result, error) {
	if !nativeMediatedExternalRun(run) {
		return ctrl.Result{}, nil
	}
	previous := run.Status.DeepCopy()
	pending := func(reason string) (ctrl.Result, error) {
		if meta.IsStatusConditionTrue(previous.Conditions, ConditionNativeEgressReady) {
			if r.nativeEgressTargets == nil || r.nativeEgressTargets.Reconcile(ctx, nil, string(run.UID)) != nil {
				nativeEgressCondition(run, metav1.ConditionFalse, "NativeEgressWithdrawalPending", "native mediated egress is not ready")
				r.setRunCondition(run, ConditionExternalExecutionReady, metav1.ConditionFalse, "NativeEgressWithdrawalPending", "external execution is waiting for native mediated egress")
				if !equalAgentRunStatus(previous, &run.Status) {
					if err := r.Status().Update(ctx, run); err != nil {
						return ctrl.Result{}, fmt.Errorf("update native egress status: %w", err)
					}
				}
				return ctrl.Result{RequeueAfter: externalExecutionDefaultRequeue}, nil
			}
		}
		nativeEgressCondition(run, metav1.ConditionFalse, reason, "native mediated egress is not ready")
		r.setRunCondition(run, ConditionExternalExecutionReady, metav1.ConditionFalse, reason, "external execution is waiting for native mediated egress")
		if !equalAgentRunStatus(previous, &run.Status) {
			if err := r.Status().Update(ctx, run); err != nil {
				return ctrl.Result{}, fmt.Errorf("update native egress status: %w", err)
			}
		}
		return ctrl.Result{RequeueAfter: externalExecutionDefaultRequeue}, nil
	}
	if status.Phase != executiondriver.PhaseRunning || !status.Ready || status.ObservedGeneration != run.Generation || status.EgressConfinement == nil ||
		!nativeEgressConfinementReady(status.EgressConfinement.Ready, string(status.EgressConfinement.Boundary)) {
		return pending("NativeEgressConfinementPending")
	}
	binding, err := exactNativeEgressBinding(run)
	if err != nil {
		return pending("NativeEgressBindingPending")
	}
	if r.nativeEgressTargets == nil {
		return pending("NativeEgressPublicationUnavailable")
	}
	if err := r.reconcileBrokerTokenSecret(ctx, run); err != nil {
		return pending("NativeEgressTargetPending")
	}
	if err := r.reconcileEgressTokenSecret(ctx, run); err != nil {
		return pending("NativeEgressTargetPending")
	}
	existing, err := r.getOwnedEgressdPod(ctx, run)
	if err != nil {
		return pending("NativeEgressTargetPending")
	}
	if err := r.reconcileEgressdConfigMap(ctx, run, existing != nil); err != nil {
		return pending("NativeEgressTargetPending")
	}
	if err := r.reconcileEgressCASecret(ctx, run); err != nil {
		return pending("NativeEgressTargetPending")
	}
	if err := r.reconcileNativeVMEgressdNetworkPolicy(ctx, run); err != nil {
		return pending("NativeEgressTargetPending")
	}
	if err := r.reconcileEgressdPod(ctx, run); err != nil {
		return pending("NativeEgressTargetPending")
	}
	if err := r.reconcileEgressdService(ctx, run); err != nil {
		return pending("NativeEgressTargetPending")
	}
	if err := r.reconcileBrokerAgentsPolicy(ctx, run); err != nil {
		return pending("NativeEgressTargetPending")
	}
	egressdPod, err := r.getOwnedEgressdPod(ctx, run)
	if err != nil {
		return pending("NativeEgressTargetPending")
	}
	if egressdPod == nil || !isPodReady(egressdPod) {
		return pending("NativeEgressTargetPending")
	}
	target := nativeEgressPublishedTarget(run, binding)
	if err := r.nativeEgressTargets.Reconcile(ctx, &target, ""); err != nil {
		return pending("NativeEgressPublicationPending")
	}
	nativeEgressCondition(run, metav1.ConditionTrue, nativeEgressReadyReason, "the exact native egress target snapshot is active")
	r.setRunCondition(run, ConditionExternalExecutionReady, metav1.ConditionTrue, executionDriverReadyReason, "external execution and native mediated egress are ready")
	if !equalAgentRunStatus(previous, &run.Status) {
		if err := r.Status().Update(ctx, run); err != nil {
			return ctrl.Result{}, fmt.Errorf("publish native egress readiness: %w", err)
		}
	}
	return ctrl.Result{RequeueAfter: externalExecutionDefaultRequeue}, nil
}

func equalAgentRunStatus(left, right *nvtv1alpha1.AgentRunStatus) bool {
	if left == nil || right == nil {
		return left == right
	}
	return reflect.DeepEqual(*left, *right)
}

func (r *AgentRunReconciler) reconcileNativeVMEgressdNetworkPolicy(ctx context.Context, run *nvtv1alpha1.AgentRun) error {
	desired, err := DesiredEgressdNetworkPolicy(run, r.Scheme)
	if err != nil {
		return err
	}
	desired.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{
		From: []networkingv1.NetworkPolicyPeer{{
			PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "nvt-native-egress-relay"}},
		}},
		Ports: []networkingv1.NetworkPolicyPort{policyPort(corev1.ProtocolTCP, egressForwardProxyPort)},
	}}
	current := &networkingv1.NetworkPolicy{}
	err = r.Get(ctx, client.ObjectKeyFromObject(desired), current)
	if apierrors.IsNotFound(err) {
		return r.Create(ctx, desired)
	}
	if err != nil {
		return fmt.Errorf("get native VM egressd NetworkPolicy: %w", err)
	}
	if !metav1.IsControlledBy(current, run) {
		return errors.New("native VM egressd NetworkPolicy is not operator-owned")
	}
	if reflect.DeepEqual(current.Labels, desired.Labels) && reflect.DeepEqual(current.OwnerReferences, desired.OwnerReferences) && reflect.DeepEqual(current.Spec, desired.Spec) {
		return nil
	}
	current.Labels = desired.Labels
	current.OwnerReferences = desired.OwnerReferences
	current.Spec = desired.Spec
	if err := r.Update(ctx, current); err != nil {
		return fmt.Errorf("update native VM egressd NetworkPolicy: %w", err)
	}
	return nil
}

func (r *AgentRunReconciler) cleanupNativeEgressResources(ctx context.Context, run *nvtv1alpha1.AgentRun) error {
	objects := []client.Object{
		&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: EgressdNetworkPolicyName(run.Name), Namespace: run.Namespace}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: EgressdServiceName(run.Name), Namespace: run.Namespace}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: EgressdPodName(run.Name), Namespace: run.Namespace}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: EgressdConfigMapName(run.Name), Namespace: run.Namespace}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: EgressCASecretName(run.Name), Namespace: run.Namespace}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: EgressTokenSecretName(run.Name), Namespace: run.Namespace}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: BrokerTokenSecretName(run.Name), Namespace: run.Namespace}},
	}
	existing := make([]client.Object, 0, len(objects))
	for _, object := range objects {
		key := client.ObjectKeyFromObject(object)
		if err := r.Get(ctx, key, object); apierrors.IsNotFound(err) {
			continue
		} else if err != nil {
			return errors.New("native egress cleanup is unavailable")
		}
		if !metav1.IsControlledBy(object, run) {
			return errors.New("native egress cleanup is unavailable")
		}
		existing = append(existing, object)
	}
	if err := r.removeBrokerAgentsPolicyEntry(ctx, run); err != nil {
		return err
	}
	for _, object := range existing {
		if err := r.Delete(ctx, object); err != nil && !apierrors.IsNotFound(err) {
			return errors.New("native egress cleanup is unavailable")
		}
	}
	return nil
}
