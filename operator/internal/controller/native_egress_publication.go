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
	"k8s.io/apimachinery/pkg/util/validation"
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
	client     client.Reader
	authority  publicationclient.Interface
	namespace  string
	attachment *executiondriver.NativeEgressAttachment
	mu         sync.Mutex
}

func newNativeEgressTargetCoordinator(kubernetes client.Reader, authority publicationclient.Interface, namespace string, configured *executiondriver.NativeEgressAttachment) (nativeEgressTargetPublication, error) {
	if kubernetes == nil || authority == nil || len(validation.IsDNS1123Label(namespace)) != 0 {
		return nil, errors.New("native egress publication configuration is invalid")
	}
	var attachment *executiondriver.NativeEgressAttachment
	if configured != nil && executiondriver.ValidateNativeEgressAttachment(*configured) != nil {
		return nil, errors.New("native egress publication configuration is invalid")
	}
	if configured != nil {
		copy := *configured
		copy.RequiredDestinations = append([]executiondriver.NativeEgressRequiredDestination(nil), configured.RequiredDestinations...)
		attachment = &copy
	}
	return &nativeEgressTargetCoordinator{client: kubernetes, authority: authority, namespace: namespace, attachment: attachment}, nil
}

// ConfigureNativeEgressTargetPublication installs the optional trusted relay
// publication boundary without exporting its reconciliation interface.
func ConfigureNativeEgressTargetPublication(reconciler *AgentRunReconciler, authority *publicationclient.Client, reader client.Reader, namespace string) error {
	if reconciler == nil || authority == nil {
		return nil
	}
	if reader == nil {
		reader = reconciler.Client
	}
	if reconciler.NativeEgressAttachment == nil {
		return errors.New("native egress publication attachment is unavailable")
	}
	coordinator, err := newNativeEgressTargetCoordinator(reader, authority, namespace, reconciler.NativeEgressAttachment)
	if err != nil {
		return err
	}
	reconciler.nativeEgressTargets = coordinator
	return nil
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
	if coordinator == nil || coordinator.client == nil || coordinator.authority == nil || ctx == nil || len(validation.IsDNS1123Label(coordinator.namespace)) != 0 {
		return errors.New("native egress publication is unavailable")
	}
	if current != nil && nativeegress.ValidatePublishedTarget(*current) != nil {
		return errors.New("native egress publication is invalid")
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	runs := &nvtv1alpha1.AgentRunList{}
	if err := coordinator.client.List(ctx, runs, client.InNamespace(coordinator.namespace)); err != nil {
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
		if coordinator.attachment != nil && !nativeEgressAttachmentCurrent(run, coordinator.attachment) {
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
	expectedGeneration, generationErr := nativeEgressDesiredGeneration(run)
	if err != nil || generationErr != nil || binding.AgentRunUID != string(run.UID) || binding.ExecutionID != executionID ||
		binding.DriverRegistration != run.Spec.Execution.Driver || binding.DesiredGeneration != expectedGeneration {
		return guestenrollment.Binding{}, errors.New("native egress binding is unavailable")
	}
	return binding, nil
}

func nativeEgressAttachmentCurrent(run *nvtv1alpha1.AgentRun, attachment *executiondriver.NativeEgressAttachment) bool {
	return run != nil && attachment != nil && executiondriver.ValidateNativeEgressAttachment(*attachment) == nil &&
		run.Status.NativeEgressAttachment != nil && run.Status.NativeEgressAttachment.Generation == attachment.Generation &&
		run.Status.NativeEgressAttachment.Digest == attachment.Digest
}

// nativeMediatedConfinementReady is the single portable provider gate for
// both one-time guest enrollment and exact relay-target publication. A guest
// cannot receive bootstrap authority until the driver has read back the
// current infrastructure-owned attachment and confinement state.
func nativeMediatedConfinementReady(run *nvtv1alpha1.AgentRun, attachment *executiondriver.NativeEgressAttachment, status executiondriver.Status, desiredGeneration int64) bool {
	return nativeMediatedExternalRun(run) && nativeEgressAttachmentCurrent(run, attachment) &&
		status.Phase == executiondriver.PhaseRunning && status.Ready && status.ObservedGeneration == desiredGeneration &&
		status.EgressConfinement != nil && status.EgressConfinement.AttachmentGeneration == run.Status.NativeEgressAttachment.Generation &&
		status.EgressConfinement.AttachmentDigest == run.Status.NativeEgressAttachment.Digest &&
		nativeEgressConfinementReady(status.EgressConfinement.Ready, string(status.EgressConfinement.Boundary))
}

func nativeEgressDesiredGeneration(run *nvtv1alpha1.AgentRun) (int64, error) {
	if run == nil {
		return 0, errors.New("native egress attachment is unavailable")
	}
	// Legacy in-process tests and pre-attachment status remain readable. The
	// production coordinator carries a configured attachment and filters these
	// rows before this helper is reached; reconciliation durably installs the
	// attachment status before any provider call.
	if run.Status.NativeEgressAttachment == nil {
		return executiondriver.NativeEgressDesiredGeneration(run.Generation, 0)
	}
	return executiondriver.NativeEgressDesiredGeneration(run.Generation, run.Status.NativeEgressAttachment.Generation)
}

func (r *AgentRunReconciler) ensureNativeEgressAttachment(ctx context.Context, run *nvtv1alpha1.AgentRun) (bool, error) {
	attachment := r.NativeEgressAttachment
	if run == nil || !nativeMediatedExternalRun(run) || attachment == nil || executiondriver.ValidateNativeEgressAttachment(*attachment) != nil {
		return false, errors.New("native egress attachment is unavailable")
	}
	current := run.Status.NativeEgressAttachment
	if current != nil && current.Digest != attachment.Digest && current.Generation >= attachment.Generation {
		return false, errors.New("native egress attachment generation did not advance")
	}
	desiredGeneration, err := executiondriver.NativeEgressDesiredGeneration(run.Generation, attachment.Generation)
	if err != nil {
		return false, err
	}
	bindingCurrent := false
	if binding, bindingErr := nativeGuestBindingFromStatus(run.Status.NativeGuestBinding); bindingErr == nil {
		bindingCurrent = binding.DesiredGeneration == desiredGeneration
	}
	staleReadyWithoutBinding := run.Status.NativeGuestBinding == nil && meta.IsStatusConditionTrue(run.Status.Conditions, ConditionNativeEgressReady)
	if nativeEgressAttachmentCurrent(run, attachment) && (run.Status.NativeGuestBinding == nil || bindingCurrent) && !staleReadyWithoutBinding {
		return false, nil
	}
	if run.Status.NativeGuestBinding != nil {
		if err := r.withdrawNativeEgressTarget(ctx, run); err != nil {
			return false, err
		}
	}
	previous := run.Status.DeepCopy()
	run.Status.NativeEgressAttachment = &nvtv1alpha1.AgentRunNativeEgressAttachmentStatus{Generation: attachment.Generation, Digest: attachment.Digest}
	run.Status.NativeGuestBinding = nil
	nativeEgressCondition(run, metav1.ConditionFalse, "NativeEgressAttachmentPending", "the provider has not observed the current native egress attachment")
	r.setRunCondition(run, ConditionExternalExecutionReady, metav1.ConditionFalse, "NativeEgressAttachmentPending", "external execution is waiting for the current native egress attachment")
	if equalAgentRunStatus(previous, &run.Status) {
		return false, nil
	}
	if err := r.Status().Update(ctx, run); err != nil {
		return false, fmt.Errorf("persist native egress attachment: %w", err)
	}
	return true, nil
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
	condition := meta.FindStatusCondition(run.Status.Conditions, ConditionNativeEgressReady)
	if condition != nil && condition.Status == metav1.ConditionFalse && condition.Reason == "NativeEgressWithdrawn" {
		return nil
	}
	changed := meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{
		Type: ConditionNativeEgressReady, Status: metav1.ConditionFalse, Reason: "NativeEgressWithdrawalPending",
		Message: "the exact native egress target is being withdrawn", ObservedGeneration: run.Generation,
	})
	changed = meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{
		Type: ConditionExternalExecutionReady, Status: metav1.ConditionFalse, Reason: "NativeEgressWithdrawalPending",
		Message: "external execution is waiting for native mediated egress withdrawal", ObservedGeneration: run.Generation,
	}) || changed
	objectGone := false
	if changed {
		if err := r.Status().Update(ctx, run); apierrors.IsNotFound(err) {
			objectGone = true
		} else if err != nil {
			return fmt.Errorf("persist native egress withdrawal: %w", err)
		}
	}
	if err := r.nativeEgressTargets.Reconcile(ctx, nil, string(run.UID)); err != nil {
		return err
	}
	if objectGone {
		return nil
	}
	changed = meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{
		Type: ConditionNativeEgressReady, Status: metav1.ConditionFalse, Reason: "NativeEgressWithdrawn",
		Message: "the exact native egress target is withdrawn", ObservedGeneration: run.Generation,
	})
	changed = meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{
		Type: ConditionExternalExecutionReady, Status: metav1.ConditionFalse, Reason: "NativeEgressWithdrawn",
		Message: "external execution is waiting for native mediated egress withdrawal", ObservedGeneration: run.Generation,
	}) || changed
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
		condition := meta.FindStatusCondition(previous.Conditions, ConditionNativeEgressReady)
		if condition != nil && (condition.Status == metav1.ConditionTrue || condition.Reason == "NativeEgressWithdrawalPending") {
			if err := r.withdrawNativeEgressTarget(ctx, run); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: externalExecutionDefaultRequeue}, nil
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
	desiredGeneration, generationErr := nativeEgressDesiredGeneration(run)
	if generationErr != nil || !nativeMediatedConfinementReady(run, r.NativeEgressAttachment, status, desiredGeneration) {
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
