package controller

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

func desiredAgentPodForSecurityProjection(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme) (*corev1.Pod, error) {
	return buildDesiredAgentPod(agentRun, scheme, true)
}

// AgentRunWorkspaceMode returns the effective workspace mode. An omitted mode
// retains the historical ephemeral behavior.
func AgentRunWorkspaceMode(agentRun *nvtv1alpha1.AgentRun) nvtv1alpha1.AgentRunWorkspaceMode {
	if agentRun.Spec.Workspace.Mode == "" {
		return nvtv1alpha1.AgentRunWorkspaceEphemeral
	}
	return agentRun.Spec.Workspace.Mode
}

// ValidateAgentRunWorkspaceInstructions enforces the bounded, non-secret
// guidance contract without including its contents in diagnostics.
func ValidateAgentRunWorkspaceInstructions(agentRun *nvtv1alpha1.AgentRun) error {
	if len(agentRun.Spec.Agent.WorkspaceInstructions) > maxWorkspaceInstructionsBytes {
		return fmt.Errorf("spec.agent.workspaceInstructions must be at most %d bytes", maxWorkspaceInstructionsBytes)
	}
	if len(agentRun.Spec.Agent.WorkflowInstructions) > maxWorkspaceInstructionsBytes {
		return fmt.Errorf("spec.agent.workflowInstructions must be at most %d bytes", maxWorkspaceInstructionsBytes)
	}
	return nil
}

// ValidateAgentRunWorkspace validates the intentionally narrow storage API.
// Persistent storage is incompatible with file-bundle grants: those grants
// materialize usable credentials in the container and must never survive a Pod.
func ValidateAgentRunWorkspace(agentRun *nvtv1alpha1.AgentRun) error {
	workspace := agentRun.Spec.Workspace
	switch AgentRunWorkspaceMode(agentRun) {
	case nvtv1alpha1.AgentRunWorkspaceEphemeral:
		if workspace.Size != nil || workspace.DockerSize != nil || workspace.StorageClassName != "" {
			return fmt.Errorf("spec.workspace size, dockerSize, and storageClassName require mode Persistent")
		}
	case nvtv1alpha1.AgentRunWorkspacePersistent:
		if workspace.Size == nil || workspace.Size.Sign() <= 0 {
			return fmt.Errorf("spec.workspace.size must be a positive Kubernetes resource quantity for mode Persistent")
		}
		if workspace.StorageClassName != "" {
			if strings.TrimSpace(workspace.StorageClassName) != workspace.StorageClassName {
				return fmt.Errorf("spec.workspace.storageClassName must be normalized")
			}
			if problems := utilvalidation.IsDNS1123Subdomain(workspace.StorageClassName); len(problems) != 0 {
				return fmt.Errorf("spec.workspace.storageClassName must be a valid DNS subdomain")
			}
		}
		if workspace.DockerSize != nil && (workspace.DockerSize.Value() < minimumDockerPVCSizeBytes || workspace.DockerSize.Value() > maximumDockerPVCSizeBytes) {
			return fmt.Errorf("spec.workspace.dockerSize must be between 1Gi and 1Ti")
		}
		for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
			if AgentRunGrantMaterialization(grant) == nvtv1alpha1.AgentRunGrantFileBundle {
				return fmt.Errorf("persistent workspace is incompatible with broker grant %s materialization file-bundle", grant.Provider)
			}
		}
	default:
		return fmt.Errorf("spec.workspace.mode must be Ephemeral or Persistent, got %q", workspace.Mode)
	}
	return nil
}

// WorkspacePVCName is the stable claim name for one persistent AgentRun.
func WorkspacePVCName(agentRunName string) string {
	return agentRunName + "-workspace"
}

// DockerPVCName is the stable claim name for one persistent AgentRun's
// sidecar-only Docker data. It is deliberately separate from workspace/home.
func DockerPVCName(agentRunName string) string {
	return agentRunName + "-docker"
}

// DesiredWorkspacePVC renders the single lifecycle-scoped persistent claim.
func DesiredWorkspacePVC(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme) (*corev1.PersistentVolumeClaim, error) {
	if err := ValidateAgentRunWorkspace(agentRun); err != nil {
		return nil, err
	}
	if AgentRunWorkspaceMode(agentRun) != nvtv1alpha1.AgentRunWorkspacePersistent {
		return nil, fmt.Errorf("persistent workspace PVC requested for non-persistent AgentRun")
	}
	volumeMode := corev1.PersistentVolumeFilesystem
	claim := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      WorkspacePVCName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    agentRunLabels(agentRun.Name),
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			VolumeMode:  &volumeMode,
			Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{
				corev1.ResourceStorage: agentRun.Spec.Workspace.Size.DeepCopy(),
			}},
		},
	}
	if agentRun.Spec.Workspace.StorageClassName != "" {
		claim.Spec.StorageClassName = ptrTo(agentRun.Spec.Workspace.StorageClassName)
	}
	if err := controllerutil.SetControllerReference(agentRun, claim, scheme); err != nil {
		return nil, fmt.Errorf("set workspace PVC owner: %w", err)
	}
	return claim, nil
}

// DesiredDockerPVC renders the dedicated lifecycle-scoped Docker claim. The
// requested capacity is an enforced outer quota; the inner image reserves
// additional filesystem headroom below this value.
func DesiredDockerPVC(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme) (*corev1.PersistentVolumeClaim, error) {
	if err := ValidateAgentRunWorkspace(agentRun); err != nil {
		return nil, err
	}
	if AgentRunWorkspaceMode(agentRun) != nvtv1alpha1.AgentRunWorkspacePersistent {
		return nil, fmt.Errorf("persistent Docker PVC requested for non-persistent AgentRun")
	}
	volumeMode := corev1.PersistentVolumeFilesystem
	size := dockerPVCSize(agentRun)
	claim := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      DockerPVCName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    agentRunLabels(agentRun.Name),
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			VolumeMode:  &volumeMode,
			Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{
				corev1.ResourceStorage: size,
			}},
		},
	}
	if agentRun.Spec.Workspace.StorageClassName != "" {
		claim.Spec.StorageClassName = ptrTo(agentRun.Spec.Workspace.StorageClassName)
	}
	if err := controllerutil.SetControllerReference(agentRun, claim, scheme); err != nil {
		return nil, fmt.Errorf("set Docker PVC owner: %w", err)
	}
	return claim, nil
}

func (r *AgentRunReconciler) reconcileWorkspacePVC(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) (ctrl.Result, bool, bool, bool, error) {
	if err := ValidateAgentRunWorkspace(agentRun); err != nil {
		changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionFalse, "InvalidWorkspace", err.Error())
		return ctrl.Result{}, false, false, changed, err
	}
	if AgentRunWorkspaceMode(agentRun) == nvtv1alpha1.AgentRunWorkspaceEphemeral {
		return ctrl.Result{}, true, true, false, nil
	}

	desired, err := DesiredWorkspacePVC(agentRun, r.Scheme)
	if err != nil {
		return ctrl.Result{}, false, false, false, err
	}
	claim := &corev1.PersistentVolumeClaim{}
	key := client.ObjectKeyFromObject(desired)
	err = r.Get(ctx, key, claim)
	if errors.IsNotFound(err) {
		if err := r.Create(ctx, desired); err != nil {
			return ctrl.Result{}, false, false, false, fmt.Errorf("create workspace PVC: %w", err)
		}
		changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionFalse, "WorkspacePending", "waiting for persistent workspace claim to bind")
		// The claim now exists and is safe for a consuming Pod to reference.
		// This is required for WaitForFirstConsumer StorageClasses to provision.
		return ctrl.Result{RequeueAfter: workspacePVCReadyRequeue}, true, false, changed, nil
	}
	if err != nil {
		return ctrl.Result{}, false, false, false, fmt.Errorf("get workspace PVC: %w", err)
	}
	if !metav1.IsControlledBy(claim, agentRun) {
		err := fmt.Errorf("workspace PVC %s/%s exists but is not controlled by AgentRun %s", claim.Namespace, claim.Name, agentRun.Name)
		changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionFalse, "WorkspaceOwnershipConflict", err.Error())
		return ctrl.Result{}, false, false, changed, err
	}
	if err := validateWorkspacePVCSpec(claim, desired); err != nil {
		changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionFalse, "WorkspaceSpecConflict", err.Error())
		return ctrl.Result{}, false, false, changed, err
	}
	labelsChanged := false
	if claim.Labels == nil {
		claim.Labels = map[string]string{}
	}
	for key, value := range desired.Labels {
		if claim.Labels[key] != value {
			claim.Labels[key] = value
			labelsChanged = true
		}
	}
	if labelsChanged {
		if err := r.Update(ctx, claim); err != nil {
			return ctrl.Result{}, false, false, false, fmt.Errorf("update workspace PVC labels: %w", err)
		}
	}
	if claim.Status.Phase == corev1.ClaimLost {
		err := fmt.Errorf("workspace PVC %s/%s is Lost and will not be replaced automatically", claim.Namespace, claim.Name)
		changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionFalse, "WorkspaceLost", err.Error())
		return ctrl.Result{}, false, false, changed, err
	}
	if claim.Status.Phase != corev1.ClaimBound {
		changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionFalse, "WorkspacePending", "waiting for persistent workspace claim to bind")
		return ctrl.Result{RequeueAfter: workspacePVCReadyRequeue}, true, false, changed, nil
	}
	changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionTrue, "WorkspaceReady", "persistent workspace claim is bound")
	return ctrl.Result{}, true, true, changed, nil
}

func (r *AgentRunReconciler) reconcileDockerPVC(
	ctx context.Context,
	agentRun *nvtv1alpha1.AgentRun,
	workspaceBound bool,
) (ctrl.Result, bool, bool, error) {
	desired, err := DesiredDockerPVC(agentRun, r.Scheme)
	if err != nil {
		changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionFalse, "InvalidDockerStorage", err.Error())
		return ctrl.Result{}, false, changed, err
	}
	claim := &corev1.PersistentVolumeClaim{}
	err = r.Get(ctx, client.ObjectKeyFromObject(desired), claim)
	if errors.IsNotFound(err) {
		if err := r.Create(ctx, desired); err != nil {
			return ctrl.Result{}, false, false, fmt.Errorf("create Docker PVC: %w", err)
		}
		changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionFalse, "WorkspacePending", "waiting for persistent workspace and Docker claims to bind")
		return ctrl.Result{RequeueAfter: workspacePVCReadyRequeue}, true, changed, nil
	}
	if err != nil {
		return ctrl.Result{}, false, false, fmt.Errorf("get Docker PVC: %w", err)
	}
	if !metav1.IsControlledBy(claim, agentRun) {
		err := fmt.Errorf("Docker PVC %s/%s exists but is not controlled by AgentRun %s", claim.Namespace, claim.Name, agentRun.Name)
		changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionFalse, "DockerStorageOwnershipConflict", err.Error())
		return ctrl.Result{}, false, changed, err
	}
	if err := validateDockerPVCSpec(claim, desired); err != nil {
		changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionFalse, "DockerStorageSpecConflict", err.Error())
		return ctrl.Result{}, false, changed, err
	}
	labelsChanged := false
	if claim.Labels == nil {
		claim.Labels = map[string]string{}
	}
	for key, value := range desired.Labels {
		if claim.Labels[key] != value {
			claim.Labels[key] = value
			labelsChanged = true
		}
	}
	if labelsChanged {
		if err := r.Update(ctx, claim); err != nil {
			return ctrl.Result{}, false, false, fmt.Errorf("update Docker PVC labels: %w", err)
		}
	}
	if !claim.DeletionTimestamp.IsZero() {
		changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionFalse, "DockerStorageDeleting", "waiting for the previous Docker claim to finish deletion")
		return ctrl.Result{RequeueAfter: workspacePVCReadyRequeue}, false, changed, nil
	}
	if claim.Status.Phase == corev1.ClaimLost {
		err := fmt.Errorf("Docker PVC %s/%s is Lost and will not be replaced automatically", claim.Namespace, claim.Name)
		changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionFalse, "DockerStorageLost", err.Error())
		return ctrl.Result{}, false, changed, err
	}
	if claim.Status.Phase != corev1.ClaimBound {
		changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionFalse, "WorkspacePending", "waiting for persistent workspace and Docker claims to bind")
		return ctrl.Result{RequeueAfter: workspacePVCReadyRequeue}, true, changed, nil
	}
	if workspaceBound {
		changed := r.setRunCondition(agentRun, ConditionWorkspaceReady, metav1.ConditionTrue, "WorkspaceReady", "persistent workspace and Docker claims are bound")
		return ctrl.Result{}, true, changed, nil
	}
	return ctrl.Result{RequeueAfter: workspacePVCReadyRequeue}, true, false, nil
}

// reconcileLegacyDockerStorageMigration preserves an already-running Pod that
// predates the dedicated Docker PVC. A Pending claim cannot bind without a
// consumer under WaitForFirstConsumer, so remove only that owned, validated,
// unused claim. A Bound claim is retained for the next supported Pod
// replacement. No claim is created until a Pod that references it is needed.
func (r *AgentRunReconciler) reconcileLegacyDockerStorageMigration(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) error {
	desired, err := DesiredDockerPVC(agentRun, r.Scheme)
	if err != nil {
		return err
	}
	claim := &corev1.PersistentVolumeClaim{}
	err = r.Get(ctx, client.ObjectKeyFromObject(desired), claim)
	if errors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("get legacy-migration Docker PVC: %w", err)
	}
	if !metav1.IsControlledBy(claim, agentRun) {
		return fmt.Errorf("Docker PVC %s/%s exists but is not controlled by AgentRun %s", claim.Namespace, claim.Name, agentRun.Name)
	}
	if err := validateDockerPVCSpec(claim, desired); err != nil {
		return err
	}
	if claim.Status.Phase == corev1.ClaimLost {
		return fmt.Errorf("Docker PVC %s/%s is Lost and will not be replaced automatically", claim.Namespace, claim.Name)
	}
	if claim.Status.Phase == corev1.ClaimBound || !claim.DeletionTimestamp.IsZero() {
		return nil
	}
	if err := r.Delete(ctx, claim); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("delete unreferenced legacy-migration Docker PVC: %w", err)
	}
	return nil
}

func podUsesDockerPVC(pod *corev1.Pod, claimName string) bool {
	for _, volume := range pod.Spec.Volumes {
		if volume.Name == dindStorageVolumeName && volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == claimName {
			return true
		}
	}
	return false
}

func validateWorkspacePVCSpec(actual, desired *corev1.PersistentVolumeClaim) error {
	if !reflect.DeepEqual(actual.Spec.AccessModes, desired.Spec.AccessModes) ||
		!reflect.DeepEqual(actual.Spec.VolumeMode, desired.Spec.VolumeMode) ||
		actual.Spec.Selector != nil || actual.Spec.DataSource != nil || actual.Spec.DataSourceRef != nil ||
		len(actual.Spec.Resources.Limits) != 0 || len(actual.Spec.Resources.Requests) != 1 {
		return fmt.Errorf("workspace PVC %s/%s has immutable storage settings that differ from spec.workspace", actual.Namespace, actual.Name)
	}
	// When storageClassName is omitted, the cluster's defaulting admission may
	// populate the chosen class on the stored PVC. An explicitly requested class
	// must still match exactly.
	if desired.Spec.StorageClassName != nil && !reflect.DeepEqual(actual.Spec.StorageClassName, desired.Spec.StorageClassName) {
		return fmt.Errorf("workspace PVC %s/%s has immutable storage settings that differ from spec.workspace", actual.Namespace, actual.Name)
	}
	actualSize := actual.Spec.Resources.Requests[corev1.ResourceStorage]
	desiredSize := desired.Spec.Resources.Requests[corev1.ResourceStorage]
	if actualSize.Cmp(desiredSize) != 0 {
		return fmt.Errorf("workspace PVC %s/%s size differs from immutable spec.workspace.size", actual.Namespace, actual.Name)
	}
	return nil
}

func validateDockerPVCSpec(actual, desired *corev1.PersistentVolumeClaim) error {
	if !reflect.DeepEqual(actual.Spec.AccessModes, desired.Spec.AccessModes) ||
		!reflect.DeepEqual(actual.Spec.VolumeMode, desired.Spec.VolumeMode) ||
		actual.Spec.Selector != nil || actual.Spec.DataSource != nil || actual.Spec.DataSourceRef != nil ||
		len(actual.Spec.Resources.Limits) != 0 || len(actual.Spec.Resources.Requests) != 1 {
		return fmt.Errorf("Docker PVC %s/%s has immutable storage settings that differ from spec.workspace", actual.Namespace, actual.Name)
	}
	if desired.Spec.StorageClassName != nil && !reflect.DeepEqual(actual.Spec.StorageClassName, desired.Spec.StorageClassName) {
		return fmt.Errorf("Docker PVC %s/%s has immutable storage settings that differ from spec.workspace", actual.Namespace, actual.Name)
	}
	actualSize := actual.Spec.Resources.Requests[corev1.ResourceStorage]
	desiredSize := desired.Spec.Resources.Requests[corev1.ResourceStorage]
	if actualSize.Cmp(desiredSize) != 0 {
		return fmt.Errorf("Docker PVC %s/%s size differs from immutable spec.workspace.dockerSize", actual.Namespace, actual.Name)
	}
	return nil
}

// DesiredAgentPod returns the create-once Pod spec for an AgentRun.
