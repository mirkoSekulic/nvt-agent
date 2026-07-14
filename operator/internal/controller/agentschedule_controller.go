package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"reflect"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

const (
	scheduleLabel            = "nvt.dev/schedule"
	workIDAnnotation         = "nvt.dev/work-id"
	workURLAnnotation        = "nvt.dev/work-url"
	workRepositoryAnnotation = "nvt.dev/work-repository"
	accessKeyAnnotation      = "nvt.dev/access-key"
	displayNameAnnotation    = "nvt.dev/display-name"
	sourceURLAnnotation      = "nvt.dev/source-url"
	accessPortAnnotation     = "nvt.dev/access-port"
	defaultParallelism       = int32(1)
	generatedNameSuffix      = 5
)

type scheduleAdmissionWorkMetadata struct {
	ID         string
	Title      string
	URL        string
	Repository string
}

// AgentScheduleReconciler reconciles generic AgentSchedule admission-pool status.
type AgentScheduleReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// Reconcile syncs observed generation and active AgentRun count.
func (r *AgentScheduleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var schedule nvtv1alpha1.AgentSchedule
	if err := r.Get(ctx, req.NamespacedName, &schedule); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	activeRuns, err := CountActiveScheduledRuns(ctx, r.Client, &schedule)
	if err != nil {
		return ctrl.Result{}, err
	}

	nextStatus := schedule.Status
	nextStatus.ObservedGeneration = schedule.Generation
	nextStatus.ActiveRuns = activeRuns
	if reflect.DeepEqual(schedule.Status, nextStatus) {
		return ctrl.Result{}, nil
	}

	schedule.Status = nextStatus
	if err := r.Status().Update(ctx, &schedule); err != nil {
		return ctrl.Result{}, fmt.Errorf("update AgentSchedule status: %w", err)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager registers the AgentSchedule controller with the manager.
func (r *AgentScheduleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := ctrl.NewControllerManagedBy(mgr).
		For(&nvtv1alpha1.AgentSchedule{}).
		Owns(&nvtv1alpha1.AgentRun{}).
		Complete(r); err != nil {
		return fmt.Errorf("build AgentSchedule controller: %w", err)
	}

	return nil
}

// CountActiveScheduledRuns returns the non-terminal AgentRuns accepted by a schedule.
func CountActiveScheduledRuns(ctx context.Context, reader client.Reader, schedule *nvtv1alpha1.AgentSchedule) (int32, error) {
	runs, err := ListScheduledRuns(ctx, reader, schedule)
	if err != nil {
		return 0, err
	}

	var active int32
	for i := range runs.Items {
		if IsActiveScheduledRun(&runs.Items[i]) {
			active++
		}
	}
	return active, nil
}

// ListScheduledRuns returns AgentRuns labeled as accepted by a schedule.
func ListScheduledRuns(ctx context.Context, reader client.Reader, schedule *nvtv1alpha1.AgentSchedule) (*nvtv1alpha1.AgentRunList, error) {
	var runs nvtv1alpha1.AgentRunList
	if err := reader.List(
		ctx,
		&runs,
		client.InNamespace(schedule.Namespace),
		client.MatchingLabels{scheduleLabel: schedule.Name},
	); err != nil {
		return nil, fmt.Errorf("list scheduled AgentRuns: %w", err)
	}
	return &runs, nil
}

// IsActiveScheduledRun reports whether a run counts against schedule capacity.
func IsActiveScheduledRun(run *nvtv1alpha1.AgentRun) bool {
	return !IsTerminalAgentRunPhase(run.Status.Phase)
}

// EffectiveMaxParallelism returns the configured parallelism or the safe default.
func EffectiveMaxParallelism(schedule *nvtv1alpha1.AgentSchedule) int32 {
	if schedule.Spec.MaxParallelism > 0 {
		return schedule.Spec.MaxParallelism
	}
	return defaultParallelism
}

// PrepareScheduledAgentRun applies reserved metadata and ownership for admission-created runs.
func PrepareScheduledAgentRun(
	schedule *nvtv1alpha1.AgentSchedule,
	run *nvtv1alpha1.AgentRun,
	work scheduleAdmissionWorkMetadata,
	scheme *runtime.Scheme,
) error {
	run.Namespace = schedule.Namespace
	run.Status = nvtv1alpha1.AgentRunStatus{}
	if run.APIVersion == "" {
		run.APIVersion = nvtv1alpha1.GroupVersion.String()
	}
	if run.Kind == "" {
		run.Kind = "AgentRun"
	}
	if run.Name == "" && run.GenerateName == "" {
		run.GenerateName = schedule.Name + "-"
	}
	if run.Name == "" {
		generated, err := generatedRunName(run.GenerateName)
		if err != nil {
			return err
		}
		run.Name = generated
	}

	if run.Labels == nil {
		run.Labels = map[string]string{}
	}
	run.Labels[scheduleLabel] = schedule.Name
	if run.Annotations == nil {
		run.Annotations = map[string]string{}
	}
	run.Annotations[workIDAnnotation] = work.ID
	if work.URL != "" {
		run.Annotations[workURLAnnotation] = work.URL
	} else {
		delete(run.Annotations, workURLAnnotation)
	}
	if work.Repository != "" {
		run.Annotations[workRepositoryAnnotation] = work.Repository
	} else {
		delete(run.Annotations, workRepositoryAnnotation)
	}
	run.Annotations[accessKeyAnnotation] = run.Name
	if run.Annotations[displayNameAnnotation] == "" {
		if work.Title != "" {
			run.Annotations[displayNameAnnotation] = work.Title
		} else {
			run.Annotations[displayNameAnnotation] = run.Name
		}
	}
	if work.URL != "" {
		run.Annotations[sourceURLAnnotation] = work.URL
	}
	if run.Annotations[accessPortAnnotation] == "" {
		run.Annotations[accessPortAnnotation] = "4090"
	}

	if err := controllerutil.SetControllerReference(schedule, run, scheme); err != nil {
		return fmt.Errorf("set AgentSchedule owner: %w", err)
	}
	if err := ValidateAgentRunEgressMode(run); err != nil {
		return err
	}
	return nil
}

func generatedRunName(prefix string) (string, error) {
	randomBytes := make([]byte, generatedNameSuffix)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate AgentRun name: %w", err)
	}
	return prefix + hex.EncodeToString(randomBytes), nil
}

func retainedWorkExists(runs *nvtv1alpha1.AgentRunList, workID string) bool {
	for i := range runs.Items {
		run := &runs.Items[i]
		if run.Annotations[workIDAnnotation] == workID {
			return true
		}
	}
	return false
}
