package controller

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver/host"
)

type fakeExecutionDriverRegistry map[string]host.Client

func (r fakeExecutionDriverRegistry) Client(name string) (host.Client, bool) {
	value, found := r[name]
	return value, found
}

type recordingExecutionDriver struct {
	mu             sync.Mutex
	desired        []executiondriver.DesiredExecution
	deleteIDs      []string
	reconcile      []executiondriver.Status
	delete         []executiondriver.Status
	reconcileError error
	deleteError    error
}

func (d *recordingExecutionDriver) Reconcile(_ context.Context, desired executiondriver.DesiredExecution) (executiondriver.Status, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.desired = append(d.desired, desired)
	if d.reconcileError != nil {
		return executiondriver.Status{}, d.reconcileError
	}
	if len(d.reconcile) == 0 {
		return executiondriver.Status{}, errors.New("no test reconcile status")
	}
	status := d.reconcile[0]
	if len(d.reconcile) > 1 {
		d.reconcile = d.reconcile[1:]
	}
	if status.ObservedGeneration == -1 {
		status.ObservedGeneration = desired.Generation
	}
	return status, nil
}

func (*recordingExecutionDriver) Observe(context.Context, string) (executiondriver.Status, error) {
	return executiondriver.Status{}, errors.New("unexpected observe")
}

func (d *recordingExecutionDriver) Delete(_ context.Context, executionID string) (executiondriver.Status, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.deleteIDs = append(d.deleteIDs, executionID)
	if d.deleteError != nil {
		return executiondriver.Status{}, d.deleteError
	}
	if len(d.delete) == 0 {
		return executiondriver.Status{}, errors.New("no test delete status")
	}
	status := d.delete[0]
	if len(d.delete) > 1 {
		d.delete = d.delete[1:]
	}
	return status, nil
}

func (*recordingExecutionDriver) Shutdown(context.Context) error { return nil }

func TestExternalExecutionUsesExactDriverAndDeterministicDesiredState(t *testing.T) {
	ctx := context.Background()
	run := externalTestAgentRun()
	run.Generation = 7
	retry := int32(1)
	driver := &recordingExecutionDriver{reconcile: []executiondriver.Status{
		{Phase: executiondriver.PhaseProvisioning, ObservedGeneration: -1, RetryAfterSeconds: &retry},
		{Phase: executiondriver.PhaseRunning, Ready: true, ObservedGeneration: -1, Endpoint: &executiondriver.Endpoint{Scheme: executiondriver.EndpointSchemeHTTPS, Host: "vm.invalid", Port: 443}, ExternalResourceID: "provider-secret-looking-id"},
	}}
	other := &recordingExecutionDriver{}
	k8sClient, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{"example-vm": driver, "other": other})

	// The first pass persists the finalizer and performs no provider mutation.
	if result, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil || !result.Requeue {
		t.Fatalf("first reconcile result=%#v err=%v", result, err)
	}
	if len(driver.desired) != 0 {
		t.Fatal("driver was called before the external finalizer was durable")
	}
	if _, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatalf("provisioning reconcile: %v", err)
	}
	if result, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil || result.RequeueAfter != externalExecutionDefaultRequeue {
		t.Fatalf("ready reconcile result=%#v err=%v", result, err)
	}

	if len(driver.desired) != 2 || len(other.desired) != 0 {
		t.Fatalf("exact selection calls=%d other=%d", len(driver.desired), len(other.desired))
	}
	first, second := driver.desired[0], driver.desired[1]
	if !reflect.DeepEqual(first, second) || first.Generation != 7 || first.WorkloadKind != executiondriver.WorkloadKindVM ||
		first.ClassName != "vm-standard" || string(first.Configuration) != `{"cpu":4,"nested":{"a":1,"z":2}}` ||
		!strings.HasPrefix(first.ExecutionID, "nvt-agentrun-") || executiondriver.ValidateDesiredFingerprint(first.DesiredFingerprint) != nil {
		t.Fatalf("unexpected deterministic desired state: %#v / %#v", first, second)
	}
	reordered := run.DeepCopyObject().(*nvtv1alpha1.AgentRun)
	reordered.Spec.Execution.Configuration = rawJSON(`{"cpu":4,"nested":{"a":1,"z":2}}`)
	reorderedDesired, err := desiredExternalExecution(reordered)
	if err != nil || reorderedDesired.DesiredFingerprint != first.DesiredFingerprint ||
		string(reorderedDesired.Configuration) != string(first.Configuration) {
		t.Fatalf("equivalent object order changed canonical desired state: %#v err=%v", reorderedDesired, err)
	}

	updated := getExternalRun(t, ctx, k8sClient, run)
	if updated.Status.Phase != nvtv1alpha1.AgentRunPhaseRunning || updated.Status.PodName != "" ||
		updated.Status.Reason != executionDriverReadyReason || strings.Contains(updated.Status.Reason, "provider-secret") {
		t.Fatalf("unexpected portable status: %#v", updated.Status)
	}
	available := meta.FindStatusCondition(updated.Status.Conditions, ConditionExecutionBackendAvailable)
	ready := meta.FindStatusCondition(updated.Status.Conditions, ConditionExternalExecutionReady)
	if available == nil || available.Status != metav1.ConditionTrue || ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("unexpected conditions: %#v", updated.Status.Conditions)
	}
	assertNoAgentPods(t, ctx, k8sClient, run.Namespace)
}

func TestExternalExecutionUnavailableAndMalformedResponsesFailClosed(t *testing.T) {
	tests := map[string]*recordingExecutionDriver{
		"unavailable":          {reconcileError: errors.New("REMOTE-TOKEN-CANARY connection failed")},
		"malformed generation": {reconcile: []executiondriver.Status{{Phase: executiondriver.PhaseRunning, ObservedGeneration: 99}}},
		"permanent rejection":  {reconcileError: &host.DriverError{Failure: executiondriver.Failure{Reason: "provider-denied", Message: "REMOTE-TOKEN-CANARY", Retryable: false}}},
	}
	for name, driver := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			run := externalTestAgentRun()
			run.Finalizers = []string{externalExecutionFinalizer}
			k8sClient, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{"example-vm": driver})
			result, err := reconciler.Reconcile(ctx, requestFor(run))
			if err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			updated := getExternalRun(t, ctx, k8sClient, run)
			encoded := updated.Status.Reason
			for _, condition := range updated.Status.Conditions {
				encoded += condition.Reason + condition.Message
			}
			if strings.Contains(encoded, "REMOTE-TOKEN-CANARY") {
				t.Fatalf("status disclosed remote diagnostic: %#v", updated.Status)
			}
			condition := meta.FindStatusCondition(updated.Status.Conditions, ConditionExecutionBackendAvailable)
			if condition == nil || condition.Status != metav1.ConditionFalse {
				t.Fatalf("unavailable condition=%#v", condition)
			}
			if name == "permanent rejection" {
				if result.RequeueAfter != 0 || condition.Reason != executionDriverRejectedReason {
					t.Fatalf("permanent result=%#v condition=%#v", result, condition)
				}
			} else if result.RequeueAfter != externalExecutionDefaultRequeue {
				t.Fatalf("transient result=%#v", result)
			}
			assertNoAgentPods(t, ctx, k8sClient, run.Namespace)
		})
	}
}

func TestExternalExecutionRestartRecoveryUsesSameDesiredState(t *testing.T) {
	ctx := context.Background()
	run := externalTestAgentRun()
	run.Finalizers = []string{externalExecutionFinalizer}
	driver := &recordingExecutionDriver{reconcile: []executiondriver.Status{
		{Phase: executiondriver.PhaseProvisioning, ObservedGeneration: -1},
		{Phase: executiondriver.PhaseRunning, Ready: true, ObservedGeneration: -1, Endpoint: &executiondriver.Endpoint{Scheme: executiondriver.EndpointSchemeHTTPS, Host: "vm.invalid", Port: 443}},
	}}
	k8sClient, first := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{"example-vm": driver})
	if _, err := first.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatal(err)
	}
	// A fresh reconciler has no call history and derives the identical request.
	second := &AgentRunReconciler{Client: k8sClient, Scheme: first.Scheme, ExecutionDrivers: fakeExecutionDriverRegistry{"example-vm": driver}}
	if _, err := second.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatal(err)
	}
	if len(driver.desired) != 2 || !reflect.DeepEqual(driver.desired[0], driver.desired[1]) {
		t.Fatalf("restart changed desired state: %#v", driver.desired)
	}
}

func TestExternalExecutionDeletionConvergesAndRetainsFinalizerWhenMissing(t *testing.T) {
	ctx := context.Background()
	now := metav1.Now()
	run := externalTestAgentRun()
	run.Finalizers = []string{agentRunFinalizer, externalExecutionFinalizer}
	run.DeletionTimestamp = &now
	driver := &recordingExecutionDriver{delete: []executiondriver.Status{
		{Phase: executiondriver.PhaseDeleting, RetryAfterSeconds: ptrTo[int32](1)},
		{Phase: executiondriver.PhaseDeleted},
	}}
	k8sClient, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{})

	result, err := reconciler.Reconcile(ctx, requestFor(run))
	if err != nil || result.RequeueAfter != externalExecutionDefaultRequeue {
		t.Fatalf("missing registration result=%#v err=%v", result, err)
	}
	retained := getExternalRun(t, ctx, k8sClient, run)
	if !controllerHasFinalizer(&retained, externalExecutionFinalizer) || len(driver.deleteIDs) != 0 {
		t.Fatalf("missing registration lost finalizer or called another driver: %#v", retained.Finalizers)
	}

	reconciler.ExecutionDrivers = fakeExecutionDriverRegistry{"example-vm": driver}
	if result, err = reconciler.Reconcile(ctx, requestFor(run)); err != nil || result.RequeueAfter != externalExecutionMinimumRequeue {
		t.Fatalf("deleting result=%#v err=%v", result, err)
	}
	if _, err = reconciler.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatalf("deleted reconcile: %v", err)
	}
	if len(driver.deleteIDs) != 2 || driver.deleteIDs[0] != driver.deleteIDs[1] {
		t.Fatalf("delete did not use stable exact identity: %#v", driver.deleteIDs)
	}
	var deleted nvtv1alpha1.AgentRun
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(run), &deleted); err == nil || !apierrors.IsNotFound(err) {
		t.Fatalf("AgentRun remained after completed driver cleanup: err=%v object=%#v", err, deleted)
	}
	assertNoAgentPods(t, ctx, k8sClient, run.Namespace)
}

func externalTestAgentRun() *nvtv1alpha1.AgentRun {
	run := testAgentRun()
	run.Spec.Execution = &nvtv1alpha1.AgentRunExecution{
		Kind: nvtv1alpha1.AgentRunExecutionVM, Driver: "example-vm", ClassRef: "vm-standard",
		Configuration: rawJSON(`{"nested":{"z":2,"a":1},"cpu":4}`),
	}
	return run
}

func externalReconcileFixture(t *testing.T, run *nvtv1alpha1.AgentRun, registry executionDriverClientRegistry) (client.Client, *AgentRunReconciler) {
	t.Helper()
	scheme := testScheme(t)
	objects := []client.Object{run, testBrokerAgentsConfigMap(run.Namespace)}
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&nvtv1alpha1.AgentRun{}).WithObjects(objects...).Build()
	return k8sClient, &AgentRunReconciler{Client: k8sClient, Scheme: scheme, ExecutionDrivers: registry}
}

func getExternalRun(t *testing.T, ctx context.Context, k8sClient client.Client, run *nvtv1alpha1.AgentRun) nvtv1alpha1.AgentRun {
	t.Helper()
	var updated nvtv1alpha1.AgentRun
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(run), &updated); err != nil {
		t.Fatal(err)
	}
	return updated
}

func assertNoAgentPods(t *testing.T, ctx context.Context, k8sClient client.Client, namespace string) {
	t.Helper()
	var pods corev1.PodList
	if err := k8sClient.List(ctx, &pods, client.InNamespace(namespace)); err != nil || len(pods.Items) != 0 {
		t.Fatalf("external execution created an Agent Pod: err=%v pods=%#v", err, pods.Items)
	}
}

func controllerHasFinalizer(run *nvtv1alpha1.AgentRun, finalizer string) bool {
	for _, item := range run.Finalizers {
		if item == finalizer {
			return true
		}
	}
	return false
}

func TestExternalExecutionRetryHintIsControllerBounded(t *testing.T) {
	minimum := int32(1)
	maximum := int32(executiondriver.MaxRetryAfterSeconds)
	if got := externalExecutionRequeue(executiondriver.Status{Phase: executiondriver.PhaseProvisioning, RetryAfterSeconds: &minimum}); got != externalExecutionMinimumRequeue {
		t.Fatalf("minimum hint=%s", got)
	}
	if got := externalExecutionRequeue(executiondriver.Status{Phase: executiondriver.PhaseProvisioning, RetryAfterSeconds: &maximum}); got != externalExecutionMaximumRequeue {
		t.Fatalf("maximum hint=%s", got)
	}
	if got := externalExecutionRequeue(executiondriver.Status{Phase: executiondriver.PhaseFailed}); got != 0 {
		t.Fatalf("terminal requeue=%s", got)
	}
	if got := externalExecutionRequeue(executiondriver.Status{Phase: executiondriver.PhaseFailed, Failure: &executiondriver.Failure{Reason: "temporary", Retryable: true}}); got != externalExecutionDefaultRequeue {
		t.Fatalf("retryable failure requeue=%s", got)
	}
}
