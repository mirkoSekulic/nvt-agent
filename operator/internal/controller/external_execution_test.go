package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver/host"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
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
	reconcileBlock <-chan struct{}
	reconcileStart chan<- struct{}
}

type recordingEnrollmentDriver struct {
	*recordingExecutionDriver
	mu                sync.Mutex
	guestID           string
	prepared          bool
	accepted          bool
	prepareCalls      int
	replaceCalls      int
	deliverCalls      int
	prepareError      error
	prepareBlock      <-chan struct{}
	prepareStart      chan<- struct{}
	replaceError      error
	deliverError      error
	deliverBlock      bool
	acceptBeforeError bool
	deliveredToken    string
	operationSequence *[]string
}

func (d *recordingEnrollmentDriver) Prepare(ctx context.Context, request guestenrollment.HandoffPrepareRequest) (guestenrollment.HandoffPrepareResult, error) {
	d.mu.Lock()
	d.prepareCalls++
	block := d.prepareBlock
	started := d.prepareStart
	if d.prepareError != nil {
		err := d.prepareError
		d.mu.Unlock()
		return guestenrollment.HandoffPrepareResult{}, err
	}
	d.mu.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return guestenrollment.HandoffPrepareResult{}, ctx.Err()
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.prepareError != nil {
		return guestenrollment.HandoffPrepareResult{}, d.prepareError
	}
	if d.guestID == "" {
		d.guestID = "guest-instance-1"
	}
	newlyPrepared := !d.prepared
	d.prepared = true
	state := guestenrollment.HandoffStatePrepared
	if d.accepted {
		state = guestenrollment.HandoffStateAccepted
		newlyPrepared = false
	}
	return guestenrollment.HandoffPrepareResult{ContractVersion: guestenrollment.HandoffVersion, GuestInstanceID: d.guestID, State: state, NewlyPrepared: newlyPrepared}, nil
}

func (d *recordingEnrollmentDriver) Replace(_ context.Context, request guestenrollment.HandoffReplaceRequest) (guestenrollment.HandoffPrepareResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.replaceError != nil {
		return guestenrollment.HandoffPrepareResult{}, d.replaceError
	}
	if request.Binding.GuestInstanceID != d.guestID {
		return guestenrollment.HandoffPrepareResult{}, errors.New("wrong guest")
	}
	d.replaceCalls++
	d.guestID = "guest-instance-replacement"
	d.accepted = false
	d.prepared = true
	return guestenrollment.HandoffPrepareResult{ContractVersion: guestenrollment.HandoffVersion, GuestInstanceID: d.guestID, State: guestenrollment.HandoffStatePrepared, NewlyPrepared: true}, nil
}

func (d *recordingEnrollmentDriver) Deliver(ctx context.Context, request guestenrollment.HandoffDeliverRequest) error {
	d.mu.Lock()
	d.deliverCalls++
	d.deliveredToken = request.Envelope.Token
	if request.Envelope.Binding.GuestInstanceID != d.guestID {
		d.mu.Unlock()
		return errors.New("wrong guest")
	}
	block := d.deliverBlock
	d.mu.Unlock()
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.deliverError == nil || d.acceptBeforeError {
		d.accepted = true
	}
	return d.deliverError
}

func (d *recordingEnrollmentDriver) Delete(ctx context.Context, executionID string) (executiondriver.Status, error) {
	if d.operationSequence != nil {
		*d.operationSequence = append(*d.operationSequence, "driver-delete")
	}
	return d.recordingExecutionDriver.Delete(ctx, executionID)
}

type recordingEnrollmentIssuer struct {
	mu              sync.Mutex
	issues          []guestenrollment.IssueRequest
	revokeBindings  []guestenrollment.RevokeBindingRequest
	revokeScopes    []guestenrollment.RevokeExecutionRequest
	completions     []guestenrollment.CompleteExecutionCleanupRequest
	issueError      error
	revokeError     error
	completionError error
	sequence        *[]string
	handoffTimeout  time.Duration
}

func (i *recordingEnrollmentIssuer) EnabledFor(_ string) bool { return true }

func (i *recordingEnrollmentIssuer) TTLSeconds() int32 { return 300 }
func (i *recordingEnrollmentIssuer) HandoffTimeout() time.Duration {
	if i.handoffTimeout > 0 {
		return i.handoffTimeout
	}
	return time.Second
}

func (i *recordingEnrollmentIssuer) Issue(_ context.Context, request guestenrollment.IssueRequest) (guestenrollment.BootstrapEnvelope, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.issues = append(i.issues, request)
	if i.issueError != nil {
		return guestenrollment.BootstrapEnvelope{}, i.issueError
	}
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	return guestenrollment.BootstrapEnvelope{
		ContractVersion: guestenrollment.Version, Binding: request.Binding,
		ExchangeURL: "https://broker.example/v1/guest-enrollment/exchange",
		Token:       base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, guestenrollment.TokenBytes)),
		IssuedAt:    guestenrollment.FormatTimestamp(now), ExpiresAt: guestenrollment.FormatTimestamp(now.Add(5 * time.Minute)),
	}, nil
}

func (i *recordingEnrollmentIssuer) RevokeBinding(_ context.Context, request guestenrollment.RevokeBindingRequest) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.revokeBindings = append(i.revokeBindings, request)
	return i.revokeError
}

func (i *recordingEnrollmentIssuer) RevokeExecution(_ context.Context, request guestenrollment.RevokeExecutionRequest) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.revokeScopes = append(i.revokeScopes, request)
	if i.sequence != nil {
		*i.sequence = append(*i.sequence, "scope-revoke")
	}
	return i.revokeError
}

func (i *recordingEnrollmentIssuer) CompleteExecutionCleanup(_ context.Context, request guestenrollment.CompleteExecutionCleanupRequest) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.completions = append(i.completions, request)
	if i.sequence != nil {
		*i.sequence = append(*i.sequence, "cleanup-complete")
	}
	return i.completionError
}

func (d *recordingExecutionDriver) Reconcile(ctx context.Context, desired executiondriver.DesiredExecution) (executiondriver.Status, error) {
	d.mu.Lock()
	d.desired = append(d.desired, desired)
	block := d.reconcileBlock
	started := d.reconcileStart
	d.mu.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return executiondriver.Status{}, ctx.Err()
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
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
			run.Status.NativeGuestBinding = nativeGuestBindingStatus(exactNativeGuestBindingForRun(t, run, "failed-guest"))
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
			if updated.Status.NativeGuestBinding != nil {
				t.Fatalf("backend failure retained native guest binding: %#v", updated.Status.NativeGuestBinding)
			}
			if name == "permanent rejection" {
				if result.RequeueAfter <= 0 || condition.Reason != executionDriverRejectedReason ||
					updated.Status.Phase != nvtv1alpha1.AgentRunPhaseFailed || updated.Status.FinishedAt == nil {
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

func TestExternalExecutionTerminalResourceTTLDeletesProviderBeforeRunRetention(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	finished := metav1.Date(2026, 7, 27, 11, 59, 0, 0, time.UTC)
	tests := []struct {
		name  string
		phase nvtv1alpha1.AgentRunPhase
	}{
		{name: "completed", phase: nvtv1alpha1.AgentRunPhaseCompleted},
		{name: "failed", phase: nvtv1alpha1.AgentRunPhaseFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			run := externalTestAgentRun()
			run.Finalizers = []string{externalExecutionFinalizer}
			run.Status.Phase = test.phase
			run.Status.FinishedAt = &finished
			run.Spec.TTL = &nvtv1alpha1.AgentRunTTL{RunRetentionSeconds: ptrTo[int64](3600)}
			if test.phase == nvtv1alpha1.AgentRunPhaseCompleted {
				run.Spec.TTL.CompletedTTLSeconds = ptrTo[int64](0)
			} else {
				run.Spec.TTL.FailedTTLSeconds = ptrTo[int64](0)
			}
			driver := &recordingExecutionDriver{delete: []executiondriver.Status{
				{Phase: executiondriver.PhaseDeleting, RetryAfterSeconds: ptrTo[int32](1)},
				{Phase: executiondriver.PhaseDeleted},
			}}
			k8sClient, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{"example-vm": driver})
			reconciler.Now = func() metav1.Time { return now }

			if result, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil || result.RequeueAfter != externalExecutionMinimumRequeue {
				t.Fatalf("first cleanup result=%#v err=%v", result, err)
			}
			progress := getExternalRun(t, ctx, k8sClient, run)
			if progress.Status.Phase != test.phase || !controllerHasFinalizer(&progress, externalExecutionFinalizer) {
				t.Fatalf("terminal state changed before cleanup: %#v", progress)
			}
			if result, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil || result.RequeueAfter != 3540*time.Second {
				t.Fatalf("completed cleanup result=%#v err=%v", result, err)
			}
			retained := getExternalRun(t, ctx, k8sClient, run)
			if retained.Status.Phase != test.phase || controllerHasFinalizer(&retained, externalExecutionFinalizer) || len(driver.deleteIDs) != 2 {
				t.Fatalf("provider cleanup did not preserve retained terminal run: %#v deletes=%#v", retained, driver.deleteIDs)
			}
			assertNoAgentPods(t, ctx, k8sClient, run.Namespace)
		})
	}
}

func TestExternalExecutionRunRetentionZeroStillCleansProviderAtResourceTTL(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	finished := metav1.Date(2026, 7, 27, 11, 59, 0, 0, time.UTC)
	run := externalTestAgentRun()
	run.Finalizers = []string{externalExecutionFinalizer}
	run.Status.Phase = nvtv1alpha1.AgentRunPhaseCompleted
	run.Status.FinishedAt = &finished
	run.Spec.TTL = &nvtv1alpha1.AgentRunTTL{CompletedTTLSeconds: ptrTo[int64](0), RunRetentionSeconds: ptrTo[int64](0)}
	driver := &recordingExecutionDriver{delete: []executiondriver.Status{{Phase: executiondriver.PhaseDeleted}}}
	k8sClient, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{"example-vm": driver})
	reconciler.Now = func() metav1.Time { return now }

	if result, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil || result.RequeueAfter != 0 {
		t.Fatalf("cleanup result=%#v err=%v", result, err)
	}
	retained := getExternalRun(t, ctx, k8sClient, run)
	if controllerHasFinalizer(&retained, externalExecutionFinalizer) || len(driver.deleteIDs) != 1 {
		t.Fatalf("disabled run retention retained provider cleanup obligation: %#v deletes=%#v", retained, driver.deleteIDs)
	}
}

func TestExternalExecutionActiveDeadlineTransitionsAndCleansProvider(t *testing.T) {
	ctx := context.Background()
	now := metav1.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	started := metav1.Date(2026, 7, 27, 11, 58, 0, 0, time.UTC)
	run := externalTestAgentRun()
	run.Finalizers = []string{externalExecutionFinalizer}
	run.Status.Phase = nvtv1alpha1.AgentRunPhaseRunning
	run.Status.StartedAt = &started
	run.Status.NativeGuestBinding = nativeGuestBindingStatus(exactNativeGuestBindingForRun(t, run, "deadline-guest"))
	run.Spec.TTL = &nvtv1alpha1.AgentRunTTL{ActiveDeadlineSeconds: ptrTo[int64](60), RunRetentionSeconds: ptrTo[int64](3600)}
	driver := &recordingExecutionDriver{delete: []executiondriver.Status{{Phase: executiondriver.PhaseDeleted}}}
	k8sClient, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{"example-vm": driver})
	reconciler.Now = func() metav1.Time { return now }

	if result, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil || result.RequeueAfter != time.Hour {
		t.Fatalf("deadline cleanup result=%#v err=%v", result, err)
	}
	updated := getExternalRun(t, ctx, k8sClient, run)
	if updated.Status.Phase != nvtv1alpha1.AgentRunPhaseDeadlineExceeded || updated.Status.FinishedAt == nil ||
		updated.Status.NativeGuestBinding != nil || controllerHasFinalizer(&updated, externalExecutionFinalizer) || len(driver.desired) != 0 || len(driver.deleteIDs) != 1 {
		t.Fatalf("active deadline did not converge exact cleanup: %#v reconcile=%d delete=%#v", updated, len(driver.desired), driver.deleteIDs)
	}
}

func TestExternalExecutionNonRetryableDeleteKeepsRetryingExactDriver(t *testing.T) {
	ctx := context.Background()
	now := metav1.Now()
	run := externalTestAgentRun()
	run.Finalizers = []string{externalExecutionFinalizer}
	run.DeletionTimestamp = &now
	driver := &recordingExecutionDriver{deleteError: &host.DriverError{Failure: executiondriver.Failure{Reason: "permanent-denial", Message: "DELETE-TOKEN-CANARY", Retryable: false}}}
	k8sClient, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{"example-vm": driver})

	if result, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil || result.RequeueAfter != externalExecutionCleanupRetry {
		t.Fatalf("non-retryable cleanup result=%#v err=%v", result, err)
	}
	retained := getExternalRun(t, ctx, k8sClient, run)
	if !controllerHasFinalizer(&retained, externalExecutionFinalizer) || len(driver.deleteIDs) != 1 {
		t.Fatalf("cleanup failure stranded or removed finalizer: %#v deletes=%#v", retained, driver.deleteIDs)
	}
	encodedStatus, err := json.Marshal(retained.Status)
	if err != nil || bytes.Contains(encodedStatus, []byte("DELETE-TOKEN-CANARY")) {
		t.Fatalf("cleanup status exposed remote diagnostic: %s err=%v", encodedStatus, err)
	}
	driver.deleteError = nil
	driver.delete = []executiondriver.Status{{Phase: executiondriver.PhaseDeleted}}
	if _, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatalf("cleanup recovery: %v", err)
	}
	var deleted nvtv1alpha1.AgentRun
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(run), &deleted); !apierrors.IsNotFound(err) {
		t.Fatalf("AgentRun did not finish exact-driver cleanup: err=%v object=%#v", err, deleted)
	}
	if len(driver.deleteIDs) != 2 || driver.deleteIDs[0] != driver.deleteIDs[1] {
		t.Fatalf("cleanup switched identity or driver: %#v", driver.deleteIDs)
	}
}

func TestExternalExecutionStaleTerminalGenerationCannotTerminateCurrentRun(t *testing.T) {
	tests := map[string]executiondriver.Status{
		"succeeded": {Phase: executiondriver.PhaseSucceeded, ObservedGeneration: 4},
		"failed":    {Phase: executiondriver.PhaseFailed, ObservedGeneration: 4, Failure: &executiondriver.Failure{Reason: "rejected", Retryable: false}},
	}
	for name, status := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			run := externalTestAgentRun()
			run.Generation = 5
			run.Finalizers = []string{externalExecutionFinalizer}
			run.Status.NativeGuestBinding = nativeGuestBindingStatus(exactNativeGuestBindingForRun(t, run, "stale-guest"))
			driver := &recordingExecutionDriver{reconcile: []executiondriver.Status{status}}
			k8sClient, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{"example-vm": driver})
			if result, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil || result.RequeueAfter != externalExecutionDefaultRequeue {
				t.Fatalf("stale terminal result=%#v err=%v", result, err)
			}
			updated := getExternalRun(t, ctx, k8sClient, run)
			if IsTerminalAgentRunPhase(updated.Status.Phase) || updated.Status.FinishedAt != nil || updated.Status.NativeGuestBinding != nil || updated.Status.Reason != "ExternalExecutionStaleObservation" {
				t.Fatalf("stale terminal status ended current run: %#v", updated.Status)
			}
		})
	}
}

func TestExternalExecutionStaleNonTerminalGenerationClearsRoutingBinding(t *testing.T) {
	ctx := context.Background()
	run := externalTestAgentRun()
	run.Generation = 5
	run.Finalizers = []string{externalExecutionFinalizer, guestEnrollmentFinalizer}
	run.Status.NativeGuestBinding = nativeGuestBindingStatus(exactNativeGuestBindingForRun(t, run, "current-guest"))
	driver := &recordingEnrollmentDriver{
		recordingExecutionDriver: &recordingExecutionDriver{reconcile: []executiondriver.Status{{Phase: executiondriver.PhaseProvisioning, ObservedGeneration: 4}}},
		accepted:                 true,
	}
	issuer := &recordingEnrollmentIssuer{}
	k8sClient, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{"example-vm": driver})
	reconciler.GuestEnrollment = issuer
	if _, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatal(err)
	}
	updated := getExternalRun(t, ctx, k8sClient, run)
	if updated.Status.NativeGuestBinding != nil || driver.prepareCalls != 0 || len(issuer.issues) != 0 {
		t.Fatalf("stale non-terminal generation retained or republished routing: binding=%#v prepares=%d issues=%d", updated.Status.NativeGuestBinding, driver.prepareCalls, len(issuer.issues))
	}
}

func TestStalledExternalDriversReserveWorkerForKubernetesBackend(t *testing.T) {
	ctx := context.Background()
	blocked := make(chan struct{})
	var releaseBlocked sync.Once
	release := func() { releaseBlocked.Do(func() { close(blocked) }) }
	t.Cleanup(release)
	startedA := make(chan struct{}, 1)
	startedB := make(chan struct{}, 1)
	externalA := externalTestAgentRun()
	externalA.Name = "external-a"
	externalA.UID = "external-a-uid"
	externalA.Finalizers = []string{externalExecutionFinalizer}
	externalB := externalTestAgentRun()
	externalB.Name = "external-b"
	externalB.UID = "external-b-uid"
	externalB.Spec.Execution.Driver = "example-vm-b"
	externalB.Finalizers = []string{externalExecutionFinalizer}
	kubernetesRun := testAgentRun()
	kubernetesRun.Name = "kubernetes-run"
	kubernetesRun.UID = "kubernetes-run-uid"
	kubernetesRun.Status.Phase = nvtv1alpha1.AgentRunPhaseCompleted
	kubernetesRun.Status.FinishedAt = ptrTo(metav1.Now())
	kubernetesRun.Spec.TTL = &nvtv1alpha1.AgentRunTTL{RunRetentionSeconds: ptrTo[int64](0)}

	scheme := testScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(externalA, externalB, kubernetesRun, testBrokerAgentsConfigMap(externalA.Namespace)).Build()
	reconciler := &AgentRunReconciler{
		Client: k8sClient, Scheme: scheme,
		ExecutionDrivers: fakeExecutionDriverRegistry{
			"example-vm": &recordingExecutionDriver{
				reconcileBlock: blocked, reconcileStart: startedA,
				reconcile: []executiondriver.Status{{Phase: executiondriver.PhaseProvisioning, ObservedGeneration: -1}},
			},
			"example-vm-b": &recordingExecutionDriver{
				reconcileBlock: blocked, reconcileStart: startedB,
				reconcile: []executiondriver.Status{{Phase: executiondriver.PhaseProvisioning, ObservedGeneration: -1}},
			},
		},
	}
	errorsChannel := make(chan error, 2)
	go func() { _, err := reconciler.Reconcile(ctx, requestFor(externalA)); errorsChannel <- err }()
	go func() { _, err := reconciler.Reconcile(ctx, requestFor(externalB)); errorsChannel <- err }()
	select {
	case <-startedA:
	case <-time.After(time.Second):
		t.Fatal("first external driver did not block")
	}
	select {
	case <-startedB:
	case <-time.After(time.Second):
		t.Fatal("second external driver did not block")
	}
	if agentRunMaxConcurrentReconciles() <= externalExecutionMaxConcurrentCalls {
		t.Fatal("controller has no worker reserved beyond external call capacity")
	}
	kubernetesDone := make(chan error, 1)
	go func() { _, err := reconciler.Reconcile(ctx, requestFor(kubernetesRun)); kubernetesDone <- err }()
	select {
	case err := <-kubernetesDone:
		if err != nil {
			t.Fatalf("Kubernetes reconcile failed while external hosts stalled: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stalled external hosts blocked the built-in Kubernetes backend")
	}
	release()
	for range 2 {
		if err := <-errorsChannel; err != nil {
			t.Fatalf("external reconcile after release: %v", err)
		}
	}
}

func TestStalledGuestEnrollmentHandoffsReserveWorkerForKubernetesBackend(t *testing.T) {
	ctx := context.Background()
	blocked := make(chan struct{})
	var releaseBlocked sync.Once
	release := func() { releaseBlocked.Do(func() { close(blocked) }) }
	t.Cleanup(release)
	startedA := make(chan struct{}, 1)
	startedB := make(chan struct{}, 1)
	externalA := externalTestAgentRun()
	externalA.Name = "enrollment-a"
	externalA.UID = "enrollment-a-uid"
	externalA.Finalizers = []string{externalExecutionFinalizer, guestEnrollmentFinalizer}
	externalB := externalTestAgentRun()
	externalB.Name = "enrollment-b"
	externalB.UID = "enrollment-b-uid"
	externalB.Spec.Execution.Driver = "example-vm-b"
	externalB.Finalizers = []string{externalExecutionFinalizer, guestEnrollmentFinalizer}
	kubernetesRun := testAgentRun()
	kubernetesRun.Name = "kubernetes-during-enrollment"
	kubernetesRun.UID = "kubernetes-during-enrollment-uid"
	kubernetesRun.Status.Phase = nvtv1alpha1.AgentRunPhaseCompleted
	kubernetesRun.Status.FinishedAt = ptrTo(metav1.Now())
	kubernetesRun.Spec.TTL = &nvtv1alpha1.AgentRunTTL{RunRetentionSeconds: ptrTo[int64](0)}
	driverA := &recordingEnrollmentDriver{
		recordingExecutionDriver: &recordingExecutionDriver{reconcile: []executiondriver.Status{{Phase: executiondriver.PhaseProvisioning, ObservedGeneration: -1}}},
		prepareBlock:             blocked, prepareStart: startedA,
	}
	driverB := &recordingEnrollmentDriver{
		recordingExecutionDriver: &recordingExecutionDriver{reconcile: []executiondriver.Status{{Phase: executiondriver.PhaseProvisioning, ObservedGeneration: -1}}},
		prepareBlock:             blocked, prepareStart: startedB,
	}
	scheme := testScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&nvtv1alpha1.AgentRun{}).
		WithObjects(externalA, externalB, kubernetesRun, testBrokerAgentsConfigMap(externalA.Namespace)).Build()
	reconciler := &AgentRunReconciler{
		Client: k8sClient, Scheme: scheme, GuestEnrollment: &recordingEnrollmentIssuer{handoffTimeout: time.Second},
		ExecutionDrivers: fakeExecutionDriverRegistry{"example-vm": driverA, "example-vm-b": driverB},
	}
	errorsChannel := make(chan error, 2)
	go func() { _, err := reconciler.Reconcile(ctx, requestFor(externalA)); errorsChannel <- err }()
	go func() { _, err := reconciler.Reconcile(ctx, requestFor(externalB)); errorsChannel <- err }()
	for name, started := range map[string]<-chan struct{}{"a": startedA, "b": startedB} {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("enrollment handoff %s did not block", name)
		}
	}
	kubernetesDone := make(chan error, 1)
	go func() { _, err := reconciler.Reconcile(ctx, requestFor(kubernetesRun)); kubernetesDone <- err }()
	select {
	case err := <-kubernetesDone:
		if err != nil {
			t.Fatalf("Kubernetes reconcile failed while enrollment handoffs stalled: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stalled enrollment handoffs blocked the built-in Kubernetes backend")
	}
	release()
	for range 2 {
		if err := <-errorsChannel; err != nil {
			t.Fatalf("enrollment reconcile after release: %v", err)
		}
	}
}

func TestExternalGuestEnrollmentIssuesDeliversOnceAndRecoversAfterRestart(t *testing.T) {
	ctx := context.Background()
	run := externalTestAgentRun()
	base := &recordingExecutionDriver{reconcile: []executiondriver.Status{{Phase: executiondriver.PhaseProvisioning, ObservedGeneration: -1}}}
	driver := &recordingEnrollmentDriver{recordingExecutionDriver: base}
	other := &recordingEnrollmentDriver{recordingExecutionDriver: &recordingExecutionDriver{}}
	issuer := &recordingEnrollmentIssuer{}
	k8sClient, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{"example-vm": driver, "other": other})
	reconciler.GuestEnrollment = issuer

	// Both cleanup obligations are made durable before issuance or delivery.
	for index := range 2 {
		if result, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil || !result.Requeue {
			t.Fatalf("finalizer reconcile %d result=%#v err=%v", index, result, err)
		}
	}
	if len(issuer.issues) != 0 || driver.deliverCalls != 0 {
		t.Fatal("enrollment started before both finalizers were durable")
	}
	if pending := getExternalRun(t, ctx, k8sClient, run); pending.Status.NativeGuestBinding != nil {
		t.Fatalf("binding published before accepted handoff: %#v", pending.Status.NativeGuestBinding)
	}
	if _, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatalf("enrollment reconcile: %v", err)
	}
	if len(issuer.issues) != 1 || driver.deliverCalls != 1 || other.deliverCalls != 0 || !driver.accepted {
		t.Fatalf("exact handoff issue=%d deliver=%d other=%d accepted=%t", len(issuer.issues), driver.deliverCalls, other.deliverCalls, driver.accepted)
	}
	issued := issuer.issues[0]
	if issued.Binding.DriverRegistration != "example-vm" || issued.Binding.GuestInstanceID != "guest-instance-1" || issued.Binding.ExecutionID != base.desired[0].ExecutionID {
		t.Fatalf("incorrect exact binding: %#v", issued.Binding)
	}
	accepted := getExternalRun(t, ctx, k8sClient, run)
	assertPublishedNativeGuestBinding(t, accepted.Status.NativeGuestBinding, issued.Binding)
	acceptedResourceVersion := accepted.ResourceVersion

	// A new reconciler has no issuance history. Durable driver acceptance is
	// sufficient to avoid issuing or delivering a second token.
	restarted := &AgentRunReconciler{Client: k8sClient, Scheme: reconciler.Scheme, ExecutionDrivers: reconciler.ExecutionDrivers, GuestEnrollment: issuer}
	if _, err := restarted.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatalf("restart reconcile: %v", err)
	}
	if len(issuer.issues) != 1 || driver.deliverCalls != 1 {
		t.Fatalf("restart duplicated enrollment issue=%d deliver=%d", len(issuer.issues), driver.deliverCalls)
	}
	updated := getExternalRun(t, ctx, k8sClient, run)
	assertPublishedNativeGuestBinding(t, updated.Status.NativeGuestBinding, issued.Binding)
	if updated.ResourceVersion != acceptedResourceVersion {
		t.Fatalf("accepted restart churned AgentRun status: resourceVersion %q -> %q", acceptedResourceVersion, updated.ResourceVersion)
	}
	encoded, err := json.Marshal(struct {
		Run     nvtv1alpha1.AgentRun
		Desired []executiondriver.DesiredExecution
	}{updated, base.desired})
	if err != nil || bytes.Contains(encoded, []byte(driver.deliveredToken)) || bytes.Contains(encoded, []byte("exchange_url")) {
		t.Fatalf("ordinary state disclosed enrollment material: %s err=%v", encoded, err)
	}
	condition := meta.FindStatusCondition(updated.Status.Conditions, ConditionExecutionBackendAvailable)
	if condition == nil || condition.Status != metav1.ConditionTrue || condition.Reason != "ExternalBootstrapAccepted" {
		t.Fatalf("unexpected enrollment condition: %#v", condition)
	}
	assertNoAgentPods(t, ctx, k8sClient, run.Namespace)
}

func TestExternalGuestEnrollmentResponseLossDoesNotIssueAgain(t *testing.T) {
	ctx := context.Background()
	run := externalTestAgentRun()
	run.Finalizers = []string{externalExecutionFinalizer, guestEnrollmentFinalizer}
	driver := &recordingEnrollmentDriver{
		recordingExecutionDriver: &recordingExecutionDriver{reconcile: []executiondriver.Status{{Phase: executiondriver.PhaseProvisioning, ObservedGeneration: -1}}},
		deliverError:             errors.New("HANDOFF-TOKEN-CANARY response lost"), acceptBeforeError: true,
	}
	issuer := &recordingEnrollmentIssuer{}
	k8sClient, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{"example-vm": driver})
	reconciler.GuestEnrollment = issuer
	if result, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil || result.RequeueAfter != externalExecutionDefaultRequeue {
		t.Fatalf("lost response result=%#v err=%v", result, err)
	}
	if len(issuer.issues) != 1 || !driver.accepted {
		t.Fatalf("delivery was not durably accepted: issues=%d accepted=%t", len(issuer.issues), driver.accepted)
	}
	if updated := getExternalRun(t, ctx, k8sClient, run); updated.Status.NativeGuestBinding != nil {
		t.Fatalf("uncertain delivery published a routing binding: %#v", updated.Status.NativeGuestBinding)
	}
	if _, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatalf("recover accepted delivery: %v", err)
	}
	if len(issuer.issues) != 1 || len(issuer.revokeBindings) != 0 || driver.deliverCalls != 1 {
		t.Fatalf("uncertain accepted delivery was replaced: issues=%d revokes=%d delivers=%d", len(issuer.issues), len(issuer.revokeBindings), driver.deliverCalls)
	}
	updated := getExternalRun(t, ctx, k8sClient, run)
	assertPublishedNativeGuestBinding(t, updated.Status.NativeGuestBinding, issuer.issues[0].Binding)
	status, _ := json.Marshal(updated.Status)
	if bytes.Contains(status, []byte("HANDOFF-TOKEN-CANARY")) {
		t.Fatalf("uncertain delivery diagnostic leaked: %s", status)
	}
}

func TestExternalGuestEnrollmentDefiniteNonAcceptanceRevokesBeforeReplacement(t *testing.T) {
	ctx := context.Background()
	run := externalTestAgentRun()
	run.Finalizers = []string{externalExecutionFinalizer, guestEnrollmentFinalizer}
	driver := &recordingEnrollmentDriver{
		recordingExecutionDriver: &recordingExecutionDriver{reconcile: []executiondriver.Status{{Phase: executiondriver.PhaseProvisioning, ObservedGeneration: -1}}},
		deliverError:             errors.New("rejected"),
	}
	issuer := &recordingEnrollmentIssuer{}
	_, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{"example-vm": driver})
	reconciler.GuestEnrollment = issuer
	if _, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatal(err)
	}
	if len(issuer.issues) != 1 || driver.accepted {
		t.Fatal("first rejected handoff state is incorrect")
	}
	if _, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatal(err)
	}
	if len(issuer.revokeBindings) != 1 || driver.replaceCalls != 1 || len(issuer.issues) != 2 {
		t.Fatalf("replacement choreography revokes=%d replaces=%d issues=%d", len(issuer.revokeBindings), driver.replaceCalls, len(issuer.issues))
	}
	if issuer.revokeBindings[0].Binding.GuestInstanceID != "guest-instance-1" || issuer.issues[1].Binding.GuestInstanceID != "guest-instance-replacement" {
		t.Fatalf("replacement reused revoked binding: revoke=%#v issue=%#v", issuer.revokeBindings[0], issuer.issues[1])
	}
}

func TestExternalGuestBindingClearsBeforeReplacementAndPublishesOnlyAcceptedGuest(t *testing.T) {
	ctx := context.Background()
	run := externalTestAgentRun()
	run.Finalizers = []string{externalExecutionFinalizer, guestEnrollmentFinalizer}
	oldBinding := exactNativeGuestBindingForRun(t, run, "guest-instance-1")
	run.Status.NativeGuestBinding = nativeGuestBindingStatus(oldBinding)
	driver := &recordingEnrollmentDriver{
		recordingExecutionDriver: &recordingExecutionDriver{reconcile: []executiondriver.Status{{Phase: executiondriver.PhaseProvisioning, ObservedGeneration: -1}}},
		guestID:                  "guest-instance-1", prepared: true,
	}
	issuer := &recordingEnrollmentIssuer{}
	k8sClient, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{"example-vm": driver})
	reconciler.GuestEnrollment = issuer

	if result, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil || result.RequeueAfter != externalExecutionDefaultRequeue {
		t.Fatalf("clear old binding result=%#v err=%v", result, err)
	}
	cleared := getExternalRun(t, ctx, k8sClient, run)
	if cleared.Status.NativeGuestBinding != nil || len(issuer.revokeBindings) != 0 || driver.replaceCalls != 0 {
		t.Fatalf("old binding was not cleared before replacement: status=%#v revokes=%d replaces=%d", cleared.Status.NativeGuestBinding, len(issuer.revokeBindings), driver.replaceCalls)
	}

	if _, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatal(err)
	}
	updated := getExternalRun(t, ctx, k8sClient, run)
	if len(issuer.revokeBindings) != 1 || driver.replaceCalls != 1 || len(issuer.issues) != 1 {
		t.Fatalf("replacement choreography revokes=%d replaces=%d issues=%d prepares=%d desired=%d finalizers=%#v status=%#v", len(issuer.revokeBindings), driver.replaceCalls, len(issuer.issues), driver.prepareCalls, len(driver.desired), updated.Finalizers, updated.Status)
	}
	assertPublishedNativeGuestBinding(t, updated.Status.NativeGuestBinding, issuer.issues[0].Binding)
	if updated.Status.NativeGuestBinding.GuestInstanceID == oldBinding.GuestInstanceID {
		t.Fatal("replacement republished the obsolete guest")
	}
}

func TestExternalGuestBindingAcceptedReplacementClearsBeforeRestartRecoveryPublication(t *testing.T) {
	ctx := context.Background()
	run := externalTestAgentRun()
	run.Finalizers = []string{externalExecutionFinalizer, guestEnrollmentFinalizer}
	run.Status.NativeGuestBinding = nativeGuestBindingStatus(exactNativeGuestBindingForRun(t, run, "obsolete-guest"))
	driver := &recordingEnrollmentDriver{
		recordingExecutionDriver: &recordingExecutionDriver{reconcile: []executiondriver.Status{{Phase: executiondriver.PhaseProvisioning, ObservedGeneration: -1}}},
		guestID:                  "accepted-replacement", prepared: true, accepted: true,
	}
	issuer := &recordingEnrollmentIssuer{}
	k8sClient, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{"example-vm": driver})
	reconciler.GuestEnrollment = issuer
	if _, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatal(err)
	}
	cleared := getExternalRun(t, ctx, k8sClient, run)
	if cleared.Status.NativeGuestBinding != nil || len(issuer.issues) != 0 || driver.deliverCalls != 0 {
		t.Fatalf("accepted replacement was published before old binding cleared: status=%#v issues=%d deliveries=%d", cleared.Status.NativeGuestBinding, len(issuer.issues), driver.deliverCalls)
	}
	if _, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatal(err)
	}
	updated := getExternalRun(t, ctx, k8sClient, run)
	want := exactNativeGuestBindingForRun(t, run, "accepted-replacement")
	assertPublishedNativeGuestBinding(t, updated.Status.NativeGuestBinding, want)
	if len(issuer.issues) != 0 || driver.deliverCalls != 0 {
		t.Fatal("restart recovery issued or delivered enrollment for an already accepted replacement")
	}
}

func TestExternalGuestBindingMalformedOrStaleStatusFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*nvtv1alpha1.AgentRunNativeGuestBinding){
		"malformed": func(binding *nvtv1alpha1.AgentRunNativeGuestBinding) { binding.GuestInstanceID = "" },
		"stale":     func(binding *nvtv1alpha1.AgentRunNativeGuestBinding) { binding.DesiredGeneration++ },
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			run := externalTestAgentRun()
			run.Finalizers = []string{externalExecutionFinalizer, guestEnrollmentFinalizer}
			run.Status.NativeGuestBinding = nativeGuestBindingStatus(exactNativeGuestBindingForRun(t, run, "obsolete-guest"))
			mutate(run.Status.NativeGuestBinding)
			driver := &recordingEnrollmentDriver{recordingExecutionDriver: &recordingExecutionDriver{reconcile: []executiondriver.Status{{Phase: executiondriver.PhaseProvisioning, ObservedGeneration: -1}}}}
			issuer := &recordingEnrollmentIssuer{}
			k8sClient, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{"example-vm": driver})
			reconciler.GuestEnrollment = issuer
			if _, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil {
				t.Fatal(err)
			}
			updated := getExternalRun(t, ctx, k8sClient, run)
			if updated.Status.NativeGuestBinding != nil || driver.prepareCalls != 0 || len(issuer.issues) != 0 {
				t.Fatalf("invalid status was used: binding=%#v prepares=%d issues=%d", updated.Status.NativeGuestBinding, driver.prepareCalls, len(issuer.issues))
			}
		})
	}
}

func TestExternalGuestBindingClearsBeforeDeletionAndMissingBackendCleanup(t *testing.T) {
	ctx := context.Background()
	now := metav1.Now()
	for _, missing := range []bool{false, true} {
		run := externalTestAgentRun()
		run.Name = fmt.Sprintf("delete-binding-%t", missing)
		run.UID = types.UID(run.Name + "-uid")
		run.Finalizers = []string{externalExecutionFinalizer, guestEnrollmentFinalizer}
		run.DeletionTimestamp = &now
		run.Status.NativeGuestBinding = nativeGuestBindingStatus(exactNativeGuestBindingForRun(t, run, "deleting-guest"))
		driver := &recordingEnrollmentDriver{recordingExecutionDriver: &recordingExecutionDriver{delete: []executiondriver.Status{{Phase: executiondriver.PhaseDeleted}}}}
		registry := fakeExecutionDriverRegistry{"example-vm": driver}
		if missing {
			registry = fakeExecutionDriverRegistry{}
		}
		issuer := &recordingEnrollmentIssuer{}
		k8sClient, reconciler := externalReconcileFixture(t, run, registry)
		reconciler.GuestEnrollment = issuer
		if result, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil || !result.Requeue {
			t.Fatalf("clear deletion binding missing=%t result=%#v err=%v", missing, result, err)
		}
		updated := getExternalRun(t, ctx, k8sClient, run)
		if updated.Status.NativeGuestBinding != nil || len(issuer.revokeScopes) != 0 || len(driver.deleteIDs) != 0 {
			t.Fatalf("cleanup began before binding clear missing=%t status=%#v revokes=%d deletes=%d", missing, updated.Status.NativeGuestBinding, len(issuer.revokeScopes), len(driver.deleteIDs))
		}
	}
}

func TestExternalGuestEnrollmentIssueFailureRevokesBeforeRetry(t *testing.T) {
	ctx := context.Background()
	run := externalTestAgentRun()
	run.Finalizers = []string{externalExecutionFinalizer, guestEnrollmentFinalizer}
	driver := &recordingEnrollmentDriver{
		recordingExecutionDriver: &recordingExecutionDriver{reconcile: []executiondriver.Status{{Phase: executiondriver.PhaseProvisioning, ObservedGeneration: -1}}},
	}
	issuer := &recordingEnrollmentIssuer{issueError: errors.New("ISSUER-RESPONSE-CANARY lost")}
	k8sClient, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{"example-vm": driver})
	reconciler.GuestEnrollment = issuer
	if _, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatal(err)
	}
	if len(issuer.issues) != 1 || driver.deliverCalls != 0 || len(issuer.revokeBindings) != 0 {
		t.Fatalf("first issue failure issues=%d delivers=%d revokes=%d", len(issuer.issues), driver.deliverCalls, len(issuer.revokeBindings))
	}
	if updated := getExternalRun(t, ctx, k8sClient, run); updated.Status.NativeGuestBinding != nil {
		t.Fatalf("issue failure published a routing binding: %#v", updated.Status.NativeGuestBinding)
	}
	issuer.issueError = nil
	if _, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatal(err)
	}
	if len(issuer.revokeBindings) != 1 || driver.replaceCalls != 1 || len(issuer.issues) != 2 || driver.deliverCalls != 1 {
		t.Fatalf("issue recovery revokes=%d replaces=%d issues=%d delivers=%d", len(issuer.revokeBindings), driver.replaceCalls, len(issuer.issues), driver.deliverCalls)
	}
	if issuer.revokeBindings[0].Binding == issuer.issues[1].Binding {
		t.Fatal("issue response loss retried the same binding")
	}
	updated := getExternalRun(t, ctx, k8sClient, run)
	assertPublishedNativeGuestBinding(t, updated.Status.NativeGuestBinding, issuer.issues[1].Binding)
	encoded, _ := json.Marshal(updated.Status)
	if bytes.Contains(encoded, []byte("ISSUER-RESPONSE-CANARY")) {
		t.Fatalf("issue diagnostic leaked: %s", encoded)
	}
}

func TestExternalGuestEnrollmentUnavailableHandoffDoesNotIssueOrFallback(t *testing.T) {
	ctx := context.Background()
	run := externalTestAgentRun()
	run.Finalizers = []string{externalExecutionFinalizer, guestEnrollmentFinalizer}
	driver := &recordingEnrollmentDriver{
		recordingExecutionDriver: &recordingExecutionDriver{reconcile: []executiondriver.Status{{Phase: executiondriver.PhaseProvisioning, ObservedGeneration: -1}}},
		prepareError:             errors.New("HANDOFF-SECRET-CANARY unavailable"),
	}
	other := &recordingEnrollmentDriver{recordingExecutionDriver: &recordingExecutionDriver{}}
	issuer := &recordingEnrollmentIssuer{}
	k8sClient, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{"example-vm": driver, "other": other})
	reconciler.GuestEnrollment = issuer
	if result, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil || result.RequeueAfter != externalExecutionDefaultRequeue {
		t.Fatalf("unavailable handoff result=%#v err=%v", result, err)
	}
	if len(issuer.issues) != 0 || other.prepareCalls != 0 || other.deliverCalls != 0 {
		t.Fatalf("unavailable exact handoff issued or fell back: issues=%d other_prepare=%d other_deliver=%d", len(issuer.issues), other.prepareCalls, other.deliverCalls)
	}
	updated := getExternalRun(t, ctx, k8sClient, run)
	encoded, _ := json.Marshal(updated.Status)
	if bytes.Contains(encoded, []byte("HANDOFF-SECRET-CANARY")) {
		t.Fatalf("handoff diagnostic leaked: %s", encoded)
	}
	assertNoAgentPods(t, ctx, k8sClient, run.Namespace)
}

func TestExternalGuestEnrollmentDeliveryUsesBoundedDedicatedDeadline(t *testing.T) {
	ctx := context.Background()
	run := externalTestAgentRun()
	run.Finalizers = []string{externalExecutionFinalizer, guestEnrollmentFinalizer}
	driver := &recordingEnrollmentDriver{
		recordingExecutionDriver: &recordingExecutionDriver{reconcile: []executiondriver.Status{{Phase: executiondriver.PhaseProvisioning, ObservedGeneration: -1}}},
		deliverBlock:             true,
	}
	issuer := &recordingEnrollmentIssuer{handoffTimeout: 20 * time.Millisecond}
	_, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{"example-vm": driver})
	reconciler.GuestEnrollment = issuer
	started := time.Now()
	result, err := reconciler.Reconcile(ctx, requestFor(run))
	if err != nil || result.RequeueAfter != externalExecutionDefaultRequeue {
		t.Fatalf("bounded delivery result=%#v err=%v", result, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("delivery exceeded its dedicated deadline: %s", elapsed)
	}
	if len(issuer.issues) != 1 || driver.deliverCalls != 1 || driver.accepted {
		t.Fatalf("timed-out delivery state issues=%d delivers=%d accepted=%t", len(issuer.issues), driver.deliverCalls, driver.accepted)
	}
}

func TestExternalPodDriverDoesNotParticipateInGuestEnrollment(t *testing.T) {
	ctx := context.Background()
	run := externalTestAgentRun()
	run.Spec.Execution.Kind = nvtv1alpha1.AgentRunExecutionPod
	driver := &recordingEnrollmentDriver{
		recordingExecutionDriver: &recordingExecutionDriver{reconcile: []executiondriver.Status{{Phase: executiondriver.PhaseRunning, Ready: true, ObservedGeneration: 1}}},
		guestID:                  "must-not-be-used",
	}
	issuer := &recordingEnrollmentIssuer{}
	k8sClient, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{"example-vm": driver})
	reconciler.GuestEnrollment = issuer

	if _, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatalf("add external finalizer: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatalf("external Pod reconcile: %v", err)
	}
	updated := getExternalRun(t, ctx, k8sClient, run)
	if controllerHasFinalizer(&updated, guestEnrollmentFinalizer) {
		t.Fatalf("external Pod gained VM enrollment finalizer: %#v", updated.Finalizers)
	}
	if updated.Status.NativeGuestBinding != nil {
		t.Fatalf("external Pod published a native guest binding: %#v", updated.Status.NativeGuestBinding)
	}
	if len(issuer.issues) != 0 || len(issuer.revokeBindings) != 0 || len(issuer.revokeScopes) != 0 || len(issuer.completions) != 0 || driver.deliverCalls != 0 {
		t.Fatalf("external Pod used guest enrollment: issuer=%#v delivers=%d", issuer, driver.deliverCalls)
	}

	now := metav1.Now()
	deleting := externalTestAgentRun()
	deleting.Name = "external-pod-delete"
	deleting.UID = "external-pod-delete-uid"
	deleting.Spec.Execution.Kind = nvtv1alpha1.AgentRunExecutionPod
	deleting.Finalizers = []string{externalExecutionFinalizer}
	deleting.DeletionTimestamp = &now
	deleteDriver := &recordingEnrollmentDriver{recordingExecutionDriver: &recordingExecutionDriver{delete: []executiondriver.Status{{Phase: executiondriver.PhaseDeleted}}}}
	_, deleteReconciler := externalReconcileFixture(t, deleting, fakeExecutionDriverRegistry{"example-vm": deleteDriver})
	deleteReconciler.GuestEnrollment = issuer
	if _, err := deleteReconciler.Reconcile(ctx, requestFor(deleting)); err != nil {
		t.Fatalf("external Pod delete: %v", err)
	}
	if len(issuer.revokeScopes) != 0 || len(issuer.completions) != 0 || len(issuer.issues) != 0 || driver.deliverCalls != 0 {
		t.Fatalf("external Pod deletion used guest enrollment: revokes=%d completions=%d issues=%d delivers=%d", len(issuer.revokeScopes), len(issuer.completions), len(issuer.issues), driver.deliverCalls)
	}
}

func TestExistingGuestEnrollmentFinalizerRemainsCleanupAuthoritative(t *testing.T) {
	ctx := context.Background()
	now := metav1.Now()
	run := externalTestAgentRun()
	run.Spec.Execution.Kind = nvtv1alpha1.AgentRunExecutionPod
	run.Finalizers = []string{guestEnrollmentFinalizer}
	run.DeletionTimestamp = &now
	sequence := []string{}
	driver := &recordingEnrollmentDriver{
		recordingExecutionDriver: &recordingExecutionDriver{delete: []executiondriver.Status{{Phase: executiondriver.PhaseDeleted}}},
		operationSequence:        &sequence,
	}
	issuer := &recordingEnrollmentIssuer{sequence: &sequence}
	k8sClient, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{"example-vm": driver})
	reconciler.GuestEnrollment = issuer
	if _, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatalf("existing enrollment cleanup obligation: %v", err)
	}
	if !reflect.DeepEqual(sequence, []string{"scope-revoke", "driver-delete", "cleanup-complete"}) {
		t.Fatalf("existing cleanup obligation ordering=%#v", sequence)
	}
	var deleted nvtv1alpha1.AgentRun
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(run), &deleted); !apierrors.IsNotFound(err) {
		t.Fatalf("existing cleanup obligation did not finalize: err=%v finalizers=%#v", err, deleted.Finalizers)
	}
}

func TestExternalGuestEnrollmentCleanupRevokesScopeBeforeExactDriverDelete(t *testing.T) {
	ctx := context.Background()
	now := metav1.Now()
	run := externalTestAgentRun()
	run.Finalizers = []string{agentRunFinalizer, externalExecutionFinalizer, guestEnrollmentFinalizer}
	run.DeletionTimestamp = &now
	sequence := []string{}
	driver := &recordingEnrollmentDriver{
		recordingExecutionDriver: &recordingExecutionDriver{delete: []executiondriver.Status{{Phase: executiondriver.PhaseDeleted}}},
		operationSequence:        &sequence,
	}
	issuer := &recordingEnrollmentIssuer{sequence: &sequence}
	k8sClient, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{"example-vm": driver})
	reconciler.GuestEnrollment = issuer
	if _, err := reconciler.Reconcile(ctx, requestFor(run)); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if !reflect.DeepEqual(sequence, []string{"scope-revoke", "driver-delete", "cleanup-complete"}) || len(issuer.revokeScopes) != 1 || len(issuer.completions) != 1 {
		t.Fatalf("cleanup ordering=%#v scope=%#v completions=%#v", sequence, issuer.revokeScopes, issuer.completions)
	}
	var deleted nvtv1alpha1.AgentRun
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(run), &deleted); !apierrors.IsNotFound(err) {
		t.Fatalf("run remained after ordered cleanup: %#v err=%v", deleted.Finalizers, err)
	}

	blockedRun := externalTestAgentRun()
	blockedRun.Name = "blocked-cleanup"
	blockedRun.UID = "blocked-cleanup-uid"
	blockedRun.Finalizers = []string{externalExecutionFinalizer, guestEnrollmentFinalizer}
	blockedRun.DeletionTimestamp = &now
	blockedDriver := &recordingEnrollmentDriver{recordingExecutionDriver: &recordingExecutionDriver{delete: []executiondriver.Status{{Phase: executiondriver.PhaseDeleted}}}}
	blockedIssuer := &recordingEnrollmentIssuer{revokeError: errors.New("BROKER-TOKEN-CANARY unavailable")}
	blockedClient, blocked := externalReconcileFixture(t, blockedRun, fakeExecutionDriverRegistry{"example-vm": blockedDriver})
	blocked.GuestEnrollment = blockedIssuer
	if result, err := blocked.Reconcile(ctx, requestFor(blockedRun)); err != nil || result.RequeueAfter != externalExecutionCleanupRetry {
		t.Fatalf("blocked cleanup result=%#v err=%v", result, err)
	}
	retained := getExternalRun(t, ctx, blockedClient, blockedRun)
	if !controllerHasFinalizer(&retained, guestEnrollmentFinalizer) || len(blockedDriver.deleteIDs) != 0 {
		t.Fatalf("revocation failure allowed delete/finalize: %#v deletes=%#v", retained.Finalizers, blockedDriver.deleteIDs)
	}
	encoded, _ := json.Marshal(retained.Status)
	if bytes.Contains(encoded, []byte("BROKER-TOKEN-CANARY")) {
		t.Fatalf("cleanup disclosed broker diagnostic: %s", encoded)
	}

	completionRun := externalTestAgentRun()
	completionRun.Name = "blocked-completion"
	completionRun.UID = "blocked-completion-uid"
	completionRun.Finalizers = []string{externalExecutionFinalizer, guestEnrollmentFinalizer}
	completionRun.DeletionTimestamp = &now
	completionSequence := []string{}
	completionDriver := &recordingEnrollmentDriver{
		recordingExecutionDriver: &recordingExecutionDriver{delete: []executiondriver.Status{{Phase: executiondriver.PhaseDeleted}, {Phase: executiondriver.PhaseDeleted}}},
		operationSequence:        &completionSequence,
	}
	completionIssuer := &recordingEnrollmentIssuer{completionError: errors.New("COMPLETION-CANARY response lost"), sequence: &completionSequence}
	completionRegistry := fakeExecutionDriverRegistry{"example-vm": completionDriver}
	completionClient, completionReconciler := externalReconcileFixture(t, completionRun, completionRegistry)
	completionReconciler.GuestEnrollment = completionIssuer
	if result, err := completionReconciler.Reconcile(ctx, requestFor(completionRun)); err != nil || result.RequeueAfter != externalExecutionCleanupRetry {
		t.Fatalf("completion response loss result=%#v err=%v", result, err)
	}
	retained = getExternalRun(t, ctx, completionClient, completionRun)
	if !controllerHasFinalizer(&retained, guestEnrollmentFinalizer) || !controllerHasFinalizer(&retained, externalExecutionFinalizer) {
		t.Fatalf("completion response loss released finalizers: %#v", retained.Finalizers)
	}
	if !reflect.DeepEqual(completionSequence, []string{"scope-revoke", "driver-delete", "cleanup-complete"}) {
		t.Fatalf("completion failure ordering=%#v", completionSequence)
	}
	completionIssuer.completionError = nil
	restartedCompletionReconciler := &AgentRunReconciler{
		Client: completionClient, Scheme: completionReconciler.Scheme,
		ExecutionDrivers: completionRegistry, GuestEnrollment: completionIssuer,
	}
	if _, err := restartedCompletionReconciler.Reconcile(ctx, requestFor(completionRun)); err != nil {
		t.Fatalf("completion response-loss retry: %v", err)
	}
	if !reflect.DeepEqual(completionSequence, []string{"scope-revoke", "driver-delete", "cleanup-complete", "scope-revoke", "driver-delete", "cleanup-complete"}) {
		t.Fatalf("completion retry ordering=%#v", completionSequence)
	}
	if err := completionClient.Get(ctx, client.ObjectKeyFromObject(completionRun), &retained); !apierrors.IsNotFound(err) {
		t.Fatalf("completion retry did not finalize run: err=%v finalizers=%#v", err, retained.Finalizers)
	}
}

func TestExternalGuestEnrollmentMissingRegistrationStillRevokesAndRetainsCleanup(t *testing.T) {
	ctx := context.Background()
	now := metav1.Now()
	run := externalTestAgentRun()
	run.Finalizers = []string{externalExecutionFinalizer, guestEnrollmentFinalizer}
	run.DeletionTimestamp = &now
	issuer := &recordingEnrollmentIssuer{}
	k8sClient, reconciler := externalReconcileFixture(t, run, fakeExecutionDriverRegistry{})
	reconciler.GuestEnrollment = issuer
	result, err := reconciler.Reconcile(ctx, requestFor(run))
	if err != nil || result.RequeueAfter != externalExecutionDefaultRequeue {
		t.Fatalf("missing registration cleanup result=%#v err=%v", result, err)
	}
	if len(issuer.revokeScopes) != 1 || issuer.revokeScopes[0].ExecutionScope.DriverRegistration != "example-vm" {
		t.Fatalf("missing registration did not revoke exact scope: %#v", issuer.revokeScopes)
	}
	retained := getExternalRun(t, ctx, k8sClient, run)
	if !controllerHasFinalizer(&retained, externalExecutionFinalizer) || !controllerHasFinalizer(&retained, guestEnrollmentFinalizer) {
		t.Fatalf("missing registration released cleanup finalizers: %#v", retained.Finalizers)
	}
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

func assertPublishedNativeGuestBinding(t *testing.T, status *nvtv1alpha1.AgentRunNativeGuestBinding, want guestenrollment.Binding) {
	t.Helper()
	if status == nil {
		t.Fatal("native guest routing binding was not published")
	}
	got := guestenrollment.Binding{
		AgentRunUID: status.AgentRunUID, ExecutionID: status.ExecutionID, DriverRegistration: status.DriverRegistration,
		DesiredGeneration: status.DesiredGeneration, GuestInstanceID: status.GuestInstanceID,
	}
	if got != want {
		t.Fatalf("published native guest binding=%#v, want %#v", got, want)
	}
}

func exactNativeGuestBindingForRun(t *testing.T, run *nvtv1alpha1.AgentRun, guestInstanceID string) guestenrollment.Binding {
	t.Helper()
	desired, err := desiredExternalExecution(run)
	if err != nil {
		t.Fatal(err)
	}
	return guestenrollment.Binding{
		AgentRunUID: string(run.UID), ExecutionID: desired.ExecutionID, DriverRegistration: run.Spec.Execution.Driver,
		DesiredGeneration: desired.Generation, GuestInstanceID: guestInstanceID,
	}
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
