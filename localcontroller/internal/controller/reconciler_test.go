package controller

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeBackend struct {
	mu            sync.Mutex
	resources     map[string]bool
	ensureErr     error
	inspectErr    error
	deleteErr     error
	ensureCalls   int
	deleteCalls   int
	ensureStarted chan struct{}
	ensureRelease chan struct{}
}

func newFakeBackend() *fakeBackend { return &fakeBackend{resources: map[string]bool{}} }

func (backend *fakeBackend) Ready(context.Context) bool { return true }

func (backend *fakeBackend) Ensure(_ context.Context, run BackendRun) (BackendObservation, error) {
	backend.mu.Lock()
	backend.ensureCalls++
	backend.resources[run.Resolved.RunID] = true
	err := backend.ensureErr
	started, release := backend.ensureStarted, backend.ensureRelease
	backend.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if release != nil {
		<-release
	}
	if err != nil {
		return BackendObservation{}, err
	}
	return BackendObservation{Ready: true}, nil
}

func TestTwoControllerProcessesWithSameStableResourceOwnerCannotEnterBackendTogether(t *testing.T) {
	store, _ := openTestStore(t, &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}, 4)
	firstBackend, secondBackend := newFakeBackend(), newFakeBackend()
	firstBackend.ensureStarted = make(chan struct{}, 1)
	firstBackend.ensureRelease = make(chan struct{})
	firstOwner, err := NewProcessReconcileOwner("nvt-local-controller")
	if err != nil {
		t.Fatal(err)
	}
	secondOwner, err := NewProcessReconcileOwner("nvt-local-controller")
	if err != nil || firstOwner == secondOwner || !strings.HasPrefix(firstOwner, "nvt-local-controller-") || !strings.HasPrefix(secondOwner, "nvt-local-controller-") {
		t.Fatalf("process owners are not distinct: %q %q %v", firstOwner, secondOwner, err)
	}
	firstReconciler, _ := NewReconciler(store, firstBackend, firstOwner, 30*time.Second, log.New(io.Discard, "", 0))
	secondReconciler, _ := NewReconciler(store, secondBackend, secondOwner, 30*time.Second, log.New(io.Discard, "", 0))
	run := createRun(t, store, "delayed-operation", false)
	if err := firstReconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- firstReconciler.Reconcile(context.Background()) }()
	<-firstBackend.ensureStarted
	owned, err := store.Get(context.Background(), run.RunID)
	if err != nil || owned.ReconcileOwner != firstOwner || owned.ReconcileUntil == nil {
		t.Fatalf("operation not claimed: %#v %v", owned, err)
	}
	if err := secondReconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	secondBackend.mu.Lock()
	secondCalls := secondBackend.ensureCalls
	secondBackend.mu.Unlock()
	if secondCalls != 0 {
		t.Fatalf("second controller entered backend %d times", secondCalls)
	}
	close(firstBackend.ensureRelease)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	running, err := store.Get(context.Background(), run.RunID)
	if err != nil || running.State != StateRunning {
		t.Fatalf("delayed operation did not commit: %#v %v", running, err)
	}
}

func (backend *fakeBackend) Inspect(_ context.Context, run BackendRun) (BackendObservation, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.inspectErr != nil {
		return BackendObservation{}, backend.inspectErr
	}
	return BackendObservation{Ready: backend.resources[run.Resolved.RunID]}, nil
}

func (backend *fakeBackend) Delete(_ context.Context, run BackendRun) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.deleteCalls++
	if backend.deleteErr != nil {
		return backend.deleteErr
	}
	delete(backend.resources, run.Resolved.RunID)
	return nil
}

func TestReconcilerDeadlineAndDeleteRemainClaimableUntilBackendCleanup(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	backend := newFakeBackend()
	reconciler, err := NewReconciler(store, backend, "controller-a", 30*time.Second, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}

	deadline := createRun(t, store, "deadline-owned", false)
	reconcileToRunning(t, reconciler, store, deadline.RunID)
	clock.Advance(10 * time.Second)
	if _, err := store.Get(context.Background(), deadline.RunID); err != nil {
		t.Fatal(err)
	}
	expiring, err := store.Get(context.Background(), deadline.RunID)
	if err != nil || expiring.State != StateStopping || expiring.TerminalTarget != StateExpired || !backend.resources[deadline.RunID] {
		t.Fatalf("deadline cleanup invariant = %#v resources=%v err=%v", expiring, backend.resources, err)
	}
	if err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	expired, err := store.Get(context.Background(), deadline.RunID)
	if err != nil || expired.State != StateExpired || backend.resources[deadline.RunID] {
		t.Fatalf("deadline cleanup result = %#v resources=%v err=%v", expired, backend.resources, err)
	}

	deleting := createRun(t, store, "delete-owned", true)
	reconcileToRunning(t, reconciler, store, deleting.RunID)
	requested, deleted, err := store.Delete(context.Background(), deleting.RunID)
	if err != nil || deleted || requested.State != StateStopping || !backend.resources[deleting.RunID] {
		t.Fatalf("delete request stranded resources: %#v %v %v", requested, deleted, err)
	}
	backend.deleteErr = errors.New("synthetic cleanup failure")
	if err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	stillStopping, err := store.Get(context.Background(), deleting.RunID)
	if err != nil || stillStopping.State != StateStopping || !backend.resources[deleting.RunID] {
		t.Fatalf("failed cleanup became terminal: %#v resources=%v err=%v", stillStopping, backend.resources, err)
	}
	backend.deleteErr = nil
	if err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), deleting.RunID); !errors.Is(err, ErrNotFound) || backend.resources[deleting.RunID] {
		t.Fatalf("delete cleanup result err=%v resources=%v", err, backend.resources)
	}
}

func TestReconcilerRecoversPartialCreationAndRuntimeFailure(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	backend := newFakeBackend()
	var logs bytes.Buffer
	reconciler, _ := NewReconciler(store, backend, "controller-a", 30*time.Second, log.New(&logs, "", 0))
	run := createRun(t, store, "partial", false)
	if err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	backend.ensureErr = errors.Join(ErrBackendDesiredRunInvalid, errors.New("BACKEND-SECRET-NEEDLE partial create"))
	if err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	stopping, err := store.Get(context.Background(), run.RunID)
	if err != nil || stopping.State != StateStopping || stopping.TerminalTarget != StateFailed || !backend.resources[run.RunID] {
		t.Fatalf("partial failure = %#v resources=%v err=%v", stopping, backend.resources, err)
	}
	backend.ensureErr = nil
	if err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	failed, err := store.Get(context.Background(), run.RunID)
	if err != nil || failed.State != StateFailed || backend.resources[run.RunID] {
		t.Fatalf("partial cleanup = %#v resources=%v err=%v", failed, backend.resources, err)
	}
	if bytes.Contains(logs.Bytes(), []byte("BACKEND-SECRET-NEEDLE")) {
		t.Fatalf("backend diagnostic reached logs: %s", logs.String())
	}
}

func TestReconcilerRetriesDependencyFailuresWithoutDestroyingPartialResources(t *testing.T) {
	for _, dependency := range []string{"broker", "docker"} {
		t.Run(dependency, func(t *testing.T) {
			clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
			store, _ := openTestStore(t, clock, 4)
			backend := newFakeBackend()
			reconciler, _ := NewReconciler(store, backend, "controller-a", 30*time.Second, log.New(io.Discard, "", 0))
			run := createRun(t, store, "retry-"+dependency, false)
			if err := reconciler.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			backend.ensureErr = errors.Join(ErrBackendRetryable, errors.New("SECRET-DEPENDENCY-DIAGNOSTIC"))
			if err := reconciler.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			preparing, err := store.Get(context.Background(), run.RunID)
			if err != nil || preparing.State != StatePreparing || !backend.resources[run.RunID] || backend.deleteCalls != 0 {
				t.Fatalf("retryable %s failure changed lifecycle: %#v resources=%v deletes=%d err=%v", dependency, preparing, backend.resources, backend.deleteCalls, err)
			}
			backend.ensureErr = nil
			if err := reconciler.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			running, err := store.Get(context.Background(), run.RunID)
			if err != nil || running.State != StateRunning {
				t.Fatalf("recovered %s dependency = %#v %v", dependency, running, err)
			}
		})
	}
}

func TestReconcilerConfirmedRuntimeLossEntersCleanup(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	backend := newFakeBackend()
	reconciler, _ := NewReconciler(store, backend, "controller-a", 30*time.Second, log.New(io.Discard, "", 0))
	run := createRun(t, store, "runtime-lost", false)
	reconcileToRunning(t, reconciler, store, run.RunID)
	backend.mu.Lock()
	delete(backend.resources, run.RunID)
	backend.mu.Unlock()
	if err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	stopping, err := store.Get(context.Background(), run.RunID)
	if err != nil || stopping.State != StateStopping || stopping.TerminalTarget != StateFailed || stopping.LastReason != "backend-runtime-failed" {
		t.Fatalf("confirmed loss = %#v %v", stopping, err)
	}
}

func TestReconcilerKeepsRunningStateDuringBackendInspectionUncertainty(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	backend := newFakeBackend()
	reconciler, _ := NewReconciler(store, backend, "controller-a", 30*time.Second, log.New(io.Discard, "", 0))
	run := createRun(t, store, "inspect-uncertain", false)
	reconcileToRunning(t, reconciler, store, run.RunID)
	backend.inspectErr = errors.New("temporary backend uncertainty")
	if err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	retained, err := store.Get(context.Background(), run.RunID)
	if err != nil || retained.State != StateRunning || !backend.resources[run.RunID] || backend.deleteCalls != 0 {
		t.Fatalf("uncertain inspect changed the run: %#v resources=%v deletes=%d err=%v", retained, backend.resources, backend.deleteCalls, err)
	}
}

func reconcileToRunning(t *testing.T, reconciler *Reconciler, store *Store, runID string) {
	t.Helper()
	for range 2 {
		if err := reconciler.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	run, err := store.Get(context.Background(), runID)
	if err != nil || run.State != StateRunning {
		t.Fatalf("run did not reach running: %#v %v", run, err)
	}
}
