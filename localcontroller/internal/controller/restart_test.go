package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const restartTestID = "0123456789abcdef0123456789abcdef"

type restartTestBackend struct {
	*fakeBackend
	quiesced   []BackendRun
	quiesceErr error
}

func (backend *restartTestBackend) QuiesceForRestart(_ context.Context, run BackendRun) (BackendObservation, error) {
	backend.quiesced = append(backend.quiesced, run)
	delete(backend.resources, run.Resolved.RunID)
	return BackendObservation{LifecycleCursor: "v1:1:2:999"}, backend.quiesceErr
}

func restartFixture(t *testing.T) (*Store, string, *fakeClock, *Scheduler, *restartTestBackend, *Reconciler) {
	t.Helper()
	clock := &fakeClock{value: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)}
	store, dbPath := openTestStore(t, clock, 8)
	document := testNativeConfiguration()
	document.Workstations = []workstationConfig{testWorkstation("personal", "Personal"), testWorkstation("other", "Other")}
	path := filepath.Join(t.TempDir(), "controller.json")
	if err := os.WriteFile(path, mustJSON(t, document), 0o600); err != nil {
		t.Fatal(err)
	}
	scheduler, err := LoadScheduler(path, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := scheduler.BootstrapWorkstations(context.Background()); err != nil {
		t.Fatal(err)
	}
	backend := &restartTestBackend{fakeBackend: newFakeBackend()}
	reconciler, err := NewReconciler(store, backend, "first-controller", 30*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	reconcileToRunning(t, reconciler, store, "personal")
	return store, dbPath, clock, scheduler, backend, reconciler
}

func TestScopedRestartRunningAndCleanedTerminalWorkstations(t *testing.T) {
	for _, initial := range []State{StateRunning, StateCompleted, StateFailed} {
		t.Run(string(initial), func(t *testing.T) {
			ctx := context.Background()
			store, _, _, _, backend, reconciler := restartFixture(t)
			if initial != StateRunning {
				backend.inspectTarget = initial
				run, _ := store.Get(ctx, "personal")
				if err := reconciler.reconcileRun(ctx, run); err != nil {
					t.Fatal(err)
				}
				run, _ = store.Get(ctx, "personal")
				if err := reconciler.reconcileRun(ctx, run); err != nil {
					t.Fatal(err)
				}
				backend.inspectTarget = ""
				if backend.resources["personal"] {
					t.Fatal("terminal runtime was not cleaned up")
				}
			}
			before, _ := store.Get(ctx, "personal")
			other, _ := store.Get(ctx, "other")
			snapshot, digest, _ := store.ResolvedSnapshot(ctx, "personal")
			requested, err := store.RestartWorkstation(ctx, "personal", restartTestID)
			if err != nil || requested.RestartPhase != "quiescing" {
				t.Fatalf("request=%+v %v", requested, err)
			}
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					joined, err := store.RestartWorkstation(ctx, "personal", strings.Repeat("a", 32))
					if err != nil || joined.RestartID != restartTestID || joined.Revision != requested.Revision {
						t.Errorf("join=%+v %v", joined, err)
					}
				}()
			}
			wg.Wait()
			for i := 0; i < 3; i++ {
				if err := reconciler.Reconcile(ctx); err != nil {
					t.Fatal(err)
				}
			}
			after, _ := store.Get(ctx, "personal")
			if after.State != StateRunning || after.RestartPhase != "complete" || after.RestartID != restartTestID || len(backend.quiesced) != 1 {
				t.Fatalf("after=%+v quiesces=%d", after, len(backend.quiesced))
			}
			replayed, err := store.RestartWorkstation(ctx, "personal", restartTestID)
			if err != nil || replayed.Revision != after.Revision {
				t.Fatalf("completed replay=%+v %v", replayed, err)
			}
			current, currentDigest, _ := store.ResolvedSnapshot(ctx, "personal")
			if !bytes.Equal(snapshot, current) || digest != currentDigest || !before.CreatedAt.Equal(after.CreatedAt) || before.Subject != after.Subject {
				t.Fatal("restart changed applied identity/configuration")
			}
			otherAfter, _ := store.Get(ctx, "other")
			if !reflect.DeepEqual(other, otherAfter) {
				t.Fatal("unrelated workstation changed")
			}
			last := backend.ensuredRuns[len(backend.ensuredRuns)-1]
			if last.Resolved.RunID != "personal" || last.LifecycleCursor != "v1:1:2:999" || last.ConfigurationRollout || last.DeleteRequested {
				t.Fatalf("unsafe restart preparation: %+v", last)
			}
		})
	}
}

func TestRestartSurvivesControllerCrashBeforeAndAfterQuiesceCommit(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[committed], func(t *testing.T) {
			ctx := context.Background()
			store, path, clock, scheduler, backend, reconciler := restartFixture(t)
			requested, err := store.RestartWorkstation(ctx, "personal", restartTestID)
			if err != nil {
				t.Fatal(err)
			}
			if !committed {
				backend.quiesceErr = ErrBackendRetryable
			}
			_ = reconciler.reconcileRun(ctx, requested)
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			clock.Advance(time.Minute)
			reopened, err := OpenStore(ctx, path, StoreOptions{MaxActiveRuns: 8, MaxClaimLease: time.Minute, Now: clock.Now})
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			scheduler.store = reopened
			if err := scheduler.BootstrapWorkstations(ctx); err != nil {
				t.Fatal(err)
			}
			backend.quiesceErr = nil
			recovered, _ := NewReconciler(reopened, backend, "second-controller", 30*time.Second, nil)
			if err := recovered.Recover(ctx); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 4; i++ {
				_ = recovered.Reconcile(ctx)
			}
			run, err := reopened.Get(ctx, "personal")
			if err != nil || run.State != StateRunning || run.RestartPhase != "complete" || run.RestartID != restartTestID {
				t.Fatalf("recovered=%+v %v", run, err)
			}
			want := 1
			if !committed {
				want = 2
			}
			if len(backend.quiesced) != want {
				t.Fatalf("quiesce count=%d want=%d", len(backend.quiesced), want)
			}
		})
	}
}

func TestRestartConflictsAndStaleLifecycleRevisions(t *testing.T) {
	ctx := context.Background()
	store, _, clock, scheduler, _, reconciler := restartFixture(t)
	before, _ := store.Get(ctx, "personal")
	claimed, err := store.Claim(ctx, ClaimInput{RunID: "personal", Owner: "busy", ExpectedRevision: before.Revision, Lease: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RestartWorkstation(ctx, "personal", restartTestID); !errors.Is(err, ErrRestartConflict) {
		t.Fatalf("active lease: %v", err)
	}
	clock.Advance(2 * time.Second)
	if _, err := store.RestartWorkstation(ctx, "personal", restartTestID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateStatus(ctx, StatusInput{RunID: "personal", Owner: "busy", ExpectedRevision: claimed.Revision, State: StateStopping, TerminalTarget: StateFailed}); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("stale failure accepted: %v", err)
	}
	if _, err := store.Cancel(ctx, "personal"); !errors.Is(err, ErrRestartConflict) {
		t.Fatalf("cancel discarded restart: %v", err)
	}
	if _, _, err := store.Delete(ctx, "personal"); !errors.Is(err, ErrRestartConflict) {
		t.Fatalf("delete discarded restart: %v", err)
	}
	inputs := append([]CreateInput{}, scheduler.workstations...)
	var desired map[string]any
	for i := range inputs {
		_ = json.Unmarshal(inputs[i].ResolvedRun, &desired)
		if desired["run_id"] == "personal" {
			desired["workspace_instructions"].(map[string]any)["workflow"] = "pending unrelated edits"
			inputs[i].ResolvedRun = mustJSON(t, desired)
		}
	}
	if _, err := store.ReconcileWorkstations(ctx, inputs, false, false, false); !errors.Is(err, ErrRestartConflict) {
		t.Fatalf("rollout during restart: %v", err)
	}
	for i := 0; i < 3; i++ {
		_ = reconciler.Reconcile(ctx)
	}
	if _, err := store.ReconcileWorkstations(ctx, inputs, false, false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RestartWorkstation(ctx, "personal", strings.Repeat("b", 32)); !errors.Is(err, ErrRestartConflict) {
		t.Fatalf("pending rollout: %v", err)
	}
}

func TestRestartAPIRequiresAdminAndExistingWorkstation(t *testing.T) {
	ctx := context.Background()
	store, _, _, _, _, _ := restartFixture(t)
	authorization, _ := LoadAPIAuthorization(writePrivateToken(t, "admin", apiAdminToken), writePrivateToken(t, "routes", apiRouteToken), nil)
	handler, err := NewAuthorizedHTTPHandlerWithServices(store, nil, nil, nil, nil, authorization)
	if err != nil {
		t.Fatal(err)
	}
	body := mustJSON(t, map[string]string{"api_version": APIVersion, "request_id": restartTestID})
	before, _ := store.Get(ctx, "personal")
	for _, token := range []string{"", apiRouteToken, schedulingTestToken} {
		response := authorizedRequest(t, handler, http.MethodPost, "/v1/runs/personal/restart", body, token)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("unauthorized=%d", response.Code)
		}
	}
	after, _ := store.Get(ctx, "personal")
	if !reflect.DeepEqual(before, after) {
		t.Fatal("unauthorized mutation")
	}
	createRun(t, store, "ephemeral", false)
	for name, status := range map[string]int{"unknown": 404, "ephemeral": 409, "personal": 202} {
		response := authorizedRequest(t, handler, http.MethodPost, "/v1/runs/"+name+"/restart", body, apiAdminToken)
		if response.Code != status {
			t.Fatalf("%s=%d %s", name, response.Code, response.Body.String())
		}
	}
	for _, invalid := range []string{`{}`, `{"api_version":"nvt.local-runs/v1","request_id":"bad"}`, `{"api_version":"nvt.local-runs/v1","request_id":"0123456789abcdef0123456789abcdef","snapshot":{}}`} {
		if response := authorizedRequest(t, handler, http.MethodPost, "/v1/runs/personal/restart", []byte(invalid), apiAdminToken); response.Code != 400 {
			t.Fatalf("invalid=%d", response.Code)
		}
	}
	if _, _, err := store.Delete(ctx, "other"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RestartWorkstation(ctx, "other", restartTestID); !errors.Is(err, ErrGone) {
		t.Fatalf("deleting target: %v", err)
	}
}

func TestRestartRejectsBusyDeletedAndMalformedRecords(t *testing.T) {
	for _, mode := range []string{"pending", "preparing", "stopping", "deleted", "malformed", "capacity", "not-owned"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			store, _, _, _, _, reconciler := restartFixture(t)
			want := ErrRestartConflict
			switch mode {
			case "pending", "preparing":
				if _, err := store.db.Exec(`UPDATE local_runs SET state=? WHERE run_id='personal'`, mode); err != nil {
					t.Fatal(err)
				}
			case "stopping":
				if _, err := store.Cancel(ctx, "personal"); err != nil {
					t.Fatal(err)
				}
			case "deleted":
				if _, _, err := store.Delete(ctx, "personal"); err != nil {
					t.Fatal(err)
				}
				_ = reconciler.Reconcile(ctx)
				want = ErrGone
			case "malformed":
				if _, err := store.db.Exec(`UPDATE local_runs SET snapshot_digest=? WHERE run_id='personal'`, strings.Repeat("0", 64)); err != nil {
					t.Fatal(err)
				}
				want = ErrStoreUnavailable
			case "capacity":
				_, _ = store.Cancel(ctx, "personal")
				_ = reconciler.Reconcile(ctx)
				store.maxActiveRuns = 1
				want = ErrCapacityExceeded
			case "not-owned":
				if _, err := store.db.Exec(`UPDATE local_runs SET idempotency_key='not-administrator-owned' WHERE run_id='personal'`); err != nil {
					t.Fatal(err)
				}
				want = ErrNotWorkstation
			}
			if _, err := store.RestartWorkstation(ctx, "personal", restartTestID); !errors.Is(err, want) {
				t.Fatalf("restart=%v want=%v", err, want)
			}
		})
	}
}

func TestRestartBackendRejectionDoesNotPruneRetainedState(t *testing.T) {
	for _, phase := range []string{"quiescing", "preparing"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			store, _, _, _, backend, reconciler := restartFixture(t)
			_, err := store.RestartWorkstation(ctx, "personal", restartTestID)
			if err != nil {
				t.Fatal(err)
			}
			if phase == "quiescing" {
				backend.quiesceErr = ErrBackendDesiredRunInvalid
			} else {
				backend.ensureErr = ErrBackendDesiredRunInvalid
			}
			for i := 0; i < 3; i++ {
				_ = reconciler.Reconcile(ctx)
			}
			run, err := store.Get(ctx, "personal")
			if err != nil || run.State != StateFailed || run.RestartPhase != "failed" || backend.deleteCalls != 0 {
				t.Fatalf("failure=%+v %v deletes=%d", run, err, backend.deleteCalls)
			}
		})
	}
}

func TestRestartRefusesApprovedImmutableReplacement(t *testing.T) {
	ctx := context.Background()
	store, _, _, scheduler, _, _ := restartFixture(t)
	inputs := append([]CreateInput{}, scheduler.workstations...)
	for i := range inputs {
		var value map[string]any
		_ = json.Unmarshal(inputs[i].ResolvedRun, &value)
		if value["run_id"] == "personal" {
			value["image"] = "registry.example.test/runtime:different"
			inputs[i].ResolvedRun = mustJSON(t, value)
		}
	}
	if _, err := store.ReconcileWorkstations(ctx, inputs, false, true, true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RestartWorkstation(ctx, "personal", restartTestID); !errors.Is(err, ErrRestartConflict) {
		t.Fatalf("replacement conflict=%v", err)
	}
	run, err := store.Get(ctx, "personal")
	if err != nil || !run.DeleteRequested || run.LastReason != "immutable-replacement-requested" || run.RestartID != "" {
		t.Fatalf("replacement was modified: %+v %v", run, err)
	}
}

func TestRestartSchemaMigrationPreservesExistingAppliedRuns(t *testing.T) {
	ctx := context.Background()
	store, path, clock, _, _, _ := restartFixture(t)
	before, err := store.Get(ctx, "personal")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`ALTER TABLE local_runs DROP COLUMN restart_id; ALTER TABLE local_runs DROP COLUMN restart_phase; PRAGMA user_version=6;`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(ctx, path, StoreOptions{MaxActiveRuns: 8, MaxClaimLease: time.Minute, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	after, err := reopened.Get(ctx, "personal")
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("migration changed run: before=%+v after=%+v %v", before, after, err)
	}
}
