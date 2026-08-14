package controller

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestStoreRestartIdempotencyAndSnapshotDigest(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	store, path := openTestStore(t, clock, 4)
	created := createRun(t, store, "infra", true)
	if created.State != StatePending || created.Profile != "engineering" || !created.Persistent || len(created.SnapshotDigest) != 64 {
		t.Fatalf("created run metadata is incomplete: %#v", created)
	}
	replay, err := store.Create(context.Background(), CreateInput{IdempotencyKey: "idempotency-key-infra", ResolvedRun: testResolvedRun(t, "infra", true)})
	if err != nil || replay.Created || replay.Run.Revision != created.Revision {
		t.Fatalf("idempotent replay = %#v, %v", replay, err)
	}
	claimed, err := store.Claim(context.Background(), ClaimInput{
		RunID: created.RunID, Owner: "controller-before-restart", ExpectedRevision: created.Revision, Lease: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenStore(context.Background(), path, StoreOptions{MaxActiveRuns: 4, MaxClaimLease: time.Minute, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	got, err := restarted.Get(context.Background(), "infra")
	if err != nil || got.SnapshotDigest != created.SnapshotDigest || got.Issuer != "https://identity.example.test" ||
		got.ReconcileOwner != "controller-before-restart" || got.Revision != claimed.Revision {
		t.Fatalf("restarted run = %#v, %v", got, err)
	}
	if _, err := restarted.Claim(context.Background(), ClaimInput{
		RunID: got.RunID, Owner: "controller-after-restart", ExpectedRevision: got.Revision, Lease: 5 * time.Second,
	}); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("restart lost active reconciliation lease: %v", err)
	}
	clock.Advance(6 * time.Second)
	if _, err := restarted.Claim(context.Background(), ClaimInput{
		RunID: got.RunID, Owner: "controller-after-restart", ExpectedRevision: got.Revision, Lease: 5 * time.Second,
	}); err != nil {
		t.Fatalf("restart lease takeover: %v", err)
	}
	snapshot, snapshotDigest, err := restarted.ResolvedSnapshot(context.Background(), "infra")
	if err != nil || snapshotDigest != created.SnapshotDigest {
		t.Fatalf("restarted snapshot digest = %q, %v", snapshotDigest, err)
	}
	_, _, canonicalDigest, err := canonicalSnapshot(snapshot)
	if err != nil || canonicalDigest != created.SnapshotDigest {
		t.Fatalf("restarted snapshot is not canonical: digest=%q err=%v", canonicalDigest, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode = %v, %v", info, err)
	}
	stateFiles, err := filepath.Glob(path + "*")
	if err != nil || len(stateFiles) == 0 {
		t.Fatalf("state files = %v, %v", stateFiles, err)
	}
	for _, stateFile := range stateFiles {
		info, err := os.Stat(stateFile)
		if err != nil || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("state file %s mode = %v, %v", filepath.Base(stateFile), info, err)
		}
	}
	if _, err := restarted.Create(context.Background(), CreateInput{IdempotencyKey: "different-idempotency-key", ResolvedRun: testResolvedRun(t, "infra", true)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate run ID error = %v", err)
	}
}

func TestStoreConcurrencyLimitIsAtomicAndReplayPrecedesCapacity(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 1)
	type result struct {
		created bool
		err     error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	var wait sync.WaitGroup
	rawRuns := map[string][]byte{
		"first":  testResolvedRun(t, "first", false),
		"second": testResolvedRun(t, "second", false),
	}
	for _, runID := range []string{"first", "second"} {
		wait.Add(1)
		go func(id string) {
			defer wait.Done()
			<-start
			value, err := store.Create(context.Background(), CreateInput{IdempotencyKey: "idempotency-key-" + id, ResolvedRun: rawRuns[id]})
			results <- result{created: value.Created, err: err}
		}(runID)
	}
	close(start)
	wait.Wait()
	close(results)
	created, capacity := 0, 0
	for result := range results {
		if result.created && result.err == nil {
			created++
		}
		if errors.Is(result.err, ErrCapacityExceeded) {
			capacity++
		}
	}
	if created != 1 || capacity != 1 {
		t.Fatalf("concurrent admission created=%d capacity=%d", created, capacity)
	}
	listed, err := store.List(context.Background(), 10, "")
	if err != nil || len(listed.Runs) != 1 {
		t.Fatalf("list after concurrent admission = %#v, %v", listed, err)
	}
	winner := listed.Runs[0]
	replay, err := store.Create(context.Background(), CreateInput{IdempotencyKey: "idempotency-key-" + winner.RunID, ResolvedRun: testResolvedRun(t, winner.RunID, false)})
	if err != nil || replay.Created {
		t.Fatalf("capacity blocked idempotent replay: %#v, %v", replay, err)
	}
}

func TestExpiredReconciliationLeaseCanBeClaimedByAnotherOwner(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	run := createRun(t, store, "lease-takeover", false)
	first, err := store.Claim(context.Background(), ClaimInput{
		RunID: run.RunID, Owner: "controller-a", ExpectedRevision: run.Revision, Lease: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Second)

	claimed, err := store.Claim(context.Background(), ClaimInput{
		RunID: run.RunID, Owner: "controller-b", ExpectedRevision: first.Revision, Lease: 30 * time.Second,
	})
	if err != nil || claimed.ReconcileOwner != "controller-b" || claimed.Revision != first.Revision+1 {
		t.Fatalf("expired lease takeover = %#v, %v", claimed, err)
	}
	if _, err := store.UpdateStatus(context.Background(), StatusInput{
		RunID: run.RunID, Owner: "controller-a", ExpectedRevision: claimed.Revision, State: StatePreparing,
	}); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("stale owner updated after takeover: %v", err)
	}
}

func TestOptimisticOwnershipTransitionsAndCancellation(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	run := createRun(t, store, "worker", false)
	claimed := claimRun(t, store, run, "controller-a")
	if _, err := store.Claim(context.Background(), ClaimInput{RunID: run.RunID, Owner: "controller-b", ExpectedRevision: claimed.Revision, Lease: 30 * time.Second}); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("concurrent owner error = %v", err)
	}
	if _, err := store.UpdateStatus(context.Background(), StatusInput{RunID: run.RunID, Owner: "controller-a", ExpectedRevision: claimed.Revision, State: StateRunning}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("invalid transition error = %v", err)
	}
	preparing := transitionRun(t, store, claimed, "controller-a", StatePreparing)
	if preparing.ReconcileOwner != "" || preparing.TerminalExpiresAt != nil {
		t.Fatalf("transition retained ownership: %#v", preparing)
	}
	claimed = claimRun(t, store, preparing, "controller-a")
	running := transitionRun(t, store, claimed, "controller-a", StateRunning)
	if running.TerminalExpiresAt != nil {
		t.Fatalf("active run received terminal retention: %#v", running)
	}
	claimed = claimRun(t, store, running, "controller-a")
	cancelled, err := store.Cancel(context.Background(), run.RunID)
	if err != nil || cancelled.State != StateStopping || cancelled.ReconcileOwner != "" || cancelled.LastReason != "cancel-requested" {
		t.Fatalf("cancelled run = %#v, %v", cancelled, err)
	}
	if _, err := store.UpdateStatus(context.Background(), StatusInput{RunID: run.RunID, Owner: "controller-a", ExpectedRevision: claimed.Revision, State: StateCompleted}); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("stale worker updated cancelled run: %v", err)
	}
	claimed = claimRun(t, store, cancelled, "controller-b")
	failed := transitionRun(t, store, claimed, "controller-b", StateFailed)
	if failed.State != StateFailed || failed.TerminalExpiresAt == nil {
		t.Fatalf("failed run = %#v", failed)
	}
	repeated, err := store.Cancel(context.Background(), run.RunID)
	if err != nil || repeated.Revision != failed.Revision {
		t.Fatalf("terminal cancel was not idempotent: %#v, %v", repeated, err)
	}
}

func TestDeleteWaitsForCleanupAndPreservesIdempotencyTombstone(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	run := createRun(t, store, "delete-me", false)
	stopping, deleted, err := store.Delete(context.Background(), run.RunID)
	if err != nil || deleted || stopping.State != StateStopping || !stopping.DeleteRequested {
		t.Fatalf("delete request = %#v %v %v", stopping, deleted, err)
	}
	claimed := claimRun(t, store, stopping, "cleanup-worker")
	if _, err := store.UpdateStatus(context.Background(), StatusInput{RunID: run.RunID, Owner: "cleanup-worker", ExpectedRevision: claimed.Revision, State: StateCompleted, Reason: "cleanup-complete"}); !errors.Is(err, ErrGone) {
		t.Fatalf("cleanup completion error = %v", err)
	}
	if _, err := store.Get(context.Background(), run.RunID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted run remained visible: %v", err)
	}
	if _, deleted, err := store.Delete(context.Background(), run.RunID); err != nil || !deleted {
		t.Fatalf("repeated delete was not idempotent: deleted=%v err=%v", deleted, err)
	}
	if _, err := store.Create(context.Background(), CreateInput{IdempotencyKey: "idempotency-key-delete-me", ResolvedRun: testResolvedRun(t, "delete-me", false)}); !errors.Is(err, ErrGone) {
		t.Fatalf("deleted idempotency key was reused: %v", err)
	}
	if _, err := store.db.Exec(`UPDATE local_runs SET last_reason='TOMBSTONE-SECRET-NEEDLE' WHERE run_id='delete-me'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Delete(context.Background(), run.RunID); !errors.Is(err, ErrStoreUnavailable) || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("corrupt tombstone delete error = %v", err)
	}
}

func TestTTLExpiryAndRetentionAreDeterministic(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	disposable := createRun(t, store, "ttl-run", false)
	clock.Advance(10 * time.Second)
	if changed, err := store.Sweep(context.Background()); err != nil || changed != 1 {
		t.Fatalf("active expiry changed=%d err=%v", changed, err)
	}
	stopping, err := store.Get(context.Background(), disposable.RunID)
	if err != nil || stopping.State != StateStopping || stopping.TerminalTarget != StateExpired || stopping.TerminalExpiresAt != nil {
		t.Fatalf("expiring run = %#v, %v", stopping, err)
	}
	claimed := claimRun(t, store, stopping, "cleanup")
	expired := transitionRun(t, store, claimed, "cleanup", StateExpired)
	if expired.TerminalExpiresAt == nil || expired.LastReason != "backend-observed" {
		t.Fatalf("expired terminal state = %#v", expired)
	}
	clock.Advance(5 * time.Second)
	if changed, err := store.Sweep(context.Background()); err != nil || changed != 1 {
		t.Fatalf("disposable retention changed=%d err=%v", changed, err)
	}
	retiring, err := store.Get(context.Background(), disposable.RunID)
	if err != nil || retiring.State != StateStopping || !retiring.DeleteRequested || retiring.TerminalTarget != StateExpired {
		t.Fatalf("retention cleanup state = %#v %v", retiring, err)
	}
	claimed = claimRun(t, store, retiring, "retention-cleanup")
	if _, err := store.UpdateStatus(context.Background(), StatusInput{RunID: retiring.RunID, Owner: "retention-cleanup", ExpectedRevision: claimed.Revision, State: StateExpired}); !errors.Is(err, ErrGone) {
		t.Fatalf("retention cleanup terminal result = %v", err)
	}
	if _, err := store.Get(context.Background(), disposable.RunID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired disposable run remained: %v", err)
	}

	persistent := createRun(t, store, "persistent-run", true)
	claimed = claimRun(t, store, persistent, "controller")
	preparing := transitionRun(t, store, claimed, "controller", StatePreparing)
	claimed = claimRun(t, store, preparing, "controller")
	running := transitionRun(t, store, claimed, "controller", StateRunning)
	claimed = claimRun(t, store, running, "controller")
	stoppingCompleted, err := store.UpdateStatus(context.Background(), StatusInput{
		RunID: persistent.RunID, Owner: "controller", ExpectedRevision: claimed.Revision,
		State: StateStopping, TerminalTarget: StateCompleted, Reason: "backend-completed",
	})
	if err != nil {
		t.Fatal(err)
	}
	claimed = claimRun(t, store, stoppingCompleted, "controller")
	completed := transitionRun(t, store, claimed, "controller", StateCompleted)
	if completed.TerminalExpiresAt == nil || completed.TerminalExpiresAt.Sub(clock.value) != 20*time.Second {
		t.Fatalf("persistent retention expiry = %#v", completed.TerminalExpiresAt)
	}
	clock.Advance(5 * time.Second)
	if changed, err := store.Sweep(context.Background()); err != nil || changed != 0 {
		t.Fatalf("persistent state used disposable TTL: changed=%d err=%v", changed, err)
	}
	clock.Advance(15 * time.Second)
	if changed, err := store.Sweep(context.Background()); err != nil || changed != 1 {
		t.Fatalf("persistent retention cap changed=%d err=%v", changed, err)
	}
}

func TestDeleteRequestedRunRemainsClaimableUntilCleanup(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	run := createRun(t, store, "delete-expiry", false)
	if _, deleted, err := store.Delete(context.Background(), run.RunID); err != nil || deleted {
		t.Fatalf("delete request: deleted=%v err=%v", deleted, err)
	}
	clock.Advance(10 * time.Second)
	if changed, err := store.Sweep(context.Background()); err != nil || changed != 0 {
		t.Fatalf("delete expiry changed=%d err=%v", changed, err)
	}
	stopping, err := store.Get(context.Background(), run.RunID)
	if err != nil || stopping.State != StateStopping || !stopping.DeleteRequested {
		t.Fatalf("deadline stranded cleanup: %#v %v", stopping, err)
	}
	claimed := claimRun(t, store, stopping, "cleanup")
	if _, err := store.UpdateStatus(context.Background(), StatusInput{RunID: run.RunID, Owner: "cleanup", ExpectedRevision: claimed.Revision, State: StateCompleted}); !errors.Is(err, ErrGone) {
		t.Fatalf("cleanup completion: %v", err)
	}
	if _, deleted, err := store.Delete(context.Background(), run.RunID); err != nil || !deleted {
		t.Fatalf("deadline-terminal repeated delete: deleted=%v err=%v", deleted, err)
	}
}

func TestDeleteDuringExistingStopDoesNotRewriteCleanupOutcome(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	run := createRun(t, store, "cancel-then-delete", false)
	cancelled, err := store.Cancel(context.Background(), run.RunID)
	if err != nil || cancelled.TerminalTarget != StateFailed {
		t.Fatalf("cancel = %#v %v", cancelled, err)
	}
	deleting, deleted, err := store.Delete(context.Background(), run.RunID)
	if err != nil || deleted || !deleting.DeleteRequested || deleting.TerminalTarget != StateFailed {
		t.Fatalf("delete rewrote the cleanup target = %#v deleted=%v err=%v", deleting, deleted, err)
	}
}

func TestMigrationAndCorruptionFailClosed(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	directory := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := directory + "/migration.sqlite3"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE local_runs (
run_id TEXT PRIMARY KEY,idempotency_key TEXT NOT NULL UNIQUE,request_digest TEXT NOT NULL,snapshot BLOB NOT NULL,
snapshot_digest TEXT NOT NULL,state TEXT NOT NULL,revision INTEGER NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
deadline_at TEXT,terminal_expires_at TEXT,reconcile_owner TEXT,reconcile_until TEXT,delete_requested INTEGER NOT NULL DEFAULT 0,deleted_at TEXT);
PRAGMA user_version=1;`)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _, digest, err := canonicalSnapshot(testResolvedRun(t, "migrated", true))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO local_runs(run_id,idempotency_key,request_digest,snapshot,snapshot_digest,state,revision,created_at,updated_at)
VALUES(?,?,?,?,?,'pending',1,?,?)`, "migrated", "idempotency-key-migrated", digest, snapshot, digest, formatTimestamp(clock.value), formatTimestamp(clock.value))
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	store, err := OpenStore(context.Background(), path, StoreOptions{MaxActiveRuns: 4, MaxClaimLease: time.Minute, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := store.Get(context.Background(), "migrated"); err != nil || got.LastReason != "" {
		t.Fatalf("migrated record = %#v, %v", got, err)
	}
	_ = store.Close()

	db, _ = sql.Open("sqlite", path)
	_, err = db.Exec(`UPDATE local_runs SET snapshot=? WHERE run_id='migrated'`, []byte("STATE-SECRET-NEEDLE"))
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	_, err = OpenStore(context.Background(), path, StoreOptions{MaxActiveRuns: 4, MaxClaimLease: time.Minute, Now: clock.Now})
	if !errors.Is(err, ErrStoreUnavailable) || strings.Contains(err.Error(), "STATE-SECRET-NEEDLE") {
		t.Fatalf("corrupt startup error = %v", err)
	}

	future := directory + "/future.sqlite3"
	db, _ = sql.Open("sqlite", future)
	_, _ = db.Exec(`PRAGMA user_version=99`)
	_ = db.Close()
	if _, err := OpenStore(context.Background(), future, StoreOptions{MaxActiveRuns: 4, MaxClaimLease: time.Minute, Now: clock.Now}); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("future schema error = %v", err)
	}
}

func TestVersionTwoStoppingRowsGainDeterministicCleanupTargets(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	directory := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "local-controller.sqlite3")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE local_runs (
run_id TEXT PRIMARY KEY,idempotency_key TEXT NOT NULL UNIQUE,request_digest TEXT NOT NULL,snapshot BLOB NOT NULL,
snapshot_digest TEXT NOT NULL,state TEXT NOT NULL,revision INTEGER NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
deadline_at TEXT,terminal_expires_at TEXT,reconcile_owner TEXT,reconcile_until TEXT,delete_requested INTEGER NOT NULL DEFAULT 0,
deleted_at TEXT,last_reason TEXT NOT NULL DEFAULT ''); PRAGMA user_version=2;`)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		id       string
		deleting int
	}{{"cancel-migrated", 0}, {"delete-migrated", 1}} {
		snapshot, _, digest, snapshotErr := canonicalSnapshot(testResolvedRun(t, item.id, false))
		if snapshotErr != nil {
			t.Fatal(snapshotErr)
		}
		_, err = db.Exec(`INSERT INTO local_runs(run_id,idempotency_key,request_digest,snapshot,snapshot_digest,state,revision,created_at,updated_at,delete_requested,last_reason)
VALUES(?,?,?,?,?,'stopping',2,?,?,?,'migrated-stop')`, item.id, "idempotency-key-"+item.id, digest, snapshot, digest,
			formatTimestamp(clock.value), formatTimestamp(clock.value), item.deleting)
		if err != nil {
			t.Fatal(err)
		}
	}
	_ = db.Close()
	store, err := OpenStore(context.Background(), path, StoreOptions{MaxActiveRuns: 4, MaxClaimLease: time.Minute, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cancelled, _ := store.Get(context.Background(), "cancel-migrated")
	deleting, _ := store.Get(context.Background(), "delete-migrated")
	if cancelled.TerminalTarget != StateFailed || deleting.TerminalTarget != StateCompleted {
		t.Fatalf("migration targets = cancel:%q delete:%q", cancelled.TerminalTarget, deleting.TerminalTarget)
	}
}

func TestStatePathSecurityFailsClosedWithoutChangingBroadDirectoryModes(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	parent := t.TempDir()
	broad := parent + "/shared"
	if err := os.Mkdir(broad, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := OpenStore(context.Background(), broad+"/local-controller.sqlite3", StoreOptions{
		MaxActiveRuns: 4, MaxClaimLease: time.Minute, Now: clock.Now,
	})
	if !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("broad state directory error = %v", err)
	}
	info, statErr := os.Stat(broad)
	if statErr != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("controller changed shared directory mode: %v, %v", info, statErr)
	}

	secure := parent + "/secure"
	if err := os.Mkdir(secure, 0o700); err != nil {
		t.Fatal(err)
	}
	target := secure + "/target.sqlite3"
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := secure + "/local-controller.sqlite3"
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(context.Background(), link, StoreOptions{
		MaxActiveRuns: 4, MaxClaimLease: time.Minute, Now: clock.Now,
	}); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("symlink state path error = %v", err)
	}
}
