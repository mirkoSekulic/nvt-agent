package controller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
	_ "modernc.org/sqlite"
)

const schemaVersion = 6

type StoreOptions struct {
	MaxActiveRuns int
	MaxClaimLease time.Duration
	Now           func() time.Time
}

type Store struct {
	db            *sql.DB
	maxActiveRuns int
	maxClaimLease time.Duration
	now           func() time.Time
}

type storedRun struct {
	view            Run
	snapshot        []byte
	requestDigest   string
	idempotencyKey  string
	activeGroup     string
	deletedAt       *time.Time
	lifecycleCursor string
	ownershipDigest string
	pendingSnapshot []byte
	pendingDigest   string
}

func OpenStore(ctx context.Context, path string, options StoreOptions) (*Store, error) {
	if path == "" || options.MaxActiveRuns < 1 || options.MaxActiveRuns > 10_000 ||
		options.MaxClaimLease < time.Second || options.MaxClaimLease > time.Hour {
		return nil, ErrInvalidRequest
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) == string(filepath.Separator) {
		return nil, ErrInvalidRequest
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	directory := filepath.Dir(path)
	if err := prepareStatePath(directory, path); err != nil {
		return nil, ErrStoreUnavailable
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{db: db, maxActiveRuns: options.MaxActiveRuns, maxClaimLease: options.MaxClaimLease, now: options.Now}
	if err := store.initialize(ctx, path); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func prepareStatePath(directory, path string) error {
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(directory)
	}
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return ErrStoreUnavailable
	}
	fileInfo, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		file, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if createErr != nil {
			return createErr
		}
		return file.Close()
	}
	if err != nil || !fileInfo.Mode().IsRegular() {
		return ErrStoreUnavailable
	}
	return os.Chmod(path, 0o600)
}

func (store *Store) initialize(ctx context.Context, path string) error {
	for _, statement := range []string{
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA journal_mode = WAL`,
		`PRAGMA synchronous = FULL`,
	} {
		if _, err := store.db.ExecContext(ctx, statement); err != nil {
			return ErrStoreUnavailable
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return ErrStoreUnavailable
	}
	if err := store.migrate(ctx); err != nil {
		return err
	}
	if err := store.validate(ctx); err != nil {
		return err
	}
	return nil
}

func (store *Store) migrate(ctx context.Context) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrStoreUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	var version int
	if err := tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return ErrStoreUnavailable
	}
	if version < 0 || version > schemaVersion {
		return ErrStoreUnavailable
	}
	if version == 0 {
		if _, err := tx.ExecContext(ctx, `
CREATE TABLE local_runs (
  run_id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  request_digest TEXT NOT NULL,
  snapshot BLOB NOT NULL,
  snapshot_digest TEXT NOT NULL,
  state TEXT NOT NULL,
  revision INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deadline_at TEXT,
  terminal_expires_at TEXT,
  reconcile_owner TEXT,
  reconcile_until TEXT,
  delete_requested INTEGER NOT NULL DEFAULT 0,
  deleted_at TEXT
);
PRAGMA user_version = 1;`); err != nil {
			return ErrStoreUnavailable
		}
		version = 1
	}
	if version == 1 {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE local_runs ADD COLUMN last_reason TEXT NOT NULL DEFAULT '';
PRAGMA user_version = 2;`); err != nil {
			return ErrStoreUnavailable
		}
		version = 2
	}
	if version == 2 {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE local_runs ADD COLUMN terminal_target TEXT NOT NULL DEFAULT '';
UPDATE local_runs SET terminal_target=CASE WHEN delete_requested=1 THEN 'completed' ELSE 'failed' END WHERE state='stopping';
PRAGMA user_version = 3;`); err != nil {
			return ErrStoreUnavailable
		}
		version = 3
	}
	if version == 3 {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE local_runs ADD COLUMN lifecycle_cursor TEXT NOT NULL DEFAULT '';
PRAGMA user_version = 4;`); err != nil {
			return ErrStoreUnavailable
		}
		version = 4
	}
	if version == 4 {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE local_runs ADD COLUMN active_group TEXT NOT NULL DEFAULT '';
PRAGMA user_version = 5;`); err != nil {
			return ErrStoreUnavailable
		}
		version = 5
	}
	if version == 5 {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE local_runs ADD COLUMN ownership_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE local_runs ADD COLUMN pending_snapshot BLOB;
ALTER TABLE local_runs ADD COLUMN pending_snapshot_digest TEXT NOT NULL DEFAULT '';
UPDATE local_runs SET ownership_digest=snapshot_digest;
PRAGMA user_version = 6;`); err != nil {
			return ErrStoreUnavailable
		}
	}
	if err := tx.Commit(); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}

func (store *Store) validate(ctx context.Context) error {
	var integrity string
	if err := store.db.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return ErrStoreUnavailable
	}
	var version int
	if err := store.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil || version != schemaVersion {
		return ErrStoreUnavailable
	}
	rows, err := store.db.QueryContext(ctx, selectRuns+` ORDER BY run_id`)
	if err != nil {
		return ErrStoreUnavailable
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		if count > 100_000 {
			return ErrStoreUnavailable
		}
		record, err := scanStoredRun(rows)
		if err != nil || validateStoredRun(&record) != nil {
			return ErrStoreUnavailable
		}
	}
	if rows.Err() != nil {
		return ErrStoreUnavailable
	}
	return nil
}

const selectRuns = `SELECT run_id, idempotency_key, active_group, request_digest, snapshot, snapshot_digest,
state, revision, created_at, updated_at, deadline_at, terminal_expires_at,
reconcile_owner, reconcile_until, delete_requested, deleted_at, last_reason, terminal_target, lifecycle_cursor,
ownership_digest, pending_snapshot, pending_snapshot_digest FROM local_runs`

type scanner interface {
	Scan(dest ...any) error
}

func scanStoredRun(row scanner) (storedRun, error) {
	var record storedRun
	var state, createdAt, updatedAt string
	var deadlineAt, terminalExpiresAt, reconcileOwner, reconcileUntil, deletedAt sql.NullString
	var deleteRequested int
	err := row.Scan(
		&record.view.RunID, &record.idempotencyKey, &record.activeGroup, &record.requestDigest, &record.snapshot, &record.view.SnapshotDigest,
		&state, &record.view.Revision, &createdAt, &updatedAt, &deadlineAt, &terminalExpiresAt,
		&reconcileOwner, &reconcileUntil, &deleteRequested, &deletedAt, &record.view.LastReason, &record.view.TerminalTarget, &record.lifecycleCursor,
		&record.ownershipDigest, &record.pendingSnapshot, &record.pendingDigest,
	)
	if err != nil {
		return storedRun{}, err
	}
	if deleteRequested != 0 && deleteRequested != 1 {
		return storedRun{}, ErrStoreUnavailable
	}
	record.view.APIVersion = APIVersion
	record.view.State = State(state)
	record.view.DeleteRequested = deleteRequested == 1
	record.view.ReconcileOwner = reconcileOwner.String
	if record.view.CreatedAt, err = parseTimestamp(createdAt); err != nil {
		return storedRun{}, err
	}
	if record.view.UpdatedAt, err = parseTimestamp(updatedAt); err != nil {
		return storedRun{}, err
	}
	if record.view.DeadlineAt, err = parseOptionalTimestamp(deadlineAt); err != nil {
		return storedRun{}, err
	}
	if record.view.TerminalExpiresAt, err = parseOptionalTimestamp(terminalExpiresAt); err != nil {
		return storedRun{}, err
	}
	if record.view.ReconcileUntil, err = parseOptionalTimestamp(reconcileUntil); err != nil {
		return storedRun{}, err
	}
	if record.deletedAt, err = parseOptionalTimestamp(deletedAt); err != nil {
		return storedRun{}, err
	}
	return record, nil
}

func validateStoredRun(record *storedRun) error {
	if !validRunID(record.view.RunID) || !record.view.State.valid() || record.view.Revision < 1 ||
		!validIdempotencyKey(record.idempotencyKey) || record.activeGroup != "" && !validIdempotencyKey(record.activeGroup) ||
		!validReason(record.view.LastReason) || !validLifecycleCursor(record.lifecycleCursor) ||
		len(record.snapshot) == 0 || len(record.snapshot) > resolvedrun.MaxDocumentBytes ||
		len(record.requestDigest) != 64 || len(record.view.SnapshotDigest) != 64 || len(record.ownershipDigest) != 64 ||
		record.view.CreatedAt.After(record.view.UpdatedAt) ||
		record.view.DeadlineAt != nil && record.view.DeadlineAt.Before(record.view.CreatedAt) ||
		record.deletedAt != nil && record.deletedAt.Before(record.view.CreatedAt) {
		return ErrStoreUnavailable
	}
	digest := sha256.Sum256(record.snapshot)
	if hex.EncodeToString(digest[:]) != record.view.SnapshotDigest || record.requestDigest != record.view.SnapshotDigest {
		return ErrStoreUnavailable
	}
	if decoded, decodeErr := hex.DecodeString(record.ownershipDigest); decodeErr != nil || len(decoded) != sha256.Size {
		return ErrStoreUnavailable
	}
	resolved, err := resolvedrun.DecodeResolvedAgentRun(record.snapshot)
	if err != nil || resolved.RunID != record.view.RunID {
		return ErrStoreUnavailable
	}
	if len(record.pendingSnapshot) != 0 {
		digest := sha256.Sum256(record.pendingSnapshot)
		pending, pendingErr := resolvedrun.DecodeResolvedAgentRun(record.pendingSnapshot)
		if len(record.pendingSnapshot) > resolvedrun.MaxDocumentBytes || record.pendingDigest != hex.EncodeToString(digest[:]) || pendingErr != nil ||
			!workstationUpdateCompatible(resolved, pending) || record.view.State != StatePreparing {
			return ErrStoreUnavailable
		}
	} else if record.pendingDigest != "" {
		return ErrStoreUnavailable
	}
	populateRunMetadata(&record.view, resolved)
	if record.deletedAt != nil && (!record.view.State.terminal() || !record.view.DeleteRequested) ||
		!record.view.State.terminal() && record.view.TerminalExpiresAt != nil ||
		record.view.State.terminal() && record.view.DeleteRequested && record.deletedAt == nil ||
		record.view.DeleteRequested && record.deletedAt == nil && !record.view.State.terminal() && record.view.State != StateStopping {
		return ErrStoreUnavailable
	}
	if record.view.ReconcileOwner == "" && record.view.ReconcileUntil != nil ||
		record.view.ReconcileOwner != "" && record.view.ReconcileUntil == nil || record.view.State.terminal() && record.view.ReconcileOwner != "" {
		return ErrStoreUnavailable
	}
	if record.view.State == StateStopping {
		if !record.view.TerminalTarget.terminal() {
			return ErrStoreUnavailable
		}
	} else if record.view.TerminalTarget != "" {
		return ErrStoreUnavailable
	}
	return nil
}

func populateRunMetadata(view *Run, resolved resolvedrun.ResolvedAgentRun) {
	view.Issuer = resolved.Principal.Issuer
	view.Subject = resolved.Principal.Subject
	view.SourceURL = resolved.SourceURL
	view.Profile = resolved.Profile
	view.Workflow = resolved.Workflow
	view.Retention = resolved.Retention
	view.Persistent = persistentRun(resolved.Persistence.Workspace, resolved.Persistence.RuntimeState, resolved.Persistence.DockerData)
}

func canonicalSnapshot(raw json.RawMessage) ([]byte, resolvedrun.ResolvedAgentRun, string, error) {
	resolved, err := resolvedrun.DecodeResolvedAgentRun(raw)
	if err != nil {
		return nil, resolvedrun.ResolvedAgentRun{}, "", ErrInvalidRequest
	}
	canonical, err := json.Marshal(resolved)
	if err != nil || len(canonical) > resolvedrun.MaxDocumentBytes {
		return nil, resolvedrun.ResolvedAgentRun{}, "", ErrInvalidRequest
	}
	digest := sha256.Sum256(canonical)
	return canonical, resolved, hex.EncodeToString(digest[:]), nil
}

func (store *Store) Create(ctx context.Context, input CreateInput) (CreateResult, error) {
	// Preserve the single-run API's existing eager deadline convergence. The
	// named-run bootstrap calls CreateBatch directly so a rejected batch cannot
	// mutate unrelated durable state before all entries validate.
	if _, err := store.Sweep(ctx); err != nil {
		return CreateResult{}, err
	}
	results, err := store.createBatch(ctx, []CreateInput{input}, false)
	if err != nil {
		return CreateResult{}, err
	}
	return results[0], nil
}

type preparedCreate struct {
	input    CreateInput
	snapshot []byte
	resolved resolvedrun.ResolvedAgentRun
	digest   string
}

// CreateBatch validates all immutable snapshots, replays, tombstones, run-ID
// collisions, and capacity before committing any row. It is the startup
// boundary for administrator-owned named runs; a rejected document cannot
// leave a partially installed set behind.
func (store *Store) CreateBatch(ctx context.Context, inputs []CreateInput) ([]CreateResult, error) {
	return store.createBatch(ctx, inputs, true)
}

func (store *Store) createBatch(ctx context.Context, inputs []CreateInput, reclaimCleanupCapacity bool) ([]CreateResult, error) {
	if len(inputs) == 0 || len(inputs) > store.maxActiveRuns {
		return nil, ErrInvalidRequest
	}
	prepared := make([]preparedCreate, 0, len(inputs))
	seenKeys := make(map[string]struct{}, len(inputs))
	seenRunIDs := make(map[string]struct{}, len(inputs))
	seenGroups := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		if !validIdempotencyKey(input.IdempotencyKey) || input.ActiveGroup != "" && !validIdempotencyKey(input.ActiveGroup) {
			return nil, ErrInvalidRequest
		}
		snapshot, resolved, digest, err := canonicalSnapshot(input.ResolvedRun)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seenKeys[input.IdempotencyKey]; duplicate {
			return nil, ErrConflict
		}
		if _, duplicate := seenRunIDs[resolved.RunID]; duplicate {
			return nil, ErrConflict
		}
		if input.ActiveGroup != "" {
			if _, duplicate := seenGroups[input.ActiveGroup]; duplicate {
				return nil, ErrActiveGroup
			}
			seenGroups[input.ActiveGroup] = struct{}{}
		}
		seenKeys[input.IdempotencyKey] = struct{}{}
		seenRunIDs[resolved.RunID] = struct{}{}
		prepared = append(prepared, preparedCreate{input: input, snapshot: snapshot, resolved: resolved, digest: digest})
	}
	now := store.now().UTC()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := sweepTx(ctx, tx, now); err != nil {
		return nil, err
	}
	results := make([]CreateResult, len(prepared))
	newIndexes := make([]int, 0, len(prepared))
	updateIndexes := make([]int, 0, len(prepared))
	cancelIndexes := make([]int, 0, len(prepared))
	for index, candidate := range prepared {
		existing, found, queryErr := queryByIdempotency(ctx, tx, candidate.input.IdempotencyKey)
		if queryErr != nil {
			return nil, queryErr
		}
		if !found {
			newIndexes = append(newIndexes, index)
			continue
		}
		if validateStoredRun(&existing) != nil {
			return nil, ErrStoreUnavailable
		}
		if existing.deletedAt != nil {
			return nil, ErrGone
		}
		if existing.view.RunID != candidate.resolved.RunID {
			return nil, ErrConflict
		}
		if (existing.requestDigest != candidate.digest || len(existing.pendingSnapshot) != 0) && existing.view.ReconcileUntil != nil && existing.view.ReconcileUntil.After(now) {
			return nil, ErrConflict
		}
		if existing.requestDigest != candidate.digest {
			active, decodeErr := resolvedrun.DecodeResolvedAgentRun(existing.snapshot)
			if decodeErr != nil || !workstationUpdateCompatible(active, candidate.resolved) || existing.view.DeleteRequested ||
				existing.view.State != StateRunning && !(existing.view.State == StatePreparing && len(existing.pendingSnapshot) != 0) {
				return nil, ErrConflict
			}
			if existing.pendingDigest != candidate.digest {
				updateIndexes = append(updateIndexes, index)
			}
		} else if len(existing.pendingSnapshot) != 0 {
			cancelIndexes = append(cancelIndexes, index)
		}
		results[index] = CreateResult{Run: existing.view, Created: false}
	}
	for _, index := range newIndexes {
		group := prepared[index].input.ActiveGroup
		if group == "" {
			continue
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM local_runs
WHERE deleted_at IS NULL AND (active_group = ? OR idempotency_key = ?)
AND state IN ('pending','preparing','running','stopping')`, group, group).Scan(&count); err != nil {
			return nil, ErrStoreUnavailable
		}
		if count > 0 {
			return nil, ErrActiveGroup
		}
	}
	var active int
	activeStates := "('pending','preparing','running','stopping')"
	if reclaimCleanupCapacity {
		// Named runs are durable startup intent. Cleanup-bound rows are already
		// denied execution and reconciled before pending work; excluding them
		// prevents expired downtime state from permanently blocking bootstrap.
		activeStates = "('pending','preparing','running')"
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM local_runs WHERE deleted_at IS NULL AND state IN `+activeStates).Scan(&active); err != nil {
		return nil, ErrStoreUnavailable
	}
	if active+len(newIndexes) > store.maxActiveRuns {
		return nil, ErrCapacityExceeded
	}
	for _, index := range newIndexes {
		candidate := prepared[index]
		deadline := optionalDeadline(now, candidate.resolved.TTL.ActiveSeconds)
		_, err = tx.ExecContext(ctx, `INSERT INTO local_runs (
run_id,idempotency_key,active_group,request_digest,snapshot,snapshot_digest,ownership_digest,state,revision,created_at,updated_at,deadline_at,last_reason
) VALUES (?,?,?,?,?,?,?,'pending',1,?,?,?,'')`,
			candidate.resolved.RunID, candidate.input.IdempotencyKey, candidate.input.ActiveGroup,
			candidate.digest, candidate.snapshot, candidate.digest, candidate.digest,
			formatTimestamp(now), formatTimestamp(now), formatOptionalTimestamp(deadline),
		)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				return nil, ErrConflict
			}
			return nil, ErrStoreUnavailable
		}
		view := Run{
			APIVersion: APIVersion, RunID: candidate.resolved.RunID, State: StatePending, Revision: 1,
			SnapshotDigest: candidate.digest, CreatedAt: now, UpdatedAt: now, DeadlineAt: deadline,
		}
		populateRunMetadata(&view, candidate.resolved)
		results[index] = CreateResult{Run: view, Created: true}
	}
	for _, index := range updateIndexes {
		candidate := prepared[index]
		result, updateErr := tx.ExecContext(ctx, `UPDATE local_runs SET pending_snapshot=?,pending_snapshot_digest=?,state='preparing',revision=revision+1,updated_at=?,last_reason='configuration-rollout-requested',reconcile_owner=NULL,reconcile_until=NULL WHERE idempotency_key=? AND deleted_at IS NULL`,
			candidate.snapshot, candidate.digest, formatTimestamp(now), candidate.input.IdempotencyKey)
		if updateErr != nil || rowsAffected(result) != 1 {
			return nil, ErrStoreUnavailable
		}
		updated, found, queryErr := queryByIdempotency(ctx, tx, candidate.input.IdempotencyKey)
		if queryErr != nil || !found {
			return nil, ErrStoreUnavailable
		}
		results[index] = CreateResult{Run: updated.view, Created: false}
	}
	for _, index := range cancelIndexes {
		candidate := prepared[index]
		result, updateErr := tx.ExecContext(ctx, `UPDATE local_runs SET pending_snapshot=snapshot,pending_snapshot_digest=snapshot_digest,state='preparing',revision=revision+1,updated_at=?,last_reason='configuration-rollback-requested',reconcile_owner=NULL,reconcile_until=NULL WHERE idempotency_key=? AND pending_snapshot IS NOT NULL`,
			formatTimestamp(now), candidate.input.IdempotencyKey)
		if updateErr != nil || rowsAffected(result) != 1 {
			return nil, ErrStoreUnavailable
		}
		updated, found, queryErr := queryByIdempotency(ctx, tx, candidate.input.IdempotencyKey)
		if queryErr != nil || !found {
			return nil, ErrStoreUnavailable
		}
		results[index] = CreateResult{Run: updated.view, Created: false}
	}
	if err := tx.Commit(); err != nil {
		return nil, ErrStoreUnavailable
	}
	return results, nil
}

func workstationUpdateCompatible(active, desired resolvedrun.ResolvedAgentRun) bool {
	if !active.Persistence.Workspace || !active.Persistence.RuntimeState || !active.Persistence.DockerData ||
		!desired.Persistence.Workspace || !desired.Persistence.RuntimeState || !desired.Persistence.DockerData || active.TTL != (resolvedrun.TTL{}) || desired.TTL != (resolvedrun.TTL{}) {
		return false
	}
	active.AgentConfig = append(json.RawMessage(nil), desired.AgentConfig...)
	active.Workflow = desired.Workflow
	active.Repositories = desired.Repositories
	active.CredentialProviders = desired.CredentialProviders
	active.DefaultCredentialProvider = desired.DefaultCredentialProvider
	active.Broker = desired.Broker
	active.Egress = desired.Egress
	active.WorkspaceInstructions = desired.WorkspaceInstructions
	return reflect.DeepEqual(active, desired)
}

func queryByIdempotency(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, key string) (storedRun, bool, error) {
	record, err := scanStoredRun(query.QueryRowContext(ctx, selectRuns+` WHERE idempotency_key = ?`, key))
	if errors.Is(err, sql.ErrNoRows) {
		return storedRun{}, false, nil
	}
	if err != nil {
		return storedRun{}, false, ErrStoreUnavailable
	}
	return record, true, nil
}

func (store *Store) Get(ctx context.Context, runID string) (Run, error) {
	if !validRunID(runID) {
		return Run{}, ErrInvalidRequest
	}
	if _, err := store.Sweep(ctx); err != nil {
		return Run{}, err
	}
	record, err := scanStoredRun(store.db.QueryRowContext(ctx, selectRuns+` WHERE run_id = ?`, runID))
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	if err != nil || validateStoredRun(&record) != nil {
		return Run{}, ErrStoreUnavailable
	}
	if record.deletedAt != nil {
		return Run{}, ErrNotFound
	}
	return record.view, nil
}

// ResolvedSnapshot returns an immutable copy for trusted in-process backend
// reconciliation. The HTTP API deliberately exposes only non-secret metadata.
func (store *Store) ResolvedSnapshot(ctx context.Context, runID string) (json.RawMessage, string, error) {
	if !validRunID(runID) {
		return nil, "", ErrInvalidRequest
	}
	record, err := scanStoredRun(store.db.QueryRowContext(ctx, selectRuns+` WHERE run_id = ?`, runID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrNotFound
	}
	if err != nil || validateStoredRun(&record) != nil {
		return nil, "", ErrStoreUnavailable
	}
	if record.deletedAt != nil {
		return nil, "", ErrNotFound
	}
	return append(json.RawMessage(nil), record.snapshot...), record.view.SnapshotDigest, nil
}

// backendSnapshot returns the immutable desired value and opaque lifecycle
// progress in one read. Lifecycle progress is private to the trusted
// reconciler/backend boundary and never enters API responses.
func (store *Store) backendSnapshot(ctx context.Context, runID string) (json.RawMessage, string, string, string, bool, error) {
	if !validRunID(runID) {
		return nil, "", "", "", false, ErrInvalidRequest
	}
	record, err := scanStoredRun(store.db.QueryRowContext(ctx, selectRuns+` WHERE run_id = ?`, runID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", "", "", false, ErrNotFound
	}
	if err != nil || validateStoredRun(&record) != nil {
		return nil, "", "", "", false, ErrStoreUnavailable
	}
	if record.deletedAt != nil {
		return nil, "", "", "", false, ErrNotFound
	}
	snapshot, digest := record.snapshot, record.view.SnapshotDigest
	if len(record.pendingSnapshot) != 0 {
		snapshot, digest = record.pendingSnapshot, record.pendingDigest
	}
	return append(json.RawMessage(nil), snapshot...), digest, record.ownershipDigest, record.lifecycleCursor, len(record.pendingSnapshot) != 0, nil
}

func (store *Store) List(ctx context.Context, limit int, after string) (ListResult, error) {
	return store.list(ctx, limit, after, false)
}

func (store *Store) listActive(ctx context.Context, limit int, after string) (ListResult, error) {
	return store.list(ctx, limit, after, true)
}

func (store *Store) list(ctx context.Context, limit int, after string, activeOnly bool) (ListResult, error) {
	if limit < 1 || limit > MaxListLimit || after != "" && !validRunID(after) {
		return ListResult{}, ErrInvalidRequest
	}
	if _, err := store.Sweep(ctx); err != nil {
		return ListResult{}, err
	}
	where := ` WHERE deleted_at IS NULL AND run_id > ?`
	if activeOnly {
		where += ` AND state IN ('pending','preparing','running','stopping')`
	}
	rows, err := store.db.QueryContext(ctx, selectRuns+where+` ORDER BY run_id LIMIT ?`, after, limit+1)
	if err != nil {
		return ListResult{}, ErrStoreUnavailable
	}
	defer rows.Close()
	result := ListResult{APIVersion: APIVersion, Runs: make([]Run, 0, limit)}
	for rows.Next() {
		record, err := scanStoredRun(rows)
		if err != nil || validateStoredRun(&record) != nil {
			return ListResult{}, ErrStoreUnavailable
		}
		if len(result.Runs) == limit {
			result.NextAfter = result.Runs[len(result.Runs)-1].RunID
			break
		}
		result.Runs = append(result.Runs, record.view)
	}
	if rows.Err() != nil {
		return ListResult{}, ErrStoreUnavailable
	}
	return result, nil
}

func (store *Store) Claim(ctx context.Context, input ClaimInput) (Run, error) {
	if !validRunID(input.RunID) || !validOwner(input.Owner) || input.ExpectedRevision < 1 ||
		input.Lease < time.Second || input.Lease > store.maxClaimLease {
		return Run{}, ErrInvalidRequest
	}
	if _, err := store.Sweep(ctx); err != nil {
		return Run{}, err
	}
	now := store.now().UTC()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Run{}, ErrStoreUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	record, err := loadForUpdate(ctx, tx, input.RunID)
	if err != nil {
		return Run{}, err
	}
	if record.view.Revision != input.ExpectedRevision || record.view.State.terminal() {
		return Run{}, ErrOwnershipConflict
	}
	if record.view.ReconcileOwner != "" && record.view.ReconcileOwner != input.Owner && record.view.ReconcileUntil.After(now) {
		return Run{}, ErrOwnershipConflict
	}
	until := now.Add(input.Lease)
	newRevision := record.view.Revision + 1
	result, err := tx.ExecContext(ctx, `UPDATE local_runs SET reconcile_owner=?,reconcile_until=?,revision=?,updated_at=? WHERE run_id=? AND revision=?`,
		input.Owner, formatTimestamp(until), newRevision, formatTimestamp(now), input.RunID, input.ExpectedRevision)
	if err != nil || rowsAffected(result) != 1 {
		return Run{}, ErrOwnershipConflict
	}
	if err := tx.Commit(); err != nil {
		return Run{}, ErrStoreUnavailable
	}
	record.view.ReconcileOwner = input.Owner
	record.view.ReconcileUntil = &until
	record.view.Revision = newRevision
	record.view.UpdatedAt = now
	return record.view, nil
}

func (store *Store) UpdateStatus(ctx context.Context, input StatusInput) (Run, error) {
	if !validRunID(input.RunID) || !validOwner(input.Owner) || input.ExpectedRevision < 1 || !input.State.valid() ||
		!validReason(input.Reason) || input.State == StateStopping && !input.TerminalTarget.terminal() ||
		input.State != StateStopping && input.TerminalTarget != "" ||
		input.LifecycleCursor != nil && !validLifecycleCursor(*input.LifecycleCursor) {
		return Run{}, ErrInvalidRequest
	}
	if _, err := store.Sweep(ctx); err != nil {
		return Run{}, err
	}
	now := store.now().UTC()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Run{}, ErrStoreUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	record, err := loadForUpdate(ctx, tx, input.RunID)
	if err != nil {
		return Run{}, err
	}
	if record.view.Revision != input.ExpectedRevision || record.view.ReconcileOwner != input.Owner ||
		record.view.ReconcileUntil == nil || !record.view.ReconcileUntil.After(now) {
		return Run{}, ErrOwnershipConflict
	}
	if input.State == record.view.State {
		if input.LifecycleCursor == nil || *input.LifecycleCursor == record.lifecycleCursor {
			return record.view, nil
		}
		if input.Reason != "" || input.TerminalTarget != "" {
			return Run{}, ErrInvalidTransition
		}
		newRevision := record.view.Revision + 1
		result, updateErr := tx.ExecContext(ctx, `UPDATE local_runs SET lifecycle_cursor=?,revision=?,updated_at=?,
reconcile_owner=NULL,reconcile_until=NULL WHERE run_id=? AND revision=?`,
			*input.LifecycleCursor, newRevision, formatTimestamp(now), input.RunID, input.ExpectedRevision)
		if updateErr != nil || rowsAffected(result) != 1 {
			return Run{}, ErrOwnershipConflict
		}
		if err := tx.Commit(); err != nil {
			return Run{}, ErrStoreUnavailable
		}
		record.view.Revision = newRevision
		record.view.UpdatedAt = now
		record.view.ReconcileOwner = ""
		record.view.ReconcileUntil = nil
		return record.view, nil
	}
	if !transitionAllowed(record.view.State, input.State) {
		return Run{}, ErrInvalidTransition
	}
	if record.view.State == StatePreparing && input.State == StateRunning && len(record.pendingSnapshot) != 0 {
		cursor := record.lifecycleCursor
		if input.LifecycleCursor != nil {
			cursor = *input.LifecycleCursor
		}
		newRevision := record.view.Revision + 1
		result, updateErr := tx.ExecContext(ctx, `UPDATE local_runs SET snapshot=pending_snapshot,snapshot_digest=pending_snapshot_digest,request_digest=pending_snapshot_digest,pending_snapshot=NULL,pending_snapshot_digest='',state='running',revision=?,updated_at=?,reconcile_owner=NULL,reconcile_until=NULL,last_reason=?,lifecycle_cursor=? WHERE run_id=? AND revision=?`,
			newRevision, formatTimestamp(now), input.Reason, cursor, input.RunID, input.ExpectedRevision)
		if updateErr != nil || rowsAffected(result) != 1 {
			return Run{}, ErrOwnershipConflict
		}
		if err := tx.Commit(); err != nil {
			return Run{}, ErrStoreUnavailable
		}
		resolved, decodeErr := resolvedrun.DecodeResolvedAgentRun(record.pendingSnapshot)
		if decodeErr != nil {
			return Run{}, ErrStoreUnavailable
		}
		record.view.State = StateRunning
		record.view.Revision = newRevision
		record.view.UpdatedAt = now
		record.view.SnapshotDigest = record.pendingDigest
		record.view.ReconcileOwner = ""
		record.view.ReconcileUntil = nil
		record.view.LastReason = input.Reason
		populateRunMetadata(&record.view, resolved)
		return record.view, nil
	}
	if record.view.State == StateStopping && input.State != record.view.TerminalTarget {
		return Run{}, ErrInvalidTransition
	}
	resolved, err := resolvedrun.DecodeResolvedAgentRun(record.snapshot)
	if err != nil {
		return Run{}, ErrStoreUnavailable
	}
	terminalExpiry := terminalExpiry(now, input.State, resolved)
	deletedAt := (*time.Time)(nil)
	if input.State.terminal() && record.view.DeleteRequested {
		deletedAt = &now
	}
	newRevision := record.view.Revision + 1
	target := State("")
	if input.State == StateStopping {
		target = input.TerminalTarget
	}
	cursor := record.lifecycleCursor
	if input.LifecycleCursor != nil {
		cursor = *input.LifecycleCursor
	}
	result, err := tx.ExecContext(ctx, `UPDATE local_runs SET state=?,revision=?,updated_at=?,terminal_expires_at=?,
	reconcile_owner=NULL,reconcile_until=NULL,deleted_at=?,last_reason=?,terminal_target=?,lifecycle_cursor=?,
	pending_snapshot=CASE WHEN ?='stopping' THEN NULL ELSE pending_snapshot END,
	pending_snapshot_digest=CASE WHEN ?='stopping' THEN '' ELSE pending_snapshot_digest END WHERE run_id=? AND revision=?`,
		string(input.State), newRevision, formatTimestamp(now), formatOptionalTimestamp(terminalExpiry),
		formatOptionalTimestamp(deletedAt), input.Reason, string(target), cursor, string(input.State), string(input.State), input.RunID, input.ExpectedRevision)
	if err != nil || rowsAffected(result) != 1 {
		return Run{}, ErrOwnershipConflict
	}
	if err := tx.Commit(); err != nil {
		return Run{}, ErrStoreUnavailable
	}
	record.view.State = input.State
	record.view.Revision = newRevision
	record.view.UpdatedAt = now
	record.view.TerminalExpiresAt = terminalExpiry
	record.view.ReconcileOwner = ""
	record.view.ReconcileUntil = nil
	record.view.LastReason = input.Reason
	record.view.TerminalTarget = target
	if deletedAt != nil {
		return Run{}, ErrGone
	}
	return record.view, nil
}

func (store *Store) abortPendingConfiguration(ctx context.Context, runID, owner string, expectedRevision int64) error {
	now := store.now().UTC()
	result, err := store.db.ExecContext(ctx, `UPDATE local_runs SET pending_snapshot=NULL,pending_snapshot_digest='',state='running',revision=revision+1,updated_at=?,reconcile_owner=NULL,reconcile_until=NULL,last_reason='configuration-rollout-rejected' WHERE run_id=? AND revision=? AND reconcile_owner=? AND pending_snapshot IS NOT NULL`,
		formatTimestamp(now), runID, expectedRevision, owner)
	if err != nil {
		return ErrStoreUnavailable
	}
	if rowsAffected(result) != 1 {
		return ErrOwnershipConflict
	}
	return nil
}

func (store *Store) Cancel(ctx context.Context, runID string) (Run, error) {
	return store.requestStop(ctx, runID, false)
}

func (store *Store) Delete(ctx context.Context, runID string) (Run, bool, error) {
	run, err := store.requestStop(ctx, runID, true)
	if errors.Is(err, ErrGone) {
		return Run{}, true, nil
	}
	if errors.Is(err, ErrNotFound) {
		record, queryErr := scanStoredRun(store.db.QueryRowContext(ctx, selectRuns+` WHERE run_id = ?`, runID))
		if queryErr == nil && validateStoredRun(&record) == nil && record.deletedAt != nil {
			return Run{}, true, nil
		}
		if queryErr == nil || queryErr != nil && !errors.Is(queryErr, sql.ErrNoRows) {
			return Run{}, false, ErrStoreUnavailable
		}
	}
	return run, false, err
}

func (store *Store) requestStop(ctx context.Context, runID string, deleteRequested bool) (Run, error) {
	if !validRunID(runID) {
		return Run{}, ErrInvalidRequest
	}
	if _, err := store.Sweep(ctx); err != nil {
		return Run{}, err
	}
	now := store.now().UTC()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Run{}, ErrStoreUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	record, err := loadForUpdate(ctx, tx, runID)
	if err != nil {
		return Run{}, err
	}
	if record.view.State.terminal() {
		if !deleteRequested {
			return record.view, nil
		}
		result, err := tx.ExecContext(ctx, `UPDATE local_runs SET state='stopping',terminal_target=?,terminal_expires_at=NULL,
delete_requested=1,revision=revision+1,updated_at=?,last_reason='delete-requested' WHERE run_id=? AND revision=?`,
			string(record.view.State), formatTimestamp(now), runID, record.view.Revision)
		if err != nil || rowsAffected(result) != 1 {
			return Run{}, ErrConflict
		}
		if err := tx.Commit(); err != nil {
			return Run{}, ErrStoreUnavailable
		}
		record.view.TerminalTarget = record.view.State
		record.view.State = StateStopping
		record.view.TerminalExpiresAt = nil
		record.view.DeleteRequested = true
		record.view.Revision++
		record.view.UpdatedAt = now
		record.view.LastReason = "delete-requested"
		return record.view, nil
	}
	if record.view.State == StateStopping && (!deleteRequested || record.view.DeleteRequested) {
		return record.view, nil
	}
	reason := "cancel-requested"
	target := StateFailed
	if record.view.State == StateStopping {
		target = record.view.TerminalTarget
		if deleteRequested {
			reason = "delete-requested"
		}
	} else if deleteRequested {
		reason = "delete-requested"
		target = StateCompleted
	}
	newRevision := record.view.Revision + 1
	result, err := tx.ExecContext(ctx, `UPDATE local_runs SET state='stopping',delete_requested=?,revision=?,updated_at=?,
	reconcile_owner=NULL,reconcile_until=NULL,last_reason=?,terminal_target=?,pending_snapshot=NULL,pending_snapshot_digest='' WHERE run_id=? AND revision=?`,
		boolInt(deleteRequested || record.view.DeleteRequested), newRevision, formatTimestamp(now), reason, string(target), runID, record.view.Revision)
	if err != nil || rowsAffected(result) != 1 {
		return Run{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return Run{}, ErrStoreUnavailable
	}
	record.view.State = StateStopping
	record.view.DeleteRequested = deleteRequested || record.view.DeleteRequested
	record.view.Revision = newRevision
	record.view.UpdatedAt = now
	record.view.ReconcileOwner = ""
	record.view.ReconcileUntil = nil
	record.view.LastReason = reason
	record.view.TerminalTarget = target
	return record.view, nil
}

func (store *Store) Sweep(ctx context.Context) (int, error) {
	now := store.now().UTC()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, ErrStoreUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	changed, err := sweepTx(ctx, tx, now)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, ErrStoreUnavailable
	}
	return changed, nil
}

func sweepTx(ctx context.Context, tx *sql.Tx, now time.Time) (int, error) {
	rows, err := tx.QueryContext(ctx, selectRuns+` WHERE deleted_at IS NULL ORDER BY run_id`)
	if err != nil {
		return 0, ErrStoreUnavailable
	}
	records := []storedRun{}
	for rows.Next() {
		record, err := scanStoredRun(rows)
		if err != nil || validateStoredRun(&record) != nil {
			_ = rows.Close()
			return 0, ErrStoreUnavailable
		}
		records = append(records, record)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return 0, ErrStoreUnavailable
	}
	changed := 0
	for _, record := range records {
		if record.view.State.active() && record.view.State != StateStopping && record.view.DeadlineAt != nil && !record.view.DeadlineAt.After(now) {
			result, err := tx.ExecContext(ctx, `UPDATE local_runs SET state='stopping',revision=revision+1,updated_at=?,
	reconcile_owner=NULL,reconcile_until=NULL,last_reason='active-deadline-exceeded',terminal_target='expired',pending_snapshot=NULL,pending_snapshot_digest='' WHERE run_id=? AND revision=?`,
				formatTimestamp(now), record.view.RunID, record.view.Revision)
			if err != nil || rowsAffected(result) != 1 {
				return 0, ErrStoreUnavailable
			}
			changed++
			continue
		}
		if record.view.State.terminal() && record.view.TerminalExpiresAt != nil && !record.view.TerminalExpiresAt.After(now) {
			result, err := tx.ExecContext(ctx, `UPDATE local_runs SET state='stopping',terminal_target=state,terminal_expires_at=NULL,
delete_requested=1,revision=revision+1,updated_at=?,last_reason='retention-expired' WHERE run_id=? AND revision=?`,
				formatTimestamp(now), record.view.RunID, record.view.Revision)
			if err != nil || rowsAffected(result) != 1 {
				return 0, ErrStoreUnavailable
			}
			changed++
		}
	}
	return changed, nil
}

func (store *Store) replacementCleanupPending(ctx context.Context) (bool, error) {
	var active, stopping int
	err := store.db.QueryRowContext(ctx, `SELECT
COUNT(*),
COALESCE(SUM(CASE WHEN state = 'stopping' THEN 1 ELSE 0 END), 0)
FROM local_runs
WHERE deleted_at IS NULL AND state IN ('pending','preparing','running','stopping')`).Scan(&active, &stopping)
	if err != nil {
		return false, ErrStoreUnavailable
	}
	return stopping > 0 && active > store.maxActiveRuns, nil
}

func (store *Store) Ready(ctx context.Context) bool {
	if store == nil || store.db == nil {
		return false
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return false
	}
	defer func() { _ = tx.Rollback() }()
	var version int
	if err := tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil || version != schemaVersion {
		return false
	}
	var integrity string
	if err := tx.QueryRowContext(ctx, `PRAGMA quick_check(1)`).Scan(&integrity); err != nil || integrity != "ok" {
		return false
	}
	if _, err := tx.ExecContext(ctx, `UPDATE local_runs SET revision=revision WHERE 0`); err != nil {
		return false
	}
	return tx.Commit() == nil
}

func (store *Store) Close() error {
	if store == nil || store.db == nil {
		return nil
	}
	if err := store.db.Close(); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}

func loadForUpdate(ctx context.Context, tx *sql.Tx, runID string) (storedRun, error) {
	record, err := scanStoredRun(tx.QueryRowContext(ctx, selectRuns+` WHERE run_id = ?`, runID))
	if errors.Is(err, sql.ErrNoRows) {
		return storedRun{}, ErrNotFound
	}
	if err != nil || validateStoredRun(&record) != nil {
		return storedRun{}, ErrStoreUnavailable
	}
	if record.deletedAt != nil {
		return storedRun{}, ErrNotFound
	}
	return record, nil
}

func terminalExpiry(now time.Time, state State, resolved resolvedrun.ResolvedAgentRun) *time.Time {
	if !state.terminal() {
		return nil
	}
	persistent := persistentRun(resolved.Persistence.Workspace, resolved.Persistence.RuntimeState, resolved.Persistence.DockerData)
	candidates := []int64{}
	if !persistent {
		if state == StateCompleted && resolved.TTL.CompletedSeconds > 0 {
			candidates = append(candidates, resolved.TTL.CompletedSeconds)
		}
		if (state == StateFailed || state == StateExpired) && resolved.TTL.FailedSeconds > 0 {
			candidates = append(candidates, resolved.TTL.FailedSeconds)
		}
	}
	if resolved.TTL.RunRetentionSeconds > 0 {
		candidates = append(candidates, resolved.TTL.RunRetentionSeconds)
	}
	if len(candidates) == 0 {
		return nil
	}
	minimum := candidates[0]
	for _, candidate := range candidates[1:] {
		if candidate < minimum {
			minimum = candidate
		}
	}
	expires := now.Add(time.Duration(minimum) * time.Second)
	return &expires
}

func optionalDeadline(now time.Time, seconds int64) *time.Time {
	if seconds <= 0 {
		return nil
	}
	deadline := now.Add(time.Duration(seconds) * time.Second)
	return &deadline
}

func rowsAffected(result sql.Result) int64 {
	if result == nil {
		return 0
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0
	}
	return count
}

func validRunID(value string) bool {
	if len(value) == 0 || len(value) > 63 || !lowerAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !lowerAlphaNumeric(value[index]) && value[index] != '-' {
			return false
		}
	}
	return lowerAlphaNumeric(value[len(value)-1])
}

func lowerAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}

func validIdempotencyKey(value string) bool {
	if len(value) < 16 || len(value) > MaxIdempotencyKeyBytes || value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validOwner(value string) bool {
	return len(value) > 0 && len(value) <= MaxOwnerBytes && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func validReason(value string) bool {
	if len(value) > MaxReasonBytes || value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				if character != '-' && character != '.' {
					return false
				}
			}
		}
	}
	return true
}

func validLifecycleCursor(value string) bool {
	if len(value) > MaxLifecycleCursorBytes {
		return false
	}
	for index := range value {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '.' || character == ':' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func formatTimestamp(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func formatOptionalTimestamp(value *time.Time) any {
	if value == nil {
		return nil
	}
	return formatTimestamp(*value)
}

func parseTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC {
		return time.Time{}, ErrStoreUnavailable
	}
	return parsed, nil
}

func parseOptionalTimestamp(value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	parsed, err := parseTimestamp(value.String)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
