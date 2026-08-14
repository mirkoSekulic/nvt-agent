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
	"strings"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
	_ "modernc.org/sqlite"
)

const schemaVersion = 2

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
	view           Run
	snapshot       []byte
	requestDigest  string
	idempotencyKey string
	deletedAt      *time.Time
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

const selectRuns = `SELECT run_id, idempotency_key, request_digest, snapshot, snapshot_digest,
state, revision, created_at, updated_at, deadline_at, terminal_expires_at,
reconcile_owner, reconcile_until, delete_requested, deleted_at, last_reason FROM local_runs`

type scanner interface {
	Scan(dest ...any) error
}

func scanStoredRun(row scanner) (storedRun, error) {
	var record storedRun
	var state, createdAt, updatedAt string
	var deadlineAt, terminalExpiresAt, reconcileOwner, reconcileUntil, deletedAt sql.NullString
	var deleteRequested int
	err := row.Scan(
		&record.view.RunID, &record.idempotencyKey, &record.requestDigest, &record.snapshot, &record.view.SnapshotDigest,
		&state, &record.view.Revision, &createdAt, &updatedAt, &deadlineAt, &terminalExpiresAt,
		&reconcileOwner, &reconcileUntil, &deleteRequested, &deletedAt, &record.view.LastReason,
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
		!validIdempotencyKey(record.idempotencyKey) || !validReason(record.view.LastReason) ||
		len(record.snapshot) == 0 || len(record.snapshot) > resolvedrun.MaxDocumentBytes ||
		len(record.requestDigest) != 64 || len(record.view.SnapshotDigest) != 64 ||
		record.view.CreatedAt.After(record.view.UpdatedAt) ||
		record.view.DeadlineAt != nil && record.view.DeadlineAt.Before(record.view.CreatedAt) ||
		record.deletedAt != nil && record.deletedAt.Before(record.view.CreatedAt) {
		return ErrStoreUnavailable
	}
	digest := sha256.Sum256(record.snapshot)
	if hex.EncodeToString(digest[:]) != record.view.SnapshotDigest || record.requestDigest != record.view.SnapshotDigest {
		return ErrStoreUnavailable
	}
	resolved, err := resolvedrun.DecodeResolvedAgentRun(record.snapshot)
	if err != nil || resolved.RunID != record.view.RunID {
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
	return nil
}

func populateRunMetadata(view *Run, resolved resolvedrun.ResolvedAgentRun) {
	view.Issuer = resolved.Principal.Issuer
	view.Subject = resolved.Principal.Subject
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
	if !validIdempotencyKey(input.IdempotencyKey) {
		return CreateResult{}, ErrInvalidRequest
	}
	snapshot, resolved, digest, err := canonicalSnapshot(input.ResolvedRun)
	if err != nil {
		return CreateResult{}, err
	}
	if _, err := store.Sweep(ctx); err != nil {
		return CreateResult{}, err
	}
	now := store.now().UTC()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return CreateResult{}, ErrStoreUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	existing, found, err := queryByIdempotency(ctx, tx, input.IdempotencyKey)
	if err != nil {
		return CreateResult{}, err
	}
	if found {
		if validateStoredRun(&existing) != nil {
			return CreateResult{}, ErrStoreUnavailable
		}
		if existing.requestDigest != digest || existing.view.RunID != resolved.RunID {
			return CreateResult{}, ErrConflict
		}
		if existing.deletedAt != nil {
			return CreateResult{}, ErrGone
		}
		return CreateResult{Run: existing.view, Created: false}, nil
	}
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM local_runs WHERE deleted_at IS NULL AND state IN ('pending','preparing','running','stopping')`).Scan(&active); err != nil {
		return CreateResult{}, ErrStoreUnavailable
	}
	if active >= store.maxActiveRuns {
		return CreateResult{}, ErrCapacityExceeded
	}
	deadline := optionalDeadline(now, resolved.TTL.ActiveSeconds)
	_, err = tx.ExecContext(ctx, `INSERT INTO local_runs (
run_id,idempotency_key,request_digest,snapshot,snapshot_digest,state,revision,created_at,updated_at,deadline_at,last_reason
) VALUES (?,?,?,?,?,'pending',1,?,?,?,'')`,
		resolved.RunID, input.IdempotencyKey, digest, snapshot, digest, formatTimestamp(now), formatTimestamp(now), formatOptionalTimestamp(deadline),
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return CreateResult{}, ErrConflict
		}
		return CreateResult{}, ErrStoreUnavailable
	}
	if err := tx.Commit(); err != nil {
		return CreateResult{}, ErrStoreUnavailable
	}
	view := Run{
		APIVersion: APIVersion, RunID: resolved.RunID, State: StatePending, Revision: 1,
		SnapshotDigest: digest, CreatedAt: now, UpdatedAt: now, DeadlineAt: deadline,
	}
	populateRunMetadata(&view, resolved)
	return CreateResult{Run: view, Created: true}, nil
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

func (store *Store) List(ctx context.Context, limit int, after string) (ListResult, error) {
	if limit < 1 || limit > MaxListLimit || after != "" && !validRunID(after) {
		return ListResult{}, ErrInvalidRequest
	}
	if _, err := store.Sweep(ctx); err != nil {
		return ListResult{}, err
	}
	rows, err := store.db.QueryContext(ctx, selectRuns+` WHERE deleted_at IS NULL AND run_id > ? ORDER BY run_id LIMIT ?`, after, limit+1)
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
		!validReason(input.Reason) {
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
		return record.view, nil
	}
	if !transitionAllowed(record.view.State, input.State) {
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
	result, err := tx.ExecContext(ctx, `UPDATE local_runs SET state=?,revision=?,updated_at=?,terminal_expires_at=?,
reconcile_owner=NULL,reconcile_until=NULL,deleted_at=?,last_reason=? WHERE run_id=? AND revision=?`,
		string(input.State), newRevision, formatTimestamp(now), formatOptionalTimestamp(terminalExpiry),
		formatOptionalTimestamp(deletedAt), input.Reason, input.RunID, input.ExpectedRevision)
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
	if deletedAt != nil {
		return Run{}, ErrGone
	}
	return record.view, nil
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
		result, err := tx.ExecContext(ctx, `UPDATE local_runs SET deleted_at=?,delete_requested=1,revision=revision+1,updated_at=?,last_reason='delete-requested' WHERE run_id=? AND revision=?`,
			formatTimestamp(now), formatTimestamp(now), runID, record.view.Revision)
		if err != nil || rowsAffected(result) != 1 {
			return Run{}, ErrConflict
		}
		if err := tx.Commit(); err != nil {
			return Run{}, ErrStoreUnavailable
		}
		return Run{}, ErrGone
	}
	if record.view.State == StateStopping && (!deleteRequested || record.view.DeleteRequested) {
		return record.view, nil
	}
	reason := "cancel-requested"
	if deleteRequested {
		reason = "delete-requested"
	}
	newRevision := record.view.Revision + 1
	result, err := tx.ExecContext(ctx, `UPDATE local_runs SET state='stopping',delete_requested=?,revision=?,updated_at=?,
reconcile_owner=NULL,reconcile_until=NULL,last_reason=? WHERE run_id=? AND revision=?`,
		boolInt(deleteRequested || record.view.DeleteRequested), newRevision, formatTimestamp(now), reason, runID, record.view.Revision)
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
	return record.view, nil
}

func (store *Store) Sweep(ctx context.Context) (int, error) {
	now := store.now().UTC()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, ErrStoreUnavailable
	}
	defer func() { _ = tx.Rollback() }()
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
		if record.view.State.active() && record.view.DeadlineAt != nil && !record.view.DeadlineAt.After(now) {
			resolved, err := resolvedrun.DecodeResolvedAgentRun(record.snapshot)
			if err != nil {
				return 0, ErrStoreUnavailable
			}
			expires := terminalExpiry(now, StateExpired, resolved)
			deletedAt := (*time.Time)(nil)
			if record.view.DeleteRequested {
				deletedAt = &now
			}
			result, err := tx.ExecContext(ctx, `UPDATE local_runs SET state='expired',revision=revision+1,updated_at=?,terminal_expires_at=?,deleted_at=?,
reconcile_owner=NULL,reconcile_until=NULL,last_reason='active-deadline-exceeded' WHERE run_id=? AND revision=?`,
				formatTimestamp(now), formatOptionalTimestamp(expires), formatOptionalTimestamp(deletedAt), record.view.RunID, record.view.Revision)
			if err != nil || rowsAffected(result) != 1 {
				return 0, ErrStoreUnavailable
			}
			changed++
			continue
		}
		if record.view.State.terminal() && record.view.TerminalExpiresAt != nil && !record.view.TerminalExpiresAt.After(now) {
			result, err := tx.ExecContext(ctx, `UPDATE local_runs SET deleted_at=?,delete_requested=1,revision=revision+1,updated_at=?,last_reason='retention-expired' WHERE run_id=? AND revision=?`,
				formatTimestamp(now), formatTimestamp(now), record.view.RunID, record.view.Revision)
			if err != nil || rowsAffected(result) != 1 {
				return 0, ErrStoreUnavailable
			}
			changed++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, ErrStoreUnavailable
	}
	return changed, nil
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
