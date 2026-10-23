package controller

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
)

// Restart intent is durable and independent of configuration intent. Only the
// controller advances quiescing -> preparing -> complete/failed. Retaining the
// last request ID makes a lost response retry safe even after completion.
func restartActive(run Run) bool {
	return run.RestartPhase == "quiescing" || run.RestartPhase == "preparing"
}

func validRestartID(id string) bool {
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == id
}

func validRestartState(run Run) bool {
	if run.RestartID == "" {
		return run.RestartPhase == ""
	}
	if !validRestartID(run.RestartID) {
		return false
	}
	switch run.RestartPhase {
	case "quiescing":
		return run.State == StateStopping && !run.DeleteRequested
	case "preparing":
		return run.State == StatePreparing && !run.DeleteRequested
	case "complete", "failed":
		return true
	}
	return false
}

func (store *Store) RestartWorkstation(ctx context.Context, name, requestID string) (Run, error) {
	if !validRunID(name) || !validRestartID(requestID) {
		return Run{}, ErrInvalidRequest
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Run{}, ErrStoreUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	record, err := scanStoredRun(tx.QueryRowContext(ctx, selectRuns+` WHERE run_id=?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	if err != nil || validateStoredRun(&record) != nil {
		return Run{}, ErrStoreUnavailable
	}
	if record.deletedAt != nil {
		return Run{}, ErrGone
	}
	if len(record.pendingSnapshot) != 0 {
		return Run{}, ErrRestartConflict
	}
	if record.view.DeleteRequested {
		return Run{}, ErrGone
	}
	if !administratorWorkstation(record) {
		return Run{}, ErrNotWorkstation
	}
	// Concurrent requests join one operation, rather than scheduling successive
	// restarts. The response identifies the operation the caller must wait for.
	if restartActive(record.view) || record.view.RestartID == requestID {
		return record.view, nil
	}
	now := store.now().UTC()
	if record.view.State != StateRunning && record.view.State != StateFailed && record.view.State != StateCompleted ||
		record.view.ReconcileUntil != nil && record.view.ReconcileUntil.After(now) {
		return Run{}, ErrRestartConflict
	}
	if record.view.State.terminal() {
		var active int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM local_runs WHERE deleted_at IS NULL AND state IN ('pending','preparing','running','stopping')`).Scan(&active); err != nil {
			return Run{}, ErrStoreUnavailable
		}
		if active >= store.maxActiveRuns {
			return Run{}, ErrCapacityExceeded
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE local_runs SET restart_id=?,restart_phase='quiescing',state='stopping',terminal_target='failed',terminal_expires_at=NULL,reconcile_owner=NULL,reconcile_until=NULL,revision=revision+1,updated_at=?,last_reason='restart-requested' WHERE run_id=? AND revision=?`, requestID, formatTimestamp(now), name, record.view.Revision)
	if err != nil || rowsAffected(result) != 1 {
		return Run{}, ErrOwnershipConflict
	}
	if err := tx.Commit(); err != nil {
		return Run{}, ErrStoreUnavailable
	}
	run := record.view
	run.RestartID, run.RestartPhase = requestID, "quiescing"
	run.State, run.TerminalTarget, run.LastReason = StateStopping, StateFailed, "restart-requested"
	run.ReconcileOwner, run.ReconcileUntil, run.TerminalExpiresAt = "", nil, nil
	run.Revision++
	run.UpdatedAt = now
	return run, nil
}

// finishRestartQuiesce commits the fresh event-log boundary before any runtime
// can be started. On uncertainty the quiesce operation can be safely repeated.
func (store *Store) finishRestartQuiesce(ctx context.Context, claimed Run, owner, cursor string, failed bool) error {
	if !validLifecycleCursor(cursor) {
		return ErrInvalidRequest
	}
	state, phase, reason := StatePreparing, "preparing", "restart-preparing"
	if failed {
		state, phase, reason = StateFailed, "failed", "restart-backend-rejected"
	}
	now := store.now().UTC()
	result, err := store.db.ExecContext(ctx, `UPDATE local_runs SET state=?,restart_phase=?,last_reason=?,terminal_target='',lifecycle_cursor=?,revision=revision+1,updated_at=?,reconcile_owner=NULL,reconcile_until=NULL WHERE run_id=? AND revision=? AND restart_id=? AND restart_phase='quiescing' AND reconcile_owner=? AND reconcile_until>?`, state, phase, reason, cursor, formatTimestamp(now), claimed.RunID, claimed.Revision, claimed.RestartID, owner, formatTimestamp(now))
	if err != nil || rowsAffected(result) != 1 {
		return ErrOwnershipConflict
	}
	return nil
}

func (store *Store) failRestartPreparation(ctx context.Context, claimed Run, owner string) error {
	now := store.now().UTC()
	result, err := store.db.ExecContext(ctx, `UPDATE local_runs SET state='failed',restart_phase='failed',last_reason='restart-backend-rejected',terminal_target='',revision=revision+1,updated_at=?,reconcile_owner=NULL,reconcile_until=NULL WHERE run_id=? AND revision=? AND restart_phase='preparing' AND reconcile_owner=? AND reconcile_until>?`, formatTimestamp(now), claimed.RunID, claimed.Revision, owner, formatTimestamp(now))
	if err != nil || rowsAffected(result) != 1 {
		return ErrOwnershipConflict
	}
	return nil
}
