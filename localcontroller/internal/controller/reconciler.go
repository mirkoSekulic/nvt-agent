package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

// NewProcessReconcileOwner derives an opaque per-process lease identity from
// the stable resource owner. Resource labels remain stable across restarts,
// while two live controller processes can never intentionally share a claim.
func NewProcessReconcileOwner(resourceOwner string) (string, error) {
	if !validOwner(resourceOwner) || len(resourceOwner) > 63 {
		return "", ErrInvalidRequest
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return "", ErrStoreUnavailable
	}
	owner := resourceOwner + "-" + hex.EncodeToString(random)
	if !validOwner(owner) {
		return "", ErrInvalidRequest
	}
	return owner, nil
}

// BackendRun is the immutable desired value handed to one trusted local
// execution backend. SnapshotDigest binds every owned backend resource to the
// durable controller record.
type BackendRun struct {
	Resolved        resolvedrun.ResolvedAgentRun
	SnapshotDigest  string
	DeleteRequested bool
	LifecycleCursor string
}

// BackendObservation contains only the portable state needed by the lifecycle
// reconciler. Backend object IDs, credentials and raw diagnostics never cross
// this boundary.
type BackendObservation struct {
	Ready           bool
	TerminalTarget  State
	LifecycleCursor string
}

// These sentinels classify a backend operation without exposing backend or
// provider diagnostics. Unknown errors are treated as dependency uncertainty;
// only ErrBackendDesiredRunInvalid may permanently fail a preparing run.
var (
	ErrBackendRetryable         = errors.New("local backend temporarily unavailable")
	ErrBackendDesiredRunInvalid = errors.New("local backend rejected desired run")
)

// LocalBackend is deliberately smaller than Docker. Later QEMU or sandbox
// implementations need only idempotent ensure, inspect and cleanup behavior.
type LocalBackend interface {
	Ready(context.Context) bool
	Ensure(context.Context, BackendRun) (BackendObservation, error)
	Inspect(context.Context, BackendRun) (BackendObservation, error)
	Delete(context.Context, BackendRun) error
}

type Reconciler struct {
	store   *Store
	backend LocalBackend
	owner   string
	lease   time.Duration
	logger  *log.Logger
}

func NewReconciler(store *Store, backend LocalBackend, owner string, lease time.Duration, logger *log.Logger) (*Reconciler, error) {
	if store == nil || backend == nil || !validOwner(owner) || lease < time.Second || lease > store.maxClaimLease {
		return nil, ErrInvalidRequest
	}
	if logger == nil {
		logger = log.New(log.Writer(), "", 0)
	}
	return &Reconciler{store: store, backend: backend, owner: owner, lease: lease, logger: logger}, nil
}

func (reconciler *Reconciler) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	recovered := false
	for {
		var err error
		if recovered {
			err = reconciler.Reconcile(ctx)
		} else {
			recoveryErr := reconciler.Recover(ctx)
			recovered = recoveryErr == nil
			err = errors.Join(recoveryErr, reconciler.Reconcile(ctx))
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			reason := "backend-unavailable"
			if !recovered {
				reason = "recovery-unavailable"
			}
			reconciler.logger.Printf("reconcile warning reason=%s", reason)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Recover moves every previously running record back through idempotent
// preparation exactly once per controller process. The backend then reconciles
// the durable snapshot against exact-owned resources, recreating missing
// containers while retaining named data volumes. Other lifecycle states are
// already restart-safe and remain untouched.
func (reconciler *Reconciler) Recover(ctx context.Context) error {
	after := ""
	pendingLease := false
	for {
		page, err := reconciler.store.List(ctx, MaxListLimit, after)
		if err != nil {
			return err
		}
		for _, run := range page.Runs {
			if run.State != StateRunning {
				continue
			}
			claimed, err := reconciler.claim(ctx, run)
			if errors.Is(err, ErrOwnershipConflict) {
				pendingLease = true
				continue
			}
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if _, err := reconciler.store.UpdateStatus(ctx, StatusInput{
				RunID: run.RunID, Owner: reconciler.owner, ExpectedRevision: claimed.Revision,
				State: StatePreparing, Reason: "backend-recovery-requested",
			}); err != nil {
				if errors.Is(err, ErrOwnershipConflict) {
					pendingLease = true
					continue
				}
				if !errors.Is(err, ErrNotFound) {
					return err
				}
			} else {
				reconciler.logger.Printf("reconcile event=recovery-requested run_id=%s", run.RunID)
			}
		}
		if page.NextAfter == "" {
			if pendingLease {
				return ErrOwnershipConflict
			}
			return nil
		}
		after = page.NextAfter
	}
}

func (reconciler *Reconciler) Reconcile(ctx context.Context) error {
	after := ""
	for {
		page, err := reconciler.store.List(ctx, MaxListLimit, after)
		if err != nil {
			return err
		}
		for _, run := range page.Runs {
			if run.State.terminal() {
				continue
			}
			if err := reconciler.reconcileRun(ctx, run); err != nil && !errors.Is(err, ErrOwnershipConflict) && !errors.Is(err, ErrNotFound) {
				reconciler.logger.Printf("reconcile warning reason=run-unavailable run_id=%s", run.RunID)
			}
		}
		if page.NextAfter == "" {
			return nil
		}
		after = page.NextAfter
	}
}

func (reconciler *Reconciler) reconcileRun(ctx context.Context, run Run) error {
	backendRun, err := reconciler.backendRun(ctx, run)
	if err != nil {
		return err
	}
	switch run.State {
	case StatePending:
		claimed, err := reconciler.claim(ctx, run)
		if err != nil {
			return err
		}
		_, err = reconciler.store.UpdateStatus(ctx, StatusInput{
			RunID: run.RunID, Owner: reconciler.owner, ExpectedRevision: claimed.Revision,
			State: StatePreparing, Reason: "backend-preparing",
		})
		return err
	case StatePreparing:
		claimed, err := reconciler.claim(ctx, run)
		if err != nil {
			return err
		}
		observation, ensureErr := reconciler.backend.Ensure(ctx, backendRun)
		if ensureErr != nil && !errors.Is(ensureErr, ErrBackendDesiredRunInvalid) {
			return ensureErr
		}
		if ensureErr == nil && observation.TerminalTarget != "" {
			if observation.TerminalTarget != StateCompleted && observation.TerminalTarget != StateFailed {
				return ErrBackendRetryable
			}
			_, updateErr := reconciler.store.UpdateStatus(ctx, StatusInput{
				RunID: run.RunID, Owner: reconciler.owner, ExpectedRevision: claimed.Revision,
				State: StateStopping, TerminalTarget: observation.TerminalTarget, Reason: terminalReason(observation.TerminalTarget),
				LifecycleCursor: &observation.LifecycleCursor,
			})
			if updateErr == nil {
				reconciler.logger.Printf("reconcile event=%s run_id=%s", terminalReason(observation.TerminalTarget), run.RunID)
			}
			return updateErr
		}
		if ensureErr == nil && !observation.Ready {
			return ErrBackendRetryable
		}
		if ensureErr != nil {
			_, updateErr := reconciler.store.UpdateStatus(ctx, StatusInput{
				RunID: run.RunID, Owner: reconciler.owner, ExpectedRevision: claimed.Revision,
				State: StateStopping, TerminalTarget: StateFailed, Reason: "backend-prepare-failed",
			})
			return updateErr
		}
		reason := "backend-ready"
		if run.LastReason == "backend-recovery-requested" {
			reason = "backend-recovered"
		}
		_, err = reconciler.store.UpdateStatus(ctx, StatusInput{
			RunID: run.RunID, Owner: reconciler.owner, ExpectedRevision: claimed.Revision,
			State: StateRunning, Reason: reason, LifecycleCursor: &observation.LifecycleCursor,
		})
		if err == nil && reason == "backend-recovered" {
			reconciler.logger.Printf("reconcile event=backend-recovered run_id=%s", run.RunID)
		}
		return err
	case StateRunning:
		observation, inspectErr := reconciler.backend.Inspect(ctx, backendRun)
		if inspectErr != nil {
			return inspectErr
		}
		if observation.Ready && observation.LifecycleCursor == backendRun.LifecycleCursor {
			return nil
		}
		if observation.TerminalTarget != StateCompleted && observation.TerminalTarget != StateFailed {
			if observation.LifecycleCursor != backendRun.LifecycleCursor {
				claimed, err := reconciler.claim(ctx, run)
				if err != nil {
					return err
				}
				_, err = reconciler.store.UpdateStatus(ctx, StatusInput{
					RunID: run.RunID, Owner: reconciler.owner, ExpectedRevision: claimed.Revision,
					State: StateRunning, LifecycleCursor: &observation.LifecycleCursor,
				})
				return err
			}
			return ErrBackendRetryable
		}
		claimed, err := reconciler.claim(ctx, run)
		if err != nil {
			return err
		}
		_, err = reconciler.store.UpdateStatus(ctx, StatusInput{
			RunID: run.RunID, Owner: reconciler.owner, ExpectedRevision: claimed.Revision,
			State: StateStopping, TerminalTarget: observation.TerminalTarget, Reason: terminalReason(observation.TerminalTarget),
			LifecycleCursor: &observation.LifecycleCursor,
		})
		if err == nil {
			reconciler.logger.Printf("reconcile event=%s run_id=%s", terminalReason(observation.TerminalTarget), run.RunID)
		}
		return err
	case StateStopping:
		claimed, err := reconciler.claim(ctx, run)
		if err != nil {
			return err
		}
		if err := reconciler.backend.Delete(ctx, backendRun); err != nil {
			return err
		}
		_, err = reconciler.store.UpdateStatus(ctx, StatusInput{
			RunID: run.RunID, Owner: reconciler.owner, ExpectedRevision: claimed.Revision,
			State: run.TerminalTarget, Reason: "backend-cleanup-complete",
		})
		if err == nil || errors.Is(err, ErrGone) {
			reconciler.logger.Printf("reconcile event=backend-cleanup-complete run_id=%s", run.RunID)
		}
		return err
	default:
		return nil
	}
}

func terminalReason(target State) string {
	if target == StateCompleted {
		return "backend-completed"
	}
	return "backend-runtime-failed"
}

func (reconciler *Reconciler) claim(ctx context.Context, run Run) (Run, error) {
	return reconciler.store.Claim(ctx, ClaimInput{
		RunID: run.RunID, Owner: reconciler.owner, ExpectedRevision: run.Revision, Lease: reconciler.lease,
	})
}

func (reconciler *Reconciler) backendRun(ctx context.Context, run Run) (BackendRun, error) {
	snapshot, digest, cursor, err := reconciler.store.backendSnapshot(ctx, run.RunID)
	if err != nil {
		return BackendRun{}, err
	}
	resolved, err := resolvedrun.DecodeResolvedAgentRun(json.RawMessage(snapshot))
	if err != nil || digest != run.SnapshotDigest {
		return BackendRun{}, ErrStoreUnavailable
	}
	return BackendRun{Resolved: resolved, SnapshotDigest: digest, DeleteRequested: run.DeleteRequested, LifecycleCursor: cursor}, nil
}
