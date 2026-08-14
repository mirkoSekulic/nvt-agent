package controller

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

// BackendRun is the immutable desired value handed to one trusted local
// execution backend. SnapshotDigest binds every owned backend resource to the
// durable controller record.
type BackendRun struct {
	Resolved        resolvedrun.ResolvedAgentRun
	SnapshotDigest  string
	DeleteRequested bool
}

// BackendObservation contains only the portable state needed by the lifecycle
// reconciler. Backend object IDs, credentials and raw diagnostics never cross
// this boundary.
type BackendObservation struct {
	Ready bool
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
	for {
		if err := reconciler.Reconcile(ctx); err != nil && !errors.Is(err, context.Canceled) {
			reconciler.logger.Print("reconcile warning reason=backend-unavailable")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
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
		_, err = reconciler.store.UpdateStatus(ctx, StatusInput{
			RunID: run.RunID, Owner: reconciler.owner, ExpectedRevision: claimed.Revision,
			State: StateRunning, Reason: "backend-ready",
		})
		return err
	case StateRunning:
		observation, inspectErr := reconciler.backend.Inspect(ctx, backendRun)
		if inspectErr != nil {
			return inspectErr
		}
		if observation.Ready {
			return nil
		}
		claimed, err := reconciler.claim(ctx, run)
		if err != nil {
			return err
		}
		_, err = reconciler.store.UpdateStatus(ctx, StatusInput{
			RunID: run.RunID, Owner: reconciler.owner, ExpectedRevision: claimed.Revision,
			State: StateStopping, TerminalTarget: StateFailed, Reason: "backend-runtime-failed",
		})
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
		return err
	default:
		return nil
	}
}

func (reconciler *Reconciler) claim(ctx context.Context, run Run) (Run, error) {
	return reconciler.store.Claim(ctx, ClaimInput{
		RunID: run.RunID, Owner: reconciler.owner, ExpectedRevision: run.Revision, Lease: reconciler.lease,
	})
}

func (reconciler *Reconciler) backendRun(ctx context.Context, run Run) (BackendRun, error) {
	snapshot, digest, err := reconciler.store.ResolvedSnapshot(ctx, run.RunID)
	if err != nil {
		return BackendRun{}, err
	}
	resolved, err := resolvedrun.DecodeResolvedAgentRun(json.RawMessage(snapshot))
	if err != nil || digest != run.SnapshotDigest {
		return BackendRun{}, ErrStoreUnavailable
	}
	return BackendRun{Resolved: resolved, SnapshotDigest: digest, DeleteRequested: run.DeleteRequested}, nil
}
