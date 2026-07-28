package guestidentity

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

type Runtime struct {
	Store    *Store
	Client   *Client
	Now      func() time.Time
	Generate func() (string, error)
}

func NewRuntime(store *Store, client *Client) (*Runtime, error) {
	if store == nil || client == nil {
		return nil, failure(ReasonStateInvalid, false, false)
	}
	return &Runtime{Store: store, Client: client, Now: time.Now, Generate: guestenrollment.GenerateRuntimeIdentity}, nil
}

// AcceptEnvelope is the small provider-neutral bootstrap boundary used by a
// trusted guest initializer. It commits the one-time envelope to root-only
// state and does not acknowledge acceptance until exchange and identity-state
// persistence complete. Re-delivery is idempotent only for the same binding
// after a complete enrollment.
func (runtime *Runtime) AcceptEnvelope(ctx context.Context, envelope guestenrollment.BootstrapEnvelope) error {
	state, exists, err := runtime.Store.load()
	if err != nil {
		return err
	}
	if exists {
		if state.FailureReason == "" && state.Binding == envelope.Binding && state.RuntimeIdentity != nil {
			envelope.Token = ""
			return nil
		}
		envelope.Token = ""
		return failure(ReasonReplacementRequired, false, false)
	}
	if err := runtime.Store.saveEnvelope(envelope); err != nil {
		envelope.Token = ""
		return err
	}
	envelope.Token = ""
	return runtime.Initialize(ctx)
}

// Initialize consumes the protected one-time envelope only when no durable
// state exists. A transport or malformed-success ambiguity is terminal because
// an exchange response cannot be reconstructed from the issuer's digest.
func (runtime *Runtime) Initialize(ctx context.Context) error {
	if _, exists, err := runtime.Store.load(); err != nil || exists {
		return err
	}
	envelope, err := runtime.Store.loadEnvelope()
	if err != nil {
		return err
	}
	brokerURL, brokerErr := brokerURLFromExchange(envelope.ExchangeURL)
	if brokerErr != nil {
		envelope.Token = ""
		return runtime.failEnrollment(envelope.Binding, "", ReasonReplacementRequired)
	}
	expiresAt, parseErr := time.Parse(time.RFC3339, envelope.ExpiresAt)
	if parseErr != nil || !runtime.now().Before(expiresAt) {
		envelope.Token = ""
		return runtime.failEnrollment(envelope.Binding, brokerURL, ReasonReplacementRequired)
	}
	result, exchangeErr := runtime.Client.Exchange(ctx, envelope)
	envelope.Token = ""
	if exchangeErr != nil {
		reason, temporary, uncertain := FailureDetails(exchangeErr)
		if temporary && !uncertain {
			return exchangeErr
		}
		if reason == ReasonBrokerUnavailable || uncertain || reason == ReasonProtocolInvalid || reason == ReasonReplacementRequired {
			return runtime.failEnrollment(envelope.Binding, brokerURL, ReasonReplacementRequired)
		}
		return exchangeErr
	}
	identity := result.RuntimeIdentity
	state := durableState{
		ContractVersion: StateVersion, Binding: result.Binding, BrokerURL: brokerURL, RuntimeIdentity: &identity,
	}
	if err := runtime.Store.save(state); err != nil {
		identity.Opaque = ""
		_ = runtime.Store.removeEnvelope()
		return failure(ReasonReplacementRequired, false, false)
	}
	identity.Opaque = ""
	if err := runtime.Store.removeEnvelope(); err != nil {
		return err
	}
	return nil
}

func (runtime *Runtime) failEnrollment(binding guestenrollment.Binding, brokerURL string, reason Reason) error {
	stateErr := runtime.Store.saveFailure(binding, brokerURL)
	removeErr := runtime.Store.removeEnvelope()
	if stateErr != nil {
		return stateErr
	}
	if removeErr != nil {
		return removeErr
	}
	return failure(reason, false, false)
}

// Reconcile authenticates the current state, resolves any ambiguous rotation,
// and performs at most one due rotation. It returns only non-secret metadata.
func (runtime *Runtime) Reconcile(ctx context.Context) (Snapshot, time.Duration, error) {
	state, exists, err := runtime.Store.load()
	if err != nil {
		return Snapshot{Reason: ReasonStateInvalid}, retryInterval, err
	}
	if !exists {
		if err := runtime.Initialize(ctx); err != nil {
			reason, temporary, _ := FailureDetails(err)
			return Snapshot{Reason: reason}, retryFor(temporary), err
		}
		state, _, err = runtime.Store.load()
		if err != nil {
			return Snapshot{Reason: ReasonStateInvalid}, retryInterval, err
		}
	}
	if state.FailureReason != "" {
		return Snapshot{Reason: state.FailureReason, Binding: state.Binding}, retryInterval,
			failure(state.FailureReason, false, false)
	}
	if state.PendingSuccessor != "" {
		if err := runtime.resolvePending(ctx, &state); err != nil {
			reason, temporary, _ := FailureDetails(err)
			return snapshotFor(state, runtime.now(), reason), retryFor(temporary), err
		}
	}
	status, err := runtime.Client.Status(ctx, state.BrokerURL, state.RuntimeIdentity.Opaque, state.Binding)
	if err != nil {
		return runtime.statusFailure(&state, err)
	}
	previous := *state.RuntimeIdentity
	if err := applyStatus(&state, state.RuntimeIdentity.Opaque, status); err != nil {
		return Snapshot{Reason: ReasonProtocolInvalid, Binding: state.Binding}, retryInterval, err
	}
	if *state.RuntimeIdentity != previous {
		if err := runtime.Store.save(state); err != nil {
			return Snapshot{Reason: ReasonStateUnavailable, Binding: state.Binding}, retryInterval, err
		}
	}
	now := runtime.now()
	due, scheduleErr := rotationDue(state, now)
	if scheduleErr != nil {
		return runtime.markReplacement(&state)
	}
	if !now.Before(due) {
		if runtime.Generate == nil {
			return Snapshot{Reason: ReasonStateUnavailable, Binding: state.Binding}, retryInterval,
				failure(ReasonStateUnavailable, true, false)
		}
		successor, generateErr := runtime.Generate()
		if generateErr != nil || !validRuntimeIdentity(successor) {
			return Snapshot{Reason: ReasonStateUnavailable, Binding: state.Binding}, retryInterval,
				failure(ReasonStateUnavailable, true, false)
		}
		state.PendingSuccessor = successor
		if err := runtime.Store.save(state); err != nil {
			state.PendingSuccessor = ""
			return Snapshot{Reason: ReasonStateUnavailable, Binding: state.Binding}, retryInterval, err
		}
		if err := runtime.resolvePending(ctx, &state); err != nil {
			reason, temporary, _ := FailureDetails(err)
			return snapshotFor(state, now, reason), retryFor(temporary), err
		}
		due, scheduleErr = rotationDue(state, runtime.now())
		if scheduleErr != nil {
			return runtime.markReplacement(&state)
		}
	}
	wait := statusPollInterval
	if until := due.Sub(runtime.now()); until > 0 && until < wait {
		wait = until
	}
	if wait <= 0 {
		wait = time.Second
	}
	return snapshotFor(state, runtime.now(), ""), wait, nil
}

func (runtime *Runtime) resolvePending(ctx context.Context, state *durableState) error {
	successor := state.PendingSuccessor
	status, err := runtime.Client.Status(ctx, state.BrokerURL, successor, state.Binding)
	if err == nil {
		return runtime.commitSuccessor(state, successor, status)
	}
	reason, temporary, _ := FailureDetails(err)
	if temporary {
		return err
	}
	if reason != ReasonReplacementRequired {
		return err
	}
	predecessor := state.RuntimeIdentity.Opaque
	if _, err := runtime.Client.Status(ctx, state.BrokerURL, predecessor, state.Binding); err != nil {
		predecessorReason, predecessorTemporary, _ := FailureDetails(err)
		if predecessorTemporary {
			return err
		}
		if predecessorReason == ReasonReplacementRequired {
			_, _, marked := runtime.markReplacement(state)
			return marked
		}
		return err
	}
	status, err = runtime.Client.Rotate(ctx, state.BrokerURL, predecessor, successor, state.Binding)
	if err != nil {
		// The pending candidate remains durable for successor-first recovery.
		rotateReason, _, uncertain := FailureDetails(err)
		if !uncertain && (rotateReason == ReasonReplacementRequired || rotateReason == ReasonProtocolInvalid) {
			_, _, marked := runtime.markReplacement(state)
			return marked
		}
		return err
	}
	return runtime.commitSuccessor(state, successor, status)
}

func (runtime *Runtime) commitSuccessor(state *durableState, successor string, status guestenrollment.RuntimeIdentityStatus) error {
	if err := applyStatus(state, successor, status); err != nil {
		return err
	}
	state.PendingSuccessor = ""
	return runtime.Store.save(*state)
}

func (runtime *Runtime) statusFailure(state *durableState, err error) (Snapshot, time.Duration, error) {
	reason, temporary, _ := FailureDetails(err)
	if temporary {
		return snapshotFor(*state, runtime.now(), reason), retryInterval, err
	}
	if reason == ReasonReplacementRequired {
		return runtime.markReplacement(state)
	}
	return snapshotFor(*state, runtime.now(), reason), retryInterval, err
}

func (runtime *Runtime) markReplacement(state *durableState) (Snapshot, time.Duration, error) {
	binding, brokerURL := state.Binding, state.BrokerURL
	if err := runtime.Store.saveFailure(binding, brokerURL); err != nil {
		return Snapshot{Reason: ReasonStateUnavailable, Binding: binding}, retryInterval, err
	}
	state.RuntimeIdentity = nil
	state.PendingSuccessor = ""
	state.FailureReason = ReasonReplacementRequired
	return Snapshot{Reason: ReasonReplacementRequired, Binding: binding}, retryInterval,
		failure(ReasonReplacementRequired, false, false)
}

func applyStatus(state *durableState, identity string, status guestenrollment.RuntimeIdentityStatus) error {
	if guestenrollment.ValidateRuntimeIdentityStatus(status) != nil || status.Binding != state.Binding || !validRuntimeIdentity(identity) {
		return failure(ReasonProtocolInvalid, false, false)
	}
	state.RuntimeIdentity = &guestenrollment.RuntimeIdentity{
		Type: guestenrollment.RuntimeIdentityType, Opaque: identity, IssuedAt: status.IssuedAt, ExpiresAt: status.ExpiresAt,
	}
	return nil
}

func rotationDue(state durableState, now time.Time) (time.Time, error) {
	if state.RuntimeIdentity == nil {
		return time.Time{}, errors.New("runtime identity is unavailable")
	}
	issued, err := time.Parse(time.RFC3339, state.RuntimeIdentity.IssuedAt)
	if err != nil {
		return time.Time{}, err
	}
	expires, err := time.Parse(time.RFC3339, state.RuntimeIdentity.ExpiresAt)
	if err != nil || !issued.Before(expires) {
		return time.Time{}, errors.New("runtime identity window is invalid")
	}
	earliest := issued.Add(minimumRotationInterval)
	latest := expires.Add(-rotationRecoveryWindow)
	if latest.Before(earliest) {
		return time.Time{}, errors.New("runtime identity window cannot be rotated safely")
	}
	due := earliest.Add(rotationJitter(state.Binding, state.RuntimeIdentity.Opaque))
	if due.After(latest) {
		due = latest
	}
	if !now.Before(expires) {
		return time.Time{}, errors.New("runtime identity expired")
	}
	return due, nil
}

func rotationJitter(binding guestenrollment.Binding, identity string) time.Duration {
	if maximumRotationJitter <= 0 {
		return 0
	}
	value := binding.AgentRunUID + "\x00" + binding.ExecutionID + "\x00" + binding.DriverRegistration + "\x00" +
		binding.GuestInstanceID + "\x00" + identity
	digest := sha256.Sum256([]byte(value))
	return time.Duration(binary.BigEndian.Uint64(digest[:8]) % uint64(maximumRotationJitter))
}

func snapshotFor(state durableState, now time.Time, reason Reason) Snapshot {
	result := Snapshot{Reason: reason, Binding: state.Binding}
	if state.RuntimeIdentity == nil {
		return result
	}
	result.IssuedAt, result.ExpiresAt = state.RuntimeIdentity.IssuedAt, state.RuntimeIdentity.ExpiresAt
	if due, err := rotationDue(state, now); err == nil {
		result.Ready = reason == ""
		result.NextRotationAt = guestenrollment.FormatTimestamp(due)
	}
	return result
}

func retryFor(temporary bool) time.Duration {
	if temporary {
		return retryInterval
	}
	return retryInterval
}

func (runtime *Runtime) now() time.Time {
	if runtime.Now == nil {
		return time.Now().UTC().Truncate(time.Second)
	}
	return runtime.Now().UTC().Truncate(time.Second)
}

func WriteReadiness(runtimeDirectory string, ready bool) error {
	if !validAbsoluteDirectory(runtimeDirectory) {
		return failure(ReasonStateInvalid, false, false)
	}
	path := filepath.Join(runtimeDirectory, ReadinessFileName)
	if !ready {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return failure(ReasonStateUnavailable, false, false)
		}
		return nil
	}
	store := &Store{directory: runtimeDirectory, statePath: path, ownerUID: uint32(os.Geteuid())}
	if err := ensurePrivateDirectory(runtimeDirectory, store.ownerUID); err != nil {
		return failure(ReasonStateUnavailable, false, false)
	}
	if err := store.atomicWrite(path, []byte("ready\n"), 0o600); err != nil {
		return failure(ReasonStateUnavailable, false, false)
	}
	return nil
}
