package nativeegress

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	protocol "github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

var (
	credentialRenewalAge          = 3 * time.Minute
	credentialRecoveryWindow      = time.Minute
	credentialRenewalJitter       = 30 * time.Second
	reconnectDelay                = time.Second
	renewalRetryDelay             = 5 * time.Second
	replacementPreparationTimeout = 20 * time.Second
)

type Runtime struct {
	Configuration    Configuration
	Identity         CredentialIssuer
	Connector        Connector
	Now              func() time.Time
	MonotonicNow     func() time.Time
	readinessChanged func(bool)
}

type CredentialIssuer interface {
	Issue(context.Context) (guestenrollment.NativeEgressIssueResult, error)
}

type credential struct {
	Binding        guestenrollment.Binding
	Opaque         string
	Sequence       uint64
	IssuedAt       time.Time
	ExpiresAt      time.Time
	RenewAt        time.Time
	LocalExpiresAt time.Time
	LocalRenewAt   time.Time
}

type credentialState struct {
	current              *credential
	pending              *credential
	renewalUncertain     bool
	nextRenewalAttemptAt time.Time
}

type relaySession struct {
	connection net.Conn
	done       chan error
	closeOnce  sync.Once
}

type preparation struct {
	cancel context.CancelFunc
	done   chan preparationResult
}

type preparationResult struct {
	session     *relaySession
	issued      *credential
	err         error
	issueFailed bool
}

func (credential) String() string   { return "[sensitive native egress credential]" }
func (credential) GoString() string { return "[sensitive native egress credential]" }

func (state *credentialState) clear() {
	if state == nil {
		return
	}
	if state.current != nil {
		state.current.Opaque = ""
	}
	if state.pending != nil {
		state.pending.Opaque = ""
	}
	*state = credentialState{}
}

func (result *preparationResult) discard() {
	if result == nil {
		return
	}
	if result.session != nil {
		result.session.Close()
		result.session = nil
	}
	if result.issued != nil {
		result.issued.Opaque = ""
		result.issued = nil
	}
}

func NewRuntime(configuration Configuration, identity CredentialIssuer, connector Connector) (*Runtime, error) {
	if validateConfiguration(configuration) != nil || identity == nil || connector == nil {
		return nil, fail(ReasonConfiguration, false, false)
	}
	return &Runtime{
		Configuration: configuration,
		Identity:      identity,
		Connector:     connector,
		Now:           time.Now,
		MonotonicNow:  time.Now,
	}, nil
}

func (runtime *Runtime) Run(ctx context.Context) error {
	if runtime == nil || ctx == nil || ensureRuntimeDirectory(runtime.Configuration.RuntimeDirectory) != nil {
		return fail(ReasonConfiguration, false, false)
	}
	_ = runtime.writeReadiness(false)
	defer runtime.writeReadiness(false)
	state := &credentialState{}
	defer state.clear()
	for {
		if ctx.Err() != nil {
			return nil
		}
		if state.current == nil {
			issued, err := runtime.issueCredential(ctx)
			if err != nil {
				_, temporary, _ := FailureDetails(err)
				if !temporary {
					return err
				}
				if waitContext(ctx, reconnectDelay) != nil {
					return nil
				}
				continue
			}
			state.current = &issued
		}
		if !runtime.credentialCurrent(*state.current) {
			return fail(ReasonCredentialExpired, false, false)
		}
		session, err := runtime.openSession(ctx, *state.current)
		if err != nil {
			_, temporary, _ := FailureDetails(err)
			if !temporary || !runtime.credentialCurrent(*state.current) {
				return err
			}
			if waitContext(ctx, reconnectDelay) != nil {
				return nil
			}
			continue
		}
		err = runtime.serveSession(ctx, state, session)
		if ctx.Err() != nil {
			return nil
		}
		_, temporary, _ := FailureDetails(err)
		if !temporary || state.current == nil || !runtime.credentialCurrent(*state.current) {
			return err
		}
		if waitContext(ctx, reconnectDelay) != nil {
			return nil
		}
	}
}

func (runtime *Runtime) serveSession(ctx context.Context, state *credentialState, active *relaySession) error {
	if state == nil || state.current == nil || active == nil || !runtime.credentialCurrent(*state.current) {
		if active != nil {
			active.Close()
		}
		return fail(ReasonCredentialExpired, false, false)
	}
	select {
	case err := <-active.done:
		active.Close()
		if err == nil {
			err = fail(ReasonRelayUnavailable, true, false)
		}
		return err
	default:
	}
	if err := runtime.writeReadiness(true); err != nil {
		active.Close()
		return err
	}
	var attempt *preparation
	defer func() {
		_ = runtime.writeReadiness(false)
		active.Close()
		if attempt != nil {
			runtime.cancelPreparation(state, attempt)
		}
	}()
	for {
		if ctx.Err() != nil {
			return nil
		}
		if state.current == nil || !runtime.credentialCurrent(*state.current) {
			return fail(ReasonCredentialExpired, false, false)
		}
		if attempt == nil && runtime.credentialRenewalDue(*state.current) && runtime.renewalAttemptDue(state) {
			attempt = runtime.startPreparation(ctx, state)
		}
		wait := runtime.nextEventDelay(state)
		timer := time.NewTimer(wait)
		var preparationDone <-chan preparationResult
		if attempt != nil {
			preparationDone = attempt.done
		}
		select {
		case <-ctx.Done():
			stopTimer(timer)
			return nil
		case err := <-active.done:
			stopTimer(timer)
			if ctx.Err() != nil {
				return nil
			}
			if err == nil {
				err = fail(ReasonRelayUnavailable, true, false)
			}
			return err
		case result := <-preparationDone:
			stopTimer(timer)
			attempt.cancel()
			attempt = nil
			replacement, switched, err := runtime.completePreparation(state, &result)
			result.discard()
			if err != nil {
				return err
			}
			if !switched {
				continue
			}
			previous := active
			active = replacement
			previous.Close()
		case <-timer.C:
		}
	}
}

func (runtime *Runtime) issueCredential(ctx context.Context) (credential, error) {
	for attempt := 0; attempt < guestenrollment.MaxLiveNativeEgressCredentials; attempt++ {
		result, err := runtime.Identity.Issue(ctx)
		if err != nil {
			_, _, uncertain := FailureDetails(err)
			if uncertain && attempt == 0 {
				continue
			}
			if attempt > 0 {
				return credential{}, fail(ReasonIdentityUnavailable, false, true)
			}
			return credential{}, err
		}
		value, err := runtime.validateCredential(result)
		result.Credential.Opaque = ""
		return value, err
	}
	return credential{}, fail(ReasonIdentityUnavailable, false, true)
}

func (runtime *Runtime) validateCredential(result guestenrollment.NativeEgressIssueResult) (credential, error) {
	if guestenrollment.ValidateNativeEgressIssueResult(result) != nil {
		return credential{}, fail(ReasonProtocolInvalid, false, true)
	}
	sequence, sequenceErr := guestenrollment.NativeEgressCredentialSequence(result.Credential.Opaque)
	issuedAt, issuedErr := time.Parse(time.RFC3339, result.Credential.IssuedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339, result.Credential.ExpiresAt)
	now := runtime.now()
	localNow := runtime.monotonicNow()
	if sequenceErr != nil || issuedErr != nil || expiresErr != nil || !issuedAt.Before(expiresAt) || !now.Before(expiresAt) {
		return credential{}, fail(ReasonCredentialExpired, false, false)
	}
	renewAt := issuedAt.Add(credentialRenewalAge + renewalJitter(result.Binding, sequence))
	latest := expiresAt.Add(-credentialRecoveryWindow)
	if renewAt.After(latest) {
		renewAt = latest
	}
	if !issuedAt.Before(renewAt) || !renewAt.Before(expiresAt) || !now.Before(renewAt) {
		return credential{}, fail(ReasonCredentialExpired, false, false)
	}
	expiresIn := expiresAt.Sub(now)
	if maximum := expiresAt.Sub(issuedAt); expiresIn > maximum {
		expiresIn = maximum
	}
	renewIn := renewAt.Sub(now)
	if maximum := renewAt.Sub(issuedAt); renewIn > maximum {
		renewIn = maximum
	}
	if expiresIn <= 0 || renewIn <= 0 {
		return credential{}, fail(ReasonCredentialExpired, false, false)
	}
	return credential{
		Binding: result.Binding, Opaque: result.Credential.Opaque, Sequence: sequence,
		IssuedAt: issuedAt, ExpiresAt: expiresAt, RenewAt: renewAt,
		LocalExpiresAt: localNow.Add(expiresIn), LocalRenewAt: localNow.Add(renewIn),
	}, nil
}

func (runtime *Runtime) openSession(ctx context.Context, value credential) (*relaySession, error) {
	if !runtime.credentialCurrent(value) {
		return nil, fail(ReasonCredentialExpired, false, false)
	}
	establishContext, cancel := context.WithTimeout(ctx, replacementPreparationTimeout)
	defer cancel()
	connection, err := runtime.Connector.Connect(establishContext, runtime.Configuration.RelayEndpoint)
	if err != nil {
		return nil, err
	}
	if err := protocol.Establish(establishContext, connection, value.Binding, value.Opaque); err != nil {
		value.Opaque = ""
		_ = connection.Close()
		return nil, mapProtocolError(err)
	}
	value.Opaque = ""
	session := &relaySession{connection: connection, done: make(chan error, 1)}
	go session.monitor()
	return session, nil
}

func (runtime *Runtime) startPreparation(ctx context.Context, state *credentialState) *preparation {
	if state.pending != nil && !runtime.credentialCurrent(*state.pending) {
		state.pending.Opaque = ""
		state.pending = nil
	}
	attemptContext, cancel := context.WithTimeout(ctx, replacementPreparationTimeout)
	attempt := &preparation{cancel: cancel, done: make(chan preparationResult, 1)}
	var pending *credential
	if state.pending != nil {
		value := *state.pending
		pending = &value
	}
	go func() {
		result := preparationResult{}
		value := pending
		if value == nil {
			issued, err := runtime.issueCredential(attemptContext)
			if err != nil {
				result.err = err
				result.issueFailed = true
				attempt.done <- result
				return
			}
			value = &issued
			result.issued = &issued
		}
		result.session, result.err = runtime.openSession(attemptContext, *value)
		attempt.done <- result
	}()
	return attempt
}

func (runtime *Runtime) completePreparation(state *credentialState, result *preparationResult) (*relaySession, bool, error) {
	if state == nil || result == nil {
		return nil, false, fail(ReasonProtocolInvalid, false, false)
	}
	if result.issued != nil && state.pending == nil {
		state.pending = result.issued
		result.issued = nil
	}
	if result.err == nil && result.session != nil {
		select {
		case sessionErr := <-result.session.done:
			result.session.Close()
			result.session = nil
			if sessionErr == nil {
				sessionErr = fail(ReasonRelayUnavailable, true, false)
			}
			result.err = sessionErr
		default:
		}
	}
	if result.issueFailed {
		_, temporary, uncertain := FailureDetails(result.err)
		if uncertain {
			state.renewalUncertain = true
			return nil, false, nil
		}
		if temporary {
			state.nextRenewalAttemptAt = runtime.monotonicNow().Add(renewalRetryDelay)
			return nil, false, nil
		}
		return nil, false, result.err
	}
	if result.err != nil {
		_, temporary, _ := FailureDetails(result.err)
		if temporary {
			state.nextRenewalAttemptAt = runtime.monotonicNow().Add(renewalRetryDelay)
			return nil, false, nil
		}
		return nil, false, result.err
	}
	if result.session == nil || state.pending == nil {
		return nil, false, fail(ReasonProtocolInvalid, false, false)
	}
	replacement := result.session
	result.session = nil
	previous := state.current
	state.current = state.pending
	state.pending = nil
	state.nextRenewalAttemptAt = time.Time{}
	state.renewalUncertain = false
	if previous != nil {
		previous.Opaque = ""
	}
	return replacement, true, nil
}

func (runtime *Runtime) cancelPreparation(state *credentialState, attempt *preparation) {
	if attempt == nil {
		return
	}
	attempt.cancel()
	result := <-attempt.done
	if result.issued != nil && state != nil && state.pending == nil {
		state.pending = result.issued
		result.issued = nil
	}
	if result.issueFailed {
		_, _, uncertain := FailureDetails(result.err)
		if uncertain && state != nil {
			state.renewalUncertain = true
		}
	}
	result.discard()
}

func (runtime *Runtime) renewalAttemptDue(state *credentialState) bool {
	return state != nil && !state.renewalUncertain &&
		(state.nextRenewalAttemptAt.IsZero() || !runtime.monotonicNow().Before(state.nextRenewalAttemptAt))
}

func (runtime *Runtime) nextEventDelay(state *credentialState) time.Duration {
	wait := time.Second
	if state == nil || state.current == nil {
		return wait
	}
	wallExpiry := state.current.ExpiresAt.Sub(runtime.now())
	localExpiry := state.current.LocalExpiresAt.Sub(runtime.monotonicNow())
	if wallExpiry < wait {
		wait = wallExpiry
	}
	if localExpiry < wait {
		wait = localExpiry
	}
	if !runtime.credentialRenewalDue(*state.current) {
		if renewal := runtime.untilRenewal(*state.current); renewal < wait {
			wait = renewal
		}
	}
	if !state.nextRenewalAttemptAt.IsZero() {
		if retry := state.nextRenewalAttemptAt.Sub(runtime.monotonicNow()); retry < wait {
			wait = retry
		}
	}
	if wait <= 0 {
		return time.Millisecond
	}
	return wait
}

func (runtime *Runtime) credentialCurrent(value credential) bool {
	return runtime.now().Before(value.ExpiresAt) && runtime.monotonicNow().Before(value.LocalExpiresAt)
}

func (runtime *Runtime) credentialRenewalDue(value credential) bool {
	return !runtime.now().Before(value.RenewAt) || !runtime.monotonicNow().Before(value.LocalRenewAt)
}

func (runtime *Runtime) untilRenewal(value credential) time.Duration {
	wall := value.RenewAt.Sub(runtime.now())
	local := value.LocalRenewAt.Sub(runtime.monotonicNow())
	if local < wall {
		return local
	}
	return wall
}

func (runtime *Runtime) now() time.Time {
	if runtime.Now == nil {
		return time.Now().UTC().Truncate(time.Second)
	}
	return runtime.Now().UTC().Truncate(time.Second)
}

func (runtime *Runtime) monotonicNow() time.Time {
	if runtime.MonotonicNow == nil {
		return time.Now()
	}
	return runtime.MonotonicNow()
}

func renewalJitter(binding guestenrollment.Binding, sequence uint64) time.Duration {
	if credentialRenewalJitter <= 0 {
		return 0
	}
	value := binding.AgentRunUID + "\x00" + binding.ExecutionID + "\x00" + binding.DriverRegistration + "\x00" +
		binding.GuestInstanceID
	digest := sha256.Sum256([]byte(value))
	mixed := binary.BigEndian.Uint64(digest[:8]) ^ sequence
	return time.Duration(mixed % uint64(credentialRenewalJitter))
}

func (session *relaySession) monitor() {
	buffer := make([]byte, 1)
	count, err := session.connection.Read(buffer)
	zero(buffer)
	if count > 0 {
		session.done <- fail(ReasonProtocolInvalid, false, false)
		return
	}
	_ = err
	session.done <- fail(ReasonRelayUnavailable, true, false)
}

func (session *relaySession) Close() {
	if session == nil || session.connection == nil {
		return
	}
	session.closeOnce.Do(func() {
		closed := make(chan struct{})
		go func() {
			_ = session.connection.SetDeadline(time.Now())
			_ = session.connection.Close()
			close(closed)
		}()
		select {
		case <-closed:
		case <-time.After(protocol.ShutdownTimeout):
		}
	})
}

func mapProtocolError(err error) error {
	switch {
	case errors.Is(err, protocol.ErrDenied):
		return fail(ReasonRelayDenied, false, false)
	case errors.Is(err, protocol.ErrProtocol):
		return fail(ReasonProtocolInvalid, false, false)
	default:
		return fail(ReasonRelayUnavailable, true, false)
	}
}

func (runtime *Runtime) writeReadiness(ready bool) error {
	path := filepath.Join(runtime.Configuration.RuntimeDirectory, ReadinessFileName)
	if !ready {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fail(ReasonConfiguration, false, false)
		}
		if runtime.readinessChanged != nil {
			runtime.readinessChanged(false)
		}
		return nil
	}
	temporary, err := os.CreateTemp(runtime.Configuration.RuntimeDirectory, ".egress-ready-*.tmp")
	if err != nil {
		return fail(ReasonConfiguration, false, false)
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fail(ReasonConfiguration, false, false)
	}
	if _, err := temporary.Write([]byte("ready\n")); err != nil || temporary.Sync() != nil || temporary.Close() != nil || os.Rename(name, path) != nil {
		return fail(ReasonConfiguration, false, false)
	}
	directory, err := os.Open(runtime.Configuration.RuntimeDirectory)
	if err != nil {
		return fail(ReasonConfiguration, false, false)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fail(ReasonConfiguration, false, false)
	}
	if runtime.readinessChanged != nil {
		runtime.readinessChanged(true)
	}
	return nil
}

func stopTimer(timer *time.Timer) {
	if timer != nil && !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func waitContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
