package nativesession

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

var (
	credentialRenewalAge     = 3 * time.Minute
	credentialRecoveryWindow = time.Minute
	credentialRenewalJitter  = 30 * time.Second
	reconnectDelay           = time.Second
	renewalRetryDelay        = 5 * time.Second
	idleProbeInterval        = 5 * time.Second
)

type Runtime struct {
	Configuration Configuration
	Identity      CredentialIssuer
	Connector     Connector
	Now           func() time.Time
	MonotonicNow  func() time.Time
}

type CredentialIssuer interface {
	Issue(context.Context) (guestenrollment.GuestSessionIssueResult, error)
}

type sessionCredential struct {
	Binding        guestenrollment.Binding
	Opaque         string
	IssuedAt       time.Time
	ExpiresAt      time.Time
	RenewAt        time.Time
	LocalExpiresAt time.Time
	LocalRenewAt   time.Time
}

type credentialState struct {
	current              *sessionCredential
	pending              *sessionCredential
	renewalUncertain     bool
	nextRenewalAttemptAt time.Time
}

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

func (sessionCredential) String() string   { return "[sensitive guest session credential]" }
func (sessionCredential) GoString() string { return "[sensitive guest session credential]" }

func NewRuntime(configuration Configuration, identity CredentialIssuer, connector Connector) (*Runtime, error) {
	if validateConfiguration(configuration) != nil || identity == nil || connector == nil {
		return nil, fail(ReasonConfiguration, false, false)
	}
	return &Runtime{Configuration: configuration, Identity: identity, Connector: connector, Now: time.Now, MonotonicNow: time.Now}, nil
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
				if err := waitContext(ctx, reconnectDelay); err != nil {
					return nil
				}
				continue
			}
			state.current = &issued
		}
		err := runtime.serveCredential(ctx, state)
		if err == nil && ctx.Err() != nil {
			return nil
		}
		_, temporary, _ := FailureDetails(err)
		if !temporary || state.current == nil || !runtime.credentialCurrent(*state.current) {
			return err
		}
		if err := waitContext(ctx, reconnectDelay); err != nil {
			return nil
		}
	}
}

func (runtime *Runtime) issueCredential(ctx context.Context) (sessionCredential, error) {
	for attempt := 0; attempt < 2; attempt++ {
		result, err := runtime.Identity.Issue(ctx)
		if err != nil {
			_, _, uncertain := FailureDetails(err)
			if uncertain && attempt == 0 {
				continue
			}
			if attempt > 0 {
				// Once the first mutation is uncertain, no later failure can
				// prove that another credential was not committed. Stop before
				// the Run loop can issue a third candidate.
				return sessionCredential{}, fail(ReasonIdentityUnavailable, false, true)
			}
			return sessionCredential{}, err
		}
		credential, err := runtime.validateCredential(result)
		result.Credential.Opaque = ""
		return credential, err
	}
	return sessionCredential{}, fail(ReasonIdentityUnavailable, false, true)
}

func (runtime *Runtime) validateCredential(result guestenrollment.GuestSessionIssueResult) (sessionCredential, error) {
	if guestenrollment.ValidateGuestSessionIssueResult(result) != nil {
		return sessionCredential{}, fail(ReasonProtocolInvalid, false, true)
	}
	issuedAt, issuedErr := time.Parse(time.RFC3339, result.Credential.IssuedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339, result.Credential.ExpiresAt)
	now := runtime.now()
	localNow := runtime.monotonicNow()
	if issuedErr != nil || expiresErr != nil || !issuedAt.Before(expiresAt) || !now.Before(expiresAt) {
		return sessionCredential{}, fail(ReasonCredentialExpired, false, false)
	}
	renewAt := issuedAt.Add(credentialRenewalAge + renewalJitter(result.Binding))
	latest := expiresAt.Add(-credentialRecoveryWindow)
	if renewAt.After(latest) {
		renewAt = latest
	}
	if !issuedAt.Before(renewAt) || !renewAt.Before(expiresAt) || !now.Before(renewAt) {
		return sessionCredential{}, fail(ReasonCredentialExpired, false, false)
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
		return sessionCredential{}, fail(ReasonCredentialExpired, false, false)
	}
	return sessionCredential{
		Binding: result.Binding, Opaque: result.Credential.Opaque,
		IssuedAt: issuedAt, ExpiresAt: expiresAt, RenewAt: renewAt,
		LocalExpiresAt: localNow.Add(expiresIn), LocalRenewAt: localNow.Add(renewIn),
	}, nil
}

func (runtime *Runtime) serveCredential(ctx context.Context, state *credentialState) error {
	if state == nil || state.current == nil || !runtime.credentialCurrent(*state.current) {
		return fail(ReasonCredentialExpired, false, false)
	}
	connection, reader, err := runtime.openCredential(ctx, *state.current)
	if err != nil {
		return err
	}
	defer func() { _ = connection.Close() }()
	if err := runtime.writeReadiness(true); err != nil {
		return err
	}
	defer runtime.writeReadiness(false)
	requestIDs := make(map[string]struct{}, guestenrollment.MaxNativeSessionRequestsPerConnection)
	for {
		if ctx.Err() != nil {
			return nil
		}
		if state.current == nil || !runtime.credentialCurrent(*state.current) {
			return fail(ReasonCredentialExpired, false, false)
		}
		if runtime.credentialRenewalDue(*state.current) && runtime.renewalAttemptDue(state) {
			replacement, replacementReader, switched, renewalErr := runtime.prepareReplacement(ctx, state)
			if renewalErr != nil {
				return renewalErr
			}
			if switched {
				previous := connection
				connection, reader = replacement, replacementReader
				requestIDs = make(map[string]struct{}, guestenrollment.MaxNativeSessionRequestsPerConnection)
				_ = previous.Close()
				continue
			}
		}
		deadline := runtime.nextReadDeadline(state)
		frame, readErr := readFrame(reader, connection, deadline)
		if readErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			_, temporary, _ := FailureDetails(readErr)
			if !temporary {
				return readErr
			}
			if state.current == nil || !runtime.credentialCurrent(*state.current) {
				return fail(ReasonCredentialExpired, false, false)
			}
			if runtime.credentialRenewalDue(*state.current) && runtime.renewalAttemptDue(state) {
				continue
			}
			if err := runtime.checkAgentd(); err != nil {
				return err
			}
			if err := writeFrame(connection, guestenrollment.NativeSessionMessage{
				ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionPing,
			}, time.Now().Add(frameTimeout)); err != nil {
				return err
			}
			if err := runtime.awaitPong(reader, connection, requestIDs, time.Now().Add(frameTimeout)); err != nil {
				return err
			}
			continue
		}
		if _, err := runtime.handleFrame(frame, connection, requestIDs); err != nil {
			return err
		}
	}
}

func (runtime *Runtime) openCredential(ctx context.Context, credential sessionCredential) (net.Conn, *bufio.Reader, error) {
	if !runtime.credentialCurrent(credential) {
		return nil, nil, fail(ReasonCredentialExpired, false, false)
	}
	connection, err := runtime.Connector.Connect(ctx, runtime.Configuration.GatewayEndpoint)
	if err != nil {
		return nil, nil, err
	}
	reader := newFrameReader(connection)
	hello := guestenrollment.NativeSessionMessage{
		ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionHello,
		Binding: &credential.Binding, Audience: guestenrollment.NativeGuestControlAudience, Credential: credential.Opaque,
	}
	if err := writeFrame(connection, hello, time.Now().Add(frameTimeout)); err != nil {
		hello.Credential = ""
		_ = connection.Close()
		return nil, nil, err
	}
	hello.Credential = ""
	response, err := readFrame(reader, connection, time.Now().Add(frameTimeout))
	if err != nil {
		_ = connection.Close()
		return nil, nil, err
	}
	if response.Type == guestenrollment.NativeSessionHelloReject {
		_ = connection.Close()
		return nil, nil, fail(ReasonGatewayDenied, false, false)
	}
	if response.Type != guestenrollment.NativeSessionHelloAck || response.Binding == nil ||
		*response.Binding != credential.Binding || response.Audience != guestenrollment.NativeGuestControlAudience {
		_ = connection.Close()
		return nil, nil, fail(ReasonProtocolInvalid, false, false)
	}
	if err := runtime.checkAgentd(); err != nil {
		_ = connection.Close()
		return nil, nil, err
	}
	return connection, reader, nil
}

func (runtime *Runtime) prepareReplacement(ctx context.Context, state *credentialState) (net.Conn, *bufio.Reader, bool, error) {
	if state.renewalUncertain {
		return nil, nil, false, nil
	}
	if state.pending != nil && !runtime.credentialCurrent(*state.pending) {
		state.pending.Opaque = ""
		state.pending = nil
	}
	if state.pending == nil {
		issued, err := runtime.issueCredential(ctx)
		if err != nil {
			_, temporary, uncertain := FailureDetails(err)
			if uncertain {
				state.renewalUncertain = true
				return nil, nil, false, nil
			}
			if temporary {
				state.nextRenewalAttemptAt = runtime.monotonicNow().Add(renewalRetryDelay)
				return nil, nil, false, nil
			}
			return nil, nil, false, err
		}
		state.pending = &issued
	}
	connection, reader, err := runtime.openCredential(ctx, *state.pending)
	if err != nil {
		_, temporary, _ := FailureDetails(err)
		if temporary {
			state.nextRenewalAttemptAt = runtime.monotonicNow().Add(renewalRetryDelay)
			return nil, nil, false, nil
		}
		return nil, nil, false, err
	}
	previous := state.current
	state.current = state.pending
	state.pending = nil
	state.nextRenewalAttemptAt = time.Time{}
	state.renewalUncertain = false
	if previous != nil {
		previous.Opaque = ""
	}
	return connection, reader, true, nil
}

func (runtime *Runtime) renewalAttemptDue(state *credentialState) bool {
	return state != nil && !state.renewalUncertain &&
		(state.nextRenewalAttemptAt.IsZero() || !runtime.monotonicNow().Before(state.nextRenewalAttemptAt))
}

func (runtime *Runtime) nextReadDeadline(state *credentialState) time.Time {
	wait := idleProbeInterval
	if state != nil && state.current != nil {
		if until := runtime.untilRenewal(*state.current); until > 0 && until < wait {
			wait = until
		}
		wallExpiry := state.current.ExpiresAt.Sub(runtime.now())
		localExpiry := state.current.LocalExpiresAt.Sub(runtime.monotonicNow())
		if wallExpiry > 0 && wallExpiry < wait {
			wait = wallExpiry
		}
		if localExpiry > 0 && localExpiry < wait {
			wait = localExpiry
		}
		if !state.nextRenewalAttemptAt.IsZero() {
			if retry := state.nextRenewalAttemptAt.Sub(runtime.monotonicNow()); retry > 0 && retry < wait {
				wait = retry
			}
		}
	}
	if wait <= 0 {
		wait = time.Millisecond
	}
	return time.Now().Add(wait)
}

func (runtime *Runtime) awaitPong(reader *bufio.Reader, connection net.Conn, requestIDs map[string]struct{}, deadline time.Time) error {
	for {
		frame, err := readFrame(reader, connection, deadline)
		if err != nil {
			return err
		}
		pong, err := runtime.handleFrame(frame, connection, requestIDs)
		if err != nil {
			return err
		}
		if pong {
			return nil
		}
	}
}

func (runtime *Runtime) handleFrame(frame guestenrollment.NativeSessionMessage, connection net.Conn, requestIDs map[string]struct{}) (bool, error) {
	switch frame.Type {
	case guestenrollment.NativeSessionPing:
		return false, writeFrame(connection, guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionPong,
		}, time.Now().Add(frameTimeout))
	case guestenrollment.NativeSessionPong:
		return true, nil
	case guestenrollment.NativeSessionAgentdRequest:
		if _, duplicate := requestIDs[frame.RequestID]; duplicate || len(requestIDs) >= guestenrollment.MaxNativeSessionRequestsPerConnection {
			return false, fail(ReasonProtocolInvalid, false, false)
		}
		requestIDs[frame.RequestID] = struct{}{}
		payload, err := relayAgentd(runtime.Configuration.AgentdSocketPath, frame.Payload)
		if err != nil {
			return false, err
		}
		defer zero(payload)
		response := guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionAgentdResponse,
			RequestID: frame.RequestID, Payload: json.RawMessage(payload),
		}
		return false, writeFrame(connection, response, time.Now().Add(frameTimeout))
	default:
		return false, fail(ReasonProtocolInvalid, false, false)
	}
}

func (runtime *Runtime) checkAgentd() error {
	response, err := relayAgentd(runtime.Configuration.AgentdSocketPath, []byte(`{"type":"health"}`))
	if err != nil {
		return err
	}
	defer zero(response)
	var value map[string]json.RawMessage
	if json.Unmarshal(response, &value) != nil {
		return fail(ReasonProtocolInvalid, false, false)
	}
	var status string
	if json.Unmarshal(value["status"], &status) != nil || status != "ready" {
		return fail(ReasonAgentdUnavailable, true, false)
	}
	return nil
}

func renewalJitter(binding guestenrollment.Binding) time.Duration {
	if credentialRenewalJitter <= 0 {
		return 0
	}
	value := binding.AgentRunUID + "\x00" + binding.ExecutionID + "\x00" + binding.DriverRegistration + "\x00" + binding.GuestInstanceID
	digest := sha256.Sum256([]byte(value))
	return time.Duration(binary.BigEndian.Uint64(digest[:8]) % uint64(credentialRenewalJitter))
}

func (runtime *Runtime) writeReadiness(ready bool) error {
	path := filepath.Join(runtime.Configuration.RuntimeDirectory, ReadinessFileName)
	if !ready {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fail(ReasonConfiguration, false, false)
		}
		return nil
	}
	temporary, err := os.CreateTemp(runtime.Configuration.RuntimeDirectory, ".session-ready-*.tmp")
	if err != nil {
		return fail(ReasonConfiguration, false, false)
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o640); err != nil {
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
	return nil
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

func (runtime *Runtime) credentialCurrent(credential sessionCredential) bool {
	return runtime.now().Before(credential.ExpiresAt) && runtime.monotonicNow().Before(credential.LocalExpiresAt)
}

func (runtime *Runtime) credentialRenewalDue(credential sessionCredential) bool {
	return !runtime.now().Before(credential.RenewAt) || !runtime.monotonicNow().Before(credential.LocalRenewAt)
}

func (runtime *Runtime) untilRenewal(credential sessionCredential) time.Duration {
	wall := credential.RenewAt.Sub(runtime.now())
	local := credential.LocalRenewAt.Sub(runtime.monotonicNow())
	if local < wall {
		return local
	}
	return wall
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
