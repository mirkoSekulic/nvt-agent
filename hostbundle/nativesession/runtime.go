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
	"sync"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/workspacetunnel"
)

var (
	credentialRenewalAge          = 3 * time.Minute
	credentialRecoveryWindow      = time.Minute
	credentialRenewalJitter       = 30 * time.Second
	reconnectDelay                = time.Second
	renewalRetryDelay             = 5 * time.Second
	idleProbeInterval             = 5 * time.Second
	replacementPreparationTimeout = 50 * time.Second
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

type sessionPair struct {
	control         net.Conn
	reader          *bufio.Reader
	workspace       *workspacetunnel.GuestForwarder
	workspaceCancel context.CancelFunc
	workspaceDone   chan error
	readWorkers     sync.WaitGroup
}

type controlReadResult struct {
	frame guestenrollment.NativeSessionMessage
	err   error
}

type replacementResult struct {
	pair        *sessionPair
	issued      *sessionCredential
	err         error
	issueFailed bool
}

type replacementAttempt struct {
	cancel context.CancelFunc
	done   chan replacementResult
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

func (pair *sessionPair) Close() {
	if pair == nil {
		return
	}
	if pair.workspaceCancel != nil {
		pair.workspaceCancel()
	}
	if pair.control != nil {
		_ = pair.control.Close()
	}
	pair.readWorkers.Wait()
	if pair.workspace != nil {
		_ = pair.workspace.Close()
	}
	if pair.workspaceDone != nil {
		select {
		case <-pair.workspaceDone:
		case <-time.After(workspacetunnel.StreamCloseTimeout):
		}
	}
}

func (pair *sessionPair) workspaceStopped() <-chan struct{} {
	if pair == nil || pair.workspace == nil {
		return nil
	}
	return pair.workspace.Done()
}

func (pair *sessionPair) readControl(deadline time.Time) <-chan controlReadResult {
	result := make(chan controlReadResult, 1)
	pair.readWorkers.Add(1)
	go func() {
		defer pair.readWorkers.Done()
		frame, err := readFrame(pair.reader, pair.control, deadline)
		result <- controlReadResult{frame: frame, err: err}
	}()
	return result
}

func (result *replacementResult) discard() {
	if result == nil {
		return
	}
	if result.pair != nil {
		result.pair.Close()
		result.pair = nil
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
	pair, err := runtime.openCredentialPair(ctx, *state.current)
	if err != nil {
		return err
	}
	var replacement *replacementAttempt
	var retiredPairDone <-chan struct{}
	defer func() {
		if replacement != nil {
			replacement.cancel()
			result := <-replacement.done
			result.discard()
		}
		pair.Close()
		if retiredPairDone != nil {
			<-retiredPairDone
		}
	}()
	if err := runtime.writeReadiness(true); err != nil {
		return err
	}
	defer runtime.writeReadiness(false)
	requestIDs := make(map[string]struct{}, guestenrollment.MaxNativeSessionRequestsPerConnection)
	var controlRead <-chan controlReadResult
	var pongDeadline time.Time
	for {
		if ctx.Err() != nil {
			return nil
		}
		if state.current == nil || !runtime.credentialCurrent(*state.current) {
			return fail(ReasonCredentialExpired, false, false)
		}
		if !pongDeadline.IsZero() && deadlineElapsed(pongDeadline) {
			return fail(ReasonGatewayUnavailable, true, false)
		}
		if replacement == nil && retiredPairDone == nil && runtime.credentialRenewalDue(*state.current) && runtime.renewalAttemptDue(state) {
			replacement = runtime.startReplacement(ctx, state)
		}
		if controlRead == nil {
			deadline := runtime.nextReadDeadline(state)
			if !pongDeadline.IsZero() && pongDeadline.Before(deadline) {
				deadline = pongDeadline
			}
			controlRead = pair.readControl(deadline)
		}
		var replacementDone <-chan replacementResult
		if replacement != nil {
			replacementDone = replacement.done
		}
		select {
		case <-ctx.Done():
			return nil
		case <-pair.workspaceStopped():
			if ctx.Err() != nil {
				return nil
			}
			if state.current == nil || !runtime.credentialCurrent(*state.current) {
				return fail(ReasonCredentialExpired, false, false)
			}
			return fail(ReasonGatewayUnavailable, true, false)
		case <-retiredPairDone:
			retiredPairDone = nil
			continue
		case result := <-replacementDone:
			replacement.cancel()
			replacement = nil
			prepared, switched, renewalErr := runtime.completeReplacement(state, &result)
			result.discard()
			if renewalErr != nil {
				return renewalErr
			}
			if !switched {
				continue
			}
			previous := pair
			pair = prepared
			controlRead = nil
			pongDeadline = time.Time{}
			requestIDs = make(map[string]struct{}, guestenrollment.MaxNativeSessionRequestsPerConnection)
			closed := make(chan struct{})
			retiredPairDone = closed
			go func() {
				previous.Close()
				close(closed)
			}()
			continue
		case result := <-controlRead:
			controlRead = nil
			if result.err == nil {
				operationDeadline := time.Now().Add(frameTimeout)
				if !pongDeadline.IsZero() && pongDeadline.Before(operationDeadline) {
					operationDeadline = pongDeadline
				}
				if deadlineElapsed(operationDeadline) {
					return fail(ReasonGatewayUnavailable, true, false)
				}
				pong, handleErr := runtime.handleFrame(result.frame, pair.control, requestIDs, operationDeadline)
				if handleErr != nil {
					return handleErr
				}
				if deadlineElapsed(operationDeadline) {
					return fail(ReasonGatewayUnavailable, true, false)
				}
				if pong && !pongDeadline.IsZero() {
					pongDeadline = time.Time{}
				}
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			select {
			case <-pair.workspaceStopped():
				if state.current == nil || !runtime.credentialCurrent(*state.current) {
					return fail(ReasonCredentialExpired, false, false)
				}
				return fail(ReasonGatewayUnavailable, true, false)
			default:
			}
			_, temporary, _ := FailureDetails(result.err)
			if !temporary {
				return result.err
			}
			if state.current == nil || !runtime.credentialCurrent(*state.current) {
				return fail(ReasonCredentialExpired, false, false)
			}
			if !pongDeadline.IsZero() {
				return fail(ReasonGatewayUnavailable, true, false)
			}
			if err := runtime.checkAgentd(); err != nil {
				return err
			}
			pongDeadline = time.Now().Add(frameTimeout)
			if err := writeFrame(pair.control, guestenrollment.NativeSessionMessage{
				ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionPing,
			}, pongDeadline); err != nil {
				return err
			}
		}
	}
}

func (runtime *Runtime) openCredentialPair(ctx context.Context, credential sessionCredential) (*sessionPair, error) {
	connection, reader, err := runtime.openControlCredential(ctx, credential)
	if err != nil {
		return nil, err
	}
	pair := &sessionPair{control: connection, reader: reader}
	if runtime.Configuration.Workspace == nil {
		return pair, nil
	}
	workspaceConnection, err := runtime.Connector.Connect(ctx, runtime.Configuration.Workspace.GatewayEndpoint)
	if err != nil {
		pair.Close()
		return nil, err
	}
	if err := workspacetunnel.Establish(ctx, workspaceConnection, credential.Binding, credential.Opaque); err != nil {
		_ = workspaceConnection.Close()
		pair.Close()
		return nil, mapWorkspaceError(err)
	}
	forwarder, err := workspacetunnel.NewGuestForwarder(
		workspaceConnection, credential.Binding, credential.LocalExpiresAt, runtime.Configuration.Workspace.LoopbackEndpoint,
	)
	if err != nil {
		_ = workspaceConnection.Close()
		pair.Close()
		return nil, mapWorkspaceError(err)
	}
	if err := forwarder.CheckDestination(ctx); err != nil {
		_ = forwarder.Close()
		pair.Close()
		return nil, mapWorkspaceError(err)
	}
	// Establishment observes the caller's bounded context, but the accepted
	// workspace leg belongs to the returned pair. In particular, a replacement
	// preparation context is cancelled as soon as the pair is handed to the
	// active loop and must not tear down the newly promoted session.
	workspaceContext, cancel := context.WithCancel(context.Background())
	pair.workspace = forwarder
	pair.workspaceCancel = cancel
	pair.workspaceDone = make(chan error, 1)
	go func() {
		err := forwarder.Serve(workspaceContext)
		pair.workspaceDone <- err
	}()
	select {
	case err := <-pair.workspaceDone:
		pair.workspaceDone = nil
		pair.Close()
		if err == nil {
			err = workspacetunnel.ErrUnavailable
		}
		return nil, mapWorkspaceError(err)
	default:
		return pair, nil
	}
}

func (runtime *Runtime) openControlCredential(ctx context.Context, credential sessionCredential) (net.Conn, *bufio.Reader, error) {
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

func (runtime *Runtime) startReplacement(ctx context.Context, state *credentialState) *replacementAttempt {
	if state.pending != nil && !runtime.credentialCurrent(*state.pending) {
		state.pending.Opaque = ""
		state.pending = nil
	}
	attemptContext, cancel := context.WithTimeout(ctx, replacementPreparationTimeout)
	attempt := &replacementAttempt{cancel: cancel, done: make(chan replacementResult, 1)}
	var pending *sessionCredential
	if state.pending != nil {
		value := *state.pending
		pending = &value
	}
	go func() {
		result := replacementResult{}
		credential := pending
		if credential == nil {
			issued, err := runtime.issueCredential(attemptContext)
			if err != nil {
				result.err = err
				result.issueFailed = true
				attempt.done <- result
				return
			}
			credential = &issued
			result.issued = &issued
		}
		result.pair, result.err = runtime.openCredentialPair(attemptContext, *credential)
		attempt.done <- result
	}()
	return attempt
}

func (runtime *Runtime) completeReplacement(state *credentialState, result *replacementResult) (*sessionPair, bool, error) {
	if state == nil || result == nil {
		return nil, false, fail(ReasonProtocolInvalid, false, false)
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
	if result.issued != nil && state.pending == nil {
		state.pending = result.issued
		result.issued = nil
	}
	if result.err != nil {
		_, temporary, _ := FailureDetails(result.err)
		if temporary {
			state.nextRenewalAttemptAt = runtime.monotonicNow().Add(renewalRetryDelay)
			return nil, false, nil
		}
		return nil, false, result.err
	}
	if result.pair == nil || state.pending == nil {
		return nil, false, fail(ReasonProtocolInvalid, false, false)
	}
	replacement := result.pair
	result.pair = nil
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

func (runtime *Runtime) handleFrame(frame guestenrollment.NativeSessionMessage, connection net.Conn, requestIDs map[string]struct{}, deadline time.Time) (bool, error) {
	switch frame.Type {
	case guestenrollment.NativeSessionPing:
		return false, writeFrame(connection, guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionPong,
		}, deadline)
	case guestenrollment.NativeSessionPong:
		return true, nil
	case guestenrollment.NativeSessionAgentdRequest:
		if _, duplicate := requestIDs[frame.RequestID]; duplicate || len(requestIDs) >= guestenrollment.MaxNativeSessionRequestsPerConnection {
			return false, fail(ReasonProtocolInvalid, false, false)
		}
		requestIDs[frame.RequestID] = struct{}{}
		payload, err := relayAgentdUntil(runtime.Configuration.AgentdSocketPath, frame.Payload, deadline)
		if err != nil {
			return false, err
		}
		defer zero(payload)
		response := guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionAgentdResponse,
			RequestID: frame.RequestID, Payload: json.RawMessage(payload),
		}
		return false, writeFrame(connection, response, deadline)
	default:
		return false, fail(ReasonProtocolInvalid, false, false)
	}
}

func deadlineElapsed(deadline time.Time) bool {
	return deadline.IsZero() || !time.Now().Before(deadline)
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
		if runtime.readinessChanged != nil {
			runtime.readinessChanged(false)
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
	if runtime.readinessChanged != nil {
		runtime.readinessChanged(true)
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

func mapWorkspaceError(err error) error {
	switch {
	case errors.Is(err, workspacetunnel.ErrDenied):
		return fail(ReasonGatewayDenied, false, false)
	case errors.Is(err, workspacetunnel.ErrProtocol):
		return fail(ReasonProtocolInvalid, false, false)
	default:
		return fail(ReasonGatewayUnavailable, true, false)
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
