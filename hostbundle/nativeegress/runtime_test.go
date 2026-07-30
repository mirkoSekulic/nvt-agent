package nativeegress

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	protocol "github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

type fakeIssuer struct {
	mu      sync.Mutex
	binding guestenrollment.Binding
	now     time.Time
	calls   int
	errors  []error
}

func (issuer *fakeIssuer) Issue(context.Context) (guestenrollment.NativeEgressIssueResult, error) {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	issuer.calls++
	if len(issuer.errors) > 0 {
		err := issuer.errors[0]
		issuer.errors = issuer.errors[1:]
		if err != nil {
			return guestenrollment.NativeEgressIssueResult{}, err
		}
	}
	credential, err := guestenrollment.GenerateNativeEgressCredential(uint64(issuer.calls))
	if err != nil {
		return guestenrollment.NativeEgressIssueResult{}, err
	}
	return nativeEgressIssueResult(issuer.binding, credential, issuer.now), nil
}

type fakeAuthenticator struct {
	mu            sync.Mutex
	binding       guestenrollment.Binding
	issuedAt      time.Time
	credentials   []string
	temporaryCall int
	denied        bool
}

func (authenticator *fakeAuthenticator) AuthenticateNativeEgress(_ context.Context, credential string, binding guestenrollment.Binding) (protocol.Authentication, error) {
	authenticator.mu.Lock()
	defer authenticator.mu.Unlock()
	authenticator.credentials = append(authenticator.credentials, credential)
	call := len(authenticator.credentials)
	if authenticator.denied || binding != authenticator.binding {
		return protocol.Authentication{}, protocol.ErrAuthenticationDenied
	}
	if authenticator.temporaryCall == call {
		return protocol.Authentication{}, protocol.ErrAuthenticationTemporary
	}
	sequence, err := guestenrollment.NativeEgressCredentialSequence(credential)
	if err != nil {
		return protocol.Authentication{}, protocol.ErrAuthenticationDenied
	}
	return protocol.Authentication{
		Binding: binding, Sequence: sequence, IssuedAt: authenticator.issuedAt,
		ExpiresAt: authenticator.issuedAt.Add(guestenrollment.MaxNativeEgressCredentialLifetime),
	}, nil
}

type pipeConnector struct {
	mu      sync.Mutex
	calls   int
	handler func(int, net.Conn)
}

type runtimeRelayTarget struct {
	binding guestenrollment.Binding
}

func (target runtimeRelayTarget) Binding() guestenrollment.Binding { return target.binding }

func (runtimeRelayTarget) OpenFlow(context.Context, protocol.Destination) (net.Conn, error) {
	return nil, protocol.ErrUnavailable
}

func newRuntimeRelayTransport(connection net.Conn, authenticator protocol.Authenticator) (*protocol.RelayFlowTransport, error) {
	authentication, err := protocol.Accept(context.Background(), connection, authenticator)
	if err != nil {
		return nil, err
	}
	session, err := protocol.NewSession(authentication, runtimeRelayTarget{binding: authentication.Binding})
	if err != nil {
		return nil, err
	}
	transport, err := protocol.NewRelayFlowTransport(connection, session)
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	return transport, nil
}

func (connector *pipeConnector) Connect(context.Context, string) (net.Conn, error) {
	client, server := net.Pipe()
	connector.mu.Lock()
	connector.calls++
	call := connector.calls
	connector.mu.Unlock()
	go connector.handler(call, server)
	return client, nil
}

func TestRuntimeReconnectsRenewsMakeBeforeBreakAndReusesPendingCredential(t *testing.T) {
	originalAge, originalRecovery, originalJitter := credentialRenewalAge, credentialRecoveryWindow, credentialRenewalJitter
	originalReconnect, originalRetry := reconnectDelay, renewalRetryDelay
	credentialRenewalAge, credentialRecoveryWindow, credentialRenewalJitter = 150*time.Millisecond, 50*time.Millisecond, 0
	reconnectDelay, renewalRetryDelay = 10*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() {
		credentialRenewalAge, credentialRecoveryWindow, credentialRenewalJitter = originalAge, originalRecovery, originalJitter
		reconnectDelay, renewalRetryDelay = originalReconnect, originalRetry
	})

	binding := nativeEgressBinding()
	now := time.Now().UTC().Truncate(time.Second)
	issuer := &fakeIssuer{binding: binding, now: now}
	authenticator := &fakeAuthenticator{binding: binding, issuedAt: now, temporaryCall: 3}
	accepted := make(chan int, 4)
	closed := make(chan int, 4)
	connector := &pipeConnector{}
	connector.handler = func(call int, connection net.Conn) {
		defer connection.Close()
		transport, err := newRuntimeRelayTransport(connection, authenticator)
		if err != nil {
			return
		}
		accepted <- call
		if call == 1 {
			_ = transport.Close()
			return
		}
		_ = transport.Serve(context.Background())
		closed <- call
	}

	work := t.TempDir()
	runtimeDirectory := filepath.Join(work, "run")
	runtime, err := NewRuntime(Configuration{
		Version: ConfigurationVersion, RuntimeDirectory: runtimeDirectory,
		IdentitySocketPath: filepath.Join(work, "identity.sock"),
		RelayEndpoint:      "tls://relay.example:7445", CAPEMPath: filepath.Join(work, "ca.pem"),
	}, issuer, connector)
	if err != nil {
		t.Fatal(err)
	}
	runtime.Now = func() time.Time { return now }
	runtime.MonotonicNow = time.Now
	var readinessMu sync.Mutex
	readiness := []bool{}
	runtime.readinessChanged = func(value bool) {
		readinessMu.Lock()
		readiness = append(readiness, value)
		readinessMu.Unlock()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()

	if call := waitInt(t, accepted, "first relay session"); call != 1 {
		t.Fatalf("first accepted call=%d", call)
	}
	if call := waitInt(t, accepted, "same-credential reconnect"); call != 2 {
		t.Fatalf("reconnect accepted call=%d", call)
	}
	waitForFile(t, filepath.Join(runtimeDirectory, ReadinessFileName))
	readinessMu.Lock()
	baseline := len(readiness)
	readinessMu.Unlock()
	// Call three is a temporary authority failure before acknowledgement. The
	// retry must use the already-issued sequence-two credential and call four is
	// the only replacement that may promote.
	if call := waitInt(t, accepted, "retried replacement"); call != 4 {
		t.Fatalf("replacement accepted call=%d", call)
	}
	if call := waitInt(t, closed, "retired predecessor"); call != 2 {
		t.Fatalf("retired relay call=%d", call)
	}

	authenticator.mu.Lock()
	credentials := append([]string(nil), authenticator.credentials...)
	authenticator.mu.Unlock()
	if len(credentials) != 4 || credentials[0] != credentials[1] || credentials[1] == credentials[2] || credentials[2] != credentials[3] {
		t.Fatalf("reconnect/replacement credentials = %d same-current=%v renewed=%v reused-pending=%v",
			len(credentials), len(credentials) > 1 && credentials[0] == credentials[1],
			len(credentials) > 2 && credentials[1] != credentials[2], len(credentials) > 3 && credentials[2] == credentials[3])
	}
	issuer.mu.Lock()
	issueCalls := issuer.calls
	issuer.mu.Unlock()
	if issueCalls != 2 {
		t.Fatalf("credential issue calls=%d want=2", issueCalls)
	}
	readinessMu.Lock()
	for _, value := range readiness[baseline:] {
		if !value {
			readinessMu.Unlock()
			t.Fatal("readiness flickered during make-before-break replacement")
		}
	}
	readinessMu.Unlock()

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(runtimeDirectory, ReadinessFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("egress readiness remained after shutdown: %v", err)
	}
	readinessMu.Lock()
	if len(readiness) == 0 || readiness[len(readiness)-1] {
		readinessMu.Unlock()
		t.Fatal("shutdown did not withdraw readiness")
	}
	readinessMu.Unlock()
}

func TestFirstIssuanceResponseLossIsBoundedToTwoCandidates(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuer := &fakeIssuer{
		binding: nativeEgressBinding(), now: now,
		errors: []error{fail(ReasonIdentityUnavailable, true, true)},
	}
	runtime := &Runtime{Identity: issuer, Now: func() time.Time { return now }, MonotonicNow: time.Now}
	value, err := runtime.issueCredential(context.Background())
	if err != nil || value.Opaque == "" {
		t.Fatalf("response-loss recovery=%#v error=%v", value, err)
	}
	issuer.mu.Lock()
	calls := issuer.calls
	issuer.mu.Unlock()
	if calls != 2 {
		t.Fatalf("response-loss calls=%d want=2", calls)
	}

	issuer = &fakeIssuer{
		binding: nativeEgressBinding(), now: now,
		errors: []error{
			fail(ReasonIdentityUnavailable, true, true),
			fail(ReasonIdentityUnavailable, true, true),
		},
	}
	runtime.Identity = issuer
	if _, err := runtime.issueCredential(context.Background()); err == nil {
		t.Fatal("second ambiguous issuance was accepted")
	} else if _, temporary, uncertain := FailureDetails(err); temporary || !uncertain {
		t.Fatalf("second ambiguity remained retryable: %v", err)
	}
	issuer.mu.Lock()
	calls = issuer.calls
	issuer.mu.Unlock()
	if calls != guestenrollment.MaxLiveNativeEgressCredentials {
		t.Fatalf("ambiguous issue calls=%d", calls)
	}
}

func TestReplacementCredentialRequiresExactBindingAndHigherSequence(t *testing.T) {
	binding := nativeEgressBinding()
	newCredential := func(binding guestenrollment.Binding, sequence uint64) *credential {
		opaque, err := guestenrollment.GenerateNativeEgressCredential(sequence)
		if err != nil {
			t.Fatal(err)
		}
		return &credential{Binding: binding, Opaque: opaque, Sequence: sequence}
	}
	for name, candidate := range map[string]*credential{
		"older sequence": newCredential(binding, 4),
		"equal sequence": newCredential(binding, 5),
		"changed binding": func() *credential {
			changed := binding
			changed.GuestInstanceID = "replacement-guest"
			return newCredential(changed, 6)
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			current := newCredential(binding, 5)
			state := &credentialState{current: current}
			result := preparationResult{issued: candidate}
			if replacement, switched, err := (&Runtime{}).completePreparation(state, &result); err == nil || switched || replacement != nil {
				t.Fatalf("unsafe replacement result=%v switched=%v replacement=%v", err, switched, replacement)
			} else if reason, temporary, uncertain := FailureDetails(err); reason != ReasonProtocolInvalid || temporary || uncertain {
				t.Fatalf("unsafe replacement classification=%s temporary=%v uncertain=%v", reason, temporary, uncertain)
			}
			if candidate.Opaque != "" || state.pending != nil || state.current != current {
				t.Fatal("rejected replacement was retained or changed current authority")
			}
		})
	}

	current := newCredential(binding, 5)
	skipped := newCredential(binding, 8)
	client, server := net.Pipe()
	transport, err := protocol.NewGuestFlowTransport(client)
	if err != nil {
		_ = client.Close()
		_ = server.Close()
		t.Fatal(err)
	}
	state := &credentialState{current: current}
	result := preparationResult{
		issued:  skipped,
		session: &relaySession{transport: transport, done: make(chan error, 1)},
	}
	replacement, switched, err := (&Runtime{}).completePreparation(state, &result)
	if err != nil || !switched || replacement == nil || state.current == nil || state.current.Sequence != 8 || state.current.Binding != binding {
		_ = server.Close()
		t.Fatalf("valid skipped sequence was rejected: state=%#v switched=%v error=%v", state, switched, err)
	}
	if current.Opaque != "" {
		replacement.Close()
		_ = server.Close()
		t.Fatal("promoted replacement did not clear predecessor")
	}
	replacement.Close()
	_ = server.Close()
}

func TestRenewalResponseLossAtTwoLiveCapacityRetainsPredecessor(t *testing.T) {
	originalAge, originalRecovery, originalJitter := credentialRenewalAge, credentialRecoveryWindow, credentialRenewalJitter
	originalReconnect, originalRetry := reconnectDelay, renewalRetryDelay
	credentialRenewalAge, credentialRecoveryWindow, credentialRenewalJitter = 50*time.Millisecond, 20*time.Millisecond, 0
	reconnectDelay, renewalRetryDelay = 5*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() {
		credentialRenewalAge, credentialRecoveryWindow, credentialRenewalJitter = originalAge, originalRecovery, originalJitter
		reconnectDelay, renewalRetryDelay = originalReconnect, originalRetry
	})

	binding := nativeEgressBinding()
	now := time.Now().UTC().Truncate(time.Second)
	issuer := &fakeIssuer{
		binding: binding,
		now:     now,
		errors: []error{
			nil,
			fail(ReasonIdentityUnavailable, true, true),  // committed candidate, response lost
			fail(ReasonIdentityUnavailable, true, false), // two-live capacity denial
		},
	}
	authenticator := &fakeAuthenticator{binding: binding, issuedAt: now}
	accepted := make(chan struct{}, 1)
	closed := make(chan struct{}, 1)
	connector := &pipeConnector{handler: func(_ int, connection net.Conn) {
		defer connection.Close()
		transport, err := newRuntimeRelayTransport(connection, authenticator)
		if err != nil {
			return
		}
		accepted <- struct{}{}
		_ = transport.Serve(context.Background())
		closed <- struct{}{}
	}}
	work := t.TempDir()
	runtime, err := NewRuntime(Configuration{
		Version: ConfigurationVersion, RuntimeDirectory: filepath.Join(work, "run"),
		IdentitySocketPath: filepath.Join(work, "identity.sock"), RelayEndpoint: "tls://relay.example:7445",
		CAPEMPath: filepath.Join(work, "ca.pem"),
	}, issuer, connector)
	if err != nil {
		t.Fatal(err)
	}
	runtime.Now = func() time.Time { return now }
	runtime.MonotonicNow = time.Now
	var readinessMu sync.Mutex
	readiness := []bool{}
	runtime.readinessChanged = func(value bool) {
		readinessMu.Lock()
		readiness = append(readiness, value)
		readinessMu.Unlock()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("predecessor session did not authenticate")
	}
	waitForFile(t, filepath.Join(runtime.Configuration.RuntimeDirectory, ReadinessFileName))
	readinessMu.Lock()
	baseline := len(readiness)
	readinessMu.Unlock()
	waitForIssuerCalls(t, issuer, 3)
	time.Sleep(10 * renewalRetryDelay)
	issuer.mu.Lock()
	issueCalls := issuer.calls
	issuer.mu.Unlock()
	connector.mu.Lock()
	connectionCalls := connector.calls
	connector.mu.Unlock()
	authenticator.mu.Lock()
	authenticated := append([]string(nil), authenticator.credentials...)
	authenticator.mu.Unlock()
	if issueCalls != 3 || connectionCalls != 1 || len(authenticated) != 1 {
		cancel()
		t.Fatalf("two-live edge issued=%d connected=%d authenticated=%d", issueCalls, connectionCalls, len(authenticated))
	}
	if _, err := os.Stat(filepath.Join(runtime.Configuration.RuntimeDirectory, ReadinessFileName)); err != nil {
		cancel()
		t.Fatalf("usable predecessor lost readiness: %v", err)
	}
	readinessMu.Lock()
	for _, value := range readiness[baseline:] {
		if !value {
			readinessMu.Unlock()
			cancel()
			t.Fatal("uncertain renewal withdrew predecessor readiness")
		}
	}
	readinessMu.Unlock()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not close predecessor")
	}
}

func TestRuntimeFailsClosedOnDenialExpiryAndSecretFormatting(t *testing.T) {
	binding := nativeEgressBinding()
	now := time.Now().UTC().Truncate(time.Second)
	issuer := &fakeIssuer{binding: binding, now: now}
	authenticator := &fakeAuthenticator{binding: binding, issuedAt: now, denied: true}
	connector := &pipeConnector{handler: func(_ int, connection net.Conn) {
		defer connection.Close()
		_, _ = protocol.Accept(context.Background(), connection, authenticator)
	}}
	work := t.TempDir()
	runtime, err := NewRuntime(Configuration{
		Version: ConfigurationVersion, RuntimeDirectory: filepath.Join(work, "run"),
		IdentitySocketPath: filepath.Join(work, "identity.sock"), RelayEndpoint: "tls://relay.example:7445",
		CAPEMPath: filepath.Join(work, "ca.pem"),
	}, issuer, connector)
	if err != nil {
		t.Fatal(err)
	}
	runtime.Now = func() time.Time { return now }
	err = runtime.Run(context.Background())
	reason, temporary, _ := FailureDetails(err)
	if reason != ReasonRelayDenied || temporary {
		t.Fatalf("denial result=%v reason=%s temporary=%v", err, reason, temporary)
	}
	if _, statErr := os.Stat(filepath.Join(runtime.Configuration.RuntimeDirectory, ReadinessFileName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("denied session retained readiness: %v", statErr)
	}

	credentialValue, _ := guestenrollment.GenerateNativeEgressCredential(9)
	result := nativeEgressIssueResult(binding, credentialValue, now.Add(-guestenrollment.MaxNativeEgressCredentialLifetime))
	if _, err := runtime.validateCredential(result); err == nil {
		t.Fatal("expired credential was accepted")
	}
	if strings.Contains(fmt.Sprintf("%#v", credential{Opaque: credentialValue}), credentialValue) ||
		strings.Contains(fail(ReasonRelayDenied, false, false).Error(), credentialValue) {
		t.Fatal("credential escaped formatting or errors")
	}
}

func TestRuntimeRejectsMalformedWrongBindingAndAudienceAcknowledgements(t *testing.T) {
	binding := nativeEgressBinding()
	now := time.Now().UTC().Truncate(time.Second)
	credentialValue, err := guestenrollment.GenerateNativeEgressCredential(1)
	if err != nil {
		t.Fatal(err)
	}
	result := nativeEgressIssueResult(binding, credentialValue, now)
	for name, response := range map[string]string{
		"malformed":      "{not-json}\n",
		"wrong audience": `{"contract_version":"nvt.native-egress/v1","type":"hello_ack","binding":{"agent_run_uid":"11111111-1111-1111-1111-111111111111","execution_id":"execution-native-egress","driver_registration":"driver-native-egress","desired_generation":1,"guest_instance_id":"guest-native-egress"},"audience":"nvt.native-guest-control/v1"}` + "\n",
		"wrong binding":  `{"contract_version":"nvt.native-egress/v1","type":"hello_ack","binding":{"agent_run_uid":"11111111-1111-1111-1111-111111111111","execution_id":"execution-native-egress","driver_registration":"driver-native-egress","desired_generation":1,"guest_instance_id":"other-guest"},"audience":"nvt.native-egress/v1"}` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			connector := &pipeConnector{handler: func(_ int, connection net.Conn) {
				defer connection.Close()
				_, _ = bufio.NewReader(connection).ReadBytes('\n')
				_, _ = connection.Write([]byte(response))
			}}
			work := t.TempDir()
			runtime, err := NewRuntime(Configuration{
				Version: ConfigurationVersion, RuntimeDirectory: filepath.Join(work, "run"),
				IdentitySocketPath: filepath.Join(work, "identity.sock"), RelayEndpoint: "tls://relay.example:7445",
				CAPEMPath: filepath.Join(work, "ca.pem"),
			}, &fakeIssuer{binding: binding, now: now}, connector)
			if err != nil {
				t.Fatal(err)
			}
			runtime.Now = func() time.Time { return now }
			value, err := runtime.validateCredential(result)
			if err != nil {
				t.Fatal(err)
			}
			if session, err := runtime.openSession(context.Background(), value); err == nil {
				session.Close()
				t.Fatal("unsafe relay acknowledgement was accepted")
			} else if reason, temporary, _ := FailureDetails(err); reason != ReasonProtocolInvalid || temporary {
				t.Fatalf("unsafe acknowledgement result=%v reason=%s temporary=%v", err, reason, temporary)
			}
		})
	}
}

func TestRuntimeRequiresUsableYamuxBeforeRelayReadiness(t *testing.T) {
	binding := nativeEgressBinding()
	now := time.Now().UTC().Truncate(time.Second)
	authenticator := &fakeAuthenticator{binding: binding, issuedAt: now}
	connector := &pipeConnector{handler: func(_ int, connection net.Conn) {
		defer connection.Close()
		if _, err := protocol.Accept(context.Background(), connection, authenticator); err != nil {
			return
		}
		// Deliberately acknowledge the authenticated preface without switching
		// to yamux. The guest must not treat this as transport readiness.
		_, _ = io.Copy(io.Discard, connection)
	}}
	runtime := &Runtime{Connector: connector, Configuration: Configuration{RelayEndpoint: "tls://relay.example:7445"}, Now: func() time.Time { return now }, MonotonicNow: time.Now}
	opaque, err := guestenrollment.GenerateNativeEgressCredential(1)
	if err != nil {
		t.Fatal(err)
	}
	value, err := runtime.validateCredential(nativeEgressIssueResult(binding, opaque, now))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	if session, err := runtime.openSession(ctx, value); err == nil {
		session.Close()
		t.Fatal("hello-only relay was reported transport-ready")
	} else if reason, temporary, _ := FailureDetails(err); reason != ReasonRelayUnavailable || !temporary {
		t.Fatalf("hello-only relay result=%v reason=%s temporary=%v", err, reason, temporary)
	}
}

func TestActiveCredentialExpiryWithdrawsReadinessAndClosesRelay(t *testing.T) {
	binding := nativeEgressBinding()
	now := time.Now().UTC().Truncate(time.Second)
	issuer := &fakeIssuer{binding: binding, now: now}
	authenticator := &fakeAuthenticator{binding: binding, issuedAt: now}
	closedAfterWithdrawal := make(chan bool, 1)
	var readinessPublished atomic.Bool
	var readinessWithdrawn atomic.Bool
	connector := &pipeConnector{handler: func(_ int, connection net.Conn) {
		defer connection.Close()
		transport, err := newRuntimeRelayTransport(connection, authenticator)
		if err != nil {
			return
		}
		_ = transport.Serve(context.Background())
		closedAfterWithdrawal <- readinessWithdrawn.Load()
	}}
	work := t.TempDir()
	runtime, err := NewRuntime(Configuration{
		Version: ConfigurationVersion, RuntimeDirectory: filepath.Join(work, "run"),
		IdentitySocketPath: filepath.Join(work, "identity.sock"), RelayEndpoint: "tls://relay.example:7445",
		CAPEMPath: filepath.Join(work, "ca.pem"),
	}, issuer, connector)
	if err != nil {
		t.Fatal(err)
	}
	var wall atomic.Int64
	wall.Store(now.Unix())
	runtime.Now = func() time.Time { return time.Unix(wall.Load(), 0).UTC() }
	runtime.MonotonicNow = time.Now
	runtime.readinessChanged = func(ready bool) {
		if ready {
			readinessPublished.Store(true)
		} else if readinessPublished.Load() {
			readinessWithdrawn.Store(true)
		}
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Run(context.Background()) }()
	waitForFile(t, filepath.Join(runtime.Configuration.RuntimeDirectory, ReadinessFileName))
	wall.Store(now.Add(guestenrollment.MaxNativeEgressCredentialLifetime).Unix())
	select {
	case err := <-done:
		reason, temporary, _ := FailureDetails(err)
		if reason != ReasonCredentialExpired || temporary {
			t.Fatalf("expiry result=%v reason=%s temporary=%v", err, reason, temporary)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expired session remained ready")
	}
	if _, err := os.Stat(filepath.Join(runtime.Configuration.RuntimeDirectory, ReadinessFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expiry retained readiness: %v", err)
	}
	select {
	case withdrawn := <-closedAfterWithdrawal:
		if !withdrawn {
			t.Fatal("relay closed before readiness withdrawal")
		}
	case <-time.After(time.Second):
		t.Fatal("expiry did not close the relay")
	}
}

func nativeEgressBinding() guestenrollment.Binding {
	return guestenrollment.Binding{
		AgentRunUID: "11111111-1111-1111-1111-111111111111",
		ExecutionID: "execution-native-egress", DriverRegistration: "driver-native-egress",
		DesiredGeneration: 1, GuestInstanceID: "guest-native-egress",
	}
}

func nativeEgressIssueResult(binding guestenrollment.Binding, opaque string, issuedAt time.Time) guestenrollment.NativeEgressIssueResult {
	return guestenrollment.NativeEgressIssueResult{
		ContractVersion: guestenrollment.NativeEgressIdentityVersion,
		Binding:         binding,
		Credential: guestenrollment.NativeEgressCredential{
			Type: guestenrollment.NativeEgressCredentialType, Opaque: opaque, Audience: guestenrollment.NativeEgressAudience,
			IssuedAt:  guestenrollment.FormatTimestamp(issuedAt),
			ExpiresAt: guestenrollment.FormatTimestamp(issuedAt.Add(guestenrollment.MaxNativeEgressCredentialLifetime)),
		},
	}
}

func waitInt(t *testing.T, values <-chan int, name string) int {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
		return 0
	}
}

func waitForIssuerCalls(t *testing.T, issuer *fakeIssuer, minimum int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		issuer.mu.Lock()
		calls := issuer.calls
		issuer.mu.Unlock()
		if calls >= minimum {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("issuer calls did not reach %d", minimum)
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("file did not appear: %s", filepath.Base(path))
}
