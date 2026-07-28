package nativesession

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

type fakeIssuer struct {
	mu      sync.Mutex
	binding guestenrollment.Binding
	now     time.Time
	clock   func() time.Time
	calls   int
	errors  []error
}

func (issuer *fakeIssuer) Issue(_ context.Context) (guestenrollment.GuestSessionIssueResult, error) {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	issuer.calls++
	if len(issuer.errors) > 0 {
		err := issuer.errors[0]
		issuer.errors = issuer.errors[1:]
		if err != nil {
			return guestenrollment.GuestSessionIssueResult{}, err
		}
	}
	credential, _ := guestenrollment.GenerateGuestSessionCredential(uint64(issuer.calls))
	issuedAt := issuer.now
	if issuer.clock != nil {
		issuedAt = issuer.clock().UTC().Truncate(time.Second)
	}
	return guestenrollment.GuestSessionIssueResult{
		ContractVersion: guestenrollment.GuestSessionIdentityVersion,
		Binding:         issuer.binding,
		Credential: guestenrollment.GuestSessionCredential{
			Type: guestenrollment.GuestSessionCredentialType, Opaque: credential,
			Audience: guestenrollment.NativeGuestControlAudience,
			IssuedAt: guestenrollment.FormatTimestamp(issuedAt), ExpiresAt: guestenrollment.FormatTimestamp(issuedAt.Add(5 * time.Minute)),
		},
	}, nil
}

type pipeConnector struct {
	mu      sync.Mutex
	calls   int
	handler func(int, net.Conn)
}

func (connector *pipeConnector) Connect(_ context.Context, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	connector.mu.Lock()
	connector.calls++
	call := connector.calls
	connector.mu.Unlock()
	go connector.handler(call, server)
	return client, nil
}

func TestRuntimeEstablishesRelaysReconnectsAndRenews(t *testing.T) {
	originalRenewalAge, originalRecovery, originalJitter := credentialRenewalAge, credentialRecoveryWindow, credentialRenewalJitter
	originalReconnect, originalProbe := reconnectDelay, idleProbeInterval
	credentialRenewalAge, credentialRecoveryWindow, credentialRenewalJitter = 150*time.Millisecond, 50*time.Millisecond, 0
	reconnectDelay, idleProbeInterval = 10*time.Millisecond, 25*time.Millisecond
	t.Cleanup(func() {
		credentialRenewalAge, credentialRecoveryWindow, credentialRenewalJitter = originalRenewalAge, originalRecovery, originalJitter
		reconnectDelay, idleProbeInterval = originalReconnect, originalProbe
	})

	work := t.TempDir()
	agentdSocket := filepath.Join(work, "agentd.sock")
	stopAgentd := serveFakeAgentd(t, agentdSocket)
	defer stopAgentd()
	binding := testBinding()
	now := time.Now().UTC().Truncate(time.Second)
	issuer := &fakeIssuer{binding: binding, now: now, clock: time.Now}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	credentials := make(chan string, 4)
	connector := &pipeConnector{}
	connector.handler = func(call int, connection net.Conn) {
		defer connection.Close()
		reader := newFrameReader(connection)
		hello, err := readFrame(reader, connection, time.Now().Add(time.Second))
		if err != nil || hello.Type != guestenrollment.NativeSessionHello || hello.Binding == nil || *hello.Binding != binding {
			t.Errorf("hello %d = %#v, %v", call, hello, err)
			return
		}
		credentials <- hello.Credential
		_ = writeFrame(connection, guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionHelloAck,
			Binding: &binding, Audience: guestenrollment.NativeGuestControlAudience,
		}, time.Now().Add(time.Second))
		if call == 1 {
			_ = connection.Close()
			return
		}
		_ = writeFrame(connection, guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionAgentdRequest,
			RequestID: "health-1", Payload: json.RawMessage(`{"type":"health"}`),
		}, time.Now().Add(time.Second))
		response, err := readFrame(reader, connection, time.Now().Add(time.Second))
		if err != nil || response.Type != guestenrollment.NativeSessionAgentdResponse || response.RequestID != "health-1" {
			t.Errorf("relay response = %#v, %v", response, err)
			return
		}
		if call >= 3 {
			cancel()
			return
		}
		for {
			frame, err := readFrame(reader, connection, time.Now().Add(time.Second))
			if err != nil {
				return
			}
			if frame.Type == guestenrollment.NativeSessionPing {
				_ = writeFrame(connection, guestenrollment.NativeSessionMessage{
					ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionPong,
				}, time.Now().Add(time.Second))
			}
		}
	}
	runtime := newTestRuntime(t, work, agentdSocket, issuer, connector)
	runtime.Now = time.Now
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runtime failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("runtime did not reconnect and renew")
	}
	close(credentials)
	values := make([]string, 0, 3)
	for value := range credentials {
		values = append(values, value)
	}
	if len(values) < 3 || values[0] != values[1] || values[1] == values[2] {
		t.Fatalf("reconnect/renew credentials = %d same-first=%v renewed=%v", len(values), len(values) > 1 && values[0] == values[1], len(values) > 2 && values[1] != values[2])
	}
	issuer.mu.Lock()
	issueCalls := issuer.calls
	issuer.mu.Unlock()
	if issueCalls != 2 {
		t.Fatalf("credential issues = %d, want 2", issueCalls)
	}
	if _, err := os.Stat(filepath.Join(runtime.Configuration.RuntimeDirectory, ReadinessFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("session readiness remained after stop: %v", err)
	}
}

func TestFirstIssuanceResponseLossHasOneBoundedRetry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuer := &fakeIssuer{
		binding: testBinding(), now: now,
		errors: []error{fail(ReasonIdentityUnavailable, true, true)},
	}
	runtime := &Runtime{Identity: issuer, Now: func() time.Time { return now }}
	credential, err := runtime.issueCredential(context.Background())
	if err != nil || credential.Opaque == "" {
		t.Fatalf("response-loss recovery = %#v, %v", credential, err)
	}
	issuer.mu.Lock()
	calls := issuer.calls
	issuer.mu.Unlock()
	if calls != 2 {
		t.Fatalf("response-loss issue calls = %d", calls)
	}

	issuer = &fakeIssuer{
		binding: testBinding(), now: now,
		errors: []error{
			fail(ReasonIdentityUnavailable, true, true),
			fail(ReasonIdentityUnavailable, true, true),
		},
	}
	runtime.Identity = issuer
	if _, err := runtime.issueCredential(context.Background()); err == nil {
		t.Fatal("second ambiguous issuance was accepted")
	} else if _, temporary, uncertain := FailureDetails(err); temporary || !uncertain {
		t.Fatalf("second ambiguous issuance remained retryable: %v", err)
	}
	issuer.mu.Lock()
	calls = issuer.calls
	issuer.mu.Unlock()
	if calls != 2 {
		t.Fatalf("unbounded ambiguous issue calls = %d", calls)
	}
}

func TestCredentialScheduleRemainsBoundedAcrossClockRollback(t *testing.T) {
	issuedAt := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	local := time.Now()
	issuer := &fakeIssuer{binding: testBinding(), now: issuedAt}
	runtime := &Runtime{
		Identity: issuer, Now: func() time.Time { return issuedAt.Add(-time.Hour) },
		MonotonicNow: func() time.Time { return local },
	}
	result, err := issuer.Issue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := runtime.validateCredential(result)
	if err != nil {
		t.Fatalf("broker-valid window rejected after local rollback: %v", err)
	}
	if lifetime := credential.LocalExpiresAt.Sub(local); lifetime <= 0 || lifetime > guestenrollment.MaxGuestSessionCredentialLifetime {
		t.Fatalf("rollback extended local credential lifetime to %s", lifetime)
	}
	if renewal := credential.LocalRenewAt.Sub(local); renewal <= 0 || renewal > credentialRenewalAge+credentialRenewalJitter {
		t.Fatalf("rollback extended local renewal schedule to %s", renewal)
	}
	runtime.MonotonicNow = func() time.Time { return credential.LocalRenewAt }
	if !runtime.credentialRenewalDue(credential) {
		t.Fatal("monotonic schedule did not force renewal while wall clock remained behind")
	}
}

func TestGatewayDenialFailsClosedAndRemovesReadiness(t *testing.T) {
	work := t.TempDir()
	agentdSocket := filepath.Join(work, "agentd.sock")
	stopAgentd := serveFakeAgentd(t, agentdSocket)
	defer stopAgentd()
	binding := testBinding()
	issuer := &fakeIssuer{binding: binding, now: time.Now().UTC().Truncate(time.Second)}
	connector := &pipeConnector{handler: func(_ int, connection net.Conn) {
		defer connection.Close()
		reader := newFrameReader(connection)
		if _, err := readFrame(reader, connection, time.Now().Add(time.Second)); err != nil {
			return
		}
		_ = writeFrame(connection, guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionHelloReject, Reason: "unauthorized",
		}, time.Now().Add(time.Second))
	}}
	runtime := newTestRuntime(t, work, agentdSocket, issuer, connector)
	err := runtime.Run(context.Background())
	reason, temporary, _ := FailureDetails(err)
	if reason != ReasonGatewayDenied || temporary {
		t.Fatalf("gateway denial = %v", err)
	}
	if _, err := os.Stat(filepath.Join(runtime.Configuration.RuntimeDirectory, ReadinessFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readiness remained after denial: %v", err)
	}
}

func TestDuplicateGatewayRequestFailsClosed(t *testing.T) {
	work := t.TempDir()
	agentdSocket := filepath.Join(work, "agentd.sock")
	stopAgentd := serveFakeAgentd(t, agentdSocket)
	defer stopAgentd()
	binding := testBinding()
	issuer := &fakeIssuer{binding: binding, now: time.Now().UTC().Truncate(time.Second)}
	connector := &pipeConnector{handler: func(_ int, connection net.Conn) {
		defer connection.Close()
		reader := newFrameReader(connection)
		if _, err := readFrame(reader, connection, time.Now().Add(time.Second)); err != nil {
			return
		}
		_ = writeFrame(connection, guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionHelloAck,
			Binding: &binding, Audience: guestenrollment.NativeGuestControlAudience,
		}, time.Now().Add(time.Second))
		request := guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionAgentdRequest,
			RequestID: "duplicate", Payload: json.RawMessage(`{"type":"health"}`),
		}
		_ = writeFrame(connection, request, time.Now().Add(time.Second))
		_, _ = readFrame(reader, connection, time.Now().Add(time.Second))
		_ = writeFrame(connection, request, time.Now().Add(time.Second))
	}}
	runtime := newTestRuntime(t, work, agentdSocket, issuer, connector)
	err := runtime.Run(context.Background())
	reason, temporary, _ := FailureDetails(err)
	if reason != ReasonProtocolInvalid || temporary {
		t.Fatalf("duplicate request result = %v", err)
	}
	if _, err := os.Stat(filepath.Join(runtime.Configuration.RuntimeDirectory, ReadinessFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readiness remained after duplicate request: %v", err)
	}
}

func newTestRuntime(t *testing.T, work, agentdSocket string, issuer CredentialIssuer, connector Connector) *Runtime {
	t.Helper()
	runtimeDirectory := filepath.Join(work, "session-run")
	if err := os.Mkdir(runtimeDirectory, 0o750); err != nil {
		t.Fatal(err)
	}
	configuration := Configuration{
		Version: ConfigurationVersion, RuntimeDirectory: runtimeDirectory,
		IdentitySocketPath: filepath.Join(work, "identity.sock"), AgentdSocketPath: agentdSocket,
		GatewayEndpoint: "tls://gateway.test:443", CAPEMPath: filepath.Join(work, "gateway-ca.pem"),
	}
	runtime, err := NewRuntime(configuration, issuer, connector)
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func serveFakeAgentd(t *testing.T, path string) func() {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				line, _ := bufio.NewReader(connection).ReadBytes('\n')
				if len(line) != 0 {
					_, _ = connection.Write([]byte(`{"status":"ready"}` + "\n"))
				}
			}()
		}
	}()
	return func() {
		_ = listener.Close()
		<-done
	}
}

func testBinding() guestenrollment.Binding {
	return guestenrollment.Binding{
		AgentRunUID: "11111111-1111-1111-1111-111111111111", ExecutionID: "native-session-execution",
		DriverRegistration: "test-driver", DesiredGeneration: 1, GuestInstanceID: "native-session-guest",
	}
}
