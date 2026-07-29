package nativesession

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

type issuerFunc func(context.Context) (guestenrollment.GuestSessionIssueResult, error)

func (function issuerFunc) Issue(ctx context.Context) (guestenrollment.GuestSessionIssueResult, error) {
	return function(ctx)
}

func testIssueResult(binding guestenrollment.Binding, sequence uint64, issuedAt time.Time) guestenrollment.GuestSessionIssueResult {
	credential, _ := guestenrollment.GenerateGuestSessionCredential(sequence)
	return guestenrollment.GuestSessionIssueResult{
		ContractVersion: guestenrollment.GuestSessionIdentityVersion,
		Binding:         binding,
		Credential: guestenrollment.GuestSessionCredential{
			Type: guestenrollment.GuestSessionCredentialType, Opaque: credential,
			Audience: guestenrollment.NativeGuestControlAudience,
			IssuedAt: guestenrollment.FormatTimestamp(issuedAt), ExpiresAt: guestenrollment.FormatTimestamp(issuedAt.Add(5 * time.Minute)),
		},
	}
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
	issuer := &fakeIssuer{binding: binding, now: now}
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
	// Keep the authoritative wall clock fixed so the sub-second test renewal
	// window cannot already be due solely because protocol timestamps have
	// whole-second precision. Monotonic time still drives the planned renewal.
	runtime.Now = func() time.Time { return now }
	runtime.MonotonicNow = time.Now
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

func TestRenewalBrokerOutageKeepsReadySessionUntilReplacement(t *testing.T) {
	restoreFastRenewal(t)
	work := t.TempDir()
	agentdSocket := filepath.Join(work, "agentd.sock")
	stopAgentd := serveFakeAgentd(t, agentdSocket)
	defer stopAgentd()
	binding := testBinding()
	var mu sync.Mutex
	calls := 0
	renewalStarted := make(chan struct{})
	releaseRenewal := make(chan struct{})
	replacementHello := make(chan struct{})
	releaseReplacementAck := make(chan struct{})
	issuer := issuerFunc(func(_ context.Context) (guestenrollment.GuestSessionIssueResult, error) {
		mu.Lock()
		calls++
		call := calls
		mu.Unlock()
		switch call {
		case 1:
			return testIssueResult(binding, 1, time.Now().UTC().Truncate(time.Second)), nil
		case 2:
			close(renewalStarted)
			<-releaseRenewal
			return guestenrollment.GuestSessionIssueResult{}, fail(ReasonIdentityUnavailable, true, false)
		default:
			return testIssueResult(binding, uint64(call), time.Now().UTC().Truncate(time.Second)), nil
		}
	})
	connected := make(chan int, 4)
	connector := keepAliveConnectorBeforeAck(binding, connected, func(call int) {
		if call == 2 {
			close(replacementHello)
			<-releaseReplacementAck
		}
	})
	runtime := newTestRuntime(t, work, agentdSocket, issuer, connector)
	runtime.Now = time.Now
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	waitConnected(t, connected, 1)
	readinessPath := filepath.Join(runtime.Configuration.RuntimeDirectory, ReadinessFileName)
	select {
	case <-renewalStarted:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("renewal did not start")
	}
	if _, err := os.Stat(readinessPath); err != nil {
		cancel()
		t.Fatalf("renewal removed healthy readiness: %v", err)
	}
	close(releaseRenewal)
	select {
	case <-replacementHello:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("replacement hello did not start")
	}
	if _, err := os.Stat(readinessPath); err != nil {
		cancel()
		t.Fatalf("readiness disappeared before replacement authentication: %v", err)
	}
	close(releaseReplacementAck)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(readinessPath); err != nil {
			cancel()
			t.Fatalf("readiness disappeared before replacement: %v", err)
		}
		select {
		case call := <-connected:
			if call != 2 {
				t.Fatalf("replacement connection = %d", call)
			}
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			return
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("replacement session was not established")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRenewalResponseLossCapacityKeepsPredecessorAndNeverIssuesThird(t *testing.T) {
	restoreFastRenewal(t)
	work := t.TempDir()
	agentdSocket := filepath.Join(work, "agentd.sock")
	stopAgentd := serveFakeAgentd(t, agentdSocket)
	defer stopAgentd()
	binding := testBinding()
	var mu sync.Mutex
	calls := 0
	issuer := issuerFunc(func(_ context.Context) (guestenrollment.GuestSessionIssueResult, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		switch calls {
		case 1:
			return testIssueResult(binding, 1, time.Now().UTC().Truncate(time.Second)), nil
		case 2:
			return guestenrollment.GuestSessionIssueResult{}, fail(ReasonIdentityUnavailable, true, true)
		case 3:
			return guestenrollment.GuestSessionIssueResult{}, fail(ReasonIdentityUnavailable, true, false)
		default:
			return guestenrollment.GuestSessionIssueResult{}, fail(ReasonIdentityUnavailable, false, true)
		}
	})
	connected := make(chan int, 2)
	runtime := newTestRuntime(t, work, agentdSocket, issuer, keepAliveConnector(binding, connected))
	runtime.Now = time.Now
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	waitConnected(t, connected, 1)
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		observed := calls
		mu.Unlock()
		if observed == 3 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("response-loss recovery calls = %d", observed)
		}
		time.Sleep(time.Millisecond)
	}
	readinessPath := filepath.Join(runtime.Configuration.RuntimeDirectory, ReadinessFileName)
	if _, err := os.Stat(readinessPath); err != nil {
		cancel()
		t.Fatalf("uncertain renewal removed usable predecessor: %v", err)
	}
	time.Sleep(5 * renewalRetryDelay)
	mu.Lock()
	observed := calls
	mu.Unlock()
	if observed != 3 {
		cancel()
		t.Fatalf("renewal issued %d candidates after bounded response loss", observed)
	}
	if _, err := os.Stat(readinessPath); err != nil {
		cancel()
		t.Fatalf("predecessor readiness was not retained: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestHeartbeatProcessesQueuedRequestAndSimultaneousPing(t *testing.T) {
	originalProbe := idleProbeInterval
	idleProbeInterval = 20 * time.Millisecond
	t.Cleanup(func() { idleProbeInterval = originalProbe })
	work := t.TempDir()
	agentdSocket := filepath.Join(work, "agentd.sock")
	stopAgentd := serveFakeAgentd(t, agentdSocket)
	defer stopAgentd()
	binding := testBinding()
	issuer := &fakeIssuer{binding: binding, now: time.Now().UTC().Truncate(time.Second)}
	ctx, cancel := context.WithCancel(context.Background())
	connector := &pipeConnector{handler: func(_ int, connection net.Conn) {
		defer connection.Close()
		reader := newFrameReader(connection)
		hello, err := readFrame(reader, connection, time.Now().Add(time.Second))
		if err != nil || hello.Type != guestenrollment.NativeSessionHello {
			t.Errorf("hello = %#v, %v", hello, err)
			return
		}
		_ = writeFrame(connection, guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionHelloAck,
			Binding: &binding, Audience: guestenrollment.NativeGuestControlAudience,
		}, time.Now().Add(time.Second))
		ping, err := readFrame(reader, connection, time.Now().Add(time.Second))
		if err != nil || ping.Type != guestenrollment.NativeSessionPing {
			t.Errorf("client heartbeat = %#v, %v", ping, err)
			return
		}
		_ = writeFrame(connection, guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionAgentdRequest,
			RequestID: "queued-during-ping", Payload: json.RawMessage(`{"type":"health"}`),
		}, time.Now().Add(time.Second))
		response, err := readFrame(reader, connection, time.Now().Add(time.Second))
		if err != nil || response.Type != guestenrollment.NativeSessionAgentdResponse || response.RequestID != "queued-during-ping" {
			t.Errorf("queued response = %#v, %v", response, err)
			return
		}
		_ = writeFrame(connection, guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionPing,
		}, time.Now().Add(time.Second))
		pong, err := readFrame(reader, connection, time.Now().Add(time.Second))
		if err != nil || pong.Type != guestenrollment.NativeSessionPong {
			t.Errorf("simultaneous ping response = %#v, %v", pong, err)
			return
		}
		_ = writeFrame(connection, guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionPong,
		}, time.Now().Add(time.Second))
		cancel()
	}}
	runtime := newTestRuntime(t, work, agentdSocket, issuer, connector)
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("heartbeat collision did not converge")
	}
}

func TestHeartbeatBufferedRequestsRespectAbsoluteDeadline(t *testing.T) {
	originalProbe, originalFrame := idleProbeInterval, frameTimeout
	idleProbeInterval, frameTimeout = 10*time.Millisecond, 80*time.Millisecond
	t.Cleanup(func() { idleProbeInterval, frameTimeout = originalProbe, originalFrame })
	work := t.TempDir()
	agentdSocket := filepath.Join(work, "agentd.sock")
	stopAgentd := serveDelayedAgentd(t, agentdSocket, 2, 60*time.Millisecond)
	defer stopAgentd()
	binding := testBinding()
	issuer := &fakeIssuer{binding: binding, now: time.Now().UTC().Truncate(time.Second)}
	heartbeat := make(chan struct{})
	releaseQueued := make(chan struct{})
	connector := &pipeConnector{handler: func(_ int, connection net.Conn) {
		defer connection.Close()
		reader := newFrameReader(connection)
		hello, err := readFrame(reader, connection, time.Now().Add(time.Second))
		if err != nil || hello.Type != guestenrollment.NativeSessionHello {
			t.Errorf("hello = %#v, %v", hello, err)
			return
		}
		if err := writeFrame(connection, guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionHelloAck,
			Binding: &binding, Audience: guestenrollment.NativeGuestControlAudience,
		}, time.Now().Add(time.Second)); err != nil {
			t.Errorf("hello acknowledgment: %v", err)
			return
		}
		ping, err := readFrame(reader, connection, time.Now().Add(time.Second))
		if err != nil || ping.Type != guestenrollment.NativeSessionPing {
			t.Errorf("client heartbeat = %#v, %v", ping, err)
			return
		}
		close(heartbeat)
		<-releaseQueued
		var queued []byte
		for index := 1; index <= 2; index++ {
			encoded, encodeErr := guestenrollment.EncodeNativeSessionMessage(guestenrollment.NativeSessionMessage{
				ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionAgentdRequest,
				RequestID: fmt.Sprintf("buffered-%d", index), Payload: json.RawMessage(`{"type":"health"}`),
			})
			if encodeErr != nil {
				t.Errorf("encode queued request: %v", encodeErr)
				return
			}
			queued = append(queued, encoded...)
		}
		pong, encodeErr := guestenrollment.EncodeNativeSessionMessage(guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionPong,
		})
		if encodeErr != nil {
			t.Errorf("encode queued pong: %v", encodeErr)
			return
		}
		queued = append(queued, pong...)
		if _, err := connection.Write(queued); err != nil {
			return
		}
		_, _ = readFrame(reader, connection, time.Now().Add(time.Second))
	}}
	runtime := newTestRuntime(t, work, agentdSocket, issuer, connector)
	result, err := issuer.Issue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := runtime.validateCredential(result)
	if err != nil {
		t.Fatal(err)
	}
	state := &credentialState{current: &credential}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runtime.serveCredential(ctx, state) }()
	select {
	case <-heartbeat:
	case <-time.After(time.Second):
		t.Fatal("client heartbeat was not sent")
	}
	readinessPath := filepath.Join(runtime.Configuration.RuntimeDirectory, ReadinessFileName)
	if _, err := os.Stat(readinessPath); err != nil {
		t.Fatalf("session was not ready before heartbeat: %v", err)
	}
	started := time.Now()
	close(releaseQueued)
	select {
	case err := <-done:
		reason, temporary, _ := FailureDetails(err)
		if (reason != ReasonAgentdUnavailable && reason != ReasonGatewayUnavailable) || !temporary {
			t.Fatalf("buffered heartbeat result = %v", err)
		}
		if elapsed := time.Since(started); elapsed > frameTimeout+150*time.Millisecond {
			t.Fatalf("absolute heartbeat deadline overrun: %v", elapsed)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("buffered requests extended the heartbeat deadline")
	}
	if _, err := os.Stat(readinessPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readiness remained after heartbeat failure: %v", err)
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

func restoreFastRenewal(t *testing.T) {
	t.Helper()
	originalAge, originalRecovery, originalJitter := credentialRenewalAge, credentialRecoveryWindow, credentialRenewalJitter
	originalReconnect, originalRetry, originalProbe := reconnectDelay, renewalRetryDelay, idleProbeInterval
	credentialRenewalAge, credentialRecoveryWindow, credentialRenewalJitter = 40*time.Millisecond, 20*time.Millisecond, 0
	reconnectDelay, renewalRetryDelay, idleProbeInterval = 5*time.Millisecond, 10*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() {
		credentialRenewalAge, credentialRecoveryWindow, credentialRenewalJitter = originalAge, originalRecovery, originalJitter
		reconnectDelay, renewalRetryDelay, idleProbeInterval = originalReconnect, originalRetry, originalProbe
	})
}

func keepAliveConnector(binding guestenrollment.Binding, connected chan<- int) *pipeConnector {
	return keepAliveConnectorBeforeAck(binding, connected, nil)
}

func keepAliveConnectorBeforeAck(binding guestenrollment.Binding, connected chan<- int, beforeAck func(int)) *pipeConnector {
	connector := &pipeConnector{}
	connector.handler = func(call int, connection net.Conn) {
		defer connection.Close()
		reader := newFrameReader(connection)
		hello, err := readFrame(reader, connection, time.Now().Add(time.Second))
		if err != nil || hello.Type != guestenrollment.NativeSessionHello || hello.Binding == nil || *hello.Binding != binding {
			return
		}
		if beforeAck != nil {
			beforeAck(call)
		}
		if writeFrame(connection, guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionHelloAck,
			Binding: &binding, Audience: guestenrollment.NativeGuestControlAudience,
		}, time.Now().Add(time.Second)) != nil {
			return
		}
		connected <- call
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
	return connector
}

func waitConnected(t *testing.T, connected <-chan int, want int) {
	t.Helper()
	select {
	case call := <-connected:
		if call != want {
			t.Fatalf("connection = %d, want %d", call, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("connection %d was not established", want)
	}
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

func serveDelayedAgentd(t *testing.T, path string, immediate int, delay time.Duration) func() {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	calls := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			calls++
			call := calls
			mu.Unlock()
			go func() {
				defer connection.Close()
				line, _ := bufio.NewReader(connection).ReadBytes('\n')
				if len(line) == 0 {
					return
				}
				if call > immediate {
					time.Sleep(delay)
				}
				_, _ = connection.Write([]byte(`{"status":"ready"}` + "\n"))
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
