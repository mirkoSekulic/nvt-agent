package nativesession

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/workspacetunnel"
)

const (
	testControlEndpoint   = "tls://control.gateway.test:7443"
	testWorkspaceEndpoint = "tls://workspace.gateway.test:7444"
)

type workspacePipeConnector struct {
	mu               sync.Mutex
	controlCalls     int
	workspaceCalls   int
	controlHandler   func(int, net.Conn)
	workspaceHandler func(int, net.Conn)
}

func (connector *workspacePipeConnector) Connect(_ context.Context, endpoint string) (net.Conn, error) {
	client, server := net.Pipe()
	connector.mu.Lock()
	var call int
	var handler func(int, net.Conn)
	switch endpoint {
	case testControlEndpoint:
		connector.controlCalls++
		call, handler = connector.controlCalls, connector.controlHandler
	case testWorkspaceEndpoint:
		connector.workspaceCalls++
		call, handler = connector.workspaceCalls, connector.workspaceHandler
	default:
		connector.mu.Unlock()
		_ = client.Close()
		_ = server.Close()
		return nil, fail(ReasonConfiguration, false, false)
	}
	connector.mu.Unlock()
	if handler == nil {
		_ = client.Close()
		_ = server.Close()
		return nil, fail(ReasonGatewayUnavailable, true, false)
	}
	go handler(call, server)
	return client, nil
}

type workspaceAuthenticator struct {
	binding     guestenrollment.Binding
	credentials chan<- string
	err         error
}

func (authenticator workspaceAuthenticator) AuthenticateWorkspace(_ context.Context, credential string, binding guestenrollment.Binding) (workspacetunnel.Authentication, error) {
	if binding != authenticator.binding {
		return workspacetunnel.Authentication{}, workspacetunnel.ErrAuthenticationDenied
	}
	sequence, err := guestenrollment.GuestSessionCredentialSequence(credential)
	if err != nil {
		return workspacetunnel.Authentication{}, workspacetunnel.ErrAuthenticationDenied
	}
	if authenticator.credentials != nil {
		authenticator.credentials <- credential
	}
	if authenticator.err != nil {
		return workspacetunnel.Authentication{}, authenticator.err
	}
	now := time.Now()
	return workspacetunnel.Authentication{
		Binding: binding, Sequence: sequence, IssuedAt: now, ExpiresAt: now.Add(guestenrollment.MaxGuestSessionCredentialLifetime),
	}, nil
}

func TestWorkspaceRuntimeUsesSameCredentialAndForwardsFixedHTTPAndUpgrade(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/upgrade" {
			_, _ = io.WriteString(response, "workspace-ok")
			return
		}
		connection, buffer, err := response.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: nvt-test\r\n\r\n")
		_ = buffer.Flush()
		line, err := buffer.ReadString('\n')
		if err == nil {
			_, _ = buffer.WriteString("echo:" + line)
			_ = buffer.Flush()
		}
	}))
	defer backend.Close()

	work := t.TempDir()
	agentdSocket := filepath.Join(work, "agentd.sock")
	stopAgentd := serveFakeAgentd(t, agentdSocket)
	defer stopAgentd()
	binding := testBinding()
	now := time.Now().UTC().Truncate(time.Second)
	issuer := &fakeIssuer{binding: binding, now: now}
	controlCredentials := make(chan string, 2)
	workspaceCredentials := make(chan string, 2)
	workspaceSessions := make(chan *workspacetunnel.GatewaySession, 2)
	connector := &workspacePipeConnector{}
	connector.controlHandler = keepWorkspaceControlGateway(binding, controlCredentials)
	connector.workspaceHandler = keepWorkspaceGateway(t, binding, workspaceCredentials, workspaceSessions)
	runtime := newWorkspaceTestRuntime(t, work, agentdSocket, strings.TrimPrefix(backend.URL, "http://"), issuer, connector)
	runtime.Now = func() time.Time { return now }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()

	gateway := waitWorkspaceSession(t, workspaceSessions)
	waitForSessionReadiness(t, runtime.Configuration.RuntimeDirectory)
	controlCredential := waitString(t, controlCredentials, "control credential")
	workspaceCredential := waitString(t, workspaceCredentials, "workspace credential")
	if controlCredential == "" || controlCredential != workspaceCredential {
		cancel()
		t.Fatal("control and workspace did not authenticate with the same credential")
	}
	controlSequence, controlSequenceErr := guestenrollment.GuestSessionCredentialSequence(controlCredential)
	workspaceSequence, workspaceSequenceErr := guestenrollment.GuestSessionCredentialSequence(workspaceCredential)
	if controlSequenceErr != nil || workspaceSequenceErr != nil || controlSequence == 0 || controlSequence != workspaceSequence {
		cancel()
		t.Fatal("control and workspace did not authenticate with the same issuance sequence")
	}
	for _, rendered := range []string{
		fmt.Sprint(runtime.Configuration), fmt.Sprintf("%#v", runtime.Configuration),
		fmt.Sprint(gateway), fmt.Sprintf("%#v", gateway),
	} {
		if strings.Contains(rendered, controlCredential) {
			cancel()
			t.Fatal("session credential entered ordinary formatting")
		}
	}

	stream, err := gateway.OpenStream(t.Context())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, "http://workspace.invalid/", nil)
	if err := request.Write(stream); err != nil {
		cancel()
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(stream), request)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	_ = stream.Close()
	if err != nil || string(body) != "workspace-ok" {
		cancel()
		t.Fatalf("workspace HTTP body=%q error=%v", body, err)
	}

	upgrade, err := gateway.OpenStream(t.Context())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	_, _ = io.WriteString(upgrade, "GET /upgrade HTTP/1.1\r\nHost: workspace.invalid\r\nConnection: Upgrade\r\nUpgrade: nvt-test\r\n\r\n")
	reader := bufio.NewReader(upgrade)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		cancel()
		t.Fatalf("upgrade status=%q error=%v", status, err)
	}
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			cancel()
			t.Fatal(readErr)
		}
		if line == "\r\n" {
			break
		}
	}
	_, _ = io.WriteString(upgrade, "bidirectional\n")
	echo, err := reader.ReadString('\n')
	_ = upgrade.Close()
	if err != nil || echo != "echo:bidirectional\n" {
		cancel()
		t.Fatalf("upgrade echo=%q error=%v", echo, err)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(runtime.Configuration.RuntimeDirectory, ReadinessFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readiness remained after shutdown: %v", err)
	}
	if _, err := gateway.OpenStream(t.Context()); !errors.Is(err, workspacetunnel.ErrUnavailable) {
		t.Fatalf("workspace remained open after shutdown: %v", err)
	}
	issuer.mu.Lock()
	issueCalls := issuer.calls
	issuer.mu.Unlock()
	if issueCalls != 1 {
		t.Fatalf("workspace caused %d credential issues", issueCalls)
	}
	entries, err := os.ReadDir(runtime.Configuration.RuntimeDirectory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("runtime retained ordinary or sensitive state: entries=%d error=%v", len(entries), err)
	}
}

func TestWorkspaceTemporaryDisconnectReusesCurrentCredential(t *testing.T) {
	backend := startWorkspaceEchoBackend(t)
	work := t.TempDir()
	agentdSocket := filepath.Join(work, "agentd.sock")
	stopAgentd := serveFakeAgentd(t, agentdSocket)
	defer stopAgentd()
	binding := testBinding()
	now := time.Now().UTC().Truncate(time.Second)
	issuer := &fakeIssuer{binding: binding, now: now}
	controlCredentials := make(chan string, 4)
	workspaceCredentials := make(chan string, 4)
	workspaceSessions := make(chan *workspacetunnel.GatewaySession, 4)
	workspaceConnections := make(chan net.Conn, 4)
	workspaceHandler := keepWorkspaceGateway(t, binding, workspaceCredentials, workspaceSessions)
	connector := &workspacePipeConnector{
		controlHandler: keepWorkspaceControlGateway(binding, controlCredentials),
		workspaceHandler: func(call int, connection net.Conn) {
			workspaceConnections <- connection
			workspaceHandler(call, connection)
		},
	}
	runtime := newWorkspaceTestRuntime(t, work, agentdSocket, backend, issuer, connector)
	runtime.Now = func() time.Time { return now }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	_ = waitWorkspaceSession(t, workspaceSessions)
	waitForSessionReadiness(t, runtime.Configuration.RuntimeDirectory)
	firstControl := waitString(t, controlCredentials, "first control credential")
	firstWorkspace := waitString(t, workspaceCredentials, "first workspace credential")
	if firstControl != firstWorkspace {
		cancel()
		t.Fatal("initial control/workspace credentials differ")
	}
	_ = (<-workspaceConnections).Close()
	second := waitWorkspaceSession(t, workspaceSessions)
	<-workspaceConnections
	secondControl := waitString(t, controlCredentials, "reconnected control credential")
	secondWorkspace := waitString(t, workspaceCredentials, "reconnected workspace credential")
	if secondControl != firstControl || secondWorkspace != firstControl {
		cancel()
		t.Fatal("temporary reconnect did not reuse the current credential")
	}
	waitForSessionReadiness(t, runtime.Configuration.RuntimeDirectory)
	assertWorkspaceEcho(t, second, "reconnected")
	issuer.mu.Lock()
	issueCalls := issuer.calls
	issuer.mu.Unlock()
	if issueCalls != 1 {
		cancel()
		t.Fatalf("temporary reconnect issued %d credentials", issueCalls)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceRenewalSwitchesOnlyAfterBothPendingLegsReady(t *testing.T) {
	restoreFastRenewal(t)
	backend := startWorkspaceEchoBackend(t)
	work := t.TempDir()
	agentdSocket := filepath.Join(work, "agentd.sock")
	stopAgentd := serveFakeAgentd(t, agentdSocket)
	defer stopAgentd()
	binding := testBinding()
	now := time.Now().UTC().Truncate(time.Second)
	issuer := &fakeIssuer{binding: binding, now: now}
	controlCredentials := make(chan string, 8)
	workspaceCredentials := make(chan string, 8)
	workspaceSessions := make(chan *workspacetunnel.GatewaySession, 4)
	failedPendingWorkspace := make(chan struct{})
	connector := &workspacePipeConnector{controlHandler: keepWorkspaceControlGateway(binding, controlCredentials)}
	connector.workspaceHandler = func(call int, connection net.Conn) {
		if call == 2 {
			defer connection.Close()
			_, _ = workspacetunnel.Accept(t.Context(), connection, workspaceAuthenticator{
				binding: binding, credentials: workspaceCredentials, err: workspacetunnel.ErrAuthenticationTemporary,
			})
			close(failedPendingWorkspace)
			return
		}
		keepWorkspaceGateway(t, binding, workspaceCredentials, workspaceSessions)(call, connection)
	}
	runtime := newWorkspaceTestRuntime(t, work, agentdSocket, backend, issuer, connector)
	runtime.Now = func() time.Time { return now }
	runtime.MonotonicNow = time.Now
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	first := waitWorkspaceSession(t, workspaceSessions)
	waitForSessionReadiness(t, runtime.Configuration.RuntimeDirectory)
	initialControl := waitString(t, controlCredentials, "initial control credential")
	initialWorkspace := waitString(t, workspaceCredentials, "initial workspace credential")
	if initialControl != initialWorkspace {
		cancel()
		t.Fatal("initial pair did not share a credential")
	}
	select {
	case <-failedPendingWorkspace:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("pending workspace failure was not exercised")
	}
	if _, err := os.Stat(filepath.Join(runtime.Configuration.RuntimeDirectory, ReadinessFileName)); err != nil {
		cancel()
		t.Fatalf("one-leg pending failure removed current readiness: %v", err)
	}
	assertWorkspaceEcho(t, first, "predecessor-still-ready")
	failedControl := waitString(t, controlCredentials, "failed replacement control credential")
	failedWorkspace := waitString(t, workspaceCredentials, "failed replacement workspace credential")
	if failedControl == initialControl || failedControl != failedWorkspace {
		cancel()
		t.Fatal("pending replacement did not use one new credential on both legs")
	}

	replacement := waitWorkspaceSession(t, workspaceSessions)
	retriedControl := waitString(t, controlCredentials, "retried replacement control credential")
	retriedWorkspace := waitString(t, workspaceCredentials, "retried replacement workspace credential")
	if retriedControl != failedControl || retriedWorkspace != failedControl {
		cancel()
		t.Fatal("one-leg retry issued or used a different pending credential")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		stream, err := first.OpenStream(t.Context())
		if errors.Is(err, workspacetunnel.ErrUnavailable) {
			break
		}
		if stream != nil {
			_ = stream.Close()
		}
		time.Sleep(time.Millisecond)
	}
	stream, err := first.OpenStream(t.Context())
	if stream != nil {
		_ = stream.Close()
	}
	if !errors.Is(err, workspacetunnel.ErrUnavailable) {
		cancel()
		t.Fatalf("predecessor remained active after complete replacement: %v", err)
	}
	waitForSessionReadiness(t, runtime.Configuration.RuntimeDirectory)
	assertWorkspaceEcho(t, replacement, "replacement-ready")
	issuer.mu.Lock()
	issueCalls := issuer.calls
	issuer.mu.Unlock()
	if issueCalls != 2 {
		cancel()
		t.Fatalf("one-leg retry issued %d credentials", issueCalls)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceMalformedAckAndUnavailableDestinationFailClosed(t *testing.T) {
	for _, test := range []struct {
		name      string
		handler   func(guestenrollment.Binding, net.Conn)
		loopback  func(*testing.T) string
		reason    Reason
		temporary bool
	}{
		{
			name: "malformed acknowledgement",
			handler: func(_ guestenrollment.Binding, connection net.Conn) {
				defer connection.Close()
				_, _ = bufio.NewReader(connection).ReadBytes('\n')
				_, _ = io.WriteString(connection, "{}\n")
			},
			loopback: startWorkspaceEchoBackend, reason: ReasonProtocolInvalid,
		},
		{
			name: "unavailable fixed destination",
			handler: func(binding guestenrollment.Binding, connection net.Conn) {
				credentials := make(chan string, 1)
				sessions := make(chan *workspacetunnel.GatewaySession, 1)
				keepWorkspaceGateway(t, binding, credentials, sessions)(1, connection)
			},
			loopback: unavailableWorkspaceEndpoint, reason: ReasonGatewayUnavailable, temporary: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			work := t.TempDir()
			agentdSocket := filepath.Join(work, "agentd.sock")
			stopAgentd := serveFakeAgentd(t, agentdSocket)
			defer stopAgentd()
			binding := testBinding()
			now := time.Now().UTC().Truncate(time.Second)
			issuer := &fakeIssuer{binding: binding, now: now}
			connector := &workspacePipeConnector{controlHandler: keepWorkspaceControlGateway(binding, make(chan string, 1))}
			connector.workspaceHandler = func(_ int, connection net.Conn) { test.handler(binding, connection) }
			runtime := newWorkspaceTestRuntime(t, work, agentdSocket, test.loopback(t), issuer, connector)
			runtime.Now = func() time.Time { return now }
			credential, err := runtime.issueCredential(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			pair, err := runtime.openCredentialPair(t.Context(), credential)
			if pair != nil {
				pair.Close()
				t.Fatal("invalid workspace pair became ready")
			}
			reason, temporary, _ := FailureDetails(err)
			if reason != test.reason || temporary != test.temporary {
				t.Fatalf("workspace failure=%v reason=%s temporary=%v", err, reason, temporary)
			}
			if _, err := os.Stat(filepath.Join(runtime.Configuration.RuntimeDirectory, ReadinessFileName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("workspace failure published readiness: %v", err)
			}
		})
	}
}

func TestWorkspaceCredentialExpiryRemovesReadinessAndClosesPair(t *testing.T) {
	backend := startWorkspaceEchoBackend(t)
	work := t.TempDir()
	agentdSocket := filepath.Join(work, "agentd.sock")
	stopAgentd := serveFakeAgentd(t, agentdSocket)
	defer stopAgentd()
	binding := testBinding()
	workspaceSessions := make(chan *workspacetunnel.GatewaySession, 1)
	connector := &workspacePipeConnector{
		controlHandler:   keepWorkspaceControlGateway(binding, make(chan string, 1)),
		workspaceHandler: keepWorkspaceGateway(t, binding, make(chan string, 1), workspaceSessions),
	}
	runtime := newWorkspaceTestRuntime(t, work, agentdSocket, backend, &fakeIssuer{}, connector)
	runtime.Now = time.Now
	runtime.MonotonicNow = time.Now
	now := time.Now()
	opaque, err := guestenrollment.GenerateGuestSessionCredential(1)
	if err != nil {
		t.Fatal(err)
	}
	state := &credentialState{current: &sessionCredential{
		Binding: binding, Opaque: opaque, IssuedAt: now, ExpiresAt: now.Add(150 * time.Millisecond),
		RenewAt: now.Add(time.Hour), LocalExpiresAt: now.Add(150 * time.Millisecond), LocalRenewAt: now.Add(time.Hour),
	}, renewalUncertain: true}
	done := make(chan error, 1)
	go func() {
		err := runtime.serveCredential(t.Context(), state)
		state.clear()
		done <- err
	}()
	gateway := waitWorkspaceSession(t, workspaceSessions)
	waitForSessionReadiness(t, runtime.Configuration.RuntimeDirectory)
	select {
	case err := <-done:
		reason, temporary, _ := FailureDetails(err)
		if reason != ReasonCredentialExpired || temporary {
			t.Fatalf("workspace expiry result=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("workspace pair did not stop at credential expiry")
	}
	if state.current != nil || state.pending != nil {
		t.Fatal("expired workspace lifecycle retained credential state")
	}
	if _, err := os.Stat(filepath.Join(runtime.Configuration.RuntimeDirectory, ReadinessFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readiness remained after workspace credential expiry: %v", err)
	}
	if _, err := gateway.OpenStream(t.Context()); !errors.Is(err, workspacetunnel.ErrUnavailable) {
		t.Fatalf("workspace remained open after credential expiry: %v", err)
	}
}

func newWorkspaceTestRuntime(t *testing.T, work, agentdSocket, loopback string, issuer CredentialIssuer, connector Connector) *Runtime {
	t.Helper()
	runtime := newTestRuntime(t, work, agentdSocket, issuer, connector)
	runtime.Configuration.GatewayEndpoint = testControlEndpoint
	runtime.Configuration.Workspace = &WorkspaceConfiguration{
		GatewayEndpoint: testWorkspaceEndpoint, LoopbackEndpoint: loopback,
	}
	if validateConfiguration(runtime.Configuration) != nil {
		t.Fatal("workspace test configuration is invalid")
	}
	return runtime
}

func keepWorkspaceControlGateway(binding guestenrollment.Binding, credentials chan<- string) func(int, net.Conn) {
	return func(_ int, connection net.Conn) {
		defer connection.Close()
		reader := newFrameReader(connection)
		hello, err := readFrame(reader, connection, time.Now().Add(time.Second))
		if err != nil || hello.Type != guestenrollment.NativeSessionHello || hello.Binding == nil || *hello.Binding != binding {
			return
		}
		credentials <- hello.Credential
		if writeFrame(connection, guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionHelloAck,
			Binding: &binding, Audience: guestenrollment.NativeGuestControlAudience,
		}, time.Now().Add(time.Second)) != nil {
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
}

func keepWorkspaceGateway(t *testing.T, binding guestenrollment.Binding, credentials chan<- string, sessions chan<- *workspacetunnel.GatewaySession) func(int, net.Conn) {
	t.Helper()
	return func(_ int, connection net.Conn) {
		authentication, err := workspacetunnel.Accept(t.Context(), connection, workspaceAuthenticator{binding: binding, credentials: credentials})
		if err != nil {
			_ = connection.Close()
			return
		}
		session, err := workspacetunnel.NewGatewaySession(connection, authentication)
		if err != nil {
			_ = connection.Close()
			return
		}
		sessions <- session
	}
}

func waitWorkspaceSession(t *testing.T, sessions <-chan *workspacetunnel.GatewaySession) *workspacetunnel.GatewaySession {
	t.Helper()
	select {
	case session := <-sessions:
		return session
	case <-time.After(workspacetunnel.StreamCloseTimeout + 2*time.Second):
		t.Fatal("workspace session was not established")
		return nil
	}
}

func waitString(t *testing.T, values <-chan string, name string) string {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(2 * time.Second):
		t.Fatalf("%s was not observed", name)
		return ""
	}
}

func waitForSessionReadiness(t *testing.T, runtimeDirectory string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(filepath.Join(runtimeDirectory, ReadinessFileName)); err == nil && info.Mode().IsRegular() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("native control/workspace pair did not become ready")
}

func startWorkspaceEchoBackend(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	return listener.Addr().String()
}

func unavailableWorkspaceEndpoint(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := listener.Addr().String()
	_ = listener.Close()
	return endpoint
}

func assertWorkspaceEcho(t *testing.T, session *workspacetunnel.GatewaySession, value string) {
	t.Helper()
	stream, err := session.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(stream, value); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(value))
	if _, err := io.ReadFull(stream, response); err != nil || string(response) != value {
		t.Fatalf("workspace echo=%q error=%v", response, err)
	}
}
