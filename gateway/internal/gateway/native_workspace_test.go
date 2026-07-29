package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/workspacetunnel"
)

type fakeWorkspaceAuthenticator struct {
	mu       sync.Mutex
	result   workspacetunnel.Authentication
	err      error
	calls    int
	canaries []string
}

func (authenticator *fakeWorkspaceAuthenticator) AuthenticateWorkspace(_ context.Context, credential string, binding guestenrollment.Binding) (workspacetunnel.Authentication, error) {
	authenticator.mu.Lock()
	defer authenticator.mu.Unlock()
	authenticator.calls++
	authenticator.canaries = append(authenticator.canaries, credential)
	result := authenticator.result
	result.Binding = binding
	return result, authenticator.err
}

func (authenticator *fakeWorkspaceAuthenticator) setSequence(sequence uint64) {
	authenticator.mu.Lock()
	authenticator.result.Sequence = sequence
	authenticator.mu.Unlock()
}

func (authenticator *fakeWorkspaceAuthenticator) snapshot() (int, []string) {
	authenticator.mu.Lock()
	defer authenticator.mu.Unlock()
	return authenticator.calls, append([]string(nil), authenticator.canaries...)
}

func TestNativeWorkspaceConfigValidation(t *testing.T) {
	server, err := NewNativeWorkspaceServer(NativeWorkspaceConfig{}, NativeSessionConfig{})
	if err != nil || server != nil {
		t.Fatalf("disabled server=%v error=%v", server, err)
	}
	native := NativeSessionConfig{Enabled: true}
	for name, config := range map[string]NativeWorkspaceConfig{
		"missing native session": {Enabled: true, ListenAddr: ":7444"},
		"missing port":           {Enabled: true, ListenAddr: "localhost"},
		"zero port":              {Enabled: true, ListenAddr: ":0"},
	} {
		t.Run(name, func(t *testing.T) {
			parent := native
			if name == "missing native session" {
				parent.Enabled = false
			}
			if err := config.validate(parent); err == nil {
				t.Fatal("invalid native workspace configuration accepted")
			}
		})
	}
	if err := (NativeWorkspaceConfig{}).validate(NativeSessionConfig{}); err != nil {
		t.Fatalf("disabled configuration: %v", err)
	}
	if err := (NativeWorkspaceConfig{Enabled: true, ListenAddr: ":7444"}).validate(native); err != nil {
		t.Fatalf("valid configuration: %v", err)
	}
	base := Config{
		BaseDomain: "agents.test", ListenAddr: ":8080", DefaultTargetPort: 4090,
		NativeSession: NativeSessionConfig{
			Enabled: true, ListenAddr: ":7443", TLSCertificateFile: "/run/tls.crt", TLSKeyFile: "/run/tls.key",
			BrokerURL: "https://broker.test:7347", BrokerServerName: "broker.test", BrokerCAFile: "/run/ca.crt",
			AuthenticationTimeout: time.Second, RevalidationInterval: 30 * time.Second,
		},
		NativeWorkspace: NativeWorkspaceConfig{Enabled: true, ListenAddr: ":7444"},
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid combined configuration: %v", err)
	}
	for _, address := range []string{":8080", ":7443"} {
		value := base
		value.NativeWorkspace.ListenAddr = address
		if err := value.Validate(); err == nil {
			t.Fatalf("colliding workspace address %q accepted", address)
		}
	}
}

func TestNativeWorkspaceTLSAuthenticationLookupAndRevalidation(t *testing.T) {
	binding := nativeSessionTestBinding()
	credential := nativeSessionTestCredential(7)
	now := time.Now().UTC()
	authenticator := &fakeWorkspaceAuthenticator{result: workspacetunnel.Authentication{
		Sequence: 7, IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute),
	}}
	server, address, roots := startNativeWorkspaceTestServer(t, authenticator, 180*time.Millisecond)
	forwarder, connection := connectNativeWorkspaceTestGuest(t, address, roots, binding, credential)
	defer connection.Close()
	defer forwarder.Close()

	stream := waitForWorkspaceStream(t, server.Registry(), binding)
	if stream.Sequence() != 7 || stream.Binding() != binding {
		t.Fatalf("stream metadata binding=%#v sequence=%d", stream.Binding(), stream.Sequence())
	}
	opened, err := stream.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := opened.Write([]byte("workspace-echo")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("workspace-echo"))
	if _, err := io.ReadFull(opened, response); err != nil {
		t.Fatal(err)
	}
	_ = opened.Close()
	if string(response) != "workspace-echo" {
		t.Fatalf("echo response=%q", response)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, ok := server.Registry().Lookup(binding); !ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ok := server.Registry().Lookup(binding); ok {
		t.Fatal("expired local trust remained in registry")
	}
	calls, canaries := authenticator.snapshot()
	if calls != 1 || canaries[0] != credential {
		t.Fatalf("authentication calls=%d", calls)
	}
	if server.String() != "[native workspace server]" || server.Registry().(*nativeWorkspaceStreams).String() != "[native workspace streams]" {
		t.Fatal("sanitized formatting changed")
	}
}

func TestNativeWorkspaceActiveStandbyPromotion(t *testing.T) {
	binding := nativeSessionTestBinding()
	now := time.Now().UTC()
	authenticator := &fakeWorkspaceAuthenticator{result: workspacetunnel.Authentication{
		IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute),
	}}
	server, address, roots := startNativeWorkspaceTestServer(t, authenticator, 30*time.Second)

	authenticator.setSequence(10)
	active, activeConn := connectNativeWorkspaceTestGuest(t, address, roots, binding, nativeSessionTestCredential(10))
	defer active.Close()
	if stream := waitForWorkspaceStream(t, server.Registry(), binding); stream.Sequence() != 10 {
		t.Fatal("initial workspace session was not active")
	}
	authenticator.setSequence(11)
	standby, standbyConn := connectNativeWorkspaceTestGuest(t, address, roots, binding, nativeSessionTestCredential(11))
	defer standby.Close()
	if stream := waitForWorkspaceStream(t, server.Registry(), binding); stream.Sequence() != 10 {
		t.Fatal("newer standby preempted active")
	}

	authenticator.setSequence(12)
	thirdTLS := dialNativeWorkspaceTest(t, address, roots)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	err := workspacetunnel.Establish(ctx, thirdTLS, binding, nativeSessionTestCredential(12))
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	_ = thirdTLS.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := thirdTLS.Read(make([]byte, 1)); err == nil {
		t.Fatal("third connection remained open")
	}
	_ = thirdTLS.Close()

	_ = activeConn.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if stream, ok := server.Registry().Lookup(binding); ok && stream.Sequence() == 11 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if stream, ok := server.Registry().Lookup(binding); !ok || stream.Sequence() != 11 {
		t.Fatal("ready standby was not promoted")
	}
	_ = standbyConn.Close()
}

func TestNativeWorkspaceAuthorityOutcomesAreSafe(t *testing.T) {
	binding := nativeSessionTestBinding()
	credential := nativeSessionTestCredential(3)
	for name, authorityError := range map[string]error{
		"definitive": workspacetunnel.ErrAuthenticationDenied,
		"temporary":  workspacetunnel.ErrAuthenticationTemporary,
	} {
		t.Run(name, func(t *testing.T) {
			authenticator := &fakeWorkspaceAuthenticator{err: authorityError}
			_, address, roots := startNativeWorkspaceTestServer(t, authenticator, time.Second)
			connection := dialNativeWorkspaceTest(t, address, roots)
			defer connection.Close()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			err := workspacetunnel.Establish(ctx, connection, binding, credential)
			cancel()
			if name == "definitive" && !errors.Is(err, workspacetunnel.ErrDenied) {
				t.Fatalf("definitive error=%v", err)
			}
			if name == "temporary" && !errors.Is(err, workspacetunnel.ErrUnavailable) {
				t.Fatalf("temporary error=%v", err)
			}
			if err != nil && strings.Contains(err.Error(), credential) {
				t.Fatal("authentication error disclosed credential")
			}
		})
	}
}

func TestNativeWorkspacePreAuthenticationCapacityAndDeadline(t *testing.T) {
	previous := nativeWorkspaceTLSHandshakeLimit
	nativeWorkspaceTLSHandshakeLimit = 100 * time.Millisecond
	t.Cleanup(func() { nativeWorkspaceTLSHandshakeLimit = previous })
	now := time.Now().UTC()
	authenticator := &fakeWorkspaceAuthenticator{result: workspacetunnel.Authentication{
		Sequence: 1, IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute),
	}}
	server, address, roots := startNativeWorkspaceTestServer(t, authenticator, time.Second)
	connections := make([]net.Conn, 0, maxNativeWorkspacePendingHandshakes)
	for range maxNativeWorkspacePendingHandshakes {
		connection, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
	}
	deadline := time.Now().Add(time.Second)
	for len(server.handshakeSlots) != maxNativeWorkspacePendingHandshakes && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(server.handshakeSlots) != maxNativeWorkspacePendingHandshakes {
		t.Fatalf("occupied handshakes=%d", len(server.handshakeSlots))
	}
	dialer := &net.Dialer{Timeout: time.Second}
	if connection, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "gateway.test"}); err == nil {
		connection.Close()
		t.Fatal("connection beyond pre-authentication capacity succeeded")
	}
	for _, connection := range connections {
		defer connection.Close()
	}
	deadline = time.Now().Add(time.Second)
	for len(server.handshakeSlots) != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(server.handshakeSlots) != 0 {
		t.Fatalf("handshake slots were not released: %d", len(server.handshakeSlots))
	}
	forwarder, connection := connectNativeWorkspaceTestGuest(t, address, roots, nativeSessionTestBinding(), nativeSessionTestCredential(1))
	forwarder.Close()
	connection.Close()
}

func startNativeWorkspaceTestServer(t *testing.T, authenticator workspacetunnel.Authenticator, revalidation time.Duration) (*NativeWorkspaceServer, string, *x509.CertPool) {
	t.Helper()
	certificate, roots := nativeSessionTestCertificate(t, "gateway.test")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := newNativeWorkspaceServer(NativeWorkspaceConfig{Enabled: true, ListenAddr: listener.Addr().String()}, revalidation,
		&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}, authenticator)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("native workspace server: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("native workspace server did not stop")
		}
	})
	return server, listener.Addr().String(), roots
}

func connectNativeWorkspaceTestGuest(t *testing.T, address string, roots *x509.CertPool, binding guestenrollment.Binding, credential string) (*workspacetunnel.GuestForwarder, net.Conn) {
	t.Helper()
	connection := dialNativeWorkspaceTest(t, address, roots)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	if err := workspacetunnel.Establish(ctx, connection, binding, credential); err != nil {
		cancel()
		connection.Close()
		t.Fatal(err)
	}
	cancel()
	forwarder, err := workspacetunnel.NewGuestForwarder(connection, binding, time.Now().Add(time.Minute), startWorkspaceEchoServer(t))
	if err != nil {
		connection.Close()
		t.Fatal(err)
	}
	go func() { _ = forwarder.Serve(t.Context()) }()
	return forwarder, connection
}

func dialNativeWorkspaceTest(t *testing.T, address string, roots *x509.CertPool) net.Conn {
	t.Helper()
	dialer := &net.Dialer{Timeout: time.Second}
	connection, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "gateway.test"})
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func waitForWorkspaceStream(t *testing.T, registry NativeWorkspaceStreams, binding guestenrollment.Binding) workspacetunnel.StreamOpener {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if stream, ok := registry.Lookup(binding); ok {
			return stream
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("workspace stream did not become active")
	return nil
}

func startWorkspaceEchoServer(t *testing.T) string {
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
