package nativeegress

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

func TestRuntimeComposesPurposeOnlyIPCWithStrictTLSRelay(t *testing.T) {
	certificateSource := httptest.NewTLSServer(http.NotFoundHandler())
	serverTLS := certificateSource.TLS.Clone()
	serverTLS.MinVersion = tls.VersionTLS12
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateSource.Certificate().Raw})
	certificateSource.Close()

	directory, err := os.MkdirTemp("/tmp", "nvt-ne-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	binding := nativeEgressBinding()
	now := time.Now().UTC().Truncate(time.Second)
	credentialValue, err := guestenrollment.GenerateNativeEgressCredential(1)
	if err != nil {
		t.Fatal(err)
	}

	identitySocket := filepath.Join(directory, "i.sock")
	identityListener, err := net.Listen("unix", identitySocket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityListener.Close() })
	identityRequest := make(chan []byte, 1)
	go func() {
		connection, acceptErr := identityListener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		request, readErr := bufio.NewReader(io.LimitReader(connection, guestenrollment.MaxNativeEgressLocalMessageBytes+1)).ReadBytes('\n')
		if readErr != nil {
			return
		}
		identityRequest <- append([]byte(nil), request...)
		result := nativeEgressIssueResult(binding, credentialValue, now)
		response, encodeErr := guestenrollment.EncodeNativeEgressCredentialResponse(guestenrollment.NativeEgressCredentialResponse{
			ContractVersion: guestenrollment.NativeEgressLocalVersion, Type: guestenrollment.NativeEgressCredentialResult, Result: &result,
		})
		if encodeErr == nil {
			_, _ = connection.Write(response)
		}
	}()

	authenticator := &fakeAuthenticator{binding: binding, issuedAt: now}
	relayListener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = relayListener.Close() })
	relayAccepted := make(chan error, 1)
	go func() {
		connection, acceptErr := relayListener.Accept()
		if acceptErr != nil {
			relayAccepted <- acceptErr
			return
		}
		defer connection.Close()
		transport, acceptErr := newRuntimeRelayTransport(connection, authenticator)
		relayAccepted <- acceptErr
		if acceptErr == nil {
			_ = transport.Serve(context.Background())
		}
	}()
	connector, err := NewTLSConnector(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	connector.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, relayListener.Addr().String())
	}
	runtime, err := NewRuntime(Configuration{
		Version: ConfigurationVersion, RuntimeDirectory: filepath.Join(directory, "run"), IdentitySocketPath: identitySocket,
		RelayEndpoint: "tls://example.com:7445", CAPEMPath: filepath.Join(directory, "ca.pem"),
	}, &IdentityClient{SocketPath: identitySocket}, connector)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Capture != nil {
		t.Fatal("omitted capture configuration changed the control-only runtime")
	}
	runtime.Now = func() time.Time { return now }
	runtime.MonotonicNow = time.Now
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	waitForFile(t, filepath.Join(runtime.Configuration.RuntimeDirectory, ReadinessFileName))
	if info, err := os.Stat(runtime.Configuration.RuntimeDirectory); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("control-only runtime directory mode=%v error=%v", info, err)
	}
	if info, err := os.Stat(filepath.Join(runtime.Configuration.RuntimeDirectory, ReadinessFileName)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("control-only readiness mode=%v error=%v", info, err)
	}
	if err := <-relayAccepted; err != nil {
		cancel()
		t.Fatal(err)
	}
	request := <-identityRequest
	if _, err := guestenrollment.DecodeNativeEgressCredentialRequest(request); err != nil {
		cancel()
		t.Fatal(err)
	}
	for _, forbidden := range []string{binding.AgentRunUID, binding.ExecutionID, "runtime_identity", "audience", "broker", "target", "provider", credentialValue} {
		if strings.Contains(string(request), forbidden) {
			cancel()
			t.Fatalf("identity IPC contained forbidden value %q", forbidden)
		}
	}
	authenticator.mu.Lock()
	authenticated := append([]string(nil), authenticator.credentials...)
	authenticator.mu.Unlock()
	if len(authenticated) != 1 || authenticated[0] != credentialValue {
		cancel()
		t.Fatal("TLS relay did not authenticate the issued egress credential")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(runtime.Configuration.RuntimeDirectory, ReadinessFileName)); !os.IsNotExist(err) {
		t.Fatalf("readiness remained after shutdown: %v", err)
	}
	if treeContainsNativeEgress(t, directory, []byte(credentialValue)) {
		t.Fatal("native egress credential was persisted")
	}
}

func treeContainsNativeEgress(t *testing.T, root string, needle []byte) bool {
	t.Helper()
	found := false
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || found || info.IsDir() || info.Mode()&os.ModeSocket != 0 {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr == nil && strings.Contains(string(data), string(needle)) {
			found = true
		}
		return nil
	})
	return found
}
