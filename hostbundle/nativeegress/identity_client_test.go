package nativeegress

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

func TestIdentityClientRequestsOnlyTheFixedNativeEgressPurpose(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "nvt-ne-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(directory, "i.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	binding := nativeEgressBinding()
	now := time.Now().UTC().Truncate(time.Second)
	credentialValue, err := guestenrollment.GenerateNativeEgressCredential(1)
	if err != nil {
		t.Fatal(err)
	}
	requestObserved := make(chan []byte, 1)
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		request, readErr := bufio.NewReader(io.LimitReader(connection, guestenrollment.MaxNativeEgressLocalMessageBytes+1)).ReadBytes('\n')
		if readErr != nil {
			serverDone <- readErr
			return
		}
		requestObserved <- append([]byte(nil), request...)
		result := nativeEgressIssueResult(binding, credentialValue, now)
		response, encodeErr := guestenrollment.EncodeNativeEgressCredentialResponse(guestenrollment.NativeEgressCredentialResponse{
			ContractVersion: guestenrollment.NativeEgressLocalVersion,
			Type:            guestenrollment.NativeEgressCredentialResult,
			Result:          &result,
		})
		if encodeErr == nil {
			_, encodeErr = connection.Write(response)
		}
		serverDone <- encodeErr
	}()

	client := &IdentityClient{SocketPath: socket}
	result, err := client.Issue(context.Background())
	if err != nil || result.Binding != binding || result.Credential.Opaque != credentialValue {
		t.Fatalf("identity result=%#v error=%v", result, err)
	}
	request := <-requestObserved
	decoded, err := guestenrollment.DecodeNativeEgressCredentialRequest(request)
	if err != nil || decoded.ContractVersion != guestenrollment.NativeEgressLocalVersion {
		t.Fatalf("local request=%s error=%v", request, err)
	}
	for _, forbidden := range []string{
		"runtime_identity", "binding", "audience", "broker", "target", "provider",
		binding.AgentRunUID, binding.ExecutionID, credentialValue,
	} {
		if strings.Contains(string(request), forbidden) {
			t.Fatalf("local request contained forbidden authority input %q", forbidden)
		}
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.String(), credentialValue) || strings.Contains(result.GoString(), credentialValue) {
		t.Fatal("credential escaped local response formatting")
	}
}

func TestIdentityClientRejectsMalformedAndTrailingResponses(t *testing.T) {
	credentialValue, err := guestenrollment.GenerateNativeEgressCredential(1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	result := nativeEgressIssueResult(nativeEgressBinding(), credentialValue, now)
	valid, err := guestenrollment.EncodeNativeEgressCredentialResponse(guestenrollment.NativeEgressCredentialResponse{
		ContractVersion: guestenrollment.NativeEgressLocalVersion,
		Type:            guestenrollment.NativeEgressCredentialResult,
		Result:          &result,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, response := range map[string][]byte{
		"duplicate": []byte(`{"contract_version":"nvt.native-egress-local/v1","contract_version":"nvt.native-egress-local/v1","type":"error","error":{"reason":"identity-unavailable","temporary":true,"uncertain":false}}\n`),
		"trailing":  append(append([]byte(nil), valid...), []byte("{}\n")...),
		"oversized": append(make([]byte, guestenrollment.MaxNativeEgressLocalMessageBytes), '\n'),
	} {
		t.Run(name, func(t *testing.T) {
			clientSide, serverSide := unixSocketPair(t)
			defer clientSide.Close()
			defer serverSide.Close()
			go func() {
				_, _ = bufio.NewReader(serverSide).ReadBytes('\n')
				_, _ = serverSide.Write(response)
			}()
			client := &IdentityClient{
				SocketPath: "/run/nvt-agent-identity/session-credential.sock",
				Dial:       func(context.Context, string, string) (net.Conn, error) { return clientSide, nil },
			}
			if result, err := client.Issue(context.Background()); err == nil {
				result.Credential.Opaque = ""
				t.Fatal("malformed local response was accepted")
			}
		})
	}
}

func unixSocketPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "nvt-ne-pair-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "p.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- connection
	}()
	client, err := net.Dial("unix", path)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	select {
	case server := <-accepted:
		_ = listener.Close()
		return client, server
	case err := <-acceptErr:
		_ = listener.Close()
		t.Fatal(err)
	case <-time.After(time.Second):
		_ = listener.Close()
		t.Fatal("timed out creating Unix socket pair")
	}
	return nil, nil
}

func TestIdentityClientUnavailableErrorIsSecretFree(t *testing.T) {
	client := &IdentityClient{
		SocketPath: "/run/nvt-agent-identity/session-credential.sock",
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("secret-runtime-identity secret-provider-detail")
		},
	}
	_, err := client.Issue(context.Background())
	if err == nil || strings.Contains(err.Error(), "secret-") {
		t.Fatalf("unsafe identity error: %v", err)
	}
}
