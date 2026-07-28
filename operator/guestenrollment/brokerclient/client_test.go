package brokerclient

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

func TestClientIssueRevokeAndAuthoritativeShutdown(t *testing.T) {
	t.Parallel()
	token := "orchestrator-token-0123456789abcdef"
	binding := guestenrollment.Binding{AgentRunUID: "uid", ExecutionID: "execution", DriverRegistration: "fake-vm", DesiredGeneration: 3, GuestInstanceID: "guest"}
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	envelope := guestenrollment.BootstrapEnvelope{
		ContractVersion: guestenrollment.Version, Binding: binding,
		ExchangeURL: "https://broker.example/v1/guest-enrollment/exchange",
		Token:       base64.RawURLEncoding.EncodeToString(make([]byte, guestenrollment.TokenBytes)),
		IssuedAt:    guestenrollment.FormatTimestamp(now), ExpiresAt: guestenrollment.FormatTimestamp(now.Add(5 * time.Minute)),
	}
	var mu sync.Mutex
	paths := []string{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get("Content-Type") != "application/json" {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		paths = append(paths, request.URL.Path)
		mu.Unlock()
		response.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/v1/guest-enrollment/issue" {
			_ = json.NewEncoder(response).Encode(envelope)
			return
		}
		_, _ = response.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	client := newTestClient(t, server, token)
	if !client.EnabledFor("fake-vm") || client.EnabledFor("other-vm") {
		t.Fatal("client registration allowlist is not exact")
	}
	issued, err := client.Issue(context.Background(), guestenrollment.IssueRequest{ContractVersion: guestenrollment.Version, Binding: binding})
	if err != nil || issued.Token != envelope.Token || issued.Binding != binding {
		t.Fatalf("issue=%#v err=%v", issued, err)
	}
	if err := client.RevokeBinding(context.Background(), guestenrollment.RevokeBindingRequest{ContractVersion: guestenrollment.Version, Binding: binding}); err != nil {
		t.Fatal(err)
	}
	if err := client.RevokeExecution(context.Background(), guestenrollment.RevokeExecutionRequest{ContractVersion: guestenrollment.Version, ExecutionScope: binding.ExecutionScope()}); err != nil {
		t.Fatal(err)
	}
	if err := client.CompleteExecutionCleanup(context.Background(), guestenrollment.CompleteExecutionCleanupRequest{ContractVersion: guestenrollment.Version, ExecutionScope: binding.ExecutionScope()}); err != nil {
		t.Fatal(err)
	}
	if err := client.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Issue(context.Background(), guestenrollment.IssueRequest{ContractVersion: guestenrollment.Version, Binding: binding}); !errors.Is(err, ErrClosed) {
		t.Fatalf("post-shutdown issue=%v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"/v1/guest-enrollment/issue", "/v1/guest-enrollment/revoke-binding", "/v1/guest-enrollment/revoke-execution", "/v1/guest-enrollment/complete-execution-cleanup"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("paths=%#v", paths)
	}
}

func TestClientFailsClosedAndSanitizesResponses(t *testing.T) {
	t.Parallel()
	canary := "BROKER-ENROLLMENT-TOKEN-CANARY"
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusServiceUnavailable)
		_, _ = response.Write([]byte(`{"ok":false,"error":"issuer-storage-failed","message":"` + canary + `"}`))
	}))
	defer server.Close()
	client := newTestClient(t, server, "orchestrator-token-0123456789abcdef")
	binding := guestenrollment.Binding{AgentRunUID: "uid", ExecutionID: "execution", DriverRegistration: "fake-vm", DesiredGeneration: 1, GuestInstanceID: "guest"}
	_, err := client.Issue(context.Background(), guestenrollment.IssueRequest{ContractVersion: guestenrollment.Version, Binding: binding, TTLSeconds: 30})
	if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), canary) {
		t.Fatalf("unsanitized failure: %v", err)
	}
}

func TestClientRejectsMalformedResponsesAndBoundsTimeout(t *testing.T) {
	t.Run("malformed", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"contract_version":"nvt.guest-enrollment/v1","binding":null,"binding":null}`))
		}))
		defer server.Close()
		client := newTestClientWithTimeout(t, server, "orchestrator-token-0123456789abcdef", time.Second)
		binding := guestenrollment.Binding{AgentRunUID: "uid", ExecutionID: "execution", DriverRegistration: "fake-vm", DesiredGeneration: 1, GuestInstanceID: "guest"}
		if _, err := client.Issue(context.Background(), guestenrollment.IssueRequest{ContractVersion: guestenrollment.Version, Binding: binding, TTLSeconds: 30}); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("malformed response error=%v", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		release := make(chan struct{})
		server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			<-release
		}))
		client := newTestClientWithTimeout(t, server, "orchestrator-token-0123456789abcdef", 25*time.Millisecond)
		binding := guestenrollment.Binding{AgentRunUID: "uid", ExecutionID: "execution", DriverRegistration: "fake-vm", DesiredGeneration: 1, GuestInstanceID: "guest"}
		started := time.Now()
		if _, err := client.Issue(context.Background(), guestenrollment.IssueRequest{ContractVersion: guestenrollment.Version, Binding: binding, TTLSeconds: 30}); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("timeout error=%v", err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("request deadline was not bounded: %s", elapsed)
		}
		close(release)
		server.Close()
	})
}

func TestClientShutdownCancelsActiveIssue(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
	}))
	client := newTestClientWithTimeout(t, server, "orchestrator-token-0123456789abcdef", time.Second)
	binding := guestenrollment.Binding{AgentRunUID: "uid", ExecutionID: "execution", DriverRegistration: "fake-vm", DesiredGeneration: 1, GuestInstanceID: "guest"}
	done := make(chan error, 1)
	go func() {
		_, err := client.Issue(context.Background(), guestenrollment.IssueRequest{ContractVersion: guestenrollment.Version, Binding: binding, TTLSeconds: 30})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("issue did not reach broker")
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("active issue error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("active issue was not canceled")
	}
	if _, err := client.Issue(context.Background(), guestenrollment.IssueRequest{ContractVersion: guestenrollment.Version, Binding: binding, TTLSeconds: 30}); !errors.Is(err, ErrClosed) {
		t.Fatalf("post-shutdown issue=%v", err)
	}
	close(release)
	server.Close()
}

func TestLoadConfiguredIsStrictAndDefaultDisabled(t *testing.T) {
	t.Setenv(EnvironmentConfigFile, "")
	client, err := LoadConfigured()
	if err != nil || client != nil {
		t.Fatalf("disabled client=%#v err=%v", client, err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "config.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"baseURL":"https://broker.example","serverName":"broker.example","caFile":"/ca","bearerTokenFile":"/token","requestTimeoutSeconds":30,"ttlSeconds":300,"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvironmentConfigFile, path)
	if _, err := LoadConfigured(); err == nil || strings.Contains(err.Error(), "broker.example") {
		t.Fatalf("unknown-field configuration error=%v", err)
	}
}

func newTestClient(t *testing.T, server *httptest.Server, token string) *Client {
	return newTestClientWithTimeout(t, server, token, time.Second)
}

func newTestClientWithTimeout(t *testing.T, server *httptest.Server, token string, timeout time.Duration) *Client {
	t.Helper()
	directory := t.TempDir()
	certificate, err := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(directory, "ca.crt")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(directory, "token")
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	endpoint, err := url.Parse(server.URL)
	if err != nil || endpoint.Hostname() == "" || len(certificate.DNSNames) == 0 {
		t.Fatalf("test TLS endpoint is invalid: %v", err)
	}
	client, err := New(Config{
		BaseURL: server.URL, ServerName: certificate.DNSNames[0], CAFile: caPath, BearerTokenFile: tokenPath,
		RequestTimeout: timeout, HandoffTimeout: time.Second, TTLSeconds: 300, Registrations: []string{"fake-vm"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Shutdown(context.Background()) })
	return client
}
