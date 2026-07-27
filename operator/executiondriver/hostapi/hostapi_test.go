package hostapi_test

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	driverhost "github.com/mirkoSekulic/nvt-agent/operator/executiondriver/host"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver/hostapi"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

var fakeDriverBinary string

type fakeHandoff struct {
	guestID  string
	accepted bool
	token    string
}

func (h *fakeHandoff) Prepare(context.Context, guestenrollment.HandoffPrepareRequest) (guestenrollment.HandoffPrepareResult, error) {
	state := guestenrollment.HandoffStatePrepared
	if h.accepted {
		state = guestenrollment.HandoffStateAccepted
	}
	return guestenrollment.HandoffPrepareResult{ContractVersion: guestenrollment.HandoffVersion, GuestInstanceID: h.guestID, State: state, NewlyPrepared: !h.accepted}, nil
}

func (h *fakeHandoff) Replace(_ context.Context, request guestenrollment.HandoffReplaceRequest) (guestenrollment.HandoffPrepareResult, error) {
	if request.Binding.GuestInstanceID != h.guestID {
		return guestenrollment.HandoffPrepareResult{}, errors.New("binding mismatch")
	}
	h.guestID = "guest-replacement"
	return guestenrollment.HandoffPrepareResult{ContractVersion: guestenrollment.HandoffVersion, GuestInstanceID: h.guestID, State: guestenrollment.HandoffStatePrepared, NewlyPrepared: true}, nil
}

func (h *fakeHandoff) Deliver(_ context.Context, request guestenrollment.HandoffDeliverRequest) error {
	h.token = request.Envelope.Token
	h.accepted = true
	return nil
}

func TestMain(m *testing.M) {
	directory, err := os.MkdirTemp("", "nvt-driver-host-api-*")
	if err != nil {
		os.Exit(1)
	}
	fakeDriverBinary = filepath.Join(directory, "fake-driver")
	command := exec.Command("go", "build", "-trimpath", "-o", fakeDriverBinary, "../testdata/fake-driver")
	if output, buildErr := command.CombinedOutput(); buildErr != nil {
		fmt.Fprintf(os.Stderr, "build fake driver: %v\n%s", buildErr, output)
		_ = os.RemoveAll(directory)
		os.Exit(1)
	}
	status := m.Run()
	_ = os.RemoveAll(directory)
	os.Exit(status)
}

func TestAuthenticatedServiceLifecycle(t *testing.T) {
	local, server, remote := newService(t, "")
	desired := testDesired(t, "remote-run", map[string]any{"ready": true, "delete_steps": 1})
	status, err := remote.Reconcile(testContext(t), desired)
	if err != nil || !status.Ready || status.Phase != executiondriver.PhaseRunning {
		t.Fatalf("reconcile status=%#v error=%v", status, err)
	}
	observed, err := remote.Observe(testContext(t), desired.ExecutionID)
	if err != nil || observed.ExternalResourceID != status.ExternalResourceID {
		t.Fatalf("observe status=%#v error=%v", observed, err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		status, err = remote.Delete(testContext(t), desired.ExecutionID)
		if err != nil {
			t.Fatalf("delete: %v", err)
		}
		if status.Phase == executiondriver.PhaseDeleted {
			break
		}
	}
	if status.Phase != executiondriver.PhaseDeleted {
		t.Fatalf("delete did not converge: %#v", status)
	}

	conflict := testDesired(t, "conflict-run", map[string]any{"ready": true})
	if _, err := remote.Reconcile(testContext(t), conflict); err != nil {
		t.Fatalf("seed conflict run: %v", err)
	}
	conflict.DesiredFingerprint = "sha256:" + strings.Repeat("f", 64)
	if _, err := remote.Reconcile(testContext(t), conflict); err == nil || !strings.Contains(err.Error(), "generation-conflict") {
		t.Fatalf("portable driver error=%v", err)
	}

	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/observe", strings.NewReader(`{"execution_id":"remote-run"}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated response=%v error=%v", response, err)
	}
	_ = response.Body.Close()

	ready, err := server.Client().Get(server.URL + "/readyz")
	if err != nil || ready.StatusCode != http.StatusOK {
		t.Fatalf("ready response=%v error=%v", ready, err)
	}
	_ = ready.Body.Close()
	if err := local.Shutdown(testContext(t)); err != nil {
		t.Fatalf("shutdown local driver: %v", err)
	}
	notReady, err := server.Client().Get(server.URL + "/readyz")
	if err != nil || notReady.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("not-ready response=%v error=%v", notReady, err)
	}
	_ = notReady.Body.Close()
}

func TestClientRejectsMalformedAndOversizedResponsesWithoutDisclosure(t *testing.T) {
	canary := "REMOTE-DRIVER-SECRET-CANARY"
	cases := map[string]struct {
		contentType string
		body        []byte
	}{
		"wrong content type": {contentType: "text/plain", body: []byte(`{}`)},
		"duplicate key":      {contentType: "application/json", body: []byte(`{"protocol_version":"nvt.execution-driver-host/v1","protocol_version":"nvt.execution-driver-host/v1","status":{}}`)},
		"invalid utf8":       {contentType: "application/json", body: []byte{'{', '"', 0xff, '"', ':', '1', '}'}},
		"oversized":          {contentType: "application/json", body: []byte(strings.Repeat(canary, hostapi.MaxBodyBytes/len(canary)+2))},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Content-Type", test.contentType)
				_, _ = response.Write(test.body)
			}))
			remote := newClientForTLSServer(t, server)
			_, err := remote.Observe(testContext(t), "malformed-response")
			if err == nil || strings.Contains(err.Error(), canary) {
				t.Fatalf("response error=%v", err)
			}
			server.Close()
		})
	}
}

func TestServiceBoundsAndSanitizesFailures(t *testing.T) {
	_, server, remote := newService(t, "")
	desired := testDesired(t, "failed-run", map[string]any{"fail": true})
	status, err := remote.Reconcile(testContext(t), desired)
	if err != nil || status.Failure == nil || status.Failure.Reason != "provider-operation-failed" || strings.Contains(fmt.Sprintf("%#v", status), "SECRET-CANARY") {
		t.Fatalf("sanitized status=%#v error=%v", status, err)
	}

	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/observe", strings.NewReader(strings.Repeat("x", hostapi.MaxBodyBytes+1)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testToken())
	response, requestErr := server.Client().Do(request)
	if requestErr != nil || response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized response=%v error=%v", response, requestErr)
	}
	_ = response.Body.Close()
}

func TestServiceFailureInvalidatesAndLaterRestartsExactDriver(t *testing.T) {
	_, _, remote := newService(t, "crash-once-reconcile")
	desired := testDesired(t, "restart-run", map[string]any{"ready": true})
	if _, err := remote.Reconcile(testContext(t), desired); err == nil {
		t.Fatal("crashed driver unexpectedly succeeded")
	}
	time.Sleep(120 * time.Millisecond)
	status, err := remote.Reconcile(testContext(t), desired)
	if err != nil || !status.Ready {
		t.Fatalf("restart status=%#v error=%v", status, err)
	}
}

func TestClientShutdownCancelsActiveOperationAndClosesAuthoritatively(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		close(started)
		<-request.Context().Done()
		close(canceled)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	remote := newClientForTLSServer(t, server)
	operationDone := make(chan error, 1)
	go func() {
		_, err := remote.Observe(context.Background(), "blocked-operation")
		operationDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("active operation did not reach the host")
	}

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), time.Second)
	defer cancelShutdown()
	if err := remote.Shutdown(shutdownContext); err != nil {
		t.Fatalf("shutdown active client: %v", err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("driver-host request context was not canceled")
	}
	select {
	case err := <-operationDone:
		if err == nil {
			t.Fatal("canceled operation unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("active operation remained blocked after shutdown")
	}
	if _, err := remote.Observe(context.Background(), "after-shutdown"); !errors.Is(err, driverhost.ErrClosed) {
		t.Fatalf("operation after shutdown error=%v, want ErrClosed", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("host received %d requests, want only the in-flight request", got)
	}
}

func TestSensitiveHandoffUsesExactAuthenticatedHostBoundary(t *testing.T) {
	t.Setenv("NVT_FAKE_DRIVER_MODE", "")
	t.Setenv("NVT_FAKE_DRIVER_STATE_DIR", t.TempDir())
	local, err := driverhost.NewLocalExecutable(testContext(t), driverhost.LocalExecutableConfig{
		DriverInstanceName: "fake-driver", ExecutablePath: fakeDriverBinary,
		PassEnv: []string{"NVT_FAKE_DRIVER_MODE", "NVT_FAKE_DRIVER_STATE_DIR"}, InitializeTimeout: time.Second,
		OperationTimeout: time.Second, ShutdownTimeout: time.Second, TerminationGrace: 25 * time.Millisecond, RestartBackoff: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = local.Shutdown(context.Background()) })
	handoff := &fakeHandoff{guestID: "guest-1"}
	handler, err := hostapi.NewServer(hostapi.ServerConfig{
		Client: local, Handoff: handoff, DriverRegistration: "fake-driver", BearerToken: []byte(testToken()), OperationTimeout: time.Second, HandoffTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	remote := newClientForTLSServer(t, server)
	binding := guestenrollment.Binding{AgentRunUID: "uid", ExecutionID: "execution", DriverRegistration: "fake-driver", DesiredGeneration: 1, GuestInstanceID: "guest-1"}
	prepared, err := remote.Prepare(testContext(t), guestenrollment.HandoffPrepareRequest{ContractVersion: guestenrollment.HandoffVersion, ExecutionScope: binding.ExecutionScope(), DesiredGeneration: 1})
	if err != nil || prepared.GuestInstanceID != binding.GuestInstanceID {
		t.Fatalf("prepare=%#v err=%v", prepared, err)
	}
	replaced, err := remote.Replace(testContext(t), guestenrollment.HandoffReplaceRequest{ContractVersion: guestenrollment.HandoffVersion, Binding: binding})
	if err != nil || replaced.GuestInstanceID == binding.GuestInstanceID {
		t.Fatalf("replace=%#v err=%v", replaced, err)
	}
	binding.GuestInstanceID = replaced.GuestInstanceID
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	// Use one canonical 32-byte base64url token.
	token := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	envelope := guestenrollment.BootstrapEnvelope{
		ContractVersion: guestenrollment.Version, Binding: binding, ExchangeURL: "https://broker.example/v1/guest-enrollment/exchange",
		Token: token, IssuedAt: guestenrollment.FormatTimestamp(now), ExpiresAt: guestenrollment.FormatTimestamp(now.Add(time.Minute)),
	}
	if err := remote.Deliver(testContext(t), guestenrollment.HandoffDeliverRequest{ContractVersion: guestenrollment.HandoffVersion, Envelope: envelope}); err != nil {
		t.Fatal(err)
	}
	if handoff.token != token || !handoff.accepted {
		t.Fatal("exact handoff did not receive the sensitive envelope")
	}
	wrong := binding
	wrong.DriverRegistration = "other-driver"
	if _, err := remote.Prepare(testContext(t), guestenrollment.HandoffPrepareRequest{
		ContractVersion: guestenrollment.HandoffVersion, ExecutionScope: wrong.ExecutionScope(), DesiredGeneration: wrong.DesiredGeneration,
	}); err == nil {
		t.Fatal("cross-registration prepare was accepted")
	}
	if err := remote.Deliver(testContext(t), guestenrollment.HandoffDeliverRequest{ContractVersion: guestenrollment.HandoffVersion, Envelope: guestenrollment.BootstrapEnvelope{
		ContractVersion: guestenrollment.Version, Binding: wrong, ExchangeURL: envelope.ExchangeURL, Token: token, IssuedAt: envelope.IssuedAt, ExpiresAt: envelope.ExpiresAt,
	}}); err == nil {
		t.Fatal("cross-registration handoff was accepted")
	}
}

func newService(t *testing.T, mode string) (*driverhost.LocalExecutable, *httptest.Server, *hostapi.Client) {
	t.Helper()
	t.Setenv("NVT_FAKE_DRIVER_MODE", mode)
	t.Setenv("NVT_FAKE_DRIVER_STATE_DIR", t.TempDir())
	local, err := driverhost.NewLocalExecutable(testContext(t), driverhost.LocalExecutableConfig{
		DriverInstanceName: "fake-driver",
		ExecutablePath:     fakeDriverBinary,
		PassEnv:            []string{"NVT_FAKE_DRIVER_MODE", "NVT_FAKE_DRIVER_STATE_DIR"},
		InitializeTimeout:  time.Second,
		OperationTimeout:   500 * time.Millisecond,
		ShutdownTimeout:    500 * time.Millisecond,
		TerminationGrace:   25 * time.Millisecond,
		RestartBackoff:     100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("start local driver: %v", err)
	}
	handler, err := hostapi.NewServer(hostapi.ServerConfig{Client: local, BearerToken: []byte(testToken()), OperationTimeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	server := httptest.NewTLSServer(handler)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	remote := newClientForTLSServerWithCA(t, server, caFile)
	t.Cleanup(func() {
		_ = remote.Shutdown(context.Background())
		server.Close()
		_ = local.Shutdown(context.Background())
	})
	return local, server, remote
}

func newClientForTLSServer(t *testing.T, server *httptest.Server) *hostapi.Client {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	return newClientForTLSServerWithCA(t, server, caFile)
}

func newClientForTLSServerWithCA(t *testing.T, server *httptest.Server, caFile string) *hostapi.Client {
	t.Helper()
	parsed, err := x509.ParseCertificate(server.Certificate().Raw)
	if err != nil {
		t.Fatalf("parse server certificate: %v", err)
	}
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(testToken()), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	remote, err := hostapi.NewClient(hostapi.ClientConfig{BaseURL: server.URL, DriverRegistration: "fake-driver", ServerName: parsed.DNSNames[0], CAFile: caFile, BearerTokenFile: tokenFile, RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("create remote client: %v", err)
	}
	t.Cleanup(func() { _ = remote.Shutdown(context.Background()) })
	return remote
}

func testDesired(t *testing.T, executionID string, configuration any) executiondriver.DesiredExecution {
	t.Helper()
	encoded, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(append([]byte("vm:fake-small:"), encoded...))
	return executiondriver.DesiredExecution{ExecutionID: executionID, Generation: 1, DesiredFingerprint: fmt.Sprintf("sha256:%x", digest[:]), WorkloadKind: executiondriver.WorkloadKindVM, ClassName: "fake-small", Configuration: encoded}
}

func testToken() string { return strings.Repeat("t", 64) }

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return ctx
}
