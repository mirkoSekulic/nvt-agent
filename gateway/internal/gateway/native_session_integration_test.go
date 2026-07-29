package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/nativesession"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

type integrationSessionAuthority struct {
	mu          sync.Mutex
	binding     guestenrollment.Binding
	sequence    uint64
	credentials map[string]guestenrollment.GuestSessionStatus
	revoked     bool
	authCalls   int
}

func newIntegrationSessionAuthority(binding guestenrollment.Binding) *integrationSessionAuthority {
	return &integrationSessionAuthority{binding: binding, credentials: make(map[string]guestenrollment.GuestSessionStatus)}
}

func (authority *integrationSessionAuthority) Issue(context.Context) (guestenrollment.GuestSessionIssueResult, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.revoked {
		return guestenrollment.GuestSessionIssueResult{}, errors.New("identity unavailable")
	}
	authority.sequence++
	credential := nativeSessionTestCredential(authority.sequence)
	issuedAt := time.Now().UTC().Truncate(time.Second)
	expiresAt := issuedAt.Add(62 * time.Second)
	status := guestenrollment.GuestSessionStatus{
		ContractVersion: guestenrollment.GuestSessionIdentityVersion,
		CredentialType:  guestenrollment.GuestSessionCredentialType,
		Binding:         authority.binding,
		Audience:        guestenrollment.NativeGuestControlAudience,
		IssuedAt:        issuedAt.Format(time.RFC3339),
		ExpiresAt:       expiresAt.Format(time.RFC3339),
	}
	authority.credentials[credential] = status
	return guestenrollment.GuestSessionIssueResult{
		ContractVersion: guestenrollment.GuestSessionIdentityVersion,
		Binding:         authority.binding,
		Credential: guestenrollment.GuestSessionCredential{
			Type: guestenrollment.GuestSessionCredentialType, Opaque: credential,
			Audience: guestenrollment.NativeGuestControlAudience,
			IssuedAt: status.IssuedAt, ExpiresAt: status.ExpiresAt,
		},
	}, nil
}

func (authority *integrationSessionAuthority) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.URL.Path != guestenrollment.GuestSessionIdentityAuthenticatePath || request.Header.Get("Content-Type") != "application/json" {
		http.NotFound(response, request)
		return
	}
	credential := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	body, _ := ioReadAllBounded(request.Body, guestenrollment.MaxGuestSessionAuthRequestBytes)
	request.Header.Del("Authorization")
	decoded, err := guestenrollment.DecodeGuestSessionAuthenticateRequest(body)
	zeroNativeSessionBytes(body)
	authority.mu.Lock()
	status, found := authority.credentials[credential]
	revoked := authority.revoked
	if found {
		authority.authCalls++
	}
	authority.mu.Unlock()
	credential = ""
	if err != nil || revoked || !found || decoded.Binding != authority.binding || decoded.Audience != guestenrollment.NativeGuestControlAudience {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusUnauthorized)
		_, _ = response.Write([]byte(`{"error":"unauthorized"}`))
		return
	}
	encoded, _ := json.Marshal(status)
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(encoded)
}

func (authority *integrationSessionAuthority) counts() (uint64, int) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	return authority.sequence, authority.authCalls
}

func (authority *integrationSessionAuthority) revoke() {
	authority.mu.Lock()
	authority.revoked = true
	authority.mu.Unlock()
}

func TestProductionNativeSessionAcceptorWithGuestRuntime(t *testing.T) {
	binding := nativeSessionTestBinding()
	authority := newIntegrationSessionAuthority(binding)
	broker := httptest.NewTLSServer(authority)
	defer broker.Close()
	brokerCAPath := filepath.Join(t.TempDir(), "broker-ca.pem")
	writeCertificatePEM(t, brokerCAPath, broker.Certificate())
	authenticator, err := newBrokerNativeSessionAuthenticator(NativeSessionConfig{
		BrokerURL: broker.URL, BrokerServerName: broker.Certificate().IPAddresses[0].String(),
		BrokerCAFile: brokerCAPath, AuthenticationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	gatewayCertificate, _ := nativeSessionTestCertificate(t, "gateway.test")
	gatewayCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: gatewayCertificate.Certificate[0]})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gateway := newNativeSessionServer(NativeSessionConfig{
		Enabled: true, ListenAddr: listener.Addr().String(), AuthenticationTimeout: time.Second,
		RevalidationInterval: 200 * time.Millisecond,
	}, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{gatewayCertificate}}, authenticator)
	gatewayDone := make(chan error, 1)
	go func() { gatewayDone <- gateway.Serve(listener) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = gateway.Shutdown(ctx)
		<-gatewayDone
	}()

	work := t.TempDir()
	runtimeDirectory := filepath.Join(work, "session-runtime")
	agentdSocket := filepath.Join(work, "agentd.sock")
	identitySocket := filepath.Join(work, "identity.sock")
	agentdRequestCount, stopAgentd := startIntegrationAgentd(t, agentdSocket)
	defer stopAgentd()
	connector, err := nativesession.NewTLSConnector(gatewayCAPEM)
	zeroNativeSessionBytes(gatewayCAPEM)
	if err != nil {
		t.Fatal(err)
	}
	actualAddress := listener.Addr().String()
	connector.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, actualAddress)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	runtime, err := nativesession.NewRuntime(nativesession.Configuration{
		Version: 1, RuntimeDirectory: runtimeDirectory, IdentitySocketPath: identitySocket,
		AgentdSocketPath: agentdSocket, GatewayEndpoint: fmt.Sprintf("tls://gateway.test:%d", port),
		CAPEMPath: filepath.Join(work, "unused-ca-path.pem"),
	}, authority, connector)
	if err != nil {
		t.Fatal(err)
	}
	runtimeContext, cancelRuntime := context.WithCancel(t.Context())
	runtimeDone := make(chan error, 1)
	go func() { runtimeDone <- runtime.Run(runtimeContext) }()
	defer cancelRuntime()

	waitNativeSessionReady(t, gateway.registry, binding)
	response, err := gateway.registry.RelayAgentd(t.Context(), binding, json.RawMessage(`{"type":"health"}`))
	if err != nil || string(response) != `{"status":"ready"}` {
		t.Fatalf("production relay response=%s error=%v", response, err)
	}
	if count := agentdRequestCount(); count < 2 { // local readiness plus gateway relay
		t.Fatalf("agentd requests=%d, want local readiness plus relay", count)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		issued, authenticated := authority.counts()
		if issued >= 2 && authenticated >= 3 && gateway.registry.Ready(binding) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	issued, authenticated := authority.counts()
	if issued < 2 || authenticated < 3 {
		t.Fatalf("make-before-break/reconnect proof incomplete: issued=%d authenticated=%d", issued, authenticated)
	}
	if issued > guestenrollment.MaxLiveGuestSessionsPerBinding {
		t.Fatalf("guest issued too many live credentials: %d", issued)
	}

	authority.revoke()
	select {
	case err := <-runtimeDone:
		if err == nil {
			t.Fatal("revoked native session runtime exited successfully")
		}
		if strings.Contains(err.Error(), nativeSessionTestCredential(1)) || strings.Contains(err.Error(), nativeSessionTestCredential(2)) {
			t.Fatal("native session error disclosed credential")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("broker revocation did not fail the guest session closed")
	}
	if gateway.registry.Ready(binding) {
		t.Fatal("revocation left production gateway registry ready")
	}
	if _, err := os.Stat(filepath.Join(runtimeDirectory, nativesession.ReadinessFileName)); !os.IsNotExist(err) {
		t.Fatal("revocation left guest session readiness")
	}
}

func startIntegrationAgentd(t *testing.T, path string) (func() int, func()) {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	requests := make([]string, 0, 8)
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
				line, err := bufio.NewReader(connection).ReadString('\n')
				if err != nil {
					return
				}
				mu.Lock()
				requests = append(requests, strings.TrimSpace(line))
				mu.Unlock()
				_, _ = connection.Write([]byte(`{"status":"ready"}` + "\n"))
			}()
		}
	}()
	return func() int {
			mu.Lock()
			defer mu.Unlock()
			return len(requests)
		}, func() {
			_ = listener.Close()
			<-done
		}
}
