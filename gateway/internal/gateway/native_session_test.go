package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
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
)

type fakeNativeSessionAuthenticator struct {
	mu       sync.Mutex
	statuses map[string]authenticatedNativeSession
	calls    []string
	err      error
}

func (authenticator *fakeNativeSessionAuthenticator) Authenticate(_ context.Context, credential string, binding guestenrollment.Binding) (authenticatedNativeSession, error) {
	authenticator.mu.Lock()
	defer authenticator.mu.Unlock()
	authenticator.calls = append(authenticator.calls, credential)
	if authenticator.err != nil {
		return authenticatedNativeSession{}, authenticator.err
	}
	status, ok := authenticator.statuses[credential]
	if !ok || status.Binding != binding {
		return authenticatedNativeSession{}, errors.New("denied")
	}
	return status, nil
}

func TestNativeSessionConfigValidation(t *testing.T) {
	valid := NativeSessionConfig{
		Enabled: true, ListenAddr: ":7443",
		TLSCertificateFile: "/run/nvt/native/tls.crt", TLSKeyFile: "/run/nvt/native/tls.key",
		BrokerURL: "https://nvt-broker.nvt.svc.cluster.local:7347", BrokerServerName: "nvt-broker.nvt.svc.cluster.local",
		BrokerCAFile: "/run/nvt/broker/ca.crt", AuthenticationTimeout: 5 * time.Second, RevalidationInterval: 30 * time.Second,
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid native session config: %v", err)
	}
	disabled := NativeSessionConfig{}
	if err := disabled.validate(); err != nil {
		t.Fatalf("disabled native session config: %v", err)
	}
	mutations := map[string]func(*NativeSessionConfig){
		"listen":          func(value *NativeSessionConfig) { value.ListenAddr = "7443" },
		"zero port":       func(value *NativeSessionConfig) { value.ListenAddr = ":0" },
		"relative cert":   func(value *NativeSessionConfig) { value.TLSCertificateFile = "tls.crt" },
		"same trust file": func(value *NativeSessionConfig) { value.BrokerCAFile = value.TLSCertificateFile },
		"plain broker":    func(value *NativeSessionConfig) { value.BrokerURL = "http://nvt-broker.nvt.svc.cluster.local:7347" },
		"broker path":     func(value *NativeSessionConfig) { value.BrokerURL += "/prefix" },
		"broker user": func(value *NativeSessionConfig) {
			value.BrokerURL = "https://user@nvt-broker.nvt.svc.cluster.local:7347"
		},
		"wrong server": func(value *NativeSessionConfig) { value.BrokerServerName = "other.nvt.svc.cluster.local" },
		"IP server": func(value *NativeSessionConfig) {
			value.BrokerURL = "https://127.0.0.1:7347"
			value.BrokerServerName = "127.0.0.1"
		},
		"auth timeout": func(value *NativeSessionConfig) { value.AuthenticationTimeout = 31 * time.Second },
		"revalidation": func(value *NativeSessionConfig) { value.RevalidationInterval = 61 * time.Second },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			value := valid
			mutate(&value)
			if err := value.validate(); err == nil {
				t.Fatalf("invalid config passed: %#v", value)
			}
		})
	}
	httpConfig := Config{BaseDomain: "agents.test", ListenAddr: ":7443", DefaultTargetPort: 4090, NativeSession: valid}
	if err := httpConfig.Validate(); err == nil || !strings.Contains(err.Error(), "separate port") {
		t.Fatalf("shared HTTP/native port error = %v", err)
	}
}

func TestBrokerNativeSessionAuthenticationIsStrictAndRedacted(t *testing.T) {
	binding := nativeSessionTestBinding()
	credentialCanary := nativeSessionTestCredential(1)
	issued := time.Now().UTC().Truncate(time.Second).Add(-time.Second)
	validStatus := guestenrollment.GuestSessionStatus{
		ContractVersion: guestenrollment.GuestSessionIdentityVersion,
		CredentialType:  guestenrollment.GuestSessionCredentialType,
		Binding:         binding, Audience: guestenrollment.NativeGuestControlAudience,
		IssuedAt: issued.Format(time.RFC3339), ExpiresAt: issued.Add(5 * time.Minute).Format(time.RFC3339),
	}
	for _, test := range []struct {
		name        string
		status      int
		contentType string
		body        func() []byte
		wantOK      bool
	}{
		{name: "valid", status: http.StatusOK, contentType: "application/json", body: func() []byte { value, _ := json.Marshal(validStatus); return value }, wantOK: true},
		{name: "denied", status: http.StatusUnauthorized, contentType: "application/json", body: func() []byte { return []byte(`{"error":"unauthorized"}`) }},
		{name: "wrong content", status: http.StatusOK, contentType: "application/json; charset=utf-8", body: func() []byte { value, _ := json.Marshal(validStatus); return value }},
		{name: "wrong binding", status: http.StatusOK, contentType: "application/json", body: func() []byte {
			value := validStatus
			value.Binding.GuestInstanceID = "other"
			encoded, _ := json.Marshal(value)
			return encoded
		}},
		{name: "wrong audience", status: http.StatusOK, contentType: "application/json", body: func() []byte {
			value := validStatus
			value.Audience = "other"
			encoded, _ := json.Marshal(value)
			return encoded
		}},
		{name: "expired", status: http.StatusOK, contentType: "application/json", body: func() []byte {
			value := validStatus
			value.IssuedAt = issued.Add(-10 * time.Minute).Format(time.RFC3339)
			value.ExpiresAt = issued.Add(-5 * time.Minute).Format(time.RFC3339)
			encoded, _ := json.Marshal(value)
			return encoded
		}},
		{name: "duplicate key", status: http.StatusOK, contentType: "application/json", body: func() []byte {
			return []byte(`{"contract_version":"nvt.guest-session-identity/v1","contract_version":"nvt.guest-session-identity/v1"}`)
		}},
		{name: "invalid UTF-8", status: http.StatusOK, contentType: "application/json", body: func() []byte { return []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'} }},
		{name: "oversized", status: http.StatusOK, contentType: "application/json", body: func() []byte { return bytes.Repeat([]byte("x"), guestenrollment.MaxGuestSessionResponseBytes+1) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path != guestenrollment.GuestSessionIdentityAuthenticatePath || request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer "+credentialCanary || request.Header.Get("Cookie") != "" {
					t.Errorf("unexpected broker request: %s %s", request.Method, request.URL.Path)
				}
				requestBody, _ := ioReadAllBounded(request.Body, guestenrollment.MaxGuestSessionAuthRequestBytes)
				decoded, decodeErr := guestenrollment.DecodeGuestSessionAuthenticateRequest(requestBody)
				if decodeErr != nil || decoded.Binding != binding || decoded.Audience != guestenrollment.NativeGuestControlAudience {
					t.Errorf("broker request body invalid")
				}
				response.Header().Set("Content-Type", test.contentType)
				response.WriteHeader(test.status)
				_, _ = response.Write(test.body())
			}))
			defer server.Close()
			caPath := filepath.Join(t.TempDir(), "ca.pem")
			writeCertificatePEM(t, caPath, server.Certificate())
			authenticator, err := newBrokerNativeSessionAuthenticator(NativeSessionConfig{
				BrokerURL: server.URL, BrokerServerName: server.Certificate().IPAddresses[0].String(), BrokerCAFile: caPath,
				AuthenticationTimeout: time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = authenticator.Authenticate(t.Context(), credentialCanary, binding)
			if test.wantOK != (err == nil) {
				t.Fatalf("Authenticate error=%v wantOK=%v", err, test.wantOK)
			}
			if err != nil && strings.Contains(err.Error(), credentialCanary) {
				t.Fatal("authentication error disclosed session credential")
			}
		})
	}
}

func TestBrokerNativeSessionAuthenticationTimeoutFailsClosed(t *testing.T) {
	binding := nativeSessionTestBinding()
	credential := nativeSessionTestCredential(1)
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	defer func() {
		close(release)
		server.Close()
	}()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	writeCertificatePEM(t, caPath, server.Certificate())
	authenticator, err := newBrokerNativeSessionAuthenticator(NativeSessionConfig{
		BrokerURL: server.URL, BrokerServerName: server.Certificate().IPAddresses[0].String(), BrokerCAFile: caPath,
		AuthenticationTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = authenticator.Authenticate(t.Context(), credential, binding)
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("timeout error=%v duration=%s", err, time.Since(started))
	}
	if strings.Contains(err.Error(), credential) {
		t.Fatal("timeout error disclosed credential")
	}
}

func TestNativeSessionRelayPingReplacementAndThirdRejection(t *testing.T) {
	binding := nativeSessionTestBinding()
	firstCredential := nativeSessionTestCredential(1)
	secondCredential := nativeSessionTestCredential(2)
	thirdCredential := nativeSessionTestCredential(3)
	authenticator := &fakeNativeSessionAuthenticator{statuses: map[string]authenticatedNativeSession{
		firstCredential:  nativeSessionTestStatus(binding, time.Now().Add(-time.Second), time.Now().Add(time.Minute)),
		secondCredential: nativeSessionTestStatus(binding, time.Now(), time.Now().Add(2*time.Minute)),
		thirdCredential:  nativeSessionTestStatus(binding, time.Now().Add(time.Second), time.Now().Add(3*time.Minute)),
	}}
	server, address, roots := startNativeSessionTestServer(t, authenticator, time.Minute)
	first := connectNativeSessionTestGuest(t, address, roots, binding, firstCredential)
	defer first.Close()
	if !server.registry.Ready(binding) {
		t.Fatal("first session did not become ready")
	}
	guestDone := make(chan error, 1)
	go func() { guestDone <- serveNativeSessionTestGuest(first, true) }()
	response, err := server.registry.RelayAgentd(t.Context(), binding, json.RawMessage(`{"type":"health"}`))
	if err != nil || string(response) != `{"status":"ready"}` {
		t.Fatalf("relay response=%s error=%v", response, err)
	}

	second := connectNativeSessionTestGuest(t, address, roots, binding, secondCredential)
	defer second.Close()
	third := dialNativeSessionTest(t, address, roots)
	writeNativeSessionTestHello(t, third, binding, thirdCredential)
	rejection := readNativeSessionTestFrame(t, third)
	_ = third.Close()
	if rejection.Type != guestenrollment.NativeSessionHelloReject || rejection.Reason != "capacity-exceeded" {
		t.Fatalf("third connection response = %#v", rejection)
	}
	_ = first.Close()
	select {
	case <-guestDone:
	case <-time.After(time.Second):
		t.Fatal("first session did not close")
	}
	waitNativeSessionActive(t, server.registry, binding, authenticator.statuses[secondCredential].IssuedAt)
	secondDone := make(chan error, 1)
	go func() { secondDone <- serveNativeSessionTestGuest(second, true) }()
	response, err = server.registry.RelayAgentd(t.Context(), binding, json.RawMessage(`{"type":"health"}`))
	if err != nil || string(response) != `{"status":"ready"}` {
		t.Fatalf("replacement relay response=%s error=%v", response, err)
	}
	_ = second.Close()
	<-secondDone
}

func TestNativeSessionRevalidationExpiryAndShutdownRemoveReadiness(t *testing.T) {
	binding := nativeSessionTestBinding()
	credential := nativeSessionTestCredential(1)
	authenticator := &fakeNativeSessionAuthenticator{statuses: map[string]authenticatedNativeSession{
		credential: nativeSessionTestStatus(binding, time.Now().Add(-time.Second), time.Now().Add(5*time.Second)),
	}}
	server, address, roots := startNativeSessionTestServer(t, authenticator, 80*time.Millisecond)
	connection := connectNativeSessionTestGuest(t, address, roots, binding, credential)
	defer connection.Close()
	waitNativeSessionReady(t, server.registry, binding)
	deadline := time.Now().Add(time.Second)
	for server.registry.Ready(binding) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if server.registry.Ready(binding) {
		t.Fatal("revalidation deadline left stale registry readiness")
	}
	buffer := make([]byte, 1)
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := connection.Read(buffer); err == nil {
		t.Fatal("revalidation deadline did not close connection")
	}

	reconnected := connectNativeSessionTestGuest(t, address, roots, binding, credential)
	waitNativeSessionReady(t, server.registry, binding)
	shutdownContext, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	if server.registry.Ready(binding) {
		t.Fatal("shutdown left registry readiness")
	}
	_ = reconnected.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := reconnected.Read(buffer); err == nil {
		t.Fatal("shutdown did not close session")
	}
}

func TestNativeSessionOlderReplayCannotPreemptAndRequestLimitCloses(t *testing.T) {
	binding := nativeSessionTestBinding()
	newCredential := nativeSessionTestCredential(2)
	oldCredential := nativeSessionTestCredential(1)
	now := time.Now()
	authenticator := &fakeNativeSessionAuthenticator{statuses: map[string]authenticatedNativeSession{
		newCredential: nativeSessionTestStatus(binding, now, now.Add(time.Minute)),
		oldCredential: nativeSessionTestStatus(binding, now, now.Add(time.Minute)),
	}}
	server, address, roots := startNativeSessionTestServer(t, authenticator, time.Minute)
	active := connectNativeSessionTestGuest(t, address, roots, binding, newCredential)
	activeDone := make(chan error, 1)
	go func() { activeDone <- serveNativeSessionTestGuest(active, true) }()
	replay := dialNativeSessionTest(t, address, roots)
	writeNativeSessionTestHello(t, replay, binding, oldCredential)
	rejection := readNativeSessionTestFrame(t, replay)
	_ = replay.Close()
	if rejection.Type != guestenrollment.NativeSessionHelloReject || !server.registry.Ready(binding) {
		t.Fatalf("older replay response=%#v ready=%v", rejection, server.registry.Ready(binding))
	}
	server.registry.mu.Lock()
	session := server.registry.bindings[binding].active
	session.requests = guestenrollment.MaxNativeSessionRequestsPerConnection
	server.registry.mu.Unlock()
	if _, err := server.registry.RelayAgentd(t.Context(), binding, json.RawMessage(`{"type":"health"}`)); !errors.Is(err, ErrNativeSessionCapacity) {
		t.Fatalf("request limit error=%v", err)
	}
	if server.registry.Ready(binding) {
		t.Fatal("request limit left session ready")
	}
	_ = active.Close()
	<-activeDone
}

func TestNativeSessionMalformedFramesAndCorrelationFailClosed(t *testing.T) {
	binding := nativeSessionTestBinding()
	credential := nativeSessionTestCredential(1)
	authenticator := &fakeNativeSessionAuthenticator{statuses: map[string]authenticatedNativeSession{
		credential: nativeSessionTestStatus(binding, time.Now().Add(-time.Second), time.Now().Add(time.Minute)),
	}}
	server, address, roots := startNativeSessionTestServer(t, authenticator, time.Minute)
	for name, payload := range map[string][]byte{
		"duplicate": []byte(`{"contract_version":"nvt.native-session/v1","contract_version":"nvt.native-session/v1","type":"hello"}` + "\n"),
		"UTF-8":     {'{', '"', 'x', '"', ':', '"', 0xff, '"', '}', '\n'},
		"oversized": append(bytes.Repeat([]byte("x"), guestenrollment.MaxNativeSessionFrameBytes), '\n'),
	} {
		t.Run(name, func(t *testing.T) {
			connection := dialNativeSessionTest(t, address, roots)
			_, _ = connection.Write(payload)
			_ = connection.SetReadDeadline(time.Now().Add(time.Second))
			buffer := make([]byte, 1)
			if _, err := connection.Read(buffer); err == nil {
				t.Fatal("malformed frame was not rejected")
			}
			_ = connection.Close()
		})
	}

	connection := connectNativeSessionTestGuest(t, address, roots, binding, credential)
	result := make(chan error, 1)
	go func() {
		_, err := server.registry.RelayAgentd(context.Background(), binding, json.RawMessage(`{"type":"health"}`))
		result <- err
	}()
	request := readNativeSessionTestFrame(t, connection)
	if request.Type != guestenrollment.NativeSessionAgentdRequest {
		t.Fatalf("request = %#v", request)
	}
	writeNativeSessionTestFrame(t, connection, guestenrollment.NativeSessionMessage{
		ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionAgentdResponse,
		RequestID: "wrong-id", Payload: json.RawMessage(`{"status":"ready"}`),
	})
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("mismatched response unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("mismatched response did not unblock relay")
	}
	if server.registry.Ready(binding) {
		t.Fatal("protocol failure left registry ready")
	}
}

func TestNativeSessionHeartbeatInterleavesPingAndResponse(t *testing.T) {
	oldHeartbeat, oldFrame := nativeSessionHeartbeatInterval, nativeSessionFrameTimeout
	nativeSessionHeartbeatInterval, nativeSessionFrameTimeout = 20*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { nativeSessionHeartbeatInterval, nativeSessionFrameTimeout = oldHeartbeat, oldFrame })
	binding := nativeSessionTestBinding()
	credential := nativeSessionTestCredential(1)
	authenticator := &fakeNativeSessionAuthenticator{statuses: map[string]authenticatedNativeSession{
		credential: nativeSessionTestStatus(binding, time.Now().Add(-time.Second), time.Now().Add(time.Minute)),
	}}
	server, address, roots := startNativeSessionTestServer(t, authenticator, time.Minute)
	connection := connectNativeSessionTestGuest(t, address, roots, binding, credential)
	defer connection.Close()
	reader := bufio.NewReaderSize(connection, guestenrollment.MaxNativeSessionFrameBytes)
	result := make(chan nativeSessionResponse, 1)
	go func() {
		payload, err := server.registry.RelayAgentd(context.Background(), binding, json.RawMessage(`{"type":"health"}`))
		result <- nativeSessionResponse{payload: payload, err: err}
	}()
	request, err := readNativeSessionFrame(reader, connection, time.Now().Add(time.Second))
	if err != nil || request.Type != guestenrollment.NativeSessionAgentdRequest {
		t.Fatalf("agentd request=%#v error=%v", request, err)
	}
	ping, err := readNativeSessionFrame(reader, connection, time.Now().Add(time.Second))
	if err != nil || ping.Type != guestenrollment.NativeSessionPing {
		t.Fatalf("heartbeat=%#v error=%v", ping, err)
	}
	writeNativeSessionTestFrame(t, connection, guestenrollment.NativeSessionMessage{ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionPing})
	writeNativeSessionTestFrame(t, connection, guestenrollment.NativeSessionMessage{
		ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionAgentdResponse,
		RequestID: request.RequestID, Payload: json.RawMessage(`{"status":"ready"}`),
	})
	writeNativeSessionTestFrame(t, connection, guestenrollment.NativeSessionMessage{ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionPong})
	pong, err := readNativeSessionFrame(reader, connection, time.Now().Add(time.Second))
	if err != nil || pong.Type != guestenrollment.NativeSessionPong {
		t.Fatalf("peer pong=%#v error=%v", pong, err)
	}
	select {
	case response := <-result:
		if response.err != nil || string(response.payload) != `{"status":"ready"}` {
			t.Fatalf("response=%s error=%v", response.payload, response.err)
		}
	case <-time.After(time.Second):
		t.Fatal("interleaved response did not complete")
	}
}

func TestNativeSessionAbsoluteHandshakeAndHelloDeadlinesReleaseCapacity(t *testing.T) {
	oldHandshake, oldFrame := nativeSessionHandshakeLimit, nativeSessionFrameTimeout
	nativeSessionHandshakeLimit, nativeSessionFrameTimeout = 80*time.Millisecond, 80*time.Millisecond
	t.Cleanup(func() { nativeSessionHandshakeLimit, nativeSessionFrameTimeout = oldHandshake, oldFrame })
	binding := nativeSessionTestBinding()
	credential := nativeSessionTestCredential(1)
	authenticator := &fakeNativeSessionAuthenticator{statuses: map[string]authenticatedNativeSession{
		credential: nativeSessionTestStatus(binding, time.Now().Add(-time.Second), time.Now().Add(time.Minute)),
	}}
	server, address, roots := startNativeSessionTestServer(t, authenticator, time.Minute)

	stalledTLS, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	valid := connectNativeSessionTestGuest(t, address, roots, binding, credential)
	_ = valid.Close()
	time.Sleep(120 * time.Millisecond)
	_ = stalledTLS.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := stalledTLS.Read(make([]byte, 1)); err == nil {
		t.Fatal("stalled TLS handshake was not closed at its absolute deadline")
	}
	_ = stalledTLS.Close()

	dripping := dialNativeSessionTest(t, address, roots)
	hello, _ := guestenrollment.EncodeNativeSessionMessage(guestenrollment.NativeSessionMessage{
		ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionHello,
		Binding: &binding, Audience: guestenrollment.NativeGuestControlAudience, Credential: credential,
	})
	start := time.Now()
	for index := 0; index < len(hello) && time.Since(start) < 160*time.Millisecond; index++ {
		if _, err := dripping.Write(hello[index : index+1]); err != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	zeroNativeSessionBytes(hello)
	_ = dripping.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := dripping.Read(make([]byte, 1)); err == nil {
		t.Fatal("slow-drip hello was not closed at its absolute deadline")
	}
	_ = dripping.Close()
	if len(server.connectionSlots) != 0 {
		deadline := time.Now().Add(time.Second)
		for len(server.connectionSlots) != 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}
	if len(server.connectionSlots) != 0 {
		t.Fatalf("connection admission slots were not released: %d", len(server.connectionSlots))
	}
}

func TestNativeSessionGlobalConnectionAdmissionIsBounded(t *testing.T) {
	oldHandshake := nativeSessionHandshakeLimit
	nativeSessionHandshakeLimit = 250 * time.Millisecond
	t.Cleanup(func() { nativeSessionHandshakeLimit = oldHandshake })
	binding := nativeSessionTestBinding()
	credential := nativeSessionTestCredential(1)
	authenticator := &fakeNativeSessionAuthenticator{statuses: map[string]authenticatedNativeSession{
		credential: nativeSessionTestStatus(binding, time.Now().Add(-time.Second), time.Now().Add(time.Minute)),
	}}
	server, address, roots := startNativeSessionTestServer(t, authenticator, time.Minute)
	stalled := make([]net.Conn, 0, maxNativeSessionConnections)
	defer func() {
		for _, connection := range stalled {
			_ = connection.Close()
		}
	}()
	for range maxNativeSessionConnections {
		connection, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		stalled = append(stalled, connection)
	}
	deadline := time.Now().Add(time.Second)
	for len(server.connectionSlots) != maxNativeSessionConnections && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(server.connectionSlots) != maxNativeSessionConnections {
		t.Fatalf("connection admission slots=%d want=%d", len(server.connectionSlots), maxNativeSessionConnections)
	}
	overflow, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = overflow.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := overflow.Read(make([]byte, 1)); err == nil {
		t.Fatal("overflow connection was not rejected")
	}
	_ = overflow.Close()
	deadline = time.Now().Add(time.Second)
	for len(server.connectionSlots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(server.connectionSlots) != 0 {
		t.Fatalf("expired handshakes retained %d connection slots", len(server.connectionSlots))
	}
	valid := connectNativeSessionTestGuest(t, address, roots, binding, credential)
	_ = valid.Close()
}

func nativeSessionTestBinding() guestenrollment.Binding {
	return guestenrollment.Binding{
		AgentRunUID: "11111111-1111-1111-1111-111111111111", ExecutionID: "execution-native-session",
		DriverRegistration: "reference-driver", DesiredGeneration: 1, GuestInstanceID: "guest-instance-1",
	}
}

func nativeSessionTestCredential(sequence uint64) string {
	value := make([]byte, guestenrollment.GuestSessionCredentialBytes)
	binary.BigEndian.PutUint64(value[:8], sequence)
	for index := 8; index < len(value); index++ {
		value[index] = byte(index)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func nativeSessionTestStatus(binding guestenrollment.Binding, issuedAt, expiresAt time.Time) authenticatedNativeSession {
	remaining := time.Until(expiresAt)
	return authenticatedNativeSession{
		Binding: binding, IssuedAt: issuedAt, ExpiresAt: expiresAt,
		LocalExpiresAt: time.Now().Add(remaining),
	}
}

func startNativeSessionTestServer(t *testing.T, authenticator nativeSessionAuthenticator, revalidation time.Duration) (*NativeSessionServer, string, *x509.CertPool) {
	t.Helper()
	certificate, ca := nativeSessionTestCertificate(t, "gateway.test")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := newNativeSessionServer(NativeSessionConfig{
		Enabled: true, ListenAddr: listener.Addr().String(), AuthenticationTimeout: time.Second, RevalidationInterval: revalidation,
	}, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}, authenticator)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("native session server: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("native session server did not stop")
		}
	})
	return server, listener.Addr().String(), ca
}

func connectNativeSessionTestGuest(t *testing.T, address string, roots *x509.CertPool, binding guestenrollment.Binding, credential string) net.Conn {
	t.Helper()
	connection := dialNativeSessionTest(t, address, roots)
	writeNativeSessionTestHello(t, connection, binding, credential)
	acknowledgement := readNativeSessionTestFrame(t, connection)
	if acknowledgement.Type != guestenrollment.NativeSessionHelloAck || acknowledgement.Binding == nil || *acknowledgement.Binding != binding {
		t.Fatalf("native session acknowledgement = %#v", acknowledgement)
	}
	return connection
}

func dialNativeSessionTest(t *testing.T, address string, roots *x509.CertPool) net.Conn {
	t.Helper()
	dialer := &net.Dialer{Timeout: time.Second}
	connection, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "gateway.test"})
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func writeNativeSessionTestHello(t *testing.T, connection net.Conn, binding guestenrollment.Binding, credential string) {
	t.Helper()
	writeNativeSessionTestFrame(t, connection, guestenrollment.NativeSessionMessage{
		ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionHello,
		Binding: &binding, Audience: guestenrollment.NativeGuestControlAudience, Credential: credential,
	})
}

func writeNativeSessionTestFrame(t *testing.T, connection net.Conn, frame guestenrollment.NativeSessionMessage) {
	t.Helper()
	if err := writeNativeSessionFrame(connection, frame, time.Now().Add(time.Second), nil); err != nil {
		t.Fatal(err)
	}
}

func readNativeSessionTestFrame(t *testing.T, connection net.Conn) guestenrollment.NativeSessionMessage {
	t.Helper()
	frame, err := readNativeSessionFrame(bufio.NewReaderSize(connection, guestenrollment.MaxNativeSessionFrameBytes), connection, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func serveNativeSessionTestGuest(connection net.Conn, answerAgentd bool) error {
	reader := bufio.NewReaderSize(connection, guestenrollment.MaxNativeSessionFrameBytes)
	for {
		frame, err := readNativeSessionFrame(reader, connection, time.Now().Add(time.Second))
		if err != nil {
			return err
		}
		switch frame.Type {
		case guestenrollment.NativeSessionPing:
			if err := writeNativeSessionFrame(connection, guestenrollment.NativeSessionMessage{ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionPong}, time.Now().Add(time.Second), nil); err != nil {
				return err
			}
		case guestenrollment.NativeSessionAgentdRequest:
			if !answerAgentd {
				return errors.New("unexpected agentd request")
			}
			if err := writeNativeSessionFrame(connection, guestenrollment.NativeSessionMessage{
				ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionAgentdResponse,
				RequestID: frame.RequestID, Payload: json.RawMessage(`{"status":"ready"}`),
			}, time.Now().Add(time.Second), nil); err != nil {
				return err
			}
		default:
			return errors.New("unexpected frame")
		}
	}
}

func waitNativeSessionReady(t *testing.T, registry *nativeSessionRegistry, binding guestenrollment.Binding) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !registry.Ready(binding) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !registry.Ready(binding) {
		t.Fatal("native session did not become ready")
	}
}

func waitNativeSessionActive(t *testing.T, registry *nativeSessionRegistry, binding guestenrollment.Binding, issuedAt time.Time) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		registry.mu.Lock()
		slot := registry.bindings[binding]
		active := slot != nil && slot.active != nil && slot.active.ready && !slot.active.closed.Load() && slot.active.authenticated.IssuedAt.Equal(issuedAt)
		registry.mu.Unlock()
		if active {
			// The fake authenticator records credentials in authentication order;
			// after the first connection closes, only the acknowledged replacement
			// can occupy the active slot.
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("replacement did not become active")
}

func nativeSessionTestCertificate(t *testing.T, dnsName string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: dnsName}, DNSNames: []string{dnsName},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatePEM) {
		t.Fatal("append test CA")
	}
	return certificate, roots
}

func writeCertificatePEM(t *testing.T, path string, certificate *x509.Certificate) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func ioReadAllBounded(reader io.Reader, limit int) ([]byte, error) {
	return io.ReadAll(io.LimitReader(reader, int64(limit)+1))
}
