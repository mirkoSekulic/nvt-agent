package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

type controlFixture struct {
	server     *ControlServer
	publisher  *TargetPublisher
	registry   *EgressdTargetRegistry
	address    string
	credential string
	pki        testPKI
	done       chan error
}

func startControlFixture(t *testing.T, config Configuration, registry *EgressdTargetRegistry, timeoutOverride ...time.Duration) *controlFixture {
	t.Helper()
	if registry == nil {
		var err error
		registry, err = NewEgressdTargetRegistry([]EgressdTargetDescriptor{})
		if err != nil {
			t.Fatal(err)
		}
	}
	publisher, err := NewTargetPublisher(registry)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewControlServer(config, publisher)
	if err != nil {
		t.Fatal(err)
	}
	if len(timeoutOverride) == 1 {
		server.timeout = timeoutOverride[0]
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	credentialBytes, err := os.ReadFile(config.ControlCredentialFile)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &controlFixture{
		server: server, publisher: publisher, registry: registry, address: listener.Addr().String(),
		credential: string(credentialBytes), pki: newPKIFromConfiguration(t, config), done: done,
	}
	zero(credentialBytes)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	})
	return fixture
}

func newPKIFromConfiguration(t *testing.T, config Configuration) testPKI {
	t.Helper()
	certificatePEM, err := os.ReadFile(config.ControlTLSCertificateFile)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(config.ControlTLSKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(config.BrokerCAFile)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("test control CA was invalid")
	}
	return testPKI{caPEM: caPEM, certificatePEM: certificatePEM, keyPEM: keyPEM, certificate: certificate, rootPool: pool}
}

func (fixture *controlFixture) client(t *testing.T, roots *x509.CertPool, serverName string) *http.Client {
	t.Helper()
	return &http.Client{
		Transport: &http.Transport{
			Proxy: nil, ForceAttemptHTTP2: false,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: serverName},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect rejected") },
		Timeout:       2 * time.Second,
	}
}

func (fixture *controlFixture) post(t *testing.T, client *http.Client, path, credential string, body []byte) (int, []byte) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "https://"+fixture.address+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if credential != "" {
		request.Header.Set("Authorization", "Bearer "+credential)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(response.Body, nativeegress.MaxTargetPublicationResponseBytes+1))
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, encoded
}

func snapshotRequest(t *testing.T, generation uint64, targets []nativeegress.PublishedTarget) (nativeegress.TargetSnapshot, []byte) {
	t.Helper()
	canonical, digest, err := nativeegress.CanonicalTargetSnapshot(targets)
	if err != nil {
		t.Fatal(err)
	}
	request := nativeegress.TargetSnapshot{
		ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetSnapshotReplace,
		Generation: generation, Digest: digest, Targets: canonical,
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return request, encoded
}

func statusRequest(t *testing.T) []byte {
	t.Helper()
	encoded, err := json.Marshal(nativeegress.TargetStatusRequest{
		ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetPublicationStatusRequest,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestControlPublishesCompleteSnapshotStatusIdempotencyAndRestartDenyAll(t *testing.T) {
	broker := newBrokerFixture(t, http.NotFoundHandler())
	fixture := startControlFixture(t, broker.config, nil)
	client := fixture.client(t, fixture.pki.rootPool, "localhost")

	statusCode, body := fixture.post(t, client, nativeegress.TargetStatusPath, fixture.credential, statusRequest(t))
	var status nativeegress.TargetStatus
	if statusCode != http.StatusOK || guestenrollment.DecodeStrictJSON(body, nativeegress.MaxTargetPublicationResponseBytes, &status) != nil ||
		nativeegress.ValidateTargetStatus(status) != nil || status.Published {
		t.Fatalf("initial status=%d %#v", statusCode, status)
	}

	bindingA := testBinding("control-a")
	bindingB := testBinding("control-b")
	request, encoded := snapshotRequest(t, 4, []nativeegress.PublishedTarget{
		{Binding: bindingB, TargetType: nativeegress.EgressdConnectTargetType, ConnectURL: "http://egressd-b.example:8470"},
		{Binding: bindingA, TargetType: nativeegress.EgressdConnectTargetType, ConnectURL: "http://egressd-a.example:8470"},
	})
	statusCode, body = fixture.post(t, client, nativeegress.TargetSnapshotPath, fixture.credential, encoded)
	var acknowledgement nativeegress.TargetSnapshotAcknowledgement
	if statusCode != http.StatusOK || guestenrollment.DecodeStrictJSON(body, nativeegress.MaxTargetPublicationResponseBytes, &acknowledgement) != nil ||
		nativeegress.ValidateTargetSnapshotAcknowledgement(acknowledgement) != nil || acknowledgement.Generation != 4 ||
		acknowledgement.Digest != request.Digest || acknowledgement.TargetCount != 2 {
		t.Fatalf("publication response=%d %#v body=%q", statusCode, acknowledgement, body)
	}
	for _, binding := range []guestenrollment.Binding{bindingA, bindingB} {
		target, err := fixture.registry.ResolveNativeEgressTarget(t.Context(), binding)
		if err != nil || target.Binding() != binding {
			t.Fatalf("exact published target unavailable: %v", err)
		}
	}
	statusCode, statusBody := fixture.post(t, client, nativeegress.TargetStatusPath, fixture.credential, statusRequest(t))
	if statusCode != http.StatusOK || strings.Contains(string(statusBody), bindingA.GuestInstanceID) ||
		strings.Contains(string(statusBody), "egressd-a.example") || strings.Contains(string(statusBody), fixture.credential) {
		t.Fatalf("published status exposed topology or credential: %d %q", statusCode, statusBody)
	}
	statusCode, secondBody := fixture.post(t, client, nativeegress.TargetSnapshotPath, fixture.credential, encoded)
	if statusCode != http.StatusOK || !bytes.Equal(body, secondBody) {
		t.Fatal("same generation and digest was not idempotent")
	}

	conflictRequest, conflictBody := snapshotRequest(t, 4, []nativeegress.PublishedTarget{
		{Binding: bindingA, TargetType: nativeegress.EgressdConnectTargetType, ConnectURL: "http://other.example:8470"},
	})
	if conflictRequest.Digest == request.Digest {
		t.Fatal("conflicting snapshots shared a digest")
	}
	if code, _ := fixture.post(t, client, nativeegress.TargetSnapshotPath, fixture.credential, conflictBody); code != http.StatusConflict {
		t.Fatalf("equal-generation conflict status=%d", code)
	}
	_, staleBody := snapshotRequest(t, 3, []nativeegress.PublishedTarget{})
	if code, _ := fixture.post(t, client, nativeegress.TargetSnapshotPath, fixture.credential, staleBody); code != http.StatusConflict {
		t.Fatalf("stale generation status=%d", code)
	}
	if current := fixture.publisher.Status(); current.Generation != 4 || current.Digest != request.Digest || current.TargetCount != 2 {
		t.Fatal("rejected publication changed applied state")
	}

	_, emptyBody := snapshotRequest(t, 5, []nativeegress.PublishedTarget{})
	if code, _ := fixture.post(t, client, nativeegress.TargetSnapshotPath, fixture.credential, emptyBody); code != http.StatusOK {
		t.Fatalf("applied empty snapshot status=%d", code)
	}
	if current := fixture.publisher.Status(); !current.Published || current.Generation != 5 || current.TargetCount != 0 || current.Digest == "" {
		t.Fatalf("applied empty status=%#v", current)
	}
	if target, err := fixture.registry.ResolveNativeEgressTarget(t.Context(), bindingA); target != nil || !errors.Is(err, ErrTargetUnavailable) {
		t.Fatal("applied empty snapshot did not deny all")
	}

	restartedRegistry, err := NewEgressdTargetRegistry([]EgressdTargetDescriptor{})
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewTargetPublisher(restartedRegistry)
	if err != nil {
		t.Fatal(err)
	}
	if current := restarted.Status(); current.Published || current.Generation != 0 || current.Digest != "" || current.TargetCount != 0 {
		t.Fatal("process restart retained publication state")
	}
}

func TestProductionServiceStartsDenyAllPublishesExactTargetAndRestartsUnpublished(t *testing.T) {
	binding := testBinding("service-restart")
	credential := testCredential(t, 9)
	now := time.Now().UTC().Truncate(time.Second)
	broker := newBrokerFixture(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+credential {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, guestenrollment.MaxNativeEgressIdentityRequestBytes+1))
		decoded, decodeErr := guestenrollment.DecodeNativeEgressAuthenticateRequest(body)
		if err != nil || decodeErr != nil || decoded.Binding != binding {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(guestenrollment.NativeEgressStatus{
			ContractVersion: guestenrollment.NativeEgressIdentityVersion, CredentialType: guestenrollment.NativeEgressCredentialType,
			Binding: binding, Audience: guestenrollment.NativeEgressAudience, Sequence: 9,
			IssuedAt: guestenrollment.FormatTimestamp(now.Add(-time.Minute)), ExpiresAt: guestenrollment.FormatTimestamp(now.Add(4 * time.Minute)),
		})
	}))

	start := func(t *testing.T) (*Service, string, *controlFixture, <-chan error) {
		t.Helper()
		service, err := NewService(broker.config)
		if err != nil {
			t.Fatal(err)
		}
		dataListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		controlListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- service.Serve(dataListener, controlListener) }()
		credentialBytes, err := os.ReadFile(broker.config.ControlCredentialFile)
		if err != nil {
			t.Fatal(err)
		}
		control := &controlFixture{
			server: service.control, publisher: service.publisher, registry: service.registry,
			address: controlListener.Addr().String(), credential: string(credentialBytes), pki: newPKIFromConfiguration(t, broker.config),
		}
		zero(credentialBytes)
		return service, dataListener.Addr().String(), control, done
	}

	service, dataAddress, control, done := start(t)
	if connection, err := connectGuest(t, dataAddress, broker.pki, binding, credential); err == nil {
		_ = connection.Close()
		t.Fatal("unpublished process acknowledged a guest")
	}
	target := nativeegress.PublishedTarget{
		Binding: binding, TargetType: nativeegress.EgressdConnectTargetType, ConnectURL: "http://egressd.example:8470",
	}
	_, encoded := snapshotRequest(t, 1, []nativeegress.PublishedTarget{target})
	client := control.client(t, control.pki.rootPool, "localhost")
	if code, _ := control.post(t, client, nativeegress.TargetSnapshotPath, control.credential, encoded); code != http.StatusOK {
		t.Fatalf("production publication status=%d", code)
	}
	guest, err := connectGuest(t, dataAddress, broker.pki, binding, credential)
	if err != nil {
		t.Fatal(err)
	}
	waitActive(t, service.Sessions(), binding, true)
	_ = guest.Close()
	shutdownContext, cancel := context.WithTimeout(context.Background(), nativeegress.ShutdownTimeout)
	if err := service.Shutdown(shutdownContext); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	restarted, restartedData, restartedControl, restartedDone := start(t)
	if status := restarted.PublicationStatus(); status.Published || status.Generation != 0 || status.Digest != "" {
		t.Fatal("restart retained publication status")
	}
	if connection, err := connectGuest(t, restartedData, broker.pki, binding, credential); err == nil {
		_ = connection.Close()
		t.Fatal("restarted process acknowledged before republish")
	}
	restartedClient := restartedControl.client(t, restartedControl.pki.rootPool, "localhost")
	if code, _ := restartedControl.post(t, restartedClient, nativeegress.TargetSnapshotPath, restartedControl.credential, encoded); code != http.StatusOK {
		t.Fatalf("restart republish status=%d", code)
	}
	republished, err := connectGuest(t, restartedData, broker.pki, binding, credential)
	if err != nil {
		t.Fatal(err)
	}
	waitActive(t, restarted.Sessions(), binding, true)
	_ = republished.Close()
	restartedShutdown, restartedCancel := context.WithTimeout(context.Background(), nativeegress.ShutdownTimeout)
	if err := restarted.Shutdown(restartedShutdown); err != nil {
		restartedCancel()
		t.Fatal(err)
	}
	restartedCancel()
	if err := <-restartedDone; err != nil {
		t.Fatal(err)
	}
}

func TestControlFailsClosedForAuthenticationTLSFramingAndAtomicValidation(t *testing.T) {
	broker := newBrokerFixture(t, http.NotFoundHandler())
	fixture := startControlFixture(t, broker.config, nil)
	client := fixture.client(t, fixture.pki.rootPool, "localhost")
	validTarget := nativeegress.PublishedTarget{
		Binding: testBinding("strict"), TargetType: nativeegress.EgressdConnectTargetType, ConnectURL: "http://egressd.example:8470",
	}
	_, valid := snapshotRequest(t, 1, []nativeegress.PublishedTarget{validTarget})
	for name, credential := range map[string]string{"missing": "", "wrong": mustControlCredential(t)} {
		t.Run(name, func(t *testing.T) {
			code, body := fixture.post(t, client, nativeegress.TargetSnapshotPath, credential, valid)
			failure, decodeErr := nativeegress.DecodeTargetPublicationFailure(body)
			if code != http.StatusUnauthorized || decodeErr != nil || failure.Reason != nativeegress.TargetPublicationReasonDenied ||
				strings.Contains(string(body), validTarget.ConnectURL) || strings.Contains(string(body), fixture.credential) {
				t.Fatalf("credential failure=%d %q", code, body)
			}
		})
	}
	if fixture.publisher.Status().Published {
		t.Fatal("unauthenticated request changed publication state")
	}

	for name, tlsClient := range map[string]*http.Client{
		"wrong SNI":    fixture.client(t, fixture.pki.rootPool, "other.example"),
		"untrusted CA": fixture.client(t, x509.NewCertPool(), "localhost"),
		"TLS downgrade": {Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11, RootCAs: fixture.pki.rootPool, ServerName: "localhost",
		}}, Timeout: time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodPost, "https://"+fixture.address+nativeegress.TargetStatusPath, bytes.NewReader(statusRequest(t)))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+fixture.credential)
			request.Header.Set("Content-Type", "application/json")
			if response, err := tlsClient.Do(request); err == nil {
				response.Body.Close()
				t.Fatal("invalid TLS trust established")
			}
		})
	}

	targetField := []byte(`"connect_url":"http://egressd.example:8470"`)
	malformed := map[string][]byte{
		"duplicate": bytes.Replace(valid, targetField, append(targetField, []byte(`,"connect_url":"http://other.example:8470"`)...), 1),
		"unknown":   append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"credential":"forbidden"}`)...),
		"trailing":  append(append([]byte(nil), valid...), []byte(` {}`)...),
		"oversized": bytes.Repeat([]byte{' '}, nativeegress.MaxTargetPublicationRequestBytes+1),
	}
	for name, value := range malformed {
		t.Run(name, func(t *testing.T) {
			code, body := fixture.post(t, client, nativeegress.TargetSnapshotPath, fixture.credential, value)
			if code != http.StatusBadRequest || strings.Contains(string(body), validTarget.ConnectURL) {
				t.Fatalf("malformed response=%d %q", code, body)
			}
		})
	}
	if fixture.publisher.Status().Published {
		t.Fatal("malformed publication partially applied")
	}

	shared := validTarget
	shared.Binding = testBinding("strict-other")
	if _, _, err := nativeegress.CanonicalTargetSnapshot([]nativeegress.PublishedTarget{validTarget, shared}); err == nil {
		t.Fatal("duplicate exact listener across bindings was accepted")
	}
	validDigest := "sha256:" + strings.Repeat("0", 64)
	for name, targets := range map[string][]nativeegress.PublishedTarget{
		"duplicate binding":  {validTarget, validTarget},
		"duplicate listener": {validTarget, shared},
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(nativeegress.TargetSnapshot{
				ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetSnapshotReplace,
				Generation: 1, Digest: validDigest, Targets: targets,
			})
			if err != nil {
				t.Fatal(err)
			}
			if code, body := fixture.post(t, client, nativeegress.TargetSnapshotPath, fixture.credential, encoded); code != http.StatusBadRequest || strings.Contains(string(body), validTarget.ConnectURL) {
				t.Fatalf("duplicate snapshot response=%d %q", code, body)
			}
		})
	}

	_, firstValid := snapshotRequest(t, 2, []nativeegress.PublishedTarget{validTarget})
	if code, _ := fixture.post(t, client, nativeegress.TargetSnapshotPath, fixture.credential, firstValid); code != http.StatusOK {
		t.Fatalf("valid baseline publication status=%d", code)
	}
	baselineTarget, err := fixture.registry.ResolveNativeEgressTarget(t.Context(), validTarget.Binding)
	if err != nil {
		t.Fatal(err)
	}
	invalidEntry := validTarget
	invalidEntry.Binding = testBinding("invalid-entry")
	invalidEntry.ConnectURL = "http://EGRESSD.example:8470"
	encodedInvalid, err := json.Marshal(nativeegress.TargetSnapshot{
		ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetSnapshotReplace,
		Generation: 3, Digest: validDigest, Targets: []nativeegress.PublishedTarget{validTarget, invalidEntry},
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := fixture.post(t, client, nativeegress.TargetSnapshotPath, fixture.credential, encodedInvalid); code != http.StatusBadRequest {
		t.Fatalf("invalid-entry snapshot response=%d", code)
	}
	if current, err := fixture.registry.ResolveNativeEgressTarget(t.Context(), validTarget.Binding); err != nil || current != baselineTarget {
		t.Fatal("invalid complete snapshot disturbed the previous mapping")
	}
	if current := fixture.publisher.Status(); current.Generation != 2 || current.TargetCount != 1 {
		t.Fatal("invalid complete snapshot disturbed publication metadata")
	}
}

func TestPublicationReplacementWithdrawsAffectedSessionBeforeAckAndPreservesUnaffected(t *testing.T) {
	registry, err := NewEgressdTargetRegistry([]EgressdTargetDescriptor{})
	if err != nil {
		t.Fatal(err)
	}
	bindingA := testBinding("withdraw-a")
	bindingB := testBinding("withdraw-b")
	credentialA := testCredential(t, 1)
	credentialB := testCredential(t, 2)
	authenticator := &fakeAuthenticator{bindings: map[string]guestenrollment.Binding{credentialA: bindingA, credentialB: bindingB}}
	dataServer, address, pki, _ := startInjectedServer(t, authenticator, registry, time.Second, 8)
	if err := registry.bindSessionWithdrawal(dataServer.registry.WithdrawBindings); err != nil {
		t.Fatal(err)
	}
	publisher, err := NewTargetPublisher(registry)
	if err != nil {
		t.Fatal(err)
	}
	initial, _ := snapshotRequest(t, 1, []nativeegress.PublishedTarget{
		{Binding: bindingA, TargetType: nativeegress.EgressdConnectTargetType, ConnectURL: "http://egressd-a.example:8470"},
		{Binding: bindingB, TargetType: nativeegress.EgressdConnectTargetType, ConnectURL: "http://egressd-b.example:8470"},
	})
	if _, err := publisher.Apply(t.Context(), initial); err != nil {
		t.Fatal(err)
	}
	guestA, err := connectGuest(t, address, pki, bindingA, credentialA)
	if err != nil {
		t.Fatal(err)
	}
	defer guestA.Close()
	guestB, err := connectGuest(t, address, pki, bindingB, credentialB)
	if err != nil {
		t.Fatal(err)
	}
	defer guestB.Close()
	waitActive(t, dataServer.Sessions(), bindingA, true)
	unaffected := waitActive(t, dataServer.Sessions(), bindingB, true)
	oldTarget, err := registry.ResolveNativeEgressTarget(t.Context(), bindingA)
	if err != nil {
		t.Fatal(err)
	}

	replacement, _ := snapshotRequest(t, 2, []nativeegress.PublishedTarget{
		{Binding: bindingA, TargetType: nativeegress.EgressdConnectTargetType, ConnectURL: "http://egressd-a-new.example:8470"},
		{Binding: bindingB, TargetType: nativeegress.EgressdConnectTargetType, ConnectURL: "http://egressd-b.example:8470"},
	})
	acknowledgement, err := publisher.Apply(t.Context(), replacement)
	if err != nil || acknowledgement.Generation != 2 {
		t.Fatal(err)
	}
	if _, ready := dataServer.Sessions().Active(bindingA); ready {
		t.Fatal("replacement acknowledged before affected session withdrawal")
	}
	if current, ready := dataServer.Sessions().Active(bindingB); !ready || current != unaffected {
		t.Fatal("replacement disturbed unaffected binding")
	}
	if flow, err := oldTarget.OpenFlow(t.Context(), nativeegress.Destination{Network: nativeegress.NetworkTCP, Host: "api.example", Port: 443}); err == nil {
		_ = flow.Close()
		t.Fatal("withdrawn target accepted a new flow")
	}
	waitGuestClosed(t, guestA)
}

func TestControlBoundsSlowRequestsConcurrencyAndRedactsObservability(t *testing.T) {
	broker := newBrokerFixture(t, http.NotFoundHandler())
	fixture := startControlFixture(t, broker.config, nil, time.Second)

	connections := make([]net.Conn, 0, nativeegress.MaxTargetPublicationConcurrency)
	for range nativeegress.MaxTargetPublicationConcurrency {
		connection, err := tls.Dial("tcp", fixture.address, &tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: fixture.pki.rootPool, ServerName: "localhost",
		})
		if err != nil {
			t.Fatal(err)
		}
		request := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAuthorization: Bearer %s\r\nContent-Length: 100\r\n\r\n{", nativeegress.TargetSnapshotPath, fixture.credential)
		if _, err := io.WriteString(connection, request); err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
	}
	waitForCondition(t, func() bool { return len(fixture.server.requestSlots) == nativeegress.MaxTargetPublicationConcurrency }, "bounded control admissions")
	start := time.Now()
	overflow, err := net.DialTimeout("tcp", fixture.address, time.Second)
	if err == nil {
		_ = overflow.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, _ = overflow.Read(make([]byte, 1))
		_ = overflow.Close()
	}
	if time.Since(start) > time.Second {
		t.Fatal("control capacity rejection was not bounded")
	}
	for _, connection := range connections {
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = connection.Read(make([]byte, 1))
		_ = connection.Close()
	}
	waitForCondition(t, func() bool { return len(fixture.server.requestSlots) == 0 }, "control deadline admission release")

	canary := fixture.credential
	bindingCanary := "topology-binding-canary"
	for _, formatted := range []string{
		fmt.Sprint(fixture.server), fmt.Sprintf("%#v", fixture.server), fmt.Sprint(fixture.publisher),
		fmt.Sprint(nativeegress.PublishedTarget{Binding: testBinding(bindingCanary), ConnectURL: "http://target-canary.example:8470"}),
	} {
		if strings.Contains(formatted, canary) || strings.Contains(formatted, bindingCanary) || strings.Contains(formatted, "target-canary") {
			t.Fatalf("control formatting exposed secret/topology: %q", formatted)
		}
	}
}

func TestPublisherCancellationBeforeCommitLeavesDenyAllUnpublished(t *testing.T) {
	registry, err := NewEgressdTargetRegistry([]EgressdTargetDescriptor{})
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewTargetPublisher(registry)
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding("canceled-publication")
	snapshot, _ := snapshotRequest(t, 1, []nativeegress.PublishedTarget{{
		Binding: binding, TargetType: nativeegress.EgressdConnectTargetType, ConnectURL: "http://egressd.example:8470",
	}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := publisher.Apply(ctx, snapshot); !errors.Is(err, errTargetPublicationUnavailable) {
		t.Fatalf("canceled publication error=%v", err)
	}
	if publisher.Status().Published {
		t.Fatal("canceled pre-commit publication changed status")
	}
	if target, err := registry.ResolveNativeEgressTarget(t.Context(), binding); target != nil || !errors.Is(err, ErrTargetUnavailable) {
		t.Fatal("canceled pre-commit publication installed a target")
	}
}

func TestControlCredentialComparisonHandlesConcurrentWrongValues(t *testing.T) {
	broker := newBrokerFixture(t, http.NotFoundHandler())
	fixture := startControlFixture(t, broker.config, nil)
	client := fixture.client(t, fixture.pki.rootPool, "localhost")
	body := statusRequest(t)
	var wait sync.WaitGroup
	for index := range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			wrong := fmt.Sprintf("%s%043d", nativeegress.RelayControlCredentialPrefix, index)
			request, _ := http.NewRequest(http.MethodPost, "https://"+fixture.address+nativeegress.TargetStatusPath, bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+wrong)
			response, err := client.Do(request)
			if err == nil {
				_, _ = io.Copy(io.Discard, response.Body)
				response.Body.Close()
			}
		}()
	}
	wait.Wait()
	if fixture.publisher.Status().Published {
		t.Fatal("wrong concurrent credentials changed state")
	}
}
