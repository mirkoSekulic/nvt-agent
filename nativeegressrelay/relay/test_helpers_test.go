package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

type testPKI struct {
	caPEM          []byte
	certificatePEM []byte
	keyPEM         []byte
	certificate    tls.Certificate
	rootPool       *x509.CertPool
}

func newTestPKI(t *testing.T, serverName string) testPKI {
	t.Helper()
	now := time.Now().Add(-time.Hour)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "NVT relay test CA"},
		NotBefore: now, NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: serverName},
		NotBefore: now, NotAfter: now.Add(24 * time.Hour), DNSNames: []string{serverName},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	value := testPKI{
		caPEM:          pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		certificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		keyPEM:         pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
	value.certificate, err = tls.X509KeyPair(value.certificatePEM, value.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	value.rootPool = x509.NewCertPool()
	if !value.rootPool.AppendCertsFromPEM(value.caPEM) {
		t.Fatal("test CA was rejected")
	}
	return value
}

func testBinding(suffix string) guestenrollment.Binding {
	return guestenrollment.Binding{
		AgentRunUID: "run-uid-" + suffix, ExecutionID: "execution-" + suffix,
		DriverRegistration: "driver-" + suffix, DesiredGeneration: 7, GuestInstanceID: "guest-" + suffix,
	}
}

func testCredential(t *testing.T, sequence uint64) string {
	t.Helper()
	credential, err := guestenrollment.GenerateNativeEgressCredential(sequence)
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

type fakeAuthenticator struct {
	mu        sync.Mutex
	bindings  map[string]guestenrollment.Binding
	calls     []string
	denied    bool
	temporary bool
	now       func() time.Time
	events    *[]string
	eventsMu  *sync.Mutex
}

func (authenticator *fakeAuthenticator) AuthenticateNativeEgress(_ context.Context, credential string, binding guestenrollment.Binding) (nativeegress.Authentication, error) {
	authenticator.mu.Lock()
	authenticator.calls = append(authenticator.calls, credential)
	denied := authenticator.denied
	temporary := authenticator.temporary
	expected, exists := authenticator.bindings[credential]
	now := time.Now().UTC().Truncate(time.Second)
	if authenticator.now != nil {
		now = authenticator.now()
	}
	authenticator.mu.Unlock()
	if authenticator.events != nil {
		authenticator.eventsMu.Lock()
		*authenticator.events = append(*authenticator.events, "broker")
		authenticator.eventsMu.Unlock()
	}
	if temporary {
		return nativeegress.Authentication{}, nativeegress.ErrAuthenticationTemporary
	}
	if denied || !exists || expected != binding {
		return nativeegress.Authentication{}, nativeegress.ErrAuthenticationDenied
	}
	sequence, err := guestenrollment.NativeEgressCredentialSequence(credential)
	if err != nil {
		return nativeegress.Authentication{}, nativeegress.ErrAuthenticationDenied
	}
	return nativeegress.Authentication{
		Binding: binding, Sequence: sequence, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(4 * time.Minute),
	}, nil
}

type fakeTarget struct {
	binding      guestenrollment.Binding
	mu           sync.Mutex
	opens        int
	destinations []nativeegress.Destination
	peers        []net.Conn
	echo         bool
	deny         bool
	err          error
}

func (target *fakeTarget) Binding() guestenrollment.Binding { return target.binding }

func (target *fakeTarget) OpenFlow(_ context.Context, destination nativeegress.Destination) (net.Conn, error) {
	target.mu.Lock()
	target.opens++
	target.destinations = append(target.destinations, destination)
	denied := target.deny
	failure := target.err
	target.mu.Unlock()
	if denied {
		return nil, nativeegress.ErrDenied
	}
	if failure != nil {
		return nil, failure
	}
	client, peer := net.Pipe()
	target.mu.Lock()
	target.peers = append(target.peers, peer)
	target.mu.Unlock()
	if target.echo {
		go func() {
			_, _ = io.Copy(peer, peer)
			_ = peer.Close()
		}()
	}
	return client, nil
}

func (target *fakeTarget) closePeers() {
	target.mu.Lock()
	peers := append([]net.Conn(nil), target.peers...)
	target.peers = nil
	target.mu.Unlock()
	for _, peer := range peers {
		_ = peer.Close()
	}
}

type fakeResolver struct {
	mu       sync.Mutex
	targets  map[guestenrollment.Binding]*fakeTarget
	calls    []guestenrollment.Binding
	err      error
	events   *[]string
	eventsMu *sync.Mutex
}

func (resolver *fakeResolver) ResolveNativeEgressTarget(_ context.Context, binding guestenrollment.Binding) (nativeegress.EgressTarget, error) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	resolver.calls = append(resolver.calls, binding)
	if resolver.events != nil {
		resolver.eventsMu.Lock()
		*resolver.events = append(*resolver.events, "target")
		resolver.eventsMu.Unlock()
	}
	if resolver.err != nil {
		return nil, resolver.err
	}
	target := resolver.targets[binding]
	if target == nil {
		return nil, ErrTargetUnavailable
	}
	return target, nil
}

func startInjectedServer(t *testing.T, authenticator nativeegress.Authenticator, resolver TargetResolver, revalidation time.Duration, handshakeCapacity int, handshakeTimeout ...time.Duration) (*Server, string, testPKI, <-chan error) {
	t.Helper()
	pki := newTestPKI(t, "localhost")
	server := newServer("127.0.0.1:1", revalidation, &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pki.certificate},
	}, authenticator, resolver, handshakeCapacity)
	if len(handshakeTimeout) == 1 {
		server.handshakeTimeout = handshakeTimeout[0]
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), nativeegress.ShutdownTimeout)
		defer cancel()
		_ = server.Shutdown(ctx)
		select {
		case <-serveDone:
		default:
		}
	})
	return server, listener.Addr().String(), pki, serveDone
}

type guestRelayConnection struct {
	transport *nativeegress.GuestFlowTransport
}

func (connection *guestRelayConnection) OpenFlow(ctx context.Context, destination nativeegress.Destination) (net.Conn, error) {
	return connection.transport.OpenFlow(ctx, destination)
}

func (connection *guestRelayConnection) Close() error { return connection.transport.Close() }
func (connection *guestRelayConnection) Done() <-chan struct{} {
	return connection.transport.Done()
}

func connectGuest(t *testing.T, address string, pki testPKI, binding guestenrollment.Binding, credential string) (*guestRelayConnection, error) {
	t.Helper()
	dialer := &tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pki.rootPool, ServerName: "localhost"}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	tlsConnection := connection.(*tls.Conn)
	if err := nativeegress.Establish(ctx, tlsConnection, binding, credential); err != nil {
		_ = tlsConnection.Close()
		return nil, err
	}
	transport, err := nativeegress.NewGuestFlowTransport(tlsConnection)
	if err != nil {
		_ = tlsConnection.Close()
		return nil, err
	}
	readyContext, cancelReady := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelReady()
	if err := transport.AwaitReady(readyContext); err != nil {
		_ = transport.Close()
		return nil, err
	}
	return &guestRelayConnection{transport: transport}, nil
}

func waitActive(t *testing.T, lookup SessionLookup, binding guestenrollment.Binding, expected bool) *nativeegress.Session {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		session, active := lookup.Active(binding)
		if active == expected {
			return session
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("native egress active state did not become %v", expected)
	return nil
}

func waitConnectionClosed(t *testing.T, connection net.Conn) {
	t.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	var one [1]byte
	if _, err := connection.Read(one[:]); err == nil {
		t.Fatal("native egress connection remained open")
	}
}

func waitGuestClosed(t *testing.T, connection *guestRelayConnection) {
	t.Helper()
	select {
	case <-connection.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("native egress guest transport remained open")
	}
}

func writeTestFile(t *testing.T, directory, name string, value []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, value, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}
