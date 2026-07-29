package nativesession

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/workspacetunnel"
)

func TestWorkspaceRuntimeUsesSeparateTLSConnectionsAndExplicitTrust(t *testing.T) {
	certificateSource := httptest.NewTLSServer(http.NotFoundHandler())
	serverTLS := certificateSource.TLS.Clone()
	serverTLS.MinVersion = tls.VersionTLS12
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateSource.Certificate().Raw})
	certificateSource.Close()

	controlListener := listenWorkspaceTLS(t, serverTLS)
	workspaceListener := listenWorkspaceTLS(t, serverTLS)
	backend := startWorkspaceEchoBackend(t)
	work := shortNativeSessionTestDirectory(t)
	agentdSocket := filepath.Join(work, "agentd.sock")
	stopAgentd := serveFakeAgentd(t, agentdSocket)
	defer stopAgentd()
	binding := testBinding()
	now := time.Now().UTC().Truncate(time.Second)
	issuer := &fakeIssuer{binding: binding, now: now}
	controlCredentials := make(chan string, 2)
	workspaceCredentials := make(chan string, 2)
	workspaceSessions := make(chan *workspacetunnel.GatewaySession, 2)
	acceptWorkspaceTLS(t, controlListener, keepWorkspaceControlGateway(binding, controlCredentials))
	acceptWorkspaceTLS(t, workspaceListener, keepWorkspaceGateway(t, binding, workspaceCredentials, workspaceSessions))

	connector, err := NewTLSConnector(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	connector.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		destination := controlListener.Addr().String()
		if address == "example.com:7444" {
			destination = workspaceListener.Addr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, network, destination)
	}
	runtime := newWorkspaceTestRuntime(t, work, agentdSocket, backend, issuer, connector)
	runtime.Configuration.GatewayEndpoint = "tls://example.com:7443"
	runtime.Configuration.Workspace.GatewayEndpoint = "tls://example.com:7444"
	runtime.Now = func() time.Time { return now }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	gateway := waitWorkspaceSession(t, workspaceSessions)
	waitForSessionReadiness(t, runtime.Configuration.RuntimeDirectory)
	controlCredential := waitString(t, controlCredentials, "TLS control credential")
	workspaceCredential := waitString(t, workspaceCredentials, "TLS workspace credential")
	if controlCredential == "" || controlCredential != workspaceCredential {
		cancel()
		t.Fatal("separate TLS legs did not use the same credential")
	}
	assertWorkspaceEcho(t, gateway, "separate-tls")
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(runtime.Configuration.RuntimeDirectory, ReadinessFileName)); !os.IsNotExist(err) {
		t.Fatalf("readiness remained after TLS pair shutdown: %v", err)
	}

	for name, roots := range map[string][]byte{
		"untrusted CA":      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newUnrelatedCertificate(t)}),
		"wrong server name": caPEM,
	} {
		t.Run(name, func(t *testing.T) {
			listener := listenWorkspaceTLS(t, serverTLS)
			acceptWorkspaceTLS(t, listener, func(_ int, connection net.Conn) {
				defer connection.Close()
				if tlsConnection, ok := connection.(*tls.Conn); ok {
					_ = tlsConnection.Handshake()
				}
			})
			client, err := NewTLSConnector(roots)
			if err != nil {
				t.Fatal(err)
			}
			client.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
			}
			endpoint := "tls://example.com:7444"
			if name == "wrong server name" {
				endpoint = "tls://wrong.example:7444"
			}
			if connection, err := client.Connect(t.Context(), endpoint); err == nil {
				_ = connection.Close()
				t.Fatal("invalid workspace trust was accepted")
			}
		})
	}
}

func listenWorkspaceTLS(t *testing.T, configuration *tls.Config) net.Listener {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", configuration.Clone())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func acceptWorkspaceTLS(t *testing.T, listener net.Listener, handler func(int, net.Conn)) {
	t.Helper()
	go func() {
		call := 0
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			call++
			go handler(call, connection)
		}
	}()
}

func newUnrelatedCertificate(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "unrelated.test"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
