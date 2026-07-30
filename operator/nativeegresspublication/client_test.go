package nativeegresspublication

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
	"strings"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

func TestClientPublishesAndReadsStrictTLSStatus(t *testing.T) {
	credential, err := nativeegress.GenerateRelayControlCredential()
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding()
	targets, digest, err := nativeegress.CanonicalTargetSnapshot([]nativeegress.PublishedTarget{{
		Binding: binding, TargetType: nativeegress.EgressdConnectTargetType, ConnectURL: "http://run-egressd.test:8473",
	}})
	if err != nil {
		t.Fatal(err)
	}
	var seenAuthorization []string
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		seenAuthorization = append(seenAuthorization, request.Header.Get("Authorization"))
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case nativeegress.TargetStatusPath:
			encoded, _ := nativeegress.EncodeTargetStatus(nativeegress.TargetStatus{ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetPublicationStatusResponse})
			_, _ = response.Write(encoded)
		case nativeegress.TargetSnapshotPath:
			encoded, _ := nativeegress.EncodeTargetSnapshotAcknowledgement(nativeegress.TargetSnapshotAcknowledgement{
				ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetSnapshotAck, Generation: 1, Digest: digest, TargetCount: 1,
			})
			_, _ = response.Write(encoded)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	})
	server, ca := newTLSServer(t, handler)
	defer server.Close()
	client := newTestClient(t, server, ca, credential, "localhost")
	status, err := client.Status(context.Background())
	if err != nil || status.Published {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	ack, err := client.Publish(context.Background(), nativeegress.TargetSnapshot{
		ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetSnapshotReplace,
		Generation: 1, Digest: digest, Targets: targets,
	})
	if err != nil || ack.Digest != digest {
		t.Fatalf("ack=%#v err=%v", ack, err)
	}
	if len(seenAuthorization) != 2 || seenAuthorization[0] != "Bearer "+credential || seenAuthorization[1] != "Bearer "+credential {
		t.Fatal("control authorization was not exact")
	}
	for _, value := range []string{client.String(), client.GoString(), ErrUnavailable.Error(), ErrConflict.Error(), ErrRejected.Error()} {
		if strings.Contains(value, credential) {
			t.Fatal("credential leaked through formatting")
		}
	}
}

func TestClientFailsClosedForTrustRedirectAndMalformedResponses(t *testing.T) {
	credential, _ := nativeegress.GenerateRelayControlCredential()
	tests := []struct {
		name       string
		handler    http.Handler
		serverName string
		wrongCA    bool
	}{
		{name: "wrong server name", handler: statusHandler(), serverName: "wrong.localhost"},
		{name: "wrong CA", handler: statusHandler(), serverName: "localhost", wrongCA: true},
		{name: "redirect", serverName: "localhost", handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://localhost/other", http.StatusFound)
		})},
		{name: "malformed", serverName: "localhost", handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"published":true}`))
		})},
		{name: "oversized", serverName: "localhost", handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(make([]byte, nativeegress.MaxTargetPublicationResponseBytes+1))
		})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, ca := newTLSServer(t, test.handler)
			defer server.Close()
			if test.wrongCA {
				_, ca = testTLSIdentity(t, "another.localhost")
			}
			client := newTestClient(t, server, ca, credential, test.serverName)
			if _, err := client.Status(context.Background()); !errorsIsUnavailable(err) {
				t.Fatalf("expected generic unavailable, got %v", err)
			}
		})
	}
}

func statusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		encoded, _ := nativeegress.EncodeTargetStatus(nativeegress.TargetStatus{ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetPublicationStatusResponse})
		_, _ = w.Write(encoded)
	})
}

func newTestClient(t *testing.T, server *httptest.Server, ca []byte, credential, serverName string) *Client {
	t.Helper()
	directory := t.TempDir()
	caFile, credentialFile := filepath.Join(directory, "ca.pem"), filepath.Join(directory, "credential")
	if err := os.WriteFile(caFile, ca, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credentialFile, []byte(credential), 0600); err != nil {
		t.Fatal(err)
	}
	address := server.Listener.Addr().String()
	_, port, _ := net.SplitHostPort(address)
	client, err := New(Config{BaseURL: "https://localhost:" + port, ServerName: "localhost", CAFile: caFile, CredentialFile: credentialFile, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if serverName != "localhost" {
		client.http.Transport.(*http.Transport).TLSClientConfig.ServerName = serverName
	}
	return client
}

func newTLSServer(t *testing.T, handler http.Handler) (*httptest.Server, []byte) {
	t.Helper()
	certificate, ca := testTLSIdentity(t, "localhost")
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	return server, ca
}

func testTLSIdentity(t *testing.T, name string) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, certPEM
}

func testBinding() guestenrollment.Binding {
	return guestenrollment.Binding{AgentRunUID: "12345678-1234-1234-1234-123456789012", ExecutionID: "agentrun-1234567812341234", DriverRegistration: "example-vm", DesiredGeneration: 1, GuestInstanceID: "guest-1"}
}

func errorsIsUnavailable(err error) bool { return err == ErrUnavailable }
