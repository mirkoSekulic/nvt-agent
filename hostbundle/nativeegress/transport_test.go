package nativeegress

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
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	protocol "github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

func TestTLSConnectorAndNativeEgressHelloUseExplicitTrust(t *testing.T) {
	certificateSource := httptest.NewTLSServer(http.NotFoundHandler())
	serverTLS := certificateSource.TLS.Clone()
	serverTLS.MinVersion = tls.VersionTLS12
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateSource.Certificate().Raw})
	certificateSource.Close()

	binding := nativeEgressBinding()
	now := time.Now().UTC().Truncate(time.Second)
	credentialValue, err := guestenrollment.GenerateNativeEgressCredential(1)
	if err != nil {
		t.Fatal(err)
	}
	authenticator := &fakeAuthenticator{binding: binding, issuedAt: now}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer connection.Close()
		_, err = protocol.Accept(context.Background(), connection, authenticator)
		accepted <- err
		if err == nil {
			var one [1]byte
			_, _ = connection.Read(one[:])
		}
	}()

	connector, err := NewTLSConnector(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	connector.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	}
	connection, err := connector.Connect(context.Background(), "tls://example.com:7445")
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.Establish(context.Background(), connection, binding, credentialValue); err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	if err := <-accepted; err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	_ = connection.Close()
	authenticator.mu.Lock()
	observed := append([]string(nil), authenticator.credentials...)
	authenticator.mu.Unlock()
	if len(observed) != 1 || observed[0] != credentialValue {
		t.Fatal("relay did not authenticate the exact transient credential")
	}
}

func TestTLSConnectorRejectsUntrustedWrongNameAndTLS11(t *testing.T) {
	certificateSource := httptest.NewTLSServer(http.NotFoundHandler())
	serverTLS := certificateSource.TLS.Clone()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateSource.Certificate().Raw})
	certificateSource.Close()

	for name, configure := range map[string]func(*TLSConnector, *tls.Config) string{
		"wrong server name": func(_ *TLSConnector, _ *tls.Config) string { return "tls://wrong.example:7445" },
		"TLS 1.1 only": func(_ *TLSConnector, server *tls.Config) string {
			server.MinVersion, server.MaxVersion = tls.VersionTLS11, tls.VersionTLS11
			return "tls://example.com:7445"
		},
	} {
		t.Run(name, func(t *testing.T) {
			serverConfiguration := serverTLS.Clone()
			connector, err := NewTLSConnector(caPEM)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := configure(connector, serverConfiguration)
			listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfiguration)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				connection, err := listener.Accept()
				if err == nil {
					if tlsConnection, ok := connection.(*tls.Conn); ok {
						_ = tlsConnection.Handshake()
					}
					_ = connection.Close()
				}
			}()
			connector.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
			}
			if connection, err := connector.Connect(context.Background(), endpoint); err == nil {
				_ = connection.Close()
				t.Fatal("invalid relay TLS was accepted")
			}
		})
	}

	unrelatedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: unrelatedNativeEgressCertificate(t)})
	connector, err := NewTLSConnector(unrelatedPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			if tlsConnection, ok := connection.(*tls.Conn); ok {
				_ = tlsConnection.Handshake()
			}
			_ = connection.Close()
		}
	}()
	connector.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	}
	if connection, err := connector.Connect(context.Background(), "tls://example.com:7445"); err == nil {
		_ = connection.Close()
		t.Fatal("untrusted relay CA was accepted")
	}
}

func unrelatedNativeEgressCertificate(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(841), Subject: pkix.Name{CommonName: "unrelated.invalid"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestRelayEndpointIsCanonicalAndSecretFree(t *testing.T) {
	for _, value := range []string{
		"http://relay.example:7445", "tls://127.0.0.1:7445", "tls://[::1]:7445",
		"tls://relay.example", "tls://relay.example:0", "tls://relay.example:65536",
		"tls://user@relay.example:7445", "tls://relay.example:7445/path", "TLS://relay.example:7445",
		"tls://Relay.example:7445", "tls://-relay.example:7445", "tls://relay_.example:7445",
		"tls://relay.example.:7445",
	} {
		if validateRelayEndpoint(value) == nil {
			t.Fatalf("invalid relay endpoint accepted: %q", value)
		}
	}
	if validateRelayEndpoint("tls://relay.example:7445") != nil {
		t.Fatal("canonical relay endpoint rejected")
	}
	configuration := Configuration{RelayEndpoint: "tls://relay.example:7445"}
	if configuration.String() == configuration.RelayEndpoint || configuration.GoString() == configuration.RelayEndpoint {
		t.Fatal("configuration formatting exposed relay details")
	}
}
