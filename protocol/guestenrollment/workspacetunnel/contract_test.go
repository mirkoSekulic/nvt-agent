package workspacetunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

type testAuthenticator struct {
	credential     string
	binding        guestenrollment.Binding
	authentication *Authentication
	err            error
}

type blockingAuthenticator struct{}

func (blockingAuthenticator) AuthenticateWorkspace(ctx context.Context, _ string, _ guestenrollment.Binding) (Authentication, error) {
	<-ctx.Done()
	return Authentication{}, ErrAuthenticationTemporary
}

func (authenticator testAuthenticator) AuthenticateWorkspace(_ context.Context, credential string, binding guestenrollment.Binding) (Authentication, error) {
	if authenticator.err != nil {
		return Authentication{}, authenticator.err
	}
	if credential != authenticator.credential || binding != authenticator.binding {
		return Authentication{}, ErrAuthenticationDenied
	}
	if authenticator.authentication != nil {
		return *authenticator.authentication, nil
	}
	sequence, err := guestenrollment.GuestSessionCredentialSequence(credential)
	if err != nil {
		return Authentication{}, ErrAuthenticationDenied
	}
	now := time.Now()
	return Authentication{Binding: binding, Sequence: sequence, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, nil
}

func TestWorkspaceHandshakeStrictRoundTripAndRedaction(t *testing.T) {
	binding := testBinding()
	credential := testCredential(t, 1)
	message := Message{
		ContractVersion: Version,
		Type:            Hello,
		Binding:         &binding,
		Audience:        guestenrollment.NativeGuestControlAudience,
		Credential:      credential,
	}
	encoded, err := EncodeMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeMessage(encoded)
	if err != nil || decoded.Binding == nil || *decoded.Binding != binding || decoded.Credential != credential {
		t.Fatalf("decoded handshake=%#v error=%v", decoded, err)
	}
	for _, rendered := range []string{fmt.Sprint(message), fmt.Sprintf("%#v", message)} {
		if strings.Contains(rendered, credential) {
			t.Fatal("handshake formatting disclosed credential")
		}
	}

	valid, _ := EncodeMessage(message)
	oversized := append(make([]byte, MaxFrameBytes), '\n')
	invalidUTF8 := append([]byte(nil), valid...)
	invalidUTF8[len(invalidUTF8)-2] = 0xff
	for name, value := range map[string][]byte{
		"unknown field":   []byte(`{"contract_version":"nvt.native-workspace/v1","type":"hello","binding":{},"audience":"nvt.native-guest-control/v1","credential":"x","extra":true}`),
		"duplicate key":   []byte(`{"contract_version":"nvt.native-workspace/v1","contract_version":"nvt.native-workspace/v1","type":"hello"}`),
		"invalid utf8":    invalidUTF8,
		"trailing object": append(valid, []byte(`{}`)...),
		"oversized":       oversized,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeMessage(value); !errors.Is(err, ErrProtocol) {
				t.Fatalf("DecodeMessage error=%v", err)
			}
		})
	}
}

func TestWorkspaceHandshakeAuthenticationOutcomes(t *testing.T) {
	binding := testBinding()
	credential := testCredential(t, 1)
	for _, test := range []struct {
		name      string
		authError error
		guestErr  error
		serverErr error
	}{
		{name: "success"},
		{name: "denied", authError: ErrAuthenticationDenied, guestErr: ErrDenied, serverErr: ErrDenied},
		{name: "temporary closes silently", authError: ErrAuthenticationTemporary, guestErr: ErrUnavailable, serverErr: ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			gatewayConnection, guestConnection := net.Pipe()
			serverResult := make(chan error, 1)
			go func() {
				defer gatewayConnection.Close()
				_, err := Accept(t.Context(), gatewayConnection, testAuthenticator{
					credential: credential, binding: binding, err: test.authError,
				})
				serverResult <- err
			}()
			guestErr := Establish(t.Context(), guestConnection, binding, credential)
			_ = guestConnection.Close()
			serverErr := <-serverResult
			if test.guestErr == nil {
				if guestErr != nil || serverErr != nil {
					t.Fatalf("guest error=%v server error=%v", guestErr, serverErr)
				}
				return
			}
			if !errors.Is(guestErr, test.guestErr) || !errors.Is(serverErr, test.serverErr) {
				t.Fatalf("guest error=%v server error=%v", guestErr, serverErr)
			}
		})
	}
}

func TestWorkspaceHandshakeBoundsAuthenticationByCallerDeadline(t *testing.T) {
	binding := testBinding()
	credential := testCredential(t, 1)
	gatewayConnection, guestConnection := net.Pipe()
	serverResult := make(chan error, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	go func() {
		defer gatewayConnection.Close()
		_, err := Accept(ctx, gatewayConnection, blockingAuthenticator{})
		serverResult <- err
	}()

	started := time.Now()
	guestErr := Establish(t.Context(), guestConnection, binding, credential)
	_ = guestConnection.Close()
	serverErr := <-serverResult
	if !errors.Is(guestErr, ErrUnavailable) || !errors.Is(serverErr, ErrUnavailable) {
		t.Fatalf("guest error=%v server error=%v", guestErr, serverErr)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("authentication exceeded caller deadline: %v", elapsed)
	}
}

func TestWorkspaceAuthenticationCarriesSequenceAndBoundsTrustWindow(t *testing.T) {
	binding := testBinding()
	credential := testCredential(t, 41)
	gatewayConnection, guestConnection := net.Pipe()
	type result struct {
		authentication Authentication
		err            error
	}
	serverResult := make(chan result, 1)
	go func() {
		defer gatewayConnection.Close()
		authentication, err := Accept(t.Context(), gatewayConnection, testAuthenticator{credential: credential, binding: binding})
		serverResult <- result{authentication: authentication, err: err}
	}()
	if err := Establish(t.Context(), guestConnection, binding, credential); err != nil {
		t.Fatal(err)
	}
	_ = guestConnection.Close()
	accepted := <-serverResult
	if accepted.err != nil || accepted.authentication.Binding != binding || accepted.authentication.Sequence != 41 {
		t.Fatalf("authentication=%#v error=%v", accepted.authentication, accepted.err)
	}
	remaining := time.Until(accepted.authentication.LocalExpiresAt)
	if remaining <= 0 || remaining > guestenrollment.MaxGuestSessionCredentialLifetime {
		t.Fatalf("derived local trust window=%v", remaining)
	}

	now := time.Now()
	farFuture := Authentication{
		Binding: binding, Sequence: 41, IssuedAt: now,
		ExpiresAt: now.Add(guestenrollment.MaxGuestSessionCredentialLifetime + time.Hour),
	}
	gatewayConnection, guestConnection = net.Pipe()
	serverError := make(chan error, 1)
	go func() {
		defer gatewayConnection.Close()
		_, err := Accept(t.Context(), gatewayConnection, testAuthenticator{
			credential: credential, binding: binding, authentication: &farFuture,
		})
		serverError <- err
	}()
	guestError := Establish(t.Context(), guestConnection, binding, credential)
	_ = guestConnection.Close()
	authorityError := <-serverError
	if !errors.Is(guestError, ErrUnavailable) || !errors.Is(authorityError, ErrUnavailable) {
		t.Fatalf("far-future authority errors guest=%v server=%v", guestError, authorityError)
	}

	mismatchedSequence := Authentication{
		Binding: binding, Sequence: 42, IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	gatewayConnection, guestConnection = net.Pipe()
	serverError = make(chan error, 1)
	go func() {
		defer gatewayConnection.Close()
		_, err := Accept(t.Context(), gatewayConnection, testAuthenticator{
			credential: credential, binding: binding, authentication: &mismatchedSequence,
		})
		serverError <- err
	}()
	guestError = Establish(t.Context(), guestConnection, binding, credential)
	_ = guestConnection.Close()
	authorityError = <-serverError
	if !errors.Is(guestError, ErrDenied) || !errors.Is(authorityError, ErrDenied) {
		t.Fatalf("sequence-mismatch errors guest=%v server=%v", guestError, authorityError)
	}

	invalidAccepted := Authentication{
		Binding: binding, Sequence: 41, IssuedAt: now,
		ExpiresAt:      now.Add(guestenrollment.MaxGuestSessionCredentialLifetime),
		LocalExpiresAt: now.Add(guestenrollment.MaxGuestSessionCredentialLifetime + time.Hour),
	}
	gatewayConnection, guestConnection = net.Pipe()
	if _, err := NewGatewaySession(gatewayConnection, invalidAccepted); !errors.Is(err, ErrProtocol) {
		t.Fatalf("gateway accepted extended local trust: %v", err)
	}
	_ = gatewayConnection.Close()
	_ = guestConnection.Close()
	invalidAccepted = Authentication{
		Binding: binding, Sequence: 41, IssuedAt: now.Add(-4 * time.Minute),
		ExpiresAt: now.Add(time.Minute), LocalExpiresAt: now.Add(2 * time.Minute),
	}
	gatewayConnection, guestConnection = net.Pipe()
	if _, err := NewGatewaySession(gatewayConnection, invalidAccepted); !errors.Is(err, ErrProtocol) {
		t.Fatalf("gateway accepted trust beyond authoritative expiry: %v", err)
	}
	_ = gatewayConnection.Close()
	_ = guestConnection.Close()
	gatewayConnection, guestConnection = net.Pipe()
	if _, err := NewGuestForwarder(gatewayConnection, binding, now.Add(guestenrollment.MaxGuestSessionCredentialLifetime+time.Hour), "127.0.0.1:4090"); !errors.Is(err, ErrProtocol) {
		t.Fatalf("guest accepted extended local trust: %v", err)
	}
	_ = gatewayConnection.Close()
	_ = guestConnection.Close()
}

func TestWorkspaceHandshakeRejectsPipelinedYamuxBytes(t *testing.T) {
	binding := testBinding()
	credential := testCredential(t, 1)
	gatewayConnection, guestConnection := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer gatewayConnection.Close()
		_, err := Accept(t.Context(), gatewayConnection, testAuthenticator{credential: credential, binding: binding})
		done <- err
	}()
	hello, err := EncodeMessage(Message{
		ContractVersion: Version, Type: Hello, Binding: &binding,
		Audience: guestenrollment.NativeGuestControlAudience, Credential: credential,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guestConnection.Write(append(hello, 0)); err != nil {
		t.Fatal(err)
	}
	_ = guestConnection.Close()
	if err := <-done; !errors.Is(err, ErrProtocol) {
		t.Fatalf("pipelined handshake error=%v", err)
	}
}

func TestWorkspaceHandshakeComposesWithExplicitTLSBoundary(t *testing.T) {
	serverConfig, clientConfig := workspaceTLSConfigs(t)
	binding := testBinding()
	credential := testCredential(t, 7)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverResult := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer raw.Close()
		connection := tls.Server(raw, serverConfig.Clone())
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if err := connection.HandshakeContext(ctx); err != nil {
			serverResult <- err
			return
		}
		_, err = Accept(ctx, connection, testAuthenticator{credential: credential, binding: binding})
		serverResult <- err
	}()
	raw, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	connection := tls.Client(raw, clientConfig.Clone())
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := connection.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if version := connection.ConnectionState().Version; version < tls.VersionTLS12 {
		t.Fatalf("negotiated TLS version=%x", version)
	}
	if err := Establish(ctx, connection, binding, credential); err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	_ = listener.Close()
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*tls.Config)
	}{
		{name: "untrusted CA", mutate: func(config *tls.Config) { config.RootCAs = x509.NewCertPool() }},
		{name: "wrong server name", mutate: func(config *tls.Config) { config.ServerName = "attacker.invalid" }},
		{name: "TLS below 1.2", mutate: func(config *tls.Config) {
			config.MinVersion = tls.VersionTLS10
			config.MaxVersion = tls.VersionTLS11
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := clientConfig.Clone()
			test.mutate(invalid)
			clientErr, _ := workspaceTLSHandshake(t, serverConfig.Clone(), invalid)
			if clientErr == nil {
				t.Fatal("invalid TLS boundary was accepted")
			}
		})
	}
}

func workspaceTLSHandshake(t *testing.T, serverConfig *tls.Config, clientConfig *tls.Config) (error, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(time.Second))
		serverResult <- tls.Server(raw, serverConfig).Handshake()
	}()
	raw, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(time.Second))
	clientErr := tls.Client(raw, clientConfig).Handshake()
	return clientErr, <-serverResult
}

func workspaceTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "NVT workspace test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "workspace-gateway.test"},
		DNSNames: []string{"workspace-gateway.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCertificate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	serverConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{serverDER, caDER}, PrivateKey: serverKey,
		}},
	}
	clientConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "workspace-gateway.test",
	}
	return serverConfig, clientConfig
}

func testBinding() guestenrollment.Binding {
	return guestenrollment.Binding{
		AgentRunUID:        "11111111-1111-1111-1111-111111111111",
		ExecutionID:        "execution-workspace",
		DriverRegistration: "reference-driver",
		DesiredGeneration:  1,
		GuestInstanceID:    "guest-workspace-1",
	}
}

func testCredential(t *testing.T, sequence uint64) string {
	t.Helper()
	credential, err := guestenrollment.GenerateGuestSessionCredential(sequence)
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func testAcceptedAuthentication(binding guestenrollment.Binding, sequence uint64, expiresAt time.Time) Authentication {
	return Authentication{
		Binding: binding, Sequence: sequence, IssuedAt: time.Now(), ExpiresAt: expiresAt, LocalExpiresAt: expiresAt,
	}
}
