package relay

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

type brokerFixture struct {
	config Configuration
	server *httptest.Server
	pki    testPKI
}

func newBrokerFixture(t *testing.T, handler http.Handler) brokerFixture {
	t.Helper()
	directory := t.TempDir()
	pki := newTestPKI(t, "localhost")
	server := httptest.NewUnstartedServer(handler)
	server.TLS = (tlsConfigForTest{certificate: pki.certificate}).config()
	server.StartTLS()
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	config := Configuration{
		Version: ConfigurationVersion, ListenAddress: "127.0.0.1:7445",
		TLSCertificateFile: writeTestFile(t, directory, "relay.crt", pki.certificatePEM, 0o644),
		TLSKeyFile:         writeTestFile(t, directory, "relay.key", pki.keyPEM, 0o600),
		BrokerURL:          "https://localhost:" + parsed.Port(), BrokerServerName: "localhost",
		BrokerCAFile:                 writeTestFile(t, directory, "broker-ca.crt", pki.caPEM, 0o644),
		AuthenticationTimeoutSeconds: 1, RevalidationIntervalSeconds: 30,
	}
	return brokerFixture{config: config, server: server, pki: pki}
}

// Keep crypto/tls construction out of fixture call sites so tests never
// accidentally inherit httptest's system-trust client.
type tlsConfigForTest struct{ certificate tls.Certificate }

func (value tlsConfigForTest) config() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{value.certificate}}
}

func TestBrokerAuthenticatorStrictSuccessExactBindingAndCredentialCustody(t *testing.T) {
	binding := testBinding("authority")
	credential := testCredential(t, 17)
	now := time.Now().UTC().Truncate(time.Second)
	var mu sync.Mutex
	requests := 0
	fixture := newBrokerFixture(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		if request.Method != http.MethodPost || request.URL.Path != guestenrollment.NativeEgressIdentityAuthenticatePath ||
			request.Header.Get("Authorization") != "Bearer "+credential || request.Header.Get("Content-Type") != "application/json" ||
			request.Header.Get("Accept") != "application/json" {
			t.Error("broker request transport contract mismatch")
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		var raw json.RawMessage
		if err := json.NewDecoder(request.Body).Decode(&raw); err != nil || strings.Contains(string(raw), credential) {
			t.Error("credential entered broker request body")
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		decoded, err := guestenrollment.DecodeNativeEgressAuthenticateRequest(raw)
		if err != nil || decoded.Binding != binding || decoded.Audience != guestenrollment.NativeEgressAudience {
			t.Error("broker request body did not repeat exact binding and purpose")
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(guestenrollment.NativeEgressStatus{
			ContractVersion: guestenrollment.NativeEgressIdentityVersion, CredentialType: guestenrollment.NativeEgressCredentialType,
			Binding: binding, Audience: guestenrollment.NativeEgressAudience, Sequence: 17,
			IssuedAt: guestenrollment.FormatTimestamp(now.Add(-time.Minute)), ExpiresAt: guestenrollment.FormatTimestamp(now.Add(4 * time.Minute)),
		})
	}))
	authenticator, err := NewBrokerAuthenticator(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	authenticator.now = func() time.Time { return now }
	authentication, err := authenticator.AuthenticateNativeEgress(context.Background(), credential, binding)
	if err != nil || authentication.Binding != binding || authentication.Sequence != 17 || authentication.LocalExpiresAt != (time.Time{}) {
		t.Fatalf("broker authentication failed: %#v %v", authentication, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 1 {
		t.Fatalf("broker requests=%d", requests)
	}
	for _, formatted := range []string{fmt.Sprint(authenticator), fmt.Sprintf("%#v", authenticator), fmt.Sprint(authentication)} {
		if strings.Contains(formatted, credential) || strings.Contains(formatted, binding.GuestInstanceID) {
			t.Fatalf("sensitive authentication formatting: %q", formatted)
		}
	}
}

func TestBrokerAuthenticatorFailureClassificationAndBounds(t *testing.T) {
	binding := testBinding("failures")
	credential := testCredential(t, 3)
	now := time.Now().UTC().Truncate(time.Second)
	tests := []struct {
		name       string
		handler    http.Handler
		binding    guestenrollment.Binding
		credential string
		wantDenied bool
		context    func() (context.Context, context.CancelFunc)
	}{
		{name: "definitive denial", handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }), binding: binding, credential: credential, wantDenied: true},
		{name: "definitive forbidden", handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }), binding: binding, credential: credential, wantDenied: true},
		{name: "server unavailable", handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }), binding: binding, credential: credential},
		{name: "rate limited", handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTooManyRequests) }), binding: binding, credential: credential},
		{name: "redirect", handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "https://elsewhere.invalid")
			w.WriteHeader(http.StatusFound)
		}), binding: binding, credential: credential},
		{name: "malformed success", handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"contract_version":`))
		}), binding: binding, credential: credential},
		{name: "oversized success", handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(make([]byte, guestenrollment.MaxNativeEgressIdentityResponseBytes+1))
		}), binding: binding, credential: credential},
		{name: "wrong content type", handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write([]byte(`{}`))
		}), binding: binding, credential: credential},
		{name: "timeout", handler: http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { time.Sleep(100 * time.Millisecond) }), binding: binding, credential: credential, context: func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 40*time.Millisecond)
		}},
		{name: "unknown credential", handler: http.NotFoundHandler(), binding: binding, credential: "nvt_eg1_invalid", wantDenied: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newBrokerFixture(t, testCase.handler)
			authenticator, err := NewBrokerAuthenticator(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			authenticator.now = func() time.Time { return now }
			ctx, cancel := context.WithCancel(context.Background())
			if testCase.context != nil {
				cancel()
				ctx, cancel = testCase.context()
			}
			defer cancel()
			_, err = authenticator.AuthenticateNativeEgress(ctx, testCase.credential, testCase.binding)
			if err == nil {
				t.Fatal("authority failure was accepted")
			}
			if testCase.wantDenied != errors.Is(err, nativeegress.ErrAuthenticationDenied) {
				t.Fatalf("denial classification=%v error=%v", testCase.wantDenied, err)
			}
			if !testCase.wantDenied && !errors.Is(err, nativeegress.ErrAuthenticationTemporary) {
				t.Fatalf("temporary authority failure classification: %v", err)
			}
			if strings.Contains(err.Error(), credential) || strings.Contains(err.Error(), binding.GuestInstanceID) || strings.Contains(err.Error(), fixture.config.BrokerURL) {
				t.Fatalf("authority error leaked internals: %q", err)
			}
		})
	}
}

func TestBrokerAuthenticatorTreatsContradictorySuccessAsTemporary(t *testing.T) {
	binding := testBinding("cross-record")
	credential := testCredential(t, 8)
	now := time.Now().UTC().Truncate(time.Second)
	for name, mutate := range map[string]func(*guestenrollment.NativeEgressStatus){
		"wrong binding": func(status *guestenrollment.NativeEgressStatus) { status.Binding.GuestInstanceID = "other-guest" },
		"wrong audience": func(status *guestenrollment.NativeEgressStatus) {
			status.Audience = guestenrollment.NativeGuestControlAudience
		},
		"wrong sequence": func(status *guestenrollment.NativeEgressStatus) { status.Sequence++ },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newBrokerFixture(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				status := guestenrollment.NativeEgressStatus{
					ContractVersion: guestenrollment.NativeEgressIdentityVersion, CredentialType: guestenrollment.NativeEgressCredentialType,
					Binding: binding, Audience: guestenrollment.NativeEgressAudience, Sequence: 8,
					IssuedAt: guestenrollment.FormatTimestamp(now.Add(-time.Minute)), ExpiresAt: guestenrollment.FormatTimestamp(now.Add(time.Minute)),
				}
				mutate(&status)
				response.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(response).Encode(status)
			}))
			authenticator, err := NewBrokerAuthenticator(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			authenticator.now = func() time.Time { return now }
			if _, err := authenticator.AuthenticateNativeEgress(context.Background(), credential, binding); !errors.Is(err, nativeegress.ErrAuthenticationTemporary) {
				t.Fatalf("contradictory success was not temporary: %v", err)
			}
		})
	}
}

func TestBrokerAuthenticatorDeniesExactExpiredStatus(t *testing.T) {
	binding := testBinding("expired")
	credential := testCredential(t, 8)
	now := time.Now().UTC().Truncate(time.Second)
	fixture := newBrokerFixture(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(guestenrollment.NativeEgressStatus{
			ContractVersion: guestenrollment.NativeEgressIdentityVersion, CredentialType: guestenrollment.NativeEgressCredentialType,
			Binding: binding, Audience: guestenrollment.NativeEgressAudience, Sequence: 8,
			IssuedAt: guestenrollment.FormatTimestamp(now.Add(-2 * time.Minute)), ExpiresAt: guestenrollment.FormatTimestamp(now),
		})
	}))
	authenticator, err := NewBrokerAuthenticator(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	authenticator.now = func() time.Time { return now }
	if _, err := authenticator.AuthenticateNativeEgress(context.Background(), credential, binding); !errors.Is(err, nativeegress.ErrAuthenticationDenied) {
		t.Fatalf("exact expired authority status was not denied: %v", err)
	}
}

func TestBrokerAuthenticatorUsesOnlyExplicitCAAndExactSNI(t *testing.T) {
	binding := testBinding("broker-tls")
	credential := testCredential(t, 1)
	handler := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		now := time.Now().UTC().Truncate(time.Second)
		_ = json.NewEncoder(response).Encode(guestenrollment.NativeEgressStatus{
			ContractVersion: guestenrollment.NativeEgressIdentityVersion, CredentialType: guestenrollment.NativeEgressCredentialType,
			Binding: binding, Audience: guestenrollment.NativeEgressAudience, Sequence: 1,
			IssuedAt: guestenrollment.FormatTimestamp(now.Add(-time.Minute)), ExpiresAt: guestenrollment.FormatTimestamp(now.Add(time.Minute)),
		})
	})
	fixture := newBrokerFixture(t, handler)
	untrusted := newTestPKI(t, "localhost")
	fixture.config.BrokerCAFile = writeTestFile(t, filepath.Dir(fixture.config.BrokerCAFile), "untrusted-ca.crt", untrusted.caPEM, 0o644)
	authenticator, err := NewBrokerAuthenticator(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticator.AuthenticateNativeEgress(context.Background(), credential, binding); !errors.Is(err, nativeegress.ErrAuthenticationTemporary) {
		t.Fatalf("untrusted broker CA did not fail closed: %v", err)
	}

	wrongNamePKI := newTestPKI(t, "wrong.example")
	server := httptest.NewUnstartedServer(handler)
	server.TLS = (&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{wrongNamePKI.certificate}})
	server.StartTLS()
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	fixture.config.BrokerURL = "https://localhost:" + parsed.Port()
	fixture.config.BrokerCAFile = writeTestFile(t, filepath.Dir(fixture.config.BrokerCAFile), "wrong-name-ca.crt", wrongNamePKI.caPEM, 0o644)
	authenticator, err = NewBrokerAuthenticator(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticator.AuthenticateNativeEgress(context.Background(), credential, binding); !errors.Is(err, nativeegress.ErrAuthenticationTemporary) {
		t.Fatalf("wrong broker certificate name did not fail closed: %v", err)
	}
}
