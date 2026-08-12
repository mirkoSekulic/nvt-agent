package principalaccounts

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testAssertionKey = "0123456789abcdef0123456789abcdef"
const testCoordinationKey = "abcdef0123456789abcdef0123456789"
const readyResponse = `{"ok":true,"state":"ready","template":"work","generation":7}`

type brokerFixture struct { //nolint:govet // Test fixture fields follow request/response flow for readability.
	t              *testing.T
	server         *httptest.Server
	client         *Client
	principal      Principal
	mu             sync.Mutex
	requests       []string
	readinessCode  int
	readinessBody  string
	resolutionCode int
	resolutionBody string
}

func newBrokerFixture(t *testing.T) *brokerFixture {
	t.Helper()
	fixture := &brokerFixture{
		t: t,
		principal: Principal{
			Issuer: "https://issuer.example/tenant", Subject: "immutable-42",
		},
		readinessCode:  http.StatusOK,
		readinessBody:  readyResponse,
		resolutionCode: http.StatusOK,
		resolutionBody: `{"ok":true,"template":"work","provider_instance_id":"dpa_0123456789abcdef0123456789abcdef","generation":7}`,
	}
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(fixture.serveHTTP))
	t.Cleanup(fixture.server.Close)
	directory := t.TempDir()
	certificate, err := x509.ParseCertificate(fixture.server.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(directory, "ca.pem")
	keyPath := filepath.Join(directory, "key")
	if writeErr := os.WriteFile(caPath, pemCertificate(certificate.Raw), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	if writeErr := os.WriteFile(keyPath, []byte(testAssertionKey), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	fixture.client, err = New(Config{
		Version: 1, BaseURL: fixture.server.URL, CAFile: caPath, AssertionKeyFile: keyPath,
		AssertionTTLSeconds: 30, RequestTimeoutSeconds: 2, MaxResponseBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.client.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	t.Cleanup(fixture.client.Close)
	return fixture
}

func (f *brokerFixture) serveHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.Header.Get("Content-Type") != jsonContentType ||
		request.Header.Get("Accept") != jsonContentType {
		f.t.Errorf("unexpected request %s %s headers=%v", request.Method, request.URL.Path, request.Header)
	}
	f.verifyAssertion(request.Header.Get("Authorization"))
	f.mu.Lock()
	f.requests = append(f.requests, request.URL.Path)
	f.mu.Unlock()
	response.Header().Set("Content-Type", jsonContentType)
	switch request.URL.Path {
	case "/v1/principal-accounts/readiness":
		response.WriteHeader(f.readinessCode)
		if _, err := response.Write([]byte(f.readinessBody)); err != nil {
			f.t.Errorf("write readiness response: %v", err)
		}
	case "/v1/principal-accounts/resolve":
		response.WriteHeader(f.resolutionCode)
		if _, err := response.Write([]byte(f.resolutionBody)); err != nil {
			f.t.Errorf("write resolution response: %v", err)
		}
	default:
		http.NotFound(response, request)
	}
}

func (f *brokerFixture) verifyAssertion(header string) {
	prefix := assertionScheme + " "
	if !strings.HasPrefix(header, prefix) {
		f.t.Errorf("missing assertion scheme")
		return
	}
	parts := strings.Split(strings.TrimPrefix(header, prefix), ".")
	if len(parts) != 2 {
		f.t.Errorf("invalid assertion structure")
		return
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		f.t.Error(err)
		return
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		f.t.Error(err)
		return
	}
	mac := hmac.New(sha256.New, []byte(testAssertionKey))
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		f.t.Errorf("invalid assertion signature")
	}
	var claims struct {
		Issuer    string `json:"issuer"`
		Subject   string `json:"subject"`
		Audience  string `json:"audience"`
		ExpiresAt int64  `json:"expires_at"`
		Version   int    `json:"version"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		f.t.Error(err)
	}
	if claims.Audience != assertionAudience || claims.ExpiresAt != 1_700_000_030 || claims.Version != 1 ||
		claims.Issuer != f.principal.Issuer || claims.Subject != f.principal.Subject {
		f.t.Errorf("assertion is not exact-principal bounded: %#v", claims)
	}
}

func (f *brokerFixture) requestPaths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

func TestResolveExactReadyAccount(t *testing.T) {
	fixture := newBrokerFixture(t)
	resolution, err := fixture.client.Resolve(context.Background(), fixture.principal)
	if err != nil {
		t.Fatal(err)
	}
	if resolution != (Resolution{Template: "work", ProviderInstanceID: "dpa_0123456789abcdef0123456789abcdef", Generation: 7}) {
		t.Fatalf("unexpected resolution: %#v", resolution)
	}
	wantPaths := "/v1/principal-accounts/readiness,/v1/principal-accounts/resolve"
	if got := strings.Join(fixture.requestPaths(), ","); got != wantPaths {
		t.Fatalf("unexpected calls: %s", got)
	}
}

func TestResolveStableAccountStates(t *testing.T) {
	tests := []struct { //nolint:govet // Table fields follow the broker request sequence.
		name           string
		readinessCode  int
		readinessBody  string
		resolutionCode int
		resolutionBody string
		want           error
	}{
		{
			name: "missing", readinessCode: 404,
			readinessBody: `{"ok":false,"error":"account-not-found","message":"account-not-found"}`,
			want:          ErrNotEnrolled,
		},
		{
			name: "revoked", readinessCode: 200,
			readinessBody: `{"ok":true,"state":"revoked","template":"work","generation":7}`,
			want:          ErrNotEnrolled,
		},
		{
			name: "unready", readinessCode: 200,
			readinessBody: `{"ok":true,"state":"unready","template":"work","generation":7}`,
			want:          ErrNotReady,
		},
		{
			name: "eligibility-expired", readinessCode: 403,
			readinessBody: `{"ok":false,"error":"principal-not-eligible","message":"principal-not-eligible"}`,
			want:          ErrNotEligible,
		},
		{
			name: "eligibility-revoked-between-checks", readinessCode: 200, readinessBody: readyResponse,
			resolutionCode: 403,
			resolutionBody: `{"ok":false,"error":"principal-not-eligible","message":"principal-not-eligible"}`,
			want:           ErrNotEligible,
		},
		{
			name: "raced-unready", readinessCode: 200, readinessBody: readyResponse, resolutionCode: 503,
			resolutionBody: `{"ok":false,"error":"account-unready","message":"account-unready"}`,
			want:           ErrNotReady,
		},
		{
			name: "raced-missing", readinessCode: 200, readinessBody: readyResponse, resolutionCode: 404,
			resolutionBody: `{"ok":false,"error":"account-not-found","message":"account-not-found"}`,
			want:           ErrNotReady,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBrokerFixture(t)
			fixture.readinessCode, fixture.readinessBody = test.readinessCode, test.readinessBody
			if test.resolutionCode != 0 {
				fixture.resolutionCode, fixture.resolutionBody = test.resolutionCode, test.resolutionBody
			}
			_, err := fixture.client.Resolve(context.Background(), fixture.principal)
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestResolveFailsClosedForMalformedOrInconsistentBrokerResponses(t *testing.T) {
	tests := []struct {
		name      string
		readiness string
		resolved  string
	}{
		{
			name: "unknown-readiness-field",
			readiness: `{"ok":true,"state":"ready","template":"work","generation":7,` +
				`"credential":"SECRET-NEEDLE"}`,
		},
		{
			name:      "duplicate",
			readiness: `{"ok":true,"state":"ready","state":"unready","template":"work","generation":7}`,
		},
		{
			name:      "unknown-state",
			readiness: `{"ok":true,"state":"healthy","template":"work","generation":7}`,
		},
		{
			name: "generation-mismatch",
			resolved: `{"ok":true,"template":"work",` +
				`"provider_instance_id":"dpa_0123456789abcdef0123456789abcdef","generation":8}`,
		},
		{
			name: "template-mismatch",
			resolved: `{"ok":true,"template":"other",` +
				`"provider_instance_id":"dpa_0123456789abcdef0123456789abcdef","generation":7}`,
		},
		{
			name:     "invalid-provider",
			resolved: `{"ok":true,"template":"work","provider_instance_id":"shared-provider","generation":7}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBrokerFixture(t)
			if test.readiness != "" {
				fixture.readinessBody = test.readiness
			}
			if test.resolved != "" {
				fixture.resolutionBody = test.resolved
			}
			_, err := fixture.client.Resolve(context.Background(), fixture.principal)
			if !errors.Is(err, ErrUnavailable) || strings.Contains(fmt.Sprint(err), "SECRET-NEEDLE") {
				t.Fatalf("expected redacted unavailable error, got %v", err)
			}
		})
	}
}

func TestResolveRejectsOversizedResponseAndUnverifiedTLS(t *testing.T) {
	fixture := newBrokerFixture(t)
	fixture.readinessBody = `{"ok":true,"state":"ready","template":"` + strings.Repeat("x", 5000) + `","generation":7}`
	if _, err := fixture.client.Resolve(context.Background(), fixture.principal); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected oversized response rejection, got %v", err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", jsonContentType)
		if _, err := response.Write([]byte(`{"ok":true}`)); err != nil {
			t.Errorf("write TLS fixture response: %v", err)
		}
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	fixture.client.baseURL = parsed
	if _, err := fixture.client.Resolve(context.Background(), fixture.principal); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected TLS failure, got %v", err)
	}
}

func TestResolveRejectsInvalidPrincipalWithoutBrokerCall(t *testing.T) {
	fixture := newBrokerFixture(t)
	for _, principal := range []Principal{
		{}, {Issuer: "http://issuer.example", Subject: "subject"},
		{Issuer: fixture.principal.Issuer, Subject: " subject"},
		{Issuer: fixture.principal.Issuer, Subject: "subject\nother"},
	} {
		if _, err := fixture.client.Resolve(context.Background(), principal); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("expected invalid principal rejection for %#v: %v", principal, err)
		}
	}
	if len(fixture.requestPaths()) != 0 {
		t.Fatalf("invalid principals reached broker: %v", fixture.requestPaths())
	}
}

func TestCoordinationClientBindsBodyAndAcceptsOnlyExactStates(t *testing.T) {
	principal := Principal{Issuer: "https://issuer.example/tenant", Subject: "immutable-42"}
	expiresAt := int64(1_700_000_060)
	var paths []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}
		verifyCoordinationAssertion(t, request.Header.Get("Authorization"), request.URL.Path, body)
		paths = append(paths, request.URL.Path)
		response.Header().Set("Content-Type", jsonContentType)
		switch request.URL.Path {
		case "/v1/principal-account-coordination/begin-admission":
			_, _ = fmt.Fprintf(response, `{"ok":true,"state":"reserved","expires_at":%d}`, expiresAt)
		case "/v1/principal-account-coordination/end-admission":
			_, _ = response.Write([]byte(`{"ok":true,"state":"released"}`))
		case "/v1/principal-account-coordination/begin-template-switch":
			_, _ = fmt.Fprintf(
				response,
				`{"ok":true,"issuer":"https://issuer.example/tenant","subject":"immutable-42","expires_at":%d}`,
				expiresAt,
			)
		case "/v1/principal-account-coordination/commit-template-switch":
			_, _ = response.Write([]byte(`{"ok":true,"state":"authorized"}`))
		case "/v1/principal-account-coordination/abort-template-switch":
			_, _ = response.Write([]byte(`{"ok":true,"state":"released"}`))
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	client := newCoordinationTestClient(t, server)
	reservation, err := client.BeginAdmission(t.Context(), principal, "admission-op")
	if err != nil || reservation.ExpiresAt.Unix() != expiresAt {
		t.Fatal(err)
	}
	if err := client.EndAdmission(t.Context(), principal, "admission-op"); err != nil {
		t.Fatal(err)
	}
	resolved, switchReservation, err := client.BeginTemplateSwitch(t.Context(), "opaque-request", "switch-op")
	if err != nil || resolved != principal || switchReservation.ExpiresAt.Unix() != expiresAt {
		t.Fatalf("begin switch = %#v, %#v, %v", resolved, switchReservation, err)
	}
	if err := client.CommitTemplateSwitch(t.Context(), principal, "switch-op"); err != nil {
		t.Fatal(err)
	}
	if err := client.AbortTemplateSwitch(t.Context(), principal, "switch-op"); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 5 {
		t.Fatalf("coordination request count=%d paths=%v", len(paths), paths)
	}
}

func TestBeginAdmissionPreservesStablePrincipalFailures(t *testing.T) {
	principal := Principal{Issuer: "https://issuer.example/tenant", Subject: "immutable-42"}
	for _, test := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{name: "not-enrolled", status: http.StatusNotFound, body: `{"ok":false,"error":"account-not-found","message":"account-not-found"}`, want: ErrNotEnrolled},
		{name: "not-eligible", status: http.StatusForbidden, body: `{"ok":false,"error":"principal-not-eligible","message":"principal-not-eligible"}`, want: ErrNotEligible},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				body, err := io.ReadAll(request.Body)
				if err != nil {
					t.Fatal(err)
				}
				verifyCoordinationAssertion(t, request.Header.Get("Authorization"), request.URL.Path, body)
				response.Header().Set("Content-Type", jsonContentType)
				response.WriteHeader(test.status)
				_, _ = response.Write([]byte(test.body))
			}))
			defer server.Close()
			client := newCoordinationTestClient(t, server)
			defer client.Close()
			_, err := client.BeginAdmission(t.Context(), principal, "admission-op")
			if !errors.Is(err, test.want) {
				t.Fatalf("BeginAdmission error=%v want=%v", err, test.want)
			}
		})
	}
}

func newCoordinationTestClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	directory := t.TempDir()
	certificate, err := x509.ParseCertificate(server.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(directory, "ca.pem")
	keyPath := filepath.Join(directory, "key")
	coordinationPath := filepath.Join(directory, "coordination-key")
	for path, body := range map[string][]byte{
		caPath: pemCertificate(certificate.Raw), keyPath: []byte(testAssertionKey),
		coordinationPath: []byte(testCoordinationKey),
	} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	client, err := New(Config{
		Version: 1, BaseURL: server.URL, CAFile: caPath, AssertionKeyFile: keyPath,
		AssertionTTLSeconds: 30, RequestTimeoutSeconds: 2, MaxResponseBytes: 4096,
		Coordination: &CoordinationConfig{AssertionKeyFile: coordinationPath, AssertionTTLSeconds: 30},
	})
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	t.Cleanup(client.Close)
	return client
}

func verifyCoordinationAssertion(t *testing.T, header, path string, body []byte) {
	t.Helper()
	parts := strings.Split(strings.TrimPrefix(header, coordinationScheme+" "), ".")
	if len(parts) != 2 {
		t.Fatalf("invalid coordination assertion")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte(testCoordinationKey))
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		t.Fatal("invalid coordination signature")
	}
	var claims struct {
		Audience   string `json:"audience"`
		BodySHA256 string `json:"body_sha256"`
		ExpiresAt  int64  `json:"expires_at"`
		Operation  string `json:"operation"`
		Version    int    `json:"version"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	wantOperation := strings.TrimPrefix(path, "/v1/principal-account-coordination/")
	if claims.Audience != coordinationAudience || claims.Operation != wantOperation ||
		claims.BodySHA256 != fmt.Sprintf("%x", sha256.Sum256(body)) ||
		claims.ExpiresAt != 1_700_000_030 || claims.Version != 1 {
		t.Fatalf("coordination assertion is not body/action bounded: %#v", claims)
	}
}

func TestConfigRejectsInsecureOrUnboundedValues(t *testing.T) {
	base := Config{
		Version: 1, BaseURL: "https://broker.example", CAFile: "ca", AssertionKeyFile: "key",
		AssertionTTLSeconds: 30, RequestTimeoutSeconds: 5, MaxResponseBytes: 4096,
	}
	for _, mutate := range []func(*Config){
		func(config *Config) { config.BaseURL = "http://broker.example" },
		func(config *Config) { config.BaseURL = "https://broker.example/path" },
		func(config *Config) { config.AssertionTTLSeconds = 901 },
		func(config *Config) { config.RequestTimeoutSeconds = 0 },
		func(config *Config) { config.MaxResponseBytes = 65537 },
	} {
		config := base
		mutate(&config)
		if err := config.validate(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("expected invalid config rejection: %#v err=%v", config, err)
		}
	}
}

func TestLoadConfiguredPreservesAbsentCompatibilityAndRejectsMalformedConfig(t *testing.T) {
	t.Setenv(ConfigFileEnv, "")
	client, err := LoadConfigured()
	if err != nil || client != nil {
		t.Fatalf("absent optional configuration must return a nil client: client=%v err=%v", client, err)
	}

	path := filepath.Join(t.TempDir(), "config.json")
	if writeErr := os.WriteFile(path, []byte(`{"version":1,"unknown":"value"}`), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	t.Setenv(ConfigFileEnv, path)
	client, err = LoadConfigured()
	if client != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("malformed optional configuration must fail closed: client=%v err=%v", client, err)
	}
}

func pemCertificate(raw []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(raw)
	var builder strings.Builder
	builder.WriteString("-----BEGIN CERTIFICATE-----\n")
	for len(encoded) > 64 {
		builder.WriteString(encoded[:64] + "\n")
		encoded = encoded[64:]
	}
	builder.WriteString(encoded + "\n-----END CERTIFICATE-----\n")
	return []byte(builder.String())
}
