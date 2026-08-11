package portal

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	brokerClientSecretNeedle = "BROKER-CLIENT-CREDENTIAL-NEEDLE"
	testBrokerTemplate       = "approved"
	testBrokerIssuer         = "https://issuer.example"
)

func writeBrokerTestResponse(t *testing.T, response io.Writer, value string) {
	t.Helper()
	if _, err := io.WriteString(response, value); err != nil {
		t.Error(err)
	}
}

func newTestPrincipalAccountBroker(
	t *testing.T,
	handler http.Handler,
) (*HTTPPrincipalAccountBroker, []byte) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = false
	server.StartTLS()
	t.Cleanup(server.Close)
	root := t.TempDir()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	caPath := filepath.Join(root, "ca.crt")
	if err := os.WriteFile(caPath, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	keyPath := filepath.Join(root, "assertion-key")
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewHTTPPrincipalAccountBroker(DynamicBrokerConfig{
		URL: server.URL, CAFile: caPath, AssertionKeyFile: keyPath,
		AssertionTTLSeconds: 60, RequestTimeoutSeconds: 2, MaxResponseBytes: 64 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client, key
}

func verifyTestPrincipalAssertion(
	t *testing.T,
	header string,
	key []byte,
) Principal {
	t.Helper()
	encoded, found := strings.CutPrefix(header, principalAssertionScheme+" ")
	if !found {
		t.Fatal("broker request omitted the principal assertion scheme")
	}
	payloadText, signatureText, found := strings.Cut(encoded, ".")
	if !found || strings.Contains(signatureText, ".") {
		t.Fatal("broker request carried a malformed principal assertion")
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadText)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(signatureText)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		t.Fatal("broker principal assertion signature did not verify")
	}
	var assertion struct { //nolint:govet // Signed field order mirrors the production assertion.
		Audience  string `json:"audience"`
		ExpiresAt int64  `json:"expires_at"`
		Issuer    string `json:"issuer"`
		Subject   string `json:"subject"`
		Version   int    `json:"version"`
	}
	if !strictBrokerJSON(payload, &assertion) || assertion.Version != 1 ||
		assertion.Audience != principalAssertionAudience || assertion.ExpiresAt <= time.Now().Unix() ||
		assertion.ExpiresAt > time.Now().Add(61*time.Second).Unix() {
		t.Fatal("broker principal assertion payload was invalid or unbounded")
	}
	return Principal{Issuer: assertion.Issuer, Subject: assertion.Subject}
}

func TestPrincipalAccountBrokerUsesVerifiedTLSExactPrincipalAndBoundedStates(t *testing.T) {
	var key []byte
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", jsonContentType)
		if request.URL.Path == "/ready" {
			writeBrokerTestResponse(t, response, `{"ok":true,"status":"ready"}`)
			return
		}
		if request.URL.Path != "/v1/principal-accounts/readiness" {
			t.Errorf("portal used unexpected dynamic account endpoint %q", request.URL.Path)
			response.WriteHeader(http.StatusNotFound)
			return
		}
		principal := verifyTestPrincipalAssertion(t, request.Header.Get("Authorization"), key)
		switch principal.Subject {
		case "new-principal":
			response.WriteHeader(http.StatusNotFound)
			writeBrokerTestResponse(
				t, response, `{"ok":false,"error":"account-not-found","message":"account-not-found"}`,
			)
		case "degraded-principal":
			writeBrokerTestResponse(
				t, response, `{"ok":true,"state":"unready","template":"approved","generation":3}`,
			)
		case "revoked-principal":
			writeBrokerTestResponse(
				t, response, `{"ok":true,"state":"revoked","template":"approved","generation":4}`,
			)
		default:
			writeBrokerTestResponse(
				t, response, `{"ok":true,"state":"ready","template":"approved","generation":2}`,
			)
		}
	})
	client, assertionKey := newTestPrincipalAccountBroker(t, handler)
	key = assertionKey
	if err := client.Ready(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		subject, state, template string
		generation               int
	}{
		{"new-principal", accountStateNotEnrolled, "", 0},
		{"degraded-principal", accountStateUnready, testBrokerTemplate, 3},
		{"revoked-principal", accountStateRevoked, testBrokerTemplate, 4},
		{"ready-principal", accountStateReady, testBrokerTemplate, 2},
	} {
		state, err := client.Account(
			t.Context(), Principal{Issuer: testBrokerIssuer, Subject: test.subject},
		)
		if err != nil || state.State != test.state || state.Template != test.template ||
			state.Generation != test.generation {
			t.Fatalf("unexpected account state for %s: %#v err=%v", test.subject, state, err)
		}
	}
}

func TestPrincipalAccountBrokerRejectsMutationResponseStateConfusion(t *testing.T) {
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", jsonContentType)
		switch request.URL.Path {
		case "/v1/principal-accounts/complete-enrollment", "/v1/principal-accounts/reconnect":
			writeBrokerTestResponse(t, response, `{"ok":true,"state":"revoked"}`)
		case "/v1/principal-accounts/revoke":
			writeBrokerTestResponse(
				t, response, `{"ok":true,"state":"ready","template":"approved","generation":2}`,
			)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	})
	client, _ := newTestPrincipalAccountBroker(t, handler)
	principal := Principal{Issuer: testBrokerIssuer, Subject: "state-confusion"}
	credential := []byte("credential")
	for operation, err := range map[string]error{
		"enroll": client.CompleteEnrollment(
			t.Context(), principal, testBrokerTemplate, "wrong-enroll-state", credential,
		),
		"reconnect":  client.Reconnect(t.Context(), principal, "wrong-reconnect-state", credential),
		"revocation": client.Revoke(t.Context(), principal, "wrong-revoke-state"),
	} {
		if !errors.Is(err, ErrBrokerUnavailable) {
			t.Fatalf("%s accepted the wrong broker response state: %v", operation, err)
		}
	}
}

func TestPrincipalAccountBrokerRetriesResponseLossWithSameOperationAndNoDisclosure(t *testing.T) {
	var key []byte
	var mu sync.Mutex
	requests := [][]byte{}
	principals := []Principal{}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		principal := verifyTestPrincipalAssertion(t, request.Header.Get("Authorization"), key)
		mu.Lock()
		requests = append(requests, bytes.Clone(body))
		principals = append(principals, principal)
		attempt := len(requests)
		mu.Unlock()
		if attempt == 1 {
			hijacker, ok := response.(http.Hijacker)
			if !ok {
				t.Error("test server response does not support connection hijacking")
				return
			}
			connection, _, err := hijacker.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			if err := connection.Close(); err != nil {
				t.Error(err)
			}
			return
		}
		response.Header().Set("Content-Type", jsonContentType)
		writeBrokerTestResponse(t, response, `{"ok":true,"state":"ready","template":"approved","generation":1}`)
	})
	client, assertionKey := newTestPrincipalAccountBroker(t, handler)
	key = assertionKey
	credential := []byte(`{"tokens":{"access_token":"` + brokerClientSecretNeedle + `","refresh_token":"refresh"}}`)
	err := client.CompleteEnrollment(
		t.Context(),
		Principal{Issuer: testBrokerIssuer, Subject: "immutable-subject"},
		testBrokerTemplate,
		"same-operation-after-response-loss",
		credential,
	)
	if err != nil {
		t.Fatalf("response-loss recovery failed: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 2 || !bytes.Equal(requests[0], requests[1]) || principals[0] != principals[1] ||
		principals[0].Subject != "immutable-subject" {
		t.Fatal("broker retry changed its operation, credential body, or exact principal")
	}
	var requestBody struct {
		Template         string `json:"template"`
		OperationID      string `json:"operation_id"`
		CredentialBase64 string `json:"credential_base64"`
	}
	if !strictBrokerJSON(requests[0], &requestBody) || requestBody.Template != testBrokerTemplate ||
		requestBody.OperationID != "same-operation-after-response-loss" {
		t.Fatal("broker completion request shape changed")
	}
	decoded, err := base64.StdEncoding.DecodeString(requestBody.CredentialBase64)
	if err != nil || !bytes.Equal(decoded, credential) {
		t.Fatal("broker completion credential was not preserved across retry")
	}
	clearBytes(decoded)
}

func TestPrincipalAccountBrokerFailsClosedOnMalformedUnavailableAndAssertionRejection(t *testing.T) {
	var key []byte
	mode := "malformed"
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_ = verifyTestPrincipalAssertion(t, request.Header.Get("Authorization"), key)
		response.Header().Set("Content-Type", jsonContentType)
		switch mode {
		case "malformed":
			writeBrokerTestResponse(t, response, `{"ok":true,"state":"ready","template":"approved"}`)
		case "rejected":
			response.WriteHeader(http.StatusUnauthorized)
			writeBrokerTestResponse(t, response, `{"ok":false,"error":"unauthorized","message":"unauthorized"}`)
		case "secret-error":
			response.WriteHeader(http.StatusServiceUnavailable)
			writeBrokerTestResponse(
				t,
				response,
				`{"ok":false,"error":"provider-`+brokerClientSecretNeedle+
					`","message":"provider-`+brokerClientSecretNeedle+`"}`,
			)
		default:
			response.WriteHeader(http.StatusBadGateway)
			writeBrokerTestResponse(t, response, `not-json`)
		}
	})
	client, assertionKey := newTestPrincipalAccountBroker(t, handler)
	key = assertionKey
	principal := Principal{Issuer: testBrokerIssuer, Subject: "subject"}
	if _, err := client.Account(t.Context(), principal); !errors.Is(err, ErrBrokerUnavailable) {
		t.Fatal("malformed broker response did not fail closed")
	}
	if err := client.Reconnect(
		t.Context(), principal, "malformed-completion", []byte("credential"),
	); !errors.Is(err, ErrBrokerUnavailable) {
		t.Fatal("malformed broker completion did not fail closed")
	}
	mode = "rejected"
	err := client.Reconnect(t.Context(), principal, "operation", []byte("credential"))
	if !errors.Is(err, ErrBrokerRejected) || brokerCompletionReason(err) != "broker-authorization-failed" ||
		strings.Contains(err.Error(), brokerClientSecretNeedle) {
		t.Fatal("broker assertion rejection was not sanitized")
	}
	mode = "secret-error"
	err = client.Reconnect(t.Context(), principal, "secret-error", []byte("credential"))
	if !errors.Is(err, ErrBrokerRejected) || brokerCompletionReason(err) != "broker-update-failed" ||
		strings.Contains(err.Error()+brokerCompletionReason(err), brokerClientSecretNeedle) {
		t.Fatal("broker diagnostic was not normalized before portal output")
	}
	mode = "unavailable"
	if _, err := client.Account(t.Context(), principal); !errors.Is(err, ErrBrokerUnavailable) {
		t.Fatal("unavailable broker response did not fail closed")
	}
}
