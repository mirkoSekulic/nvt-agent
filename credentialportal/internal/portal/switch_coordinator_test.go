package portal

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestTemplateSwitchCoordinatorRetriesResponseLossAndAcceptsOnlyExactResult(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost ||
			request.URL.Path != "/v1/principal-accounts/authorize-template-switch" ||
			request.Header.Get("Content-Type") != jsonContentType {
			t.Errorf("unexpected coordinator request: %s %s", request.Method, request.URL.Path)
		}
		if calls.Add(1) == 1 {
			hijacker, ok := response.(http.Hijacker)
			if !ok {
				t.Fatal("fixture cannot reset connection")
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
		if _, err := response.Write([]byte(`{"authorized":true}`)); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	client, err := NewHTTPTemplateSwitchCoordinator(TemplateSwitchConfig{
		Enabled: true, CoordinatorURL: server.URL, RequestTimeoutSeconds: 2, MaxResponseBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Authorize(t.Context(), "opaque-request"); err != nil || calls.Load() != 2 {
		t.Fatalf("response-loss retry failed: calls=%d err=%v", calls.Load(), err)
	}
}

func TestTemplateSwitchCoordinatorFailsClosedForActiveMalformedAndOversizedResponses(t *testing.T) {
	for _, test := range []struct { //nolint:govet // Test-case field names favor readable literals.
		name   string
		status int
		body   string
		want   error
	}{
		{name: "active", status: 409, body: `{"authorized":false,"reason":"active-agentruns"}`, want: ErrTemplateSwitchDenied},
		{name: "wrong reason", status: 409, body: `{"authorized":false,"reason":"SECRET-NEEDLE"}`, want: ErrTemplateSwitchUnavailable},
		{name: "unknown field", status: 200, body: `{"authorized":true,"credential":"SECRET-NEEDLE"}`, want: ErrTemplateSwitchUnavailable},
		{name: "oversized", status: 200, body: `{"authorized":true,"padding":"` + strings.Repeat("x", 5000) + `"}`, want: ErrTemplateSwitchUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Content-Type", jsonContentType)
				response.WriteHeader(test.status)
				if _, err := response.Write([]byte(test.body)); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			client, err := NewHTTPTemplateSwitchCoordinator(TemplateSwitchConfig{
				Enabled: true, CoordinatorURL: server.URL, RequestTimeoutSeconds: 2, MaxResponseBytes: 4096,
			})
			if err != nil {
				t.Fatal(err)
			}
			authorizeErr := client.Authorize(t.Context(), "opaque")
			if !errors.Is(authorizeErr, test.want) || strings.Contains(authorizeErr.Error(), "SECRET") {
				t.Fatalf("coordinator did not fail closed: %v", authorizeErr)
			}
		})
	}
}
