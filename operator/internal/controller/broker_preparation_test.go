package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBrokerPreparationRequestRetriesOnlyTransientUnauthorized(t *testing.T) {
	oldInterval := brokerPreparationRetryInterval
	brokerPreparationRetryInterval = time.Millisecond
	t.Cleanup(func() { brokerPreparationRetryInterval = oldInterval })
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 12 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"ok":false,"error":"unauthorized","message":"invalid broker bearer token"}`))
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	status, body, err := brokerPreparationRequest(context.Background(), server.Client(), server.URL, "token-canary", []byte(`{}`), 64<<10)
	if err != nil || status != http.StatusOK || string(body) != `{"ok":true}` || attempts != 12 {
		t.Fatalf("transient retry result status=%d attempts=%d body=%q err=%v", status, attempts, body, err)
	}
}

func TestBrokerPreparationRequestPermanentUnauthorizedAndCancellation(t *testing.T) {
	oldInterval := brokerPreparationRetryInterval
	brokerPreparationRetryInterval = 50 * time.Millisecond
	t.Cleanup(func() { brokerPreparationRetryInterval = oldInterval })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"ok":false,"error":"provider-not-granted","message":"denied"}`))
	}))
	defer server.Close()
	started := time.Now()
	status, _, err := brokerPreparationRequest(context.Background(), server.Client(), server.URL, "token-canary", []byte(`{}`), 64<<10)
	if err != nil || status != http.StatusUnauthorized || time.Since(started) > 200*time.Millisecond {
		t.Fatalf("permanent denial was retried: status=%d err=%v", status, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := brokerPreparationRequest(ctx, server.Client(), server.URL, "token-canary", []byte(`{}`), 64<<10); err == nil {
		t.Fatal("expected cancellation")
	}
	transient := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"ok":false,"error":"unauthorized","message":"invalid broker bearer token"}`))
	}))
	defer transient.Close()
	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer timeoutCancel()
	if _, _, err := brokerPreparationRequest(timeoutCtx, transient.Client(), transient.URL, "token-canary", []byte(`{}`), 64<<10); err == nil {
		t.Fatal("expected bounded timeout")
	}
}

func TestBrokerPreparationRequestHonorsEndpointBodyLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 128)))
	}))
	defer server.Close()
	_, body, err := brokerPreparationRequest(context.Background(), server.Client(), server.URL, "token-canary", []byte(`{}`), 64)
	if err != nil || len(body) != 65 {
		t.Fatalf("expected bounded body read, got len=%d err=%v", len(body), err)
	}
}
