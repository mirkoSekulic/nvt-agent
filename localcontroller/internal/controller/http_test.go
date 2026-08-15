package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHTTPRunLifecycleHealthAndGenericResponses(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	var logs bytes.Buffer
	handler := newAuthorizedTestHandler(t, store, log.New(&logs, "", 0), nil, nil)

	for _, path := range []string{"/healthz", "/readyz"} {
		response := serveRequest(t, handler, http.MethodGet, path, nil, "")
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s = %d %s", path, response.Code, response.Body.String())
		}
	}
	rawRun := testResolvedRun(t, "http-run", false)
	var runObject map[string]any
	if err := json.Unmarshal(rawRun, &runObject); err != nil {
		t.Fatal(err)
	}
	runObject["prompt"] = "HTTP-PROMPT-NEEDLE"
	createBody := mustJSON(t, map[string]any{
		"api_version": APIVersion, "idempotency_key": "HTTP-IDEMPOTENCY-NEEDLE", "resolved_run": runObject,
	})
	created := serveRequest(t, handler, http.MethodPost, "/v1/runs", createBody, "application/json")
	if created.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", created.Code, created.Body.String())
	}
	for _, forbidden := range []string{"HTTP-PROMPT-NEEDLE", "HTTP-IDEMPOTENCY-NEEDLE", "agent-cli", "agent_config"} {
		if strings.Contains(created.Body.String(), forbidden) || strings.Contains(logs.String(), forbidden) {
			t.Fatalf("response/log disclosed %q: response=%s logs=%s", forbidden, created.Body.String(), logs.String())
		}
	}
	var createResponse struct {
		Run Run `json:"run"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createResponse); err != nil {
		t.Fatal(err)
	}
	if createResponse.Run.RunID != "http-run" || createResponse.Run.State != StatePending {
		t.Fatalf("created run = %#v", createResponse.Run)
	}
	got := serveRequest(t, handler, http.MethodGet, "/v1/runs/http-run", nil, "")
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"snapshot_digest":"`) {
		t.Fatalf("get = %d %s", got.Code, got.Body.String())
	}
	replay := serveRequest(t, handler, http.MethodPost, "/v1/runs", createBody, "application/json")
	if replay.Code != http.StatusOK || !strings.Contains(replay.Body.String(), `"created":false`) {
		t.Fatalf("replay = %d %s", replay.Code, replay.Body.String())
	}

	claimBody := mustJSON(t, map[string]any{
		"api_version": APIVersion, "owner": "controller-a", "expected_revision": createResponse.Run.Revision, "lease_seconds": 30,
	})
	claimed := serveRequest(t, handler, http.MethodPost, "/v1/runs/http-run/claim", claimBody, "application/json")
	if claimed.Code != http.StatusOK {
		t.Fatalf("claim = %d %s", claimed.Code, claimed.Body.String())
	}
	var claimedRun Run
	if err := json.Unmarshal(claimed.Body.Bytes(), &claimedRun); err != nil {
		t.Fatal(err)
	}
	statusBody := mustJSON(t, map[string]any{
		"api_version": APIVersion, "owner": "controller-a", "expected_revision": claimedRun.Revision,
		"state": StatePreparing, "reason": "backend-started",
	})
	status := serveRequest(t, handler, http.MethodPut, "/v1/runs/http-run/status", statusBody, "application/json")
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"state":"preparing"`) {
		t.Fatalf("status = %d %s", status.Code, status.Body.String())
	}
	cancelled := serveRequest(t, handler, http.MethodPost, "/v1/runs/http-run/cancel", nil, "")
	if cancelled.Code != http.StatusOK || !strings.Contains(cancelled.Body.String(), `"state":"stopping"`) {
		t.Fatalf("cancel = %d %s", cancelled.Code, cancelled.Body.String())
	}
	listed := serveRequest(t, handler, http.MethodGet, "/v1/runs?limit=10", nil, "")
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"run_id":"http-run"`) {
		t.Fatalf("list = %d %s", listed.Code, listed.Body.String())
	}
}

func TestHTTPDeleteWaitsForTerminalCleanupAndIsIdempotent(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	handler := newAuthorizedTestHandler(t, store, nil, nil, nil)
	run := createRun(t, store, "http-delete", false)

	deleting := serveRequest(t, handler, http.MethodDelete, "/v1/runs/http-delete", nil, "")
	if deleting.Code != http.StatusAccepted || !strings.Contains(deleting.Body.String(), `"state":"stopping"`) {
		t.Fatalf("active delete = %d %s", deleting.Code, deleting.Body.String())
	}
	stopping, err := store.Get(context.Background(), run.RunID)
	if err != nil {
		t.Fatal(err)
	}
	claimed := claimRun(t, store, stopping, "cleanup-controller")
	statusBody := mustJSON(t, map[string]any{
		"api_version": APIVersion, "owner": "cleanup-controller", "expected_revision": claimed.Revision,
		"state": StateCompleted, "reason": "cleanup-complete",
	})
	terminal := serveRequest(t, handler, http.MethodPut, "/v1/runs/http-delete/status", statusBody, "application/json")
	if terminal.Code != http.StatusGone {
		t.Fatalf("terminal cleanup = %d %s", terminal.Code, terminal.Body.String())
	}
	if response := serveRequest(t, handler, http.MethodGet, "/v1/runs/http-delete", nil, ""); response.Code != http.StatusNotFound {
		t.Fatalf("deleted get = %d %s", response.Code, response.Body.String())
	}
	if response := serveRequest(t, handler, http.MethodDelete, "/v1/runs/http-delete", nil, ""); response.Code != http.StatusNoContent {
		t.Fatalf("repeated delete = %d %s", response.Code, response.Body.String())
	}
}

func TestHTTPFailsClosedAndNeverLogsRejectedBodies(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	store, path := openTestStore(t, clock, 4)
	var logs bytes.Buffer
	handler := newAuthorizedTestHandler(t, store, log.New(&logs, "", 0), nil, nil)

	valid := testResolvedRun(t, "invalid-run", false)
	var object map[string]any
	if err := json.Unmarshal(valid, &object); err != nil {
		t.Fatal(err)
	}
	object["access_token"] = "HTTP-REAL-SECRET-NEEDLE"
	rejected := serveRequest(t, handler, http.MethodPost, "/v1/runs", mustJSON(t, map[string]any{
		"api_version": APIVersion, "idempotency_key": "rejected-idempotency-key", "resolved_run": object,
	}), "application/json")
	if rejected.Code != http.StatusBadRequest || strings.Contains(rejected.Body.String(), "SECRET") || strings.Contains(logs.String(), "SECRET") {
		t.Fatalf("rejected secret request = %d response=%s logs=%s", rejected.Code, rejected.Body.String(), logs.String())
	}
	stateFiles, err := filepath.Glob(path + "*")
	if err != nil || len(stateFiles) == 0 {
		t.Fatalf("enumerate state files: %v", err)
	}
	for _, stateFile := range stateFiles {
		database, readErr := os.ReadFile(stateFile)
		if readErr != nil || bytes.Contains(database, []byte("HTTP-REAL-SECRET-NEEDLE")) {
			t.Fatalf("rejected secret reached %s: err=%v", filepath.Base(stateFile), readErr)
		}
	}

	for name, body := range map[string][]byte{
		"duplicate":     []byte(`{"api_version":"nvt.local-runs/v1","api_version":"nvt.local-runs/v1","idempotency_key":"duplicate-key-123","resolved_run":{}}`),
		"unknown":       []byte(`{"api_version":"nvt.local-runs/v1","idempotency_key":"unknown-field-key","resolved_run":{},"provider":"forbidden"}`),
		"trailing":      []byte(`{"api_version":"nvt.local-runs/v1","idempotency_key":"trailing-data-key","resolved_run":{}} {}`),
		"invalid UTF-8": append([]byte(`{"api_version":"`), 0xff, '}'),
	} {
		t.Run(name, func(t *testing.T) {
			response := serveRequest(t, handler, http.MethodPost, "/v1/runs", body, "application/json")
			if response.Code != http.StatusBadRequest || response.Body.String() != `{"error":{"reason":"invalid-request","message":"request denied"}}`+"\n" {
				t.Fatalf("response = %d %q", response.Code, response.Body.String())
			}
		})
	}
	badQueryRequest := httptest.NewRequest(http.MethodGet, "http://local-controller.test/v1/runs", nil)
	badQueryRequest.URL.RawQuery = "after=%zz"
	badQuery := httptest.NewRecorder()
	handler.ServeHTTP(badQuery, badQueryRequest)
	if badQuery.Code != http.StatusBadRequest {
		t.Fatalf("malformed query = %d", badQuery.Code)
	}
	wrongType := serveRequest(t, handler, http.MethodPost, "/v1/runs", []byte(`{}`), "text/plain")
	if wrongType.Code != http.StatusBadRequest {
		t.Fatalf("wrong content type = %d", wrongType.Code)
	}
	oversized := serveRequest(t, handler, http.MethodPost, "/v1/runs", bytes.Repeat([]byte{'x'}, MaxRequestBytes+1), "application/json")
	if oversized.Code != http.StatusBadRequest {
		t.Fatalf("oversized request = %d", oversized.Code)
	}
}

func TestReadinessFailsWhenStoreIsUnavailableButHealthRemainsLive(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	handler := newAuthorizedTestHandler(t, store, nil, nil, nil)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if response := serveRequest(t, handler, http.MethodGet, "/healthz", nil, ""); response.Code != http.StatusOK {
		t.Fatalf("health after store close = %d", response.Code)
	}
	if response := serveRequest(t, handler, http.MethodGet, "/readyz", nil, ""); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness after store close = %d", response.Code)
	}
}

func TestReadinessFailsClosedOnIncompatibleLiveSchema(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	handler := newAuthorizedTestHandler(t, store, nil, nil, nil)
	if _, err := store.db.Exec(`PRAGMA user_version=99`); err != nil {
		t.Fatal(err)
	}
	if response := serveRequest(t, handler, http.MethodGet, "/healthz", nil, ""); response.Code != http.StatusOK {
		t.Fatalf("health with incompatible live schema = %d", response.Code)
	}
	if response := serveRequest(t, handler, http.MethodGet, "/readyz", nil, ""); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness with incompatible live schema = %d", response.Code)
	}
}

func TestReadinessIncludesBackendDependencyWithoutChangingLiveness(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	handler := NewHTTPHandlerWithBackend(store, nil, func(context.Context) bool { return false })
	if response := serveRequest(t, handler, http.MethodGet, "/readyz", nil, ""); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("backend-unready readiness = %d %s", response.Code, response.Body.String())
	}
	if response := serveRequest(t, handler, http.MethodGet, "/healthz", nil, ""); response.Code != http.StatusOK {
		t.Fatalf("backend-unready liveness = %d %s", response.Code, response.Body.String())
	}
}

func TestRequestDuplicateScannerIsDepthBounded(t *testing.T) {
	deep := strings.Repeat("[", 68) + "null" + strings.Repeat("]", 68)
	if err := rejectDuplicateJSONKeys([]byte(deep)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("deep JSON error = %v", err)
	}
}

func serveRequest(t *testing.T, handler http.Handler, method, path string, body []byte, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, "http://local-controller.test"+path, bytes.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

const (
	testAdminBearer = "admin-bearer-00000000000000000000000000000000"
	testRouteBearer = "route-bearer-00000000000000000000000000000000"
)

func newAuthorizedTestHandler(t *testing.T, store *Store, logger *log.Logger, routeProvider RouteProvider, scheduler *Scheduler) http.Handler {
	t.Helper()
	adminDigest := sha256.Sum256([]byte(testAdminBearer))
	routeDigest := sha256.Sum256([]byte(testRouteBearer))
	handler, err := NewAuthorizedHTTPHandlerWithServices(store, logger, nil, routeProvider, scheduler, &APIAuthorization{admin: &adminDigest, routes: &routeDigest})
	if err != nil {
		t.Fatal(err)
	}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch apiAudienceForPath(request.URL.Path) {
		case apiAudienceAdmin:
			request.Header.Set("Authorization", "Bearer "+testAdminBearer)
		case apiAudienceRoutes:
			request.Header.Set("Authorization", "Bearer "+testRouteBearer)
		}
		handler.ServeHTTP(response, request)
	})
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
