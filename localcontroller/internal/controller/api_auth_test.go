package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	apiAdminToken = "api-admin-token-00000000000000000000000000000000"
	apiRouteToken = "api-route-token-00000000000000000000000000000000"
)

func TestAPIAudiencesAreLeastPrivilegeAndRejectBeforeStateCreation(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	scheduler := testScheduler(t, store, schedulingTestToken)
	authorization, err := LoadAPIAuthorization(writePrivateToken(t, "admin", apiAdminToken), writePrivateToken(t, "routes", apiRouteToken), scheduler)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewAuthorizedHTTPHandlerWithServices(store, nil, nil, fixedRouteProvider{}, scheduler, authorization)
	if err != nil {
		t.Fatal(err)
	}
	createBody := mustJSON(t, map[string]any{
		"api_version": APIVersion, "idempotency_key": "admin-create-idempotency",
		"resolved_run": jsonObject(t, testResolvedRun(t, "admin-created", false)),
	})
	for name, token := range map[string]string{"missing": "", "wrong": "wrong-token-00000000000000000000000000000000", "producer": schedulingTestToken, "routes": apiRouteToken} {
		t.Run("raw-create-"+name, func(t *testing.T) {
			response := authorizedRequest(t, handler, http.MethodPost, "/v1/runs", createBody, token)
			if response.Code != http.StatusUnauthorized || response.Body.String() != `{"error":{"reason":"not-authorized","message":"request denied"}}`+"\n" {
				t.Fatalf("denial = %d %s", response.Code, response.Body.String())
			}
		})
	}
	listed, err := store.List(context.Background(), 10, "")
	if err != nil || len(listed.Runs) != 0 {
		t.Fatalf("unauthorized request changed state: %#v %v", listed, err)
	}
	created := authorizedRequest(t, handler, http.MethodPost, "/v1/runs", createBody, apiAdminToken)
	if created.Code != http.StatusCreated {
		t.Fatalf("admin create = %d %s", created.Code, created.Body.String())
	}

	for _, path := range []string{
		"/v1/runs", "/v1/runs/admin-created", "/v1/runs/admin-created/cancel",
		"/v1/runs/admin-created/claim", "/v1/runs/admin-created/status",
	} {
		method := http.MethodGet
		if strings.HasSuffix(path, "/cancel") || strings.HasSuffix(path, "/claim") {
			method = http.MethodPost
		} else if strings.HasSuffix(path, "/status") {
			method = http.MethodPut
		}
		for _, token := range []string{schedulingTestToken, apiRouteToken} {
			if response := authorizedRequest(t, handler, method, path, nil, token); response.Code != http.StatusUnauthorized {
				t.Fatalf("cross-audience %s %s = %d %s", method, path, response.Code, response.Body.String())
			}
		}
	}
	if response := authorizedRequest(t, handler, http.MethodGet, "/v1/routes", nil, apiRouteToken); response.Code != http.StatusOK {
		t.Fatalf("route read = %d %s", response.Code, response.Body.String())
	}
	for _, token := range []string{apiAdminToken, schedulingTestToken, ""} {
		if response := authorizedRequest(t, handler, http.MethodGet, "/v1/routes", nil, token); response.Code != http.StatusUnauthorized {
			t.Fatalf("route cross-audience = %d %s", response.Code, response.Body.String())
		}
	}

	scheduleBody := testAdmissionBody(t, "https://identity.example.test", "subject-1", "development", "prompt")
	if response := authorizedRequest(t, handler, http.MethodPost, "/v1/schedules/github/admissions", scheduleBody, schedulingTestToken); response.Code != http.StatusCreated {
		t.Fatalf("producer schedule = %d %s", response.Code, response.Body.String())
	}
	for _, token := range []string{apiAdminToken, apiRouteToken, ""} {
		if response := authorizedRequest(t, handler, http.MethodPost, "/v1/schedules/github/admissions", scheduleBody, token); response.Code != http.StatusUnauthorized {
			t.Fatalf("schedule cross-audience = %d %s", response.Code, response.Body.String())
		}
	}
}

func TestAPIAuthorizationRejectsMissingRouteAndReusedAudienceTokens(t *testing.T) {
	store, _ := openTestStore(t, &fakeClock{value: time.Now().UTC()}, 4)
	scheduler := testScheduler(t, store, schedulingTestToken)
	admin := writePrivateToken(t, "admin", apiAdminToken)
	routes := writePrivateToken(t, "routes", apiRouteToken)
	if authorization, err := LoadAPIAuthorization(admin, routes, scheduler); err != nil || authorization == nil {
		t.Fatalf("valid authorization = %#v %v", authorization, err)
	}
	if _, err := LoadAPIAuthorization(admin, admin, scheduler); err == nil {
		t.Fatal("shared admin/route token accepted")
	}
	producer := writePrivateToken(t, "producer", schedulingTestToken)
	if _, err := LoadAPIAuthorization(producer, routes, scheduler); err == nil {
		t.Fatal("producer token accepted as admin token")
	}
	if _, err := LoadAPIAuthorization(admin, producer, scheduler); err == nil {
		t.Fatal("producer token accepted as route token")
	}
	if _, err := NewAuthorizedHTTPHandlerWithServices(store, nil, nil, fixedRouteProvider{}, scheduler, &APIAuthorization{}); err == nil {
		t.Fatal("route provider accepted without route credential")
	}
}

func writePrivateToken(t *testing.T, name, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func authorizedRequest(t *testing.T, handler http.Handler, method, path string, body []byte, token string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, "http://local-controller.test"+path, bytes.NewReader(body))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func jsonObject(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}
