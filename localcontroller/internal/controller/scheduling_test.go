package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

const schedulingTestToken = "LOCAL-SCHEDULING-TOKEN-0123456789abcdef"

func TestLocalSchedulingIsOptionalAndRejectsNonPrivateToken(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	disabled, err := LoadScheduler("", store)
	if err != nil || disabled != nil {
		t.Fatalf("omitted scheduler = %#v err=%v", disabled, err)
	}
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "token")
	if err := os.WriteFile(tokenPath, []byte(schedulingTestToken), 0o644); err != nil {
		t.Fatal(err)
	}
	document := schedulingDocument{
		APIVersion:        SchedulingAPIVersion,
		ResolvedRunConfig: mustJSON(t, testSchedulingTrustedConfiguration()),
		Schedules: []scheduleConfig{{Name: "github", Producers: []scheduleProducerConfig{{
			Identity: "producer", TokenFile: tokenPath, AllowedPrincipalIssuers: []string{"https://identity.example.test"},
			Selections: []scheduleSelection{{Profile: "engineering", Workflow: "development"}}, DefaultWorkflow: "development", Retention: "disposable",
		}}}},
	}
	path := filepath.Join(directory, "scheduling.json")
	if err := os.WriteFile(path, mustJSON(t, document), 0o600); err != nil {
		t.Fatal(err)
	}
	if scheduler, err := LoadScheduler(path, store); err == nil || scheduler != nil {
		t.Fatal("non-private scheduling bearer was accepted")
	}
}

func TestLocalSchedulingAuthorizesSelectionIsIdempotentAndSupportsStatusCancel(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	var logs bytes.Buffer
	scheduler := testScheduler(t, store, schedulingTestToken)
	handler := NewHTTPHandlerWithServices(store, log.New(&logs, "", 0), nil, nil, scheduler)
	body := testAdmissionBody(t, "https://identity.example.test", "subject-1", "development", "Implement the bounded change")

	created := scheduleRequest(t, handler, http.MethodPost, "/v1/schedules/github/admissions", body, schedulingTestToken)
	if created.Code != http.StatusCreated || !containsAll(created.Body.String(), `"scheduled":true`, `"namespace":"local"`, `"state":"pending"`) {
		t.Fatalf("created = %d %s", created.Code, created.Body.String())
	}
	restartedScheduler := testScheduler(t, store, schedulingTestToken)
	restartedHandler := NewHTTPHandlerWithServices(store, log.New(&logs, "", 0), nil, nil, restartedScheduler)
	replayed := scheduleRequest(t, restartedHandler, http.MethodPost, "/v1/schedules/github/admissions", body, schedulingTestToken)
	if replayed.Code != http.StatusAccepted || replayed.Body.String() != `{"scheduled":false,"reason":"duplicate-work"}`+"\n" {
		t.Fatalf("replay = %d %s", replayed.Code, replayed.Body.String())
	}
	runs, err := store.List(context.Background(), 10, "")
	if err != nil || len(runs.Runs) != 1 {
		t.Fatalf("durable runs = %#v err=%v", runs, err)
	}
	snapshot, _, err := store.ResolvedSnapshot(context.Background(), runs.Runs[0].RunID)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolvedrun.DecodeResolvedAgentRun(snapshot)
	clear(snapshot)
	if err != nil || resolved.Principal.Issuer != "https://identity.example.test" || resolved.Principal.Subject != "subject-1" ||
		resolved.Profile != "engineering" || resolved.Workflow != "development" || resolved.Prompt != "Implement the bounded change" ||
		resolved.Execution.Name != "container" || resolved.Retention != "disposable" {
		t.Fatalf("resolved trusted selection = %#v err=%v", resolved, err)
	}
	status := scheduleRequest(t, restartedHandler, http.MethodGet, "/v1/schedules/github/work?work_id=acme/widget/issues/7", nil, schedulingTestToken)
	if status.Code != http.StatusOK || !containsAll(status.Body.String(), `"scheduled":true`, `"state":"pending"`) {
		t.Fatalf("status = %d %s", status.Code, status.Body.String())
	}
	cancelled := scheduleRequest(t, restartedHandler, http.MethodPost, "/v1/schedules/github/work/cancel?work_id=acme/widget/issues/7", nil, schedulingTestToken)
	if cancelled.Code != http.StatusAccepted || !strings.Contains(cancelled.Body.String(), `"state":"stopping"`) {
		t.Fatalf("cancel = %d %s", cancelled.Code, cancelled.Body.String())
	}
	if strings.Contains(logs.String(), schedulingTestToken) || strings.Contains(created.Body.String()+replayed.Body.String(), schedulingTestToken) {
		t.Fatalf("scheduling token disclosed: logs=%s", logs.String())
	}
}

func TestLocalSchedulingDeniesUntrustedSelectionBeforeBackendAndBoundsCapacity(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 1)
	scheduler := testScheduler(t, store, schedulingTestToken)
	handler := NewHTTPHandlerWithServices(store, nil, nil, nil, scheduler)
	backend := newFakeBackend()
	reconciler, err := NewReconciler(store, backend, "scheduler-controller", 30*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}

	for name, body := range map[string][]byte{
		"issuer":   testAdmissionBody(t, "https://other.example.test", "subject-1", "development", "prompt"),
		"workflow": testAdmissionBody(t, "https://identity.example.test", "subject-1", "administrator", "prompt"),
		"override": append(testAdmissionBody(t, "https://identity.example.test", "subject-1", "development", "prompt")[:len(testAdmissionBody(t, "https://identity.example.test", "subject-1", "development", "prompt"))-1], []byte(`,"profile":"forbidden"}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			response := scheduleRequest(t, handler, http.MethodPost, "/v1/schedules/github/admissions", body, schedulingTestToken)
			if response.Code != http.StatusForbidden && response.Code != http.StatusBadRequest {
				t.Fatalf("denial = %d %s", response.Code, response.Body.String())
			}
		})
	}
	if err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	ensureCalls := backend.ensureCalls
	backend.mu.Unlock()
	if ensureCalls != 0 {
		t.Fatalf("unauthorized selection reached backend %d times", ensureCalls)
	}
	listed, err := store.List(context.Background(), 10, "")
	if err != nil || len(listed.Runs) != 0 {
		t.Fatalf("unauthorized selection created state: %#v %v", listed, err)
	}

	first := scheduleRequest(t, handler, http.MethodPost, "/v1/schedules/github/admissions", testAdmissionBody(t, "https://identity.example.test", "subject-1", "development", "first"), schedulingTestToken)
	if first.Code != http.StatusCreated {
		t.Fatalf("first = %d %s", first.Code, first.Body.String())
	}
	secondBody := testAdmissionBody(t, "https://identity.example.test", "subject-1", "development", "second")
	var second map[string]any
	if err := json.Unmarshal(secondBody, &second); err != nil {
		t.Fatal(err)
	}
	second["work"].(map[string]any)["id"] = "acme/widget/issues/8"
	secondResponse := scheduleRequest(t, handler, http.MethodPost, "/v1/schedules/github/admissions", mustJSON(t, second), schedulingTestToken)
	if secondResponse.Code != http.StatusTooManyRequests || secondResponse.Body.String() != `{"scheduled":false,"reason":"max-parallelism-reached"}`+"\n" {
		t.Fatalf("capacity = %d %s", secondResponse.Code, secondResponse.Body.String())
	}
}

func testScheduler(t *testing.T, store *Store, token string) *Scheduler {
	t.Helper()
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "producer-token")
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configuration := testSchedulingTrustedConfiguration()
	document := schedulingDocument{
		APIVersion: SchedulingAPIVersion, ResolvedRunConfig: mustJSON(t, configuration),
		Schedules: []scheduleConfig{{Name: "github", Producers: []scheduleProducerConfig{{
			Identity: "github-comments", TokenFile: tokenPath, AllowedPrincipalIssuers: []string{"https://identity.example.test"},
			Selections: []scheduleSelection{{Profile: "engineering", Workflow: "development"}}, DefaultWorkflow: "development", Retention: "disposable", Backend: "container",
		}}}},
	}
	configPath := filepath.Join(directory, "scheduling.json")
	if err := os.WriteFile(configPath, mustJSON(t, document), 0o600); err != nil {
		t.Fatal(err)
	}
	scheduler, err := LoadScheduler(configPath, store)
	if err != nil {
		t.Fatal(err)
	}
	return scheduler
}

func testSchedulingTrustedConfiguration() resolvedrun.TrustedConfiguration {
	return resolvedrun.TrustedConfiguration{
		Defaults: resolvedrun.PlatformDefaults{
			Image: "registry.example/runtime:stable", Runtime: resolvedrun.Runtime{Type: "generic-agent", Autonomy: "interactive", User: "root"},
			AgentConfig: json.RawMessage(`{"runtime":{"command":"agent-cli","args":[]},"plugins":[]}`),
		},
		Profiles: []resolvedrun.Profile{{
			Name: "engineering", Broker: resolvedrun.Broker{}, Egress: resolvedrun.Egress{Mode: "direct"},
			AllowedBackends: []string{"container"}, DefaultBackend: "container", AllowedRetentions: []string{"disposable"},
		}},
		Workflows:         []resolvedrun.Workflow{{Name: "development"}},
		ExecutionBackends: []resolvedrun.ExecutionBackend{{Name: "container", Kind: "container"}},
		RetentionPolicies: []resolvedrun.RetentionPolicy{{Name: "disposable", TTL: resolvedrun.TTL{ActiveSeconds: 3600, CompletedSeconds: 60, FailedSeconds: 60}}},
	}
}

func testAdmissionBody(t *testing.T, issuer, subject, workflow, prompt string) []byte {
	t.Helper()
	return mustJSON(t, map[string]any{
		"workflow": workflow,
		"work": map[string]any{
			"id": "acme/widget/issues/7", "title": "Issue 7", "url": "https://github.example/acme/widget/issues/7", "repository": "acme/widget",
			"principal": map[string]any{"issuer": issuer, "subject": subject, "displayName": "Alice"},
		},
		"input": map[string]any{"prompt": prompt},
	})
}

func scheduleRequest(t *testing.T, handler http.Handler, method, path string, body []byte, token string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, "http://local-controller.test"+path, bytes.NewReader(body))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
