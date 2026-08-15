package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/localroutes"
)

type fixedRouteProvider struct{}

func (fixedRouteProvider) Routes(_ context.Context, run BackendRun) (BackendRoutes, error) {
	return BackendRoutes{
		Session:   localroutes.Endpoint{Host: run.Resolved.RunID + ".agent.localhost", Path: "/agents/" + run.Resolved.RunID + "/", UpstreamHost: "nvt-local-test-namespace", UpstreamPort: 4090},
		Exposures: []localroutes.Exposure{{Name: "app", Host: "app." + run.Resolved.RunID + ".agent.localhost", UpstreamHost: "nvt-local-test-namespace", UpstreamPort: 3000}},
	}, nil
}

func TestLocalRoutesAreDurableReadyAndDisappearOnlyAfterCleanup(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	store, path := openTestStore(t, clock, 4)
	run := createRun(t, store, "persistent-route", true)
	handler := newAuthorizedTestHandler(t, store, nil, fixedRouteProvider{}, nil)

	pending := serveRequest(t, handler, http.MethodGet, "/v1/routes/persistent-route", nil, "")
	if pending.Code != http.StatusOK || !containsAll(pending.Body.String(), `"ready":false`, `"path":"/agents/persistent-route/"`, `"host":"persistent-route.agent.localhost"`) {
		t.Fatalf("pending route = %d %s", pending.Code, pending.Body.String())
	}
	claimed := claimRun(t, store, run, "route-controller")
	preparing := transitionRun(t, store, claimed, "route-controller", StatePreparing)
	preparing = claimRun(t, store, preparing, "route-controller")
	_ = transitionRun(t, store, preparing, "route-controller", StateRunning)
	ready := serveRequest(t, handler, http.MethodGet, "/v1/routes/persistent-route", nil, "")
	if ready.Code != http.StatusOK || !containsAll(ready.Body.String(), `"ready":true`, `"state":"running"`, `"name":"app"`) {
		t.Fatalf("ready route = %d %s", ready.Code, ready.Body.String())
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenStore(context.Background(), path, StoreOptions{MaxActiveRuns: 4, MaxClaimLease: time.Minute, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	restartedHandler := newAuthorizedTestHandler(t, restarted, nil, fixedRouteProvider{}, nil)
	afterRestart := serveRequest(t, restartedHandler, http.MethodGet, "/v1/routes/persistent-route", nil, "")
	if afterRestart.Code != http.StatusOK || afterRestart.Body.String() != ready.Body.String() {
		t.Fatalf("route changed across restart: before=%s after=%s", ready.Body.String(), afterRestart.Body.String())
	}

	disposable := createRun(t, restarted, "disposable-route", false)
	disposable = claimRun(t, restarted, disposable, "route-controller")
	disposable = transitionRun(t, restarted, disposable, "route-controller", StatePreparing)
	disposable = claimRun(t, restarted, disposable, "route-controller")
	disposable = transitionRun(t, restarted, disposable, "route-controller", StateRunning)
	if _, _, err := restarted.Delete(context.Background(), disposable.RunID); err != nil {
		t.Fatal(err)
	}
	stopping := serveRequest(t, restartedHandler, http.MethodGet, "/v1/routes/disposable-route", nil, "")
	if stopping.Code != http.StatusOK || !containsAll(stopping.Body.String(), `"ready":false`, `"state":"stopping"`) {
		t.Fatalf("stopping route = %d %s", stopping.Code, stopping.Body.String())
	}
	current, _ := restarted.Get(context.Background(), disposable.RunID)
	cleanup := claimRun(t, restarted, current, "cleanup-controller")
	if _, err := restarted.UpdateStatus(context.Background(), StatusInput{RunID: cleanup.RunID, Owner: "cleanup-controller", ExpectedRevision: cleanup.Revision, State: cleanup.TerminalTarget, Reason: "cleanup-complete"}); !errors.Is(err, ErrGone) {
		t.Fatal(err)
	}
	missing := serveRequest(t, restartedHandler, http.MethodGet, "/v1/routes/disposable-route", nil, "")
	if missing.Code != http.StatusNotFound {
		t.Fatalf("terminal route remained = %d %s", missing.Code, missing.Body.String())
	}
	listed := serveRequest(t, restartedHandler, http.MethodGet, "/v1/routes?limit=8", nil, "")
	var result localroutes.List
	if listed.Code != http.StatusOK || json.Unmarshal(listed.Body.Bytes(), &result) != nil || len(result.Runs) != 1 || result.Runs[0].RunID != "persistent-route" {
		t.Fatalf("terminal route listed = %d %s", listed.Code, listed.Body.String())
	}
}

func TestLocalRoutePaginationSkipsTerminalRecordsBeforeActiveRuns(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	terminal := createRun(t, store, "aaa-terminal", true)
	terminal = claimRun(t, store, terminal, "route-controller")
	terminal = transitionRun(t, store, terminal, "route-controller", StatePreparing)
	terminal = claimRun(t, store, terminal, "route-controller")
	terminal = transitionRun(t, store, terminal, "route-controller", StateRunning)
	terminal = claimRun(t, store, terminal, "route-controller")
	stopping, err := store.UpdateStatus(context.Background(), StatusInput{
		RunID: terminal.RunID, Owner: "route-controller", ExpectedRevision: terminal.Revision,
		State: StateStopping, TerminalTarget: StateCompleted, Reason: "backend-completed",
	})
	if err != nil {
		t.Fatal(err)
	}
	stopping = claimRun(t, store, stopping, "route-controller")
	if _, err := store.UpdateStatus(context.Background(), StatusInput{
		RunID: stopping.RunID, Owner: "route-controller", ExpectedRevision: stopping.Revision,
		State: StateCompleted, Reason: "cleanup-complete",
	}); err != nil {
		t.Fatal(err)
	}
	_ = createRun(t, store, "zzz-active", true)

	handler := newAuthorizedTestHandler(t, store, nil, fixedRouteProvider{}, nil)
	listed := serveRequest(t, handler, http.MethodGet, "/v1/routes?limit=1", nil, "")
	var result localroutes.List
	if listed.Code != http.StatusOK || json.Unmarshal(listed.Body.Bytes(), &result) != nil || len(result.Runs) != 1 || result.Runs[0].RunID != "zzz-active" || result.NextAfter != "" {
		t.Fatalf("active pagination = %d %s", listed.Code, listed.Body.String())
	}
}

func containsAll(value string, needles ...string) bool {
	for _, needle := range needles {
		if !strings.Contains(value, needle) {
			return false
		}
	}
	return true
}
