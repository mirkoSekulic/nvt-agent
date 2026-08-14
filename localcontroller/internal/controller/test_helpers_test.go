package controller

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

type fakeClock struct{ value time.Time }

func (clock *fakeClock) Now() time.Time                 { return clock.value }
func (clock *fakeClock) Advance(duration time.Duration) { clock.value = clock.value.Add(duration) }

func testResolvedRun(t *testing.T, runID string, persistent bool) json.RawMessage {
	t.Helper()
	persistence := resolvedrun.Persistence{}
	retention := "disposable"
	if persistent {
		persistence = resolvedrun.Persistence{Workspace: true, RuntimeState: true}
		retention = "persistent"
	}
	run := resolvedrun.ResolvedAgentRun{
		ContractVersion: resolvedrun.ContractVersion,
		RunID:           runID,
		Principal:       resolvedrun.Principal{Issuer: "https://identity.example.test", Subject: "subject-1", DisplayName: "User"},
		Profile:         "engineering", Workflow: "development", Image: "registry.example/runtime:stable",
		Runtime:     resolvedrun.Runtime{Type: "generic-agent", Autonomy: "interactive", User: "root"},
		AgentConfig: json.RawMessage(`{"runtime":{"command":"agent-cli","args":[]},"plugins":[]}`),
		Broker:      resolvedrun.Broker{}, Egress: resolvedrun.Egress{Mode: "direct"},
		WorkspaceInstructions: resolvedrun.WorkspaceInstructions{Profile: "Trusted profile guidance.\n", Workflow: "Trusted workflow guidance.\n"},
		Persistence:           persistence, Retention: retention,
		TTL:       resolvedrun.TTL{ActiveSeconds: 10, CompletedSeconds: 5, FailedSeconds: 5, RunRetentionSeconds: 20},
		Lifecycle: resolvedrun.Lifecycle{CompleteOn: []string{"plugin.work.completed"}, FailOn: []string{"plugin.work.failed"}},
		Execution: resolvedrun.ExecutionBackend{Name: "container", Kind: "container"},
	}
	if err := resolvedrun.ValidateResolvedAgentRun(run); err != nil {
		t.Fatalf("test resolved run: %v", err)
	}
	encoded, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func openTestStore(t *testing.T, clock *fakeClock, maxActive int) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state", "local-controller.sqlite3")
	store, err := OpenStore(context.Background(), path, StoreOptions{
		MaxActiveRuns: maxActive, MaxClaimLease: time.Minute, Now: clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, path
}

func createRun(t *testing.T, store *Store, runID string, persistent bool) Run {
	t.Helper()
	result, err := store.Create(context.Background(), CreateInput{
		IdempotencyKey: "idempotency-key-" + runID,
		ResolvedRun:    testResolvedRun(t, runID, persistent),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Created {
		t.Fatal("new run was not created")
	}
	return result.Run
}

func claimRun(t *testing.T, store *Store, run Run, owner string) Run {
	t.Helper()
	claimed, err := store.Claim(context.Background(), ClaimInput{
		RunID: run.RunID, Owner: owner, ExpectedRevision: run.Revision, Lease: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return claimed
}

func transitionRun(t *testing.T, store *Store, run Run, owner string, state State) Run {
	t.Helper()
	updated, err := store.UpdateStatus(context.Background(), StatusInput{
		RunID: run.RunID, Owner: owner, ExpectedRevision: run.Revision, State: state, Reason: "backend-observed",
	})
	if err != nil {
		t.Fatal(err)
	}
	return updated
}
