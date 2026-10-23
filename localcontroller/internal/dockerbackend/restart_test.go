package dockerbackend

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/controller"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

func TestRestartQuiescePreservesExactVolumesIdentityAndTrust(t *testing.T) {
	for _, cleaned := range []bool{false, true} {
		t.Run(map[bool]string{false: "running", true: "cleaned"}[cleaned], func(t *testing.T) {
			ctx := context.Background()
			backend, docker, run, _ := testBackend(t)
			run.Persistence = resolvedrun.Persistence{Workspace: true, RuntimeState: true, DockerData: true}
			desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("a", 64)}
			if _, err := backend.Ensure(ctx, desired); err != nil {
				t.Fatal(err)
			}
			if cleaned {
				if err := backend.Delete(ctx, desired); err != nil {
					t.Fatal(err)
				}
			}
			objects := map[string]map[string]string{}
			for name, labels := range docker.objects {
				objects[name] = cloneLabels(labels)
			}
			registryBefore, err := os.ReadFile(backend.config.BrokerAgentsPath)
			if err != nil {
				t.Fatal(err)
			}
			caDigest, rotations := docker.caNameSetDigest, docker.caRotations
			docker.containers["unrelated-runtime"] = map[string]string{ownerLabel: backend.config.Owner, runLabel: "other", digestLabel: strings.Repeat("b", 64)}
			other := cloneLabels(docker.containers["unrelated-runtime"])
			docker.lifecycleEvents = []string{"plugin.work.failed"}
			docker.lifecycleCursor = "v1:1:2:400"
			start := len(docker.commands)
			for i := 0; i < 2; i++ {
				observation, err := backend.QuiesceForRestart(ctx, desired)
				if err != nil || observation.TerminalTarget != "" || observation.LifecycleCursor != docker.lifecycleCursor {
					t.Fatalf("quiesce=%+v %v", observation, err)
				}
				desired.LifecycleCursor = observation.LifecycleCursor
			}
			if !reflect.DeepEqual(objects, docker.objects) || !reflect.DeepEqual(other, docker.containers["unrelated-runtime"]) {
				t.Fatal("quiesce mutated storage/network/unrelated runtime")
			}
			registryAfter, _ := os.ReadFile(backend.config.BrokerAgentsPath)
			if !bytes.Equal(registryBefore, registryAfter) {
				t.Fatal("quiesce changed broker identity")
			}
			for _, cmd := range docker.commands[start:] {
				if contains(cmd, "unrelated-runtime") || contains(cmd, "--volumes") || len(cmd) > 1 && (cmd[0] == "volume" || cmd[0] == "network") && cmd[1] == "rm" {
					t.Fatalf("destructive restart: %v", cmd)
				}
			}
			// The real cursor reader's retained-log behavior is exercised below.
			docker.lifecycleEvents = nil
			if observation, err := backend.Ensure(ctx, desired); err != nil || !observation.Ready {
				t.Fatalf("recreate=%+v %v", observation, err)
			}
			for name, labels := range objects {
				if !reflect.DeepEqual(labels, docker.objects[name]) {
					t.Fatalf("retained object changed: %s", name)
				}
			}
			if docker.caNameSetDigest != caDigest || docker.caRotations != rotations {
				t.Fatal("restart rotated existing CA")
			}
		})
	}
}

func TestRestartRefusesMissingDataOrConflictingOwnershipBeforeStopping(t *testing.T) {
	for _, mode := range []string{"missing-home", "wrong-workspace-owner", "pending-configuration", "delete-intent"} {
		t.Run(mode, func(t *testing.T) {
			backend, docker, run, _ := testBackend(t)
			run.Persistence = resolvedrun.Persistence{Workspace: true, RuntimeState: true, DockerData: true}
			desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("a", 64)}
			if _, err := backend.Ensure(context.Background(), desired); err != nil {
				t.Fatal(err)
			}
			names := namesFor(backend.config, run.RunID, desired.SnapshotDigest)
			switch mode {
			case "missing-home":
				delete(docker.objects, "volume:"+names.home)
			case "wrong-workspace-owner":
				docker.objects["volume:"+names.workspace][ownerLabel] = "other"
			case "pending-configuration":
				desired.ConfigurationRollout = true
			case "delete-intent":
				desired.DeleteRequested = true
			}
			start := len(docker.commands)
			if _, err := backend.QuiesceForRestart(context.Background(), desired); !errors.Is(err, controller.ErrBackendDesiredRunInvalid) {
				t.Fatalf("conflict=%v", err)
			}
			for _, cmd := range docker.commands[start:] {
				if cmd[0] == "stop" || cmd[0] == "rm" || contains(cmd, "up") {
					t.Fatalf("conflict mutated containers: %v", cmd)
				}
			}
		})
	}
}

func TestRestartTailSkipsOldEventsAndObservesNewFailures(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(stateDir, "agentd"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(stateDir, "agentd", "events.jsonl")
	old := []byte(`{"event":"plugin.event","plugin_event":"plugin.work.failed","payload":{"secret":"fake-old-payload"}}` + "\n")
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("python3", "-c", lifecycleEventReader)
	command.Env = append(os.Environ(), "NVT_STATE_DIR="+stateDir)
	command.Stdin = strings.NewReader(`{"cursor":"v1:0:0:999999","tail":true}`)
	raw, err := command.Output()
	var baseline lifecycleReaderResponse
	if err != nil || json.Unmarshal(raw, &baseline) != nil || baseline.Error != "" || len(baseline.Events) != 0 || baseline.Cursor == "" || bytes.Contains(raw, []byte("fake-old-payload")) {
		t.Fatalf("baseline=%s %v", raw, err)
	}
	unchanged, _ := runLifecycleReader(t, stateDir, baseline.Cursor)
	if len(unchanged.Events) != 0 {
		t.Fatal("old terminal event replayed")
	}
	if err := os.WriteFile(path, append(old, []byte(`{"event":"plugin.event","plugin_event":"plugin.work.failed"}`+"\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	next, _ := runLifecycleReader(t, stateDir, baseline.Cursor)
	if !reflect.DeepEqual(next.Events, []string{"plugin.work.failed"}) {
		t.Fatalf("new failure ignored: %+v", next)
	}
}

// Actual admin HTTP -> durable SQLite -> reconciler -> Docker backend, with
// only Docker/broker dependencies replaced by isolated in-memory/loopback fixtures.
func TestScopedRestartHTTPReconciliationIntegration(t *testing.T) {
	backend, docker, run, _ := testBackend(t)
	run.Persistence = resolvedrun.Persistence{Workspace: true, RuntimeState: true, DockerData: true}
	run.TTL = resolvedrun.TTL{}
	run.Principal.Subject = "workstation-" + run.RunID
	raw, _ := json.Marshal(run)
	ctx := context.Background()
	store, err := controller.OpenStore(ctx, filepath.Join(t.TempDir(), "controller", "state.sqlite3"), controller.StoreOptions{MaxActiveRuns: 4, MaxClaimLease: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	hash := sha256.Sum256([]byte("nvt.workstation/v1\x00" + run.RunID))
	created, err := store.CreateBatch(ctx, []controller.CreateInput{{IdempotencyKey: "workstation-" + hex.EncodeToString(hash[:]), ResolvedRun: raw}})
	if err != nil {
		t.Fatal(err)
	}
	reconciler, err := controller.NewReconciler(store, backend, "fixture-controller", time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := reconciler.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
	}
	adminPath := filepath.Join(t.TempDir(), "admin")
	const token = "fixture-admin-token-not-a-real-credential-000000"
	if err := os.WriteFile(adminPath, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := controller.LoadAPIAuthorization(adminPath, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := controller.NewAuthorizedHTTPHandlerWithServices(store, nil, nil, nil, nil, auth)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/runs/"+run.RunID+"/restart", strings.NewReader(`{"api_version":"nvt.local-runs/v1","request_id":"0123456789abcdef0123456789abcdef"}`))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 202 {
		t.Fatalf("request=%d", response.StatusCode)
	}
	docker.lifecycleCursor = "v1:1:2:500"
	for i := 0; i < 2; i++ {
		if err := reconciler.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
	}
	got, err := store.Get(ctx, run.RunID)
	if err != nil || got.State != controller.StateRunning || got.RestartPhase != "complete" || got.SnapshotDigest != created[0].Run.SnapshotDigest {
		t.Fatalf("restart=%+v %v", got, err)
	}
}
