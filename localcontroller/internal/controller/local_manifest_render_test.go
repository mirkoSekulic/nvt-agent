package controller

import (
	"bytes"
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	serviceconfig "github.com/mirkoSekulic/nvt-agent/localplatform/config"
	localmanifest "github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

func TestHTTPBindingRolloutFromLocalManifestPreservesOwnership(t *testing.T) {
	raw, err := os.ReadFile("../../../examples/http-credentials/manifest.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m, err := localmanifest.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	m.Workstations = m.Workstations[:1]
	profile := m.Profiles["api-only"]
	profile.HTTPCredentials = nil
	profile.Egress = nil
	m.Profiles["api-only"] = profile
	path := filepath.Join(t.TempDir(), "controller.json")
	clock := &fakeClock{value: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	stage := func() {
		t.Helper()
		c, err := localmanifest.Compile(m)
		if err != nil {
			t.Fatal(err)
		}
		data, err := serviceconfig.Controller(c, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		s, err := LoadScheduler(path, store)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.BootstrapWorkstations(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	stage()
	backend := newFakeBackend()
	reconciler, _ := NewReconciler(store, backend, "controller", 30*time.Second, log.New(io.Discard, "", 0))
	for i := 0; i < 2; i++ {
		if err := reconciler.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	_, ownership, err := store.ResolvedSnapshot(context.Background(), "api-only")
	if err != nil {
		t.Fatal(err)
	}
	for _, selected := range [][]string{{"forge-api"}, {"forge-api", "forge-git"}, nil} {
		profile.HTTPCredentials = selected
		m.Profiles["api-only"] = profile
		stage() // no replacement or destructive acknowledgement flags
		if err := reconciler.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
		raw, _, err := store.ResolvedSnapshot(context.Background(), "api-only")
		if err != nil {
			t.Fatal(err)
		}
		run, err := resolvedrun.DecodeResolvedAgentRun(raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(run.Broker.Grants) != len(selected) || len(run.Repositories) != 0 {
			t.Fatal("binding update/checkout separation lost")
		}
		backend.mu.Lock()
		last := backend.ensuredRuns[len(backend.ensuredRuns)-1]
		backend.mu.Unlock()
		if last.SnapshotDigest != ownership || !last.ConfigurationRollout || last.PreviousResolved == nil {
			t.Fatal("binding update changed ownership or required replacement")
		}
	}
}

func TestLocalManifestRendererProducesNativeWorkstations(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "..", "nvt.local.example.yaml")
	file, err := os.Open(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := localmanifest.Decode(file)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := localmanifest.Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := serviceconfig.Controller(compiled, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "local-controller.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{value: time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 8)
	scheduler, err := LoadScheduler(path, store)
	if err != nil {
		t.Fatalf("rendered controller configuration was rejected: %v\n%s", err, encoded)
	}
	if err := scheduler.BootstrapWorkstations(context.Background()); err != nil {
		t.Fatal(err)
	}
	listed, err := store.List(context.Background(), 10, "")
	if err != nil || len(listed.Runs) != 1 {
		t.Fatalf("rendered workstations = %#v, %v", listed, err)
	}
	for _, runID := range []string{"project"} {
		snapshot, _, snapshotErr := store.ResolvedSnapshot(context.Background(), runID)
		if snapshotErr != nil {
			t.Fatal(snapshotErr)
		}
		resolved, decodeErr := resolvedrun.DecodeResolvedAgentRun(snapshot)
		clear(snapshot)
		if decodeErr != nil || !resolved.Persistence.Workspace || !resolved.Persistence.RuntimeState || !resolved.Persistence.DockerData ||
			resolved.Runtime.Docker == nil || resolved.Execution.Name != "local-docker" || resolved.Retention != "persistent" {
			t.Fatalf("workstation %s = %#v err=%v", runID, resolved, decodeErr)
		}
	}
}
