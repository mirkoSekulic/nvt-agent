package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	serviceconfig "github.com/mirkoSekulic/nvt-agent/localplatform/config"
	localmanifest "github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

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
