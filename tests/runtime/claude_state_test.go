package runtime_test

// Bootstrap seeding of Claude Code's state file (~/.claude.json): a claude
// runtime gets onboarding and workspace trust marked complete so a headless
// session is never blocked on the interactive first-run wizard; the file is
// never overwritten and non-claude runtimes are untouched.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func readClaudeState(t *testing.T, f *fixture) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.home, ".claude.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("invalid claude state JSON: %v\n%s", err, data)
	}
	return state
}

func TestBootstrapSeedsClaudeStateForClaudeRuntime(t *testing.T) {
	f := newFixture(t)
	config := f.writeAgentConfig(`
runtime:
  command: claude
`)

	f.runWithEnv(bootstrapBin(f.root), true, nil, config)

	state := readClaudeState(t, f)
	if state["hasCompletedOnboarding"] != true {
		t.Fatalf("expected hasCompletedOnboarding true, got %#v", state)
	}
	projects, ok := state["projects"].(map[string]any)
	if !ok {
		t.Fatalf("expected projects object, got %#v", state)
	}
	project, ok := projects[f.workspace].(map[string]any)
	if !ok {
		t.Fatalf("expected project entry for %s, got %#v", f.workspace, projects)
	}
	if project["hasTrustDialogAccepted"] != true {
		t.Fatalf("expected hasTrustDialogAccepted true, got %#v", project)
	}
	info, err := os.Stat(filepath.Join(f.home, ".claude.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected mode 0600, got %v", info.Mode().Perm())
	}
}

func TestBootstrapPreservesExistingClaudeState(t *testing.T) {
	f := newFixture(t)
	existing := `{"hasCompletedOnboarding":true,"customKey":"user-managed"}`
	mustWriteFile(t, filepath.Join(f.home, ".claude.json"), existing)
	config := f.writeAgentConfig(`
runtime:
  command: claude
`)

	f.runWithEnv(bootstrapBin(f.root), true, nil, config)

	data, err := os.ReadFile(filepath.Join(f.home, ".claude.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != existing {
		t.Fatalf("bootstrap rewrote existing claude state:\n%s", data)
	}
}

func TestBootstrapDoesNotSeedClaudeStateForOtherRuntimes(t *testing.T) {
	f := newFixture(t)
	config := f.writeAgentConfig(`
runtime:
  command: codex
`)

	f.runWithEnv(bootstrapBin(f.root), true, nil, config)

	if _, err := os.Stat(filepath.Join(f.home, ".claude.json")); !os.IsNotExist(err) {
		t.Fatalf("expected no claude state file for codex runtime, err=%v", err)
	}
}
