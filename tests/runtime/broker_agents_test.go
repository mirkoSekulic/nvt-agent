package runtime_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrokerAgentsRegisterAndGrantAreIdempotent(t *testing.T) {
	f := newFixture(t)
	agentsFile := filepath.Join(f.home, "agents.yaml")
	if err := os.WriteFile(agentsFile, []byte(`{"agents":[]}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	f.runCommand("python3", true, filepath.Join(f.root, "scripts", "broker-agents.py"), "--agents-file", agentsFile, "register", "--name", "frontend", "--token", "frontend-token")
	f.runCommand("python3", true, filepath.Join(f.root, "scripts", "broker-agents.py"), "--agents-file", agentsFile, "register", "--name", "frontend", "--token", "frontend-token")
	f.runCommand("python3", true, filepath.Join(f.root, "scripts", "broker-agents.py"), "--agents-file", agentsFile, "grant", "--name", "frontend", "--provider", "github-fork-app", "--repo", "my-user/frontend")
	f.runCommand("python3", true, filepath.Join(f.root, "scripts", "broker-agents.py"), "--agents-file", agentsFile, "grant", "--name", "frontend", "--provider", "github-fork-app", "--repo", "my-user/frontend")

	data, err := os.ReadFile(agentsFile)
	if err != nil {
		t.Fatal(err)
	}
	expectedHash := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("frontend-token")))
	text := string(data)
	if strings.Count(text, `"id": "frontend"`) != 1 {
		t.Fatalf("expected one frontend entry:\n%s", text)
	}
	if !strings.Contains(text, `"token-sha256": "`+expectedHash+`"`) {
		t.Fatalf("expected token hash %s:\n%s", expectedHash, text)
	}
	if strings.Count(text, `"my-user/frontend"`) != 1 {
		t.Fatalf("expected idempotent repo grant:\n%s", text)
	}
}
