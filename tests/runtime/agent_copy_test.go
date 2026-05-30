package runtime_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentCopyCreatesFreshAgentWithCopiedGrantsAndNoState(t *testing.T) {
	root := repoRoot(t)
	src := fmt.Sprintf("copy-src-%d", os.Getpid())
	dst := fmt.Sprintf("copy-dst-%d", os.Getpid())
	cleanupAgentCopyTest(t, root, src, dst)

	f := newFixture(t)
	runInRoot(t, f, root, true, "make", "agent-init", "NAME="+src)
	runInRoot(t, f, root, true, "make", "agent-grant", "NAME="+src, "PROVIDER=github-fork-app", "REPO=my-user/frontend")

	srcDir := filepath.Join(root, ".agents", src)
	dstDir := filepath.Join(root, ".agents", dst)
	mustWriteFile(t, filepath.Join(srcDir, "workspace", "AGENTS.local.md"), "source local instructions\n")
	mustWriteFile(t, filepath.Join(srcDir, "workspace", "repo.txt"), "workspace state\n")
	mustWriteFile(t, filepath.Join(srcDir, "custom-plugins", "plugin-state"), "plugin state\n")
	mustWriteFile(t, filepath.Join(srcDir, "auth", "codex", "auth.json"), "auth state\n")
	mustWriteFile(t, filepath.Join(srcDir, "auth", "claude", "auth.json"), "auth state\n")

	runInRoot(t, f, root, true, "make", "agent-copy", "FROM="+src, "TO="+dst)
	runInRoot(t, f, root, false, "make", "agent-copy", "FROM="+src, "TO="+dst)

	if _, err := os.Stat(filepath.Join(dstDir, "agent.yaml")); err != nil {
		t.Fatalf("expected copied agent.yaml: %v", err)
	}
	if got := mustReadFile(t, filepath.Join(dstDir, "workspace", "AGENTS.local.md")); got != "source local instructions\n" {
		t.Fatalf("unexpected copied AGENTS.local.md: %q", got)
	}
	for _, path := range []string{
		filepath.Join(dstDir, "workspace", "repo.txt"),
		filepath.Join(dstDir, "custom-plugins", "plugin-state"),
		filepath.Join(dstDir, "auth", "codex", "auth.json"),
		filepath.Join(dstDir, "auth", "claude", "auth.json"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected runtime state not to be copied: %s", path)
		}
	}

	srcToken := readAgentEnvValue(t, filepath.Join(srcDir, "env"), "NVT_BROKER_TOKEN")
	dstToken := readAgentEnvValue(t, filepath.Join(dstDir, "env"), "NVT_BROKER_TOKEN")
	if srcToken == "" || dstToken == "" {
		t.Fatal("expected both agents to have broker tokens")
	}
	if srcToken == dstToken {
		t.Fatal("expected copied agent to get a fresh broker token")
	}

	agentsFile := filepath.Join(root, ".broker", "agents.yaml")
	expectedHash := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(dstToken)))
	if got := brokerAgentValue(t, root, agentsFile, dst, "token-sha256"); got != expectedHash {
		t.Fatalf("unexpected copied agent token hash: got %q want %q", got, expectedHash)
	}
	if got := brokerAgentGrantCount(t, root, agentsFile, dst); got != "1" {
		t.Fatalf("expected copied grants, got %s", got)
	}
	if got := brokerAgentFirstRepo(t, root, agentsFile, dst); got != "my-user/frontend" {
		t.Fatalf("unexpected copied grant repo: %q", got)
	}
	if strings.Contains(mustReadFile(t, agentsFile), "&id") || strings.Contains(mustReadFile(t, agentsFile), "*id") {
		t.Fatalf("agents.yaml should not contain YAML aliases:\n%s", mustReadFile(t, agentsFile))
	}
}

func TestAgentCopyCanSkipGrantCopying(t *testing.T) {
	root := repoRoot(t)
	src := fmt.Sprintf("copy-ng-src-%d", os.Getpid())
	dst := fmt.Sprintf("copy-ng-dst-%d", os.Getpid())
	cleanupAgentCopyTest(t, root, src, dst)

	f := newFixture(t)
	runInRoot(t, f, root, true, "make", "agent-init", "NAME="+src)
	runInRoot(t, f, root, true, "make", "agent-grant", "NAME="+src, "PROVIDER=github-fork-app", "REPO=my-user/frontend")
	runInRoot(t, f, root, true, "make", "agent-cp", "FROM="+src, "TO="+dst, "COPY_GRANTS=0")

	if got := brokerAgentGrantCount(t, root, filepath.Join(root, ".broker", "agents.yaml"), dst); got != "0" {
		t.Fatalf("expected no copied grants, got %s", got)
	}
}

func cleanupAgentCopyTest(t *testing.T, root string, names ...string) {
	t.Helper()
	for _, name := range names {
		_ = os.RemoveAll(filepath.Join(root, ".agents", name))
	}
	t.Cleanup(func() {
		for _, name := range names {
			_ = os.RemoveAll(filepath.Join(root, ".agents", name))
			agentsFile := filepath.Join(root, ".broker", "agents.yaml")
			if _, err := os.Stat(agentsFile); err == nil {
				commandWithEnv("python3 "+shellQuote(filepath.Join(root, "scripts", "broker-agents.py")), nil, "--agents-file", agentsFile, "unregister", "--name", name).Run()
			}
		}
	})
}

func runInRoot(t *testing.T, f *fixture, root string, wantOK bool, command string, args ...string) string {
	t.Helper()
	cmd := commandWithEnv(command, f.env(), args...)
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if wantOK && err != nil {
		t.Fatalf("command failed: %s %v\n%s", command, args, output)
	}
	if !wantOK && err == nil {
		t.Fatalf("command unexpectedly succeeded: %s %v\n%s", command, args, output)
	}
	return string(output)
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func readAgentEnvValue(t *testing.T, path, key string) string {
	t.Helper()
	for _, line := range strings.Split(mustReadFile(t, path), "\n") {
		if value, ok := strings.CutPrefix(line, key+"="); ok {
			return value
		}
	}
	t.Fatalf("%s missing %s", path, key)
	return ""
}

func brokerAgentValue(t *testing.T, root, agentsFile, name, key string) string {
	t.Helper()
	script := `
import sys
import yaml

with open(sys.argv[1], "r", encoding="utf-8") as file:
    data = yaml.safe_load(file)
for agent in data.get("agents", []):
    if isinstance(agent, dict) and agent.get("id") == sys.argv[2]:
        print(agent.get(sys.argv[3], ""))
        raise SystemExit(0)
raise SystemExit(1)
`
	return strings.TrimSpace(runCommandForAgentCopyTest(t, root, "python3", true, "-c", script, agentsFile, name, key))
}

func brokerAgentGrantCount(t *testing.T, root, agentsFile, name string) string {
	t.Helper()
	script := `
import sys
import yaml

with open(sys.argv[1], "r", encoding="utf-8") as file:
    data = yaml.safe_load(file)
for agent in data.get("agents", []):
    if isinstance(agent, dict) and agent.get("id") == sys.argv[2]:
        print(len(agent.get("grants") or []))
        raise SystemExit(0)
raise SystemExit(1)
`
	return strings.TrimSpace(runCommandForAgentCopyTest(t, root, "python3", true, "-c", script, agentsFile, name))
}

func brokerAgentFirstRepo(t *testing.T, root, agentsFile, name string) string {
	t.Helper()
	script := `
import sys
import yaml

with open(sys.argv[1], "r", encoding="utf-8") as file:
    data = yaml.safe_load(file)
for agent in data.get("agents", []):
    if isinstance(agent, dict) and agent.get("id") == sys.argv[2]:
        grants = agent.get("grants") or []
        print((grants[0].get("repositories") or [""])[0] if grants else "")
        raise SystemExit(0)
raise SystemExit(1)
`
	return strings.TrimSpace(runCommandForAgentCopyTest(t, root, "python3", true, "-c", script, agentsFile, name))
}

func runCommandForAgentCopyTest(t *testing.T, root, command string, wantOK bool, args ...string) string {
	t.Helper()
	cmd := commandWithEnv(command, nil, args...)
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if wantOK && err != nil {
		t.Fatalf("command failed: %s %v\n%s", command, args, output)
	}
	if !wantOK && err == nil {
		t.Fatalf("command unexpectedly succeeded: %s %v\n%s", command, args, output)
	}
	return string(output)
}
