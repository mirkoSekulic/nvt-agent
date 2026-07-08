package runtime_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func agentSessionBin(root string) string {
	return "python3 " + shellQuote(filepath.Join(root, "runtime", "core", "agent-session.py"))
}

// writeFakeMultiplexers installs fake tmux and zellij binaries that record their
// argv and behave enough like the real tools for the adapter's existence,
// send, and capture paths.
func writeFakeMultiplexers(f *fixture) (tmuxArgs, zellijArgs string) {
	tmuxArgs = filepath.Join(f.home, "tmux.args")
	zellijArgs = filepath.Join(f.home, "zellij.args")
	f.writeBin("tmux", `#!/usr/bin/env bash
printf '%s\n' "$*" >> "`+tmuxArgs+`"
case "$1" in
  has-session) exit 0 ;;
  capture-pane) printf 'tmux-capture\n'; exit 0 ;;
esac
exit 0
`)
	f.writeBin("zellij", `#!/usr/bin/env bash
printf '%s\n' "$*" >> "`+zellijArgs+`"
case "$1" in
  list-sessions) printf 'agent\n'; exit 0 ;;
esac
prev=""
for a in "$@"; do
  if [ "$prev" = "dump-screen" ]; then printf 'zellij-capture\n' > "$a"; fi
  prev="$a"
done
exit 0
`)
	return tmuxArgs, zellijArgs
}

func TestBootstrapPersistsDefaultSessionDriver(t *testing.T) {
	f := newFixture(t)
	config := f.writeAgentConfig(`
runtime:
  command: codex
`)
	f.runWithEnv(bootstrapBin(f.root), true, nil, config)

	data, err := os.ReadFile(filepath.Join(f.home, ".nvt-agent", "session.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"driver":"zellij"`) {
		t.Fatalf("expected default zellij driver, got %q", data)
	}
}

func TestBootstrapPersistsExplicitSessionDrivers(t *testing.T) {
	for _, driver := range []string{"zellij", "tmux"} {
		t.Run(driver, func(t *testing.T) {
			f := newFixture(t)
			config := f.writeAgentConfig(`
runtime:
  command: codex
  session:
    driver: ` + driver + `
`)
			f.runWithEnv(bootstrapBin(f.root), true, nil, config)

			data, err := os.ReadFile(filepath.Join(f.home, ".nvt-agent", "session.json"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), `"driver":"`+driver+`"`) {
				t.Fatalf("expected %s driver, got %q", driver, data)
			}
		})
	}
}

func TestBootstrapRejectsInvalidSessionDriver(t *testing.T) {
	f := newFixture(t)
	config := f.writeAgentConfig(`
runtime:
  command: codex
  session:
    driver: screen
`)
	output := f.runWithEnv(bootstrapBin(f.root), false, nil, config)
	if !strings.Contains(output, "runtime.session.driver must be one of") {
		t.Fatalf("expected loud invalid-driver failure, got:\n%s", output)
	}
	if _, err := os.Stat(filepath.Join(f.home, ".nvt-agent", "session.json")); err == nil {
		t.Fatal("invalid driver must not persist session.json")
	}
}

func TestAgentSessionResolvesDriver(t *testing.T) {
	f := newFixture(t)
	bin := agentSessionBin(f.root)

	// No state and no override -> zellij default.
	if got := strings.TrimSpace(f.run(bin, true, "driver")); got != "zellij" {
		t.Fatalf("expected default zellij, got %q", got)
	}

	// Persisted state wins over the default.
	stateFile := filepath.Join(f.state, "session.json")
	if err := os.WriteFile(stateFile, []byte(`{"driver":"tmux"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(f.run(bin, true, "driver")); got != "tmux" {
		t.Fatalf("expected persisted tmux, got %q", got)
	}

	// Env override wins over persisted state.
	got := strings.TrimSpace(f.runWithEnv(bin, true, []string{"NVT_SESSION_DRIVER=zellij"}, "driver"))
	if got != "zellij" {
		t.Fatalf("expected override zellij, got %q", got)
	}

	// Invalid override fails loudly.
	out := f.runWithEnv(bin, false, []string{"NVT_SESSION_DRIVER=screen"}, "driver")
	if !strings.Contains(out, "invalid session driver") {
		t.Fatalf("expected loud invalid override, got:\n%s", out)
	}
}

func TestAgentSessionSendUsesSelectedDriver(t *testing.T) {
	f := newFixture(t)
	bin := agentSessionBin(f.root)
	tmuxArgs, zellijArgs := writeFakeMultiplexers(f)
	promptFile := filepath.Join(f.home, "prompt.txt")
	if err := os.WriteFile(promptFile, []byte("review the failing tests\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Default driver (zellij) delivers via zellij, not tmux.
	f.run(bin, true, "send", "--session", "agent", "--file", promptFile)
	zellij := readFileString(t, zellijArgs)
	if !strings.Contains(zellij, "write-chars") || !strings.Contains(zellij, "list-sessions") {
		t.Fatalf("expected zellij delivery, got:\n%s", zellij)
	}
	if _, err := os.Stat(tmuxArgs); err == nil {
		t.Fatal("default driver must not shell out to tmux")
	}

	// Explicit tmux delivers via tmux buffer paste.
	f.runWithEnv(bin, true, []string{"NVT_SESSION_DRIVER=tmux"}, "send", "--session", "agent", "--file", promptFile)
	tmux := readFileString(t, tmuxArgs)
	for _, fragment := range []string{"has-session -t agent", "load-buffer", "paste-buffer", "send-keys -t agent Enter"} {
		if !strings.Contains(tmux, fragment) {
			t.Fatalf("expected tmux delivery fragment %q, got:\n%s", fragment, tmux)
		}
	}
}

func TestAgentSessionCaptureUsesSelectedDriver(t *testing.T) {
	f := newFixture(t)
	bin := agentSessionBin(f.root)
	tmuxArgs, zellijArgs := writeFakeMultiplexers(f)

	// Default driver (zellij) captures via dump-screen.
	out := f.run(bin, true, "capture", "--session", "agent", "--lines", "5")
	if !strings.Contains(out, "zellij-capture") {
		t.Fatalf("expected zellij capture output, got:\n%s", out)
	}
	if !strings.Contains(readFileString(t, zellijArgs), "dump-screen") {
		t.Fatalf("expected zellij dump-screen, got:\n%s", readFileString(t, zellijArgs))
	}

	// Explicit tmux captures via capture-pane.
	out = f.runWithEnv(bin, true, []string{"NVT_SESSION_DRIVER=tmux"}, "capture", "--session", "agent", "--lines", "9")
	if !strings.Contains(out, "tmux-capture") {
		t.Fatalf("expected tmux capture output, got:\n%s", out)
	}
	if !strings.Contains(readFileString(t, tmuxArgs), "capture-pane -p -S -9 -t agent") {
		t.Fatalf("expected tmux capture-pane args, got:\n%s", readFileString(t, tmuxArgs))
	}
}

func TestAgentSessionStartUsesSelectedDriver(t *testing.T) {
	f := newFixture(t)
	bin := agentSessionBin(f.root)
	tmuxArgs, zellijArgs := writeFakeMultiplexers(f)
	commandFile := filepath.Join(f.home, "agent-command.json")
	if err := os.WriteFile(commandFile, []byte(`{"command":"codex","args":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Default driver starts a background zellij session.
	f.run(bin, true, "start", "--session", "agent", "--command-file", commandFile, "--workdir", f.workspace)
	zellij := readFileString(t, zellijArgs)
	for _, fragment := range []string{"--new-session-with-layout", "attach --create-background agent"} {
		if !strings.Contains(zellij, fragment) {
			t.Fatalf("expected zellij start fragment %q, got:\n%s", fragment, zellij)
		}
	}
	if _, err := os.Stat(tmuxArgs); err == nil {
		t.Fatal("default driver must not start tmux")
	}
	layout, err := os.ReadFile(filepath.Join(f.state, "session-agent.kdl"))
	if err != nil {
		t.Fatalf("expected zellij layout file: %v", err)
	}
	if !strings.Contains(string(layout), "start-agent-session-exec") {
		t.Fatalf("layout must run the exec helper, got:\n%s", layout)
	}

	// Explicit tmux starts a detached tmux session.
	f.runWithEnv(bin, true, []string{"NVT_SESSION_DRIVER=tmux"}, "start", "--session", "agent", "--command-file", commandFile, "--workdir", f.workspace)
	if !strings.Contains(readFileString(t, tmuxArgs), "new-session -d -s agent") {
		t.Fatalf("expected tmux new-session, got:\n%s", readFileString(t, tmuxArgs))
	}
}

func TestRuntimeDockerfileInstallsBothSessionDrivers(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "runtime", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(data)
	required := []string{
		// tmux stays installed via apt.
		"    tmux \\",
		// zellij is installed alongside it.
		"releases/download/${ZELLIJ_VERSION}/zellij-",
		// the adapter that both drivers go through is on PATH.
		"COPY runtime/core/agent-session.py /usr/local/bin/agent-session",
		"/usr/local/bin/agent-session \\",
	}
	for _, fragment := range required {
		if !strings.Contains(dockerfile, fragment) {
			t.Fatalf("runtime Dockerfile missing %q\n%s", fragment, dockerfile)
		}
	}
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
