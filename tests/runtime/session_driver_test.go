package runtime_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
# Emulate zellij >= 0.44: 'action dump-screen [--full] --path FILE'. The
# pre-0.44 positional-PATH form leaves --path unset, so a caller that still
# passes the path positionally gets stdout output and no file — i.e. this fake
# rejects the invalid CLI shape instead of silently accepting it.
is_dump=0
dump_path=""
want_path=0
for a in "$@"; do
  if [ "$want_path" = 1 ]; then dump_path="$a"; want_path=0; continue; fi
  case "$a" in
    dump-screen) is_dump=1 ;;
    --path) want_path=1 ;;
  esac
done
if [ "$is_dump" = 1 ]; then
  if [ -n "$dump_path" ]; then
    printf 'zellij-capture\n' > "$dump_path"
  else
    printf 'zellij-capture\n'
  fi
fi
exit 0
`)
	return tmuxArgs, zellijArgs
}

// waitForFileContains polls path until it contains substr or the deadline
// passes. The zellij start path spawns its client through a detached PTY
// daemon, so the fake records its argv asynchronously.
func waitForFileContains(t *testing.T, path, substr string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, _ := os.ReadFile(path)
		if strings.Contains(string(data), substr) {
			return string(data)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %q in %s; got:\n%s", substr, path, data)
		}
		time.Sleep(20 * time.Millisecond)
	}
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
	zellijCap := readFileString(t, zellijArgs)
	if !strings.Contains(zellijCap, "dump-screen") || !strings.Contains(zellijCap, "--path") {
		t.Fatalf("expected zellij dump-screen --path (v0.44 form), got:\n%s", zellijCap)
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

	// Default driver starts a headless zellij session: one client that both
	// creates (--new-session-with-layout) and attaches the session, launched
	// through the detached PTY daemon so it stays injectable/capturable.
	f.run(bin, true, "start", "--session", "agent", "--command-file", commandFile, "--workdir", f.workspace)
	zellij := waitForFileContains(t, zellijArgs, "--new-session-with-layout")
	for _, fragment := range []string{"--session agent", "--new-session-with-layout"} {
		if !strings.Contains(zellij, fragment) {
			t.Fatalf("expected zellij start fragment %q, got:\n%s", fragment, zellij)
		}
	}
	// The pre-0.44 background-attach form must be gone.
	if strings.Contains(zellij, "create-background") {
		t.Fatalf("start must not use attach --create-background, got:\n%s", zellij)
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
		// zellij is installed alongside it, pinned to a version whose CLI the
		// adapter targets (dump-screen --path, headless client).
		"ARG ZELLIJ_VERSION=v0.44.3",
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

// TestAgentSessionZellijHeadlessSmoke drives the real zellij binary end to end
// with no human attached: start -> exists -> send -> capture, asserting a sent
// command's output shows up in capture. This is the check the fakes cannot make
// -- zellij (unlike tmux) delivers no keystrokes and renders no capture without
// a live client, so it exercises the detached PTY client and the v0.44
// dump-screen --path form together. Skipped when a real zellij is absent (e.g.
// the offline unit environment); it runs in the image, which ships zellij.
func TestAgentSessionZellijHeadlessSmoke(t *testing.T) {
	if _, err := exec.LookPath("zellij"); err != nil {
		t.Skip("real zellij not installed; skipping headless smoke")
	}
	f := newFixture(t)
	bin := agentSessionBin(f.root)
	session := fmt.Sprintf("nvt-smoke-%d", os.Getpid())
	marker := "NVT_SMOKE_MARKER_4731"

	// The layout wrapper sources ~/.nvt-agent/env and execs the start helper;
	// provide an empty env file and a stub helper that launches an interactive
	// shell so send/capture have a live pane to act on.
	nvtDir := filepath.Join(f.home, ".nvt-agent")
	if err := os.MkdirAll(nvtDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nvtDir, "env"), []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	helper := f.writeBin("smoke-exec-helper", "#!/usr/bin/env bash\nexec bash --norc -i\n")
	commandFile := filepath.Join(f.home, "agent-command.json")
	if err := os.WriteFile(commandFile, []byte(`{"command":"bash","args":["--norc","-i"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	promptFile := filepath.Join(f.home, "smoke-prompt.txt")
	if err := os.WriteFile(promptFile, []byte("echo "+marker), 0o600); err != nil {
		t.Fatal(err)
	}

	env := []string{"NVT_SESSION_DRIVER=zellij", "NVT_START_EXEC_HELPER=" + helper}
	fullEnv := append(f.env(), env...)
	t.Cleanup(func() {
		commandWithEnv(bin, fullEnv, "capture", "--session", session, "--lines", "1").Run()
		exec.Command("zellij", "--session", session, "kill-session").Run()
		exec.Command("zellij", "delete-session", session).Run()
	})

	f.runWithEnv(bin, true, env, "start", "--session", session, "--command-file", commandFile, "--workdir", f.workspace)

	// The session must come up (headless client established).
	if !eventually(t, 10*time.Second, func() bool {
		return commandWithEnv(bin, fullEnv, "exists", "--session", session).Run() == nil
	}) {
		t.Fatal("zellij session never became live after start")
	}

	// Deliver a prompt and confirm its output renders in capture -- proving
	// both headless input and headless capture work with no attached client.
	f.runWithEnv(bin, true, env, "send", "--session", session, "--file", promptFile)
	if !eventually(t, 10*time.Second, func() bool {
		out, _ := commandWithEnv(bin, fullEnv, "capture", "--session", session, "--lines", "50").CombinedOutput()
		return strings.Contains(string(out), marker)
	}) {
		t.Fatalf("marker %q never appeared in headless capture", marker)
	}
}

func eventually(t *testing.T, within time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return cond()
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
