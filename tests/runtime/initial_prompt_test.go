package runtime_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestInitialPromptWaitsForPostLaunchSessionReadiness(t *testing.T) {
	tmux, err := exec.LookPath("tmux")
	if err != nil {
		t.Skip("tmux is unavailable; post-launch initial-prompt integration test skipped")
	}
	f := newFixture(t)
	tmuxDir := filepath.Join(f.home, "tmux")
	if err := os.MkdirAll(tmuxDir, 0o700); err != nil {
		t.Fatal(err)
	}
	session := "nvt-initial-prompt-" + strings.ReplaceAll(t.Name(), "/", "-")
	socket := filepath.Join(f.home, "agentd.sock")
	readyMarker := filepath.Join(f.state, "agentd", "session-launched")
	env := append(f.env(),
		"TMUX_TMPDIR="+tmuxDir,
		"AGENT_SESSION="+session,
		"NVT_AGENTD_SOCKET="+socket,
		"NVT_AGENT_SESSION_READY_MARKER="+readyMarker,
		"NVT_AGENT_SESSION_STARTUP_GRACE_SECONDS=0.8",
	)

	envPath := filepath.Join(f.home, ".nvt-agent", "env")
	if err := os.MkdirAll(filepath.Dir(envPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envPath, []byte(
		"export NVT_WORKSPACE="+shellQuote(f.workspace)+"\n"+
			"export PATH="+shellQuote(f.pathPrefix+string(os.PathListSeparator)+os.Getenv("PATH"))+"\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	commandPath := filepath.Join(f.home, ".nvt-agent", "agent-command.json")
	if err := os.WriteFile(commandPath, []byte(`{"command":"sleep","args":["30"]}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.writeBin("agentdctl", "#!/usr/bin/env bash\nexec python3 "+shellQuote(filepath.Join(f.root, "runtime", "agentd", "agentdctl.py"))+" \"$@\"\n")

	agentd := exec.Command("python3", filepath.Join(f.root, "runtime", "agentd", "agentd.py"))
	agentd.Env = mergedEnv(env)
	agentdOutput := &bytes.Buffer{}
	agentd.Stdout = agentdOutput
	agentd.Stderr = agentdOutput
	if err := agentd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if agentd.ProcessState == nil {
			_ = agentd.Process.Signal(syscall.SIGTERM)
			done := make(chan error, 1)
			go func() { done <- agentd.Wait() }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				_ = agentd.Process.Kill()
				<-done
			}
		}
		kill := exec.Command(tmux, "kill-session", "-t", session)
		kill.Env = mergedEnv(env)
		_ = kill.Run()
	})
	waitForFile(t, socket, 3*time.Second)

	launcherStarted := time.Now()
	launcher := commandWithEnv("bash "+shellQuote(filepath.Join(f.root, "runtime", "core", "start-agent-session.sh")), env)
	if output, err := launcher.CombinedOutput(); err != nil {
		t.Fatalf("start agent session: %v\n%s", err, output)
	}
	if elapsed := time.Since(launcherStarted); elapsed < 4500*time.Millisecond {
		t.Fatalf("launcher did not exercise its existing five-second stability check: %s", elapsed)
	}
	if _, err := os.Stat(readyMarker); err != nil {
		t.Fatalf("launcher did not publish post-launch readiness marker: %v", err)
	}

	sentinel := "post-launch-readiness-" + strings.ReplaceAll(t.Name(), "/", "-")
	agentConfig := f.writeAgentConfig(fmt.Sprintf(`
plugins:
  - name: initial-prompt
    source: custom
    command: %s
    when: after-agent
    restart: never
    config:
      text: %s
`, quoteYAML(initialPromptRunBin(f.root)), quoteYAML(sentinel)))
	afterAgent := commandWithEnv(runPluginsBin(f.root), env, "after-agent", agentConfig)
	afterOutput := &bytes.Buffer{}
	afterAgent.Stdout = afterOutput
	afterAgent.Stderr = afterOutput
	if err := afterAgent.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- afterAgent.Wait() }()

	select {
	case err := <-done:
		t.Fatalf("after-agent prompt bypassed the post-launch grace: %v\n%s", err, afterOutput.String())
	case <-time.After(250 * time.Millisecond):
	}
	if events, err := os.ReadFile(filepath.Join(f.state, "agentd", "events.jsonl")); err != nil {
		t.Fatal(err)
	} else if strings.Contains(string(events), `"event":"prompt.queued"`) || strings.Contains(string(events), `"event":"prompt.injected"`) {
		t.Fatalf("prompt event emitted before post-launch grace:\n%s", events)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("after-agent initial prompt failed: %v\n%s", err, afterOutput.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("after-agent initial prompt did not complete after post-launch grace\n%s", afterOutput.String())
	}
	events, err := os.ReadFile(filepath.Join(f.state, "agentd", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(events), `"event":"prompt.injected"`) {
		t.Fatalf("prompt was not injected after post-launch grace:\n%s", events)
	}
	assertInitialPromptHash(t, f, sentinel)
}

func TestInitialPromptSendsPromptThroughAgentdctl(t *testing.T) {
	f := newFixture(t)
	capturePath := filepath.Join(f.home, "agentdctl-capture")
	writeInitialPromptAgentdctl(t, f, capturePath, true)
	config := f.writePluginConfig("initial-prompt.yaml", "text: |\n  hello agent\n  do work\n")

	f.runWithEnv(initialPromptRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config})

	capture := readTextFile(t, capturePath)
	if !strings.Contains(capture, "ARGS:prompt --source plugin:initial-prompt --no-external\n") {
		t.Fatalf("agentdctl prompt args not captured correctly:\n%s", capture)
	}
	if !strings.Contains(capture, "STDIN:hello agent\ndo work\n") {
		t.Fatalf("prompt text not delivered on stdin:\n%s", capture)
	}
	assertInitialPromptHash(t, f, "hello agent\ndo work\n")
}

func TestInitialPromptSkipsSamePromptHash(t *testing.T) {
	f := newFixture(t)
	capturePath := filepath.Join(f.home, "agentdctl-capture")
	writeInitialPromptAgentdctl(t, f, capturePath, true)
	config := f.writePluginConfig("initial-prompt.yaml", "text: repeat\n")

	f.runWithEnv(initialPromptRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config})
	f.runWithEnv(initialPromptRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config})

	capture := readTextFile(t, capturePath)
	if got := strings.Count(capture, "ARGS:prompt --source plugin:initial-prompt --no-external\n"); got != 1 {
		t.Fatalf("expected one delivery, got %d:\n%s", got, capture)
	}
}

func TestInitialPromptChangedHashDeliversAgain(t *testing.T) {
	f := newFixture(t)
	capturePath := filepath.Join(f.home, "agentdctl-capture")
	writeInitialPromptAgentdctl(t, f, capturePath, true)
	config := f.writePluginConfig("initial-prompt.yaml", "text: first\n")

	f.runWithEnv(initialPromptRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config})
	config = f.writePluginConfig("initial-prompt.yaml", "text: second\n")
	f.runWithEnv(initialPromptRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config})

	capture := readTextFile(t, capturePath)
	if got := strings.Count(capture, "ARGS:prompt --source plugin:initial-prompt --no-external\n"); got != 2 {
		t.Fatalf("expected two deliveries, got %d:\n%s", got, capture)
	}
	assertInitialPromptHash(t, f, "second")
}

func TestInitialPromptEmptyTextExitsWithoutDelivery(t *testing.T) {
	f := newFixture(t)
	capturePath := filepath.Join(f.home, "agentdctl-capture")
	writeInitialPromptAgentdctl(t, f, capturePath, false)
	config := f.writePluginConfig("initial-prompt.yaml", "text: \"\"\n")

	f.runWithEnv(initialPromptRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config})

	if _, err := os.Stat(capturePath); !os.IsNotExist(err) {
		t.Fatalf("expected no agentdctl delivery, stat err=%v", err)
	}
	if _, err := os.Stat(initialPromptHashPath(f)); !os.IsNotExist(err) {
		t.Fatalf("expected no hash file for empty text, stat err=%v", err)
	}
}

func TestInitialPromptWritesHashOnlyAfterSuccessfulDelivery(t *testing.T) {
	f := newFixture(t)
	capturePath := filepath.Join(f.home, "agentdctl-capture")
	writeInitialPromptAgentdctl(t, f, capturePath, false)
	config := f.writePluginConfig("initial-prompt.yaml", "text: will-fail\n")

	output := f.runWithEnv(initialPromptRunBin(f.root), false, initialPromptTestEnv(config))
	if !strings.Contains(output, "agentdctl prompt failed after 3 attempts; last exit 7") {
		t.Fatalf("expected agentdctl failure in output, got:\n%s", output)
	}
	capture := readTextFile(t, capturePath)
	if got := strings.Count(capture, "ARGS:prompt --source plugin:initial-prompt --no-external\n"); got != 3 {
		t.Fatalf("expected three delivery attempts, got %d:\n%s", got, capture)
	}
	if _, err := os.Stat(initialPromptHashPath(f)); !os.IsNotExist(err) {
		t.Fatalf("expected no hash file after failed delivery, stat err=%v", err)
	}
}

func TestInitialPromptRetriesAgentdctlUntilDeliverySucceeds(t *testing.T) {
	f := newFixture(t)
	capturePath := filepath.Join(f.home, "agentdctl-capture")
	writeFlakyInitialPromptAgentdctl(t, f, capturePath, 2)
	config := f.writePluginConfig("initial-prompt.yaml", "text: eventually-ready\n")

	f.runWithEnv(initialPromptRunBin(f.root), true, initialPromptTestEnv(config))

	capture := readTextFile(t, capturePath)
	if got := strings.Count(capture, "ARGS:prompt --source plugin:initial-prompt --no-external\n"); got != 3 {
		t.Fatalf("expected three delivery attempts, got %d:\n%s", got, capture)
	}
	if got := strings.Count(capture, "STDIN:eventually-ready"); got != 3 {
		t.Fatalf("expected prompt on stdin for every attempt, got %d:\n%s", got, capture)
	}
	assertInitialPromptHash(t, f, "eventually-ready")
}

func writeInitialPromptAgentdctl(t *testing.T, f *fixture, capturePath string, succeed bool) {
	t.Helper()
	exitCode := 7
	if succeed {
		exitCode = 0
	}
	f.writeBin("agentdctl", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
{
  printf 'ARGS:%s\n' "$*"
  printf 'STDIN:'
  cat
  printf '\n'
} >> %s
exit %d
`, "%s", shellQuote(capturePath), exitCode))
}

func writeFlakyInitialPromptAgentdctl(t *testing.T, f *fixture, capturePath string, failuresBeforeSuccess int) {
	t.Helper()
	attemptsPath := filepath.Join(f.home, "agentdctl-attempts")
	f.writeBin("agentdctl", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
attempts=0
if [ -f %s ]; then
  attempts="$(cat %s)"
fi
attempts=$((attempts + 1))
printf '%%s\n' "$attempts" > %s
{
  printf 'ARGS:%%s\n' "$*"
  printf 'STDIN:'
  cat
  printf '\n'
} >> %s
if [ "$attempts" -le %d ]; then
  exit 7
fi
exit 0
`, shellQuote(attemptsPath), shellQuote(attemptsPath), shellQuote(attemptsPath), shellQuote(capturePath), failuresBeforeSuccess))
}

func initialPromptTestEnv(config string) []string {
	return []string{
		"NVT_PLUGIN_CONFIG=" + config,
		"NVT_INITIAL_PROMPT_RETRY_ATTEMPTS=3",
		"NVT_INITIAL_PROMPT_RETRY_DELAY_SECONDS=0",
	}
}

func initialPromptHashPath(f *fixture) string {
	return filepath.Join(f.state, "initial-prompt", "last.sha256")
}

func assertInitialPromptHash(t *testing.T, f *fixture, text string) {
	t.Helper()
	wantBytes := sha256.Sum256([]byte(text))
	want := hex.EncodeToString(wantBytes[:])
	got := strings.TrimSpace(readTextFile(t, initialPromptHashPath(f)))
	if got != want {
		t.Fatalf("expected hash %s, got %s", want, got)
	}
}

func readTextFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
