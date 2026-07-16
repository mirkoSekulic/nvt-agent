package runtime_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestAgentSessionSupervisorExitsNonZeroWhenSessionDisappears(t *testing.T) {
	harness := newSessionSupervisorHarness(t)
	cmd, output := harness.start(t)
	waitForFile(t, harness.observed, time.Second)

	started := time.Now()
	if err := os.Remove(harness.sessionState); err != nil {
		t.Fatal(err)
	}
	err := waitForSupervisor(t, cmd, 2*time.Second)
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 1 {
		t.Fatalf("exit error = %v, output:\n%s", err, output.String())
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("session loss took %s to terminate", elapsed)
	}
	if !strings.Contains(output.String(), "tmux session test-agent disappeared") {
		t.Fatalf("missing sanitized session-loss diagnostic:\n%s", output.String())
	}
}

func TestAgentSessionSupervisorIntentionalTERMExitsZeroDuringSessionLoss(t *testing.T) {
	harness := newSessionSupervisorHarness(t)
	cmd, output := harness.start(t)
	waitForFile(t, harness.observed, time.Second)

	if err := os.Remove(harness.sessionState); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := waitForSupervisor(t, cmd, 2*time.Second); err != nil {
		t.Fatalf("intentional TERM failed: %v\n%s", err, output.String())
	}
	if strings.Contains(output.String(), "disappeared") {
		t.Fatalf("intentional shutdown was misclassified as session loss:\n%s", output.String())
	}
}

func TestAgentSessionSupervisorTerminationMessageWinsSessionLossRace(t *testing.T) {
	harness := newSessionSupervisorHarness(t)
	cmd, output := harness.start(t)
	waitForFile(t, harness.observed, time.Second)

	if err := os.WriteFile(harness.termination, []byte("lifecycle complete\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(harness.sessionState); err != nil {
		t.Fatal(err)
	}
	if err := waitForSupervisor(t, cmd, 2*time.Second); err != nil {
		t.Fatalf("termination-message shutdown failed: %v\n%s", err, output.String())
	}
	if strings.Contains(output.String(), "disappeared") {
		t.Fatalf("lifecycle completion was misclassified as session loss:\n%s", output.String())
	}
}

func TestAgentSessionSupervisorKeepsLiveSessionSupervised(t *testing.T) {
	harness := newSessionSupervisorHarness(t)
	cmd, output := harness.start(t)
	waitForFile(t, harness.observed, time.Second)
	time.Sleep(200 * time.Millisecond)

	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("supervisor exited while session was live: %v\n%s", err, output.String())
	}
	checks, err := os.ReadFile(harness.observed)
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(string(checks), "check\n"); count < 3 {
		t.Fatalf("session was not continuously supervised; checks=%d", count)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := waitForSupervisor(t, cmd, 2*time.Second); err != nil {
		t.Fatalf("stop live supervisor: %v\n%s", err, output.String())
	}
}

func TestRuntimeImageAndEntrypointInstallSessionSupervisor(t *testing.T) {
	root := repoRoot(t)
	dockerfile, err := os.ReadFile(filepath.Join(root, "runtime", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"COPY runtime/core/supervise-agent-session.sh /usr/local/bin/supervise-agent-session",
		"/usr/local/bin/supervise-agent-session",
	} {
		if !strings.Contains(string(dockerfile), fragment) {
			t.Fatalf("runtime Dockerfile missing %q", fragment)
		}
	}
	entrypoint, err := os.ReadFile(filepath.Join(root, "runtime", "core", "entrypoint.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(entrypoint), "supervise-agent-session &") || strings.Contains(string(entrypoint), "tail -f /dev/null") {
		t.Fatalf("entrypoint does not use bounded session supervision:\n%s", entrypoint)
	}
}

func TestEntrypointIntentionalTERMForwardsToAndReapsSupervisor(t *testing.T) {
	f := newFixture(t)
	started := filepath.Join(f.home, "entrypoint-supervisor-started")
	terminated := filepath.Join(f.home, "entrypoint-supervisor-terminated")
	for _, command := range []string{"bootstrap", "export-plugin-tools", "write-agent-instructions", "run-plugins", "agentd", "start-code-server", "start-agent-session"} {
		f.writeBin(command, "#!/usr/bin/env bash\nexit 0\n")
	}
	f.writeBin("supervise-agent-session", `#!/usr/bin/env bash
set -u
trap 'touch "$NVT_TEST_SUPERVISOR_TERMINATED"; exit 0' TERM INT
touch "$NVT_TEST_SUPERVISOR_STARTED"
while true; do
  sleep 0.05
done
`)

	cmd := exec.Command("bash", filepath.Join(f.root, "runtime", "core", "entrypoint.sh"))
	cmd.Env = mergedEnv(append(f.env(),
		"NVT_TEST_SUPERVISOR_STARTED="+started,
		"NVT_TEST_SUPERVISOR_TERMINATED="+terminated,
		"NVT_AGENT_CONFIG_FILE="+filepath.Join(f.home, "agent.yaml"),
	))
	output := &bytes.Buffer{}
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFile(t, started, time.Second)
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := waitForSupervisor(t, cmd, 2*time.Second); err != nil {
		t.Fatalf("entrypoint TERM failed: %v\n%s", err, output.String())
	}
	if _, err := os.Stat(terminated); err != nil {
		t.Fatalf("entrypoint did not terminate and reap supervisor: %v", err)
	}
}

type sessionSupervisorHarness struct {
	script       string
	path         string
	sessionState string
	observed     string
	termination  string
}

func newSessionSupervisorHarness(t *testing.T) sessionSupervisorHarness {
	t.Helper()
	f := newFixture(t)
	sessionState := filepath.Join(f.home, "session-live")
	observed := filepath.Join(f.home, "session-checks")
	if err := os.WriteFile(sessionState, []byte("live\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.writeBin("tmux", `#!/usr/bin/env bash
if [ "$1" != "has-session" ] || [ "$2" != "-t" ] || [ "$3" != "test-agent" ]; then
  exit 2
fi
printf 'check\n' >> "$NVT_TEST_SESSION_OBSERVED"
[ -f "$NVT_TEST_SESSION_STATE" ]
`)
	return sessionSupervisorHarness{
		script:       filepath.Join(f.root, "runtime", "core", "supervise-agent-session.sh"),
		path:         f.pathPrefix + string(os.PathListSeparator) + os.Getenv("PATH"),
		sessionState: sessionState,
		observed:     observed,
		termination:  filepath.Join(f.home, "termination-log"),
	}
}

func (h sessionSupervisorHarness) start(t *testing.T) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	cmd := exec.Command("bash", h.script)
	cmd.Env = mergedEnv([]string{
		"PATH=" + h.path,
		"AGENT_SESSION=test-agent",
		"NVT_AGENT_SESSION_SUPERVISOR_INTERVAL_SECONDS=0.03",
		"NVT_TERMINATION_MESSAGE_PATH=" + h.termination,
		"NVT_TEST_SESSION_STATE=" + h.sessionState,
		"NVT_TEST_SESSION_OBSERVED=" + h.observed,
	})
	output := &bytes.Buffer{}
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			_ = cmd.Wait()
		}
	})
	return cmd, output
}

func waitForSupervisor(t *testing.T, cmd *exec.Cmd, timeout time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("timed out waiting for session supervisor")
		return nil
	}
}
