package runtime_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRuntimeResumeFreshThenPersistentRestart(t *testing.T) {
	f := newFixture(t)
	invocations := filepath.Join(f.home, "session-invocations.jsonl")
	fresh := writeSessionFixture(t, f, "fresh-session", "fresh")
	resume := writeSessionFixture(t, f, "resume-session", "resume")
	config := f.writeAgentConfig(fmt.Sprintf(`
runtime:
  command: %s
  args: [--fresh-flag]
  initial-prompt:
    delivery: argument
    text: perform the initial task
  resume:
    command: %s
    args: [--resume-flag]
`, quoteYAML(fresh), quoteYAML(resume)))
	f.runWithEnv(bootstrapBin(f.root), true, nil, config)

	harness := newRuntimeSessionHarness(t, f, invocations)
	harness.start(true)
	harness.stop()
	harness.start(true)

	got := readSessionInvocations(t, invocations)
	want := [][]string{
		{"fresh", "--fresh-flag", "perform the initial task"},
		{"resume", "--resume-flag"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected fresh/restart invocations:\ngot  %#v\nwant %#v", got, want)
	}

	marker := filepath.Join(f.state, "runtime-session.json")
	var state map[string]any
	decodeJSONFile(t, marker, &state)
	if !reflect.DeepEqual(state, map[string]any{"state": "resumable", "version": float64(1)}) {
		t.Fatalf("unexpected durable resume marker: %#v", state)
	}
	info, err := os.Stat(marker)
	if err != nil {
		t.Fatal(err)
	}
	if gotMode := info.Mode().Perm(); gotMode != 0o600 {
		t.Fatalf("resume marker mode = %04o, want 0600", gotMode)
	}
	matches, err := filepath.Glob(filepath.Join(f.state, ".runtime-session.json.*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("atomic marker write left temporary files: %v", matches)
	}
}

func TestRuntimeWithoutResumeRetainsFreshRestartBehavior(t *testing.T) {
	f := newFixture(t)
	invocations := filepath.Join(f.home, "legacy-invocations.jsonl")
	fresh := writeSessionFixture(t, f, "legacy-session", "fresh")
	config := f.writeAgentConfig(fmt.Sprintf(`
runtime:
  command: %s
  args: [--existing-flag]
  initial-prompt:
    delivery: argument
    text: existing initial task
`, quoteYAML(fresh)))
	f.runWithEnv(bootstrapBin(f.root), true, nil, config)

	harness := newRuntimeSessionHarness(t, f, invocations)
	harness.start(true)
	harness.stop()
	harness.start(true)

	wantInvocation := []string{"fresh", "--existing-flag", "existing initial task"}
	got := readSessionInvocations(t, invocations)
	if !reflect.DeepEqual(got, [][]string{wantInvocation, wantInvocation}) {
		t.Fatalf("runtime.resume omission changed existing restart behavior: %#v", got)
	}
	if _, err := os.Stat(filepath.Join(f.state, "runtime-session.json")); !os.IsNotExist(err) {
		t.Fatalf("runtime without resume created a resume marker, stat error = %v", err)
	}
}

func TestRuntimeResumeFailureNeverFallsBackToFresh(t *testing.T) {
	f := newFixture(t)
	freshCalled := filepath.Join(f.home, "fresh-called")
	resumeCalled := filepath.Join(f.home, "resume-called")
	fresh := f.writeBin("fresh-must-not-run", fmt.Sprintf("#!/usr/bin/env bash\ntouch %s\nexec sleep 30\n", shellQuote(freshCalled)))
	resume := f.writeBin("failing-resume", fmt.Sprintf("#!/usr/bin/env bash\ntouch %s\nexit 23\n", shellQuote(resumeCalled)))
	config := f.writeAgentConfig(fmt.Sprintf(`
runtime:
  command: %s
  initial-prompt:
    delivery: argument
    text: do not replay this task
  resume:
    command: %s
`, quoteYAML(fresh), quoteYAML(resume)))
	f.runWithEnv(bootstrapBin(f.root), true, nil, config)
	marker := filepath.Join(f.state, "runtime-session.json")
	if err := os.WriteFile(marker, []byte("{\"state\":\"resumable\",\"version\":1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	harness := newRuntimeSessionHarness(t, f, filepath.Join(f.home, "unused.jsonl"))
	output := harness.start(false)
	if !strings.Contains(output, "resume command failed after 1 attempts") {
		t.Fatalf("resume failure was not loud:\n%s", output)
	}
	if _, err := os.Stat(resumeCalled); err != nil {
		t.Fatalf("resume command was not attempted: %v\n%s", err, output)
	}
	if _, err := os.Stat(freshCalled); !os.IsNotExist(err) {
		t.Fatalf("failed resume fell back to fresh command, stat error = %v", err)
	}
}

func TestFailedInitialLaunchDoesNotSelectResume(t *testing.T) {
	f := newFixture(t)
	invocations := filepath.Join(f.home, "failed-fresh-invocations.jsonl")
	allowFresh := filepath.Join(f.home, "allow-fresh")
	fresh := f.writeBin("sometimes-failing-fresh", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
python3 - "$NVT_TEST_INVOCATIONS" fresh "$@" <<'PY'
import json
import sys

with open(sys.argv[1], "a", encoding="utf-8") as handle:
    handle.write(json.dumps(sys.argv[2:], separators=(",", ":")) + "\n")
PY
if [ ! -f %s ]; then
  exit 19
fi
exec sleep 30
`, shellQuote(allowFresh)))
	resumeCalled := filepath.Join(f.home, "resume-called")
	resume := f.writeBin("resume-must-not-run", fmt.Sprintf("#!/usr/bin/env bash\ntouch %s\nexec sleep 30\n", shellQuote(resumeCalled)))
	config := f.writeAgentConfig(fmt.Sprintf(`
runtime:
  command: %s
  initial-prompt:
    delivery: argument
    text: at-most-once task
  resume:
    command: %s
`, quoteYAML(fresh), quoteYAML(resume)))
	f.runWithEnv(bootstrapBin(f.root), true, nil, config)
	harness := newRuntimeSessionHarness(t, f, invocations)
	output := harness.start(false)
	if !strings.Contains(output, "fresh command failed after 1 attempts") {
		t.Fatalf("failed fresh launch was not loud:\n%s", output)
	}
	marker := filepath.Join(f.state, "runtime-session.json")
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("failed fresh launch created resume marker, stat error = %v", err)
	}

	if err := os.WriteFile(allowFresh, []byte("continue\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	harness.start(true)
	got := readSessionInvocations(t, invocations)
	want := [][]string{{"fresh", "at-most-once task"}, {"fresh", "at-most-once task"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("failed initial launch selected the wrong next command: got %#v want %#v", got, want)
	}
	if _, err := os.Stat(resumeCalled); !os.IsNotExist(err) {
		t.Fatalf("failed initial launch selected resume, stat error = %v", err)
	}
}

func TestBootstrapRejectsMalformedRuntimeResume(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		message string
	}{
		{
			name:    "not object",
			config:  "runtime:\n  command: generic-fresh\n  resume: generic-resume\n",
			message: "runtime.resume must be a YAML object",
		},
		{
			name:    "missing command",
			config:  "runtime:\n  command: generic-fresh\n  resume:\n    args: []\n",
			message: "runtime.resume.command must be a non-empty string",
		},
		{
			name:    "empty command",
			config:  "runtime:\n  command: generic-fresh\n  resume:\n    command: '   '\n",
			message: "runtime.resume.command must be a non-empty string",
		},
		{
			name:    "args not strings",
			config:  "runtime:\n  command: generic-fresh\n  resume:\n    command: generic-resume\n    args: [valid, 7]\n",
			message: "runtime.resume.args must be a list of strings",
		},
		{
			name:    "unsupported field",
			config:  "runtime:\n  command: generic-fresh\n  resume:\n    command: generic-resume\n    discover: latest\n",
			message: "runtime.resume has unsupported fields: discover",
		},
		{
			name:    "fresh command required",
			config:  "runtime:\n  resume:\n    command: generic-resume\n",
			message: "runtime.command is required when runtime.resume is configured",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			config := f.writeAgentConfig(test.config)
			output := f.runWithEnv(bootstrapBin(f.root), false, nil, config)
			if !strings.Contains(output, test.message) {
				t.Fatalf("expected %q, got:\n%s", test.message, output)
			}
		})
	}
}

func TestRuntimeImageAndEntrypointWireGenericResumeComponents(t *testing.T) {
	root := repoRoot(t)
	dockerfile, err := os.ReadFile(filepath.Join(root, "runtime", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"COPY runtime/core/session-resume-state.py /usr/local/bin/session-resume-state",
		"/usr/local/bin/session-resume-state",
	} {
		if !strings.Contains(string(dockerfile), fragment) {
			t.Fatalf("runtime Dockerfile missing %q", fragment)
		}
	}

	entrypoint, err := os.ReadFile(filepath.Join(root, "runtime", "core", "entrypoint.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		`session-resume-state configured "$agent_command_file"`,
		`$NVT_STATE_DIR/agentd/prompt-queue`,
	} {
		if !strings.Contains(string(entrypoint), fragment) {
			t.Fatalf("runtime entrypoint missing %q", fragment)
		}
	}
}

type runtimeSessionHarness struct {
	t           *testing.T
	f           *fixture
	session     string
	tmuxDir     string
	invocations string
	env         []string
}

func newRuntimeSessionHarness(t *testing.T, f *fixture, invocations string) *runtimeSessionHarness {
	t.Helper()
	envPath := filepath.Join(f.home, ".nvt-agent", "env")
	envContents, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	envContents = append(envContents, []byte("export NVT_TEST_INVOCATIONS="+shellQuote(invocations)+"\n")...)
	if err := os.WriteFile(envPath, envContents, 0o600); err != nil {
		t.Fatal(err)
	}
	// The production HOME matches the runtime user's passwd entry. The fixture
	// uses an isolated synthetic HOME, so keep it when the launcher requests a
	// login shell inside tmux.
	testShell := f.writeBin("test-session-shell", fmt.Sprintf(`#!/bin/sh
export HOME=%s
if [ "${1:-}" = "-lc" ]; then
  shift
  exec /bin/bash -c "$@"
fi
exec /bin/bash "$@"
`, shellQuote(f.home)))
	tmuxDir := filepath.Join(f.home, "tmux")
	if err := os.MkdirAll(tmuxDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sessionExec := f.writeBin("generic-session-exec", fmt.Sprintf(
		"#!/usr/bin/env bash\nexec python3 %s \"$@\" >> %s 2>&1\n",
		shellQuote(filepath.Join(f.root, "runtime", "core", "start-agent-session.py")),
		shellQuote(invocations+".session.log"),
	))
	stateCommand := f.writeBin("generic-resume-state", fmt.Sprintf(
		"#!/usr/bin/env bash\nexec python3 %s \"$@\"\n",
		shellQuote(filepath.Join(f.root, "runtime", "core", "session-resume-state.py")),
	))
	harness := &runtimeSessionHarness{
		t:           t,
		f:           f,
		session:     "nvt-resume-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")),
		tmuxDir:     tmuxDir,
		invocations: invocations,
		env: []string{
			"TMUX_TMPDIR=" + tmuxDir,
			"AGENT_SESSION=" + "nvt-resume-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")),
			"NVT_TEST_INVOCATIONS=" + invocations,
			"NVT_AGENT_SESSION_EXEC=" + sessionExec,
			"NVT_AGENT_SESSION_SHELL=" + testShell,
			"NVT_AGENT_SESSION_RESUME_STATE_COMMAND=" + stateCommand,
			"NVT_AGENT_SESSION_FAST_EXIT_SECONDS=0.15",
			"NVT_AGENT_SESSION_MAX_START_ATTEMPTS=1",
		},
	}
	t.Cleanup(func() { harness.stop() })
	return harness
}

func (h *runtimeSessionHarness) start(wantOK bool) string {
	h.t.Helper()
	cmd := exec.Command("bash", filepath.Join(h.f.root, "runtime", "core", "start-agent-session.sh"))
	cmd.Env = mergedEnv(append(h.f.env(), h.env...))
	output, err := cmd.CombinedOutput()
	if wantOK && err != nil {
		sessionOutput, _ := os.ReadFile(h.invocations + ".session.log")
		h.t.Fatalf("start agent session: %v\n%s\nsession output:\n%s", err, output, sessionOutput)
	}
	if !wantOK && err == nil {
		h.t.Fatalf("start agent session unexpectedly succeeded:\n%s", output)
	}
	return string(output)
}

func (h *runtimeSessionHarness) stop() {
	h.t.Helper()
	cmd := exec.Command("tmux", "kill-session", "-t", h.session)
	cmd.Env = mergedEnv(append(h.f.env(), h.env...))
	_ = cmd.Run()
}

func writeSessionFixture(t *testing.T, f *fixture, name, mode string) string {
	t.Helper()
	return f.writeBin(name, fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
python3 - "$NVT_TEST_INVOCATIONS" %s "$@" <<'PY'
import json
import sys

with open(sys.argv[1], "a", encoding="utf-8") as handle:
    handle.write(json.dumps(sys.argv[2:], separators=(",", ":")) + "\n")
PY
exec sleep 30
`, shellQuote(mode)))
}

func readSessionInvocations(t *testing.T, path string) [][]string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var invocations [][]string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var invocation []string
		if err := json.Unmarshal(scanner.Bytes(), &invocation); err != nil {
			t.Fatalf("decode invocation %q: %v", scanner.Bytes(), err)
		}
		invocations = append(invocations, invocation)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return invocations
}
