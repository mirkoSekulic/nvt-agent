package runtime_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func codeServerTasksPath(f *fixture) string {
	return filepath.Join(f.home, ".local", "share", "code-server", "User", "tasks.json")
}

func TestCodeServerAgentTerminalConfigValidation(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "null-object",
			body: "code-server:\n  agentTerminal: null\n",
			want: "code-server.agentTerminal must be a YAML object",
		},
		{
			name: "array-object",
			body: "code-server:\n  agentTerminal: []\n",
			want: "code-server.agentTerminal must be a YAML object",
		},
		{
			name: "non-boolean-open",
			body: "code-server:\n  agentTerminal:\n    openOnStartup: yes please\n",
			want: "code-server.agentTerminal.openOnStartup must be a boolean",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			config := f.writeAgentConfig(tt.body)
			output := f.runWithEnv(bootstrapBin(f.root), false, nil, config)
			if !strings.Contains(output, tt.want) {
				t.Fatalf("expected %q, got:\n%s", tt.want, output)
			}
			if _, err := os.Stat(codeServerSettingsPath(f)); !os.IsNotExist(err) {
				t.Fatalf("invalid config mutated settings, stat err=%v", err)
			}
		})
	}
}

func TestCodeServerAgentTerminalOmittedAndDisabledAreNoOps(t *testing.T) {
	for _, body := range []string{
		"code-server: {}\n",
		"code-server:\n  agentTerminal:\n    openOnStartup: false\n",
	} {
		f := newFixture(t)
		userDir := filepath.Dir(codeServerSettingsPath(f))
		if err := os.MkdirAll(userDir, 0o755); err != nil {
			t.Fatal(err)
		}
		settingsBefore := []byte("{\n  // user-owned JSONC\n  \"editor.fontSize\": 15,\n}\n")
		tasksBefore := []byte("{\n  \"tasks\": [not valid JSON on purpose]\n}\n")
		if err := os.WriteFile(codeServerSettingsPath(f), settingsBefore, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(codeServerTasksPath(f), tasksBefore, 0o640); err != nil {
			t.Fatal(err)
		}

		config := f.writeAgentConfig(body)
		f.runWithEnv(bootstrapBin(f.root), true, nil, config)

		settingsAfter, err := os.ReadFile(codeServerSettingsPath(f))
		if err != nil {
			t.Fatal(err)
		}
		tasksAfter, err := os.ReadFile(codeServerTasksPath(f))
		if err != nil {
			t.Fatal(err)
		}
		if string(settingsAfter) != string(settingsBefore) || string(tasksAfter) != string(tasksBefore) {
			t.Fatalf("disabled/omitted config changed existing code-server files")
		}
	}
}

func TestCodeServerAgentTerminalUsesOwnedMarkerAndNeverMutatesSettingsOrTasks(t *testing.T) {
	f := newFixture(t)
	userDir := filepath.Dir(codeServerSettingsPath(f))
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(codeServerSettingsPath(f), []byte(`{
  // Existing user settings are JSON-with-comments.
  "editor.fontSize": 15,
  "task.allowAutomaticTasks": "off",
  "nvtAgent.agentTerminal.openOnStartup": "unrelated-user-value",
}
`), 0o640); err != nil {
		t.Fatal(err)
	}
	// A repository or user task with the old display label is entirely
	// unrelated to the bundled extension and must survive byte-for-byte.
	tasksBefore := []byte(`{
  "version": "2.0.0",
  "tasks": [
    {"label": "User task", "type": "shell", "command": "true"},
    {"label": "NVT: Agent Session", "type": "shell", "command": "user-command"},
    {"label": "Repository folder-open task", "runOptions": {"runOn": "folderOpen"}, "command": "never-authorize-me"}
  ]
}
`)
	if err := os.WriteFile(codeServerTasksPath(f), tasksBefore, 0o640); err != nil {
		t.Fatal(err)
	}
	settingsBefore, err := os.ReadFile(codeServerSettingsPath(f))
	if err != nil {
		t.Fatal(err)
	}
	workspaceSettings := filepath.Join(f.workspace, ".vscode", "settings.json")
	if err := os.MkdirAll(filepath.Dir(workspaceSettings), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workspaceSettings, []byte(`{"nvtAgent.agentTerminal.openOnStartup":true}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	enabled := f.writeAgentConfig(`
code-server:
  agentTerminal:
    openOnStartup: true
`)

	f.runWithEnv(bootstrapBin(f.root), true, nil, enabled)
	settingsAfterEnable, err := os.ReadFile(codeServerSettingsPath(f))
	if err != nil {
		t.Fatal(err)
	}
	if string(settingsAfterEnable) != string(settingsBefore) {
		t.Fatalf("enable changed user settings:\n%s", settingsAfterEnable)
	}
	tasksAfterEnable, err := os.ReadFile(codeServerTasksPath(f))
	if err != nil {
		t.Fatal(err)
	}
	if string(tasksAfterEnable) != string(tasksBefore) {
		t.Fatalf("enable changed user/repository tasks:\n%s", tasksAfterEnable)
	}
	workspaceSettingsAfter, err := os.ReadFile(workspaceSettings)
	if err != nil {
		t.Fatal(err)
	}
	if string(workspaceSettingsAfter) != `{"nvtAgent.agentTerminal.openOnStartup":true}`+"\n" {
		t.Fatalf("enable changed repository workspace settings: %s", workspaceSettingsAfter)
	}
	marker := filepath.Join(f.state, "code-server-agent-terminal-enabled")
	markerContent, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if string(markerContent) != "enabled\n" {
		t.Fatalf("unexpected enable marker: %q", markerContent)
	}
	markerInfo, err := os.Stat(marker)
	if err != nil {
		t.Fatal(err)
	}
	if markerInfo.Mode().Perm() != 0o600 {
		t.Fatalf("enable marker mode is %o, want 0600", markerInfo.Mode().Perm())
	}

	f.runWithEnv(bootstrapBin(f.root), true, nil, enabled)
	markerContent, err = os.ReadFile(marker)
	if err != nil || string(markerContent) != "enabled\n" {
		t.Fatalf("re-running bootstrap did not update the marker idempotently: %q, %v", markerContent, err)
	}

	disabled := f.writeAgentConfig("code-server:\n  agentTerminal:\n    openOnStartup: false\n")
	f.runWithEnv(bootstrapBin(f.root), true, nil, disabled)
	settingsAfterDisable, err := os.ReadFile(codeServerSettingsPath(f))
	if err != nil {
		t.Fatal(err)
	}
	if string(settingsAfterDisable) != string(settingsBefore) {
		t.Fatalf("disable changed user settings:\n%s", settingsAfterDisable)
	}
	tasksAfterDisable, err := os.ReadFile(codeServerTasksPath(f))
	if err != nil {
		t.Fatal(err)
	}
	if string(tasksAfterDisable) != string(tasksBefore) {
		t.Fatalf("disable changed user/repository tasks:\n%s", tasksAfterDisable)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("managed enable marker remained after disable, stat err=%v", err)
	}
}

func TestCodeServerAgentTerminalOmissionCleansPreviousOwnedMarkerOnly(t *testing.T) {
	f := newFixture(t)
	enabled := f.writeAgentConfig("code-server:\n  agentTerminal:\n    openOnStartup: true\n")
	f.runWithEnv(bootstrapBin(f.root), true, nil, enabled)
	disabled := f.writeAgentConfig("code-server: {}\n")
	f.runWithEnv(bootstrapBin(f.root), true, nil, disabled)
	if _, err := os.Stat(filepath.Join(f.state, "code-server-agent-terminal-enabled")); !os.IsNotExist(err) {
		t.Fatalf("omission did not remove the owned marker, stat err=%v", err)
	}
}

func TestSessionAttachUsesExistingSessionAndNeverCreatesOne(t *testing.T) {
	f := newFixture(t)
	logPath := filepath.Join(f.home, "tmux-calls")
	f.writeBin("tmux", `#!/usr/bin/env bash
printf '%s\n' "$*" >> "$NVT_TEST_TMUX_CALLS"
case "$1" in
  has-session) exit 0 ;;
  attach-session) exit 0 ;;
  *) exit 90 ;;
esac
`)
	helper := "bash " + shellQuote(filepath.Join(f.root, "runtime", "core", "nvt-session-attach.sh"))
	f.runWithEnv(helper, true, []string{
		"AGENT_SESSION=custom-agent",
		"NVT_SESSION_ATTACH_WAIT_SECONDS=2",
		"NVT_TEST_TMUX_CALLS=" + logPath,
	})
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(calls) != "has-session -t custom-agent\nattach-session -t custom-agent\n" || strings.Contains(string(calls), "new-session") {
		t.Fatalf("helper did not attach only to the existing session:\n%s", calls)
	}
}

func TestSessionAttachWaitsForDelayedSession(t *testing.T) {
	f := newFixture(t)
	counter := filepath.Join(f.home, "tmux-count")
	attached := filepath.Join(f.home, "tmux-attached")
	f.writeBin("tmux", `#!/usr/bin/env bash
if [ "$1" = "has-session" ]; then
  count=0
  [ ! -f "$NVT_TEST_COUNT" ] || count="$(cat "$NVT_TEST_COUNT")"
  count=$((count + 1))
  printf '%s' "$count" > "$NVT_TEST_COUNT"
  [ "$count" -ge 2 ]
  exit
fi
if [ "$1" = "attach-session" ]; then
  touch "$NVT_TEST_ATTACHED"
  exit 0
fi
exit 90
`)
	helper := "bash " + shellQuote(filepath.Join(f.root, "runtime", "core", "nvt-session-attach.sh"))
	f.runWithEnv(helper, true, []string{
		"NVT_SESSION_ATTACH_WAIT_SECONDS=3",
		"NVT_TEST_COUNT=" + counter,
		"NVT_TEST_ATTACHED=" + attached,
	})
	count, _ := os.ReadFile(counter)
	if string(count) != "2" {
		t.Fatalf("helper did not wait for delayed availability, attempts=%q", count)
	}
	if _, err := os.Stat(attached); err != nil {
		t.Fatalf("helper did not attach after availability: %v", err)
	}
}

func TestSessionAttachFailsBoundedlyWithoutCreatingSession(t *testing.T) {
	f := newFixture(t)
	logPath := filepath.Join(f.home, "tmux-calls")
	f.writeBin("tmux", `#!/usr/bin/env bash
printf '%s\n' "$*" >> "$NVT_TEST_TMUX_CALLS"
[ "$1" != "has-session" ] && exit 90
exit 1
`)
	helper := "bash " + shellQuote(filepath.Join(f.root, "runtime", "core", "nvt-session-attach.sh"))
	output := f.runWithEnv(helper, false, []string{
		"NVT_SESSION_ATTACH_WAIT_SECONDS=1",
		"NVT_TEST_TMUX_CALLS=" + logPath,
	})
	if !strings.Contains(output, "agent session agent was not available within 1s") {
		t.Fatalf("missing bounded timeout diagnostic:\n%s", output)
	}
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(calls), "new-session") || strings.Contains(string(calls), "attach-session") {
		t.Fatalf("missing-session path created or attached a session:\n%s", calls)
	}
}

func TestRuntimeImageInstallsSessionAttachBoundaryAndExtension(t *testing.T) {
	root := repoRoot(t)
	dockerfile, err := os.ReadFile(filepath.Join(root, "runtime", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"COPY runtime/code-server-agent-terminal /tmp/nvt-code-server-agent-terminal",
		"/tmp/nvt-code-server-agent-terminal/install.sh",
		"COPY runtime/core/nvt-session-attach.sh /usr/local/bin/nvt-session-attach",
		"/usr/local/bin/nvt-session-attach",
	} {
		if !strings.Contains(string(dockerfile), fragment) {
			t.Fatalf("runtime Dockerfile missing %q", fragment)
		}
	}

	bootstrap, err := os.ReadFile(filepath.Join(root, "runtime", "core", "bootstrap.py"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"task.allowAutomaticTasks", "tasks.json", "attach-session"} {
		if strings.Contains(string(bootstrap), forbidden) {
			t.Fatalf("code-server bootstrap contains forbidden task/backend behavior %q", forbidden)
		}
	}
}
