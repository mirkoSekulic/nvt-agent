package runtime_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func codeServerTasksPath(f *fixture) string {
	return filepath.Join(f.home, ".local", "share", "code-server", "User", "tasks.json")
}

func readCodeServerTasks(t *testing.T, f *fixture) map[string]any {
	t.Helper()
	var tasks map[string]any
	decodeJSONFile(t, codeServerTasksPath(f), &tasks)
	return tasks
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
			if _, err := os.Stat(codeServerTasksPath(f)); !os.IsNotExist(err) {
				t.Fatalf("invalid config mutated tasks, stat err=%v", err)
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
		tasksBefore := []byte("{\n  \"version\": \"2.0.0\",\n  \"tasks\": [not valid JSON on purpose]\n}\n")
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

func TestCodeServerAgentTerminalMergesIdempotentlyAndCleansUp(t *testing.T) {
	f := newFixture(t)
	userDir := filepath.Dir(codeServerSettingsPath(f))
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(codeServerSettingsPath(f), []byte(`{
  // Existing user settings are JSON-with-comments.
  "editor.fontSize": 15,
  "task.allowAutomaticTasks": "off",
}
`), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(codeServerTasksPath(f), []byte(`{
  "version": "2.0.0",
  "windows": {"options": {"shell": {"executable": "pwsh"}}},
  "tasks": [
    {"label": "User task", "type": "shell", "command": "true"},
    {"label": "NVT: Agent Session", "type": "shell", "command": "obsolete-command"}
  ]
}
`), 0o640); err != nil {
		t.Fatal(err)
	}
	enabled := f.writeAgentConfig(`
code-server:
  agentTerminal:
    openOnStartup: true
`)

	f.runWithEnv(bootstrapBin(f.root), true, nil, enabled)
	settings := readCodeServerSettings(t, f)
	if settings["editor.fontSize"] != float64(15) || settings["task.allowAutomaticTasks"] != "on" {
		t.Fatalf("managed settings did not preserve user values: %#v", settings)
	}
	for key := range settings {
		if strings.Contains(key, "terminal.integrated.defaultProfile") {
			t.Fatalf("agent terminal became a manual-terminal default: %#v", settings)
		}
	}
	tasks := readCodeServerTasks(t, f)
	if _, ok := tasks["windows"]; !ok {
		t.Fatalf("unrelated top-level task configuration was removed: %#v", tasks)
	}
	entries, ok := tasks["tasks"].([]any)
	if !ok || len(entries) != 2 {
		t.Fatalf("expected user and managed tasks: %#v", tasks)
	}
	managed, ok := entries[1].(map[string]any)
	if !ok {
		t.Fatalf("managed task is not an object: %#v", entries[1])
	}
	if managed["label"] != "NVT: Agent Session" || managed["type"] != "process" || managed["command"] != "nvt-session-attach" {
		t.Fatalf("unexpected managed task identity: %#v", managed)
	}
	runOptions, _ := managed["runOptions"].(map[string]any)
	if runOptions["runOn"] != "folderOpen" || runOptions["instanceLimit"] != float64(1) {
		t.Fatalf("managed task is not bounded to one folder-open instance: %#v", managed)
	}
	presentation, _ := managed["presentation"].(map[string]any)
	if presentation["panel"] != "dedicated" || presentation["focus"] != true || presentation["reveal"] != "always" {
		t.Fatalf("managed task does not use a focused dedicated terminal: %#v", managed)
	}

	firstSettings, _ := os.ReadFile(codeServerSettingsPath(f))
	firstTasks, _ := os.ReadFile(codeServerTasksPath(f))
	f.runWithEnv(bootstrapBin(f.root), true, nil, enabled)
	secondSettings, _ := os.ReadFile(codeServerSettingsPath(f))
	secondTasks, _ := os.ReadFile(codeServerTasksPath(f))
	if string(firstSettings) != string(secondSettings) || string(firstTasks) != string(secondTasks) {
		t.Fatalf("re-running bootstrap did not update managed state idempotently")
	}

	disabled := f.writeAgentConfig("code-server:\n  agentTerminal:\n    openOnStartup: false\n")
	f.runWithEnv(bootstrapBin(f.root), true, nil, disabled)
	settings = readCodeServerSettings(t, f)
	if settings["editor.fontSize"] != float64(15) || settings["task.allowAutomaticTasks"] != "off" {
		t.Fatalf("disable did not restore the prior user setting: %#v", settings)
	}
	tasks = readCodeServerTasks(t, f)
	entries, _ = tasks["tasks"].([]any)
	if len(entries) != 1 || entries[0].(map[string]any)["label"] != "User task" {
		t.Fatalf("disable did not remove only the managed task: %#v", tasks)
	}
	if _, err := os.Stat(filepath.Join(f.state, "code-server-agent-terminal.json")); !os.IsNotExist(err) {
		t.Fatalf("managed ownership state remained after disable, stat err=%v", err)
	}
}

func TestCodeServerAgentTerminalDisableRemovesFilesItOwnsOnly(t *testing.T) {
	f := newFixture(t)
	enabled := f.writeAgentConfig("code-server:\n  agentTerminal:\n    openOnStartup: true\n")
	f.runWithEnv(bootstrapBin(f.root), true, nil, enabled)

	disabled := f.writeAgentConfig("code-server: {}\n")
	f.runWithEnv(bootstrapBin(f.root), true, nil, disabled)
	if _, err := os.Stat(codeServerTasksPath(f)); !os.IsNotExist(err) {
		t.Fatalf("bootstrap-created tasks.json survived disable, stat err=%v", err)
	}
	settings := readCodeServerSettings(t, f)
	if len(settings) != 0 {
		t.Fatalf("managed automatic-task setting survived disable: %#v", settings)
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

func TestRuntimeImageInstallsSessionAttachHelper(t *testing.T) {
	root := repoRoot(t)
	dockerfile, err := os.ReadFile(filepath.Join(root, "runtime", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"COPY runtime/core/nvt-session-attach.sh /usr/local/bin/nvt-session-attach",
		"/usr/local/bin/nvt-session-attach",
	} {
		if !strings.Contains(string(dockerfile), fragment) {
			t.Fatalf("runtime Dockerfile missing %q", fragment)
		}
	}

	// The task contract is pure JSON and contains no tmux implementation detail.
	bootstrap, err := os.ReadFile(filepath.Join(root, "runtime", "core", "bootstrap.py"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bootstrap), "tmux attach") || strings.Contains(string(bootstrap), "attach-session") {
		t.Fatalf("code-server bootstrap contains a tmux-specific attach implementation")
	}
}

func TestManagedTaskJSONRoundTripsStrictly(t *testing.T) {
	// Keep encoding/json imported here so malformed managed task output cannot
	// accidentally be hidden by the more permissive code-server JSONC reader.
	f := newFixture(t)
	config := f.writeAgentConfig("code-server:\n  agentTerminal:\n    openOnStartup: true\n")
	f.runWithEnv(bootstrapBin(f.root), true, nil, config)
	data, err := os.ReadFile(codeServerTasksPath(f))
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("managed tasks.json is not strict JSON: %v", err)
	}
}
