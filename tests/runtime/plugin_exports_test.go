package runtime_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	t          *testing.T
	root       string
	home       string
	state      string
	workspace  string
	bin        string
	pathPrefix string
}

func TestExportedToolWrapperInjectsContextAndConfig(t *testing.T) {
	f := newFixture(t)
	toolCommand := f.writeTool("ctx-tool-impl", `#!/usr/bin/env bash
set -euo pipefail
python3 - <<'PY'
import json
import os
import yaml

with open(os.environ["NVT_PLUGIN_CONFIG"], "r", encoding="utf-8") as file:
    config = yaml.safe_load(file)

print(json.dumps({
    "name": os.environ["NVT_PLUGIN_NAME"],
    "workspace": os.environ["NVT_WORKSPACE"],
    "config": config,
}, sort_keys=True))
PY
`)
	config := f.writeAgentConfig(fmt.Sprintf(`
plugins:
  - name: context-plugin
    source: custom
    config:
      message: hello
      nested:
        ok: true
    exports:
      tools:
        - name: context-tool
          command: %s
          description: Context test tool
`, quoteYAML(toolCommand)))

	f.runExport(config, true)
	output := f.runCommand("context-tool", true)
	var value map[string]any
	decodeJSON(t, []byte(output), &value)

	if value["name"] != "context-plugin" {
		t.Fatalf("wrong plugin name: %#v", value)
	}
	if value["workspace"] != f.workspace {
		t.Fatalf("wrong workspace: %#v", value)
	}
	configValue, ok := value["config"].(map[string]any)
	if !ok || configValue["message"] != "hello" {
		t.Fatalf("config did not round-trip: %#v", value)
	}
}

func TestStaleManagedWrappersRemovedAndUnmanagedFilesSurvive(t *testing.T) {
	f := newFixture(t)
	firstCommand := f.writeTool("first-impl", "#!/usr/bin/env bash\necho first\n")
	firstConfig := f.writeAgentConfig(fmt.Sprintf(`
plugins:
  - name: first-plugin
    source: custom
    exports:
      tools:
        - name: first-tool
          command: %s
`, quoteYAML(firstCommand)))
	f.runExport(firstConfig, true)
	if _, err := os.Stat(filepath.Join(f.home, ".local", "bin", "first-tool")); err != nil {
		t.Fatalf("expected first-tool wrapper: %v", err)
	}

	unmanaged := filepath.Join(f.home, ".local", "bin", "keep-me")
	if err := os.WriteFile(unmanaged, []byte("#!/usr/bin/env bash\necho keep\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	secondCommand := f.writeTool("second-impl", "#!/usr/bin/env bash\necho second\n")
	secondConfig := f.writeAgentConfig(fmt.Sprintf(`
plugins:
  - name: second-plugin
    source: custom
    exports:
      tools:
        - name: second-tool
          command: %s
`, quoteYAML(secondCommand)))
	f.runExport(secondConfig, true)

	if _, err := os.Stat(filepath.Join(f.home, ".local", "bin", "first-tool")); !os.IsNotExist(err) {
		t.Fatalf("expected stale managed wrapper to be removed, stat err=%v", err)
	}
	if _, err := os.Stat(unmanaged); err != nil {
		t.Fatalf("expected unmanaged file to survive: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.home, ".local", "bin", "second-tool")); err != nil {
		t.Fatalf("expected second-tool wrapper: %v", err)
	}
}

func TestExportValidationFailures(t *testing.T) {
	tests := []struct {
		name string
		body func(*fixture) string
	}{
		{
			name: "duplicate",
			body: func(f *fixture) string {
				command := f.writeTool("duplicate-impl", "#!/usr/bin/env bash\ntrue\n")
				return fmt.Sprintf(`
plugins:
  - name: a
    source: custom
    exports:
      tools:
        - name: duplicate-tool
          command: %s
  - name: b
    source: custom
    exports:
      tools:
        - name: duplicate-tool
          command: %s
`, quoteYAML(command), quoteYAML(command))
			},
		},
		{
			name: "protected",
			body: func(f *fixture) string {
				command := f.writeTool("protected-impl", "#!/usr/bin/env bash\ntrue\n")
				return exportConfig("protected-plugin", "agentd", command)
			},
		},
		{
			name: "invalid-name",
			body: func(f *fixture) string {
				command := f.writeTool("invalid-impl", "#!/usr/bin/env bash\ntrue\n")
				return exportConfig("invalid-plugin", "bad name!", command)
			},
		},
		{
			name: "missing-command",
			body: func(f *fixture) string {
				return exportConfig("missing-plugin", "missing-tool", filepath.Join(f.home, "missing"))
			},
		},
		{
			name: "non-executable-command",
			body: func(f *fixture) string {
				command := filepath.Join(f.home, "not-executable")
				if err := os.WriteFile(command, []byte("echo nope\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				return exportConfig("non-executable-plugin", "non-executable-tool", command)
			},
		},
		{
			name: "path-shadowing",
			body: func(f *fixture) string {
				existing := filepath.Join(f.bin, "already-here")
				if err := os.WriteFile(existing, []byte("#!/usr/bin/env bash\ntrue\n"), 0o755); err != nil {
					t.Fatal(err)
				}
				command := f.writeTool("shadow-impl", "#!/usr/bin/env bash\ntrue\n")
				return exportConfig("shadow-plugin", "already-here", command)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			config := f.writeAgentConfig(tt.body(f))
			f.runExport(config, false)
		})
	}
}

func TestToolOnlyPluginRunPluginsSkipsCleanly(t *testing.T) {
	f := newFixture(t)
	toolCommand := f.writeTool("tool-only-impl", "#!/usr/bin/env bash\necho tool-only\n")
	config := f.writeAgentConfig(exportConfig("tool-only", "tool-only", toolCommand))

	f.runExport(config, true)
	f.runRunPlugins(config, "after-agent", true)

	statePath := filepath.Join(f.state, "plugins", "tool-only", "state.json")
	var state map[string]any
	decodeJSONFile(t, statePath, &state)
	if state["status"] != "skipped" || state["ready"] != true {
		t.Fatalf("expected skipped ready state, got %#v", state)
	}
}

func TestAfterAgentPluginsStartConcurrently(t *testing.T) {
	f := newFixture(t)
	firstStarted := filepath.Join(f.home, "first-after-started")
	secondStarted := filepath.Join(f.home, "second-after-started")
	releaseFirst := filepath.Join(f.home, "release-first-after")
	t.Cleanup(func() { _ = os.WriteFile(releaseFirst, []byte("ok\n"), 0o644) })
	firstCommand := f.writeTool("first-after-impl", markerScript(firstStarted, releaseFirst))
	secondCommand := f.writeTool("second-after-impl", markerScript(secondStarted, ""))
	config := f.writeAgentConfig(fmt.Sprintf(`
plugins:
  - name: first-after
    source: custom
    when: after-agent
    command: %s
  - name: second-after
    source: custom
    when: after-agent
    command: %s
`, quoteYAML(firstCommand), quoteYAML(secondCommand)))

	cmd, output := f.startRunPlugins(config, "after-agent", 5*time.Second)
	waitForFile(t, secondStarted, 2*time.Second)
	if _, err := os.Stat(firstStarted); err != nil {
		t.Fatalf("expected first after-agent plugin to start: %v", err)
	}
	if err := os.WriteFile(releaseFirst, []byte("ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("run-plugins after-agent failed: %v\n%s", err, output.String())
	}

	for _, name := range []string{"first-after", "second-after"} {
		var state map[string]any
		decodeJSONFile(t, filepath.Join(f.state, "plugins", name, "state.json"), &state)
		if state["status"] != "succeeded" || state["ready"] != true {
			t.Fatalf("expected succeeded ready state for %s, got %#v", name, state)
		}
	}
}

func TestAfterAgentPluginFailureDoesNotStopOtherPlugins(t *testing.T) {
	f := newFixture(t)
	failingStarted := filepath.Join(f.home, "failing-after-started")
	succeedingStarted := filepath.Join(f.home, "succeeding-after-started")
	failingCommand := f.writeTool("failing-after-impl", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
touch %s
exit 7
`, shellQuote(failingStarted)))
	succeedingCommand := f.writeTool("succeeding-after-impl", markerScript(succeedingStarted, ""))
	config := f.writeAgentConfig(fmt.Sprintf(`
plugins:
  - name: failing-after
    source: custom
    when: after-agent
    command: %s
  - name: succeeding-after
    source: custom
    when: after-agent
    command: %s
`, quoteYAML(failingCommand), quoteYAML(succeedingCommand)))

	output := f.runRunPlugins(config, "after-agent", false)
	if !strings.Contains(output, "1 after-agent plugin lifecycle failed") {
		t.Fatalf("expected after-agent supervisor failure, got:\n%s", output)
	}
	waitForFile(t, failingStarted, time.Second)
	waitForFile(t, succeedingStarted, time.Second)

	var failingState map[string]any
	decodeJSONFile(t, filepath.Join(f.state, "plugins", "failing-after", "state.json"), &failingState)
	if failingState["status"] != "failed" || failingState["last_exit_code"] != float64(7) {
		t.Fatalf("expected failing-after failed state, got %#v", failingState)
	}
	var succeedingState map[string]any
	decodeJSONFile(t, filepath.Join(f.state, "plugins", "succeeding-after", "state.json"), &succeedingState)
	if succeedingState["status"] != "succeeded" || succeedingState["ready"] != true {
		t.Fatalf("expected succeeding-after succeeded state, got %#v", succeedingState)
	}
}

func TestBeforeAgentPluginsRemainSequential(t *testing.T) {
	f := newFixture(t)
	firstStarted := filepath.Join(f.home, "first-before-started")
	secondStarted := filepath.Join(f.home, "second-before-started")
	releaseFirst := filepath.Join(f.home, "release-first-before")
	t.Cleanup(func() { _ = os.WriteFile(releaseFirst, []byte("ok\n"), 0o644) })
	firstCommand := f.writeTool("first-before-impl", markerScript(firstStarted, releaseFirst))
	secondCommand := f.writeTool("second-before-impl", markerScript(secondStarted, ""))
	config := f.writeAgentConfig(fmt.Sprintf(`
plugins:
  - name: first-before
    source: custom
    when: before-agent
    command: %s
  - name: second-before
    source: custom
    when: before-agent
    command: %s
`, quoteYAML(firstCommand), quoteYAML(secondCommand)))

	cmd, output := f.startRunPlugins(config, "before-agent", 5*time.Second)
	waitForFile(t, firstStarted, 2*time.Second)
	assertFileDoesNotAppear(t, secondStarted, 200*time.Millisecond)
	if err := os.WriteFile(releaseFirst, []byte("ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("run-plugins before-agent failed: %v\n%s", err, output.String())
	}
	waitForFile(t, secondStarted, time.Second)
}

func TestExportArtifactsDescribeTools(t *testing.T) {
	f := newFixture(t)
	toolCommand := f.writeTool("artifact-impl", "#!/usr/bin/env bash\necho artifact\n")
	config := f.writeAgentConfig(fmt.Sprintf(`
plugins:
  - name: artifact-plugin
    source: custom
    exports:
      tools:
        - name: artifact-tool
          command: %s
          description: Artifact test tool
`, quoteYAML(toolCommand)))

	f.runExport(config, true)

	var tools map[string][]map[string]any
	decodeJSONFile(t, filepath.Join(f.state, "plugin-tools.json"), &tools)
	if len(tools["tools"]) != 1 || tools["tools"][0]["name"] != "artifact-tool" {
		t.Fatalf("unexpected plugin-tools.json: %#v", tools)
	}

	markdown, err := os.ReadFile(filepath.Join(f.state, "plugin-tools.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(markdown), "`artifact-tool`") ||
		!strings.Contains(string(markdown), "Artifact test tool") {
		t.Fatalf("plugin-tools.md did not describe exported tool:\n%s", markdown)
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := repoRoot(t)
	home := t.TempDir()
	state := filepath.Join(home, "state")
	workspace := filepath.Join(home, "workspace")
	bin := filepath.Join(home, "test-bin")
	for _, dir := range []string{state, workspace, bin, filepath.Join(home, ".local", "bin")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	return &fixture{
		t:          t,
		root:       root,
		home:       home,
		state:      state,
		workspace:  workspace,
		bin:        bin,
		pathPrefix: filepath.Join(home, ".local", "bin") + string(os.PathListSeparator) + bin,
	}
}

func (f *fixture) writeTool(name, content string) string {
	f.t.Helper()
	path := filepath.Join(f.home, name)
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		f.t.Fatal(err)
	}
	return path
}

func (f *fixture) writeBin(name, content string) string {
	f.t.Helper()
	path := filepath.Join(f.bin, name)
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		f.t.Fatal(err)
	}
	return path
}

func (f *fixture) writeAgentConfig(content string) string {
	f.t.Helper()
	path := filepath.Join(f.home, "agent.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
	return path
}

func (f *fixture) writePluginConfig(name, content string) string {
	f.t.Helper()
	path := filepath.Join(f.home, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		f.t.Fatal(err)
	}
	return path
}

func (f *fixture) runExport(config string, wantOK bool) string {
	f.t.Helper()
	return f.run(exportPluginToolsBin(f.root), wantOK, config)
}

func (f *fixture) runRunPlugins(config, when string, wantOK bool) string {
	f.t.Helper()
	return f.run(runPluginsBin(f.root), wantOK, when, config)
}

func (f *fixture) startRunPlugins(config, when string, timeout time.Duration) (*exec.Cmd, *bytes.Buffer) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	f.t.Cleanup(cancel)
	fullCommand := runPluginsBin(f.root) + " " + shellQuote(when) + " " + shellQuote(config)
	cmd := exec.CommandContext(ctx, "sh", "-c", fullCommand)
	output := &bytes.Buffer{}
	cmd.Stdout = output
	cmd.Stderr = output
	cmd.Env = mergedEnv(f.env())
	if err := cmd.Start(); err != nil {
		f.t.Fatalf("start run-plugins: %v\n%s", err, output.String())
	}
	return cmd, output
}

func (f *fixture) runCommand(command string, wantOK bool, args ...string) string {
	f.t.Helper()
	return f.run(command, wantOK, args...)
}

func (f *fixture) initRepo(name string) string {
	f.t.Helper()
	path := filepath.Join(f.workspace, name)
	f.runCommand("git", true, "init", path)
	return path
}

func (f *fixture) run(command string, wantOK bool, args ...string) string {
	f.t.Helper()
	return f.runWithEnv(command, wantOK, nil, args...)
}

func (f *fixture) runWithEnv(command string, wantOK bool, extraEnv []string, args ...string) string {
	f.t.Helper()
	cmd := commandWithEnv(command, append(f.env(), extraEnv...), args...)
	output, err := cmd.CombinedOutput()
	if wantOK && err != nil {
		f.t.Fatalf("command failed: %s %v\n%s", command, args, output)
	}
	if !wantOK && err == nil {
		f.t.Fatalf("command unexpectedly succeeded: %s %v\n%s", command, args, output)
	}
	return string(output)
}

func (f *fixture) runWithInput(command, input string, wantOK bool, args ...string) string {
	f.t.Helper()
	cmd := commandWithEnv(command, f.env(), args...)
	cmd.Stdin = strings.NewReader(input)
	output, err := cmd.CombinedOutput()
	if wantOK && err != nil {
		f.t.Fatalf("command failed: %s %v\n%s", command, args, output)
	}
	if !wantOK && err == nil {
		f.t.Fatalf("command unexpectedly succeeded: %s %v\n%s", command, args, output)
	}
	return string(output)
}

func (f *fixture) env() []string {
	return []string{
		"HOME=" + f.home,
		"NVT_STATE_DIR=" + f.state,
		"NVT_WORKSPACE=" + f.workspace,
		"PATH=" + f.pathPrefix + string(os.PathListSeparator) + os.Getenv("PATH"),
	}
}

func exportConfig(pluginName, toolName, command string) string {
	return fmt.Sprintf(`
plugins:
  - name: %s
    source: custom
    exports:
      tools:
        - name: %s
          command: %s
`, pluginName, toolName, quoteYAML(command))
}

func repoRoot(t *testing.T) string {
	t.Helper()
	if value := os.Getenv("GITHUB_WORKSPACE"); value != "" {
		return value
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve test file path")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(file), "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func exportPluginToolsBin(root string) string {
	if value := os.Getenv("EXPORT_PLUGIN_TOOLS_BIN"); value != "" {
		return value
	}
	return "python3 " + shellQuote(filepath.Join(root, "runtime", "core", "export-plugin-tools.py"))
}

func runPluginsBin(root string) string {
	if value := os.Getenv("RUN_PLUGINS_BIN"); value != "" {
		return value
	}
	return "python3 " + shellQuote(filepath.Join(root, "runtime", "core", "run-plugins.py"))
}

func gitHostCredentialBin(root string) string {
	return "python3 " + shellQuote(filepath.Join(root, "runtime", "plugins", "git-host-credentials", "git-host-credential.py"))
}

func ghAuthBin(root string) string {
	return "python3 " + shellQuote(filepath.Join(root, "runtime", "plugins", "git-host-credentials", "gh-auth.py"))
}

func gitCredentialNvtBin(root string) string {
	return "python3 " + shellQuote(filepath.Join(root, "runtime", "plugins", "git-credentials", "git-credential-nvt.py"))
}

func gitCredentialsRunBin(root string) string {
	return "python3 " + shellQuote(filepath.Join(root, "runtime", "plugins", "git-credentials", "run.py"))
}

func githubWatchBin(root string) string {
	return "python3 " + shellQuote(filepath.Join(root, "runtime", "plugins", "github-watcher", "github-watch.py"))
}

func githubWatcherRunBin(root string) string {
	return "python3 " + shellQuote(filepath.Join(root, "runtime", "plugins", "github-watcher", "run.py"))
}

func eventWebhookRunBin(root string) string {
	return "python3 " + shellQuote(filepath.Join(root, "runtime", "plugins", "event-webhook", "run.py"))
}

func initialPromptRunBin(root string) string {
	return "python3 " + shellQuote(filepath.Join(root, "runtime", "plugins", "initial-prompt", "run.py"))
}

func smokeCompleteRunBin(root string) string {
	return "python3 " + shellQuote(filepath.Join(root, "runtime", "plugins", "smoke-complete", "run.py"))
}

func renderAgentExposeBin(root string) string {
	return "python3 " + shellQuote(filepath.Join(root, "scripts", "render-agent-expose.py"))
}

func bootstrapBin(root string) string {
	return "python3 " + shellQuote(filepath.Join(root, "runtime", "core", "bootstrap.py"))
}

func codeServerSettingsPath(f *fixture) string {
	return filepath.Join(f.home, ".local", "share", "code-server", "User", "settings.json")
}

func readCodeServerSettings(t *testing.T, f *fixture) map[string]any {
	t.Helper()
	data, err := os.ReadFile(codeServerSettingsPath(f))
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("invalid settings JSON: %v\n%s", err, data)
	}
	return settings
}

func commandWithEnv(command string, env []string, args ...string) *exec.Cmd {
	fullCommand := command
	for _, arg := range args {
		fullCommand += " " + shellQuote(arg)
	}
	cmd := exec.Command("sh", "-c", fullCommand)
	cmd.Env = mergedEnv(env)
	return cmd
}

func mergedEnv(overrides []string) []string {
	values := map[string]string{}
	order := []string{}
	for _, entry := range append(os.Environ(), overrides...) {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if _, exists := values[name]; !exists {
			order = append(order, name)
		}
		values[name] = entry
	}
	merged := make([]string, 0, len(order))
	for _, name := range order {
		merged = append(merged, values[name])
	}
	return merged
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func quoteYAML(value string) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func markerScript(marker, release string) string {
	script := fmt.Sprintf("#!/usr/bin/env bash\nset -euo pipefail\ntouch %s\n", shellQuote(marker))
	if release != "" {
		script += fmt.Sprintf("while [ ! -f %s ]; do sleep 0.02; done\n", shellQuote(release))
	}
	return script
}

func waitForFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

func assertFileDoesNotAppear(t *testing.T, path string, duration time.Duration) {
	t.Helper()
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("file appeared before expected: %s", path)
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func decodeJSON(t *testing.T, data []byte, out any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(data)))
	if err := decoder.Decode(out); err != nil {
		t.Fatalf("decode JSON %q: %v", data, err)
	}
}

func decodeJSONFile(t *testing.T, path string, out any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decodeJSON(t, data, out)
}
