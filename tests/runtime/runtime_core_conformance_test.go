package runtime_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRuntimeDockerfileInstallsAgentCapture(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "runtime", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(data)
	required := []string{
		"COPY runtime/core/agent-capture.sh /usr/local/bin/agent-capture",
		"/usr/local/bin/agent-capture",
	}
	for _, fragment := range required {
		if !strings.Contains(dockerfile, fragment) {
			t.Fatalf("runtime Dockerfile missing %q\n%s", fragment, dockerfile)
		}
	}
}
func TestWriteAgentInstructionsIncludesExposedHTTPRoutes(t *testing.T) {
	f := newFixture(t)
	script := filepath.Join(f.root, "runtime", "core", "write-agent-instructions.sh")
	routes := `[{"name":"app","targetPort":3000,"source":"agent"},{"name":"api","targetPort":8080,"source":"agent"}]`

	f.runWithEnv("bash "+shellQuote(script), true, []string{
		"AGENT_HOST=nvt-dev.agent.localhost",
		"NVT_PROXY_PORT=4090",
		"NVT_EXPOSED_HTTP_ROUTES_JSON=" + routes,
	})

	data, err := os.ReadFile(filepath.Join(f.workspace, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	instructions := string(data)
	required := []string{
		"## Runtime Tools",
		"agent-capture --lines 200 --out agent-capture.txt",
		"## Exposed Local HTTP Services",
		"`app`: `http://app.nvt-dev.agent.localhost:4090` -> shared local port `3000`",
		"`api`: `http://api.nvt-dev.agent.localhost:4090` -> shared local port `8080`",
	}
	for _, fragment := range required {
		if !strings.Contains(instructions, fragment) {
			t.Fatalf("AGENTS.md missing %q\n%s", fragment, instructions)
		}
	}
	for _, forbidden := range []string{"Docker sidecar", "egress sidecar", "same-Pod egress"} {
		if strings.Contains(instructions, forbidden) {
			t.Fatalf("generated AGENTS.md exposes deployment topology %q\n%s", forbidden, instructions)
		}
	}
}

func TestWriteAgentInstructionsIncludesRequiredDockerNetworkGuidanceOnlyWhenConfigured(t *testing.T) {
	f := newFixture(t)
	script := filepath.Join(f.root, "runtime", "core", "write-agent-instructions.sh")
	f.runWithEnv("bash "+shellQuote(script), true, nil)
	plain, err := os.ReadFile(filepath.Join(f.workspace, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "## Required Docker Networks") {
		t.Fatal("unconfigured runtime gained required-network guidance")
	}

	f.runWithEnv("bash "+shellQuote(script), true, []string{
		`NVT_DOCKER_REQUIRED_NETWORKS=[{"name":"kind","subnet":"172.31.250.0/24"}]`,
	})
	configured, err := os.ReadFile(filepath.Join(f.workspace, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"## Required Docker Networks", "including immediately after pruning", "Do not bypass the CLI"} {
		if !strings.Contains(string(configured), text) {
			t.Fatalf("configured AGENTS.md missing %q:\n%s", text, configured)
		}
	}
}

func TestWriteAgentInstructionsIncludesGitHubPRWorkflowWhenToolsAreAvailable(t *testing.T) {
	f := newFixture(t)
	script := filepath.Join(f.root, "runtime", "core", "write-agent-instructions.sh")
	f.writeBin("gh-auth", "#!/usr/bin/env bash\nexit 0\n")
	f.writeBin("github-watch", "#!/usr/bin/env bash\nexit 0\n")

	f.runWithEnv("bash "+shellQuote(script), true, nil)

	data, err := os.ReadFile(filepath.Join(f.workspace, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	instructions := string(data)
	required := []string{
		"## GitHub PR Workflow",
		"Use `gh-auth` for GitHub CLI operations.",
		"Do not use `gh-auth auth status` to test access",
		"even when an auth-status probe would fail.",
		"gh-auth pr create --repo OWNER/REPO --fill",
		"github-watch register --repo OWNER/REPO --number PR_NUMBER --label work",
		"Registered dynamic watches auto-remove after the PR is merged or closed by",
		"default.",
		"only for manual cleanup or static/kept",
		"After a PR is registered, wait for prompts instead of manually polling.",
		"always post a PR comment summarizing what changed or why no change",
		"gh-auth pr comment PR_NUMBER --repo OWNER/REPO --body-file -",
	}
	for _, fragment := range required {
		if !strings.Contains(instructions, fragment) {
			t.Fatalf("AGENTS.md missing %q\n%s", fragment, instructions)
		}
	}
}

func TestWriteAgentInstructionsAppendsLocalWorkspaceInstructions(t *testing.T) {
	f := newFixture(t)
	script := filepath.Join(f.root, "runtime", "core", "write-agent-instructions.sh")
	localInstructions := filepath.Join(f.workspace, "AGENTS.local.md")
	if err := os.WriteFile(localInstructions, []byte("Prefer focused PRs for this workspace.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	f.runWithEnv("bash "+shellQuote(script), true, nil)

	data, err := os.ReadFile(filepath.Join(f.workspace, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	instructions := string(data)
	required := []string{
		"This file is generated at container startup.",
		"Local override instructions are read from `" + localInstructions + "`",
		"Deleting that session ends the main container and fails an active Kubernetes AgentRun.",
		"## Local Workspace Instructions",
		"Prefer focused PRs for this workspace.",
	}
	for _, fragment := range required {
		if !strings.Contains(instructions, fragment) {
			t.Fatalf("AGENTS.md missing %q\n%s", fragment, instructions)
		}
	}
}

func TestWriteAgentInstructionsComposesProfileWorkflowThenLocalInstructions(t *testing.T) {
	f := newFixture(t)
	script := filepath.Join(f.root, "runtime", "core", "write-agent-instructions.sh")
	profileInstructions := filepath.Join(t.TempDir(), "profile.md")
	workflowInstructions := filepath.Join(t.TempDir(), "workflow.md")
	localInstructions := filepath.Join(f.workspace, "AGENTS.local.md")
	if err := os.WriteFile(profileInstructions, []byte("Profile workflow guidance.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workflowInstructions, []byte("Selected workflow guidance.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localInstructions, []byte("Local workspace guidance.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	f.runWithEnv("bash "+shellQuote(script), true, []string{
		"NVT_AGENT_PROFILE_INSTRUCTIONS_FILE=" + profileInstructions,
		"NVT_AGENT_WORKFLOW_INSTRUCTIONS_FILE=" + workflowInstructions,
	})
	// Startup regenerates AGENTS.md; running it again must not duplicate layers.
	f.runWithEnv("bash "+shellQuote(script), true, []string{
		"NVT_AGENT_PROFILE_INSTRUCTIONS_FILE=" + profileInstructions,
		"NVT_AGENT_WORKFLOW_INSTRUCTIONS_FILE=" + workflowInstructions,
	})
	data, err := os.ReadFile(filepath.Join(f.workspace, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	generated := string(data)
	core := strings.Index(generated, "## Runtime Context")
	profile := strings.Index(generated, "## Profile Workspace Instructions")
	workflow := strings.Index(generated, "## Workflow Workspace Instructions")
	local := strings.Index(generated, "## Local Workspace Instructions")
	if core < 0 || profile <= core || workflow <= profile || local <= workflow ||
		!strings.Contains(generated, "Profile workflow guidance.") ||
		!strings.Contains(generated, "Selected workflow guidance.") ||
		!strings.Contains(generated, "Local workspace guidance.") {
		t.Fatalf("unexpected instruction composition:\n%s", generated)
	}
	for _, heading := range []string{"## Profile Workspace Instructions", "## Workflow Workspace Instructions", "## Local Workspace Instructions"} {
		if strings.Count(generated, heading) != 1 {
			t.Fatalf("repeated startup duplicated %q:\n%s", heading, generated)
		}
	}
}

func TestWriteAgentInstructionsSkipsMissingEmptyAndDuplicateFiles(t *testing.T) {
	f := newFixture(t)
	script := filepath.Join(f.root, "runtime", "core", "write-agent-instructions.sh")
	shared := filepath.Join(t.TempDir(), "shared.md")
	alias := filepath.Join(t.TempDir(), "alias.md")
	if err := os.WriteFile(shared, []byte("One shared instruction layer.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(shared, alias); err != nil {
		t.Fatal(err)
	}
	f.runWithEnv("bash "+shellQuote(script), true, []string{
		"NVT_AGENT_PROFILE_INSTRUCTIONS_FILE=" + shared,
		"NVT_AGENT_WORKFLOW_INSTRUCTIONS_FILE=" + alias,
		"NVT_AGENT_LOCAL_INSTRUCTIONS=" + alias,
	})
	data, err := os.ReadFile(filepath.Join(f.workspace, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	generated := string(data)
	if strings.Count(generated, "One shared instruction layer.") != 1 ||
		strings.Count(generated, "## Profile Workspace Instructions") != 1 ||
		strings.Contains(generated, "## Workflow Workspace Instructions") ||
		strings.Contains(generated, "## Local Workspace Instructions") {
		t.Fatalf("duplicate instruction paths were appended more than once:\n%s", generated)
	}

	empty := filepath.Join(t.TempDir(), "empty.md")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	f.runWithEnv("bash "+shellQuote(script), true, []string{
		"NVT_AGENT_PROFILE_INSTRUCTIONS_FILE=" + empty,
		"NVT_AGENT_WORKFLOW_INSTRUCTIONS_FILE=" + filepath.Join(t.TempDir(), "missing-workflow.md"),
		"NVT_AGENT_LOCAL_INSTRUCTIONS=" + filepath.Join(t.TempDir(), "missing.md"),
	})
	data, err = os.ReadFile(filepath.Join(f.workspace, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	generated = string(data)
	if strings.Contains(generated, "## Profile Workspace Instructions") ||
		strings.Contains(generated, "## Workflow Workspace Instructions") ||
		strings.Contains(generated, "## Local Workspace Instructions") {
		t.Fatalf("missing or empty files created instruction sections:\n%s", generated)
	}

	workflowOnly := filepath.Join(t.TempDir(), "workflow-only.md")
	if err := os.WriteFile(workflowOnly, []byte("Workflow-only guidance.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.runWithEnv("bash "+shellQuote(script), true, []string{
		"NVT_AGENT_WORKFLOW_INSTRUCTIONS_FILE=" + workflowOnly,
		"NVT_AGENT_LOCAL_INSTRUCTIONS=" + filepath.Join(t.TempDir(), "missing-local.md"),
	})
	data, err = os.ReadFile(filepath.Join(f.workspace, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	generated = string(data)
	if strings.Contains(generated, "## Profile Workspace Instructions") ||
		!strings.Contains(generated, "## Workflow Workspace Instructions") ||
		strings.Contains(generated, "## Local Workspace Instructions") {
		t.Fatalf("workflow-only composition was incorrect:\n%s", generated)
	}
}

func TestAgentCaptureDefaultsAndPrintMode(t *testing.T) {
	root := repoRoot(t)
	work := t.TempDir()
	bin := t.TempDir()
	argsFile := filepath.Join(work, "tmux.args")
	fakeTmux := filepath.Join(bin, "tmux")
	if err := os.WriteFile(fakeTmux, []byte(`#!/usr/bin/env bash
printf '%s\n' "$*" >> "$TMUX_ARGS_FILE"
printf 'captured output\n'
`), 0o755); err != nil {
		t.Fatal(err)
	}

	script := "bash " + shellQuote(filepath.Join(root, "runtime", "core", "agent-capture.sh"))
	env := []string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"TMUX_ARGS_FILE=" + argsFile,
		"AGENT_SESSION=custom-agent",
	}

	cmd := commandWithEnv(script, env)
	cmd.Dir = work
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("agent-capture default failed: %v\n%s", err, output)
	}
	data, err := os.ReadFile(filepath.Join(work, "agent-capture.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "captured output\n" {
		t.Fatalf("unexpected capture file: %q", data)
	}

	cmd = commandWithEnv(script, env, "--lines", "7", "--session", "pane-1", "--print")
	cmd.Dir = work
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("agent-capture print failed: %v\n%s", err, output)
	}
	if string(output) != "captured output\n" {
		t.Fatalf("unexpected print output: %q", output)
	}

	argsData, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	args := string(argsData)
	for _, fragment := range []string{
		"capture-pane -p -S -100 -t custom-agent",
		"capture-pane -p -S -7 -t pane-1",
	} {
		if !strings.Contains(args, fragment) {
			t.Fatalf("tmux args missing %q\n%s", fragment, args)
		}
	}
}

func TestBootstrapCreatesDefaultTmuxConfig(t *testing.T) {
	f := newFixture(t)
	config := f.writeAgentConfig(`
runtime:
  command: codex
`)

	f.runWithEnv("python3 "+shellQuote(filepath.Join(f.root, "runtime", "core", "bootstrap.py")), true, nil, config)

	data, err := os.ReadFile(filepath.Join(f.home, ".tmux.conf"))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"set -g mouse on",
		"set -g history-limit 100000",
		"setw -g mode-keys vi",
	}, "\n") + "\n"
	if string(data) != want {
		t.Fatalf("unexpected tmux config: %q", data)
	}
}

func TestBootstrapPreservesExistingTmuxConfig(t *testing.T) {
	f := newFixture(t)
	config := f.writeAgentConfig(`
runtime:
  command: codex
`)
	tmuxConfig := filepath.Join(f.home, ".tmux.conf")
	if err := os.WriteFile(tmuxConfig, []byte("set -g status off\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	f.runWithEnv("python3 "+shellQuote(filepath.Join(f.root, "runtime", "core", "bootstrap.py")), true, nil, config)

	data, err := os.ReadFile(tmuxConfig)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "set -g status off\n" {
		t.Fatalf("bootstrap overwrote existing tmux config: %q", data)
	}
}

func TestBootstrapWritesPreseedFiles(t *testing.T) {
	f := newFixture(t)
	existingCodexConfig := filepath.Join(f.home, ".codex", "existing.toml")
	if err := os.MkdirAll(filepath.Dir(existingCodexConfig), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(existingCodexConfig, []byte("user-managed = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := f.writeAgentConfig(`
preseed:
  files:
    - path: "$HOME/.claude/settings.json"
      mode: "0600"
      json:
        theme: dark-daltonized
        skipDangerousModePermissionPrompt: true
    - path: ".codex/config.toml"
      mode: "0640"
      content: |
        check_for_update_on_startup = false
    - path: ".codex/existing.toml"
      content: |
        user-managed = false
`)

	f.runWithEnv(bootstrapBin(f.root), true, nil, config)

	claudeSettings := filepath.Join(f.home, ".claude", "settings.json")
	data, err := os.ReadFile(claudeSettings)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("preseed JSON is invalid: %v\n%s", err, data)
	}
	if settings["theme"] != "dark-daltonized" || settings["skipDangerousModePermissionPrompt"] != true {
		t.Fatalf("unexpected claude settings: %#v", settings)
	}
	codexConfig := filepath.Join(f.home, ".codex", "config.toml")
	data, err = os.ReadFile(codexConfig)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "check_for_update_on_startup = false\n" {
		t.Fatalf("unexpected codex config:\n%s", data)
	}
	info, err := os.Stat(codexConfig)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("expected codex config mode 0640, got %v", info.Mode().Perm())
	}
	data, err = os.ReadFile(existingCodexConfig)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "user-managed = true\n" {
		t.Fatalf("overwrite=false preseed rewrote existing file:\n%s", data)
	}
}

func TestBootstrapPreseedRejectsEscapingHome(t *testing.T) {
	f := newFixture(t)
	config := f.writeAgentConfig(`
preseed:
  files:
    - path: /tmp/nvt-escape
      content: nope
`)

	output := f.runWithEnv(bootstrapBin(f.root), false, nil, config)
	if !strings.Contains(output, "resolves outside HOME") {
		t.Fatalf("expected outside HOME rejection, got:\n%s", output)
	}
}

func TestBootstrapWritesInlineCodeServerSettingsWhenTargetMissing(t *testing.T) {
	f := newFixture(t)
	config := f.writeAgentConfig(`
code-server:
  settings:
    overwrite: false
    values:
      workbench.colorTheme: "Default Dark Modern"
      editor.minimap.enabled: false
      editor.tabSize: 2
      nested:
        enabled: true
      list:
        - one
        - 2
      nullable: null
`)

	f.runWithEnv(bootstrapBin(f.root), true, nil, config)

	settings := readCodeServerSettings(t, f)
	if settings["workbench.colorTheme"] != "Default Dark Modern" {
		t.Fatalf("unexpected color theme: %#v", settings)
	}
	if settings["editor.minimap.enabled"] != false {
		t.Fatalf("expected boolean value to be preserved: %#v", settings)
	}
	if settings["editor.tabSize"] != float64(2) {
		t.Fatalf("expected numeric value to be preserved: %#v", settings)
	}
	if settings["nullable"] != nil {
		t.Fatalf("expected null value to be preserved: %#v", settings)
	}
	nested, ok := settings["nested"].(map[string]any)
	if !ok || nested["enabled"] != true {
		t.Fatalf("expected object value to be preserved: %#v", settings)
	}
	list, ok := settings["list"].([]any)
	if !ok || len(list) != 2 || list[0] != "one" || list[1] != float64(2) {
		t.Fatalf("expected array value to be preserved: %#v", settings)
	}
}

func TestBootstrapPreservesExistingInlineCodeServerSettingsWhenOverwriteFalse(t *testing.T) {
	f := newFixture(t)
	target := codeServerSettingsPath(f)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(`{"existing":true}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := f.writeAgentConfig(`
code-server:
  settings:
    overwrite: false
    values:
      existing: false
      next: true
`)

	output := f.runWithEnv(bootstrapBin(f.root), true, nil, config)

	if !strings.Contains(output, "bootstrap: code-server settings already exist, skipping") {
		t.Fatalf("expected skip message, got:\n%s", output)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"existing":true}`+"\n" {
		t.Fatalf("bootstrap overwrote existing settings: %q", data)
	}
}

func TestBootstrapReplacesExistingInlineCodeServerSettingsWhenOverwriteTrue(t *testing.T) {
	f := newFixture(t)
	target := codeServerSettingsPath(f)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(`{"existing":true}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := f.writeAgentConfig(`
code-server:
  settings:
    overwrite: true
    values:
      existing: false
      next: true
`)

	f.runWithEnv(bootstrapBin(f.root), true, nil, config)

	settings := readCodeServerSettings(t, f)
	if settings["existing"] != false || settings["next"] != true {
		t.Fatalf("unexpected replaced settings: %#v", settings)
	}
}

func TestBootstrapLegacyCodeServerSettingsFileStillWorksAndWarns(t *testing.T) {
	f := newFixture(t)
	legacy := filepath.Join(f.workspace, ".nvt-agent", "code-server", "settings.json")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte(`{"legacy":true}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := f.writeAgentConfig(`
code-server:
  settings-file: .nvt-agent/code-server/settings.json
`)

	output := f.runWithEnv(bootstrapBin(f.root), true, nil, config)

	if !strings.Contains(output, "bootstrap: code-server.settings-file is deprecated; use code-server.settings.values") {
		t.Fatalf("expected deprecation warning, got:\n%s", output)
	}
	settings := readCodeServerSettings(t, f)
	if settings["legacy"] != true {
		t.Fatalf("legacy settings were not copied: %#v", settings)
	}
}

func TestBootstrapRejectsLegacyAndInlineCodeServerSettingsTogether(t *testing.T) {
	f := newFixture(t)
	config := f.writeAgentConfig(`
code-server:
  settings-file: .nvt-agent/code-server/settings.json
  settings:
    values:
      workbench.startupEditor: none
`)

	output := f.runWithEnv(bootstrapBin(f.root), false, nil, config)

	if !strings.Contains(output, "code-server.settings-file is deprecated; use code-server.settings.values, not both") {
		t.Fatalf("unexpected output:\n%s", output)
	}
}

func TestBootstrapRejectsInvalidCodeServerSettingsShape(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "settings-not-object",
			body: `
code-server:
  settings: []
`,
			want: "code-server.settings must be a YAML object",
		},
		{
			name: "values-not-object",
			body: `
code-server:
  settings:
    values: []
`,
			want: "code-server.settings.values must be a YAML object",
		},
		{
			name: "overwrite-not-boolean",
			body: `
code-server:
  settings:
    overwrite: yes please
    values: {}
`,
			want: "code-server.settings.overwrite must be a boolean",
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
		})
	}
}

func TestStartAgentSessionRelaunchesFastExitUntilBound(t *testing.T) {
	f := newFixture(t)
	envFile := filepath.Join(f.home, ".nvt-agent", "env")
	if err := os.MkdirAll(filepath.Dir(envFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envFile, []byte("export NVT_WORKSPACE=\""+f.workspace+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	attemptsFile := filepath.Join(f.home, "tmux-attempts")
	f.writeBin("tmux", `#!/usr/bin/env bash
if [ "$1" = "has-session" ]; then
  exit 1
fi
if [ "$1" = "new-session" ]; then
  count=0
  if [ -f "$TMUX_ATTEMPTS_FILE" ]; then
    count="$(cat "$TMUX_ATTEMPTS_FILE")"
  fi
  count=$((count + 1))
  printf '%s' "$count" > "$TMUX_ATTEMPTS_FILE"
  exit 0
fi
exit 2
`)
	script := "bash " + shellQuote(filepath.Join(f.root, "runtime", "core", "start-agent-session.sh"))

	output := f.runWithEnv(script, false, []string{
		"TMUX_ATTEMPTS_FILE=" + attemptsFile,
		"NVT_AGENT_SESSION_MAX_START_ATTEMPTS=3",
		"NVT_AGENT_SESSION_FAST_EXIT_SECONDS=0",
	})

	data, err := os.ReadFile(attemptsFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "3" {
		t.Fatalf("expected 3 tmux start attempts, got %q\noutput:\n%s", data, output)
	}
	if !strings.Contains(output, "failed after 3 attempts") {
		t.Fatalf("expected bounded failure message, got:\n%s", output)
	}
}
func TestBootstrapAcceptsNonRootUserAndUsesHome(t *testing.T) {
	f := newFixture(t)
	config := f.writeAgentConfig(`
runtime:
  command: codex
  user: non-root
`)
	f.runWithEnv("python3 "+shellQuote(filepath.Join(f.root, "runtime", "core", "bootstrap.py")), true, nil, config)

	if _, err := os.ReadFile(filepath.Join(f.home, ".nvt-agent", "agent-command.json")); err != nil {
		t.Fatalf("bootstrap did not write state under $HOME: %v", err)
	}
}

func TestBootstrapPersistsRenderedRuntimeCommandArguments(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
	}{
		{
			name:    "codex trusted local",
			command: "codex",
			args:    []string{"--sandbox", "danger-full-access", "--ask-for-approval", "never"},
		},
		{
			name:    "claude trusted local",
			command: "claude",
			args:    []string{"--dangerously-skip-permissions"},
		},
		{
			name:    "interactive",
			command: "codex",
			args:    []string{},
		},
		{
			name:    "explicit override",
			command: "custom-codex-wrapper",
			args:    []string{"--model", "gpt-test", "--ask-for-approval", "on-request"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			encodedArgs, err := json.Marshal(test.args)
			if err != nil {
				t.Fatal(err)
			}
			config := f.writeAgentConfig("runtime:\n  command: " + test.command + "\n  args: " + string(encodedArgs) + "\n")
			f.runWithEnv("python3 "+shellQuote(filepath.Join(f.root, "runtime", "core", "bootstrap.py")), true, nil, config)

			var actual struct {
				Command string   `json:"command"`
				Args    []string `json:"args"`
			}
			decodeJSONFile(t, filepath.Join(f.home, ".nvt-agent", "agent-command.json"), &actual)
			if actual.Command != test.command || !reflect.DeepEqual(actual.Args, test.args) {
				t.Fatalf("unexpected agent command: %#v", actual)
			}
		})
	}
}

// TestBootstrapRejectsInvalidRuntimeUser pins the runtime.user validation.
func TestBootstrapRejectsInvalidRuntimeUser(t *testing.T) {
	f := newFixture(t)
	config := f.writeAgentConfig(`
runtime:
  command: codex
  user: wheel
`)
	output := f.runWithEnv("python3 "+shellQuote(filepath.Join(f.root, "runtime", "core", "bootstrap.py")), false, nil, config)
	if !strings.Contains(output, "runtime.user must be root or non-root") {
		t.Fatalf("expected runtime.user rejection, got:\n%s", output)
	}
}
func TestBootstrapInstallsPackagesViaNvtAsRoot(t *testing.T) {
	f := newFixture(t)
	callLog := filepath.Join(f.home, "nvt-as-root.calls")
	// Stub nvt-as-root and apt-get so the test does not touch the real system;
	// nvt-as-root records its args then execs the rest (the stub apt-get).
	f.writeBin("nvt-as-root", "#!/usr/bin/env bash\necho \"$@\" >> "+shellQuote(callLog)+"\nexec \"$@\"\n")
	f.writeBin("apt-get", "#!/usr/bin/env bash\nexit 0\n")

	config := f.writeAgentConfig(`
runtime:
  command: codex
tools:
  packages:
    - jq
`)
	f.runWithEnv("python3 "+shellQuote(filepath.Join(f.root, "runtime", "core", "bootstrap.py")), true, nil, config)

	data, err := os.ReadFile(callLog)
	if err != nil {
		t.Fatalf("nvt-as-root was not invoked for package install: %v", err)
	}
	calls := string(data)
	if !strings.Contains(calls, "apt-get update") {
		t.Fatalf("expected apt-get update via nvt-as-root, got:\n%s", calls)
	}
	if !strings.Contains(calls, "apt-get install -y --no-install-recommends jq") {
		t.Fatalf("expected apt-get install via nvt-as-root, got:\n%s", calls)
	}
}

// TestNvtAsRootWrapper pins the shim contract: no args -> usage; non-root with
// sudo -> re-runs through sudo; non-root without sudo -> fails clearly.
func TestNvtAsRootWrapper(t *testing.T) {
	root := repoRoot(t)
	shim := filepath.Join(root, "runtime", "core", "nvt-as-root")
	bashPath, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal(err)
	}
	accessibleTempDir := func(pattern string) string {
		t.Helper()
		dir, err := os.MkdirTemp("", pattern)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	nonRootCommand := func(args ...string) *exec.Cmd {
		if os.Geteuid() != 0 {
			return exec.Command(args[0], args[1:]...)
		}
		setpriv, err := exec.LookPath("setpriv")
		if err != nil {
			t.Fatalf("root test process requires setpriv to exercise non-root contract: %v", err)
		}
		wrapped := append([]string{"--reuid=65534", "--regid=65534", "--clear-groups", "--"}, args...)
		return exec.Command(setpriv, wrapped...)
	}

	// No args -> usage, exit 2.
	cmd := nonRootCommand(bashPath, shim)
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "usage: nvt-as-root") {
		t.Fatalf("no-args must print usage and fail, got err=%v out=%s", err, out)
	}

	// This test process is non-root; a stubbed sudo must be invoked with the args.
	binDir := accessibleTempDir("nvt-as-root-bin-")
	if err := os.Chmod(binDir, 0o777); err != nil {
		t.Fatal(err)
	}
	sudoLog := filepath.Join(binDir, "sudo.calls")
	mustWriteExecutable(t, filepath.Join(binDir, "sudo"), "#!/usr/bin/env bash\necho \"$@\" > "+shellQuote(sudoLog)+"\n")
	cmd = nonRootCommand(bashPath, shim, "apt-get", "install", "-y", "jq")
	cmd.Env = mergedEnv([]string{"PATH=" + binDir + string(os.PathListSeparator) + os.Getenv("PATH")})
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("non-root shim with sudo present must succeed: err=%v out=%s", err, out)
	}
	logged, err := os.ReadFile(sudoLog)
	if err != nil || !strings.Contains(string(logged), "apt-get install -y jq") {
		t.Fatalf("shim did not route through sudo with the args: %v %s", err, logged)
	}

	// Non-root without sudo on PATH -> clear failure. Keep `id` reachable (the
	// shim needs it) but exclude sudo by pointing PATH at a minimal dir.
	noSudo := accessibleTempDir("nvt-as-root-path-")
	if idPath, err := exec.LookPath("id"); err == nil {
		if err := os.Symlink(idPath, filepath.Join(noSudo, "id")); err != nil {
			t.Fatal(err)
		}
	}
	noSudoCmd := nonRootCommand(bashPath, shim, "apt-get", "update")
	home := accessibleTempDir("nvt-as-root-home-")
	noSudoCmd.Env = []string{"PATH=" + noSudo, "HOME=" + home}
	if out, err := noSudoCmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "requires root privileges but sudo is unavailable") {
		t.Fatalf("non-root without sudo must fail clearly, got err=%v out=%s", err, out)
	}
}
