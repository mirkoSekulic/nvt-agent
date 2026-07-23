package runtime_test

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestComposeAgentUsesDindSidecar(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "compose.agent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	compose := string(data)

	required := []string{
		"DOCKER_HOST: tcp://127.0.0.1:2375",
		"network_mode: service:docker",
		"condition: service_healthy",
		"docker:",
		"image: docker:27-dind",
		"privileged: true",
		"DOCKER_TLS_CERTDIR: \"\"",
		"- dockerd",
		"--host=tcp://127.0.0.1:2375",
		"--tls=false",
		"docker info >/dev/null 2>&1",
		"docker-data:/var/lib/docker",
		"${WORKSPACE_DIR}:${NVT_WORKSPACE}",
		"agents-proxy",
		"agent-internal",
		"traefik.docker.network=agents-proxy",
		"egressd:",
		"captured:",
		"image: nvt-captured:latest",
		"NVT_CAPTURED_TRANSPARENT_LISTEN: \"[::]:15001\"",
		"NVT_EGRESS_PROXY: egressd:8470",
		"net-init:",
		"NET_ADMIN",
		"NVT_CAPTURE_EXCLUDE_HOSTS: broker",
		"for ip in $$exclude_v4; do iptables -t nat -A NVT_CAPTURE",
		"ip6tables -t nat",
		"profiles:",
		"- mediated",
		"env_file:",
		"${EGRESSD_ENV_FILE:-/dev/null}",
		"NVT_EGRESSD_CONFIG: /config/egressd.json",
		"${EGRESSD_CONFIG_FILE:-/dev/null}:/config/egressd.json:ro",
		"${EGRESS_CA_CERT_FILE:-/dev/null}:/nvt-egress-ca/ca.crt:ro",
		"user: \"0:0\"",
		"${EGRESS_CA_CERT_FILE:-/dev/null}:/etc/nvt-egress-ca/ca.crt:ro",
		"${EGRESS_CA_KEY_FILE:-/dev/null}:/etc/nvt-egress-ca/ca.key:ro",
	}
	for _, fragment := range required {
		if !strings.Contains(compose, fragment) {
			t.Fatalf("compose.agent.yaml missing %q\n%s", fragment, compose)
		}
	}
	if strings.Contains(compose, "/var/run/docker.sock:") {
		t.Fatalf("compose.agent.yaml must not mount the host Docker socket")
	}
	if strings.Contains(compose, "NVT_BROKER_TOKEN: ${NVT_EGRESS_BROKER_TOKEN") {
		t.Fatalf("compose must not pass egress token through agent-loaded interpolation env:\n%s", compose)
	}
	agentStart := strings.Index(compose, "\n  agent:\n")
	egressStart := strings.Index(compose, "\n  egressd:\n")
	if agentStart == -1 || egressStart == -1 || egressStart <= agentStart {
		t.Fatalf("compose.agent.yaml missing ordered agent/egressd services:\n%s", compose)
	}
	agentService := compose[agentStart:egressStart]
	if strings.Contains(agentService, "ca.key") || strings.Contains(agentService, "EGRESS_CA_DIR") || strings.Contains(agentService, "EGRESS_CA_KEY_FILE") {
		t.Fatalf("agent service must not mount or reference the CA private key:\n%s", agentService)
	}
	capturedStart := strings.Index(compose, "\n  captured:\n")
	if capturedStart == -1 {
		t.Fatal("compose missing captured service")
	}
	egressService := compose[egressStart:capturedStart]
	if strings.Contains(egressService, "network_mode: service:docker") {
		t.Fatal("trusted egressd must use a separate Compose network namespace")
	}
	if !strings.Contains(egressService, "- agents-proxy") {
		t.Fatal("trusted egressd must join the infrastructure network to reach broker")
	}
}

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

func TestRenderAgentExposeGeneratesTraefikLabels(t *testing.T) {
	f := newFixture(t)
	config := f.writeAgentConfig(`
expose:
  http:
    - name: app
      targetPort: 3000
    - name: api
      targetPort: 8080
`)
	output := filepath.Join(f.home, "compose.expose.yaml")

	f.runWithEnv(renderAgentExposeBin(f.root), true, nil,
		"--agent-config", config,
		"--agent-name", "nvt-dev",
		"--agent-host", "nvt-dev.agent.localhost",
		"--output", output,
	)

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(data)
	required := []string{
		"NVT_EXPOSED_HTTP_ROUTES_JSON:",
		"  egressd:",
		"    user: 0:0",
		"  docker:",
		`{"name":"app","targetPort":3000,"source":"agent"}`,
		"traefik.http.routers.nvt-dev-app.rule: 'Host(`app.nvt-dev.agent.localhost`)'",
		"traefik.http.routers.nvt-dev-app.service: 'nvt-dev-app'",
		"traefik.http.services.nvt-dev-app.loadbalancer.server.port: '3000'",
		"traefik.http.routers.nvt-dev-api.rule: 'Host(`api.nvt-dev.agent.localhost`)'",
		"traefik.http.routers.nvt-dev-api.service: 'nvt-dev-api'",
		"traefik.http.services.nvt-dev-api.loadbalancer.server.port: '8080'",
	}
	for _, fragment := range required {
		if !strings.Contains(rendered, fragment) {
			t.Fatalf("compose expose output missing %q\n%s", fragment, rendered)
		}
	}
}

func TestRenderedExposeComposeMergesWithCodeServerLabels(t *testing.T) {
	f := newFixture(t)
	config := f.writeAgentConfig(`
expose:
  http:
    - name: app
      targetPort: 3000
`)
	envFile := filepath.Join(f.home, "agent.env")
	composeEnv := []string{
		"AGENT_NAME=nvt-dev",
		"AGENT_HOST=nvt-dev.agent.localhost",
		"AGENT_ENV_FILE=" + envFile,
		"WORKSPACE_DIR=" + f.workspace,
		"NVT_WORKSPACE=/workspace",
		"CUSTOM_PLUGINS_DIR=" + filepath.Join(f.home, "custom-plugins"),
		"AGENT_CONFIG_FILE=" + config,
		"NVT_AGENT_CONFIG_FILE=/nvt-agent/agent.yaml",
		"CODEX_CONFIG_DIR=" + filepath.Join(f.home, "codex"),
		"CLAUDE_CONFIG_DIR=" + filepath.Join(f.home, "claude"),
	}
	if err := os.WriteFile(envFile, []byte(strings.Join(composeEnv, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	output := filepath.Join(f.home, "compose.expose.yaml")
	f.runWithEnv(renderAgentExposeBin(f.root), true, nil,
		"--agent-config", config,
		"--agent-name", "nvt-dev",
		"--agent-host", "nvt-dev.agent.localhost",
		"--output", output,
	)

	cmd := exec.Command("docker", "compose", "--env-file", envFile, "-f", filepath.Join(f.root, "compose.agent.yaml"), "-f", output, "config")
	cmd.Env = mergedEnv(composeEnv)
	mergedBytes, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose config failed: %v\n%s", err, mergedBytes)
	}
	merged := string(mergedBytes)
	dockerStart := strings.Index(merged, "\n  docker:\n")
	if dockerStart == -1 {
		t.Fatalf("merged compose output missing docker service\n%s", merged)
	}
	dockerRest := merged[dockerStart:]
	dockerEnd := strings.Index(dockerRest, "\nnetworks:")
	if dockerEnd == -1 {
		t.Fatalf("merged compose output missing top-level networks\n%s", merged)
	}
	dockerService := dockerRest[:dockerEnd]
	required := []string{
		"network_mode: service:docker",
		"traefik.enable: \"true\"",
		"traefik.http.routers.nvt-dev.rule: Host(`nvt-dev.agent.localhost`)",
		"traefik.http.routers.nvt-dev.entrypoints: web",
		"traefik.http.routers.nvt-dev.service: nvt-dev",
		"traefik.http.services.nvt-dev.loadbalancer.server.port: \"4090\"",
		"traefik.http.routers.nvt-dev-app.rule: Host(`app.nvt-dev.agent.localhost`)",
		"traefik.http.routers.nvt-dev-app.service: nvt-dev-app",
		"traefik.http.services.nvt-dev-app.loadbalancer.server.port: \"3000\"",
	}
	for _, fragment := range required {
		if !strings.Contains(merged, fragment) {
			t.Fatalf("merged compose output missing %q\n%s", fragment, merged)
		}
	}
	for _, fragment := range required[1:] {
		if !strings.Contains(dockerService, fragment) {
			t.Fatalf("docker service missing %q\n%s", fragment, dockerService)
		}
	}
}

func TestRenderAgentExposeValidationFailures(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "invalid-name",
			body: `
expose:
  http:
    - name: Bad_Name
      targetPort: 3000
`,
		},
		{
			name: "duplicate-name",
			body: `
expose:
  http:
    - name: app
      targetPort: 3000
    - name: app
      targetPort: 3001
`,
		},
		{
			name: "invalid-port",
			body: `
expose:
  http:
    - name: app
      targetPort: 70000
`,
		},
		{
			name: "unsupported-source",
			body: `
expose:
  http:
    - name: app
      targetPort: 3000
      source: docker
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			config := f.writeAgentConfig(tt.body)
			output := filepath.Join(f.home, "compose.expose.yaml")
			f.runWithEnv(renderAgentExposeBin(f.root), false, nil,
				"--agent-config", config,
				"--agent-name", "nvt-dev",
				"--agent-host", "nvt-dev.agent.localhost",
				"--output", output,
			)
		})
	}
}

func TestRenderAgentExposeParserAllowsCommentsAndQuotedValues(t *testing.T) {
	f := newFixture(t)
	config := f.writeAgentConfig(`
expose:
  http:
    # The renderer intentionally supports the block shape generated by templates.
    - name: "app" # quoted route name
      targetPort: "3000"
    - name: api
      targetPort: 8080 # inline comment
`)
	output := filepath.Join(f.home, "compose.expose.yaml")

	f.runWithEnv(renderAgentExposeBin(f.root), true, nil,
		"--agent-config", config,
		"--agent-name", "nvt-dev",
		"--agent-host", "nvt-dev.agent.localhost",
		"--output", output,
	)

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(data)
	if !strings.Contains(rendered, `"name":"app","targetPort":3000`) ||
		!strings.Contains(rendered, `"name":"api","targetPort":8080`) {
		t.Fatalf("parser did not render expected routes:\n%s", rendered)
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

func TestWriteAgentInstructionsComposesProfileThenLocalInstructions(t *testing.T) {
	f := newFixture(t)
	script := filepath.Join(f.root, "runtime", "core", "write-agent-instructions.sh")
	profileInstructions := filepath.Join(t.TempDir(), "profile.md")
	localInstructions := filepath.Join(f.workspace, "AGENTS.local.md")
	if err := os.WriteFile(profileInstructions, []byte("Profile workflow guidance.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localInstructions, []byte("Local workspace guidance.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	f.runWithEnv("bash "+shellQuote(script), true, []string{
		"NVT_AGENT_PROFILE_INSTRUCTIONS_FILE=" + profileInstructions,
	})
	data, err := os.ReadFile(filepath.Join(f.workspace, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	generated := string(data)
	core := strings.Index(generated, "## Runtime Context")
	profile := strings.Index(generated, "## Profile Workspace Instructions")
	local := strings.Index(generated, "## Local Workspace Instructions")
	if core < 0 || profile <= core || local <= profile ||
		!strings.Contains(generated, "Profile workflow guidance.") ||
		!strings.Contains(generated, "Local workspace guidance.") {
		t.Fatalf("unexpected instruction composition:\n%s", generated)
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
		"NVT_AGENT_LOCAL_INSTRUCTIONS=" + alias,
	})
	data, err := os.ReadFile(filepath.Join(f.workspace, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	generated := string(data)
	if strings.Count(generated, "One shared instruction layer.") != 1 ||
		strings.Count(generated, "## Profile Workspace Instructions") != 1 ||
		strings.Contains(generated, "## Local Workspace Instructions") {
		t.Fatalf("duplicate instruction paths were appended more than once:\n%s", generated)
	}

	empty := filepath.Join(t.TempDir(), "empty.md")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	f.runWithEnv("bash "+shellQuote(script), true, []string{
		"NVT_AGENT_PROFILE_INSTRUCTIONS_FILE=" + empty,
		"NVT_AGENT_LOCAL_INSTRUCTIONS=" + filepath.Join(t.TempDir(), "missing.md"),
	})
	data, err = os.ReadFile(filepath.Join(f.workspace, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	generated = string(data)
	if strings.Contains(generated, "## Profile Workspace Instructions") || strings.Contains(generated, "## Local Workspace Instructions") {
		t.Fatalf("missing or empty files created instruction sections:\n%s", generated)
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

func TestAgentInitRendersAutonomyArgs(t *testing.T) {
	root := repoRoot(t)
	tests := []struct {
		name     string
		typ      string
		autonomy string
		want     []string
	}{
		{
			name:     "codex-trusted-local",
			typ:      "codex",
			autonomy: "trusted-local",
			want: []string{
				"command: codex",
				`- "--sandbox"`,
				`- "danger-full-access"`,
				`- "--ask-for-approval"`,
				`- "never"`,
			},
		},
		{
			name:     "claude-trusted-local",
			typ:      "claude",
			autonomy: "trusted-local",
			want: []string{
				"command: claude",
				`- "--dangerously-skip-permissions"`,
			},
		},
		{
			name:     "codex-interactive",
			typ:      "codex",
			autonomy: "interactive",
			want: []string{
				"command: codex",
				"args: []",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			agentDir := filepath.Join(root, ".agents", tt.name)
			if err := os.RemoveAll(agentDir); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = os.RemoveAll(agentDir)
			})
			command := "HOME=" + shellQuote(home) + " bash " + shellQuote(filepath.Join(root, "scripts", "agent-init.sh"))
			cmd := commandWithEnv(command, nil,
				"--name", tt.name,
				"--type", tt.typ,
				"--autonomy", tt.autonomy,
			)
			cmd.Dir = root
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("agent-init failed: %v\n%s", err, output)
			}
			data, err := os.ReadFile(filepath.Join(agentDir, "agent.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			localInstructions, err := os.ReadFile(filepath.Join(agentDir, "workspace", "AGENTS.local.md"))
			if err != nil {
				t.Fatal(err)
			}
			config := string(data)
			for _, fragment := range tt.want {
				if !strings.Contains(config, fragment) {
					t.Fatalf("agent.yaml missing %q\n%s", fragment, config)
				}
			}
			if !strings.Contains(string(localInstructions), "Add workspace-specific agent guidance here.") {
				t.Fatalf("unexpected AGENTS.local.md:\n%s", localInstructions)
			}
		})
	}
}

func TestAgentInitRendersToolPreseed(t *testing.T) {
	root := repoRoot(t)
	tests := []struct {
		name string
		typ  string
		want []string
	}{
		{
			name: "codex",
			typ:  "codex",
			want: []string{
				"# BEGIN nvt-managed preseed (agent-init)",
				`path: "$HOME/.codex/config.toml"`,
				"overwrite: false",
				"check_for_update_on_startup = false",
			},
		},
		{
			name: "claude",
			typ:  "claude",
			want: []string{
				"# BEGIN nvt-managed preseed (agent-init)",
				`path: "$HOME/.claude/settings.json"`,
				"overwrite: false",
				"theme: dark-daltonized",
				"skipDangerousModePermissionPrompt: true",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			agentName := "preseed-" + tt.name
			agentDir := filepath.Join(root, ".agents", agentName)
			_ = os.RemoveAll(agentDir)
			t.Cleanup(func() { _ = os.RemoveAll(agentDir) })
			command := "HOME=" + shellQuote(home) + " bash " + shellQuote(filepath.Join(root, "scripts", "agent-init.sh"))
			cmd := commandWithEnv(command, nil, "--name", agentName, "--type", tt.typ)
			cmd.Dir = root
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("agent-init failed: %v\n%s", err, output)
			}
			config := mustReadFile(t, filepath.Join(agentDir, "agent.yaml"))
			for _, want := range tt.want {
				if !strings.Contains(config, want) {
					t.Fatalf("agent.yaml missing %q\n%s", want, config)
				}
			}
		})
	}
}

func TestAgentInitRejectsInvalidAutonomy(t *testing.T) {
	root := repoRoot(t)
	home := t.TempDir()
	command := "HOME=" + shellQuote(home) + " bash " + shellQuote(filepath.Join(root, "scripts", "agent-init.sh"))
	cmd := commandWithEnv(command, nil,
		"--name", "bad-autonomy",
		"--type", "codex",
		"--autonomy", "unsafe",
	)
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("agent-init unexpectedly succeeded:\n%s", output)
	}
	if !strings.Contains(string(output), "autonomy must be trusted-local or interactive") {
		t.Fatalf("unexpected output:\n%s", output)
	}
}

func TestAgentInitMediatedKeepsEgressTokenOutOfAgentEnv(t *testing.T) {
	root := repoRoot(t)
	name := "mediated-env-boundary"
	agentDir := filepath.Join(root, ".agents", name)
	if err := os.RemoveAll(agentDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(agentDir) })
	agentsFile := preserveBrokerAgentsFile(t, root)
	mustWriteFile(t, agentsFile, `agents:
- id: mediated-env-boundary
  token-sha256: sha256:0000000000000000000000000000000000000000000000000000000000000000
  grants:
    - provider: codex-main
      materialization: placeholder-file
      egress-hosts:
        - chatgpt.com:443
    - provider: api-main
      materialization: header-inject
      egress-hosts:
        - api.example.test:443
      repositories:
        - example/repo
`)
	home := t.TempDir()
	caInitBin := buildEgressCAInit(t, root)
	command := "HOME=" + shellQuote(home) + " NVT_EGRESS_CA_INIT_BIN=" + shellQuote(caInitBin) + " MEDIATED=1 NVT_EGRESS_ALLOW_INSECURE_BROKER=1 bash " + shellQuote(filepath.Join(root, "scripts", "agent-init.sh"))
	cmd := commandWithEnv(command, nil, "--name", name)
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("agent-init failed: %v\n%s", err, output)
	}
	agentEnv := mustReadFile(t, filepath.Join(agentDir, "env"))
	if strings.Contains(agentEnv, "NVT_EGRESS_BROKER_TOKEN") || strings.Contains(agentEnv, "EGRESS_CA_KEY_FILE") || strings.Contains(agentEnv, "EGRESS_CA_DIR") {
		t.Fatalf("agent env leaked egress-only material:\n%s", agentEnv)
	}
	egressEnv := mustReadFile(t, filepath.Join(agentDir, "egressd.env"))
	if !strings.Contains(egressEnv, "NVT_BROKER_TOKEN=") {
		t.Fatalf("egressd env missing broker token:\n%s", egressEnv)
	}
	if !strings.Contains(egressEnv, "EGRESS_CA_KEY_FILE=") {
		t.Fatalf("egressd env missing CA key path for compose interpolation:\n%s", egressEnv)
	}
	egressConfig := mustReadFile(t, filepath.Join(agentDir, "egressd.json"))
	if !strings.Contains(egressConfig, `"upstream": "api.example.test:443"`) || strings.Contains(egressConfig, "placeholder.local") {
		t.Fatalf("unexpected egressd config:\n%s", egressConfig)
	}
}

func TestAgentInitMediatedRejectsMissingRouteHostsAndMultipleGrants(t *testing.T) {
	root := repoRoot(t)
	tests := []struct {
		name   string
		agents string
		want   string
	}{
		{
			name: "mediated-missing-route",
			agents: `agents:
- id: mediated-missing-route
  token-sha256: sha256:0000000000000000000000000000000000000000000000000000000000000000
  grants:
    - provider: api-main
      materialization: header-inject
      repositories: [example/repo]
`,
			want: "egress-hosts",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agentDir := filepath.Join(root, ".agents", tt.name)
			if err := os.RemoveAll(agentDir); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(agentDir) })
			agentsFile := preserveBrokerAgentsFile(t, root)
			mustWriteFile(t, agentsFile, tt.agents)
			home := t.TempDir()
			command := "HOME=" + shellQuote(home) + " MEDIATED=1 NVT_EGRESS_ALLOW_INSECURE_BROKER=1 bash " + shellQuote(filepath.Join(root, "scripts", "agent-init.sh"))
			cmd := commandWithEnv(command, nil, "--name", tt.name)
			cmd.Dir = root
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("agent-init unexpectedly succeeded:\n%s", output)
			}
			if !strings.Contains(string(output), tt.want) {
				t.Fatalf("expected %q in output:\n%s", tt.want, output)
			}
			if _, err := os.Stat(filepath.Join(agentDir, "egressd.json")); err == nil {
				t.Fatalf("mediated invalid route wrote egressd config")
			}
			if _, err := os.Stat(filepath.Join(agentDir, "egressd.env")); err == nil {
				t.Fatalf("mediated invalid route wrote egressd env")
			}
		})
	}
}

// TestAgentInitMediatedRendersMultiRouteWithGitCA pins the mediated Compose
// shape: multiple header-inject grants each get their own listener port, a
// git grant's route terminates TLS under the boot-generated CA, and the CA
// certificate publish dir matches the shared compose volume.
func TestAgentInitMediatedRendersMultiRouteWithGitCA(t *testing.T) {
	root := repoRoot(t)
	name := "mediated-multi-route"
	agentDir := filepath.Join(root, ".agents", name)
	if err := os.RemoveAll(agentDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(agentDir) })
	agentsFile := preserveBrokerAgentsFile(t, root)
	mustWriteFile(t, agentsFile, `agents:
- id: mediated-multi-route
  token-sha256: sha256:0000000000000000000000000000000000000000000000000000000000000000
  grants:
    - provider: codex-main
      materialization: placeholder-file
      egress-hosts: [chatgpt.com:443]
    - provider: api-main
      materialization: header-inject
      egress-hosts: [api.example.test:443]
      repositories: [example/repo]
    - provider: git-app
      materialization: header-inject
      egress-hosts: [github.com:443]
      git: true
      permissions:
        contents: write
      repositories: [example/repo]
`)
	home := t.TempDir()
	caInitBin := buildEgressCAInit(t, root)
	command := "HOME=" + shellQuote(home) + " NVT_EGRESS_CA_INIT_BIN=" + shellQuote(caInitBin) + " MEDIATED=1 NVT_EGRESS_ALLOW_INSECURE_BROKER=1 bash " + shellQuote(filepath.Join(root, "scripts", "agent-init.sh"))
	cmd := commandWithEnv(command, nil, "--name", name)
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("agent-init failed: %v\n%s", err, output)
	}
	var config struct {
		Routes       []map[string]any `json:"routes"`
		ForwardProxy struct {
			Listen              string           `json:"listen"`
			TransparentMode     bool             `json:"transparent_mode"`
			AllowUnmatchedHosts bool             `json:"allow_unmatched_hosts"`
			AllowPorts          []int            `json:"allow_ports"`
			InjectRoutes        []map[string]any `json:"inject_routes"`
		} `json:"forward_proxy"`
		CA map[string]any `json:"ca"`
	}
	decodeJSONFile(t, filepath.Join(agentDir, "egressd.json"), &config)
	if len(config.Routes) != 0 {
		t.Fatalf("compose mediated egress should use forward_proxy routes, got %#v", config.Routes)
	}
	if config.ForwardProxy.Listen != "0.0.0.0:8470" || len(config.ForwardProxy.InjectRoutes) != 3 {
		t.Fatalf("unexpected forward proxy config: %#v", config.ForwardProxy)
	}
	if !config.ForwardProxy.AllowUnmatchedHosts {
		t.Fatal("local compose forward proxy should blind-tunnel unmatched hosts for dev egress")
	}
	if !config.ForwardProxy.TransparentMode || !reflect.DeepEqual(config.ForwardProxy.AllowPorts, []int{80, 443}) {
		t.Fatalf("local transparent port contract missing: %#v", config.ForwardProxy)
	}
	codex, api, git := config.ForwardProxy.InjectRoutes[0], config.ForwardProxy.InjectRoutes[1], config.ForwardProxy.InjectRoutes[2]
	if codex["host"] != "chatgpt.com" || codex["capability"] != "codex-main" || codex["upstream"] != "chatgpt.com:443" {
		t.Fatalf("unexpected codex inject route: %#v", codex)
	}
	if api["host"] != "api.example.test" || api["capability"] != "api-main" || api["upstream"] != "api.example.test:443" {
		t.Fatalf("unexpected api inject route: %#v", api)
	}
	if git["host"] != "github.com" || git["capability"] != "git-app" || git["upstream"] != "github.com:443" {
		t.Fatalf("unexpected git inject route: %#v", git)
	}
	if git["require_capability_hint"] != true {
		t.Fatalf("git inject route must require an explicit provider hint: %#v", git)
	}
	if config.CA["cert_file"] != "/etc/nvt-egress-ca/ca.crt" || config.CA["key_file"] != "/etc/nvt-egress-ca/ca.key" {
		t.Fatalf("unexpected durable CA config: %#v", config.CA)
	}
	if _, ok := config.CA["publish_dir"]; ok {
		t.Fatalf("local durable CA config should not rely on egressd republishing the cert: %#v", config.CA)
	}
	certPath := filepath.Join(agentDir, "egress-ca", "ca.crt")
	keyPath := filepath.Join(agentDir, "egress-ca", "ca.key")
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read durable CA cert: %v", err)
	}
	if !strings.Contains(string(certBytes), "BEGIN CERTIFICATE") {
		t.Fatalf("durable CA cert is not PEM:\n%s", certBytes)
	}
	if info, err := os.Stat(certPath); err != nil {
		t.Fatalf("stat durable CA cert: %v", err)
	} else if info.Mode().Perm() != 0o644 {
		t.Fatalf("durable CA cert mode = %v, want 0644", info.Mode().Perm())
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read durable CA key: %v", err)
	}
	if !strings.Contains(string(keyBytes), "BEGIN EC PRIVATE KEY") {
		t.Fatalf("durable CA key is not EC PEM")
	}
	if info, err := os.Stat(keyPath); err != nil {
		t.Fatalf("stat durable CA key: %v", err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("durable CA key mode = %v, want 0600", info.Mode().Perm())
	}
	egressEnv := mustReadFile(t, filepath.Join(agentDir, "egressd.env"))
	if !strings.Contains(egressEnv, "EGRESS_CA_KEY_FILE="+keyPath) {
		t.Fatalf("egressd env missing private key path:\n%s", egressEnv)
	}
	agentEnv := mustReadFile(t, filepath.Join(agentDir, "env"))
	if strings.Contains(agentEnv, "EGRESS_CA_KEY_FILE") || strings.Contains(agentEnv, "EGRESS_CA_DIR") {
		t.Fatalf("agent env leaked egress CA private path:\n%s", agentEnv)
	}
	firstFingerprint := sha256.Sum256(certBytes)

	// The agent config must carry the same grant metadata bootstrap needs:
	// forward-proxy mode plus provider/host metadata. Without this block the
	// sidecar starts but runtime proxy and tool wiring never happen.
	agentConfig := mustReadFile(t, filepath.Join(agentDir, "agent.yaml"))
	for _, fragment := range []string{
		"runtime:",
		"  proxy:",
		"    provider: codex-main",
		"egress:",
		"  mode: mediated",
		"  transport: transparent",
		"  forward-proxy-url: http://127.0.0.1:15002",
		"    - provider: codex-main",
		"      materialization: placeholder-file",
		"      - chatgpt.com:443",
		"    - provider: api-main",
		"      egress-hosts:",
		"      - api.example.test:443",
		"    - provider: git-app",
		"      materialization: header-inject",
		"      - github.com:443",
		"      git: true",
	} {
		if !strings.Contains(agentConfig, fragment) {
			t.Fatalf("agent.yaml missing egress fragment %q:\n%s", fragment, agentConfig)
		}
	}

	// Re-running agent-init replaces the managed block instead of stacking
	// duplicates.
	rerun := commandWithEnv(command, nil, "--name", name)
	rerun.Dir = root
	if rerunOutput, err := rerun.CombinedOutput(); err != nil {
		t.Fatalf("agent-init re-run failed: %v\n%s", err, rerunOutput)
	}
	rerunCertBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read durable CA cert after rerun: %v", err)
	}
	if got := sha256.Sum256(rerunCertBytes); got != firstFingerprint {
		t.Fatalf("agent-init rerun changed durable CA fingerprint")
	}
	agentConfig = mustReadFile(t, filepath.Join(agentDir, "agent.yaml"))
	if got := strings.Count(agentConfig, "BEGIN nvt-managed egress"); got != 1 {
		t.Fatalf("managed egress block rendered %d times:\n%s", got, agentConfig)
	}
}

func TestAgentUpMigratesPreTransparentManagedEgress(t *testing.T) {
	root := repoRoot(t)
	name := "upgrade-managed-egress"
	agentDir := filepath.Join(root, ".agents", name)
	_ = os.RemoveAll(agentDir)
	t.Cleanup(func() { _ = os.RemoveAll(agentDir) })
	if err := os.MkdirAll(agentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	agentsFile := preserveBrokerAgentsFile(t, root)
	mustWriteFile(t, agentsFile, `agents:
- id: upgrade-managed-egress
  grants:
    - provider: api-main
      materialization: header-inject
      egress-hosts: [api.example.test:443]
      git: true
`)
	configPath := filepath.Join(agentDir, "agent.yaml")
	mustWriteFile(t, configPath, `runtime:
  command: bash
user-owned: keep-me
# BEGIN nvt-managed egress (agent-init)
egress:
  mode: mediated
  placeholder: NVT-PLACEHOLDER-NOT-A-KEY
  # Pre-transport managed content must be replaced, not interpreted.
  forward-proxy: true
  forward-proxy-url: http://127.0.0.1:8470
  grants:
    - provider: api-main
      materialization: header-inject
# END nvt-managed egress (agent-init)
tools: {packages: [], mise: [], additional-paths: [], shell: []}
code-server: {extensions: []}
`)
	egressdPath := filepath.Join(agentDir, "egressd.json")
	mustWriteFile(t, egressdPath, `{"routes":[],"forward_proxy":{"listen":"0.0.0.0:8470","allow_unmatched_hosts":true,"allow_ports":[443],"inject_routes":[{"host":"api.example.test","capability":"api-main","upstream":"api.example.test:443"}]}}`)
	envPath := filepath.Join(agentDir, "env")
	mustWriteFile(t, envPath, strings.Join([]string{
		"AGENT_NAME=" + name,
		"AGENT_HOST=" + name + ".agent.localhost",
		"AGENT_CONFIG_FILE=" + configPath,
		"EGRESSD_CONFIG_FILE=" + egressdPath,
		"MEDIATED=1",
		"NVT_WORKSPACE=/workspace",
	}, "\n")+"\n")
	binDir := t.TempDir()
	dockerLog := filepath.Join(binDir, "docker.calls")
	mustWriteExecutable(t, filepath.Join(binDir, "docker"), "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> "+shellQuote(dockerLog)+"\nexit 0\n")

	for range 2 {
		cmd := exec.Command("bash", filepath.Join(root, "scripts", "agent-up.sh"), "--name", name)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("agent-up migration failed: %v\n%s", err, output)
		}
	}
	config := mustReadFile(t, configPath)
	for _, want := range []string{"user-owned: keep-me", "transport: transparent", "forward-proxy-url: http://127.0.0.1:15002"} {
		if !strings.Contains(config, want) {
			t.Fatalf("migrated config missing %q:\n%s", want, config)
		}
	}
	if strings.Contains(config, "\n  forward-proxy:") {
		t.Fatalf("managed migration retained the removed selector:\n%s", config)
	}
	if strings.Contains(config, "forward-proxy-url: http://127.0.0.1:8470") || strings.Count(config, "BEGIN nvt-managed egress") != 1 {
		t.Fatalf("managed migration was not idempotent:\n%s", config)
	}
	var egressd struct {
		ForwardProxy struct {
			TransparentMode bool             `json:"transparent_mode"`
			AllowPorts      []int            `json:"allow_ports"`
			InjectRoutes    []map[string]any `json:"inject_routes"`
		} `json:"forward_proxy"`
	}
	if err := json.Unmarshal([]byte(mustReadFile(t, egressdPath)), &egressd); err != nil {
		t.Fatal(err)
	}
	if !egressd.ForwardProxy.TransparentMode || !reflect.DeepEqual(egressd.ForwardProxy.AllowPorts, []int{80, 443}) {
		t.Fatalf("egressd upgrade migration incomplete: %#v", egressd.ForwardProxy)
	}
	if len(egressd.ForwardProxy.InjectRoutes) != 1 || egressd.ForwardProxy.InjectRoutes[0]["require_capability_hint"] != true {
		t.Fatalf("git route migration did not require an explicit provider hint: %#v", egressd.ForwardProxy.InjectRoutes)
	}
	if calls := mustReadFile(t, dockerLog); !strings.Contains(calls, "compose") || !strings.Contains(calls, "up -d") {
		t.Fatalf("agent-up did not continue to Compose after migration:\n%s", calls)
	}

	unmarked := filepath.Join(t.TempDir(), "agent.yaml")
	mustWriteFile(t, unmarked, "runtime: {command: bash}\negress: {mode: mediated, forward-proxy-url: http://user-proxy:9999}\n")
	before := mustReadFile(t, unmarked)
	cmd := exec.Command("python3", filepath.Join(root, "scripts", "render-managed-egress.py"),
		"--agent-config", unmarked, "--broker-agents", agentsFile, "--agent-name", name, "--mode", "mediated")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("unmarked migration failed: %v\n%s", err, output)
	}
	if after := mustReadFile(t, unmarked); after != before {
		t.Fatalf("agent-up renderer changed user-authored config:\nbefore=%s\nafter=%s", before, after)
	}
}

func TestAgentInitMediatedRequiresUnsafeLocalBrokerFlag(t *testing.T) {
	root := repoRoot(t)
	name := "mediated-unsafe-flag"
	agentDir := filepath.Join(root, ".agents", name)
	if err := os.RemoveAll(agentDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(agentDir) })
	agentsFile := preserveBrokerAgentsFile(t, root)
	mustWriteFile(t, agentsFile, `agents:
- id: mediated-unsafe-flag
  token-sha256: sha256:0000000000000000000000000000000000000000000000000000000000000000
  grants:
    - provider: codex-main
      materialization: header-inject
      egress-hosts: [api.example.test:443]
      repositories: [example/repo]
`)
	home := t.TempDir()
	command := "HOME=" + shellQuote(home) + " MEDIATED=1 NVT_EGRESS_ALLOW_INSECURE_BROKER=0 bash " + shellQuote(filepath.Join(root, "scripts", "agent-init.sh"))
	cmd := commandWithEnv(command, nil, "--name", name)
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("agent-init unexpectedly succeeded:\n%s", output)
	}
	if !strings.Contains(string(output), "NVT_EGRESS_ALLOW_INSECURE_BROKER=1") {
		t.Fatalf("expected unsafe local broker flag error:\n%s", output)
	}
	if _, err := os.Stat(filepath.Join(agentDir, "egressd.env")); err == nil {
		t.Fatalf("unsafe local broker rejection wrote egressd env")
	}
}

// TestComposeAgentUserModeParameterized pins that the compose agent service
// parameterizes user/HOME/state so root stays the default and non-root is
// selectable, and that the auth/home mounts follow HOME.
func TestComposeAgentUserModeParameterized(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "compose.agent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	compose := string(data)
	for _, fragment := range []string{
		"user: ${AGENT_RUN_USER:-0:0}",
		"HOME: ${AGENT_HOME:-/root}",
		"NVT_STATE_DIR: ${AGENT_HOME:-/root}/.nvt-agent",
		"${CODEX_CONFIG_DIR}:${AGENT_HOME:-/root}/.codex",
		"agent-home:${AGENT_HOME:-/root}",
	} {
		if !strings.Contains(compose, fragment) {
			t.Fatalf("compose.agent.yaml missing %q", fragment)
		}
	}
	// The hardcoded root home targets must be gone.
	if strings.Contains(compose, "agent-home:/root") || strings.Contains(compose, ":/root/.codex") {
		t.Fatalf("compose.agent.yaml still hardcodes /root home targets:\n%s", compose)
	}
}

// TestAgentInitRendersRuntimeUser pins the --user knob: default root (0:0,
// /root) and opt-in non-root (1000:1000, /home/agent).
func TestAgentInitRendersRuntimeUser(t *testing.T) {
	root := repoRoot(t)
	tests := []struct {
		name    string
		args    []string
		user    string
		runUser string
		home    string
	}{
		{name: "default-root", args: nil, user: "user: root", runUser: "AGENT_RUN_USER=0:0", home: "AGENT_HOME=/root"},
		{name: "opt-in-non-root", args: []string{"--user", "non-root"}, user: "user: non-root", runUser: "AGENT_RUN_USER=1000:1000", home: "AGENT_HOME=/home/agent"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			agentDir := filepath.Join(root, ".agents", "user-"+tt.name)
			_ = os.RemoveAll(agentDir)
			t.Cleanup(func() { _ = os.RemoveAll(agentDir) })
			command := "HOME=" + shellQuote(home) + " bash " + shellQuote(filepath.Join(root, "scripts", "agent-init.sh"))
			args := append([]string{"--name", "user-" + tt.name, "--type", "claude"}, tt.args...)
			cmd := commandWithEnv(command, nil, args...)
			cmd.Dir = root
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("agent-init failed: %v\n%s", err, output)
			}
			config, err := os.ReadFile(filepath.Join(agentDir, "agent.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(config), tt.user) {
				t.Fatalf("agent.yaml missing %q\n%s", tt.user, config)
			}
			env, err := os.ReadFile(filepath.Join(agentDir, "env"))
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{tt.runUser, tt.home} {
				if !strings.Contains(string(env), want) {
					t.Fatalf("env missing %q\n%s", want, env)
				}
			}
		})
	}
}

// TestAgentInitRejectsInvalidUser pins the --user validation.
func TestAgentInitRejectsInvalidUser(t *testing.T) {
	root := repoRoot(t)
	home := t.TempDir()
	command := "HOME=" + shellQuote(home) + " bash " + shellQuote(filepath.Join(root, "scripts", "agent-init.sh"))
	cmd := commandWithEnv(command, nil, "--name", "bad-user", "--user", "wheel")
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("agent-init unexpectedly succeeded:\n%s", output)
	}
	if !strings.Contains(string(output), "user must be root or non-root") {
		t.Fatalf("unexpected output:\n%s", output)
	}
}

// TestBootstrapAcceptsNonRootUserAndUsesHome pins that runtime.user: non-root
// is accepted and that bootstrap writes state under $HOME (not a hardcoded
// /root) — the fixture HOME is a temp dir, so a /root assumption would fail.
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

// TestAgentInitSwitchesExistingUserMode pins review finding 1: re-running
// agent-init --user on an EXISTING agent actually switches it — the env
// (compose user + HOME) and agent.yaml runtime.user both flip, so a switch to
// non-root does not silently keep running root.
func TestAgentInitSwitchesExistingUserMode(t *testing.T) {
	root := repoRoot(t)
	home := t.TempDir()
	agentDir := filepath.Join(root, ".agents", "switch-mode")
	_ = os.RemoveAll(agentDir)
	t.Cleanup(func() { _ = os.RemoveAll(agentDir) })

	run := func(args ...string) {
		command := "HOME=" + shellQuote(home) + " bash " + shellQuote(filepath.Join(root, "scripts", "agent-init.sh"))
		full := append([]string{"--name", "switch-mode", "--type", "claude"}, args...)
		cmd := commandWithEnv(command, nil, full...)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("agent-init failed: %v\n%s", err, out)
		}
	}
	assertContains := func(file string, wants ...string) {
		data, err := os.ReadFile(filepath.Join(agentDir, file))
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range wants {
			if !strings.Contains(string(data), want) {
				t.Fatalf("%s missing %q\n%s", file, want, data)
			}
		}
	}

	run() // create as root
	assertContains("env", "AGENT_RUN_USER=0:0", "AGENT_HOME=/root")
	assertContains("agent.yaml", "user: root")

	run("--user", "non-root") // switch the existing agent
	assertContains("env", "AGENT_RUN_USER=1000:1000", "AGENT_HOME=/home/agent")
	assertContains("agent.yaml", "user: non-root")

	run("--user", "root") // switch back
	assertContains("env", "AGENT_RUN_USER=0:0", "AGENT_HOME=/root")
	assertContains("agent.yaml", "user: root")
}

// TestBootstrapInstallsPackagesViaNvtAsRoot pins that apt package install goes
// through nvt-as-root (so it works under both root and non-root) rather than a
// bare apt-get that would fail as the non-root agent.
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

func mustWriteExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func buildEgressCAInit(t *testing.T, root string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "egress-ca-init")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/egress-ca-init")
	cmd.Dir = filepath.Join(root, "egressd")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build egress-ca-init: %v\n%s", err, out)
	}
	return bin
}
