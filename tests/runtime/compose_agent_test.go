package runtime_test

import (
	"os"
	"os/exec"
	"path/filepath"
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
	}
	for _, fragment := range required {
		if !strings.Contains(compose, fragment) {
			t.Fatalf("compose.agent.yaml missing %q\n%s", fragment, compose)
		}
	}
	if strings.Contains(compose, "/var/run/docker.sock:") {
		t.Fatalf("compose.agent.yaml must not mount the host Docker socket")
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
	if err := os.WriteFile(envFile, []byte(strings.Join([]string{
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
	}, "\n")+"\n"), 0o600); err != nil {
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
	cmd.Env = os.Environ()
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
	if string(data) != "set -g mouse on\n" {
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
			data, err := os.ReadFile(filepath.Join(root, ".agents", tt.name, "agent.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = os.RemoveAll(filepath.Join(root, ".agents", tt.name))
			})
			config := string(data)
			for _, fragment := range tt.want {
				if !strings.Contains(config, fragment) {
					t.Fatalf("agent.yaml missing %q\n%s", fragment, config)
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
