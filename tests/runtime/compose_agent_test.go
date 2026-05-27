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
