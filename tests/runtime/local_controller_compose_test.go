package runtime_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalControllerIsTheOnlyLocalRunComponentWithDockerAuthority(t *testing.T) {
	root := repoRoot(t)
	makefile, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(makefile), "local-controller-build:\n\tbash scripts/local-controller-build.sh\n") {
		t.Fatalf("Makefile has no local controller image target")
	}
	infraUp, err := os.ReadFile(filepath.Join(root, "scripts", "infra-up.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"local-controller-admin-token", "local-controller-route-token", "local-controller.yaml", "NVT_LOCAL_CONTROLLER_CONFIG=/broker-state/local-controller.yaml", `export NVT_LOCAL_GATEWAY_UID="$(id -u)"`, `openssl rand -hex 32`} {
		if !strings.Contains(string(infraUp), required) {
			t.Fatalf("infra-up does not provision private local API credentials: missing %q", required)
		}
	}
	for _, forbidden := range []string{"NVT_LOCAL_CONTROLLER_SCHEDULING_CONFIG", "NVT_LOCAL_CONTROLLER_NAMED_RUNS_CONFIG", "local-controller.json"} {
		if strings.Contains(string(infraUp), forbidden) {
			t.Fatalf("infra-up retained legacy local authoring %q", forbidden)
		}
	}
	data, err := os.ReadFile(filepath.Join(root, "compose.infra.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	compose := string(data)
	protocolDocument, err := os.ReadFile(filepath.Join(root, "protocol", "local-controller.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(protocolDocument), "token_file: /broker-state/github-comments-producer-token") ||
		strings.Contains(string(protocolDocument), "token_file: /run/secrets/nvt-local-controller/producer-token") {
		t.Fatal("documented producer token path is not reachable through the shipped broker-state mount")
	}
	start := strings.Index(compose, "\n  local-controller:\n")
	if start == -1 {
		t.Fatalf("compose infrastructure has no local controller:\n%s", compose)
	}
	service := compose[start:]
	if end := strings.Index(service, "\nnetworks:\n"); end >= 0 {
		service = service[:end]
	}
	for _, required := range []string{
		"image: nvt-local-controller:latest",
		"NVT_LOCAL_CONTROLLER_BIND: 0.0.0.0:7480",
		"NVT_LOCAL_CONTROLLER_STATE: /state/controller/local-controller.sqlite3",
		"NVT_LOCAL_CONTROLLER_MAX_CLAIM_LEASE_SECONDS: ${NVT_LOCAL_CONTROLLER_MAX_CLAIM_LEASE_SECONDS:-180}",
		"NVT_LOCAL_CONTROLLER_BACKEND_TIMEOUT_SECONDS: ${NVT_LOCAL_CONTROLLER_BACKEND_TIMEOUT_SECONDS:-120}",
		"NVT_LOCAL_CONTROLLER_RUN_NETWORK_POOL: ${NVT_LOCAL_CONTROLLER_RUN_NETWORK_POOL:-100.64.0.0/10}",
		"NVT_LOCAL_CONTROLLER_DOCKER_HOST: unix:///var/run/docker.sock",
		"NVT_LOCAL_CONTROLLER_BROKER_AGENTS: /broker-state/agents.yaml",
		"NVT_LOCAL_CONTROLLER_IDENTITY_KEY_FILE: /controller-private/local-controller.key",
		"NVT_LOCAL_CONTROLLER_DIND_PROTECTED_CIDRS:",
		"NVT_LOCAL_CONTROLLER_PROXY_PORT:",
		"NVT_LOCAL_CONTROLLER_ROUTE_BASE_DOMAIN: agent.localhost",
		"NVT_LOCAL_CONTROLLER_ROUTE_PATH_PREFIX: /agents",
		"NVT_LOCAL_CONTROLLER_GATEWAY_CONTAINER: nvt-local-gateway",
		"NVT_LOCAL_CONTROLLER_CONFIG:",
		"NVT_LOCAL_CONTROLLER_ADMIN_TOKEN_FILE: /controller-private/local-controller-admin-token",
		"NVT_LOCAL_CONTROLLER_ROUTE_TOKEN_FILE: /controller-private/local-controller-route-token",
		"local-controller-state:/state",
		"./.broker:/broker-state",
		"local-controller-private:/controller-private:ro",
		"/var/run/docker.sock:/var/run/docker.sock",
		"- local-control-plane",
		"read_only: true",
	} {
		if !strings.Contains(service, required) {
			t.Fatalf("local controller service missing %q:\n%s", required, service)
		}
	}
	for _, forbidden := range []string{"privileged:", "cap_add:", "env_file:", "secrets:"} {
		if strings.Contains(service, forbidden) {
			t.Fatalf("local controller received forbidden Docker authority %q:\n%s", forbidden, service)
		}
	}
	gatewayStart := strings.Index(compose, "\n  gateway:\n")
	if gatewayStart == -1 {
		t.Fatalf("compose infrastructure has no local gateway:\n%s", compose)
	}
	gateway := compose[gatewayStart:]
	if end := strings.Index(gateway, "\n  local-controller:\n"); end >= 0 {
		gateway = gateway[:end]
	}
	for _, required := range []string{
		"image: nvt-agent-gateway:latest",
		"container_name: nvt-local-gateway",
		`user: "${NVT_LOCAL_GATEWAY_UID:-65532}:${NVT_LOCAL_GATEWAY_GID:-65532}"`,
		`NVT_GATEWAY_LOCAL_RUNS_ENABLED: "true"`,
		`NVT_GATEWAY_LOCAL_RUNS_DISABLE_KUBERNETES: "true"`,
		"NVT_GATEWAY_LOCAL_RUNS_CONTROLLER_URL: http://local-controller:7480",
		"NVT_GATEWAY_LOCAL_RUNS_TOKEN_FILE: /run/secrets/local-controller-route-token",
		"local-gateway-private:/run/secrets:ro",
		"nvt.dev/local-gateway=true",
		"traefik.http.routers.nvt-local-gateway.rule=Host(`localhost`) && (PathPrefix(`/agents`) || PathPrefix(`/oauth2`) || PathPrefix(`/healthz/branding/`))",
		"traefik.http.routers.nvt-local-gateway-host.rule=HostRegexp(",
		"traefik.http.routers.nvt-local-gateway-exposure.rule=HostRegexp(",
		"- agents-proxy",
		"- local-control-plane",
		"read_only: true",
	} {
		if !strings.Contains(gateway, required) {
			t.Fatalf("local gateway missing %q:\n%s", required, gateway)
		}
	}
	for _, forbidden := range []string{"/var/run/docker.sock", "/broker-state", "local-controller-admin-token", "privileged:", "cap_add:"} {
		if strings.Contains(gateway, forbidden) {
			t.Fatalf("local gateway received forbidden authority %q:\n%s", forbidden, gateway)
		}
	}
	proxyStart := strings.Index(compose, "\n  proxy:\n")
	proxyEnd := strings.Index(compose, "\n  gateway:\n")
	if proxyStart == -1 || proxyEnd <= proxyStart || strings.Contains(compose[proxyStart:proxyEnd], "local-agents") || strings.Contains(compose[proxyStart:proxyEnd], ":8081") {
		t.Fatalf("shared proxy retained an agent-reachable private entrypoint:\n%s", compose)
	}
	if !strings.Contains(compose[proxyStart:proxyEnd], "restart: unless-stopped") {
		t.Fatalf("shared proxy will not recover after a Docker daemon restart:\n%s", compose[proxyStart:proxyEnd])
	}
	if strings.Contains(service, "networks:\n      - agents-proxy") || strings.Contains(service, "ports:") {
		t.Fatalf("local controller is exposed outside its trusted control-plane network:\n%s", service)
	}
	if !strings.Contains(compose, "\n  local-control-plane:\n    internal: true\n") {
		t.Fatalf("compose infrastructure has no internal controller network:\n%s", compose)
	}
	if !strings.Contains(compose, "\n  local-controller-state:\n") {
		t.Fatalf("compose infrastructure has no durable controller state volume:\n%s", compose)
	}
	if !strings.Contains(compose, "\n  local-controller-private:\n") {
		t.Fatalf("compose infrastructure has no private controller credential volume:\n%s", compose)
	}
	if !strings.Contains(compose, "\n  local-gateway-private:\n") {
		t.Fatalf("compose infrastructure has no private gateway credential volume:\n%s", compose)
	}
	privateInitStart := strings.Index(compose, "\n  local-controller-private-init:\n")
	if privateInitStart == -1 || privateInitStart >= gatewayStart {
		t.Fatalf("compose infrastructure has no controller credential initializer:\n%s", compose)
	}
	privateInit := compose[privateInitStart:gatewayStart]
	for _, required := range []string{
		"image: nvt-local-controller:latest",
		"network_mode: none",
		"./.broker:/source:ro",
		"local-controller-private:/private",
		"local-gateway-private:/gateway-private",
		"chmod 0600 /private/local-controller.key.next",
		"chmod 0600 /private/local-controller-admin-token.next",
		"chmod 0600 /private/local-controller-route-token.next",
		"chmod 0400 /gateway-private/local-controller-route-token.next",
	} {
		if !strings.Contains(privateInit, required) {
			t.Fatalf("controller credential initializer missing %q:\n%s", required, privateInit)
		}
	}

	dockerfileBytes, err := os.ReadFile(filepath.Join(root, "localcontroller", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(dockerfileBytes)
	for _, required := range []string{
		"COPY protocol/localroutes ./protocol/localroutes",
		"COPY protocol/resolvedrun ./protocol/resolvedrun",
		"COPY localcontroller ./localcontroller",
		"CGO_ENABLED=0 GOOS=linux go build",
		"FROM docker:27-cli",
		"RUN install -d -m 0700 /state",
		"USER root",
		`ENTRYPOINT ["/nvt-local-controller"]`,
	} {
		if !strings.Contains(dockerfile, required) {
			t.Fatalf("local controller Dockerfile missing %q:\n%s", required, dockerfile)
		}
	}
}

func TestLocalCredentialPortalComposeIsOptionalAndPrivate(t *testing.T) {
	root := repoRoot(t)
	composeBytes, err := os.ReadFile(filepath.Join(root, "compose.infra.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	compose := string(composeBytes)
	for _, required := range []string{
		"profiles: [credentials]", "credential-portal:", "credential-runner:",
		"local-credential-seeds:/seed", "local-credential-seeds:/portal-seed:ro",
		"local-broker-private:/private", "NVT_BROKER_SEED_TARGET_DIR: portal",
		"PathPrefix(`/agents/credentials`)", "NVT_GATEWAY_CREDENTIAL_PORTAL_URL:",
		"NVT_BROKER_SEED_DIR: ${NVT_BROKER_CREDENTIAL_SEED_DIR:-}",
		`if [ -n "$${NVT_BROKER_SEED_DIR:-}" ]; then`,
	} {
		if !strings.Contains(compose, required) {
			t.Fatalf("local credential compose missing %q", required)
		}
	}
	for _, forbidden := range []string{"CODEX_TOKEN=", "CLAUDE_TOKEN=", "credentials.json:"} {
		if strings.Contains(compose, forbidden) {
			t.Fatalf("compose exposes credential material via %q", forbidden)
		}
	}
	infraBytes, err := os.ReadFile(filepath.Join(root, "scripts", "infra-up.sh"))
	if err != nil {
		t.Fatal(err)
	}
	infra := string(infraBytes)
	if !strings.Contains(infra, `NVT_CREDENTIAL_PORTAL_ENABLED:-false`) ||
		!strings.Contains(infra, `--profile credentials`) ||
		!strings.Contains(infra, `export NVT_BROKER_CREDENTIAL_SEED_DIR=/portal-seed`) ||
		!strings.Contains(infra, `--profile credentials rm -sf`) ||
		!strings.Contains(infra, `credential-portal credential-runner credential-private-init`) ||
		strings.Contains(infra, `rm -sfv`) || strings.Contains(infra, `down -v`) {
		t.Fatalf("infra-up does not gate local credentials explicitly:\n%s", infra)
	}
}

func TestInfraUpDisabledRemovesCredentialContainersAndPreservesVolumes(t *testing.T) {
	root := repoRoot(t)
	fixture := t.TempDir()
	for _, directory := range []string{"scripts", "templates"} {
		if err := os.Mkdir(filepath.Join(fixture, directory), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, relative := range []string{
		"scripts/infra-up.sh", "templates/broker.yaml", "templates/broker-agents.yaml",
		"templates/broker-env", "templates/credential-portal-local.json",
	} {
		content, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fixture, relative), content, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(fixture, "compose.infra.yaml"), []byte("services: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(fixture, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(fixture, "docker.log")
	dockerStub := "#!/bin/sh\nprintf '%s\\n' \"$*\" >>\"$DOCKER_LOG\"\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(dockerStub), 0o755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", filepath.Join(fixture, "scripts", "infra-up.sh"))
	command.Env = []string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"DOCKER_LOG=" + logPath,
		"NVT_CREDENTIAL_PORTAL_ENABLED=false",
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("disabled infra-up failed: %v\n%s", err, output)
	}
	logBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(logBytes)
	remove := "--profile credentials rm -sf credential-portal credential-runner credential-private-init"
	if !strings.Contains(log, remove) || strings.Index(log, remove) > strings.LastIndex(log, " up -d") ||
		strings.Contains(log, "--profile credentials up -d") || strings.Contains(log, " down ") || strings.Contains(log, " -v") {
		t.Fatalf("disabled infra-up did not converge safely:\n%s", log)
	}
}

func TestNativeLocalConfigurationReplacesMigrationAuthoring(t *testing.T) {
	root := repoRoot(t)
	templatePath := filepath.Join(root, "templates", "local-controller.yaml")
	config, err := os.ReadFile(templatePath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(config)
	for _, required := range []string{"api_version: nvt.local-platform/v1", "profiles:", "workflows:", "execution_backends:", "name: local-docker", "kind: container", "retention_policies:", "workstations:", "name: nvt", "name: studio", "name: infra"} {
		if !strings.Contains(text, required) {
			t.Fatalf("native local config missing %q", required)
		}
	}
	makefile, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"local_runs", "source_agent", ".agents/", "local-agent-migrate", "local-controller-migration", "kind: docker"} {
		if strings.Contains(text, forbidden) || strings.Contains(string(makefile), forbidden) {
			t.Fatalf("legacy local authoring surface remains: %q", forbidden)
		}
	}
	for _, path := range []string{
		filepath.Join(root, "compose.agent.yaml"),
		filepath.Join(root, "templates", "agent.yaml"),
		filepath.Join(root, "templates", "AGENTS.local.md"),
		filepath.Join(root, "templates", "env"),
		filepath.Join(root, "scripts", "local-agent-migrate.sh"),
		filepath.Join(root, "scripts", "local-agent-migrate-proof.sh"),
		filepath.Join(root, "scripts", "render-agent-expose.py"),
		filepath.Join(root, "templates", "local-controller-migration.yaml"),
		filepath.Join(root, "docs", "local-controller-migration.md"),
	} {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("obsolete migration surface still exists: %s (%v)", path, statErr)
		}
	}
	agentScripts, err := filepath.Glob(filepath.Join(root, "scripts", "agent-*.sh"))
	if err != nil || len(agentScripts) != 0 {
		t.Fatalf("legacy per-agent scripts remain: %v err=%v", agentScripts, err)
	}
}
