package runtime_test

import (
	"os"
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
	for _, required := range []string{"local-controller-admin-token", "local-controller-route-token", "local-controller.json", "NVT_LOCAL_CONTROLLER_NAMED_RUNS_CONFIG=/broker-state/local-controller.json", `export NVT_LOCAL_GATEWAY_UID="$(id -u)"`, `openssl rand -hex 32`} {
		if !strings.Contains(string(infraUp), required) {
			t.Fatalf("infra-up does not provision private local API credentials: missing %q", required)
		}
	}
	if strings.Contains(string(infraUp), "export NVT_LOCAL_CONTROLLER_SCHEDULING_CONFIG=/broker-state/local-controller.json") {
		t.Fatal("generated named runs replaced the independent producer scheduling document")
	}
	data, err := os.ReadFile(filepath.Join(root, "compose.infra.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	compose := string(data)
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
		"NVT_LOCAL_CONTROLLER_DIND_PROTECTED_CIDRS:",
		"NVT_LOCAL_CONTROLLER_PROXY_PORT:",
		"NVT_LOCAL_CONTROLLER_ROUTE_BASE_DOMAIN: agent.localhost",
		"NVT_LOCAL_CONTROLLER_ROUTE_PATH_PREFIX: /agents",
		"NVT_LOCAL_CONTROLLER_GATEWAY_CONTAINER: nvt-local-gateway",
		"NVT_LOCAL_CONTROLLER_SCHEDULING_CONFIG:",
		"NVT_LOCAL_CONTROLLER_NAMED_RUNS_CONFIG:",
		"NVT_LOCAL_CONTROLLER_ADMIN_TOKEN_FILE: /broker-state/local-controller-admin-token",
		"NVT_LOCAL_CONTROLLER_ROUTE_TOKEN_FILE: /broker-state/local-controller-route-token",
		"local-controller-state:/state",
		"./.broker:/broker-state",
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
		"./.broker/local-controller-route-token:/run/secrets/local-controller-route-token:ro",
		"nvt.dev/local-gateway=true",
		"traefik.http.routers.nvt-local-gateway.rule=Host(`localhost`) && (PathPrefix(`/agents`) || PathPrefix(`/oauth2`))",
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
	if strings.Contains(service, "networks:\n      - agents-proxy") || strings.Contains(service, "ports:") {
		t.Fatalf("local controller is exposed outside its trusted control-plane network:\n%s", service)
	}
	if !strings.Contains(compose, "\n  local-control-plane:\n    internal: true\n") {
		t.Fatalf("compose infrastructure has no internal controller network:\n%s", compose)
	}
	if !strings.Contains(compose, "\n  local-controller-state:\n") {
		t.Fatalf("compose infrastructure has no durable controller state volume:\n%s", compose)
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
		`/usr/local/bin/nvt-local-migrate`,
	} {
		if !strings.Contains(dockerfile, required) {
			t.Fatalf("local controller Dockerfile missing %q:\n%s", required, dockerfile)
		}
	}
	migrationScript, err := os.ReadFile(filepath.Join(root, "scripts", "local-agent-migrate.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"go run ./cmd/nvt-local-migrate", "--agents-root", "--broker-agents", "--broker-config", ".broker/local-controller.json"} {
		if !strings.Contains(string(migrationScript), required) {
			t.Fatalf("migration wrapper missing %q:\n%s", required, migrationScript)
		}
	}
	agentCompose, err := os.ReadFile(filepath.Join(root, "compose.agent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	agentText := string(agentCompose)
	if strings.Contains(agentText, "- /var/run/docker.sock:/var/run/docker.sock") {
		t.Fatal("agent stack received the host Docker socket")
	}
}
