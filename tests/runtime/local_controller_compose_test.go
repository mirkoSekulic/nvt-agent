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
		"NVT_LOCAL_CONTROLLER_DOCKER_HOST: unix:///var/run/docker.sock",
		"NVT_LOCAL_CONTROLLER_BROKER_AGENTS: /broker-state/agents.yaml",
		"NVT_LOCAL_CONTROLLER_DIND_PROTECTED_CIDRS:",
		"NVT_LOCAL_CONTROLLER_PROXY_PORT:",
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
	agentCompose, err := os.ReadFile(filepath.Join(root, "compose.agent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	agentText := string(agentCompose)
	if strings.Contains(agentText, "- /var/run/docker.sock:/var/run/docker.sock") {
		t.Fatal("agent stack received the host Docker socket")
	}
}
