package runtime_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalControllerIsPackagedWithoutDockerAccess(t *testing.T) {
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
		"local-controller-state:/state",
		"- local-control-plane",
		"read_only: true",
	} {
		if !strings.Contains(service, required) {
			t.Fatalf("local controller service missing %q:\n%s", required, service)
		}
	}
	for _, forbidden := range []string{"docker.sock", "DOCKER_HOST", "privileged:", "cap_add:", "env_file:", "secrets:", ".broker"} {
		if strings.Contains(service, forbidden) {
			t.Fatalf("local controller received forbidden Docker authority %q:\n%s", forbidden, service)
		}
	}
	if strings.Contains(service, "agents-proxy") || strings.Contains(service, "ports:") {
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
		"--chown=65532:65532 /out/state /state",
		"USER nonroot:nonroot",
		`ENTRYPOINT ["/nvt-local-controller"]`,
	} {
		if !strings.Contains(dockerfile, required) {
			t.Fatalf("local controller Dockerfile missing %q:\n%s", required, dockerfile)
		}
	}
}
