package runtime_test

import (
	"os"
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
		"DOCKER_HOST: tcp://docker:2375",
		"docker:",
		"image: docker:27-dind",
		"privileged: true",
		"DOCKER_TLS_CERTDIR: \"\"",
		"docker-data:/var/lib/docker",
		"${WORKSPACE_DIR}:${NVT_WORKSPACE}",
		"agent-internal",
	}
	for _, fragment := range required {
		if !strings.Contains(compose, fragment) {
			t.Fatalf("compose.agent.yaml missing %q\n%s", fragment, compose)
		}
	}
	if strings.Contains(compose, "/var/run/docker.sock") {
		t.Fatalf("compose.agent.yaml must not mount the host Docker socket")
	}
}
