package dockerbackend

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/controller"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

// This opt-in smoke crosses the real Docker/Compose boundary. Normal unit
// tests keep a deterministic fake boundary and do not require local images.
func TestDockerBackendRealEngineSmoke(t *testing.T) {
	if os.Getenv("NVT_LOCAL_CONTROLLER_DOCKER_SMOKE") != "1" {
		t.Skip("set NVT_LOCAL_CONTROLLER_DOCKER_SMOKE=1 after building the local runtime and DinD images")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	boundary := dockerCLI{host: environmentOr("DOCKER_HOST", "unix:///var/run/docker.sock")}
	network := "nvt-lc-smoke-" + strconv.Itoa(os.Getpid())
	if _, err := boundary.Run(ctx, nil, "network", "create", network); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = boundary.Run(context.Background(), nil, "network", "rm", network) }()

	directory := t.TempDir()
	agents := filepath.Join(directory, "agents.yaml")
	if err := os.WriteFile(agents, []byte("agents: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		http.Error(response, "unexpected broker preparation", http.StatusInternalServerError)
	}))
	defer server.Close()
	preparer, err := newBrokerPreparer(server.URL, "", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	config := Config{
		DockerHost: boundary.host, RunsDir: filepath.Join(directory, "runs"), BrokerURL: server.URL,
		BrokerAgentsPath: agents, IdentityKeyPath: filepath.Join(directory, "unused-key"), Owner: "smoke-controller",
		ExternalNetwork: network, ProxyPort: 4090, ProtectedCIDRs: "127.0.0.0/8 169.254.0.0/16", DindImage: environmentOr("NVT_DIND_IMAGE", "nvt-dind:latest"),
		EgressdImage: environmentOr("NVT_EGRESSD_IMAGE", "nvt-egressd:latest"), CapturedImage: environmentOr("NVT_CAPTURED_IMAGE", "nvt-captured:latest"),
		SeedImage: environmentOr("NVT_RUNTIME_IMAGE", "nvt-agent-runtime:latest"), OperationTimeout: 2 * time.Minute,
	}
	backend, err := NewWithBoundary(config, boundary, bytes.Repeat([]byte{0x73}, 32), preparer)
	if err != nil {
		t.Fatal(err)
	}
	run := testMediatedRun(t)
	run.RunID = "docker-engine-smoke"
	run.Image = config.SeedImage
	run.AgentConfig = []byte(`{"runtime":{"command":"bash","args":["-lc","sleep 300"]},"plugins":[]}`)
	run.Repositories = nil
	run.CredentialProviders = nil
	run.Broker = resolvedrun.Broker{}
	run.Egress = resolvedrun.Egress{Mode: "direct"}
	if err := resolvedrun.ValidateResolvedAgentRun(run); err != nil {
		t.Fatal(err)
	}
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("7", 64), DeleteRequested: true}
	defer func() {
		if err := backend.Delete(context.Background(), desired); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	}()
	observation, err := backend.Ensure(ctx, desired)
	if err != nil || !observation.Ready {
		t.Fatalf("real engine ensure = %#v %v", observation, err)
	}
	observation, err = backend.Inspect(ctx, desired)
	if err != nil || !observation.Ready {
		t.Fatalf("real engine inspect = %#v %v", observation, err)
	}
}

func environmentOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
