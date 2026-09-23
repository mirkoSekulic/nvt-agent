package dockerbackend

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/controller"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

// Reproduce the restart-order race deterministically on a disposable stack:
// restart only its namespace owner while its agent/proxy remain alive. Never
// restart the developer's Docker daemon or use real provider credentials.
func TestDockerBackendNetworkNamespaceRecoverySmoke(t *testing.T) {
	if os.Getenv("NVT_LOCAL_CONTROLLER_NETWORK_RECOVERY_SMOKE") != "1" {
		t.Skip("set NVT_LOCAL_CONTROLLER_NETWORK_RECOVERY_SMOKE=1 after building local runtime images")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	backend, _, run, _ := testBackend(t)
	boundary := dockerCLI{host: environmentOr("DOCKER_HOST", "unix:///var/run/docker.sock")}
	recorded := &recordingBoundary{delegate: boundary}
	backend.docker = recorded
	suffix := strconv.Itoa(os.Getpid())
	network, gateway := "nvt-network-recovery-"+suffix, "nvt-network-recovery-gateway-"+suffix
	if _, err := boundary.Run(ctx, nil, "network", "create", network); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = boundary.Run(context.Background(), nil, "network", "rm", network) }()
	backend.config.ExternalNetwork, backend.config.GatewayContainer = network, gateway
	backend.config.SeedImage = environmentOr("NVT_RUNTIME_IMAGE", "nvt-agent-runtime:latest")
	backend.config.DindImage = environmentOr("NVT_DIND_IMAGE", "nvt-dind:latest")
	backend.config.EgressdImage = environmentOr("NVT_EGRESSD_IMAGE", "nvt-egressd:latest")
	backend.config.CapturedImage = environmentOr("NVT_CAPTURED_IMAGE", "nvt-captured:latest")
	backend.config.OperationTimeout = 2 * time.Minute
	if _, err := boundary.Run(ctx, nil, "run", "-d", "--no-healthcheck", "--name", gateway, "--network", network,
		"--label", localGatewayLabel+"=true", "--entrypoint", "sleep", backend.config.SeedImage, "300"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = boundary.Run(context.Background(), nil, "rm", "-f", gateway) }()
	run.RunID, run.Image = "network-recovery-"+suffix, backend.config.SeedImage
	run.Repositories, run.CredentialProviders = nil, nil
	run.Broker.Grants = run.Broker.Grants[:1] // Synthetic preparation from testBackend.
	run.Persistence = resolvedrun.Persistence{Workspace: true, RuntimeState: true, DockerData: true}
	run.Retention = "persistent"
	run.AgentConfig = []byte(`{"runtime":{"command":"bash","args":["-lc","echo fresh >> $HOME/recovery-modes; exec sleep 300"],"resume":{"command":"bash","args":["-lc","echo resume >> $HOME/recovery-modes; exec sleep 300"]}},"plugins":[]}`)
	if err := resolvedrun.ValidateResolvedAgentRun(run); err != nil {
		t.Fatal(err)
	}
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("a", 64), DeleteRequested: true}
	defer func() {
		if err := backend.Delete(context.Background(), desired); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	}()
	observation, err := backend.Ensure(ctx, desired)
	if err != nil || !observation.Ready {
		t.Fatalf("initial ensure = %#v %v\n%s", observation, err, recorded.tail(12))
	}
	names := namesFor(backend.config, run.RunID, desired.SnapshotDigest)
	labels := ownedLabels{Owner: backend.config.Owner, RunID: run.RunID, Digest: desired.SnapshotDigest}
	agentBefore := ownedAgentContainer(t, ctx, boundary, labels)
	proxyBefore := ownedComposeServiceContainer(t, ctx, boundary, labels, "captured")
	egressBefore := ownedComposeServiceContainer(t, ctx, boundary, labels, "egressd")
	ownerBefore := ownedComposeServiceContainer(t, ctx, boundary, labels, "docker")
	readBrowser := func() error {
		_, err := boundary.Run(ctx, nil, "exec", gateway, "curl", "--noproxy", "*", "-fsSL", "--max-time", "5", "-o", "/dev/null", "http://"+names.namespace+":4090/")
		return err
	}
	if err := readBrowser(); err != nil {
		t.Fatalf("initial gateway route: %v", err)
	}
	if _, err := boundary.Run(ctx, nil, "exec", agentBefore, "sh", "-ec", "printf retained > /workspace/recovery-marker"); err != nil {
		t.Fatal(err)
	}
	if _, err := boundary.Run(ctx, nil, "restart", "--time", "30", names.namespace); err != nil {
		t.Fatal(err)
	}
	ownerNamespace, err := backend.containerNetworkNamespace(ctx, names.namespace)
	if err != nil {
		t.Fatal(err)
	}
	agentNamespace, err := backend.containerNetworkNamespace(ctx, agentBefore)
	if err != nil || ownerNamespace == agentNamespace {
		t.Fatalf("fixture did not strand agent: owner=%d agent=%d err=%v", ownerNamespace, agentNamespace, err)
	}
	if readBrowser() == nil {
		t.Fatal("fixture browser still reachable in old namespace")
	}
	observation, err = backend.Inspect(ctx, desired)
	if err != nil || observation.Ready || !observation.RecoveryRequired || observation.TerminalTarget != "" {
		t.Fatalf("stale healthy runtime = %#v %v", observation, err)
	}
	observation, err = backend.Ensure(ctx, desired)
	if err != nil || !observation.Ready {
		t.Fatalf("recovery ensure = %#v %v", observation, err)
	}
	if err := readBrowser(); err != nil {
		t.Fatalf("recovered gateway route: %v", err)
	}
	agentAfter := ownedAgentContainer(t, ctx, boundary, labels)
	proxyAfter := ownedComposeServiceContainer(t, ctx, boundary, labels, "captured")
	if agentBefore == agentAfter || proxyBefore == proxyAfter {
		t.Fatal("stale dependants were not replaced")
	}
	if ownerBefore != ownedComposeServiceContainer(t, ctx, boundary, labels, "docker") || egressBefore != ownedComposeServiceContainer(t, ctx, boundary, labels, "egressd") {
		t.Fatal("healthy owner/egress was replaced")
	}
	if got := execInContainer(t, ctx, boundary, agentAfter, "cat", "/workspace/recovery-marker"); got != "retained" {
		t.Fatalf("workspace not retained: %q", got)
	}
	waitContainerFile(t, ctx, boundary, agentAfter, "/root/recovery-modes", "fresh\nresume\n", 20*time.Second)
	if currentNamespaceProof(t, ctx, boundary, agentAfter) != execInContainer(t, ctx, boundary, agentAfter, "cat", "/run/nvt-confinement/network-namespace") {
		t.Fatal("recovery bypassed current confinement proof")
	}
	// Minimal Linux Docker hosts need the isolated fixed-command fallback.
	backend.docker = noNamespaceColumn{boundary}
	if got, err := backend.containerNetworkNamespace(ctx, proxyAfter); err != nil || got != ownerNamespace {
		t.Fatalf("minimal-host probe = %d %v", got, err)
	}
	backend.docker = boundary
	if observation, err = backend.Ensure(ctx, desired); err != nil || !observation.Ready {
		t.Fatalf("idempotent ensure = %#v %v", observation, err)
	}
	if agentAfter != ownedAgentContainer(t, ctx, boundary, labels) || proxyAfter != ownedComposeServiceContainer(t, ctx, boundary, labels, "captured") {
		t.Fatal("healthy dependants were replaced again")
	}
}

type noNamespaceColumn struct{ CommandBoundary }

func (boundary noNamespaceColumn) Run(ctx context.Context, input io.Reader, arguments ...string) ([]byte, error) {
	if len(arguments) > 0 && arguments[0] == "top" {
		return nil, errors.New("NETNS column unavailable")
	}
	return boundary.CommandBoundary.Run(ctx, input, arguments...)
}
