package dockerbackend

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/controller"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

// This opt-in smoke crosses the real Docker/Compose boundary and proves the
// complete synthetic mediated path. It uses the audited executable-provider
// test fixture; no real provider account or credential is required.
func TestDockerBackendRealEngineSmoke(t *testing.T) {
	if os.Getenv("NVT_LOCAL_CONTROLLER_DOCKER_SMOKE") != "1" {
		t.Skip("set NVT_LOCAL_CONTROLLER_DOCKER_SMOKE=1 after building runtime, DinD, broker, egressd, captured, and echo images")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	boundary := dockerCLI{host: environmentOr("DOCKER_HOST", "unix:///var/run/docker.sock")}
	suffix := strconv.Itoa(os.Getpid())
	network := "nvt-lc-smoke-" + suffix
	subnet := fmt.Sprintf("10.233.%d.0/24", 20+os.Getpid()%200)
	if _, err := boundary.Run(ctx, nil, "network", "create", "--subnet", subnet, network); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = boundary.Run(context.Background(), nil, "network", "rm", network) }()

	repositoryRoot := smokeRepositoryRoot(t)
	directory, err := os.MkdirTemp(repositoryRoot, ".nvt-local-controller-smoke-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	fixture := filepath.Join(directory, "provider-fixture")
	build := exec.CommandContext(ctx, "go", "build", "-o", fixture, "./executable_provider_fixture")
	build.Dir = filepath.Join(repositoryRoot, "tests", "broker")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build synthetic provider: %v\n%s", err, output)
	}
	const credential = "LOCAL-MEDIATED-CREDENTIAL-NEEDLE"
	configPath := filepath.Join(directory, "broker.yaml")
	agents := filepath.Join(directory, "agents.yaml")
	config := fmt.Sprintf(`provider-plugins:
  - name: fixture
    command: [%q]
    pass-env: [FIXTURE_CREDENTIAL]
    initialize-timeout-seconds: 2
    request-timeout-seconds: 5
providers:
  - name: provider-a
    plugin: fixture
    config:
      state-file: /state/provider-state
    allow:
      repositories: ["*"]
`, "/provider/provider")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(agents, []byte("agents: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	brokerEnvironment := filepath.Join(directory, "broker.env")
	if err := os.WriteFile(brokerEnvironment, []byte("NVT_BROKER_CONFIG=/state/broker.yaml\nNVT_BROKER_AGENTS_CONFIG=/state/agents.yaml\nNVT_BROKER_AUDIT_LOG=/state/audit.jsonl\nNVT_BROKER_BIND=0.0.0.0:7347\nFIXTURE_CREDENTIAL="+credential+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	brokerName := "nvt-lc-broker-" + suffix
	brokerImage := environmentOr("NVT_BROKER_IMAGE", "nvt-broker:latest")
	if _, err := boundary.Run(ctx, nil, "run", "-d", "--name", brokerName, "--network", network, "--network-alias", "broker",
		"--env-file", brokerEnvironment,
		"-v", directory+":/state", "-v", fixture+":/provider/provider:ro", brokerImage); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = boundary.Run(context.Background(), nil, "rm", "-f", brokerName) }()
	brokerIP := containerIPAddress(t, ctx, boundary, brokerName, network)
	brokerURL := "http://" + brokerIP + ":7347"
	waitHTTPReady(t, brokerURL+"/health", 20*time.Second)

	digest := sha256.Sum256([]byte("Bearer " + credential))
	echoName := "nvt-lc-echo-" + suffix
	if _, err := boundary.Run(ctx, nil, "run", "-d", "--name", echoName, "--network", network, "--network-alias", "api.example.test",
		"-e", "ECHO_LISTEN=:443", "-e", "ECHO_EXPECTED_CREDENTIAL_SHA256="+hex.EncodeToString(digest[:]), environmentOr("NVT_ECHO_IMAGE", "nvt-smoke-echo:test")); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = boundary.Run(context.Background(), nil, "rm", "-f", echoName) }()

	preparer, err := newBrokerPreparer(brokerURL, "", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	backendConfig := Config{
		DockerHost: boundary.host, RunsDir: filepath.Join(directory, "runs"), BrokerURL: brokerURL,
		BrokerAgentsPath: agents, IdentityKeyPath: filepath.Join(directory, "unused-key"), Owner: "smoke-controller",
		ExternalNetwork: network, RunNetworkPool: "100.64.0.0/10", ProxyPort: 4090, ProtectedCIDRs: "127.0.0.0/8 169.254.0.0/16", DindImage: environmentOr("NVT_DIND_IMAGE", "nvt-dind:latest"),
		EgressdImage: environmentOr("NVT_EGRESSD_IMAGE", "nvt-egressd:latest"), CapturedImage: environmentOr("NVT_CAPTURED_IMAGE", "nvt-captured:latest"),
		SeedImage: environmentOr("NVT_RUNTIME_IMAGE", "nvt-agent-runtime:latest"), OperationTimeout: 3 * time.Minute,
	}
	recordedBoundary := &recordingBoundary{delegate: boundary}
	backend, err := NewWithBoundary(backendConfig, recordedBoundary, bytes.Repeat([]byte{0x73}, 32), preparer)
	if err != nil {
		t.Fatal(err)
	}
	assertRealEngineDeclaredServiceCollisionPreserved(t, ctx, boundary, backend, backendConfig)
	run := testMediatedRun(t)
	run.RunID = "mediated-engine-smoke"
	run.Image = backendConfig.SeedImage
	run.Runtime.Docker = nil
	run.AgentConfig = []byte(`{"runtime":{"command":"bash","args":["-lc","echo fresh >> $HOME/session-modes; exec sleep 300"],"resume":{"command":"bash","args":["-lc","echo resume >> $HOME/session-modes; exec sleep 300"]}},"plugins":[]}`)
	run.Repositories = nil
	run.CredentialProviders = nil
	run.Broker.Grants = []resolvedrun.BrokerGrant{{
		Provider: "provider-a", Materialization: "placeholder-file", EgressHosts: []string{"api.example.test:443"}, AllowInsecureUpstream: true,
	}}
	run.Egress = resolvedrun.Egress{Mode: "mediated", Transport: "transparent", Enforced: true, ProxyProvider: "provider-a", PairedEgressRequired: true, AllowInsecureBroker: true}
	run.Persistence = resolvedrun.Persistence{Workspace: true, RuntimeState: true}
	run.Retention = "persistent"
	if err := resolvedrun.ValidateResolvedAgentRun(run); err != nil {
		t.Fatal(err)
	}
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("7", 64), DeleteRequested: true}
	ownedNames := namesFor(backendConfig, run.RunID, desired.SnapshotDigest)
	ownedLabels := ownedLabels{Owner: backendConfig.Owner, RunID: run.RunID, Digest: desired.SnapshotDigest}
	defer func() {
		if err := backend.Delete(context.Background(), desired); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	}()
	observation, err := backend.Ensure(ctx, desired)
	if err != nil || !observation.Ready {
		diagnostics, _ := boundary.Run(ctx, nil, "logs", brokerName)
		names := namesFor(backendConfig, run.RunID, desired.SnapshotDigest)
		composeState, _ := boundary.Run(ctx, nil, "compose", "-p", names.project, "-f", names.composeFile, "ps", "--all")
		ownedState, _ := boundary.Run(ctx, nil, "ps", "-a", "--filter", "label="+ownerLabel+"="+backendConfig.Owner, "--format", "{{.ID}} {{.Names}} {{.Status}}")
		ownedIDs, _ := boundary.Run(ctx, nil, "ps", "-aq", "--filter", "label="+ownerLabel+"="+backendConfig.Owner)
		diagnostics = append(diagnostics, append([]byte("\ncompose:\n"), composeState...)...)
		diagnostics = append(diagnostics, append([]byte("\nowned:\n"), ownedState...)...)
		for _, id := range strings.Fields(string(ownedIDs)) {
			logs, _ := boundary.Run(ctx, nil, "logs", id)
			diagnostics = append(diagnostics, append([]byte("\nlogs "+id+":\n"), logs...)...)
		}
		if bytes.Contains(diagnostics, []byte(credential)) {
			diagnostics = []byte("broker diagnostics contained credential and were suppressed")
		}
		policy, _ := os.ReadFile(agents)
		t.Fatalf("real mediated ensure = %#v %v\nbroker=%s\nregistry=%s", observation, err, diagnostics, policy)
	}
	assertBackendCreatedNonOverlappingNetworks(t, ctx, boundary, backendConfig, ownedNames)
	agentID := ownedAgentContainer(t, ctx, boundary, ownedLabels)
	response, err := boundary.Run(ctx, nil, "exec", agentID, "curl", "-fsS", "https://api.example.test/credential-proof")
	if err != nil || !bytes.Contains(response, []byte(`"credential_match":true`)) || bytes.Contains(response, []byte(`"placeholder_seen":true`)) {
		curlDiagnostics, _ := boundary.Run(ctx, nil, "exec", agentID, "sh", "-c", "curl -v https://api.example.test/credential-proof 2>&1 || true")
		ownedIDs, _ := boundary.Run(ctx, nil, "ps", "-aq", "--filter", "label="+ownerLabel+"="+backendConfig.Owner)
		diagnostics := []byte{}
		for _, id := range strings.Fields(string(ownedIDs)) {
			logs, _ := boundary.Run(ctx, nil, "logs", id)
			diagnostics = append(diagnostics, append([]byte("\nlogs "+id+":\n"), logs...)...)
		}
		if bytes.Contains(diagnostics, []byte(credential)) {
			diagnostics = []byte("runtime diagnostics contained credential and were suppressed")
		}
		t.Fatalf("mediated injection proof = %v %s\ncurl=%s\n%s", err, response, curlDiagnostics, diagnostics)
	}
	waitContainerFile(t, ctx, boundary, agentID, "/root/session-modes", "fresh\n", 20*time.Second)
	waitContainerFileContains(t, ctx, boundary, agentID, "/root/.nvt-agent/runtime-session.json", `"state":"resumable"`, 20*time.Second)
	if _, err := boundary.Run(ctx, nil, "rm", "-f", agentID); err != nil {
		t.Fatal(err)
	}
	observation, recoveryErr := ensureEventually(ctx, backend, desired, 20*time.Second)
	if recoveryErr != nil || !observation.Ready {
		composeState, _ := boundary.Run(ctx, nil, "compose", "-p", ownedNames.project, "-f", ownedNames.composeFile, "ps", "--all")
		ownedState, _ := boundary.Run(ctx, nil, "ps", "-a", "--filter", "label="+ownerLabel+"="+backendConfig.Owner, "--format", "{{.ID}} {{.Names}} {{.Status}}")
		diagnostics := append(append([]byte("compose:\n"), composeState...), append([]byte("\nowned:\n"), ownedState...)...)
		diagnostics = append(diagnostics, append([]byte("\nbackend commands:\n"), []byte(recordedBoundary.tail(30))...)...)
		if bytes.Contains(diagnostics, []byte(credential)) {
			diagnostics = []byte("recovery diagnostics contained credential and were suppressed")
		}
		t.Fatalf("agent recreation = %#v, %v\n%s", observation, recoveryErr, diagnostics)
	}
	recoveredAgentID := ownedAgentContainer(t, ctx, boundary, ownedLabels)
	if recoveredAgentID == agentID {
		t.Fatal("removed agent container was not recreated")
	}
	waitContainerFile(t, ctx, boundary, recoveredAgentID, "/root/session-modes", "fresh\nresume\n", 20*time.Second)
	for _, retained := range []string{ownedNames.workspace, ownedNames.home} {
		if _, err := boundary.Run(ctx, nil, "volume", "inspect", retained); err != nil {
			t.Fatalf("persistent recovery volume missing: %s: %v", retained, err)
		}
	}
	assertRealEngineSecretAbsent(t, ctx, boundary, backendConfig, desired, recoveredAgentID, credential)
	if strings.Contains(strings.Join(recordedBoundary.commands, "\n"), credential) {
		t.Fatal("credential entered Docker command arguments during recovery")
	}
	if _, err := boundary.Run(ctx, nil, "exec", recoveredAgentID, "agentdctl", "publish", "plugin.work.done", "--source", "plugin:local-controller-smoke"); err != nil {
		t.Fatal(err)
	}
	lifecycle, err := backend.Inspect(ctx, desired)
	if err != nil || lifecycle.TerminalTarget != controller.StateCompleted || lifecycle.LifecycleCursor == "" {
		t.Fatalf("real lifecycle completion = %#v, %v", lifecycle, err)
	}
	desired.LifecycleCursor = lifecycle.LifecycleCursor
	if err := backend.Delete(ctx, desired); err != nil {
		t.Fatalf("real lifecycle cleanup: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(ownedNames.composeFile)); !os.IsNotExist(err) {
		t.Fatalf("real lifecycle cleanup retained generated state: %v", err)
	}
}

type recordingBoundary struct {
	delegate CommandBoundary
	commands []string
}

func (boundary *recordingBoundary) Run(ctx context.Context, input io.Reader, arguments ...string) ([]byte, error) {
	output, err := boundary.delegate.Run(ctx, input, arguments...)
	result := "ok"
	if err != nil {
		result = "error"
	}
	boundary.commands = append(boundary.commands, result+" "+strings.Join(arguments, " "))
	return output, err
}

func (boundary *recordingBoundary) tail(limit int) string {
	start := len(boundary.commands) - limit
	if start < 0 {
		start = 0
	}
	return strings.Join(boundary.commands[start:], "\n")
}

func ensureEventually(ctx context.Context, backend *Backend, desired controller.BackendRun, timeout time.Duration) (controller.BackendObservation, error) {
	deadline := time.Now().Add(timeout)
	var observation controller.BackendObservation
	var err error
	for time.Now().Before(deadline) {
		observation, err = backend.Ensure(ctx, desired)
		if err == nil && observation.Ready {
			return observation, nil
		}
		select {
		case <-ctx.Done():
			return observation, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return observation, err
}

func waitContainerFile(t *testing.T, ctx context.Context, boundary CommandBoundary, container, path, expected string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		output, err := boundary.Run(ctx, nil, "exec", container, "cat", path)
		if err == nil && string(output) == expected {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("container recovery state did not reach the expected value: %s", path)
}

func waitContainerFileContains(t *testing.T, ctx context.Context, boundary CommandBoundary, container, path, expected string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		output, err := boundary.Run(ctx, nil, "exec", container, "cat", path)
		if err == nil && strings.Contains(string(output), expected) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("container recovery marker did not reach the expected value: %s", path)
}

func assertRealEngineDeclaredServiceCollisionPreserved(t *testing.T, ctx context.Context, boundary CommandBoundary, backend *Backend, config Config) {
	t.Helper()
	run := testMediatedRun(t)
	run.RunID = "declared-collision-smoke"
	run.Image = config.SeedImage
	run.Runtime.Docker = nil
	run.AgentConfig = []byte(`{"runtime":{"command":"bash","args":["-lc","sleep 300"]},"plugins":[]}`)
	run.Repositories = nil
	run.CredentialProviders = nil
	run.Broker = resolvedrun.Broker{}
	run.Egress = resolvedrun.Egress{Mode: "direct"}
	if err := resolvedrun.ValidateResolvedAgentRun(run); err != nil {
		t.Fatal(err)
	}
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("6", 64)}
	names := namesFor(config, run.RunID, desired.SnapshotDigest)
	containerName := "nvt-lc-unmanaged-agent-" + strconv.Itoa(os.Getpid())
	created, err := boundary.Run(ctx, nil, "run", "-d", "--name", containerName, "--entrypoint", "bash",
		"--label", composeProjectLabel+"="+names.project, "--label", composeServiceLabel+"=agent", config.SeedImage, "-lc", "sleep 300")
	if err != nil {
		t.Fatal(err)
	}
	originalID := strings.TrimSpace(string(created))
	defer func() { _, _ = boundary.Run(context.Background(), nil, "rm", "-f", containerName) }()
	if _, err := backend.Ensure(ctx, desired); !errors.Is(err, controller.ErrBackendDesiredRunInvalid) {
		t.Fatalf("real declared-service collision = %v", err)
	}
	current, err := boundary.Run(ctx, nil, "inspect", "--format", "{{.Id}} {{json .Config.Labels}}", containerName)
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(current)), originalID+" ") || !bytes.Contains(current, []byte(`"com.docker.compose.service":"agent"`)) || bytes.Contains(current, []byte(ownerLabel)) {
		t.Fatalf("Compose changed unmanaged declared service: %v %s", err, current)
	}
}

func assertBackendCreatedNonOverlappingNetworks(t *testing.T, ctx context.Context, boundary CommandBoundary, config Config, names resourceNames) {
	t.Helper()
	pool := netip.MustParsePrefix(config.RunNetworkPool)
	managed := netip.MustParsePrefix("172.30.0.0/15")
	seen := map[string]bool{}
	for _, name := range []string{names.internalNet, names.privateNet} {
		raw, err := boundary.Run(ctx, nil, "network", "inspect", "--format", "{{json .IPAM.Config}}", name)
		if err != nil {
			t.Fatalf("backend-owned network missing: %s: %v", name, err)
		}
		var values []dockerIPAMConfig
		if json.Unmarshal(raw, &values) != nil || len(values) != 1 {
			t.Fatalf("backend-owned network IPAM malformed: %s: %s", name, raw)
		}
		subnet, err := netip.ParsePrefix(values[0].Subnet)
		if err != nil || subnet.Bits() != runNetworkPrefixBits || !pool.Contains(subnet.Addr()) || subnet.Overlaps(managed) || seen[subnet.String()] {
			t.Fatalf("backend-owned subnet invalid: %s: %v", values[0].Subnet, err)
		}
		seen[subnet.String()] = true
	}
	if _, err := boundary.Run(ctx, nil, "network", "inspect", names.project+"_default"); err == nil {
		t.Fatal("Compose created an unmanaged implicit project network")
	}
}

func smokeRepositoryRoot(t *testing.T) string {
	t.Helper()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(filepath.Join(workingDirectory, "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func containerIPAddress(t *testing.T, ctx context.Context, boundary CommandBoundary, name, network string) string {
	t.Helper()
	output, err := boundary.Run(ctx, nil, "inspect", "--format", "{{(index .NetworkSettings.Networks \""+network+"\").IPAddress}}", name)
	if err != nil || net.ParseIP(strings.TrimSpace(string(output))) == nil {
		t.Fatalf("container address unavailable: %v %q", err, output)
	}
	return strings.TrimSpace(string(output))
}

func waitHTTPReady(t *testing.T, endpoint string, timeout time.Duration) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		response, err := client.Get(endpoint)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("dependency did not become ready: %s", endpoint)
}

func ownedAgentContainer(t *testing.T, ctx context.Context, boundary CommandBoundary, labels ownedLabels) string {
	t.Helper()
	arguments := []string{"ps", "-q"}
	for _, pair := range labelPairs(labels) {
		arguments = append(arguments, "--filter", "label="+pair)
	}
	arguments = append(arguments, "--filter", "label=com.docker.compose.service=agent")
	output, err := boundary.Run(ctx, nil, arguments...)
	if err != nil || len(strings.Fields(string(output))) != 1 {
		t.Fatalf("owned agent unavailable: %v %q", err, output)
	}
	return strings.TrimSpace(string(output))
}

func assertRealEngineSecretAbsent(t *testing.T, ctx context.Context, boundary CommandBoundary, config Config, desired controller.BackendRun, agentID, needle string) {
	t.Helper()
	labels := ownedLabels{Owner: config.Owner, RunID: desired.Resolved.RunID, Digest: desired.SnapshotDigest}
	arguments := []string{"ps", "-aq"}
	for _, pair := range labelPairs(labels) {
		arguments = append(arguments, "--filter", "label="+pair)
	}
	owned, err := boundary.Run(ctx, nil, arguments...)
	if err != nil {
		t.Fatal(err)
	}
	containerIDs := strings.Fields(string(owned))
	inspectArguments := append([]string{"inspect"}, containerIDs...)
	inspect, err := boundary.Run(ctx, nil, inspectArguments...)
	if err != nil {
		t.Fatal(err)
	}
	values := [][]byte{inspect}
	for _, id := range containerIDs {
		logs, _ := boundary.Run(ctx, nil, "logs", id)
		values = append(values, logs)
	}
	for index, path := range []string{"/nvt-config/.", "/root/.fixture/.", "/root/.nvt-agent/.", "/workspace/."} {
		archive, copyErr := boundary.Run(ctx, nil, "cp", agentID+":"+path, "-")
		if copyErr != nil {
			if index < 2 {
				t.Fatalf("required agent filesystem surface unavailable: %s: %v", path, copyErr)
			}
			continue
		}
		values = append(values, archive)
	}
	names := namesFor(config, desired.Resolved.RunID, desired.SnapshotDigest)
	for _, path := range []string{names.composeFile, config.BrokerAgentsPath} {
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		values = append(values, raw)
	}
	for _, value := range values {
		if bytes.Contains(value, []byte(needle)) {
			t.Fatal("real credential appeared outside broker/egress custody")
		}
	}
}

func environmentOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
