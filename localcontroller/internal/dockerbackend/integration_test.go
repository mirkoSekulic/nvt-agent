package dockerbackend

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
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
		ExternalNetwork: network, ProxyPort: 4090, ProtectedCIDRs: "127.0.0.0/8 169.254.0.0/16", DindImage: environmentOr("NVT_DIND_IMAGE", "nvt-dind:latest"),
		EgressdImage: environmentOr("NVT_EGRESSD_IMAGE", "nvt-egressd:latest"), CapturedImage: environmentOr("NVT_CAPTURED_IMAGE", "nvt-captured:latest"),
		SeedImage: environmentOr("NVT_RUNTIME_IMAGE", "nvt-agent-runtime:latest"), OperationTimeout: 3 * time.Minute,
	}
	backend, err := NewWithBoundary(backendConfig, boundary, bytes.Repeat([]byte{0x73}, 32), preparer)
	if err != nil {
		t.Fatal(err)
	}
	run := testMediatedRun(t)
	run.RunID = "mediated-engine-smoke"
	run.Image = backendConfig.SeedImage
	run.Runtime.Docker = nil
	run.AgentConfig = []byte(`{"runtime":{"command":"bash","args":["-lc","sleep 300"]},"plugins":[]}`)
	run.Repositories = nil
	run.CredentialProviders = nil
	run.Broker.Grants = []resolvedrun.BrokerGrant{{
		Provider: "provider-a", Materialization: "placeholder-file", EgressHosts: []string{"api.example.test:443"}, AllowInsecureUpstream: true,
	}}
	run.Egress = resolvedrun.Egress{Mode: "mediated", Transport: "transparent", Enforced: true, ProxyProvider: "provider-a", PairedEgressRequired: true, AllowInsecureBroker: true}
	if err := resolvedrun.ValidateResolvedAgentRun(run); err != nil {
		t.Fatal(err)
	}
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("7", 64), DeleteRequested: true}
	ownedNames := namesFor(backendConfig, run.RunID, desired.SnapshotDigest)
	ownedLabels := ownedLabels{Owner: backendConfig.Owner, RunID: run.RunID, Digest: desired.SnapshotDigest}
	for index, item := range []string{ownedNames.internalNet, ownedNames.privateNet} {
		arguments := []string{"network", "create", "--subnet", fmt.Sprintf("10.%d.%d.0/24", 234+index, 20+os.Getpid()%200)}
		arguments = append(arguments, labelArguments(ownedLabels)...)
		arguments = append(arguments, item)
		if _, err := boundary.Run(ctx, nil, arguments...); err != nil {
			t.Fatal(err)
		}
	}
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
	assertRealEngineSecretAbsent(t, ctx, boundary, backendConfig, desired, agentID, credential)
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
