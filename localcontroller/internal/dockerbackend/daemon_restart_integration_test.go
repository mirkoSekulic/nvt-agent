package dockerbackend

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

// This opt-in proof restarts a disposable nested dockerd, never the
// developer's daemon. The runtime command is an adversarial immediate direct
// request: it can execute only after a proof for the current network namespace
// exists, and transparent capture must make the disallowed port fail closed.
func TestDockerBackendDaemonRestartSmoke(t *testing.T) {
	if os.Getenv("NVT_LOCAL_CONTROLLER_DAEMON_RESTART_SMOKE") != "1" {
		t.Skip("set NVT_LOCAL_CONTROLLER_DAEMON_RESTART_SMOKE=1 after building the local runtime images")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	outer := dockerCLI{host: environmentOr("DOCKER_HOST", "unix:///var/run/docker.sock")}
	suffix := strconv.Itoa(os.Getpid())
	networkName := "nvt-lc-daemon-restart-" + suffix
	subnet := fmt.Sprintf("10.234.%d.0/24", 20+os.Getpid()%200)
	if _, err := outer.Run(ctx, nil, "network", "create", "--subnet", subnet, networkName); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = outer.Run(context.Background(), nil, "network", "rm", networkName) }()

	bypassListener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	bypassServer := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "direct-bypass-reached")
	})}
	go func() { _ = bypassServer.Serve(bypassListener) }()
	defer bypassServer.Close()
	bypassPort := bypassListener.Addr().(*net.TCPAddr).Port
	outerGateway := networkGateway(t, ctx, outer, networkName)

	directory, err := os.MkdirTemp(smokeRepositoryRoot(t), ".nvt-local-daemon-restart-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	agents, brokerIP := startOuterSyntheticBroker(t, ctx, outer, networkName, directory, suffix)

	dindName := "nvt-lc-nested-daemon-" + suffix
	dindData := dindName + "-data"
	if _, err := outer.Run(ctx, nil, "volume", "create", dindData); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = outer.Run(context.Background(), nil, "volume", "rm", dindData) }()
	if _, err := outer.Run(ctx, nil, "run", "-d", "--privileged", "--name", dindName, "--network", networkName,
		"-e", "DOCKER_TLS_CERTDIR=", "-v", dindData+":/var/lib/docker", "docker:27-dind", "--host=tcp://0.0.0.0:2375", "--host=unix:///var/run/docker.sock", "--tls=false"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = outer.Run(context.Background(), nil, "rm", "-f", dindName) }()
	nestedHost := waitNestedDocker(t, ctx, outer, dindName, networkName)
	for _, image := range []string{
		environmentOr("NVT_RUNTIME_IMAGE", "nvt-agent-runtime:latest"),
		environmentOr("NVT_DIND_IMAGE", "nvt-dind:latest"),
		environmentOr("NVT_EGRESSD_IMAGE", "nvt-egressd:latest"),
		environmentOr("NVT_CAPTURED_IMAGE", "nvt-captured:latest"),
		environmentOr("NVT_ECHO_IMAGE", "nvt-smoke-echo:test"),
	} {
		copyImage(t, ctx, outer.host, nestedHost, image)
	}
	nested := dockerCLI{host: nestedHost}
	if _, err := nested.Run(ctx, nil, "network", "create", "agents-proxy"); err != nil {
		t.Fatal(err)
	}
	const credential = "LOCAL-DAEMON-RESTART-CREDENTIAL-NEEDLE"
	credentialDigest := sha256.Sum256([]byte("Bearer " + credential))
	if _, err := nested.Run(ctx, nil, "run", "-d", "--restart", "unless-stopped", "--name", "credential-upstream", "--network", "agents-proxy", "--network-alias", "api.example.test",
		"-e", "ECHO_LISTEN=:443", "-e", "ECHO_EXPECTED_CREDENTIAL_SHA256="+hex.EncodeToString(credentialDigest[:]), environmentOr("NVT_ECHO_IMAGE", "nvt-smoke-echo:test")); err != nil {
		t.Fatal(err)
	}
	if _, err := nested.Run(ctx, nil, "run", "-d", "--restart", "unless-stopped", "--name", "restart-proxy", "--network", "agents-proxy", "-p", "18088:8080", environmentOr("NVT_ECHO_IMAGE", "nvt-smoke-echo:test")); err != nil {
		t.Fatal(err)
	}
	if _, err := nested.Run(ctx, nil, "run", "-d", "--restart", "unless-stopped", "--no-healthcheck", "--name", "nvt-local-gateway", "--network", "agents-proxy", "--label", localGatewayLabel+"=true", "--entrypoint", "sh", environmentOr("NVT_RUNTIME_IMAGE", "nvt-agent-runtime:latest"), "-c", "sleep 600"); err != nil {
		t.Fatal(err)
	}
	waitProxy(t, nestedHost, 20*time.Second)

	preparer, err := newBrokerPreparer("http://"+brokerIP+":7347", "", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	config := Config{
		DockerHost: nestedHost, RunsDir: filepath.Join(directory, "runs"), BrokerURL: "http://" + brokerIP + ":7347", BrokerAgentsPath: agents,
		IdentityKeyPath: filepath.Join(directory, "unused-key"), Owner: "daemon-restart-controller", ExternalNetwork: "agents-proxy", RunNetworkPool: "100.64.0.0/10",
		ProxyPort: 4090, ProtectedCIDRs: "127.0.0.0/8 169.254.0.0/16", GatewayContainer: "nvt-local-gateway",
		DindImage: environmentOr("NVT_DIND_IMAGE", "nvt-dind:latest"), EgressdImage: environmentOr("NVT_EGRESSD_IMAGE", "nvt-egressd:latest"),
		CapturedImage: environmentOr("NVT_CAPTURED_IMAGE", "nvt-captured:latest"), SeedImage: environmentOr("NVT_RUNTIME_IMAGE", "nvt-agent-runtime:latest"), OperationTimeout: 3 * time.Minute,
	}
	if err := os.Mkdir(config.RunsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x64}, 32)
	backend, err := NewWithBoundary(config, nested, key, preparer)
	if err != nil {
		t.Fatal(err)
	}
	run := daemonRestartRun(t, config, outerGateway, bypassPort)
	persistControllerSnapshotWithoutSecret(t, ctx, directory, run, credential)
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("6", 64), DeleteRequested: true}
	defer func() { _ = backend.Delete(context.Background(), desired) }()
	observation, err := backend.Ensure(ctx, desired)
	if err != nil || !observation.Ready {
		t.Fatalf("initial nested ensure = %#v %v", observation, err)
	}
	labels := ownedLabels{Owner: config.Owner, RunID: run.RunID, Digest: desired.SnapshotDigest}
	agent := ownedAgentContainer(t, ctx, nested, labels)
	waitContainerFile(t, ctx, nested, agent, "/root/restart-proof", "confined\nfresh\n", 30*time.Second)
	assertNestedMediated(t, ctx, nested, agent, credential)
	beforeRoutes, _ := backend.Routes(ctx, desired)
	oldProof := execInContainer(t, ctx, nested, agent, "cat", "/run/nvt-confinement/network-namespace")

	// Give the nested daemon enough time to persist its layer and container
	// metadata. The default ten-second restart grace can SIGKILL dockerd under
	// nested overlayfs and would test storage corruption rather than recovery.
	if _, err := outer.Run(ctx, nil, "restart", "--time", "60", dindName); err != nil {
		t.Fatal(err)
	}
	nestedHost = waitNestedDocker(t, ctx, outer, dindName, networkName)
	nested = dockerCLI{host: nestedHost}
	waitProxy(t, nestedHost, 30*time.Second)
	agent = ownedAgentContainer(t, ctx, nested, labels)
	staleProof := execInContainer(t, ctx, nested, agent, "cat", "/run/nvt-confinement/network-namespace")
	currentNamespace := currentNamespaceProof(t, ctx, nested, agent)
	if staleProof == currentNamespace {
		t.Fatalf("stale proof unlocked the restarted namespace: %q", staleProof)
	}
	time.Sleep(2 * time.Second)
	if got := execInContainer(t, ctx, nested, agent, "cat", "/root/restart-proof"); got != "confined\nfresh" {
		t.Fatalf("agent runtime started before confinement: %q", got)
	}

	config.DockerHost = nestedHost
	recovered, err := NewWithBoundary(config, nested, key, preparer)
	if err != nil {
		t.Fatal(err)
	}
	observation, err = recovered.Ensure(ctx, desired)
	if err != nil || !observation.Ready {
		t.Fatalf("daemon recovery = %#v %v", observation, err)
	}
	agent = ownedAgentContainer(t, ctx, nested, labels)
	waitContainerFile(t, ctx, nested, agent, "/root/restart-proof", "confined\nfresh\nconfined\nresume\n", 30*time.Second)
	newProof := execInContainer(t, ctx, nested, agent, "cat", "/run/nvt-confinement/network-namespace")
	currentNamespace = currentNamespaceProof(t, ctx, nested, agent)
	if newProof == oldProof || newProof != currentNamespace {
		t.Fatalf("proof was not rebound: old=%q new=%q current=%q", oldProof, newProof, currentNamespace)
	}
	assertNestedMediated(t, ctx, nested, agent, credential)
	afterRoutes, routeErr := recovered.Routes(ctx, desired)
	if routeErr != nil || fmt.Sprintf("%#v", beforeRoutes) != fmt.Sprintf("%#v", afterRoutes) {
		t.Fatalf("routes changed: before=%#v after=%#v err=%v", beforeRoutes, afterRoutes, routeErr)
	}
	names := namesFor(config, run.RunID, desired.SnapshotDigest)
	for _, volume := range []string{names.workspace, names.home} {
		if _, err := nested.Run(ctx, nil, "volume", "inspect", volume); err != nil {
			t.Fatalf("persistent volume missing: %s", volume)
		}
	}
	assertRealEngineSecretAbsent(t, ctx, nested, config, desired, agent, credential)
	backend = recovered
}

func persistControllerSnapshotWithoutSecret(t *testing.T, ctx context.Context, directory string, run resolvedrun.ResolvedAgentRun, needle string) {
	t.Helper()
	raw, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "controller-state", "local-controller.sqlite3")
	store, err := controller.OpenStore(ctx, path, controller.StoreOptions{MaxActiveRuns: 2, MaxClaimLease: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, controller.CreateInput{IdempotencyKey: "daemon-restart-state-proof", ResolvedRun: raw}); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	stateFiles, err := filepath.Glob(path + "*")
	if err != nil || len(stateFiles) == 0 {
		t.Fatal("controller state unavailable")
	}
	for _, stateFile := range stateFiles {
		contents, readErr := os.ReadFile(stateFile)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if bytes.Contains(contents, []byte(needle)) {
			t.Fatal("real credential appeared in durable controller state")
		}
	}
}

func daemonRestartRun(t *testing.T, config Config, bypassHost string, bypassPort int) resolvedrun.ResolvedAgentRun {
	t.Helper()
	run := testMediatedRun(t)
	run.RunID, run.Image, run.Runtime.Docker = "daemon-restart-run", config.SeedImage, nil
	probe := fmt.Sprintf("http://%s:%d/direct", bypassHost, bypassPort)
	command := func(mode string) string {
		return "if curl -fsS --connect-timeout 1 --max-time 2 " + probe + "; then echo bypass >> $HOME/restart-proof; else echo confined >> $HOME/restart-proof; fi; echo " + mode + " >> $HOME/restart-proof; exec sleep 600"
	}
	run.AgentConfig = []byte(fmt.Sprintf(`{"runtime":{"command":"bash","args":["-lc",%q],"resume":{"command":"bash","args":["-lc",%q]}},"plugins":[]}`, command("fresh"), command("resume")))
	run.Repositories, run.CredentialProviders = nil, nil
	run.Broker.Grants = []resolvedrun.BrokerGrant{{Provider: "provider-a", Materialization: "placeholder-file", EgressHosts: []string{"api.example.test:443"}, AllowInsecureUpstream: true}}
	run.Egress = resolvedrun.Egress{Mode: "mediated", Transport: "transparent", Enforced: true, ProxyProvider: "provider-a", PairedEgressRequired: true, AllowInsecureBroker: true}
	run.Persistence, run.Retention = resolvedrun.Persistence{Workspace: true, RuntimeState: true}, "persistent"
	if err := resolvedrun.ValidateResolvedAgentRun(run); err != nil {
		t.Fatal(err)
	}
	return run
}

func startOuterSyntheticBroker(t *testing.T, ctx context.Context, outer CommandBoundary, network, directory, suffix string) (string, string) {
	t.Helper()
	fixture := filepath.Join(directory, "provider-fixture")
	build := exec.CommandContext(ctx, "go", "build", "-o", fixture, "./executable_provider_fixture")
	build.Dir = filepath.Join(smokeRepositoryRoot(t), "tests", "broker")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build provider: %v\n%s", err, output)
	}
	agents := filepath.Join(directory, "agents.yaml")
	if err := os.WriteFile(agents, []byte("agents: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("provider-plugins:\n  - name: fixture\n    command: [%q]\n    pass-env: [FIXTURE_CREDENTIAL]\nproviders:\n  - name: provider-a\n    plugin: fixture\n    config: {state-file: /state/provider-state}\n    allow: {repositories: [\"*\"]}\n", "/provider/provider")
	if err := os.WriteFile(filepath.Join(directory, "broker.yaml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	env := "NVT_BROKER_CONFIG=/state/broker.yaml\nNVT_BROKER_AGENTS_CONFIG=/state/agents.yaml\nNVT_BROKER_AUDIT_LOG=/state/audit.jsonl\nNVT_BROKER_BIND=0.0.0.0:7347\nFIXTURE_CREDENTIAL=LOCAL-DAEMON-RESTART-CREDENTIAL-NEEDLE\n"
	envPath := filepath.Join(directory, "broker.env")
	if err := os.WriteFile(envPath, []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	name := "nvt-lc-restart-broker-" + suffix
	if _, err := outer.Run(ctx, nil, "run", "-d", "--name", name, "--network", network, "--env-file", envPath, "-v", directory+":/state", "-v", fixture+":/provider/provider:ro", environmentOr("NVT_BROKER_IMAGE", "nvt-broker:latest")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = outer.Run(context.Background(), nil, "rm", "-f", name) })
	ip := containerIPAddress(t, ctx, outer, name, network)
	if !httpReady("http://"+ip+":7347/health", 20*time.Second) {
		logs, _ := outer.Run(ctx, nil, "logs", name)
		t.Fatalf("broker unavailable: %s", logs)
	}
	return agents, ip
}

func copyImage(t *testing.T, ctx context.Context, sourceHost, destinationHost, image string) {
	t.Helper()
	source := exec.CommandContext(ctx, "docker", "image", "save", image)
	destination := exec.CommandContext(ctx, "docker", "image", "load")
	source.Env = []string{"DOCKER_HOST=" + sourceHost, "HOME=/tmp", "PATH=" + os.Getenv("PATH")}
	destination.Env = []string{"DOCKER_HOST=" + destinationHost, "HOME=/tmp", "PATH=" + os.Getenv("PATH")}
	pipe, err := source.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	destination.Stdin = pipe
	var diagnostics limitedBuffer
	source.Stderr, destination.Stdout, destination.Stderr = &diagnostics, &diagnostics, &diagnostics
	if err := destination.Start(); err != nil {
		t.Fatal(err)
	}
	if err := source.Run(); err != nil {
		_ = destination.Process.Kill()
		t.Fatalf("save %s: %v: %s", image, err, diagnostics.Bytes())
	}
	if err := destination.Wait(); err != nil {
		t.Fatalf("load %s: %v: %s", image, err, diagnostics.Bytes())
	}
}

func waitNestedDocker(t *testing.T, ctx context.Context, outer CommandBoundary, container, network string) string {
	t.Helper()
	// A restored daemon may spend longer rebuilding its image/layer metadata
	// than a fresh daemon, especially under nested overlayfs on CI hosts.
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := outer.Run(ctx, nil, "inspect", "--format", "{{(index .NetworkSettings.Networks \""+network+"\").IPAddress}}", container)
		ip := strings.TrimSpace(string(raw))
		if err == nil && net.ParseIP(ip) != nil {
			host := "tcp://" + ip + ":2375"
			if _, err := (dockerCLI{host: host}).Run(ctx, nil, "info"); err == nil {
				return host
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	state, _ := outer.Run(ctx, nil, "inspect", "--format", "{{.State.Status}} exit={{.State.ExitCode}} error={{.State.Error}}", container)
	t.Fatalf("nested Docker unavailable: state=%s", fixedDiagnostic(state))
	return ""
}

func fixedDiagnostic(value []byte) string {
	text := strings.TrimSpace(string(value))
	if len(text) > 4096 {
		text = text[len(text)-4096:]
	}
	return text
}

func networkGateway(t *testing.T, ctx context.Context, boundary CommandBoundary, network string) string {
	t.Helper()
	raw, err := boundary.Run(ctx, nil, "network", "inspect", "--format", "{{(index .IPAM.Config 0).Subnet}}", network)
	prefix, parseErr := netip.ParsePrefix(strings.TrimSpace(string(raw)))
	if err != nil || parseErr != nil || !prefix.Addr().Is4() {
		t.Fatal("network gateway unavailable")
	}
	return prefix.Addr().Next().String()
}

func waitProxy(t *testing.T, nestedHost string, timeout time.Duration) {
	t.Helper()
	ip := strings.TrimSuffix(strings.TrimPrefix(nestedHost, "tcp://"), ":2375")
	if !httpReady("http://"+ip+":18088/healthz", timeout) {
		t.Fatal("public proxy route did not recover")
	}
}

func httpReady(endpoint string, timeout time.Duration) bool {
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		response, err := client.Get(endpoint)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

func execInContainer(t *testing.T, ctx context.Context, boundary CommandBoundary, container string, command ...string) string {
	t.Helper()
	output, err := boundary.Run(ctx, nil, append([]string{"exec", container}, command...)...)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(output))
}

func currentNamespaceProof(t *testing.T, ctx context.Context, boundary CommandBoundary, container string) string {
	t.Helper()
	return execInContainer(t, ctx, boundary, container, "sh", "-ec", "printf '%s:%s\\n' \"$(cat /proc/sys/kernel/random/boot_id)\" \"$(readlink /proc/self/ns/net)\"")
}

func assertNestedMediated(t *testing.T, ctx context.Context, boundary CommandBoundary, agent, needle string) {
	t.Helper()
	response, err := boundary.Run(ctx, nil, "exec", agent, "curl", "-fsS", "--resolve", "api.example.test:443:198.51.100.1", "https://api.example.test/credential-proof")
	if err != nil || !bytes.Contains(response, []byte(`"credential_match":true`)) || bytes.Contains(response, []byte(`"placeholder_seen":true`)) {
		diagnostics, _ := boundary.Run(ctx, nil, "ps", "-a", "--format", "{{.Names}} {{.Status}}")
		if bytes.Contains(diagnostics, []byte(needle)) {
			diagnostics = []byte("diagnostics suppressed")
		}
		t.Fatalf("mediated credential unavailable: %v %s\n%s", err, response, diagnostics)
	}
}
