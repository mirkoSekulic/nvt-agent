package dockerbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/controller"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

type fakeDocker struct {
	mu         sync.Mutex
	objects    map[string]map[string]string
	containers map[string]map[string]string
	commands   [][]string
	inputs     [][]byte
	seedCount  int
}

func newFakeDocker() *fakeDocker {
	return &fakeDocker{objects: map[string]map[string]string{"network:agents-proxy": {}}, containers: map[string]map[string]string{}}
}

func (docker *fakeDocker) Run(_ context.Context, input io.Reader, arguments ...string) ([]byte, error) {
	docker.mu.Lock()
	defer docker.mu.Unlock()
	docker.commands = append(docker.commands, append([]string(nil), arguments...))
	if input != nil {
		raw, _ := io.ReadAll(input)
		docker.inputs = append(docker.inputs, raw)
	}
	if len(arguments) == 0 {
		return nil, errors.New("missing command")
	}
	if arguments[0] == "compose" {
		return docker.compose(arguments)
	}
	if arguments[0] == "create" {
		name := argumentAfter(arguments, "--name")
		if name == "" {
			docker.seedCount++
			name = strings.Repeat("a", 63) + string(rune('0'+docker.seedCount))
		}
		labels := parsedLabels(arguments)
		if _, exists := docker.containers[name]; exists {
			return nil, errors.New("exists")
		}
		docker.containers[name] = labels
		return []byte(name + "\n"), nil
	}
	if arguments[0] == "cp" {
		return nil, nil
	}
	if arguments[0] == "rm" && len(arguments) >= 3 {
		delete(docker.containers, arguments[len(arguments)-1])
		return nil, nil
	}
	if arguments[0] == "ps" {
		values := []string{}
		for id, labels := range docker.containers {
			if labelsMatchFilters(labels, arguments) {
				values = append(values, id)
			}
		}
		return []byte(strings.Join(values, "\n")), nil
	}
	if arguments[0] == "inspect" {
		id := arguments[len(arguments)-1]
		if labels, exists := docker.containers[id]; exists {
			if contains(arguments, "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{if .State.Running}}running{{else}}stopped{{end}}{{end}}") {
				return []byte("running\n"), nil
			}
			encoded, _ := json.Marshal(labels)
			return append(encoded, '\n'), nil
		}
		return nil, errors.New("missing")
	}
	if arguments[0] == "volume" || arguments[0] == "network" {
		return docker.object(arguments)
	}
	return nil, errors.New("unsupported fake command")
}

func labelsMatchFilters(labels map[string]string, arguments []string) bool {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] != "--filter" || !strings.HasPrefix(arguments[index+1], "label=") {
			continue
		}
		key, value, found := strings.Cut(strings.TrimPrefix(arguments[index+1], "label="), "=")
		if !found || labels[key] != value {
			return false
		}
	}
	return true
}

func (docker *fakeDocker) compose(arguments []string) ([]byte, error) {
	if contains(arguments, "up") {
		var labels map[string]string
		for key, value := range docker.objects {
			if strings.HasPrefix(key, "volume:") && value[runLabel] != "" {
				labels = value
				break
			}
		}
		docker.containers["fake-agent-id"] = cloneLabels(labels)
		return nil, nil
	}
	if contains(arguments, "ps") {
		return []byte("fake-agent-id\n"), nil
	}
	if contains(arguments, "down") {
		delete(docker.containers, "fake-agent-id")
		return nil, nil
	}
	return nil, errors.New("unsupported compose command")
}

func (docker *fakeDocker) object(arguments []string) ([]byte, error) {
	kind := arguments[0]
	action := arguments[1]
	name := arguments[len(arguments)-1]
	key := kind + ":" + name
	switch action {
	case "inspect":
		labels, exists := docker.objects[key]
		if !exists {
			return nil, errors.New("missing")
		}
		encoded, _ := json.Marshal(labels)
		return append(encoded, '\n'), nil
	case "create":
		if _, exists := docker.objects[key]; exists {
			return nil, errors.New("exists")
		}
		docker.objects[key] = parsedLabels(arguments)
		return []byte(name + "\n"), nil
	case "rm":
		if _, exists := docker.objects[key]; !exists {
			return nil, errors.New("missing")
		}
		delete(docker.objects, key)
		return nil, nil
	default:
		return nil, errors.New("unsupported object command")
	}
}

func TestDockerBackendRendersCompleteIdempotentZeroSecretStack(t *testing.T) {
	backend, docker, run, tokens := testBackend(t)
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("a", 64)}
	first, err := backend.Ensure(context.Background(), desired)
	if err != nil || !first.Ready {
		t.Fatalf("first ensure = %#v %v", first, err)
	}
	planPath := namesFor(backend.config, run.RunID, desired.SnapshotDigest).composeFile
	plan, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"agent:", "docker:", "egressd:", "captured:", "net-init:", "ca-init:", "network_mode: service:docker", "NVT_BROKER_TOKEN_FILE"} {
		if !bytes.Contains(plan, []byte(required)) {
			t.Fatalf("plan missing %q:\n%s", required, plan)
		}
	}
	if !secretSafePlan(plan, tokens.agent, tokens.egress, "REAL-ACCESS-TOKEN-NEEDLE") {
		t.Fatalf("plan contains a credential:\n%s", plan)
	}
	policy, err := os.ReadFile(backend.config.BrokerAgentsPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(policy, []byte(tokens.agent)) || bytes.Contains(policy, []byte(tokens.egress)) || !bytes.Contains(policy, []byte(tokenHash(tokens.agent))) {
		t.Fatalf("broker policy did not contain hashes only: %s", policy)
	}
	for _, command := range docker.commands {
		joined := strings.Join(command, " ")
		if strings.Contains(joined, tokens.agent) || strings.Contains(joined, tokens.egress) {
			t.Fatalf("credential entered command arguments: %q", joined)
		}
	}
	if len(docker.inputs) != 2 || bytes.Contains(docker.inputs[0], []byte(tokens.egress)) || !bytes.Contains(docker.inputs[1], []byte(tokens.egress)) || bytes.Contains(docker.inputs[1], []byte("REAL-ACCESS-TOKEN-NEEDLE")) {
		t.Fatalf("broker bearer was not confined to the paired-egress private seed stream")
	}
	for _, expected := range []string{"git-host-credentials", "checkout-repos", "github.example/org/repo", "NVT-PLACEHOLDER-NOT-A-KEY", "prepared-provider-metadata.json", "Example Bot"} {
		if !bytes.Contains(docker.inputs[0], []byte(expected)) {
			t.Fatalf("agent seed omitted %q", expected)
		}
	}
	if _, err := backend.Ensure(context.Background(), desired); err != nil {
		t.Fatalf("restart ensure: %v", err)
	}
	second, _ := os.ReadFile(planPath)
	if !bytes.Equal(plan, second) {
		t.Fatal("idempotent reconcile changed deterministic compose state")
	}
	observation, err := backend.Inspect(context.Background(), desired)
	if err != nil || !observation.Ready {
		t.Fatalf("inspect = %#v %v", observation, err)
	}
}

func TestDockerBackendOwnershipAndCleanupFailClosed(t *testing.T) {
	backend, docker, run, _ := testBackend(t)
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("b", 64), DeleteRequested: true}
	names := namesFor(backend.config, run.RunID, desired.SnapshotDigest)
	legacySeedName := names.project + "-seed-agent-config"
	docker.containers[legacySeedName] = map[string]string{ownerLabel: "another-controller"}
	docker.objects["volume:"+names.workspace] = map[string]string{ownerLabel: "another-controller", runLabel: run.RunID, digestLabel: desired.SnapshotDigest}
	if _, err := backend.Ensure(context.Background(), desired); err == nil {
		t.Fatal("unmanaged same-name volume was adopted")
	}
	if labels := docker.objects["volume:"+names.workspace]; labels[ownerLabel] != "another-controller" {
		t.Fatal("unmanaged volume was changed")
	}
	if _, exists := docker.containers[legacySeedName]; !exists {
		t.Fatal("unmanaged same-name helper container was removed")
	}

	delete(docker.objects, "volume:"+names.workspace)
	if _, err := backend.Ensure(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	docker.objects["volume:unmanaged-other-run"] = map[string]string{ownerLabel: backend.config.Owner, runLabel: "other", digestLabel: strings.Repeat("c", 64)}
	if err := backend.Delete(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	if _, exists := docker.objects["volume:unmanaged-other-run"]; !exists {
		t.Fatal("cleanup touched another run")
	}
	if _, exists := docker.containers[legacySeedName]; !exists {
		t.Fatal("cleanup touched an unmanaged helper-name collision")
	}
	for key, labels := range docker.objects {
		if labels[runLabel] == run.RunID {
			t.Fatalf("owned resource remained after explicit delete: %s", key)
		}
	}
}

func TestBrokerRegistryNeverAdoptsOrDeletesCollidingIdentity(t *testing.T) {
	backend, _, run, _ := testBackend(t)
	agentID, _ := brokerIDs(run.RunID)
	collision := "agents:\n  - id: " + agentID + "\n    token-sha256: sha256:" + strings.Repeat("f", 64) + "\n    grants: []\n"
	if err := os.WriteFile(backend.config.BrokerAgentsPath, []byte(collision), 0o600); err != nil {
		t.Fatal(err)
	}
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("f", 64), DeleteRequested: true}
	if _, err := backend.Ensure(context.Background(), desired); err == nil {
		t.Fatal("colliding broker identity was adopted")
	}
	if err := backend.Delete(context.Background(), desired); err == nil {
		t.Fatal("colliding broker identity was deleted")
	}
	retained, _ := os.ReadFile(backend.config.BrokerAgentsPath)
	if !bytes.Contains(retained, []byte(strings.Repeat("f", 64))) {
		t.Fatal("colliding registry entry changed")
	}
}

func TestDockerBackendRejectsCredentialBearingDirectRunBeforeCreatingResources(t *testing.T) {
	backend, docker, run, _ := testBackend(t)
	run.Repositories = nil
	run.CredentialProviders = nil
	run.Broker.Grants = []resolvedrun.BrokerGrant{{Provider: "direct-provider", Materialization: "file-bundle"}}
	run.Egress = resolvedrun.Egress{Mode: "direct"}
	if err := resolvedrun.ValidateResolvedAgentRun(run); err != nil {
		t.Fatal(err)
	}
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("9", 64)}
	if _, err := backend.Ensure(context.Background(), desired); err == nil {
		t.Fatal("credential-bearing direct run was accepted")
	}
	if len(docker.commands) != 0 {
		t.Fatalf("rejected direct run touched Docker: %v", docker.commands)
	}
	policy, err := os.ReadFile(backend.config.BrokerAgentsPath)
	if err != nil || string(policy) != "agents: []\n" {
		t.Fatalf("rejected direct run changed broker registry: %q %v", policy, err)
	}
}

func TestDockerBackendPreservesPersistentVolumesUntilExplicitDelete(t *testing.T) {
	backend, docker, run, _ := testBackend(t)
	run.Persistence = resolvedrun.Persistence{Workspace: true, RuntimeState: true, DockerData: true}
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("d", 64)}
	if _, err := backend.Ensure(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	if err := backend.Delete(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	names := namesFor(backend.config, run.RunID, desired.SnapshotDigest)
	for _, name := range []string{names.workspace, names.home, names.dockerData} {
		if _, exists := docker.objects["volume:"+name]; !exists {
			t.Fatalf("persistent volume %s was removed", name)
		}
	}
	explicit := desired
	explicit.DeleteRequested = true
	if err := backend.Delete(context.Background(), explicit); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{names.workspace, names.home, names.dockerData} {
		if _, exists := docker.objects["volume:"+name]; exists {
			t.Fatalf("explicit delete retained volume %s", name)
		}
	}
}

func TestRenderedStackPassesRealComposeParser(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker CLI unavailable")
	}
	for _, withDocker := range []bool{false, true} {
		t.Run(strconv.FormatBool(withDocker), func(t *testing.T) {
			run := testMediatedRun(t)
			if !withDocker {
				run.Runtime.Docker = nil
			}
			config := Config{Owner: "test-controller", ExternalNetwork: "agents-proxy", ProxyPort: 4090, ProtectedCIDRs: "127.0.0.0/8 169.254.0.0/16", DindImage: "nvt-dind:test", EgressdImage: "nvt-egressd:test", CapturedImage: "nvt-captured:test", SeedImage: "nvt-runtime:test"}
			names := namesFor(Config{RunsDir: t.TempDir()}, run.RunID, strings.Repeat("e", 64))
			plan, err := renderCompose(config, run, strings.Repeat("e", 64), names)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "compose.yaml")
			if err := os.WriteFile(path, plan, 0o600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("docker", "compose", "-f", path, "config", "--quiet")
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("docker compose config: %v\n%s\n%s", err, output, plan)
			}
		})
	}
}

func TestNonRootStackPreparesWritableWorkspaceWithoutHostBind(t *testing.T) {
	run := testMediatedRun(t)
	run.Runtime.User = "non-root"
	config := Config{Owner: "test-controller", ExternalNetwork: "agents-proxy", ProxyPort: 4090, ProtectedCIDRs: "127.0.0.0/8 169.254.0.0/16", DindImage: "nvt-dind:test", EgressdImage: "nvt-egressd:test", CapturedImage: "nvt-captured:test", SeedImage: "nvt-runtime:test"}
	names := namesFor(Config{RunsDir: t.TempDir()}, run.RunID, strings.Repeat("6", 64))
	plan, err := renderCompose(config, run, strings.Repeat("6", 64), names)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"workspace-init:", "chown 1000:1000 /workspace", "user: 1000:1000", "condition: service_completed_successfully"} {
		if !bytes.Contains(plan, []byte(expected)) {
			t.Fatalf("non-root stack omitted %q:\n%s", expected, plan)
		}
	}
	if bytes.Contains(plan, []byte(":/var/run/docker.sock")) || bytes.Contains(plan, []byte("/Users/")) {
		t.Fatalf("non-root stack contains a host bind path:\n%s", plan)
	}
}

func TestDockerStackPreservesBoundedAgentHTTPExposures(t *testing.T) {
	run := testMediatedRun(t)
	run.AgentConfig = json.RawMessage(`{"runtime":{"command":"agent-cli","args":[]},"plugins":[],"expose":{"http":[{"name":"app","targetPort":3000},{"name":"api","targetPort":8080,"source":"agent"}]}}`)
	config := Config{Owner: "test-controller", ExternalNetwork: "agents-proxy", ProxyPort: 4090, ProtectedCIDRs: "127.0.0.0/8 169.254.0.0/16", DindImage: "nvt-dind:test", EgressdImage: "nvt-egressd:test", CapturedImage: "nvt-captured:test", SeedImage: "nvt-runtime:test"}
	names := namesFor(Config{RunsDir: t.TempDir()}, run.RunID, strings.Repeat("5", 64))
	plan, err := renderCompose(config, run, strings.Repeat("5", 64), names)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"NVT_EXPOSED_HTTP_ROUTES_JSON", `[{"name":"app","targetPort":3000,"source":"agent"}`,
		"app.docker-run.agent.localhost", `loadbalancer.server.port: "3000"`, "api.docker-run.agent.localhost", `loadbalancer.server.port: "8080"`,
	} {
		if !bytes.Contains(plan, []byte(expected)) {
			t.Fatalf("exposure stack omitted %q:\n%s", expected, plan)
		}
	}
	for _, invalid := range []json.RawMessage{
		json.RawMessage(`{"runtime":{"command":"agent-cli"},"plugins":[],"expose":{"http":[{"name":"Bad","targetPort":3000}]}}`),
		json.RawMessage(`{"runtime":{"command":"agent-cli"},"plugins":[],"expose":{"http":[{"name":"app","targetPort":0}]}}`),
		json.RawMessage(`{"runtime":{"command":"agent-cli"},"plugins":[],"expose":{"http":[{"name":"app","targetPort":3000,"source":"docker"}]}}`),
	} {
		run.AgentConfig = invalid
		if _, err := renderCompose(config, run, strings.Repeat("5", 64), names); err == nil {
			t.Fatalf("invalid HTTP exposure was accepted: %s", invalid)
		}
	}
}

func TestStackOmitsDinDWhenRuntimeDoesNotRequestDocker(t *testing.T) {
	run := testMediatedRun(t)
	run.Runtime.Docker = nil
	config := Config{Owner: "test-controller", ExternalNetwork: "agents-proxy", ProxyPort: 4090, ProtectedCIDRs: "127.0.0.0/8 169.254.0.0/16", DindImage: "nvt-dind:test", EgressdImage: "nvt-egressd:test", CapturedImage: "nvt-captured:test", SeedImage: "nvt-runtime:test"}
	names := namesFor(Config{RunsDir: t.TempDir()}, run.RunID, strings.Repeat("4", 64))
	plan, err := renderCompose(config, run, strings.Repeat("4", 64), names)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"network:", "network_mode: service:network", "image: nvt-runtime:test", "captured:", "net-init:"} {
		if !bytes.Contains(plan, []byte(expected)) {
			t.Fatalf("Docker-free stack omitted %q:\n%s", expected, plan)
		}
	}
	for _, forbidden := range []string{"docker-data:", "DOCKER_HOST:", "privileged: true", "network_mode: service:docker"} {
		if bytes.Contains(plan, []byte(forbidden)) {
			t.Fatalf("Docker-free stack retained %q:\n%s", forbidden, plan)
		}
	}
}

func testBackend(t *testing.T) (*Backend, *fakeDocker, resolvedrun.ResolvedAgentRun, identityTokens) {
	t.Helper()
	directory := t.TempDir()
	agents := filepath.Join(directory, "agents.yaml")
	if err := os.WriteFile(agents, []byte("agents: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !strings.HasPrefix(request.Header.Get("Authorization"), "Bearer nvt_local_") {
			http.Error(response, "denied", http.StatusForbidden)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/placeholder-files":
			_, _ = io.WriteString(response, `{"ok":true,"files":[{"path":".agent/auth.json","content":"{\"access_token\":\"NVT-PLACEHOLDER-NOT-A-KEY\"}\\n","mode":"0600"}],"hosts":["api.example.test"],"expires_at":null}`)
		case "/v1/identity":
			_, _ = io.WriteString(response, `{"ok":true,"name":"Example Bot","email":"bot@example.test"}`)
		default:
			http.Error(response, "not found", http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	config := Config{
		DockerHost: "unix:///var/run/docker.sock", RunsDir: filepath.Join(directory, "runs"), BrokerURL: server.URL,
		BrokerAgentsPath: agents, IdentityKeyPath: filepath.Join(directory, "key"), Owner: "test-controller", ExternalNetwork: "agents-proxy",
		ProxyPort:      4090,
		ProtectedCIDRs: "127.0.0.0/8 169.254.0.0/16",
		DindImage:      "nvt-dind:test", EgressdImage: "nvt-egressd:test", CapturedImage: "nvt-captured:test", SeedImage: "nvt-runtime:test",
		OperationTimeout: 30 * time.Second,
	}
	key := bytes.Repeat([]byte{0x42}, 32)
	preparer, err := newBrokerPreparer(server.URL, "", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	docker := newFakeDocker()
	backend, err := NewWithBoundary(config, docker, key, preparer)
	if err != nil {
		t.Fatal(err)
	}
	run := testMediatedRun(t)
	return backend, docker, run, deriveTokens(key, run.RunID, strings.Repeat("a", 64))
}

func testMediatedRun(t *testing.T) resolvedrun.ResolvedAgentRun {
	t.Helper()
	run := resolvedrun.ResolvedAgentRun{
		ContractVersion: resolvedrun.ContractVersion, RunID: "docker-run",
		Principal: resolvedrun.Principal{Issuer: "https://identity.example", Subject: "subject-1"}, Profile: "dynamic", Workflow: "work",
		Image: "nvt-agent-runtime:test", Runtime: resolvedrun.Runtime{Type: "generic-agent", Autonomy: "interactive", User: "root", Docker: &resolvedrun.RuntimeDocker{}},
		AgentConfig: json.RawMessage(`{"runtime":{"command":"agent-cli","args":[]},"plugins":[]}`),
		Repositories: []resolvedrun.Repository{{
			CheckoutTarget: "github.example/org/repo", BrokerRepository: "org/repo", URL: "https://github.example/org/repo.git",
			CredentialProvider: "git-provider", Identity: &resolvedrun.RepositoryIdentity{Mode: "provider"},
		}},
		CredentialProviders: []resolvedrun.CredentialProviderMapping{{
			Name: "git-provider", BrokerProvider: "git-provider", CredentialKind: "mediated", MatchTargets: []string{"github.example/org/repo"},
		}},
		Broker: resolvedrun.Broker{Grants: []resolvedrun.BrokerGrant{
			{Provider: "provider-a", Materialization: "placeholder-file", EgressHosts: []string{"api.example.test:443"}},
			{Provider: "git-provider", Materialization: "header-inject", EgressHosts: []string{"github.example:443"}, Repositories: []string{"org/repo"}, Preparations: []string{"identity"}, Git: true},
		}},
		Egress:      resolvedrun.Egress{Mode: "mediated", Transport: "transparent", Enforced: true, ProxyProvider: "provider-a", PairedEgressRequired: true, AllowInsecureBroker: true},
		Persistence: resolvedrun.Persistence{}, Retention: "disposable", TTL: resolvedrun.TTL{ActiveSeconds: 300, FailedSeconds: 60},
		Lifecycle: resolvedrun.Lifecycle{CompleteOn: []string{"work.done"}, FailOn: []string{"work.failed"}},
		Execution: resolvedrun.ExecutionBackend{Name: "docker", Kind: "container"},
	}
	if err := resolvedrun.ValidateResolvedAgentRun(run); err != nil {
		t.Fatalf("test run invalid: %v", err)
	}
	return run
}

func parsedLabels(arguments []string) map[string]string {
	result := map[string]string{}
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] != "--label" {
			continue
		}
		key, value, _ := strings.Cut(arguments[index+1], "=")
		result[key] = value
	}
	return result
}

func argumentAfter(arguments []string, name string) string {
	for index := range arguments {
		if arguments[index] == name && index+1 < len(arguments) {
			return arguments[index+1]
		}
	}
	return ""
}

func contains(arguments []string, value string) bool {
	for _, argument := range arguments {
		if argument == value {
			return true
		}
	}
	return false
}

func cloneLabels(input map[string]string) map[string]string {
	result := map[string]string{}
	for key, value := range input {
		result[key] = value
	}
	return result
}
