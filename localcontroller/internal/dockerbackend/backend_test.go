package dockerbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/controller"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
	"gopkg.in/yaml.v3"
)

type fakeDocker struct {
	mu              sync.Mutex
	objects         map[string]map[string]string
	objectSubnets   map[string]string
	networkMembers  map[string]map[string]bool
	containers      map[string]map[string]string
	commands        [][]string
	inputs          [][]byte
	seedCount       int
	agentAbsent     bool
	agentStatus     string
	agentExitCode   int
	agentOOM        bool
	gatewayStatus   string
	gatewayHealth   string
	failComposeUp   int
	caRenewal       bool
	failRemove      string
	lifecycleEvents []string
	lifecycleCursor string
	lifecycleErr    error
}

func newFakeDocker() *fakeDocker {
	return &fakeDocker{
		objects: map[string]map[string]string{"network:agents-proxy": {}}, objectSubnets: map[string]string{}, networkMembers: map[string]map[string]bool{},
		containers: map[string]map[string]string{"nvt-local-gateway": {localGatewayLabel: "true"}},
	}
}

func (docker *fakeDocker) Run(_ context.Context, input io.Reader, arguments ...string) ([]byte, error) {
	docker.mu.Lock()
	defer docker.mu.Unlock()
	docker.commands = append(docker.commands, append([]string(nil), arguments...))
	var rawInput []byte
	if input != nil {
		rawInput, _ = io.ReadAll(input)
		docker.inputs = append(docker.inputs, rawInput)
	}
	if len(arguments) == 0 {
		return nil, errors.New("missing command")
	}
	if arguments[0] == "info" {
		return []byte("27.0.0\n"), nil
	}
	if arguments[0] == "compose" {
		return docker.compose(arguments)
	}
	if arguments[0] == "exec" || arguments[0] == "run" && contains(arguments, lifecycleEventReader) {
		if docker.lifecycleErr != nil {
			return nil, docker.lifecycleErr
		}
		var request struct {
			Cursor string `json:"cursor"`
		}
		if json.Unmarshal(rawInput, &request) != nil {
			return nil, errors.New("invalid lifecycle request")
		}
		cursor := docker.lifecycleCursor
		if cursor == "" {
			cursor = request.Cursor
		}
		response, _ := json.Marshal(lifecycleReaderResponse{Version: 1, Cursor: cursor, Events: append([]string{}, docker.lifecycleEvents...)})
		return append(response, '\n'), nil
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
			if contains(arguments, "{{json .State}}") {
				status := docker.agentStatus
				health := ""
				if id == "nvt-local-gateway" {
					status = docker.gatewayStatus
					health = docker.gatewayHealth
				}
				if status == "" {
					status = "running"
				}
				state := map[string]any{"Running": status != "stopped", "OOMKilled": docker.agentOOM, "ExitCode": docker.agentExitCode}
				if health != "" {
					state["Health"] = map[string]any{"Status": health}
				} else if id != "nvt-local-gateway" && (status == "healthy" || status == "starting" || status == "unhealthy") {
					state["Health"] = map[string]any{"Status": status}
				}
				encoded, _ := json.Marshal(state)
				return append(encoded, '\n'), nil
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
	if contains(arguments, "run") && contains(arguments, "ca-init") {
		if contains(arguments, "NVT_EGRESS_CA_CHECK_ONLY=1") && docker.caRenewal {
			return []byte("renewal-required\n"), nil
		}
		if !contains(arguments, "NVT_EGRESS_CA_CHECK_ONLY=1") {
			docker.caRenewal = false
		}
		return nil, nil
	}
	if contains(arguments, "stop") {
		return nil, nil
	}
	if contains(arguments, "up") {
		if docker.failComposeUp > 0 {
			docker.failComposeUp--
			return nil, errors.New("temporary Docker unavailable")
		}
		var labels map[string]string
		project := argumentAfter(arguments, "-p")
		for key, value := range docker.objects {
			if strings.HasPrefix(key, "volume:"+project+"-") && value[runLabel] != "" {
				labels = value
				break
			}
		}
		labels = cloneLabels(labels)
		labels[composeProjectLabel] = project
		labels[composeServiceLabel] = "agent"
		if plan, err := os.ReadFile(argumentAfter(arguments, "-f")); err == nil && bytes.Contains(plan, []byte(agentConfinementRevisionLabel+":")) {
			labels[agentConfinementRevisionLabel] = agentConfinementRevision
		}
		docker.containers["fake-agent-id"] = labels
		return nil, nil
	}
	if contains(arguments, "ps") {
		if docker.agentAbsent {
			return nil, nil
		}
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
	if kind == "network" && (action == "connect" || action == "disconnect") {
		network := arguments[len(arguments)-2]
		container := arguments[len(arguments)-1]
		if _, exists := docker.objects["network:"+network]; !exists {
			return nil, errors.New("missing")
		}
		if action == "connect" {
			if docker.networkMembers[network] == nil {
				docker.networkMembers[network] = map[string]bool{}
			}
			docker.networkMembers[network][container] = true
		} else if docker.networkMembers[network] != nil {
			delete(docker.networkMembers[network], container)
		}
		return nil, nil
	}
	if action == "ls" {
		values := []string{}
		for key, labels := range docker.objects {
			prefix := kind + ":"
			if strings.HasPrefix(key, prefix) && labelsMatchFilters(labels, arguments) {
				values = append(values, strings.TrimPrefix(key, prefix))
			}
		}
		return []byte(strings.Join(values, "\n")), nil
	}
	name := arguments[len(arguments)-1]
	key := kind + ":" + name
	switch action {
	case "inspect":
		labels, exists := docker.objects[key]
		if !exists {
			return nil, errors.New("missing")
		}
		if contains(arguments, "{{json .Containers}}") {
			members := map[string]dockerNetworkEndpoint{}
			for container := range docker.networkMembers[name] {
				members[container] = dockerNetworkEndpoint{Name: container}
			}
			encoded, _ := json.Marshal(members)
			return append(encoded, '\n'), nil
		}
		if contains(arguments, "{{json .IPAM.Config}}") {
			encoded, _ := json.Marshal([]map[string]string{{"Subnet": docker.objectSubnets[key]}})
			return append(encoded, '\n'), nil
		}
		encoded, _ := json.Marshal(labels)
		return append(encoded, '\n'), nil
	case "create":
		if _, exists := docker.objects[key]; exists {
			return nil, errors.New("exists")
		}
		docker.objects[key] = parsedLabels(arguments)
		if kind == "network" {
			docker.objectSubnets[key] = argumentAfter(arguments, "--subnet")
		}
		return []byte(name + "\n"), nil
	case "rm":
		if _, exists := docker.objects[key]; !exists {
			return nil, errors.New("missing")
		}
		if docker.failRemove == kind {
			docker.failRemove = ""
			return nil, errors.New("temporary remove failure")
		}
		delete(docker.objects, key)
		delete(docker.objectSubnets, key)
		delete(docker.networkMembers, name)
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
	for _, required := range []string{
		"agent:", "docker:", "egressd:", "captured:", "net-init:", "confinement-init:", "ca-init:", "network_mode: service:docker", "NVT_BROKER_TOKEN_FILE",
		"confinement:/run/nvt-confinement:ro", "confinement-request:/run/nvt-confinement-request", "confinement:/confinement", "current network confinement was not established",
		agentConfinementRevisionLabel, "/proc/sys/kernel/random/boot_id", "/proc/sys/kernel/random/uuid", "readlink /proc/self/ns/net",
		"iptables -t nat -C NVT_DIND -i docker0", "iptables -t nat -C NVT_DIND -i br-+", "ip6tables -t nat -C NVT_DIND -i docker0", "ip6tables -t nat -C NVT_DIND -i br-+",
	} {
		if !bytes.Contains(plan, []byte(required)) {
			t.Fatalf("plan missing %q:\n%s", required, plan)
		}
	}
	proofInvalidation := bytes.Index(plan, []byte(`rm -f "$$proof_file"`))
	failClosedRedirect := bytes.Index(plan, []byte("iptables -t nat -I OUTPUT 1 -p tcp -j REDIRECT --to-ports 15001"))
	jumpRemoval := bytes.Index(plan, []byte("while iptables -t nat -D OUTPUT -j NVT_CAPTURE"))
	failClosedCleanup := bytes.Index(plan, []byte("while iptables -t nat -D OUTPUT -p tcp -j REDIRECT --to-ports 15001"))
	proofWrite := bytes.Index(plan, []byte(`printf '%s\n' "$$namespace:$$request"`))
	if proofInvalidation < 0 || failClosedRedirect < proofInvalidation || jumpRemoval < failClosedRedirect || failClosedCleanup < jumpRemoval || proofWrite < failClosedCleanup || !bytes.Contains(plan, []byte(`"$$proof" = "$$namespace"`)) {
		t.Fatalf("per-start proof does not force capture replacement before acknowledgment:\n%s", plan)
	}
	if !secretSafePlan(plan, tokens.agent, tokens.egress, "REAL-ACCESS-TOKEN-NEEDLE") {
		t.Fatalf("plan contains a credential:\n%s", plan)
	}
	names := namesFor(backend.config, run.RunID, desired.SnapshotDigest)
	managedPool := netip.MustParsePrefix("172.30.0.0/15")
	seenSubnets := map[string]bool{}
	for _, name := range []string{names.internalNet, names.privateNet} {
		subnet, err := netip.ParsePrefix(docker.objectSubnets["network:"+name])
		if err != nil || subnet.Bits() != runNetworkPrefixBits || subnet.Overlaps(managedPool) || seenSubnets[subnet.String()] {
			t.Fatalf("backend network subnet = %q, %v", subnet, err)
		}
		seenSubnets[subnet.String()] = true
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
		if len(command) > 0 && command[0] == "create" && !contains(command, seedHelperLabel+"="+seedHelperValue) {
			t.Fatalf("seed helper omitted its exact-owned identity: %q", joined)
		}
	}
	if len(docker.inputs) < 3 || bytes.Contains(docker.inputs[0], []byte(tokens.egress)) || !bytes.Contains(docker.inputs[1], []byte(tokens.egress)) || bytes.Contains(docker.inputs[1], []byte("REAL-ACCESS-TOKEN-NEEDLE")) {
		t.Fatalf("broker bearer was not confined to the paired-egress private seed stream")
	}
	for _, input := range docker.inputs[2:] {
		if bytes.Contains(input, []byte(tokens.agent)) || bytes.Contains(input, []byte(tokens.egress)) || bytes.Contains(input, []byte("REAL-ACCESS-TOKEN-NEEDLE")) {
			t.Fatal("credential entered lifecycle observation input")
		}
	}
	for _, expected := range []string{"git-host-credentials", "checkout-repos", "github.example/org/repo", "NVT-PLACEHOLDER-NOT-A-KEY", "prepared-provider-metadata.json", "Example Bot", `"resume":{"args":["resume","--last"],"command":"agent-cli"}`} {
		if !bytes.Contains(docker.inputs[0], []byte(expected)) {
			t.Fatalf("agent seed omitted %q", expected)
		}
	}
	netInitID := "exact-owned-net-init"
	docker.containers[netInitID] = map[string]string{
		ownerLabel: backend.config.Owner, runLabel: run.RunID, digestLabel: desired.SnapshotDigest,
		composeProjectLabel: names.project, composeServiceLabel: "net-init",
	}
	if _, err := backend.Ensure(context.Background(), desired); err != nil {
		t.Fatalf("restart ensure: %v", err)
	}
	if _, exists := docker.containers[netInitID]; exists {
		t.Fatal("restart reconciliation did not recreate the exact-owned net-init proof writer")
	}
	removeIndex, composeIndex := -1, -1
	for index, command := range docker.commands {
		if len(command) >= 3 && command[0] == "rm" && command[len(command)-1] == netInitID {
			removeIndex = index
		}
		if command[0] == "compose" && contains(command, "up") {
			composeIndex = index
		}
	}
	if removeIndex < 0 || composeIndex < 0 || removeIndex > composeIndex {
		t.Fatalf("net-init was not removed before Compose convergence: %v", docker.commands)
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

func TestSeedHelperIdentityIsVerified(t *testing.T) {
	backend, docker, run, _ := testBackend(t)
	labels := ownedLabels{Owner: backend.config.Owner, RunID: run.RunID, Digest: strings.Repeat("a", 64)}
	docker.containers["seed-helper"] = labelMap(labels)
	if err := backend.verifySeedHelperContainer(context.Background(), "seed-helper", labels); !errors.Is(err, errOwnershipConflict) {
		t.Fatalf("unmarked seed helper verification = %v", err)
	}
	docker.containers["seed-helper"][seedHelperLabel] = seedHelperValue
	if err := backend.verifySeedHelperContainer(context.Background(), "seed-helper", labels); err != nil {
		t.Fatalf("exact seed helper verification = %v", err)
	}
}

func TestEnsureRecreatesLegacyExactOwnedAgentBeforeReadiness(t *testing.T) {
	backend, docker, run, _ := testBackend(t)
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("7", 64)}
	names := namesFor(backend.config, run.RunID, desired.SnapshotDigest)
	legacyID := "legacy-exact-owned-agent"
	docker.containers[legacyID] = map[string]string{
		ownerLabel: backend.config.Owner, runLabel: run.RunID, digestLabel: desired.SnapshotDigest,
		composeProjectLabel: names.project, composeServiceLabel: "agent",
	}
	observation, err := backend.Ensure(context.Background(), desired)
	if err != nil || !observation.Ready {
		t.Fatalf("legacy upgrade ensure = %#v %v", observation, err)
	}
	if _, exists := docker.containers[legacyID]; exists {
		t.Fatal("legacy exact-owned agent survived confinement renderer upgrade")
	}
	if got := docker.containers["fake-agent-id"][agentConfinementRevisionLabel]; got != agentConfinementRevision {
		t.Fatalf("replacement agent confinement revision = %q", got)
	}
	removeIndex, composeIndex := -1, -1
	for index, command := range docker.commands {
		if len(command) >= 3 && command[0] == "rm" && command[len(command)-1] == legacyID {
			removeIndex = index
		}
		if command[0] == "compose" && contains(command, "up") {
			composeIndex = index
		}
	}
	if removeIndex < 0 || composeIndex < 0 || removeIndex > composeIndex {
		t.Fatalf("legacy agent was not removed before Compose convergence: %v", docker.commands)
	}
	for _, retained := range []string{names.workspace, names.home, names.dockerData} {
		if _, exists := docker.objects["volume:"+retained]; !exists {
			t.Fatalf("persistent volume was not retained during agent upgrade: %s", retained)
		}
	}
}

func TestConfinementGateIsLimitedToEnforcedTransparentRuns(t *testing.T) {
	run := testMediatedRun(t)
	config := Config{Owner: "test-controller", ExternalNetwork: "agents-proxy", ProxyPort: 4090, ProtectedCIDRs: "127.0.0.0/8 169.254.0.0/16", DindImage: "nvt-dind:test", EgressdImage: "nvt-egressd:test", CapturedImage: "nvt-captured:test", SeedImage: "nvt-runtime:test"}
	names := namesFor(Config{RunsDir: t.TempDir()}, run.RunID, strings.Repeat("3", 64))
	plan, err := renderCompose(config, run, strings.Repeat("3", 64), names)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"entrypoint:\n", "- sh", "network-namespace", names.confinement, "restart: unless-stopped"} {
		if !bytes.Contains(plan, []byte(expected)) {
			t.Fatalf("enforced transparent plan omitted %q:\n%s", expected, plan)
		}
	}

	run.Egress = resolvedrun.Egress{Mode: "direct"}
	run.Broker.Grants = nil
	run.Repositories = nil
	run.CredentialProviders = nil
	direct, err := renderCompose(config, run, strings.Repeat("3", 64), names)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"network-namespace", "nvt-confinement", names.confinement, names.confinementRequest, agentConfinementRevisionLabel} {
		if bytes.Contains(direct, []byte(forbidden)) {
			t.Fatalf("direct run received confinement gate %q:\n%s", forbidden, direct)
		}
	}
}

func TestAgentHealthcheckAllowsBoundedColdBootstrap(t *testing.T) {
	run := testMediatedRun(t)
	config := Config{Owner: "test-controller", ExternalNetwork: "agents-proxy", ProxyPort: 4090, ProtectedCIDRs: "127.0.0.0/8 169.254.0.0/16", DindImage: "nvt-dind:test", EgressdImage: "nvt-egressd:test", CapturedImage: "nvt-captured:test", SeedImage: "nvt-runtime:test"}
	names := namesFor(Config{RunsDir: t.TempDir()}, run.RunID, strings.Repeat("3", 64))
	plan, err := renderCompose(config, run, strings.Repeat("3", 64), names)
	if err != nil {
		t.Fatal(err)
	}
	var document composeDocument
	if err := yaml.Unmarshal(plan, &document); err != nil {
		t.Fatal(err)
	}
	healthcheck := document.Services["agent"].Healthcheck
	if healthcheck == nil || !reflect.DeepEqual(healthcheck.Test, []string{"CMD-SHELL", "health"}) || healthcheck.Interval != "10s" || healthcheck.Timeout != "2s" || healthcheck.StartPeriod != "15m" || healthcheck.Retries != 3 {
		t.Fatalf("agent healthcheck does not preserve the bounded bootstrap grace: %#v", healthcheck)
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
	orphanID := "unmanaged-project-orphan"
	docker.containers[orphanID] = map[string]string{"com.docker.compose.project": names.project, "com.docker.compose.service": "old-service"}
	if _, err := backend.Ensure(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	if _, exists := docker.containers[orphanID]; !exists {
		t.Fatal("compose ensure removed an unmanaged same-project orphan")
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
	if _, exists := docker.containers[orphanID]; !exists {
		t.Fatal("cleanup touched an unmanaged same-project orphan")
	}
	for _, command := range docker.commands {
		if contains(command, "--remove-orphans") || contains(command, "down") {
			t.Fatalf("broad Compose cleanup bypassed ownership checks: %v", command)
		}
		if len(command) > 0 && command[0] == "rm" && !contains(command, "--volumes") {
			t.Fatalf("exact-owned container cleanup retained anonymous volumes: %v", command)
		}
	}
	for key, labels := range docker.objects {
		if labels[runLabel] == run.RunID {
			t.Fatalf("owned resource remained after explicit delete: %s", key)
		}
	}
}

func TestRestartReconcilePrunesExactStaleResourcesAndRetainsOnlyPersistentData(t *testing.T) {
	backend, docker, run, _ := testBackend(t)
	run.Persistence = resolvedrun.Persistence{Workspace: true, RuntimeState: true, DockerData: true}
	run.Retention = "persistent"
	if err := resolvedrun.ValidateResolvedAgentRun(run); err != nil {
		t.Fatal(err)
	}
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("9", 64)}
	if observation, err := backend.Ensure(context.Background(), desired); err != nil || !observation.Ready {
		t.Fatalf("initial ensure = %#v, %v", observation, err)
	}
	names := namesFor(backend.config, run.RunID, desired.SnapshotDigest)
	labels := ownedLabels{Owner: backend.config.Owner, RunID: run.RunID, Digest: desired.SnapshotDigest}
	docker.containers["stale-owned-service"] = map[string]string{
		ownerLabel: labels.Owner, runLabel: labels.RunID, digestLabel: labels.Digest,
		composeProjectLabel: names.project, composeServiceLabel: "obsolete",
	}
	docker.containers["unmanaged-same-project"] = map[string]string{composeProjectLabel: names.project, composeServiceLabel: "obsolete"}
	docker.objects["volume:"+names.project+"-obsolete"] = labelMap(labels)
	docker.objects["network:"+names.project+"-obsolete"] = labelMap(labels)
	docker.objectSubnets["network:"+names.project+"-obsolete"] = "100.127.255.240/28"
	otherLabels := ownedLabels{Owner: backend.config.Owner, RunID: "other-run", Digest: strings.Repeat("8", 64)}
	docker.objects["volume:other-run-workspace"] = labelMap(otherLabels)

	if observation, err := backend.Ensure(context.Background(), desired); err != nil || !observation.Ready {
		t.Fatalf("restart ensure = %#v, %v", observation, err)
	}
	for _, key := range []string{"stale-owned-service", "volume:" + names.project + "-obsolete", "network:" + names.project + "-obsolete"} {
		_, containerExists := docker.containers[key]
		_, objectExists := docker.objects[key]
		if containerExists || objectExists {
			t.Fatalf("exact-owned stale resource survived: %s", key)
		}
	}
	if _, exists := docker.containers["unmanaged-same-project"]; !exists {
		t.Fatal("restart reconciliation removed unmanaged same-project resource")
	}
	if _, exists := docker.objects["volume:other-run-workspace"]; !exists {
		t.Fatal("restart reconciliation removed another run resource")
	}

	if err := backend.Delete(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	for _, retained := range []string{names.workspace, names.home, names.dockerData} {
		if _, exists := docker.objects["volume:"+retained]; !exists {
			t.Fatalf("persistent volume was removed: %s", retained)
		}
	}
	for _, removed := range []string{names.agentConfig, names.egressPrivate, names.egressPublic, names.confinement, names.confinementRequest} {
		if _, exists := docker.objects["volume:"+removed]; exists {
			t.Fatalf("ephemeral volume survived cleanup: %s", removed)
		}
	}
	if _, err := os.Stat(filepath.Dir(names.composeFile)); !os.IsNotExist(err) {
		t.Fatalf("generated Compose state survived cleanup: %v", err)
	}

	desired.DeleteRequested = true
	if err := backend.Delete(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	for _, retained := range []string{names.workspace, names.home, names.dockerData} {
		if _, exists := docker.objects["volume:"+retained]; exists {
			t.Fatalf("explicit deletion retained volume: %s", retained)
		}
	}
}

func TestDockerBackendPreflightPreservesUnmanagedDeclaredService(t *testing.T) {
	backend, docker, run, _ := testBackend(t)
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("3", 64)}
	names := namesFor(backend.config, run.RunID, desired.SnapshotDigest)
	const collisionID = "unmanaged-current-agent"
	original := map[string]string{composeProjectLabel: names.project, composeServiceLabel: "agent", "unmanaged": "true"}
	docker.containers[collisionID] = cloneLabels(original)
	if _, err := backend.Ensure(context.Background(), desired); !errors.Is(err, controller.ErrBackendDesiredRunInvalid) {
		t.Fatalf("declared-service collision = %v", err)
	}
	if labels, exists := docker.containers[collisionID]; !exists || !reflect.DeepEqual(labels, original) {
		t.Fatalf("unmanaged declared service changed: %#v", labels)
	}
	for _, command := range docker.commands {
		if len(command) > 0 && command[0] == "compose" && contains(command, "up") {
			t.Fatalf("Compose convergence ran after ownership collision: %v", command)
		}
	}
}

func TestDockerBackendRetriesTransientDockerAndRecognizesMissingOrExitedAgent(t *testing.T) {
	backend, docker, run, _ := testBackend(t)
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("8", 64)}
	docker.failComposeUp = 1
	if _, err := backend.Ensure(context.Background(), desired); !errors.Is(err, controller.ErrBackendRetryable) {
		t.Fatalf("transient Docker failure = %v", err)
	}
	if observation, err := backend.Ensure(context.Background(), desired); err != nil || !observation.Ready {
		t.Fatalf("Docker recovery = %#v %v", observation, err)
	}
	docker.agentAbsent = true
	if observation, err := backend.Inspect(context.Background(), desired); err != nil || observation.Ready {
		t.Fatalf("missing agent = %#v %v", observation, err)
	}
	docker.agentAbsent = false
	docker.agentStatus = "stopped"
	if observation, err := backend.Inspect(context.Background(), desired); err != nil || observation.Ready {
		t.Fatalf("exited agent = %#v %v", observation, err)
	}
}

func TestDockerBackendInspectionClassifiesLifecycleWithoutDiagnostics(t *testing.T) {
	backend, docker, run, _ := testBackend(t)
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("7", 64)}
	if _, err := backend.Ensure(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]struct {
		apply    func()
		ready    bool
		terminal controller.State
	}{
		"healthy":   {apply: func() { docker.agentStatus = "healthy" }, ready: true},
		"starting":  {apply: func() { docker.agentStatus = "starting" }},
		"missing":   {apply: func() { docker.agentAbsent = true }, terminal: controller.StateFailed},
		"completed": {apply: func() { docker.agentStatus = "stopped" }, terminal: controller.StateCompleted},
		"failed":    {apply: func() { docker.agentStatus = "stopped"; docker.agentExitCode = 19 }, terminal: controller.StateFailed},
		"oom":       {apply: func() { docker.agentStatus = "stopped"; docker.agentOOM = true }, terminal: controller.StateFailed},
		"unhealthy": {apply: func() { docker.agentStatus = "unhealthy" }, terminal: controller.StateFailed},
	} {
		t.Run(name, func(t *testing.T) {
			docker.agentAbsent, docker.agentStatus, docker.agentExitCode, docker.agentOOM = false, "", 0, false
			mutate.apply()
			observation, err := backend.Inspect(context.Background(), desired)
			if err != nil || observation.Ready != mutate.ready || observation.TerminalTarget != mutate.terminal {
				t.Fatalf("lifecycle observation = %#v, %v", observation, err)
			}
		})
	}
}

func TestDockerBackendInspectionCoordinatesCARotation(t *testing.T) {
	backend, docker, run, _ := testBackend(t)
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("7", 64)}
	if _, err := backend.Ensure(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	docker.commands = nil
	docker.caRenewal = true
	if _, err := backend.Inspect(context.Background(), desired); !errors.Is(err, controller.ErrBackendRetryable) {
		t.Fatalf("rotation inspection error = %v", err)
	}
	joined := make([]string, 0, len(docker.commands))
	for _, command := range docker.commands {
		joined = append(joined, strings.Join(command, " "))
	}
	want := []string{"NVT_EGRESS_CA_CHECK_ONLY=1", " stop agent egressd", " run --rm ca-init", "--force-recreate egressd agent"}
	position := 0
	for _, command := range joined {
		if position < len(want) && strings.Contains(command, want[position]) {
			position++
		}
	}
	if position != len(want) {
		t.Fatalf("rotation was not ordered check/stop/rotate/recreate: %v", joined)
	}
	if docker.caRenewal {
		t.Fatal("rotation did not clear renewal state")
	}
}

func TestDockerBackendMatchesOnlyConfiguredLifecycleEvents(t *testing.T) {
	backend, docker, run, _ := testBackend(t)
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("7", 64)}
	if _, err := backend.Ensure(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	docker.lifecycleCursor = "v1:1:2:40"
	docker.lifecycleEvents = []string{"plugin.unrelated.ready"}
	observation, err := backend.Inspect(context.Background(), desired)
	if err != nil || !observation.Ready || observation.TerminalTarget != "" || observation.LifecycleCursor != docker.lifecycleCursor {
		t.Fatalf("unrelated event = %#v, %v", observation, err)
	}
	desired.LifecycleCursor = observation.LifecycleCursor

	for _, item := range []struct {
		name   string
		event  string
		target controller.State
	}{{"complete", "plugin.work.done", controller.StateCompleted}, {"fail", "plugin.work.failed", controller.StateFailed}} {
		t.Run(item.name, func(t *testing.T) {
			docker.lifecycleCursor = "v1:1:2:80"
			docker.lifecycleEvents = []string{"plugin.unrelated.ready", item.event}
			result, observeErr := backend.Inspect(context.Background(), desired)
			if observeErr != nil || result.Ready || result.TerminalTarget != item.target || result.LifecycleCursor != docker.lifecycleCursor {
				t.Fatalf("matched event = %#v, %v", result, observeErr)
			}
		})
	}
}

func TestStoppedAgentLifecycleEventPrecedesProcessExit(t *testing.T) {
	for _, item := range []struct {
		name     string
		events   []string
		exitCode int
		oom      bool
		expected controller.State
	}{
		{name: "fail-event-before-zero-exit", events: []string{"plugin.work.failed"}, expected: controller.StateFailed},
		{name: "complete-event-before-nonzero-exit", events: []string{"plugin.work.done"}, exitCode: 17, expected: controller.StateCompleted},
		{name: "unrelated-event-keeps-zero-exit", events: []string{"plugin.unrelated.ready"}, expected: controller.StateCompleted},
		{name: "unrelated-event-keeps-nonzero-exit", events: []string{"plugin.unrelated.ready"}, exitCode: 17, expected: controller.StateFailed},
		{name: "unrelated-event-keeps-oom-failure", events: []string{"plugin.unrelated.ready"}, oom: true, expected: controller.StateFailed},
	} {
		t.Run(item.name, func(t *testing.T) {
			backend, docker, run, tokens := testBackend(t)
			desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("7", 64)}
			if _, err := backend.Ensure(context.Background(), desired); err != nil {
				t.Fatal(err)
			}
			commandStart := len(docker.commands)
			docker.agentStatus = "stopped"
			docker.agentExitCode = item.exitCode
			docker.agentOOM = item.oom
			docker.lifecycleEvents = item.events
			docker.lifecycleCursor = "v1:7:8:90"
			observation, err := backend.Inspect(context.Background(), desired)
			if err != nil || observation.TerminalTarget != item.expected || observation.LifecycleCursor != docker.lifecycleCursor {
				t.Fatalf("stopped lifecycle precedence = %#v, %v", observation, err)
			}
			commands := docker.commands[commandStart:]
			helperSeen := false
			expectedLabels := ownedLabels{Owner: backend.config.Owner, RunID: run.RunID, Digest: desired.SnapshotDigest}
			expectedHomeMount := namesFor(backend.config, run.RunID, desired.SnapshotDigest).home + ":/state:ro"
			for _, command := range commands {
				if len(command) > 0 && command[0] == "exec" {
					t.Fatalf("stopped mutable agent was executed: %v", command)
				}
				if len(command) > 0 && command[0] == "run" {
					helperSeen = contains(command, "-i") && contains(command, "--network") && contains(command, "none") &&
						contains(command, "--read-only") && contains(command, "--cap-drop") && contains(command, "ALL") &&
						contains(command, "NVT_STATE_DIR=/state/.nvt-agent") && contains(command, expectedHomeMount) &&
						contains(command, backend.config.SeedImage)
					for _, pair := range labelPairs(expectedLabels) {
						helperSeen = helperSeen && contains(command, pair)
					}
					joined := strings.Join(command, " ")
					if strings.Contains(joined, tokens.agent) || strings.Contains(joined, tokens.egress) {
						t.Fatal("credential entered lifecycle helper arguments")
					}
				}
			}
			if !helperSeen {
				t.Fatalf("constrained lifecycle helper was not used: %v", commands)
			}
		})
	}
}

func TestStoppedAgentLifecycleUncertaintyFailsClosed(t *testing.T) {
	for _, item := range []struct {
		name   string
		mutate func(*fakeDocker)
	}{
		{name: "malformed-reader", mutate: func(docker *fakeDocker) {
			docker.lifecycleErr = errors.New("LIFECYCLE-RAW-PAYLOAD-SECRET-NEEDLE")
		}},
		{name: "replaced-event-file", mutate: func(docker *fakeDocker) {
			docker.lifecycleCursor = "v1:invalid-generation"
		}},
	} {
		t.Run(item.name, func(t *testing.T) {
			backend, docker, run, _ := testBackend(t)
			desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("7", 64)}
			if _, err := backend.Ensure(context.Background(), desired); err != nil {
				t.Fatal(err)
			}
			docker.agentStatus = "stopped"
			item.mutate(docker)
			observation, err := backend.Inspect(context.Background(), desired)
			if !errors.Is(err, controller.ErrBackendRetryable) || observation.TerminalTarget != "" || strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("stopped lifecycle uncertainty = %#v, %v", observation, err)
			}
		})
	}
}

func TestLifecycleReaderAdvancesOpaqueCursorWithoutReturningPayloads(t *testing.T) {
	stateDir := t.TempDir()
	eventDir := filepath.Join(stateDir, "agentd")
	if err := os.Mkdir(eventDir, 0o700); err != nil {
		t.Fatal(err)
	}
	eventPath := filepath.Join(eventDir, "events.jsonl")
	const secretNeedle = "LIFECYCLE-PAYLOAD-SECRET-NEEDLE"
	first := `{"event":"plugin.event","plugin_event":"plugin.unrelated.ready","payload":{"value":"` + secretNeedle + `"}}` + "\n" +
		`{"event":"plugin.event","plugin_event":"plugin.work.done","payload":{"ignored":true}}` + "\n"
	if err := os.WriteFile(eventPath, []byte(first), 0o600); err != nil {
		t.Fatal(err)
	}
	response, raw := runLifecycleReader(t, stateDir, "")
	if strings.Contains(string(raw), secretNeedle) || !reflect.DeepEqual(response.Events, []string{"plugin.unrelated.ready", "plugin.work.done"}) || response.Cursor == "" {
		t.Fatalf("first lifecycle read = %#v raw=%s", response, raw)
	}
	if err := os.WriteFile(eventPath, append([]byte(first), []byte(`{"event":"plugin.event","plugin_event":"plugin.work.failed","payload":{}}`+"\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	next, _ := runLifecycleReader(t, stateDir, response.Cursor)
	if !reflect.DeepEqual(next.Events, []string{"plugin.work.failed"}) || next.Cursor == response.Cursor {
		t.Fatalf("incremental lifecycle read = %#v", next)
	}
	if err := os.WriteFile(eventPath, []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("python3", "-c", lifecycleEventReader)
	command.Env = append(os.Environ(), "NVT_STATE_DIR="+stateDir)
	command.Stdin = strings.NewReader(`{"cursor":""}`)
	output, err := command.Output()
	if err != nil || bytes.Contains(output, []byte("not-json")) || !bytes.Contains(output, []byte(`"error":"event-json"`)) {
		t.Fatalf("malformed lifecycle log did not fail closed: %v %s", err, output)
	}
	if err := os.Rename(eventPath, eventPath+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(eventPath, []byte(first), 0o600); err != nil {
		t.Fatal(err)
	}
	command = exec.Command("python3", "-c", lifecycleEventReader)
	command.Env = append(os.Environ(), "NVT_STATE_DIR="+stateDir)
	command.Stdin = strings.NewReader(`{"cursor":"` + response.Cursor + `"}`)
	output, err = command.Output()
	if err != nil || bytes.Contains(output, []byte(secretNeedle)) || !bytes.Contains(output, []byte(`"error":"generation"`)) {
		t.Fatalf("replaced lifecycle log did not fail closed: %v %s", err, output)
	}
}

func runLifecycleReader(t *testing.T, stateDir, cursor string) (lifecycleReaderResponse, []byte) {
	t.Helper()
	request, _ := json.Marshal(map[string]string{"cursor": cursor})
	command := exec.Command("python3", "-c", lifecycleEventReader)
	command.Env = append(os.Environ(), "NVT_STATE_DIR="+stateDir)
	command.Stdin = bytes.NewReader(request)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("lifecycle reader: %v", err)
	}
	var response lifecycleReaderResponse
	if err := json.Unmarshal(output, &response); err != nil {
		t.Fatal(err)
	}
	return response, output
}

func TestDockerBackendInterruptedDeleteRetriesToCompleteCleanup(t *testing.T) {
	backend, docker, run, _ := testBackend(t)
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("6", 64), DeleteRequested: true}
	if _, err := backend.Ensure(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	names := namesFor(backend.config, run.RunID, desired.SnapshotDigest)
	docker.failRemove = "network"
	if err := backend.Delete(context.Background(), desired); !errors.Is(err, controller.ErrBackendRetryable) {
		t.Fatalf("interrupted delete = %v", err)
	}
	if _, err := os.Stat(names.composeFile); err != nil {
		t.Fatalf("interrupted cleanup lost its deterministic retry state: %v", err)
	}
	if err := backend.Delete(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	for key, labels := range docker.objects {
		if labels[runLabel] == run.RunID {
			t.Fatalf("retry left owned object %s", key)
		}
	}
	if _, err := os.Stat(filepath.Dir(names.composeFile)); !os.IsNotExist(err) {
		t.Fatalf("retry left generated state: %v", err)
	}
}

func TestDockerBackendExpectedOwnershipConflictKeepsCleanupRetryable(t *testing.T) {
	for _, item := range []struct {
		name       string
		objectKind string
		selectName func(resourceNames) string
		persistent bool
		explicit   bool
	}{
		{name: "network-partial-labels", objectKind: "network", selectName: func(names resourceNames) string { return names.internalNet }, explicit: true},
		{name: "disposable-volume-mismatched-label", objectKind: "volume", selectName: func(names resourceNames) string { return names.agentConfig }},
		{name: "explicit-persistent-volume-partial-labels", objectKind: "volume", selectName: func(names resourceNames) string { return names.workspace }, persistent: true, explicit: true},
	} {
		t.Run(item.name, func(t *testing.T) {
			backend, docker, run, _ := testBackend(t)
			if item.persistent {
				run.Persistence.Workspace = true
				run.Retention = "persistent"
				if err := resolvedrun.ValidateResolvedAgentRun(run); err != nil {
					t.Fatal(err)
				}
			}
			desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("6", 64), DeleteRequested: item.explicit}
			if _, err := backend.Ensure(context.Background(), desired); err != nil {
				t.Fatal(err)
			}
			names := namesFor(backend.config, run.RunID, desired.SnapshotDigest)
			objectName := item.selectName(names)
			key := item.objectKind + ":" + objectName
			conflicting := cloneLabels(docker.objects[key])
			delete(conflicting, digestLabel)
			conflicting[ownerLabel] = "different-owner"
			docker.objects[key] = conflicting

			if err := backend.Delete(context.Background(), desired); !errors.Is(err, controller.ErrBackendRetryable) {
				t.Fatalf("ownership conflict cleanup = %v", err)
			}
			if retained, exists := docker.objects[key]; !exists || !reflect.DeepEqual(retained, conflicting) {
				t.Fatalf("conflicting expected object changed: %#v", retained)
			}
			if item.objectKind == "network" && !docker.networkMembers[objectName][backend.config.GatewayContainer] {
				t.Fatal("cleanup detached the gateway from an ownership-conflicting network")
			}
			if _, err := os.Stat(names.composeFile); err != nil {
				t.Fatalf("retryable cleanup removed deterministic state: %v", err)
			}
		})
	}
}

func TestDockerBackendRetriesBrokerStartupFailureAndRecovers(t *testing.T) {
	backend, _, run, _ := testBackend(t)
	available := false
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !available {
			http.Error(response, "starting", http.StatusServiceUnavailable)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/placeholder-files":
			_, _ = io.WriteString(response, `{"ok":true,"files":[{"path":".agent/auth.json","content":"{\"access_token\":\"NVT-PLACEHOLDER-NOT-A-KEY\"}\n","mode":"0600"}],"hosts":["api.example.test"],"expires_at":null}`)
		case "/v1/identity":
			_, _ = io.WriteString(response, `{"ok":true,"name":"Example Bot","email":"bot@example.test"}`)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	preparer, err := newBrokerPreparer(server.URL, "", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	backend.preparer = preparer
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("2", 64)}
	if _, err := backend.Ensure(context.Background(), desired); !errors.Is(err, controller.ErrBackendRetryable) {
		t.Fatalf("starting broker = %v", err)
	}
	available = true
	if observation, err := backend.Ensure(context.Background(), desired); err != nil || !observation.Ready {
		t.Fatalf("recovered broker = %#v %v", observation, err)
	}
}

func TestLocalBackendAcceptsOnlyNetworkConfinedEnforcedMediatedTransport(t *testing.T) {
	config := Config{Owner: "test-controller", ExternalNetwork: "agents-proxy", ProxyPort: 4090, ProtectedCIDRs: "127.0.0.0/8 169.254.0.0/16", DindImage: "nvt-dind:test", EgressdImage: "nvt-egressd:test", CapturedImage: "nvt-captured:test", SeedImage: "nvt-runtime:test"}
	for _, transport := range []string{"redirect", "forward-proxy", "transparent"} {
		t.Run(transport, func(t *testing.T) {
			run := testMediatedRun(t)
			run.Egress.Transport = transport
			if transport == "redirect" {
				run.Egress.ProxyProvider = ""
			}
			if err := resolvedrun.ValidateResolvedAgentRun(run); err != nil {
				t.Fatal(err)
			}
			plan, err := renderCompose(config, run, strings.Repeat("1", 64), namesFor(Config{RunsDir: t.TempDir()}, run.RunID, strings.Repeat("1", 64)))
			if transport != "transparent" {
				if err == nil {
					t.Fatalf("enforced %s was accepted without network capture", transport)
				}
				return
			}
			if err != nil || !bytes.Contains(plan, []byte("net-init:")) || !bytes.Contains(plan, []byte("NET_ADMIN")) ||
				!bytes.Contains(plan, []byte("-p tcp -j REDIRECT --to-ports 15001")) {
				t.Fatalf("transparent confinement = %v\n%s", err, plan)
			}
		})
	}
}

func TestDockerBackendConfigValidatesRunPoolAgainstProtectedCIDRs(t *testing.T) {
	directory := t.TempDir()
	valid := Config{
		DockerHost: "unix:///var/run/docker.sock", RunsDir: filepath.Join(directory, "runs"), BrokerURL: "http://broker:7347",
		BrokerAgentsPath: filepath.Join(directory, "agents.yaml"), IdentityKeyPath: filepath.Join(directory, "identity.key"),
		Owner: "test-controller", ExternalNetwork: "agents-proxy", RunNetworkPool: "100.64.0.0/10", ProxyPort: 4090,
		ProtectedCIDRs: "10.0.0.0/8 fd00:1234::/48", DindImage: "nvt-dind:test", EgressdImage: "nvt-egressd:test",
		CapturedImage: "nvt-captured:test", SeedImage: "nvt-runtime:test", OperationTimeout: 2 * time.Minute,
	}
	if err := validateConfig(valid); err != nil {
		t.Fatalf("non-overlapping mixed-family config rejected: %v", err)
	}
	for name, protected := range map[string]string{
		"malformed": "not-a-prefix",
		"overlap":   "100.96.0.0/11 fd00:1234::/48",
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.ProtectedCIDRs = protected
			if err := validateConfig(candidate); err == nil {
				t.Fatal("invalid protected CIDR policy accepted")
			}
		})
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

func TestBrokerRegistryPreservesNativeLinuxOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership transition requires root")
	}
	directory := t.TempDir()
	agents := filepath.Join(directory, "agents.yaml")
	if err := os.WriteFile(agents, []byte("agents: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const directoryUID, directoryGID, fileUID, fileGID = 23001, 23002, 23003, 23004
	if err := os.Chown(directory, directoryUID, directoryGID); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(agents, fileUID, fileGID); err != nil {
		t.Fatal(err)
	}
	registry := brokerRegistry{path: agents}
	if err := registry.mutate(context.Background(), func(policy *brokerPolicy) error { return nil }); err != nil {
		t.Fatal(err)
	}
	uid, gid, err := fileOwnership(agents)
	if err != nil || uid != fileUID || gid != fileGID {
		t.Fatalf("registry ownership = %d:%d, %v", uid, gid, err)
	}
	uid, gid, err = fileOwnership(filepath.Join(directory, "agents.lock"))
	if err != nil || uid != directoryUID || gid != directoryGID {
		t.Fatalf("lock ownership = %d:%d, %v", uid, gid, err)
	}
}

func TestBrokerRegistryLockRespectsBackendOperationDeadline(t *testing.T) {
	backend, _, run, _ := testBackend(t)
	backend.config.OperationTimeout = 120 * time.Millisecond
	lockPath := strings.TrimSuffix(backend.config.BrokerAgentsPath, filepath.Ext(backend.config.BrokerAgentsPath)) + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) //nolint:errcheck
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("4", 64), DeleteRequested: true}
	for name, operation := range map[string]func() error{
		"ensure": func() error { _, err := backend.Ensure(context.Background(), desired); return err },
		"delete": func() error { return backend.Delete(context.Background(), desired) },
	} {
		t.Run(name, func(t *testing.T) {
			started := time.Now()
			err := operation()
			elapsed := time.Since(started)
			if !errors.Is(err, controller.ErrBackendRetryable) || elapsed > 500*time.Millisecond {
				t.Fatalf("held registry lock result = %v after %s", err, elapsed)
			}
		})
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
	} {
		if !bytes.Contains(plan, []byte(expected)) {
			t.Fatalf("exposure stack omitted %q:\n%s", expected, plan)
		}
	}
	if bytes.Contains(plan, []byte("traefik.http.")) || bytes.Contains(plan, []byte("traefik.enable")) {
		t.Fatalf("agent namespace retained a directly addressable proxy route:\n%s", plan)
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
	if bytes.Contains(plan, []byte("nvt-disable-bridge-netfilter")) {
		t.Fatal("fixed namespace attempted to mutate an unavailable bridge sysctl")
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
		BrokerAgentsPath: agents, IdentityKeyPath: filepath.Join(directory, "key"), Owner: "test-controller", ExternalNetwork: "agents-proxy", RunNetworkPool: "100.64.0.0/10",
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
		AgentConfig: json.RawMessage(`{"runtime":{"command":"agent-cli","args":[],"resume":{"command":"agent-cli","args":["resume","--last"]}},"plugins":[]}`),
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
		Lifecycle: resolvedrun.Lifecycle{CompleteOn: []string{"plugin.work.done"}, FailOn: []string{"plugin.work.failed"}},
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
