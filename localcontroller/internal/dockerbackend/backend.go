package dockerbackend

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/controller"
	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/networkpolicy"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
	"gopkg.in/yaml.v3"
)

const (
	composeProjectLabel           = "com.docker.compose.project"
	composeServiceLabel           = "com.docker.compose.service"
	seedHelperLabel               = "nvt.dev/local-controller-helper"
	seedHelperValue               = "volume-seed-v1"
	agentConfinementRevisionLabel = "io.nvt.local-controller.agent-confinement-revision"
	agentConfinementRevision      = "1"
	egressCANameSetDigestLabel    = "io.nvt.local-controller.egress-ca-name-set-digest"
	egressCARotationMarker        = "ca.key.rotation"
)

type Backend struct {
	config   Config
	docker   CommandBoundary
	registry brokerRegistry
	key      []byte
	preparer *brokerPreparer
}

func (backend *Backend) Ready(ctx context.Context) bool {
	operationContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := backend.docker.Run(operationContext, nil, "info", "--format", "{{.ServerVersion}}"); err != nil {
		return false
	}
	if err := backend.verifyGateway(operationContext); err != nil {
		return false
	}
	info, err := os.Lstat(backend.config.BrokerAgentsPath)
	return err == nil && info.Mode().IsRegular()
}

func New(config Config) (*Backend, error) {
	config = withRouteDefaults(config)
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if err := prepareRunsDir(config.RunsDir); err != nil {
		return nil, err
	}
	key, err := loadIdentityKey(config.IdentityKeyPath)
	if err != nil {
		return nil, err
	}
	preparer, err := newBrokerPreparer(config.BrokerURL, config.BrokerCAFile, config.OperationTimeout)
	if err != nil {
		clear(key)
		return nil, err
	}
	return &Backend{
		config: config, docker: dockerCLI{host: config.DockerHost}, registry: brokerRegistry{path: config.BrokerAgentsPath},
		key: key, preparer: preparer,
	}, nil
}

func NewWithBoundary(config Config, boundary CommandBoundary, key []byte, preparer *brokerPreparer) (*Backend, error) {
	config = withRouteDefaults(config)
	if err := validateConfig(config); err != nil || boundary == nil || len(key) < 32 || preparer == nil {
		return nil, errors.New("docker backend configuration invalid")
	}
	if err := prepareRunsDir(config.RunsDir); err != nil {
		return nil, err
	}
	return &Backend{config: config, docker: boundary, registry: brokerRegistry{path: config.BrokerAgentsPath}, key: append([]byte(nil), key...), preparer: preparer}, nil
}

func withRouteDefaults(config Config) Config {
	if config.RouteBaseDomain == "" {
		config.RouteBaseDomain = "agent.localhost"
	}
	if config.RoutePathPrefix == "" {
		config.RoutePathPrefix = "/agents"
	}
	if config.GatewayContainer == "" {
		config.GatewayContainer = "nvt-local-gateway"
	}
	return config
}

func prepareRunsDir(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return errors.New("backend state unavailable")
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("backend state unavailable")
	}
	return nil
}

func validateConfig(config Config) error {
	config = withRouteDefaults(config)
	_, runNetworkPolicyErr := networkpolicy.ValidateRunNetworkPolicy(config.RunNetworkPool, config.ProtectedCIDRs)
	if config.DockerHost == "" || config.RunsDir == "" || !filepath.IsAbs(config.RunsDir) || filepath.Clean(config.RunsDir) != config.RunsDir ||
		config.BrokerAgentsPath == "" || !filepath.IsAbs(config.BrokerAgentsPath) || config.IdentityKeyPath == "" || !filepath.IsAbs(config.IdentityKeyPath) ||
		config.BrokerCAFile != "" && !filepath.IsAbs(config.BrokerCAFile) ||
		config.Owner == "" || len(config.Owner) > 63 || config.ExternalNetwork == "" || config.ProxyPort < 1 || config.ProxyPort > 65535 || config.ProtectedCIDRs == "" || len(config.ProtectedCIDRs) > 4096 || config.DindImage == "" || config.EgressdImage == "" ||
		config.CapturedImage == "" || config.SeedImage == "" || config.OperationTimeout < time.Second || config.OperationTimeout > 5*time.Minute ||
		runNetworkPolicyErr != nil ||
		!validDockerName(config.ExternalNetwork) || !validRouteBaseDomain(config.RouteBaseDomain) || !validRoutePathPrefix(config.RoutePathPrefix) || !validDockerName(config.GatewayContainer) ||
		!validImage(config.DindImage) || !validImage(config.EgressdImage) || !validImage(config.CapturedImage) || !validImage(config.SeedImage) ||
		strings.ContainsAny(config.Owner+config.ProtectedCIDRs, "\x00\r\n") {
		return errors.New("docker backend configuration invalid")
	}
	parsed, err := url.Parse(config.BrokerURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return errors.New("docker backend configuration invalid")
	}
	return nil
}

func validRouteBaseDomain(value string) bool {
	if len(value) == 0 || len(value) > 190 || value != strings.ToLower(value) || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !validDNSLabel(label) {
			return false
		}
	}
	return true
}

func validRoutePathPrefix(value string) bool {
	if len(value) < 2 || len(value) > 256 || value[0] != '/' || strings.HasSuffix(value, "/") || strings.Contains(value, "//") || strings.ContainsAny(value, "%\\?#\x00\r\n") {
		return false
	}
	for _, segment := range strings.Split(strings.TrimPrefix(value, "/"), "/") {
		if !validDNSLabel(segment) {
			return false
		}
	}
	return true
}

func validDockerName(value string) bool {
	if len(value) == 0 || len(value) > 128 || !asciiAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !asciiAlphaNumeric(character) && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func validImage(value string) bool {
	return len(value) > 0 && len(value) <= 4096 && value[0] != '-' && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\x00\r\n\t ")
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func (backend *Backend) Ensure(ctx context.Context, desired controller.BackendRun) (observation controller.BackendObservation, resultErr error) {
	run := desired.Resolved
	rollout := desired.ConfigurationRollout && desired.PreviousResolved != nil && desired.DesiredDigest != ""
	if run.Execution.Kind != "container" {
		return controller.BackendObservation{}, controller.ErrBackendDesiredRunInvalid
	}
	if run.Egress.Mode == "direct" && len(run.Broker.Grants) != 0 {
		return controller.BackendObservation{}, controller.ErrBackendDesiredRunInvalid
	}
	if run.Egress.Mode == "mediated" && run.Egress.Enforced && run.Egress.Transport != "transparent" {
		return controller.BackendObservation{}, controller.ErrBackendDesiredRunInvalid
	}
	if strings.HasPrefix(backend.config.BrokerURL, "http://") && run.Egress.Mode == "mediated" && !run.Egress.AllowInsecureBroker {
		return controller.BackendObservation{}, controller.ErrBackendDesiredRunInvalid
	}
	rendered, err := resolvedrun.RenderAgentConfig(run, renderBindings(run))
	if err != nil {
		return controller.BackendObservation{}, controller.ErrBackendDesiredRunInvalid
	}
	plan, err := renderCompose(backend.config, run, desired.SnapshotDigest, namesFor(backend.config, run.RunID, desired.SnapshotDigest))
	if err != nil {
		return controller.BackendObservation{}, controller.ErrBackendDesiredRunInvalid
	}
	operationContext, cancel := context.WithTimeout(ctx, backend.config.OperationTimeout)
	defer cancel()
	names := namesFor(backend.config, run.RunID, desired.SnapshotDigest)
	labels := ownedLabels{Owner: backend.config.Owner, RunID: run.RunID, Digest: desired.SnapshotDigest}
	if err := backend.preflightComposeMutation(operationContext, names.project, plan, labels); err != nil {
		if errors.Is(err, errOwnershipConflict) {
			return controller.BackendObservation{}, controller.ErrBackendDesiredRunInvalid
		}
		return controller.BackendObservation{}, controller.ErrBackendRetryable
	}
	if err := backend.ensureDirectory(run.RunID); err != nil {
		return controller.BackendObservation{}, controller.ErrBackendRetryable
	}
	tokens := deriveTokens(backend.key, run.RunID, desired.SnapshotDigest)
	runtimeStopped := false
	if rollout {
		services := []string{"agent"}
		if desired.PreviousResolved.Egress.Mode == "mediated" {
			services = append(services, "egressd")
		}
		if err := backend.stopOwnedRuntimeServices(operationContext, names.project, labels, services); err != nil {
			return controller.BackendObservation{}, controller.ErrBackendRetryable
		}
		runtimeStopped = true
	}
	if err := backend.pruneStaleOwnedResources(operationContext, run, names, plan, labels); err != nil {
		return controller.BackendObservation{}, controller.ErrBackendRetryable
	}
	registryUpdated := false
	defer func() {
		if resultErr == nil || !runtimeStopped {
			return
		}
		if errors.Is(resultErr, controller.ErrBackendDesiredRunInvalid) {
			resultErr = controller.ErrBackendRetryable
		}
		if !registryUpdated || desired.PreviousResolved == nil {
			return
		}
		rollbackContext, rollbackCancel := context.WithTimeout(context.Background(), backend.config.OperationTimeout)
		defer rollbackCancel()
		services := []string{"agent"}
		if run.Egress.Mode == "mediated" || desired.PreviousResolved.Egress.Mode == "mediated" {
			services = append(services, "egressd")
		}
		if err := backend.stopOwnedRuntimeServices(rollbackContext, names.project, labels, services); err != nil {
			resultErr = controller.ErrBackendRetryable
			return
		}
		if backend.registry.upsert(rollbackContext, *desired.PreviousResolved, desired.SnapshotDigest, tokens) != nil {
			resultErr = controller.ErrBackendRetryable
		}
	}()
	if err := backend.registry.upsert(operationContext, run, desired.SnapshotDigest, tokens); err != nil {
		if errors.Is(err, errRegistryIdentityCollision) {
			return controller.BackendObservation{}, controller.ErrBackendDesiredRunInvalid
		}
		return controller.BackendObservation{}, controller.ErrBackendRetryable
	}
	registryUpdated = rollout
	if err := backend.ensureExternalNetwork(operationContext); err != nil {
		return controller.BackendObservation{}, controller.ErrBackendRetryable
	}
	for _, volume := range backend.requiredVolumes(run, names) {
		if err := backend.ensureOwnedObject(operationContext, "volume", volume, labels); err != nil {
			if errors.Is(err, errOwnershipConflict) {
				return controller.BackendObservation{}, controller.ErrBackendDesiredRunInvalid
			}
			return controller.BackendObservation{}, controller.ErrBackendRetryable
		}
	}
	for _, network := range []string{names.internalNet, names.privateNet} {
		if err := backend.ensureOwnedNetwork(operationContext, network, labels); err != nil {
			if errors.Is(err, errOwnershipConflict) {
				return controller.BackendObservation{}, controller.ErrBackendDesiredRunInvalid
			}
			return controller.BackendObservation{}, controller.ErrBackendRetryable
		}
	}
	if err := backend.ensureGatewayAttachment(operationContext, names.internalNet, labels); err != nil {
		return controller.BackendObservation{}, controller.ErrBackendRetryable
	}
	rendered, preparedMetadata, catalogRoutes, err := backend.preparer.prepare(operationContext, run, tokens.agent, rendered)
	if err != nil {
		return controller.BackendObservation{}, controller.ErrBackendRetryable
	}
	agentUID := 0
	if run.Runtime.User == "non-root" {
		agentUID = 1000
	}
	agentFiles := map[string]seedFile{"agent.json": {content: rendered, mode: 0o644, uid: agentUID, gid: agentUID}}
	if len(preparedMetadata) != 0 {
		agentFiles["prepared-provider-metadata.json"] = seedFile{content: preparedMetadata, mode: 0o644, uid: agentUID, gid: agentUID}
	}
	if run.WorkspaceInstructions.Profile != "" {
		agentFiles["profile-instructions.md"] = seedFile{content: []byte(run.WorkspaceInstructions.Profile), mode: 0o644, uid: agentUID, gid: agentUID}
	}
	if run.WorkspaceInstructions.Workflow != "" {
		agentFiles["workflow-instructions.md"] = seedFile{content: []byte(run.WorkspaceInstructions.Workflow), mode: 0o644, uid: agentUID, gid: agentUID}
	}
	if err := backend.seedVolume(operationContext, names.agentConfig, agentFiles, labels); err != nil {
		return controller.BackendObservation{}, controller.ErrBackendRetryable
	}
	if run.Egress.Mode == "mediated" {
		egressConfig, err := renderEgressdConfig(backend.config, run, catalogRoutes)
		if err != nil {
			return controller.BackendObservation{}, errors.New("egress configuration unavailable")
		}
		if err := backend.seedManagedFiles(operationContext, names.egressPrivate, map[string]seedFile{
			"egressd.json": {content: egressConfig, mode: 0o600}, "broker-token": {content: []byte(tokens.egress), mode: 0o400},
		}, labels); err != nil {
			return controller.BackendObservation{}, controller.ErrBackendRetryable
		}
	}
	if bytes.Contains(plan, []byte(tokens.agent)) || bytes.Contains(plan, []byte(tokens.egress)) {
		return controller.BackendObservation{}, controller.ErrBackendDesiredRunInvalid
	}
	if err := atomicWrite(names.composeFile, plan, 0o600); err != nil {
		return controller.BackendObservation{}, controller.ErrBackendRetryable
	}
	if rollout && run.Egress.Mode == "mediated" && desired.PreviousResolved.Egress.Mode == "mediated" &&
		egressCANameSetFor(run).digest() != egressCANameSetFor(*desired.PreviousResolved).digest() {
		if err := backend.reconcileDesiredCANameSet(operationContext, names, labels, *desired.PreviousResolved, run); err != nil {
			return controller.BackendObservation{}, controller.ErrBackendRetryable
		}
	}
	if requiresConfinementProof(run) {
		if err := backend.removeOutdatedConfinementAgent(operationContext, names.project, labels); err != nil {
			if errors.Is(err, errOwnershipConflict) {
				return controller.BackendObservation{}, controller.ErrBackendDesiredRunInvalid
			}
			return controller.BackendObservation{}, controller.ErrBackendRetryable
		}
		if err := backend.removeOwnedComposeService(operationContext, names.project, "net-init", labels); err != nil {
			if errors.Is(err, errOwnershipConflict) {
				return controller.BackendObservation{}, controller.ErrBackendDesiredRunInvalid
			}
			return controller.BackendObservation{}, controller.ErrBackendRetryable
		}
	}
	composeArguments := []string{"compose", "-p", names.project, "-f", names.composeFile, "up", "-d"}
	if rollout {
		composeArguments = append(composeArguments, "--force-recreate")
	} else {
		composeArguments = append(composeArguments, "--no-recreate")
	}
	if _, err := backend.docker.Run(operationContext, nil, composeArguments...); err != nil {
		return controller.BackendObservation{}, controller.ErrBackendRetryable
	}
	if err := backend.preflightComposeMutation(operationContext, names.project, plan, labels); err != nil {
		return controller.BackendObservation{}, controller.ErrBackendRetryable
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		observation, inspectErr := backend.Inspect(operationContext, desired)
		if inspectErr == nil && (observation.Ready || observation.TerminalTarget != "") {
			return observation, nil
		}
		select {
		case <-operationContext.Done():
			return controller.BackendObservation{}, controller.ErrBackendRetryable
		case <-ticker.C:
		}
	}
}

func (backend *Backend) Inspect(ctx context.Context, desired controller.BackendRun) (controller.BackendObservation, error) {
	names := namesFor(backend.config, desired.Resolved.RunID, desired.SnapshotDigest)
	operationContext, cancel := context.WithTimeout(ctx, backend.config.OperationTimeout)
	defer cancel()
	output, err := backend.docker.Run(operationContext, nil, "compose", "-p", names.project, "-f", names.composeFile, "ps", "--all", "-q", "agent")
	if err != nil {
		return controller.BackendObservation{}, controller.ErrBackendRetryable
	}
	if strings.TrimSpace(string(output)) == "" {
		return controller.BackendObservation{TerminalTarget: controller.StateFailed, LifecycleCursor: desired.LifecycleCursor}, nil
	}
	containerID := strings.TrimSpace(string(output))
	labels := ownedLabels{Owner: backend.config.Owner, RunID: desired.Resolved.RunID, Digest: desired.SnapshotDigest}
	if err := backend.ensureGatewayAttachment(operationContext, names.internalNet, labels); err != nil {
		return controller.BackendObservation{}, controller.ErrBackendRetryable
	}
	if err := backend.verifyContainer(operationContext, containerID, labels); err != nil {
		return controller.BackendObservation{}, err
	}
	rawState, err := backend.docker.Run(operationContext, nil, "inspect", "--format", "{{json .State}}", containerID)
	if err != nil {
		return controller.BackendObservation{}, err
	}
	var state struct {
		Running   bool `json:"Running"`
		OOMKilled bool `json:"OOMKilled"`
		ExitCode  int  `json:"ExitCode"`
		Health    *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(rawState), &state); err != nil {
		clear(rawState)
		return controller.BackendObservation{}, controller.ErrBackendRetryable
	}
	clear(rawState)
	if state.Running {
		cursor, target, lifecycleErr := backend.observeLifecycle(operationContext, containerID, desired)
		if lifecycleErr != nil {
			return controller.BackendObservation{}, lifecycleErr
		}
		if target != "" {
			return controller.BackendObservation{TerminalTarget: target, LifecycleCursor: cursor}, nil
		}
		if state.Health != nil && state.Health.Status != "healthy" && state.Health.Status != "starting" {
			return controller.BackendObservation{TerminalTarget: controller.StateFailed, LifecycleCursor: cursor}, nil
		}
		if desired.Resolved.Egress.Mode == "mediated" {
			rotated, err := backend.reconcileComposeCARotation(operationContext, names, true)
			if err != nil || rotated {
				return controller.BackendObservation{}, controller.ErrBackendRetryable
			}
		}
		return controller.BackendObservation{Ready: state.Health == nil || state.Health.Status == "healthy", LifecycleCursor: cursor}, nil
	}
	if desired.Resolved.Egress.Mode == "mediated" {
		rollout, rolloutErr := readComposeCARollout(names)
		if rolloutErr != nil {
			return controller.BackendObservation{}, controller.ErrBackendRetryable
		}
		if rollout.Phase != "" {
			if _, err := backend.reconcileComposeCARotation(operationContext, names, false); err != nil {
				return controller.BackendObservation{}, controller.ErrBackendRetryable
			}
			return controller.BackendObservation{}, controller.ErrBackendRetryable
		}
	}
	cursor, target, lifecycleErr := backend.observeStoppedLifecycle(operationContext, desired, names, labels)
	if lifecycleErr != nil {
		return controller.BackendObservation{}, lifecycleErr
	}
	if target != "" {
		return controller.BackendObservation{TerminalTarget: target, LifecycleCursor: cursor}, nil
	}
	if state.ExitCode == 0 && !state.OOMKilled {
		return controller.BackendObservation{TerminalTarget: controller.StateCompleted, LifecycleCursor: cursor}, nil
	}
	return controller.BackendObservation{TerminalTarget: controller.StateFailed, LifecycleCursor: cursor}, nil
}

type composeCARollout struct {
	Phase     string    `json:"phase,omitempty"`
	NextCheck time.Time `json:"next_check,omitempty"`
}

func composeCARolloutPath(names resourceNames) string {
	return filepath.Join(filepath.Dir(names.composeFile), "egress-ca-rollout.json")
}

func composeCARolloutExists(names resourceNames) bool {
	state, err := readComposeCARollout(names)
	return err == nil && state.Phase != ""
}

func readComposeCARollout(names resourceNames) (composeCARollout, error) {
	encoded, err := os.ReadFile(composeCARolloutPath(names))
	if errors.Is(err, os.ErrNotExist) {
		return composeCARollout{}, nil
	}
	if err != nil {
		return composeCARollout{}, err
	}
	var state composeCARollout
	if json.Unmarshal(encoded, &state) != nil {
		return composeCARollout{}, errors.New("invalid Compose CA rollout state")
	}
	return state, nil
}

func writeComposeCARollout(names resourceNames, state composeCARollout) error {
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicWrite(composeCARolloutPath(names), append(encoded, '\n'), 0o600)
}

func (backend *Backend) reconcileComposeCARotation(ctx context.Context, names resourceNames, agentRunning bool) (bool, error) {
	state, err := readComposeCARollout(names)
	if err != nil {
		return false, err
	}
	if state.Phase == "" && !state.NextCheck.IsZero() && time.Now().Before(state.NextCheck) {
		return false, nil
	}
	if state.Phase == "" {
		check, err := backend.docker.Run(ctx, nil, "compose", "-p", names.project, "-f", names.composeFile, "run", "--rm", "-e", "NVT_EGRESS_CA_CHECK_ONLY=1", "ca-init")
		if err != nil {
			return false, err
		}
		if !strings.Contains(string(check), "renewal-required") {
			value := ""
			for _, line := range strings.Split(string(check), "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "renew-after=") {
					value = strings.TrimPrefix(strings.TrimSpace(line), "renew-after=")
				}
			}
			next, parseErr := time.Parse(time.RFC3339, value)
			if parseErr != nil {
				return false, errors.New("invalid egress CA renewal schedule")
			}
			return false, writeComposeCARollout(names, composeCARollout{NextCheck: next})
		}
		state = composeCARollout{Phase: "planned"}
		if err := writeComposeCARollout(names, state); err != nil {
			return false, err
		}
	}
	if state.Phase == "planned" {
		if agentRunning {
			if _, err := backend.docker.Run(ctx, nil, "compose", "-p", names.project, "-f", names.composeFile, "stop", "agent", "egressd"); err != nil {
				return false, err
			}
			agentRunning = false
		}
		state.Phase = "stopped"
		if err := writeComposeCARollout(names, state); err != nil {
			return false, err
		}
	}
	if state.Phase == "stopped" {
		if _, err := backend.docker.Run(ctx, nil, "compose", "-p", names.project, "-f", names.composeFile, "run", "--rm", "ca-init"); err != nil {
			return false, err
		}
		state.Phase = "rotated"
		if err := writeComposeCARollout(names, state); err != nil {
			return false, err
		}
	}
	if state.Phase != "rotated" {
		return false, errors.New("invalid Compose CA rollout phase")
	}
	if !agentRunning {
		if _, err := backend.docker.Run(ctx, nil, "compose", "-p", names.project, "-f", names.composeFile, "up", "-d", "--force-recreate", "egressd", "agent"); err != nil {
			return false, err
		}
	}
	if err := os.Remove(composeCARolloutPath(names)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return true, nil
}

// reconcileDesiredCANameSet runs only for a controller-approved rollout with
// both the previous and desired immutable snapshots available. The current
// name set is probed first so retries after a completed rotation are no-ops.
// A stale CA is rotated only after ca-init proves that the complete keypair is
// valid for the previous trusted name set; malformed or unrelated material
// therefore remains a hard failure and never receives a rotation marker.
func (backend *Backend) reconcileDesiredCANameSet(ctx context.Context, names resourceNames, labels ownedLabels, previous, desired resolvedrun.ResolvedAgentRun) error {
	currentState, currentErr := backend.checkComposeCA(ctx, names, desired)
	if currentErr == nil {
		if currentState == "renewal-required" {
			return backend.runComposeCAInit(ctx, names, desired)
		}
		return nil
	}
	if _, err := backend.checkComposeCA(ctx, names, previous); err != nil {
		return errors.New("durable egress CA does not match the previous or desired name set")
	}
	if err := backend.seedManagedFiles(ctx, names.egressPrivate, map[string]seedFile{
		egressCARotationMarker: {content: []byte("rotation-in-progress\n"), mode: 0o600},
	}, labels); err != nil {
		return err
	}
	if err := backend.runComposeCAInit(ctx, names, desired); err != nil {
		return err
	}
	if err := os.Remove(composeCARolloutPath(names)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (backend *Backend) checkComposeCA(ctx context.Context, names resourceNames, run resolvedrun.ResolvedAgentRun) (string, error) {
	arguments := []string{"compose", "-p", names.project, "-f", names.composeFile, "run", "--rm", "-e", "NVT_EGRESS_CA_CHECK_ONLY=1", "ca-init"}
	arguments = append(arguments, caInitCommand(run)...)
	output, err := backend.docker.Run(ctx, nil, arguments...)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(output))
	if value == "renewal-required" {
		return value, nil
	}
	if !strings.HasPrefix(value, "renew-after=") {
		return "", errors.New("invalid egress CA check result")
	}
	if _, err := time.Parse(time.RFC3339, strings.TrimPrefix(value, "renew-after=")); err != nil {
		return "", errors.New("invalid egress CA renewal schedule")
	}
	return value, nil
}

func (backend *Backend) runComposeCAInit(ctx context.Context, names resourceNames, run resolvedrun.ResolvedAgentRun) error {
	arguments := []string{"compose", "-p", names.project, "-f", names.composeFile, "run", "--rm", "ca-init"}
	arguments = append(arguments, caInitCommand(run)...)
	_, err := backend.docker.Run(ctx, nil, arguments...)
	return err
}

func (backend *Backend) Delete(ctx context.Context, desired controller.BackendRun) error {
	operationContext, cancel := context.WithTimeout(ctx, backend.config.OperationTimeout)
	defer cancel()
	run := desired.Resolved
	names := namesFor(backend.config, run.RunID, desired.SnapshotDigest)
	labels := ownedLabels{Owner: backend.config.Owner, RunID: run.RunID, Digest: desired.SnapshotDigest}
	tokens := deriveTokens(backend.key, run.RunID, desired.SnapshotDigest)
	if err := backend.registry.remove(operationContext, run.RunID, tokens); err != nil {
		return controller.ErrBackendRetryable
	}
	if err := backend.removeOwnedContainers(operationContext, labels); err != nil {
		return controller.ErrBackendRetryable
	}
	if err := backend.removeGatewayAttachment(operationContext, names.internalNet, labels); err != nil {
		return controller.ErrBackendRetryable
	}
	if err := backend.removeExpectedOwnedObjects(operationContext, "network", []string{names.internalNet, names.privateNet}, labels); err != nil {
		return controller.ErrBackendRetryable
	}
	if err := backend.removeOwnedObjectsExcept(operationContext, "network", labels, nil); err != nil {
		return controller.ErrBackendRetryable
	}
	preserveVolumes := map[string]bool{}
	if !desired.DeleteRequested && run.Persistence.Workspace {
		preserveVolumes[names.workspace] = true
	}
	if !desired.DeleteRequested && run.Persistence.RuntimeState {
		preserveVolumes[names.home] = true
	}
	if !desired.DeleteRequested && run.Runtime.Docker != nil && run.Persistence.DockerData {
		preserveVolumes[names.dockerData] = true
	}
	removeVolumes := []string{}
	for _, name := range backend.requiredVolumes(run, names) {
		if !preserveVolumes[name] {
			removeVolumes = append(removeVolumes, name)
		}
	}
	if err := backend.removeExpectedOwnedObjects(operationContext, "volume", removeVolumes, labels); err != nil {
		return controller.ErrBackendRetryable
	}
	if err := backend.removeOwnedObjectsExcept(operationContext, "volume", labels, preserveVolumes); err != nil {
		return controller.ErrBackendRetryable
	}
	if err := os.RemoveAll(filepath.Dir(names.composeFile)); err != nil {
		return controller.ErrBackendRetryable
	}
	return nil
}

func (backend *Backend) ensureDirectory(runID string) error {
	if err := os.MkdirAll(filepath.Join(backend.config.RunsDir, runID), 0o700); err != nil {
		return err
	}
	return os.Chmod(filepath.Join(backend.config.RunsDir, runID), 0o700)
}

func (backend *Backend) preflightComposeMutation(ctx context.Context, project string, plan []byte, expected ownedLabels) error {
	services, err := declaredComposeServices(plan)
	if err != nil {
		return errors.New("compose plan unavailable")
	}
	output, err := backend.docker.Run(ctx, nil, "ps", "-aq", "--filter", "label="+composeProjectLabel+"="+project)
	if err != nil {
		return err
	}
	for _, container := range strings.Fields(string(output)) {
		labels, err := backend.containerLabels(ctx, container)
		if err != nil {
			return err
		}
		if !services[labels[composeServiceLabel]] {
			continue
		}
		if err := verifyLabelMap(labels, expected); err != nil {
			return err
		}
	}
	return nil
}

func declaredComposeServices(plan []byte) (map[string]bool, error) {
	var document struct {
		Services map[string]any `yaml:"services"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(plan))
	if err := decoder.Decode(&document); err != nil || len(document.Services) == 0 {
		return nil, errors.New("compose plan unavailable")
	}
	services := make(map[string]bool, len(document.Services))
	for service := range document.Services {
		services[service] = true
	}
	return services, nil
}

func (backend *Backend) pruneStaleOwnedResources(ctx context.Context, run resolvedrun.ResolvedAgentRun, names resourceNames, plan []byte, labels ownedLabels) error {
	services, err := declaredComposeServices(plan)
	if err != nil {
		return err
	}
	containers, err := backend.ownedContainerIDs(ctx, labels)
	if err != nil {
		return err
	}
	for _, container := range containers {
		values, err := backend.containerLabels(ctx, container)
		if err != nil {
			return err
		}
		if values[composeProjectLabel] == names.project && services[values[composeServiceLabel]] {
			continue
		}
		if err := verifyLabelMap(values, labels); err != nil {
			return err
		}
		if _, err := backend.docker.Run(ctx, nil, "rm", "--force", "--volumes", container); err != nil {
			return err
		}
	}
	allowedVolumes := map[string]bool{}
	for _, volume := range backend.requiredVolumes(run, names) {
		allowedVolumes[volume] = true
	}
	if err := backend.removeOwnedObjectsExcept(ctx, "volume", labels, allowedVolumes); err != nil {
		return err
	}
	return backend.removeOwnedObjectsExcept(ctx, "network", labels, map[string]bool{names.internalNet: true, names.privateNet: true})
}

func (backend *Backend) requiredVolumes(run resolvedrun.ResolvedAgentRun, names resourceNames) []string {
	values := []string{names.agentConfig, names.workspace, names.home}
	if requiresConfinementProof(run) {
		values = append(values, names.confinement, names.confinementRequest)
	}
	if run.Runtime.Docker != nil {
		values = append(values, names.dockerData)
	}
	if run.Egress.Mode == "mediated" {
		values = append(values, names.egressPrivate, names.egressPublic)
	}
	return values
}

func (backend *Backend) removeOutdatedConfinementAgent(ctx context.Context, project string, labels ownedLabels) error {
	output, err := backend.docker.Run(ctx, nil, "ps", "-aq", "--filter", "label="+composeProjectLabel+"="+project, "--filter", "label="+composeServiceLabel+"=agent")
	if err != nil {
		return err
	}
	containers := strings.Fields(string(output))
	if len(containers) > 1 {
		return errors.New("backend service inventory unavailable")
	}
	for _, container := range containers {
		values, err := backend.containerLabels(ctx, container)
		if err != nil {
			return err
		}
		if err := verifyLabelMap(values, labels); err != nil {
			return err
		}
		if values[agentConfinementRevisionLabel] == agentConfinementRevision {
			continue
		}
		if _, err := backend.docker.Run(ctx, nil, "rm", "--force", "--volumes", container); err != nil {
			return err
		}
	}
	return nil
}

func (backend *Backend) removeOwnedComposeService(ctx context.Context, project, service string, labels ownedLabels) error {
	output, err := backend.docker.Run(ctx, nil, "ps", "-aq", "--filter", "label="+composeProjectLabel+"="+project, "--filter", "label="+composeServiceLabel+"="+service)
	if err != nil {
		return err
	}
	containers := strings.Fields(string(output))
	if len(containers) > 1 {
		return errors.New("backend service inventory unavailable")
	}
	for _, container := range containers {
		if err := backend.verifyContainer(ctx, container, labels); err != nil {
			return err
		}
		if _, err := backend.docker.Run(ctx, nil, "rm", "--force", "--volumes", container); err != nil {
			return err
		}
	}
	return nil
}

func (backend *Backend) stopOwnedRuntimeServices(ctx context.Context, project string, labels ownedLabels, services []string) error {
	for _, service := range services {
		output, err := backend.docker.Run(ctx, nil, "ps", "-q", "--filter", "label="+composeProjectLabel+"="+project, "--filter", "label="+composeServiceLabel+"="+service)
		if err != nil {
			return err
		}
		containers := strings.Fields(string(output))
		if len(containers) > 1 {
			return errors.New("backend service inventory unavailable")
		}
		for _, container := range containers {
			if err := backend.verifyContainer(ctx, container, labels); err != nil {
				return err
			}
			if _, err := backend.docker.Run(ctx, nil, "stop", container); err != nil {
				return err
			}
		}
	}
	return nil
}

func (backend *Backend) ensureExternalNetwork(ctx context.Context) error {
	_, err := backend.docker.Run(ctx, nil, "network", "inspect", backend.config.ExternalNetwork)
	return err
}

func (backend *Backend) ensureOwnedObject(ctx context.Context, kind, name string, labels ownedLabels) error {
	if err := backend.verifyObject(ctx, kind, name, labels); err == nil {
		return nil
	} else if errors.Is(err, errOwnershipConflict) {
		return err
	}
	arguments := []string{kind, "create"}
	arguments = append(arguments, labelArguments(labels)...)
	arguments = append(arguments, name)
	if _, err := backend.docker.Run(ctx, nil, arguments...); err != nil {
		if verifyErr := backend.verifyObject(ctx, kind, name, labels); verifyErr != nil {
			return verifyErr
		}
		return nil
	}
	return backend.verifyObject(ctx, kind, name, labels)
}

func (backend *Backend) verifyObject(ctx context.Context, kind, name string, labels ownedLabels) error {
	output, err := backend.docker.Run(ctx, nil, kind, "inspect", "--format", "{{json .Labels}}", name)
	if err != nil {
		return err
	}
	return verifyLabels(output, labels)
}

func (backend *Backend) verifyContainer(ctx context.Context, name string, labels ownedLabels) error {
	values, err := backend.containerLabels(ctx, name)
	if err != nil {
		return err
	}
	return verifyLabelMap(values, labels)
}

func (backend *Backend) verifySeedHelperContainer(ctx context.Context, name string, labels ownedLabels) error {
	values, err := backend.containerLabels(ctx, name)
	if err != nil {
		return err
	}
	if err := verifyLabelMap(values, labels); err != nil {
		return err
	}
	if values[seedHelperLabel] != seedHelperValue || values[composeProjectLabel] != "" || values[composeServiceLabel] != "" {
		return errOwnershipConflict
	}
	return nil
}

func (backend *Backend) containerLabels(ctx context.Context, name string) (map[string]string, error) {
	output, err := backend.docker.Run(ctx, nil, "inspect", "--format", "{{json .Config.Labels}}", name)
	if err != nil {
		return nil, err
	}
	var labels map[string]string
	if err := json.Unmarshal(bytes.TrimSpace(output), &labels); err != nil {
		return nil, errors.New("backend ownership unavailable")
	}
	return labels, nil
}

func verifyLabels(raw []byte, expected ownedLabels) error {
	var labels map[string]string
	if err := json.Unmarshal(bytes.TrimSpace(raw), &labels); err != nil {
		return errors.New("backend ownership unavailable")
	}
	return verifyLabelMap(labels, expected)
}

func verifyLabelMap(labels map[string]string, expected ownedLabels) error {
	for key, value := range labelMap(expected) {
		if labels[key] != value {
			return errOwnershipConflict
		}
	}
	return nil
}

func labelMap(labels ownedLabels) map[string]string {
	return map[string]string{ownerLabel: labels.Owner, runLabel: labels.RunID, digestLabel: labels.Digest}
}

type seedFile struct {
	content []byte
	mode    int64
	uid     int
	gid     int
}

func (backend *Backend) seedVolume(ctx context.Context, volume string, files map[string]seedFile, labels ownedLabels) error {
	return backend.seedVolumeWithCleanup(ctx, volume, files, labels, []string{"find /seed -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +"})
}

// seedManagedFiles replaces only controller-owned files. The same private
// volume also holds the durable egress CA key, which must survive controller
// restarts and configuration reconciliation.
func (backend *Backend) seedManagedFiles(ctx context.Context, volume string, files map[string]seedFile, labels ownedLabels) error {
	names := make([]string, 0, len(files))
	for name := range files {
		if name == "" || filepath.Base(name) != name || strings.Contains(name, "..") {
			return errors.New("invalid seed path")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	cleanup := []string{"rm -f -- \"$@\"", "nvt-seed-managed"}
	for _, name := range names {
		cleanup = append(cleanup, "/seed/"+name)
	}
	return backend.seedVolumeWithCleanup(ctx, volume, files, labels, cleanup)
}

func (backend *Backend) seedVolumeWithCleanup(ctx context.Context, volume string, files map[string]seedFile, labels ownedLabels, cleanup []string) error {
	arguments := []string{"create", "--entrypoint", "/bin/sh", "-v", volume + ":/seed"}
	arguments = append(arguments, labelArguments(labels)...)
	arguments = append(arguments, "--label", seedHelperLabel+"="+seedHelperValue)
	arguments = append(arguments, backend.config.SeedImage, "-c")
	arguments = append(arguments, cleanup...)
	created, err := backend.docker.Run(ctx, nil, arguments...)
	if err != nil {
		return err
	}
	container := strings.TrimSpace(string(created))
	if !validContainerID(container) || backend.verifySeedHelperContainer(ctx, container, labels) != nil {
		return errors.New("backend seed unavailable")
	}
	defer func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = backend.docker.Run(cleanupContext, nil, "rm", "--force", "--volumes", container)
	}()
	if _, err := backend.docker.Run(ctx, nil, "start", "--attach", container); err != nil {
		return err
	}
	archive, err := seedArchive(files)
	if err != nil {
		return errors.New("backend seed unavailable")
	}
	if _, err := backend.docker.Run(ctx, bytes.NewReader(archive), "cp", "-", container+":/seed"); err != nil {
		return err
	}
	return nil
}

func validContainerID(value string) bool {
	if len(value) < 12 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func seedArchive(files map[string]seedFile) ([]byte, error) {
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		file := files[name]
		if name == "" || filepath.Base(name) != name || strings.Contains(name, "..") {
			return nil, errors.New("invalid seed path")
		}
		header := &tar.Header{Name: name, Mode: file.mode, Size: int64(len(file.content)), Uid: file.uid, Gid: file.gid}
		if err := writer.WriteHeader(header); err != nil {
			return nil, err
		}
		if _, err := writer.Write(file.content); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func (backend *Backend) removeOwnedContainers(ctx context.Context, labels ownedLabels) error {
	containers, err := backend.ownedContainerIDs(ctx, labels)
	if err != nil {
		return err
	}
	for _, container := range containers {
		if err := backend.verifyContainer(ctx, container, labels); err != nil {
			return err
		}
		if _, err := backend.docker.Run(ctx, nil, "rm", "--force", "--volumes", container); err != nil {
			return err
		}
	}
	return nil
}

func (backend *Backend) ownedContainerIDs(ctx context.Context, labels ownedLabels) ([]string, error) {
	arguments := []string{"ps", "-aq"}
	for _, item := range labelPairs(labels) {
		arguments = append(arguments, "--filter", "label="+item)
	}
	output, err := backend.docker.Run(ctx, nil, arguments...)
	if err != nil {
		return nil, err
	}
	containers := strings.Fields(string(output))
	if len(containers) > 10_000 {
		return nil, errors.New("backend inventory exceeded its bound")
	}
	return containers, nil
}

func (backend *Backend) removeOwnedObjectsExcept(ctx context.Context, kind string, labels ownedLabels, preserve map[string]bool) error {
	arguments := []string{kind, "ls", "--format", "{{.Name}}"}
	for _, item := range labelPairs(labels) {
		arguments = append(arguments, "--filter", "label="+item)
	}
	output, err := backend.docker.Run(ctx, nil, arguments...)
	if err != nil {
		return err
	}
	names := strings.Fields(string(output))
	if len(names) > 10_000 {
		return errors.New("backend inventory exceeded its bound")
	}
	for _, name := range names {
		if preserve[name] {
			continue
		}
		if err := backend.verifyObject(ctx, kind, name, labels); err != nil {
			return err
		}
		if _, err := backend.docker.Run(ctx, nil, kind, "rm", name); err != nil {
			return err
		}
	}
	return nil
}

// removeExpectedOwnedObjects handles deterministic names independently of the
// exact-label inventory. A missing object is already clean; a present object
// with partial or conflicting labels is never touched and keeps cleanup
// retryable instead of allowing the durable run to become terminal.
func (backend *Backend) removeExpectedOwnedObjects(ctx context.Context, kind string, names []string, labels ownedLabels) error {
	for _, name := range names {
		output, err := backend.docker.Run(ctx, nil, kind, "inspect", "--format", "{{json .Labels}}", name)
		if err != nil {
			missing, missingErr := backend.objectConfirmedMissing(ctx, kind, name)
			if missingErr != nil || !missing {
				return errors.New("backend ownership unavailable")
			}
			continue
		}
		if err := verifyLabels(output, labels); err != nil {
			return err
		}
		if _, err := backend.docker.Run(ctx, nil, kind, "rm", name); err != nil {
			return err
		}
	}
	return nil
}

func (backend *Backend) objectConfirmedMissing(ctx context.Context, kind, expected string) (bool, error) {
	output, err := backend.docker.Run(ctx, nil, kind, "ls", "--format", "{{.Name}}")
	if err != nil {
		return false, err
	}
	names := strings.Fields(string(output))
	if len(names) > 10_000 {
		return false, errors.New("backend inventory exceeded its bound")
	}
	for _, name := range names {
		if name == expected {
			return false, nil
		}
	}
	return true, nil
}

func secretSafePlan(plan []byte, needles ...string) bool {
	for _, needle := range needles {
		if needle != "" && bytes.Contains(plan, []byte(needle)) {
			return false
		}
	}
	return true
}

func labelPairs(labels ownedLabels) []string {
	values := labelMap(labels)
	keys := []string{digestLabel, ownerLabel, runLabel}
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+values[key])
	}
	return result
}

func labelArguments(labels ownedLabels) []string {
	result := []string{}
	for _, pair := range labelPairs(labels) {
		result = append(result, "--label", pair)
	}
	return result
}

var _ controller.LocalBackend = (*Backend)(nil)

var errOwnershipConflict = errors.New("backend ownership conflict")
