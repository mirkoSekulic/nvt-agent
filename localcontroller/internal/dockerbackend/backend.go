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
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
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
	info, err := os.Lstat(backend.config.BrokerAgentsPath)
	return err == nil && info.Mode().IsRegular()
}

func New(config Config) (*Backend, error) {
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
	if err := validateConfig(config); err != nil || boundary == nil || len(key) < 32 || preparer == nil {
		return nil, errors.New("docker backend configuration invalid")
	}
	if err := prepareRunsDir(config.RunsDir); err != nil {
		return nil, err
	}
	return &Backend{config: config, docker: boundary, registry: brokerRegistry{path: config.BrokerAgentsPath}, key: append([]byte(nil), key...), preparer: preparer}, nil
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
	if config.DockerHost == "" || config.RunsDir == "" || !filepath.IsAbs(config.RunsDir) || filepath.Clean(config.RunsDir) != config.RunsDir ||
		config.BrokerAgentsPath == "" || !filepath.IsAbs(config.BrokerAgentsPath) || config.IdentityKeyPath == "" || !filepath.IsAbs(config.IdentityKeyPath) ||
		config.BrokerCAFile != "" && !filepath.IsAbs(config.BrokerCAFile) ||
		config.Owner == "" || len(config.Owner) > 63 || config.ExternalNetwork == "" || config.ProxyPort < 1 || config.ProxyPort > 65535 || config.ProtectedCIDRs == "" || len(config.ProtectedCIDRs) > 4096 || config.DindImage == "" || config.EgressdImage == "" ||
		config.CapturedImage == "" || config.SeedImage == "" || config.OperationTimeout < time.Second || config.OperationTimeout > 5*time.Minute ||
		!validDockerName(config.ExternalNetwork) || !validImage(config.DindImage) || !validImage(config.EgressdImage) || !validImage(config.CapturedImage) || !validImage(config.SeedImage) ||
		strings.ContainsAny(config.Owner+config.ProtectedCIDRs, "\x00\r\n") {
		return errors.New("docker backend configuration invalid")
	}
	parsed, err := url.Parse(config.BrokerURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return errors.New("docker backend configuration invalid")
	}
	return nil
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

func (backend *Backend) Ensure(ctx context.Context, desired controller.BackendRun) (controller.BackendObservation, error) {
	run := desired.Resolved
	if run.Execution.Kind != "container" {
		return controller.BackendObservation{}, errors.New("backend kind unsupported")
	}
	if run.Egress.Mode == "direct" && len(run.Broker.Grants) != 0 {
		return controller.BackendObservation{}, errors.New("zero-secret backend requires mediated credentials")
	}
	if strings.HasPrefix(backend.config.BrokerURL, "http://") && run.Egress.Mode == "mediated" && !run.Egress.AllowInsecureBroker {
		return controller.BackendObservation{}, errors.New("broker transport unavailable")
	}
	operationContext, cancel := context.WithTimeout(ctx, backend.config.OperationTimeout)
	defer cancel()
	names := namesFor(backend.config, run.RunID, desired.SnapshotDigest)
	labels := ownedLabels{Owner: backend.config.Owner, RunID: run.RunID, Digest: desired.SnapshotDigest}
	if err := backend.ensureDirectory(run.RunID); err != nil {
		return controller.BackendObservation{}, errors.New("backend state unavailable")
	}
	tokens := deriveTokens(backend.key, run.RunID, desired.SnapshotDigest)
	if err := backend.registry.upsert(run, desired.SnapshotDigest, tokens); err != nil {
		return controller.BackendObservation{}, err
	}
	if err := backend.ensureExternalNetwork(operationContext); err != nil {
		return controller.BackendObservation{}, err
	}
	for _, volume := range backend.requiredVolumes(run, names) {
		if err := backend.ensureOwnedObject(operationContext, "volume", volume, labels); err != nil {
			return controller.BackendObservation{}, err
		}
	}
	for _, network := range []string{names.internalNet, names.privateNet} {
		if err := backend.ensureOwnedObject(operationContext, "network", network, labels); err != nil {
			return controller.BackendObservation{}, err
		}
	}
	rendered, err := resolvedrun.RenderAgentConfig(run, renderBindings(run))
	if err != nil {
		return controller.BackendObservation{}, errors.New("agent configuration unavailable")
	}
	rendered, preparedMetadata, err := backend.preparer.prepare(operationContext, run, tokens.agent, rendered)
	if err != nil {
		return controller.BackendObservation{}, err
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
		return controller.BackendObservation{}, err
	}
	if run.Egress.Mode == "mediated" {
		egressConfig, err := renderEgressdConfig(backend.config, run)
		if err != nil {
			return controller.BackendObservation{}, errors.New("egress configuration unavailable")
		}
		if err := backend.seedVolume(operationContext, names.egressPrivate, map[string]seedFile{
			"egressd.json": {content: egressConfig, mode: 0o600}, "broker-token": {content: []byte(tokens.egress), mode: 0o400},
		}, labels); err != nil {
			return controller.BackendObservation{}, err
		}
	}
	plan, err := renderCompose(backend.config, run, desired.SnapshotDigest, names)
	if err != nil {
		return controller.BackendObservation{}, err
	}
	if bytes.Contains(plan, []byte(tokens.agent)) || bytes.Contains(plan, []byte(tokens.egress)) {
		return controller.BackendObservation{}, errors.New("compose plan unavailable")
	}
	if err := atomicWrite(names.composeFile, plan, 0o600); err != nil {
		return controller.BackendObservation{}, errors.New("backend state unavailable")
	}
	if _, err := backend.docker.Run(operationContext, nil, "compose", "-p", names.project, "-f", names.composeFile, "up", "-d", "--remove-orphans"); err != nil {
		return controller.BackendObservation{}, err
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		observation, inspectErr := backend.Inspect(operationContext, desired)
		if inspectErr == nil && observation.Ready {
			return observation, nil
		}
		select {
		case <-operationContext.Done():
			return controller.BackendObservation{}, errors.New("backend readiness unavailable")
		case <-ticker.C:
		}
	}
}

func (backend *Backend) Inspect(ctx context.Context, desired controller.BackendRun) (controller.BackendObservation, error) {
	names := namesFor(backend.config, desired.Resolved.RunID, desired.SnapshotDigest)
	operationContext, cancel := context.WithTimeout(ctx, backend.config.OperationTimeout)
	defer cancel()
	output, err := backend.docker.Run(operationContext, nil, "compose", "-p", names.project, "-f", names.composeFile, "ps", "-q", "agent")
	if err != nil || strings.TrimSpace(string(output)) == "" {
		return controller.BackendObservation{}, errors.New("backend instance unavailable")
	}
	containerID := strings.TrimSpace(string(output))
	labels := ownedLabels{Owner: backend.config.Owner, RunID: desired.Resolved.RunID, Digest: desired.SnapshotDigest}
	if err := backend.verifyContainer(operationContext, containerID, labels); err != nil {
		return controller.BackendObservation{}, err
	}
	running, err := backend.docker.Run(operationContext, nil, "inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{if .State.Running}}running{{else}}stopped{{end}}{{end}}", containerID)
	if err != nil {
		return controller.BackendObservation{}, err
	}
	status := strings.TrimSpace(string(running))
	return controller.BackendObservation{Ready: status == "healthy" || status == "running"}, nil
}

func (backend *Backend) Delete(ctx context.Context, desired controller.BackendRun) error {
	operationContext, cancel := context.WithTimeout(ctx, backend.config.OperationTimeout)
	defer cancel()
	run := desired.Resolved
	names := namesFor(backend.config, run.RunID, desired.SnapshotDigest)
	labels := ownedLabels{Owner: backend.config.Owner, RunID: run.RunID, Digest: desired.SnapshotDigest}
	tokens := deriveTokens(backend.key, run.RunID, desired.SnapshotDigest)
	if err := backend.registry.remove(run.RunID, tokens); err != nil {
		return err
	}
	if _, err := os.Stat(names.composeFile); err == nil {
		if _, err := backend.docker.Run(operationContext, nil, "compose", "-p", names.project, "-f", names.composeFile, "down", "--remove-orphans", "--timeout", "15"); err != nil {
			return err
		}
	}
	if err := backend.removeOwnedContainers(operationContext, labels); err != nil {
		return err
	}
	for _, network := range []string{names.internalNet, names.privateNet} {
		if err := backend.removeOwnedObject(operationContext, "network", network, labels); err != nil {
			return err
		}
	}
	volumes := []string{names.agentConfig, names.egressPrivate, names.egressPublic}
	if desired.DeleteRequested || !run.Persistence.Workspace {
		volumes = append(volumes, names.workspace)
	}
	if desired.DeleteRequested || !run.Persistence.RuntimeState {
		volumes = append(volumes, names.home)
	}
	if run.Runtime.Docker != nil && (desired.DeleteRequested || !run.Persistence.DockerData) {
		volumes = append(volumes, names.dockerData)
	}
	for _, volume := range volumes {
		if err := backend.removeOwnedObject(operationContext, "volume", volume, labels); err != nil {
			return err
		}
	}
	if desired.DeleteRequested {
		if err := os.RemoveAll(filepath.Dir(names.composeFile)); err != nil {
			return errors.New("backend state unavailable")
		}
	}
	return nil
}

func (backend *Backend) ensureDirectory(runID string) error {
	if err := os.MkdirAll(filepath.Join(backend.config.RunsDir, runID), 0o700); err != nil {
		return err
	}
	return os.Chmod(filepath.Join(backend.config.RunsDir, runID), 0o700)
}

func (backend *Backend) requiredVolumes(run resolvedrun.ResolvedAgentRun, names resourceNames) []string {
	values := []string{names.agentConfig, names.workspace, names.home}
	if run.Runtime.Docker != nil {
		values = append(values, names.dockerData)
	}
	if run.Egress.Mode == "mediated" {
		values = append(values, names.egressPrivate, names.egressPublic)
	}
	return values
}

func (backend *Backend) ensureExternalNetwork(ctx context.Context) error {
	_, err := backend.docker.Run(ctx, nil, "network", "inspect", backend.config.ExternalNetwork)
	return err
}

func (backend *Backend) ensureOwnedObject(ctx context.Context, kind, name string, labels ownedLabels) error {
	if err := backend.verifyObject(ctx, kind, name, labels); err == nil {
		return nil
	}
	arguments := []string{kind, "create"}
	arguments = append(arguments, labelArguments(labels)...)
	arguments = append(arguments, name)
	if _, err := backend.docker.Run(ctx, nil, arguments...); err != nil {
		if verifyErr := backend.verifyObject(ctx, kind, name, labels); verifyErr != nil {
			return err
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
	output, err := backend.docker.Run(ctx, nil, "inspect", "--format", "{{json .Config.Labels}}", name)
	if err != nil {
		return err
	}
	return verifyLabels(output, labels)
}

func verifyLabels(raw []byte, expected ownedLabels) error {
	var labels map[string]string
	if err := json.Unmarshal(bytes.TrimSpace(raw), &labels); err != nil {
		return errors.New("backend ownership unavailable")
	}
	for key, value := range labelMap(expected) {
		if labels[key] != value {
			return errors.New("backend ownership unavailable")
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
	arguments := []string{"create", "--entrypoint", "/bin/true", "-v", volume + ":/seed"}
	arguments = append(arguments, labelArguments(labels)...)
	arguments = append(arguments, backend.config.SeedImage)
	created, err := backend.docker.Run(ctx, nil, arguments...)
	if err != nil {
		return err
	}
	container := strings.TrimSpace(string(created))
	if !validContainerID(container) || backend.verifyContainer(ctx, container, labels) != nil {
		return errors.New("backend seed unavailable")
	}
	defer func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = backend.docker.Run(cleanupContext, nil, "rm", "-f", container)
	}()
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
	arguments := []string{"ps", "-aq"}
	for _, item := range labelPairs(labels) {
		arguments = append(arguments, "--filter", "label="+item)
	}
	output, err := backend.docker.Run(ctx, nil, arguments...)
	if err != nil {
		return err
	}
	for _, container := range strings.Fields(string(output)) {
		if err := backend.verifyContainer(ctx, container, labels); err != nil {
			return err
		}
		if _, err := backend.docker.Run(ctx, nil, "rm", "-f", container); err != nil {
			return err
		}
	}
	return nil
}

func (backend *Backend) removeOwnedObject(ctx context.Context, kind, name string, labels ownedLabels) error {
	if err := backend.verifyObject(ctx, kind, name, labels); err != nil {
		// Missing is already clean. A same-name unmanaged object is not: inspect
		// it once more to distinguish the two without ever deleting it.
		if _, inspectErr := backend.docker.Run(ctx, nil, kind, "inspect", name); inspectErr == nil {
			return errors.New("backend ownership unavailable")
		}
		return nil
	}
	_, err := backend.docker.Run(ctx, nil, kind, "rm", name)
	return err
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
