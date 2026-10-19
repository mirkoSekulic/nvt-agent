package dockerbackend

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

var errNetworkObservation = errors.New("backend network namespace unavailable")

// inspectSharedNetwork compares actual process namespaces, not NetworkMode:
// Docker retains container:<owner ID> even if an owner's restart strands live
// dependants in its old namespace. Loopback health checks still pass there.
// Use daemon-side process metadata, never binaries or files controlled by the
// agent. NETNS is provided by the Linux Docker host's ps, including on Desktop.
func (backend *Backend) inspectSharedNetwork(ctx context.Context, run resolvedrun.ResolvedAgentRun, names resourceNames, labels ownedLabels) ([]string, bool, error) {
	ownerService := "network"
	if run.Runtime.Docker != nil {
		ownerService = "docker"
	}
	owner, err := backend.networkServiceContainer(ctx, names.project, ownerService, labels)
	if err != nil {
		return nil, false, err
	}
	if owner == "" {
		return nil, true, nil
	}
	ownerNamespace, err := backend.containerNetworkNamespace(ctx, owner)
	if err != nil || ownerNamespace == 0 {
		return nil, false, errNetworkObservation
	}
	services := []string{"agent"}
	if run.Egress.Mode == "mediated" && (run.Egress.Transport == "forward-proxy" || run.Egress.Transport == "transparent" || hasCatalogGrant(run)) {
		services = append(services, "captured")
	}
	if run.Egress.Mode == "mediated" && run.Egress.Transport == "transparent" {
		services = append(services, "net-init")
	}
	var stale []string
	drift := false
	for _, service := range services {
		container, err := backend.networkServiceContainer(ctx, names.project, service, labels)
		if err != nil {
			return nil, false, err
		}
		if container == "" {
			drift = true
			continue
		}
		namespace, err := backend.containerNetworkNamespace(ctx, container)
		if err != nil {
			return nil, false, err
		}
		if namespace != ownerNamespace {
			drift = true
			stale = append(stale, container)
		}
	}
	// Do not act on a mixed observation if the owner restarted during sampling.
	currentNamespace, err := backend.containerNetworkNamespace(ctx, owner)
	if err != nil || currentNamespace != ownerNamespace {
		return nil, false, errNetworkObservation
	}
	return stale, drift, nil
}

// repairSharedNetwork runs only during durable preparation. Remove only exact-
// owned stale dependants, agent first; Compose then restores dependency order
// and the confinement gate. Keep the namespace owner and all named volumes.
func (backend *Backend) repairSharedNetwork(ctx context.Context, run resolvedrun.ResolvedAgentRun, names resourceNames, labels ownedLabels) error {
	stale, _, err := backend.inspectSharedNetwork(ctx, run, names, labels)
	if err != nil {
		return err
	}
	for _, container := range stale {
		if err := backend.verifyContainer(ctx, container, labels); err != nil {
			return err
		}
		if _, err := backend.docker.Run(ctx, nil, "rm", "--force", container); err != nil {
			return err
		}
	}
	return nil
}

func (backend *Backend) networkServiceContainer(ctx context.Context, project, service string, expected ownedLabels) (string, error) {
	output, err := backend.docker.Run(ctx, nil, "ps", "-aq", "--filter", "label="+composeProjectLabel+"="+project, "--filter", "label="+composeServiceLabel+"="+service)
	if err != nil {
		return "", err
	}
	containers := strings.Fields(string(output))
	if len(containers) == 0 {
		return "", nil
	}
	if len(containers) != 1 {
		return "", errNetworkObservation
	}
	container := containers[0]
	labels, err := backend.containerLabels(ctx, container)
	if err != nil {
		return "", err
	}
	if err := verifyLabelMap(labels, expected); err != nil {
		return "", err
	}
	if labels[composeProjectLabel] != project || labels[composeServiceLabel] != service {
		return "", errOwnershipConflict
	}
	return container, nil
}

// A stopped dependant has no namespace and must be recreated during repair.
// Inaccessible/malformed metadata is uncertainty, not permission to mutate.
func (backend *Backend) containerNetworkNamespace(ctx context.Context, container string) (uint64, error) {
	output, err := backend.docker.Run(ctx, nil, "inspect", "--format", "{{json .State}}", container)
	if err != nil {
		return 0, err
	}
	var state struct {
		Running   *bool
		Pid       int
		StartedAt string
	}
	if json.Unmarshal(output, &state) != nil || state.Running == nil || state.Pid < 0 {
		return 0, errNetworkObservation
	}
	if !*state.Running {
		if state.Pid != 0 {
			return 0, errNetworkObservation
		}
		return 0, nil
	}
	if state.Pid <= 0 {
		return 0, errNetworkObservation
	}
	output, err = backend.docker.Run(ctx, nil, "top", container, "-eo", "pid,netns")
	if err != nil {
		// Minimal Docker hosts (e.g. BusyBox-based DinD) lack ps's NETNS
		// column. Read the same kernel metadata with a trusted one-shot helper
		// sharing only this container's PID namespace, never the host PID
		// namespace, network, files, environment, or broker credentials.
		// SYS_PTRACE permits readlink for a differently-owned init process;
		// the fixed command cannot inspect its memory or execute agent tools.
		output, err = backend.docker.Run(ctx, nil, "run", "--rm", "--read-only", "--network", "none",
			"--cap-drop", "ALL", "--cap-add", "SYS_PTRACE", "--security-opt", "no-new-privileges",
			"--user", "0:0", "--pid", "container:"+container,
			"--entrypoint", "readlink", backend.config.SeedImage, "/proc/1/ns/net")
		if err != nil {
			return 0, err
		}
		value := strings.TrimSpace(string(output))
		if !strings.HasPrefix(value, "net:[") || !strings.HasSuffix(value, "]") {
			return 0, errNetworkObservation
		}
		// Reuse the strict numeric parser, and check the sampled init is still
		// current before accepting either observation path.
		output = []byte("PID NETNS\n" + strconv.Itoa(state.Pid) + " " + value[5:len(value)-1])
	}
	namespace, err := parseInitNetworkNamespace(output, state.Pid)
	if err != nil {
		return 0, err
	}
	after, err := backend.docker.Run(ctx, nil, "inspect", "--format", "{{json .State}}", container)
	var current struct {
		Running   *bool
		Pid       int
		StartedAt string
	}
	if err != nil || json.Unmarshal(after, &current) != nil || current.Running == nil || !*current.Running || current.Pid != state.Pid || current.StartedAt != state.StartedAt {
		return 0, errNetworkObservation
	}
	return namespace, nil
}

func parseInitNetworkNamespace(output []byte, pid int) (uint64, error) {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) < 2 || strings.Join(strings.Fields(lines[0]), " ") != "PID NETNS" {
		return 0, errNetworkObservation
	}
	var namespace uint64
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return 0, errNetworkObservation
		}
		if fields[0] != strconv.Itoa(pid) {
			continue // Child processes may legitimately use nested namespaces.
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || value == 0 || namespace != 0 {
			return 0, errNetworkObservation
		}
		namespace = value
	}
	if namespace == 0 {
		return 0, errNetworkObservation
	}
	return namespace, nil
}
