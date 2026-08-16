package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mirkoSekulic/nvt-agent/localplatform/lifecycle"
	"github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
	"github.com/mirkoSekulic/nvt-agent/localplatform/producer"
	"github.com/mirkoSekulic/nvt-agent/localplatform/state"
)

const defaultProject = "nvt-local"

var projectPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$`)
var runIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var runtimeProjectPattern = regexp.MustCompile(`^nvt-local-[a-f0-9]{24}$`)
var containerIDPattern = regexp.MustCompile(`^[a-f0-9]{12,64}$`)

type app struct {
	project string
	docker  state.DockerCLI
}

func main() {
	if len(os.Args) != 2 {
		fail("usage: nvt-local <init|up|status|down|reset>")
	}
	project := environment("NVT_LOCAL_PROJECT", defaultProject)
	if !projectPattern.MatchString(project) {
		fail("NVT_LOCAL_PROJECT must be a lower-case Docker name of at most 48 characters")
	}
	// Let the Docker CLI consume DOCKER_HOST from its inherited environment.
	// Passing the same value as --host breaks daemon wrappers that enforce
	// required local networks at the CLI boundary.
	application := app{project: project, docker: state.DockerCLI{}}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	var err error
	switch os.Args[1] {
	case "init":
		_, err = application.prepare(ctx)
		if err == nil {
			fmt.Printf("local project %s initialized from %s\n", project, manifestPath())
		}
	case "up":
		var compose []byte
		compose, err = application.prepare(ctx)
		if err == nil {
			_, err = application.docker.Run(ctx, bytes.NewReader(compose), "compose", "-p", project, "-f", "-", "up", "-d", "--force-recreate", "--remove-orphans")
		}
		if err == nil {
			fmt.Printf("local project %s is starting; open http://localhost:%s/agents\n", project, environment("NVT_PROXY_PORT", "4090"))
		}
	case "status":
		err = application.status(ctx)
	case "down":
		err = application.stop(ctx)
		if err == nil {
			fmt.Printf("local project %s stopped; persistent state was preserved\n", project)
		}
	case "reset":
		err = application.reset(ctx)
		if err == nil {
			fmt.Printf("local project %s exact-owned containers, networks, volumes, credentials, and session state were removed\n", project)
		}
	default:
		err = errors.New("unknown local lifecycle command")
	}
	if err != nil {
		fail(err.Error())
	}
}

func (application app) prepare(ctx context.Context) ([]byte, error) {
	path := manifestPath()
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("nvt.local.yaml is unavailable: %w", err)
	}
	decoded, err := manifest.Decode(file)
	_ = file.Close()
	if err != nil {
		return nil, fmt.Errorf("nvt.local.yaml is invalid: %w", err)
	}
	compiled, err := manifest.Compile(decoded)
	if err != nil {
		return nil, fmt.Errorf("nvt.local.yaml cannot be compiled: %w", err)
	}
	inputs, err := state.Resolve(path, compiled)
	if err != nil {
		return nil, err
	}
	defer inputs.Close()
	for _, item := range compiled.Producers {
		if item.Kind != "oci" {
			continue
		}
		if _, pullErr := application.docker.Run(ctx, nil, "pull", "--quiet", item.Image); pullErr != nil {
			return nil, fmt.Errorf("external producer image %s is unavailable", item.Name)
		}
	}
	helperID, err := application.docker.Run(ctx, nil, "image", "inspect", "--format", "{{.Id}}", environment("NVT_LOCAL_CONTROLLER_IMAGE", "nvt-local-controller:latest"))
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(helperID)), "sha256:") {
		return nil, errors.New("trusted local images are unavailable; run make local-images")
	}
	store := state.DockerStore{Docker: application.docker, HelperImage: strings.TrimSpace(string(helperID))}
	plan, err := (state.Manager{Store: store}).Ensure(ctx, application.project, compiled, inputs)
	if err != nil {
		return nil, err
	}
	proxyPort := 4090
	if _, scanErr := fmt.Sscan(environment("NVT_PROXY_PORT", "4090"), &proxyPort); scanErr != nil || proxyPort < 1 || proxyPort > 65535 {
		return nil, errors.New("NVT_PROXY_PORT is invalid")
	}
	return lifecycle.Render(ctx, compiled, plan, lifecycle.RenderOptions{
		ProxyPort: proxyPort, RuntimeImage: environment("RUNTIME_IMAGE", "nvt-agent-runtime:latest"), DindImage: environment("DIND_IMAGE", "nvt-dind:latest"),
		BrokerImage: environment("NVT_BROKER_IMAGE", "nvt-broker:latest"), ControllerImage: environment("NVT_LOCAL_CONTROLLER_IMAGE", "nvt-local-controller:latest"),
		GatewayImage: environment("GATEWAY_IMAGE", "nvt-agent-gateway:latest"), CredentialImage: environment("CREDENTIAL_PORTAL_IMAGE", "nvt-credential-portal:latest"),
		EgressdImage: environment("EGRESSD_IMAGE", "nvt-egressd:latest"), CapturedImage: environment("CAPTURED_IMAGE", "nvt-captured:latest"),
		ProducerImage: environment("PRODUCER_IMAGE", "nvt-github-comments-producer:latest"), ProducerInspector: producer.DockerImageInspector{Runner: application.docker},
	})
}

func (application app) status(ctx context.Context) error {
	platform, err := application.docker.Run(ctx, nil, "ps", "-a", "--filter", "label=nvt.dev/local-platform-owner="+application.project, "--filter", "label=nvt.dev/local-platform-version=1", "--format", "{{.Names}}\t{{.Status}}")
	if err != nil {
		return errors.New("cannot inspect local platform containers")
	}
	runs, err := application.docker.Run(ctx, nil, "ps", "-a", "--filter", "label=nvt.dev/local-controller-owner="+application.project, "--format", "{{.Names}}\t{{.Status}}")
	if err != nil {
		return errors.New("cannot inspect local workstation containers")
	}
	rows := append(nonemptyLines(platform), nonemptyLines(runs)...)
	sort.Strings(rows)
	if len(rows) == 0 {
		fmt.Printf("local project %s is not running\n", application.project)
		return nil
	}
	fmt.Printf("NAME\tSTATUS\n%s\n", strings.Join(rows, "\n"))
	return nil
}

func (application app) stop(ctx context.Context) error {
	// Quiesce the controller before inventorying workstation containers so it
	// cannot create a new run after the destructive boundary was resolved.
	for _, platform := range []bool{true, false} {
		containers, err := application.containerIDsFor(ctx, platform, false)
		if err != nil {
			return err
		}
		if len(containers) == 0 {
			continue
		}
		arguments := append([]string{"stop", "--time", "30"}, containers...)
		if _, err := application.docker.Run(ctx, nil, arguments...); err != nil {
			return errors.New("cannot stop exact-owned local containers")
		}
	}
	return nil
}

func (application app) reset(ctx context.Context) error {
	// Remove the control plane first, then its now-quiescent run inventory.
	for _, platform := range []bool{true, false} {
		containers, err := application.containerIDsFor(ctx, platform, true)
		if err != nil {
			return err
		}
		if len(containers) != 0 {
			if _, err := application.docker.Run(ctx, nil, append([]string{"rm", "--force"}, containers...)...); err != nil {
				return errors.New("cannot remove exact-owned local containers")
			}
		}
	}
	for _, kind := range []string{"network", "volume"} {
		names, listErr := application.ownedObjects(ctx, kind)
		if listErr != nil {
			return listErr
		}
		for _, name := range names {
			if _, removeErr := application.docker.Run(ctx, nil, kind, "rm", name); removeErr != nil {
				return fmt.Errorf("cannot remove exact-owned local %s %s", kind, name)
			}
		}
	}
	return nil
}

func (application app) containerIDsFor(ctx context.Context, platform, all bool) ([]string, error) {
	flag := "-q"
	if all {
		flag = "-aq"
	}
	arguments := []string{"ps", flag}
	if platform {
		arguments = append(arguments, "--filter", "label=nvt.dev/local-platform-owner="+application.project, "--filter", "label=nvt.dev/local-platform-version=1")
	} else {
		arguments = append(arguments, "--filter", "label=nvt.dev/local-controller-owner="+application.project, "--filter", "label=nvt.dev/local-run-id", "--filter", "label=nvt.dev/local-run-digest")
	}
	seen := map[string]struct{}{}
	output, err := application.docker.Run(ctx, nil, arguments...)
	if err != nil {
		return nil, errors.New("cannot inventory exact-owned local containers")
	}
	for _, id := range strings.Fields(string(output)) {
		if !containerIDPattern.MatchString(id) {
			return nil, errors.New("Docker returned an invalid container identity")
		}
		labels, inspectErr := application.containerLabels(ctx, id)
		if inspectErr != nil {
			return nil, inspectErr
		}
		if platform && !application.validPlatformContainer(labels) || !platform && !application.validRunContainer(labels) {
			return nil, fmt.Errorf("refusing ambiguous local container %s", id)
		}
		seen[id] = struct{}{}
	}
	return sortedKeys(seen), nil
}

func (application app) containerLabels(ctx context.Context, id string) (map[string]string, error) {
	output, err := application.docker.Run(ctx, nil, "container", "inspect", "--format", "{{json .Config.Labels}}", id)
	if err != nil {
		return nil, fmt.Errorf("cannot inspect local container %s", id)
	}
	labels := map[string]string{}
	if json.Unmarshal(bytes.TrimSpace(output), &labels) != nil {
		return nil, errors.New("Docker returned invalid container labels")
	}
	return labels, nil
}

func (application app) validPlatformContainer(labels map[string]string) bool {
	if labels["nvt.dev/local-platform-owner"] != application.project || labels["nvt.dev/local-platform-version"] != "1" {
		return false
	}
	if labels["nvt.dev/local-platform-state-helper"] == "1" {
		return labels["com.docker.compose.project"] == "" && labels["com.docker.compose.service"] == ""
	}
	if labels["com.docker.compose.project"] != application.project {
		return false
	}
	service := labels["com.docker.compose.service"]
	for _, expected := range []string{"proxy", "broker", "registry-init", "gateway", "local-controller", "credential-runner", "credential-portal"} {
		if service == expected {
			return true
		}
	}
	return strings.HasPrefix(service, "producer-") && runIDPattern.MatchString(strings.TrimPrefix(service, "producer-"))
}

func (application app) validRunContainer(labels map[string]string) bool {
	if labels["nvt.dev/local-controller-owner"] != application.project || !runIDPattern.MatchString(labels["nvt.dev/local-run-id"]) || !digestPattern.MatchString(labels["nvt.dev/local-run-digest"]) ||
		!runtimeProjectPattern.MatchString(labels["com.docker.compose.project"]) {
		return false
	}
	service := labels["com.docker.compose.service"]
	for _, expected := range []string{"agent", "docker", "network", "workspace-init", "egressd", "ca-init", "captured", "confinement-init", "net-init"} {
		if service == expected {
			return true
		}
	}
	return false
}

func (application app) ownedObjects(ctx context.Context, kind string) ([]string, error) {
	command := kind
	if kind == "volume" {
		command = "volume"
	}
	queries := [][]string{
		{command, "ls", "--filter", "label=nvt.dev/local-platform-owner=" + application.project, "--filter", "label=nvt.dev/local-platform-version=1", "--format", "{{.Name}}"},
		{command, "ls", "--filter", "label=nvt.dev/local-controller-owner=" + application.project, "--filter", "label=nvt.dev/local-run-id", "--filter", "label=nvt.dev/local-run-digest", "--format", "{{.Name}}"},
	}
	seen := map[string]struct{}{}
	for _, query := range queries {
		output, err := application.docker.Run(ctx, nil, query...)
		if err != nil {
			return nil, fmt.Errorf("cannot inventory exact-owned local %ss", kind)
		}
		for _, name := range nonemptyLines(output) {
			if strings.ContainsAny(name, "\x00\r\n") || name == "" {
				return nil, errors.New("Docker returned an invalid object name")
			}
			labels, inspectErr := application.objectLabels(ctx, kind, name)
			if inspectErr != nil {
				return nil, inspectErr
			}
			platformOwned := labels["nvt.dev/local-platform-owner"] == application.project && labels["nvt.dev/local-platform-version"] == "1"
			runOwned := labels["nvt.dev/local-controller-owner"] == application.project && labels["nvt.dev/local-run-id"] != "" && regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(labels["nvt.dev/local-run-digest"])
			if !platformOwned && !runOwned {
				return nil, fmt.Errorf("refusing ambiguous local %s %s", kind, name)
			}
			if kind == "volume" && platformOwned && labels["nvt.dev/local-platform-volume"] != name {
				return nil, fmt.Errorf("refusing mislabeled local volume %s", name)
			}
			if kind == "network" && platformOwned && labels["nvt.dev/local-platform-network"] != name {
				return nil, fmt.Errorf("refusing mislabeled local network %s", name)
			}
			seen[name] = struct{}{}
		}
	}
	return sortedKeys(seen), nil
}

func (application app) objectLabels(ctx context.Context, kind, name string) (map[string]string, error) {
	output, err := application.docker.Run(ctx, nil, kind, "inspect", "--format", "{{json .Labels}}", name)
	if err != nil {
		return nil, fmt.Errorf("cannot inspect local %s %s", kind, name)
	}
	labels := map[string]string{}
	if json.Unmarshal(bytes.TrimSpace(output), &labels) != nil {
		return nil, errors.New("Docker returned invalid labels")
	}
	return labels, nil
}

func manifestPath() string {
	configured := environment("NVT_LOCAL_MANIFEST", "nvt.local.yaml")
	absolute, err := filepath.Abs(configured)
	if err != nil {
		return configured
	}
	return absolute
}

func environment(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
func nonemptyLines(value []byte) []string {
	result := []string{}
	for _, line := range strings.Split(strings.TrimSpace(string(value)), "\n") {
		if strings.TrimSpace(line) != "" {
			result = append(result, strings.TrimSpace(line))
		}
	}
	return result
}
func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
func fail(message string) { _, _ = io.WriteString(os.Stderr, "nvt-local: "+message+"\n"); os.Exit(1) }
