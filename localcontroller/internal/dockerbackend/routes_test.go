package dockerbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/controller"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
	"gopkg.in/yaml.v3"
)

func TestHTTPExposureConfigurationRolloutRetainsVolumesAndNamedTargets(t *testing.T) {
	backend, docker, run, _ := testBackend(t)
	run.Persistence = resolvedrun.Persistence{Workspace: true, RuntimeState: true, DockerData: true}
	run.Retention, run.TTL = "persistent", resolvedrun.TTL{}
	ownership := strings.Repeat("a", 64)
	if _, err := backend.Ensure(context.Background(), controller.BackendRun{Resolved: run, SnapshotDigest: ownership, DesiredDigest: ownership}); err != nil {
		t.Fatal(err)
	}
	names := namesFor(backend.config, run.RunID, ownership)
	for index, route := range []exposeRoute{{Name: "website", TargetPort: 4321}, {Name: "preview", TargetPort: 8080}, {}} {
		previous := run
		var settings map[string]any
		if err := json.Unmarshal(run.AgentConfig, &settings); err != nil {
			t.Fatal(err)
		}
		delete(settings, "expose")
		if route.Name != "" {
			settings["expose"] = map[string]any{"http": []map[string]any{{"name": route.Name, "targetPort": route.TargetPort}}}
		}
		run.AgentConfig, _ = json.Marshal(settings)
		desired := controller.BackendRun{Resolved: run, PreviousResolved: &previous, SnapshotDigest: ownership, DesiredDigest: strings.Repeat(string(rune('b'+index)), 64), ConfigurationRollout: true}
		before := len(docker.commands)
		if observation, err := backend.Ensure(context.Background(), desired); err != nil || !observation.Ready {
			t.Fatalf("rollout = %#v, %v", observation, err)
		}
		stopped, recreated := false, false
		for _, command := range docker.commands[before:] {
			if command[0] == "stop" {
				stopped = true
			}
			if command[0] == "compose" && contains(command, "--force-recreate") {
				recreated = stopped
			}
			if command[0] == "volume" && contains(command, "rm") {
				t.Fatal("rollout removed a volume")
			}
		}
		if !stopped || !recreated {
			t.Fatal("rollout did not use existing stop/recreate path")
		}
		for _, volume := range []string{names.workspace, names.home, names.dockerData} {
			labels, exists := docker.objects["volume:"+volume]
			if !exists || labels[digestLabel] != ownership {
				t.Fatalf("persistent volume identity changed: %s", volume)
			}
		}
		routes, err := backend.Routes(context.Background(), desired)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := renderCompose(backend.config, run, ownership, names)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(plan, []byte("ports:")) {
			t.Fatal("route published a Docker host port")
		}
		if route.Name == "" {
			if len(routes.Exposures) != 0 || bytes.Contains(plan, []byte(`"name":"preview"`)) {
				t.Fatal("removed route retained metadata")
			}
			continue
		}
		if len(routes.Exposures) != 1 {
			t.Fatalf("route count: %d", len(routes.Exposures))
		}
		got := routes.Exposures[0]
		if got.Name != route.Name || got.Host != route.Name+"."+run.RunID+".agent.localhost" || got.UpstreamPort != route.TargetPort || got.UpstreamHost != names.namespace {
			t.Fatalf("named target = %#v", got)
		}
		route.Source = "agent"
		metadata, _ := json.Marshal([]exposeRoute{route})
		if !bytes.Contains(plan, metadata) {
			t.Fatal("runtime route instruction metadata missing")
		}
	}
}

func TestRoutesPublishOnlyStablePublicNamesAndIsolateAgentFromSharedProxy(t *testing.T) {
	run := testMediatedRun(t)
	run.RunID = "route-run"
	run.AgentConfig = json.RawMessage(`{"runtime":{"command":"agent-cli","args":[]},"plugins":[],"expose":{"http":[{"name":"app","targetPort":3000}]}}`)
	backend := &Backend{config: withRouteDefaults(Config{RouteBaseDomain: "agent.localhost", RoutePathPrefix: "/agents", GatewayContainer: "nvt-local-gateway"})}
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: "digest"}
	routes, err := backend.Routes(context.Background(), desired)
	if err != nil {
		t.Fatal(err)
	}
	if routes.Session.Host != "route-run.agent.localhost" || routes.Session.Path != "/agents/route-run/" || len(routes.Exposures) != 1 ||
		routes.Session.UpstreamHost == "" || routes.Session.UpstreamPort != 4090 || routes.Exposures[0].Name != "app" ||
		routes.Exposures[0].Host != "app.route-run.agent.localhost" || routes.Exposures[0].UpstreamHost != routes.Session.UpstreamHost || routes.Exposures[0].UpstreamPort != 3000 {
		t.Fatalf("routes = %#v", routes)
	}
	plan, err := renderCompose(backend.config, run, desired.SnapshotDigest, namesFor(backend.config, run.RunID, desired.SnapshotDigest))
	if err != nil {
		t.Fatal(err)
	}
	var document composeDocument
	if err := yaml.Unmarshal(plan, &document); err != nil {
		t.Fatal(err)
	}
	namespace := document.Services["docker"]
	if contains(namespace.Networks, "agents-proxy") || namespace.ContainerName != routes.Session.UpstreamHost {
		t.Fatalf("agent namespace retained shared proxy reachability: %#v", namespace)
	}
	for key := range namespace.Labels {
		if key == "traefik.enable" || strings.HasPrefix(key, "traefik.http.") {
			t.Fatalf("agent namespace retained direct proxy route: %s", key)
		}
	}
}

func TestUntrustedGatewayIsNeverAttachedToRunNetwork(t *testing.T) {
	backend, docker, run, _ := testBackend(t)
	docker.containers[backend.config.GatewayContainer] = map[string]string{localGatewayLabel: "false"}
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("8", 64)}
	if _, err := backend.Ensure(context.Background(), desired); !errors.Is(err, controller.ErrBackendRetryable) {
		t.Fatalf("untrusted gateway ensure = %v", err)
	}
	names := namesFor(backend.config, run.RunID, desired.SnapshotDigest)
	if docker.networkMembers[names.internalNet][backend.config.GatewayContainer] {
		t.Fatal("untrusted gateway was attached to the run network")
	}
}

func TestStoppedOrUnhealthyGatewayIsNotReadyAndRecreatedGatewayIsReattached(t *testing.T) {
	backend, docker, run, _ := testBackend(t)
	desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("7", 64)}
	docker.gatewayStatus = "stopped"
	if backend.Ready(context.Background()) {
		t.Fatal("stopped gateway reported ready")
	}
	if _, err := backend.Ensure(context.Background(), desired); !errors.Is(err, controller.ErrBackendRetryable) {
		t.Fatalf("stopped gateway ensure = %v", err)
	}
	docker.gatewayStatus = "running"
	docker.gatewayHealth = "starting"
	if backend.Ready(context.Background()) {
		t.Fatal("starting gateway reported ready")
	}
	docker.gatewayHealth = "healthy"
	if !backend.Ready(context.Background()) {
		t.Fatal("healthy running gateway not ready")
	}
	if observation, err := backend.Ensure(context.Background(), desired); err != nil || !observation.Ready {
		t.Fatalf("healthy gateway ensure = %#v %v", observation, err)
	}
	names := namesFor(backend.config, run.RunID, desired.SnapshotDigest)
	delete(docker.networkMembers[names.internalNet], backend.config.GatewayContainer)
	if observation, err := backend.Inspect(context.Background(), desired); err != nil || !observation.Ready {
		t.Fatalf("recreated gateway repair = %#v %v", observation, err)
	}
	if !docker.networkMembers[names.internalNet][backend.config.GatewayContainer] {
		t.Fatal("recreated gateway was not reattached")
	}
}

func TestCleanupRequiresGatewayIdentityButNotAvailability(t *testing.T) {
	for name, makeUnavailable := range map[string]func(*fakeDocker){
		"stopped": func(docker *fakeDocker) { docker.gatewayStatus = "stopped" },
		"unhealthy": func(docker *fakeDocker) {
			docker.gatewayStatus = "running"
			docker.gatewayHealth = "unhealthy"
		},
	} {
		t.Run(name, func(t *testing.T) {
			backend, docker, run, _ := testBackend(t)
			desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat("6", 64), DeleteRequested: true}
			if observation, err := backend.Ensure(context.Background(), desired); err != nil || !observation.Ready {
				t.Fatalf("ensure = %#v %v", observation, err)
			}
			names := namesFor(backend.config, run.RunID, desired.SnapshotDigest)
			makeUnavailable(docker)
			if backend.Ready(context.Background()) {
				t.Fatal("unavailable gateway reported ready")
			}
			if err := backend.Delete(context.Background(), desired); err != nil {
				t.Fatalf("cleanup was coupled to gateway availability: %v", err)
			}
			for _, object := range []string{"network:" + names.internalNet, "network:" + names.privateNet} {
				if _, exists := docker.objects[object]; exists {
					t.Fatalf("exact-owned object remained: %s", object)
				}
			}
			for _, volume := range backend.requiredVolumes(run, names) {
				if _, exists := docker.objects["volume:"+volume]; exists {
					t.Fatalf("disposable volume remained: %s", volume)
				}
			}
		})
	}
}

func TestSiblingRunAndPrivateProxyAreUnreachableWhileGatewayIsAttached(t *testing.T) {
	backend, docker, first, _ := testBackend(t)
	first.RunID = "isolation-first"
	second := first
	second.RunID = "isolation-second"
	for _, run := range []resolvedrun.ResolvedAgentRun{first, second} {
		desired := controller.BackendRun{Resolved: run, SnapshotDigest: strings.Repeat(run.RunID[len(run.RunID)-1:], 64)}
		if observation, err := backend.Ensure(context.Background(), desired); err != nil || !observation.Ready {
			t.Fatalf("ensure %s = %#v %v", run.RunID, observation, err)
		}
		names := namesFor(backend.config, run.RunID, desired.SnapshotDigest)
		if !docker.networkMembers[names.internalNet][backend.config.GatewayContainer] {
			t.Fatalf("gateway not attached to %s", names.internalNet)
		}
		plan, err := renderCompose(backend.config, run, desired.SnapshotDigest, names)
		if err != nil {
			t.Fatal(err)
		}
		var document composeDocument
		if yaml.Unmarshal(plan, &document) != nil || contains(document.Services["docker"].Networks, "agents-proxy") {
			t.Fatalf("namespace has a shared-network route:\n%s", plan)
		}
	}
	firstNames := namesFor(backend.config, first.RunID, strings.Repeat("t", 64))
	secondNames := namesFor(backend.config, second.RunID, strings.Repeat("d", 64))
	if firstNames.internalNet == secondNames.internalNet || docker.networkMembers[firstNames.internalNet][backend.config.GatewayContainer] == false ||
		docker.networkMembers[secondNames.internalNet][backend.config.GatewayContainer] == false {
		t.Fatal("gateway did not retain isolated per-run attachments")
	}
	// A run namespace has only its unique internal/private networks. It shares
	// neither the sibling internal network nor agents-proxy, so direct sibling
	// access and a Host-spoofed proxy:8081 request have no Docker network path.
	if firstNames.internalNet == backend.config.ExternalNetwork || firstNames.privateNet == backend.config.ExternalNetwork || firstNames.internalNet == secondNames.internalNet {
		t.Fatal("run network topology permits an authorization bypass")
	}
}
