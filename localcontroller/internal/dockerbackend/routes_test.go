package dockerbackend

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/controller"
)

func TestRoutesPublishOnlyStablePublicNamesAndRenderPrivateProxyEntrypoint(t *testing.T) {
	run := testMediatedRun(t)
	run.RunID = "route-run"
	run.AgentConfig = json.RawMessage(`{"runtime":{"command":"agent-cli","args":[]},"plugins":[],"expose":{"http":[{"name":"app","targetPort":3000}]}}`)
	backend := &Backend{config: withRouteDefaults(Config{RouteBaseDomain: "agent.localhost", RoutePathPrefix: "/agents", ProxyEntrypoint: "local-agents"})}
	routes, err := backend.Routes(context.Background(), controller.BackendRun{Resolved: run, SnapshotDigest: "digest"})
	if err != nil {
		t.Fatal(err)
	}
	if routes.Session.Host != "route-run.agent.localhost" || routes.Session.Path != "/agents/route-run/" || len(routes.Exposures) != 1 ||
		routes.Exposures[0].Name != "app" || routes.Exposures[0].Host != "app.route-run.agent.localhost" {
		t.Fatalf("routes = %#v", routes)
	}

	labels := dockerRouteLabels(backend.config, map[string]string{}, "nvt-route-run", "route-run", []exposeRoute{{Name: "app", TargetPort: 3000}})
	for _, router := range []string{"nvt-route-run", "nvt-route-run-app"} {
		if labels["traefik.http.routers."+router+".entrypoints"] != "local-agents" {
			t.Fatalf("router %s was exposed on public entrypoint: %#v", router, labels)
		}
	}
	for key, value := range labels {
		if strings.Contains(key+value, "token") || strings.Contains(key+value, "credential") {
			t.Fatalf("route labels contain credential surface: %s=%s", key, value)
		}
	}
}
