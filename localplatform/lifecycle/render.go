package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
	plancontract "github.com/mirkoSekulic/nvt-agent/localplatform/plan"
	producerrender "github.com/mirkoSekulic/nvt-agent/localplatform/producer"
	"gopkg.in/yaml.v3"
)

type RenderOptions struct {
	ProxyPort         int
	RuntimeImage      string
	DindImage         string
	BrokerImage       string
	ControllerImage   string
	GatewayImage      string
	CredentialImage   string
	EgressdImage      string
	CapturedImage     string
	ProducerImage     string
	ProducerInspector producerrender.ImageInspector
}

func (options RenderOptions) defaults() RenderOptions {
	if options.ProxyPort == 0 {
		options.ProxyPort = 4090
	}
	if options.RuntimeImage == "" {
		options.RuntimeImage = "nvt-agent-runtime:latest"
	}
	if options.DindImage == "" {
		options.DindImage = "nvt-dind:latest"
	}
	if options.BrokerImage == "" {
		options.BrokerImage = "nvt-broker:latest"
	}
	if options.ControllerImage == "" {
		options.ControllerImage = "nvt-local-controller:latest"
	}
	if options.GatewayImage == "" {
		options.GatewayImage = "nvt-agent-gateway:latest"
	}
	if options.CredentialImage == "" {
		options.CredentialImage = "nvt-credential-portal:latest"
	}
	if options.EgressdImage == "" {
		options.EgressdImage = "nvt-egressd:latest"
	}
	if options.CapturedImage == "" {
		options.CapturedImage = "nvt-captured:latest"
	}
	if options.ProducerImage == "" {
		options.ProducerImage = "nvt-github-comments-producer:latest"
	}
	return options
}

// Render emits the complete in-memory Compose document. Callers pass it to
// Docker Compose on stdin; it is never written into the workspace.
func Render(ctx context.Context, compiled manifest.Compiled, statePlan plancontract.Plan, options RenderOptions) ([]byte, error) {
	options = options.defaults()
	if ctx == nil || options.ProxyPort < 1 || options.ProxyPort > 65535 || statePlan.Project == "" {
		return nil, errors.New("local lifecycle render configuration is invalid")
	}
	project := statePlan.Project
	labels := map[string]string{"nvt.dev/local-platform-owner": project, "nvt.dev/local-platform-version": "1"}
	proxyNetwork := project + "_agents-proxy"
	controlNetwork := project + "_local-control-plane"
	egressNetwork := project + "_producer-egress"
	volumes := map[string]any{}
	for _, volume := range statePlan.Volumes {
		volumes[volume.Name] = map[string]any{"external": true, "name": volume.Name}
	}
	serviceMounts := func(service string) []any {
		mounts := []any{}
		for _, mount := range statePlan.Mounts {
			if mount.Service != service {
				continue
			}
			entry := map[string]any{"type": "volume", "source": mount.Volume, "target": mount.Target, "read_only": mount.ReadOnly}
			if mount.Subpath != "" {
				entry["volume"] = map[string]any{"subpath": mount.Subpath}
			}
			mounts = append(mounts, entry)
		}
		return mounts
	}
	registryVolume := ""
	for _, mount := range statePlan.Mounts {
		if mount.Service == "local-controller" && mount.Target == "/registry" {
			registryVolume = mount.Volume
		}
	}
	if registryVolume == "" {
		return nil, errors.New("broker registry state is unavailable")
	}
	services := map[string]any{}
	services["proxy"] = map[string]any{
		"image": "traefik:v3", "command": []string{"--providers.docker=true", "--providers.docker.exposedbydefault=false", "--providers.docker.network=" + proxyNetwork, "--entrypoints.web.address=:80"},
		"ports": []string{"127.0.0.1:" + strconv.Itoa(options.ProxyPort) + ":80"}, "volumes": []string{"/var/run/docker.sock:/var/run/docker.sock:ro"},
		"networks": []string{"agents-proxy"}, "restart": "unless-stopped", "labels": labels,
	}
	portalEnabled := len(compiled.Gateway.CredentialPortalAccounts) > 0
	brokerEnvironment := map[string]string{
		"NVT_BROKER_CONFIG": "/etc/nvt-local/broker.json", "NVT_BROKER_AGENTS_CONFIG": "/registry/agents.yaml", "NVT_BROKER_AUDIT_LOG": "/var/lib/nvt/broker/audit.jsonl",
		"NVT_BROKER_BIND": "0.0.0.0:7347", "NVT_BROKER_STATE_DIR": "/private", "NVT_BROKER_SEED_TARGET_DIR": "portal",
	}
	broker := map[string]any{"image": options.BrokerImage, "environment": brokerEnvironment, "volumes": serviceMounts("broker"), "networks": []string{"agents-proxy", "local-control-plane"}, "depends_on": map[string]any{"registry-init": map[string]string{"condition": "service_completed_successfully"}}, "restart": "unless-stopped", "labels": labels}
	if portalEnabled {
		brokerEnvironment["NVT_BROKER_SEED_DIR"] = "/portal-seed"
		broker["entrypoint"] = []string{"/opt/nvt-broker/broker/seed_supervisor.py", "--", "/opt/nvt-broker/broker/brokerd.py"}
	}
	services["broker"] = broker
	services["registry-init"] = map[string]any{
		"image": options.ControllerImage, "user": "0:0", "network_mode": "none", "entrypoint": []string{"/bin/sh", "-euc"},
		"command": []string{"umask 077; if [ ! -e /registry/agents.yaml ]; then printf 'agents: []\\n' > /registry/agents.yaml; fi; test -f /registry/agents.yaml; chmod 0600 /registry/agents.yaml"},
		"volumes": []any{map[string]any{"type": "volume", "source": registryVolume, "target": "/registry"}}, "restart": "no", "labels": labels,
	}
	gatewayLabels := cloneLabels(labels)
	gatewayLabels["nvt.dev/local-gateway"] = "true"
	gatewayEnvironment := map[string]string{
		"NVT_GATEWAY_LISTEN_ADDR": "0.0.0.0:8080", "NVT_GATEWAY_BASE_DOMAIN": "localhost", "NVT_GATEWAY_AUTH_MODE": "none",
		"NVT_GATEWAY_LOCAL_RUNS_ENABLED": "true", "NVT_GATEWAY_LOCAL_RUNS_DISABLE_KUBERNETES": "true", "NVT_GATEWAY_LOCAL_RUNS_CONTROLLER_URL": "http://local-controller:7480",
		"NVT_GATEWAY_LOCAL_RUNS_TOKEN_FILE": plancontract.PrivateTarget("local-controller-route-token"), "NVT_GATEWAY_LOCAL_RUNS_BASE_DOMAIN": "agent.localhost", "NVT_GATEWAY_LOCAL_RUNS_PATH_PREFIX": "/agents",
	}
	if portalEnabled {
		gatewayEnvironment["NVT_GATEWAY_CREDENTIAL_PORTAL_URL"] = "/agents/credentials"
	}
	services["gateway"] = map[string]any{
		"image": options.GatewayImage, "container_name": project + "-gateway", "user": "65532:65532", "environment": gatewayEnvironment,
		"networks": []string{"agents-proxy", "local-control-plane"}, "volumes": serviceMounts("gateway"), "read_only": true, "tmpfs": []string{"/tmp"}, "restart": "unless-stopped", "labels": mergeLabels(gatewayLabels, map[string]string{
			"traefik.enable": "true", "traefik.docker.network": proxyNetwork,
			"traefik.http.routers.nvt-local-gateway.rule":        "Host(`localhost`) && (PathPrefix(`/agents`) || PathPrefix(`/oauth2`) || PathPrefix(`/healthz/branding/`))",
			"traefik.http.routers.nvt-local-gateway.entrypoints": "web", "traefik.http.routers.nvt-local-gateway.service": "nvt-local-gateway",
			"traefik.http.routers.nvt-local-gateway-host.rule": "HostRegexp(`[a-z0-9-]+\\.agent\\.localhost`)", "traefik.http.routers.nvt-local-gateway-host.entrypoints": "web", "traefik.http.routers.nvt-local-gateway-host.service": "nvt-local-gateway",
			"traefik.http.services.nvt-local-gateway.loadbalancer.server.port": "8080",
		}),
	}
	services["local-controller"] = map[string]any{
		"image": options.ControllerImage, "environment": map[string]string{
			"NVT_LOCAL_CONTROLLER_BIND": "0.0.0.0:7480", "NVT_LOCAL_CONTROLLER_STATE": "/var/lib/nvt/local-controller/local-controller.sqlite3", "NVT_LOCAL_CONTROLLER_DOCKER_HOST": "unix:///var/run/docker.sock",
			"NVT_LOCAL_CONTROLLER_MAX_ACTIVE_RUNS": "128",
			"NVT_LOCAL_CONTROLLER_RUNS_DIR":        "/var/lib/nvt/local-controller/runs", "NVT_LOCAL_CONTROLLER_BROKER_URL": "http://broker:7347", "NVT_LOCAL_CONTROLLER_BROKER_AGENTS": "/registry/agents.yaml",
			"NVT_LOCAL_CONTROLLER_IDENTITY_KEY_FILE": plancontract.PrivateTarget("local-controller-identity"), "NVT_LOCAL_CONTROLLER_OWNER": project,
			"NVT_LOCAL_CONTROLLER_EXTERNAL_NETWORK": proxyNetwork, "NVT_LOCAL_CONTROLLER_ROUTE_BASE_DOMAIN": "agent.localhost", "NVT_LOCAL_CONTROLLER_ROUTE_PATH_PREFIX": "/agents",
			"NVT_LOCAL_CONTROLLER_GATEWAY_CONTAINER": project + "-gateway", "NVT_LOCAL_CONTROLLER_CONFIG": "/etc/nvt-local/local-controller.json",
			"NVT_LOCAL_CONTROLLER_ADMIN_TOKEN_FILE": plancontract.PrivateTarget("local-controller-admin-token"), "NVT_LOCAL_CONTROLLER_ROUTE_TOKEN_FILE": plancontract.PrivateTarget("local-controller-route-token"),
			"NVT_LOCAL_CONTROLLER_PROXY_PORT": strconv.Itoa(options.ProxyPort), "NVT_LOCAL_CONTROLLER_DIND_IMAGE": options.DindImage, "NVT_LOCAL_CONTROLLER_EGRESSD_IMAGE": options.EgressdImage,
			"NVT_LOCAL_CONTROLLER_CAPTURED_IMAGE": options.CapturedImage, "NVT_LOCAL_CONTROLLER_SEED_IMAGE": options.RuntimeImage,
		}, "volumes": append(serviceMounts("local-controller"), "/var/run/docker.sock:/var/run/docker.sock"), "networks": []string{"local-control-plane"},
		"depends_on": map[string]any{"registry-init": map[string]string{"condition": "service_completed_successfully"}}, "read_only": true, "tmpfs": []string{"/tmp"}, "restart": "unless-stopped", "labels": labels,
	}
	if portalEnabled {
		services["credential-runner"] = map[string]any{
			"image": options.CredentialImage, "command": []string{"runner", "--listen", "0.0.0.0:8081", "--auth-key-file", plancontract.PrivateTarget("credential-runner-key")},
			"volumes": serviceMounts("credential-runner"), "networks": []string{"agents-proxy", "local-control-plane"}, "read_only": true, "tmpfs": []string{"/tmp"}, "restart": "unless-stopped",
			"labels": mergeLabels(labels, map[string]string{"traefik.enable": "true", "traefik.docker.network": proxyNetwork, "traefik.http.routers.nvt-local-credentials.rule": "Host(`localhost`) && PathPrefix(`/agents/credentials`)", "traefik.http.routers.nvt-local-credentials.entrypoints": "web", "traefik.http.routers.nvt-local-credentials.priority": "200", "traefik.http.services.nvt-local-credentials.loadbalancer.server.port": "8080"}),
		}
		services["credential-portal"] = map[string]any{
			"image": options.CredentialImage, "environment": map[string]string{"NVT_CREDENTIAL_PORTAL_CONFIG": "/etc/nvt-local/credential-portal.json", "NVT_CREDENTIAL_PORTAL_PUBLIC_URL": fmt.Sprintf("http://localhost:%d/agents/credentials", options.ProxyPort), "NVT_CREDENTIAL_PORTAL_SESSION_SECRET_FILE": plancontract.PrivateTarget("credential-portal-session-key"), "NVT_CREDENTIAL_RUNNER_AUTH_KEY_FILE": plancontract.PrivateTarget("credential-runner-key"), "NVT_CREDENTIAL_RUNNER_URL": "http://127.0.0.1:8081"},
			"volumes": serviceMounts("credential-portal"), "network_mode": "service:credential-runner", "depends_on": map[string]any{"credential-runner": map[string]string{"condition": "service_started"}}, "read_only": true, "tmpfs": []string{"/tmp"}, "restart": "unless-stopped", "labels": labels,
		}
	}
	document := map[string]any{
		"name": project, "services": services, "volumes": volumes,
		"networks": map[string]any{
			"agents-proxy":        map[string]any{"name": proxyNetwork, "labels": mergeLabels(labels, map[string]string{"nvt.dev/local-platform-network": proxyNetwork})},
			"local-control-plane": map[string]any{"name": controlNetwork, "internal": true, "labels": mergeLabels(labels, map[string]string{"nvt.dev/local-platform-network": controlNetwork})},
			"producer-egress":     map[string]any{"name": egressNetwork, "labels": mergeLabels(labels, map[string]string{"nvt.dev/local-platform-network": egressNetwork})},
		},
	}
	producerYAML, err := producerrender.RenderCompose(ctx, compiled, statePlan, producerrender.Options{ControlNetwork: controlNetwork, EgressNetwork: egressNetwork, GitHubCommentsImage: options.ProducerImage, ImageInspector: options.ProducerInspector})
	if err != nil {
		return nil, err
	}
	var producerDocument map[string]any
	if err := yaml.Unmarshal(producerYAML, &producerDocument); err != nil {
		return nil, errors.New("producer compose merge failed")
	}
	if producerServices, ok := producerDocument["services"].(map[string]any); ok {
		for name, service := range producerServices {
			services[name] = service
		}
	}
	encoded, err := yaml.Marshal(document)
	if err != nil || len(encoded) > 1<<20 {
		return nil, errors.New("local compose rendering failed")
	}
	if strings.Contains(string(encoded), ".broker") {
		return nil, errors.New("legacy local state entered generated compose")
	}
	return encoded, nil
}

func cloneLabels(input map[string]string) map[string]string {
	result := map[string]string{}
	for key, value := range input {
		result[key] = value
	}
	return result
}
func mergeLabels(left, right map[string]string) map[string]string {
	result := cloneLabels(left)
	for key, value := range right {
		result[key] = value
	}
	return result
}
