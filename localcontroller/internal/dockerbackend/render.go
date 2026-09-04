package dockerbackend

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
	"gopkg.in/yaml.v3"
)

type composeDocument struct {
	Name     string                    `yaml:"name"`
	Services map[string]composeService `yaml:"services"`
	Volumes  map[string]externalObject `yaml:"volumes"`
	Networks map[string]externalObject `yaml:"networks"`
}

type externalObject struct {
	External bool   `yaml:"external"`
	Name     string `yaml:"name"`
}

type composeService struct {
	Image         string                       `yaml:"image"`
	ContainerName string                       `yaml:"container_name,omitempty"`
	User          string                       `yaml:"user,omitempty"`
	Entrypoint    []string                     `yaml:"entrypoint,omitempty"`
	Command       []string                     `yaml:"command,omitempty"`
	Environment   map[string]string            `yaml:"environment,omitempty"`
	WorkingDir    string                       `yaml:"working_dir,omitempty"`
	NetworkMode   string                       `yaml:"network_mode,omitempty"`
	Networks      []string                     `yaml:"networks,omitempty"`
	Volumes       []string                     `yaml:"volumes,omitempty"`
	DependsOn     map[string]composeDependency `yaml:"depends_on,omitempty"`
	Privileged    bool                         `yaml:"privileged,omitempty"`
	CapAdd        []string                     `yaml:"cap_add,omitempty"`
	Restart       string                       `yaml:"restart,omitempty"`
	Labels        map[string]string            `yaml:"labels"`
	Healthcheck   *composeHealthcheck          `yaml:"healthcheck,omitempty"`
	CPUs          string                       `yaml:"cpus,omitempty"`
	MemLimit      string                       `yaml:"mem_limit,omitempty"`
}

const transparentInitScript = `proof_file=/confinement/network-namespace
request_file=/confinement-request/request
boot_id="$$(cat /proc/sys/kernel/random/boot_id)"
netns="$$(readlink /proc/self/ns/net)"
case "$$boot_id" in ""|*[!0-9a-f-]*) echo "net-init: host boot identity unavailable" >&2; exit 1 ;; esac
case "$$netns" in net:\[*\]) ;; *) echo "net-init: network namespace identity unavailable" >&2; exit 1 ;; esac
namespace="$$boot_id:$$netns"
exclude_v4=""
exclude_v6=""
reject_managed_overlap() {
  case "$$1" in 172.30.*|172.31.*) echo "managed Docker pool overlaps protected address $$1" >&2; exit 1 ;; esac
}
/usr/local/bin/nvt-validate-managed-cidrs 172.30.0.0/15
for ip in $$(hostname -i); do reject_managed_overlap "$$ip"; done
for host in broker egressd; do
  for ip in $$(getent ahosts "$$host" | awk '{print $$1}' | sort -u); do
    reject_managed_overlap "$$ip"
    case "$$ip" in *:*) exclude_v6="$$exclude_v6 $$ip" ;; *) exclude_v4="$$exclude_v4 $$ip" ;; esac
  done
done
while true; do
request="$$(cat "$$request_file" 2>/dev/null || true)"
case "$$request" in ""|*[!0-9a-f-]*) request="" ;; esac
if [ "$${#request}" -eq 36 ] && [ "$$(cat "$$proof_file" 2>/dev/null || true)" != "$$namespace:$$request" ]; then
rm -f "$$proof_file"
iptables -t nat -I OUTPUT 1 -p tcp -j REDIRECT --to-ports 15001
iptables -t nat -I PREROUTING 1 -p tcp -j REDIRECT --to-ports 15001
ip6tables -t nat -I OUTPUT 1 -p tcp -j REDIRECT --to-ports 15001
ip6tables -t nat -I PREROUTING 1 -p tcp -j REDIRECT --to-ports 15001
while iptables -t nat -D OUTPUT -j NVT_CAPTURE 2>/dev/null; do :; done
while iptables -t nat -D PREROUTING -j NVT_DIND 2>/dev/null; do :; done
iptables -t nat -N NVT_CAPTURE 2>/dev/null || iptables -t nat -F NVT_CAPTURE
iptables -t nat -A NVT_CAPTURE -d 127.0.0.0/8 -j RETURN
for ip in $$exclude_v4; do iptables -t nat -A NVT_CAPTURE -d "$$ip/32" -j RETURN; done
iptables -t nat -A NVT_CAPTURE -m owner --uid-owner 65532 -j RETURN
iptables -t nat -A NVT_CAPTURE -o docker0 -j RETURN
iptables -t nat -A NVT_CAPTURE -o br-+ -j RETURN
iptables -t nat -A NVT_CAPTURE -p tcp -j REDIRECT --to-ports 15001
iptables -t nat -I OUTPUT 1 -j NVT_CAPTURE
iptables -t nat -N NVT_DIND 2>/dev/null || iptables -t nat -F NVT_DIND
iptables -t nat -A NVT_DIND -d 172.30.0.0/15 -j RETURN
for ip in $$exclude_v4; do iptables -t nat -A NVT_DIND -d "$$ip/32" -j RETURN; done
iptables -t nat -A NVT_DIND -i docker0 -p tcp -j REDIRECT --to-ports 15001
iptables -t nat -A NVT_DIND -i br-+ -p tcp -j REDIRECT --to-ports 15001
iptables -t nat -I PREROUTING 1 -j NVT_DIND
while ip6tables -t nat -D OUTPUT -j NVT_CAPTURE 2>/dev/null; do :; done
while ip6tables -t nat -D PREROUTING -j NVT_DIND 2>/dev/null; do :; done
ip6tables -t nat -N NVT_CAPTURE 2>/dev/null || ip6tables -t nat -F NVT_CAPTURE
ip6tables -t nat -A NVT_CAPTURE -d ::1/128 -j RETURN
for ip in $$exclude_v6; do ip6tables -t nat -A NVT_CAPTURE -d "$$ip/128" -j RETURN; done
ip6tables -t nat -A NVT_CAPTURE -m owner --uid-owner 65532 -j RETURN
ip6tables -t nat -A NVT_CAPTURE -o docker0 -j RETURN
ip6tables -t nat -A NVT_CAPTURE -o br-+ -j RETURN
ip6tables -t nat -A NVT_CAPTURE -p tcp -j REDIRECT --to-ports 15001
ip6tables -t nat -I OUTPUT 1 -j NVT_CAPTURE
ip6tables -t nat -N NVT_DIND 2>/dev/null || ip6tables -t nat -F NVT_DIND
for ip in $$exclude_v6; do ip6tables -t nat -A NVT_DIND -d "$$ip/128" -j RETURN; done
ip6tables -t nat -A NVT_DIND -i docker0 -p tcp -j REDIRECT --to-ports 15001
ip6tables -t nat -A NVT_DIND -i br-+ -p tcp -j REDIRECT --to-ports 15001
ip6tables -t nat -I PREROUTING 1 -j NVT_DIND
while iptables -t nat -D OUTPUT -p tcp -j REDIRECT --to-ports 15001 2>/dev/null; do :; done
while iptables -t nat -D PREROUTING -p tcp -j REDIRECT --to-ports 15001 2>/dev/null; do :; done
while ip6tables -t nat -D OUTPUT -p tcp -j REDIRECT --to-ports 15001 2>/dev/null; do :; done
while ip6tables -t nat -D PREROUTING -p tcp -j REDIRECT --to-ports 15001 2>/dev/null; do :; done
[ "$$(iptables -t nat -S OUTPUT 1)" = "-A OUTPUT -j NVT_CAPTURE" ]
iptables -t nat -C NVT_CAPTURE -p tcp -j REDIRECT --to-ports 15001
iptables -t nat -C NVT_DIND -i docker0 -p tcp -j REDIRECT --to-ports 15001
iptables -t nat -C NVT_DIND -i br-+ -p tcp -j REDIRECT --to-ports 15001
[ "$$(iptables -t nat -S PREROUTING 1)" = "-A PREROUTING -j NVT_DIND" ]
[ "$$(ip6tables -t nat -S OUTPUT 1)" = "-A OUTPUT -j NVT_CAPTURE" ]
ip6tables -t nat -C NVT_CAPTURE -p tcp -j REDIRECT --to-ports 15001
ip6tables -t nat -C NVT_DIND -i docker0 -p tcp -j REDIRECT --to-ports 15001
ip6tables -t nat -C NVT_DIND -i br-+ -p tcp -j REDIRECT --to-ports 15001
[ "$$(ip6tables -t nat -S PREROUTING 1)" = "-A PREROUTING -j NVT_DIND" ]
umask 077
printf '%s\n' "$$namespace:$$request" > "$$proof_file.tmp"
chmod 0444 "$$proof_file.tmp"
mv -f "$$proof_file.tmp" "$$proof_file"
fi
sleep 0.1
done
`

const agentConfinementGateScript = `proof_file=/run/nvt-confinement/network-namespace
request_file=/run/nvt-confinement-request/request
nonce="$$(cat /proc/sys/kernel/random/uuid 2>/dev/null || true)"
case "$$nonce" in ""|*[!0-9a-f-]*) echo "nvt-local-agent: confinement nonce unavailable" >&2; exit 1 ;; esac
[ "$${#nonce}" -eq 36 ] || { echo "nvt-local-agent: confinement nonce unavailable" >&2; exit 1; }
umask 077
rm -f "$$request_file" "$$request_file.tmp"
printf '%s\n' "$$nonce" > "$$request_file.tmp"
chmod 0600 "$$request_file.tmp"
mv -f "$$request_file.tmp" "$$request_file"
attempt=0
while [ "$$attempt" -lt 600 ]; do
  boot_id="$$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)"
  netns="$$(readlink /proc/self/ns/net 2>/dev/null || true)"
  namespace="$$boot_id:$$netns:$$nonce"
  proof="$$(cat "$$proof_file" 2>/dev/null || true)"
  case "$$boot_id" in ""|*[!0-9a-f-]*) valid_boot=false ;; *) valid_boot=true ;; esac
  case "$$netns" in net:\[*\]) valid_netns=true ;; *) valid_netns=false ;; esac
  if [ "$$valid_boot" = true ] && [ "$$valid_netns" = true ] && [ "$$proof" = "$$namespace" ]; then
    exec /usr/local/bin/entrypoint
  fi
  attempt=$$((attempt + 1))
  sleep 0.25
done
echo "nvt-local-agent: current network confinement was not established" >&2
exit 1
`

type composeDependency struct {
	Condition string `yaml:"condition"`
}

type composeHealthcheck struct {
	Test        []string `yaml:"test"`
	Interval    string   `yaml:"interval"`
	Timeout     string   `yaml:"timeout"`
	StartPeriod string   `yaml:"start_period,omitempty"`
	Retries     int      `yaml:"retries"`
}

type exposeRoute struct {
	Name       string `json:"name"`
	TargetPort int    `json:"targetPort"`
	Source     string `json:"source"`
}

type egressCANameSet struct {
	leafDNSNames     []string
	upstreamDNSNames []string
}

func egressCANameSetFor(run resolvedrun.ResolvedAgentRun) egressCANameSet {
	if run.Egress.Transport == "redirect" {
		return egressCANameSet{leafDNSNames: []string{"egressd"}, upstreamDNSNames: catalogLeafNames(run)}
	}
	return egressCANameSet{upstreamDNSNames: egressLeafNames(run)}
}

func (names egressCANameSet) digest() string {
	values := append([]string{"localhost"}, names.leafDNSNames...)
	values = append(values, names.upstreamDNSNames...)
	sort.Strings(values)
	encoded, _ := json.Marshal(values)
	digest := sha256.Sum256(encoded)
	return fmt.Sprintf("%x", digest[:])
}

func caInitCommand(run resolvedrun.ResolvedAgentRun) []string {
	names := egressCANameSetFor(run)
	command := []string{"--cert-file", "/public/ca.crt", "--key-file", "/private/ca.key"}
	for _, name := range names.leafDNSNames {
		command = append(command, "--leaf-dns-name", name)
	}
	for _, name := range names.upstreamDNSNames {
		command = append(command, "--upstream-leaf-name", name)
	}
	return command
}

func renderCompose(config Config, run resolvedrun.ResolvedAgentRun, digest string, names resourceNames) ([]byte, error) {
	config = withRouteDefaults(config)
	if run.Egress.Mode == "mediated" && run.Egress.Enforced && run.Egress.Transport != "transparent" {
		return nil, errors.New("enforced local transport unsupported")
	}
	routes, err := parseExposeRoutes(run.AgentConfig)
	if err != nil {
		return nil, errors.New("HTTP exposure configuration unavailable")
	}
	labels := map[string]string{ownerLabel: config.Owner, runLabel: run.RunID, digestLabel: digest}
	volumes := map[string]externalObject{
		"agent-config": {External: true, Name: names.agentConfig},
		"workspace":    {External: true, Name: names.workspace},
		"agent-home":   {External: true, Name: names.home},
	}
	networks := map[string]externalObject{
		"default":        {External: true, Name: names.internalNet},
		"agents-proxy":   {External: true, Name: config.ExternalNetwork},
		"run-internal":   {External: true, Name: names.internalNet},
		"egress-private": {External: true, Name: names.privateNet},
	}
	services := map[string]composeService{}
	namespaceService := "network"
	namespaceCondition := "service_started"
	if run.Runtime.Docker != nil {
		namespaceService = "docker"
		namespaceCondition = "service_healthy"
		volumes["docker-data"] = externalObject{External: true, Name: names.dockerData}
		dockerEnvironment := map[string]string{
			"DOCKER_TLS_CERTDIR": "", "NVT_DIND_TRANSPARENT": strconv.FormatBool(run.Egress.Transport == "transparent"),
			"NVT_DIND_PERSISTENT_STORAGE": strconv.FormatBool(run.Persistence.DockerData),
			"NVT_DIND_PROTECTED_CIDRS":    config.ProtectedCIDRs,
		}
		if run.Runtime.Docker.KernelLogDevice {
			dockerEnvironment["NVT_DIND_KERNEL_LOG_DEVICE"] = "true"
		}
		services["docker"] = composeService{
			Image: config.DindImage, ContainerName: names.namespace, Privileged: true, Restart: "unless-stopped", Labels: labels,
			Environment: dockerEnvironment,
			Command:     []string{"--host=unix:///var/run/docker.sock", "--host=tcp://127.0.0.1:2375", "--tls=false"},
			Volumes:     []string{"workspace:/workspace", "docker-data:/var/lib/nvt-dind"},
			Networks:    []string{"run-internal", "egress-private"},
			Healthcheck: &composeHealthcheck{Test: []string{"CMD-SHELL", "docker info >/dev/null 2>&1"}, Interval: "2s", Timeout: "2s", Retries: 30},
		}
	} else {
		services["network"] = composeService{
			Image: config.SeedImage, ContainerName: names.namespace, Entrypoint: []string{"sh", "-ec"}, Command: []string{"trap 'exit 0' TERM INT; while sleep 3600; do :; done"},
			Networks: []string{"run-internal", "egress-private"}, Restart: "unless-stopped", Labels: labels,
		}
	}
	agentEnvironment := map[string]string{
		"NVT_WORKSPACE": "/workspace", "NVT_AGENT_CONFIG_FILE": "/nvt-config/agent.json",
		"AGENT_HOST": run.RunID + "." + config.RouteBaseDomain, "NVT_PROXY_PORT": strconv.Itoa(config.ProxyPort),
	}
	if run.Runtime.Docker != nil {
		agentEnvironment["DOCKER_HOST"] = "tcp://127.0.0.1:2375"
	}
	user := "0:0"
	home := "/root"
	if run.Runtime.User == "non-root" {
		user, home = "1000:1000", "/home/agent"
	}
	agentEnvironment["HOME"] = home
	agentEnvironment["NVT_STATE_DIR"] = home + "/.nvt-agent"
	if len(routes) != 0 {
		routesJSON, _ := json.Marshal(routes)
		agentEnvironment["NVT_EXPOSED_HTTP_ROUTES_JSON"] = string(routesJSON)
	}
	if run.WorkspaceInstructions.Profile != "" {
		agentEnvironment["NVT_AGENT_PROFILE_INSTRUCTIONS_FILE"] = "/nvt-config/profile-instructions.md"
	}
	if run.WorkspaceInstructions.Workflow != "" {
		agentEnvironment["NVT_AGENT_WORKFLOW_INSTRUCTIONS_FILE"] = "/nvt-config/workflow-instructions.md"
	}
	if run.Runtime.Docker != nil && len(run.Runtime.Docker.RequiredNetworks) != 0 {
		encoded, _ := json.Marshal(run.Runtime.Docker.RequiredNetworks)
		agentEnvironment["NVT_DOCKER_REQUIRED_NETWORKS"] = string(encoded)
	}
	for _, grant := range run.Broker.Grants {
		if containsPreparation(grant.Preparations, "identity") {
			agentEnvironment["NVT_PREPARED_PROVIDER_METADATA_FILE"] = "/nvt-config/prepared-provider-metadata.json"
			break
		}
	}
	agentDepends := map[string]composeDependency{namespaceService: {Condition: namespaceCondition}}
	if run.Runtime.User == "non-root" {
		services["workspace-init"] = composeService{
			Image: config.SeedImage, User: "0:0", NetworkMode: "none", Entrypoint: []string{"sh", "-ec"}, Command: []string{"chown 1000:1000 /workspace"},
			Volumes: []string{"workspace:/workspace"}, Labels: labels,
		}
		agentDepends["workspace-init"] = composeDependency{Condition: "service_completed_successfully"}
	}
	if run.Egress.Mode == "mediated" {
		agentEnvironment["NVT_EGRESS_MODE"] = "mediated"
		agentEnvironment["NVT_EGRESS_CA_FILE"] = "/nvt-egress-ca/ca.crt"
		agentDepends["egressd"] = composeDependency{Condition: "service_started"}
		volumes["egress-private"] = externalObject{External: true, Name: names.egressPrivate}
		volumes["egress-public"] = externalObject{External: true, Name: names.egressPublic}
	}
	if requiresConfinementProof(run) {
		volumes["confinement"] = externalObject{External: true, Name: names.confinement}
		volumes["confinement-request"] = externalObject{External: true, Name: names.confinementRequest}
	}
	agentLabels := make(map[string]string, len(labels)+1)
	for key, value := range labels {
		agentLabels[key] = value
	}
	if requiresConfinementProof(run) {
		agentLabels[agentConfinementRevisionLabel] = agentConfinementRevision
	}
	services["agent"] = composeService{
		Image: run.Image, User: user, WorkingDir: "/workspace", NetworkMode: "service:" + namespaceService, Restart: "unless-stopped", Labels: agentLabels,
		Environment: agentEnvironment, DependsOn: agentDepends, CapAdd: append([]string(nil), runtimeCapabilities(run)...),
		Volumes:     []string{"workspace:/workspace", "agent-home:" + home, "agent-config:/nvt-config:ro"},
		Healthcheck: &composeHealthcheck{Test: []string{"CMD-SHELL", "health"}, Interval: "10s", Timeout: "2s", StartPeriod: "15m", Retries: 3},
		CPUs:        dockerCPU(run.Resources.CPULimit), MemLimit: dockerMemory(run.Resources.MemoryLimit),
	}
	if requiresConfinementProof(run) {
		agent := services["agent"]
		agent.Entrypoint = []string{"sh", "-ec"}
		agent.Command = []string{agentConfinementGateScript}
		agent.Volumes = append(agent.Volumes, "confinement:/run/nvt-confinement:ro", "confinement-request:/run/nvt-confinement-request")
		services["agent"] = agent
	}
	if run.Egress.Mode == "mediated" {
		caLabels := make(map[string]string, len(labels)+1)
		for key, value := range labels {
			caLabels[key] = value
		}
		caLabels[egressCANameSetDigestLabel] = egressCANameSetFor(run).digest()
		agent := services["agent"]
		agent.Volumes = append(agent.Volumes, "egress-public:/nvt-egress-ca:ro")
		services["agent"] = agent
		services["egressd"] = composeService{
			Image: config.EgressdImage, User: "0:0", Restart: "unless-stopped", Labels: caLabels,
			Environment: map[string]string{"NVT_EGRESSD_CONFIG": "/private/egressd.json", "NVT_BROKER_TOKEN_FILE": "/private/broker-token"},
			Volumes:     []string{"egress-private:/private:ro", "egress-public:/public:ro"},
			Networks:    []string{"agents-proxy", "run-internal", "egress-private"},
			DependsOn:   map[string]composeDependency{"ca-init": {Condition: "service_completed_successfully"}},
		}
		services["ca-init"] = composeService{
			Image: config.EgressdImage, User: "0:0", NetworkMode: "none", Entrypoint: []string{"/usr/local/bin/egress-ca-init"}, Command: caInitCommand(run),
			Volumes: []string{"egress-private:/private", "egress-public:/public"}, Labels: caLabels,
		}
		if run.Egress.Transport == "forward-proxy" || run.Egress.Transport == "transparent" || hasCatalogGrant(run) {
			services["captured"] = composeService{
				Image: config.CapturedImage, User: "65532:65532", NetworkMode: "service:" + namespaceService, Restart: "unless-stopped", Labels: labels,
				Environment: map[string]string{
					"NVT_CAPTURED_EXPLICIT_LISTEN": "[::]:15002", "NVT_CAPTURED_TRANSPARENT_LISTEN": "[::]:15001", "NVT_EGRESS_PROXY": "egressd:8470",
				}, DependsOn: map[string]composeDependency{"egressd": {Condition: "service_started"}},
			}
		}
		if run.Egress.Transport == "transparent" {
			requestOwner := "0:0"
			if run.Runtime.User == "non-root" {
				requestOwner = "1000:1000"
			}
			services["confinement-init"] = composeService{
				Image: config.SeedImage, User: "0:0", NetworkMode: "none", Entrypoint: []string{"sh", "-ec"},
				Command: []string{"chown " + requestOwner + " /request && chmod 0700 /request"}, Volumes: []string{"confinement-request:/request"}, Labels: labels,
			}
			services["net-init"] = composeService{
				Image: config.DindImage, User: "0:0", NetworkMode: "service:" + namespaceService, Entrypoint: []string{"sh", "-ec"},
				Command: []string{transparentInitScript}, CapAdd: []string{"NET_ADMIN"}, Restart: "unless-stopped", Labels: labels,
				Volumes:     []string{"confinement:/confinement", "confinement-request:/confinement-request:ro"},
				Environment: map[string]string{"NVT_DIND_PROTECTED_CIDRS": config.ProtectedCIDRs},
				DependsOn: map[string]composeDependency{
					namespaceService: {Condition: namespaceCondition}, "captured": {Condition: "service_started"}, "confinement-init": {Condition: "service_completed_successfully"},
				},
			}
			agent := services["agent"]
			agent.DependsOn["net-init"] = composeDependency{Condition: "service_started"}
			services["agent"] = agent
		}
	}
	document := composeDocument{Name: names.project, Services: services, Volumes: volumes, Networks: networks}
	encoded, err := yaml.Marshal(document)
	if err != nil || len(encoded) > 512<<10 {
		return nil, errors.New("compose plan unavailable")
	}
	return encoded, nil
}

func parseExposeRoutes(raw json.RawMessage) ([]exposeRoute, error) {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		return nil, err
	}
	exposeValue, exists := root["expose"]
	if !exists {
		return nil, nil
	}
	expose, ok := exposeValue.(map[string]any)
	if !ok {
		return nil, errors.New("expose must be an object")
	}
	httpValue, exists := expose["http"]
	if !exists {
		return nil, nil
	}
	items, ok := httpValue.([]any)
	if !ok || len(items) > 64 {
		return nil, errors.New("expose.http must be a bounded array")
	}
	result := make([]exposeRoute, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("expose route must be an object")
		}
		name, _ := object["name"].(string)
		source, _ := object["source"].(string)
		if source == "" {
			source = "agent"
		}
		portNumber, ok := object["targetPort"].(json.Number)
		port64, portErr := portNumber.Int64()
		if !validDNSLabel(name) || seen[name] || source != "agent" || !ok || portErr != nil || port64 < 1 || port64 > 65535 {
			return nil, errors.New("expose route is invalid")
		}
		seen[name] = true
		result = append(result, exposeRoute{Name: name, TargetPort: int(port64), Source: source})
	}
	return result, nil
}

func validDNSLabel(value string) bool {
	if len(value) == 0 || len(value) > 63 || !lowerAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	last := value[len(value)-1]
	return last != '-'
}

func lowerAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func renderEgressdConfig(config Config, run resolvedrun.ResolvedAgentRun, routeSets ...[]catalogRoute) ([]byte, error) {
	var catalogRoutes []catalogRoute
	if len(routeSets) > 0 {
		catalogRoutes = routeSets[0]
	}
	root := map[string]any{
		"broker_url": config.BrokerURL, "allow_insecure_broker": run.Egress.AllowInsecureBroker, "routes": []any{},
		"ca": map[string]any{"cert_file": "/public/ca.crt", "key_file": "/private/ca.key"},
	}
	if run.Egress.Transport == "redirect" {
		root["ca"].(map[string]any)["leaf_dns_names"] = []string{"egressd"}
		routes := []any{}
		port := 8471
		for _, grant := range run.Broker.Grants {
			if grant.Materialization != "header-inject" || containsPreparation(grant.Preparations, "catalog") {
				continue
			}
			route := map[string]any{
				"listen": fmt.Sprintf("0.0.0.0:%d", port), "capability": grant.Provider, "upstream": grant.EgressHosts[0],
				"allow_insecure_upstream": grant.AllowInsecureUpstream, "listen_tls": "ca",
			}
			if grant.Quota != nil {
				route["max_requests"] = grant.Quota.Requests
			}
			routes = append(routes, route)
			port++
		}
		root["routes"] = routes
	}
	// Catalog-backed Kubernetes clients carry an explicit per-cluster proxy
	// URL, so they use the forward proxy even when other mediated capabilities
	// use legacy redirect listeners.
	if run.Egress.Transport != "redirect" || len(catalogRoutes) != 0 {
		injects := []any{}
		seen := map[string]bool{}
		catalogByProvider := map[string][]catalogRoute{}
		for _, route := range catalogRoutes {
			for _, grant := range run.Broker.Grants {
				if containsPreparation(grant.Preparations, "catalog") {
					for _, allowed := range grant.EgressHosts {
						if strings.TrimSuffix(allowed, ":443") == route.Host {
							catalogByProvider[grant.Provider] = append(catalogByProvider[grant.Provider], route)
						}
					}
				}
			}
		}
		for _, grant := range run.Broker.Grants {
			if containsPreparation(grant.Preparations, "catalog") {
				for _, catalog := range catalogByProvider[grant.Provider] {
					route := map[string]any{
						"host": catalog.Host, "capability": grant.Provider, "upstream": catalog.Upstream,
						"upstream_ca_pem": catalog.CAPEM, "upstream_server_name": catalog.ServerName,
						"allow_private_upstream": catalog.AllowPrivateUpstream,
					}
					if grant.Quota != nil {
						route["max_requests"] = grant.Quota.Requests
					}
					injects = append(injects, route)
				}
				continue
			}
			if run.Egress.Transport == "redirect" {
				continue
			}
			for _, upstream := range grant.EgressHosts {
				host := strings.ToLower(strings.Split(upstream, ":")[0])
				key := host + "\x00" + grant.Provider
				if seen[key] {
					continue
				}
				seen[key] = true
				route := map[string]any{"host": host, "capability": grant.Provider, "upstream": upstream, "allow_insecure_upstream": grant.AllowInsecureUpstream}
				if grant.Git {
					route["require_capability_hint"] = true
				}
				if grant.Quota != nil {
					route["max_requests"] = grant.Quota.Requests
				}
				injects = append(injects, route)
			}
		}
		forwardProxy := map[string]any{
			"listen": "0.0.0.0:8470", "transparent_mode": run.Egress.Transport == "transparent",
			"allow_unmatched_hosts": run.Egress.Transport != "redirect" && run.Egress.DomainPolicy == nil,
			"allow_ports":           []int{80, 443}, "max_concurrent_tunnels": run.Egress.MaxConcurrentTunnels, "inject_routes": injects,
		}
		if policy := run.Egress.DomainPolicy; policy != nil {
			forwardProxy["domain_policy"] = map[string]any{
				"default_action": policy.DefaultAction,
				"allow":          append([]string(nil), policy.Allow...),
				"deny":           append([]string(nil), policy.Deny...),
			}
		}
		root["forward_proxy"] = forwardProxy
	}
	return json.MarshalIndent(root, "", "  ")
}

func renderBindings(run resolvedrun.ResolvedAgentRun) resolvedrun.AgentConfigBindings {
	if run.Egress.Mode != "mediated" {
		return resolvedrun.AgentConfigBindings{}
	}
	if run.Egress.Transport != "redirect" {
		return resolvedrun.AgentConfigBindings{ForwardProxyURL: "http://127.0.0.1:15002"}
	}
	bindings := resolvedrun.AgentConfigBindings{RedirectBaseURLs: map[string]string{}}
	port := 8471
	for _, grant := range run.Broker.Grants {
		if grant.Materialization == "header-inject" && !containsPreparation(grant.Preparations, "catalog") {
			bindings.RedirectBaseURLs[grant.Provider] = fmt.Sprintf("https://egressd:%d", port)
			port++
		}
	}
	return bindings
}

func runtimeCapabilities(run resolvedrun.ResolvedAgentRun) []string {
	if run.Runtime.Container == nil {
		return nil
	}
	return run.Runtime.Container.Capabilities
}

func egressLeafNames(run resolvedrun.ResolvedAgentRun) []string {
	values := []string{}
	seen := map[string]bool{}
	for _, grant := range run.Broker.Grants {
		for _, upstream := range grant.EgressHosts {
			host := strings.ToLower(strings.Split(upstream, ":")[0])
			if !seen[host] {
				seen[host] = true
				values = append(values, host)
			}
		}
	}
	sort.Strings(values)
	return values
}

func catalogLeafNames(run resolvedrun.ResolvedAgentRun) []string {
	values := []string{}
	seen := map[string]bool{}
	for _, grant := range run.Broker.Grants {
		if !containsPreparation(grant.Preparations, "catalog") {
			continue
		}
		for _, upstream := range grant.EgressHosts {
			host := strings.ToLower(strings.TrimSuffix(upstream, ":443"))
			if !seen[host] {
				seen[host] = true
				values = append(values, host)
			}
		}
	}
	sort.Strings(values)
	return values
}

func hasCatalogGrant(run resolvedrun.ResolvedAgentRun) bool {
	for _, grant := range run.Broker.Grants {
		if containsPreparation(grant.Preparations, "catalog") {
			return true
		}
	}
	return false
}

func dockerCPU(value string) string {
	if strings.HasSuffix(value, "m") {
		milli, err := strconv.Atoi(strings.TrimSuffix(value, "m"))
		if err == nil {
			return strconv.FormatFloat(float64(milli)/1000, 'f', 3, 64)
		}
	}
	return value
}

func dockerMemory(value string) string {
	replacer := strings.NewReplacer("Ki", "k", "Mi", "m", "Gi", "g", "Ti", "t")
	return replacer.Replace(value)
}

func namesFor(config Config, runID, digest string) resourceNames {
	project := "nvt-local-" + shortDigest(runID)
	return resourceNames{
		project: project, composeFile: filepath.Join(config.RunsDir, runID, "compose.yaml"),
		agentConfig: project + "-agent-config", egressPrivate: project + "-egress-private", egressPublic: project + "-egress-public",
		workspace: project + "-workspace", home: project + "-home", dockerData: project + "-docker-data", confinement: project + "-confinement",
		confinementRequest: project + "-confinement-request",
		internalNet:        project + "-internal", privateNet: project + "-private", namespace: project + "-namespace",
	}
}

func requiresConfinementProof(run resolvedrun.ResolvedAgentRun) bool {
	return run.Egress.Mode == "mediated" && run.Egress.Enforced && run.Egress.Transport == "transparent"
}

func shortDigest(value string) string {
	// Run IDs are already bounded and validated, but a hash keeps every Docker
	// resource comfortably below engine name limits and avoids prefix overlap.
	digest := fmt.Sprintf("%x", sha256Bytes([]byte(value)))
	return digest[:24]
}

func sha256Bytes(value []byte) [32]byte { return sha256.Sum256(value) }
