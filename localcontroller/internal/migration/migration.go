// Package migration translates existing static local-agent configuration into
// the trusted local scheduling document. It copies provider references and
// grants, never broker provider configuration or credential material.
package migration

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
	"gopkg.in/yaml.v3"
)

const ManifestVersion = "nvt.local-agent-migration/v1"

var ErrInvalidInput = errors.New("invalid local-agent migration input")

type Manifest struct {
	APIVersion      string          `yaml:"api_version"`
	Image           string          `yaml:"image"`
	PrincipalIssuer string          `yaml:"principal_issuer"`
	Backend         string          `yaml:"backend"`
	Retention       string          `yaml:"retention"`
	Agents          []ManifestAgent `yaml:"agents"`
}

type ManifestAgent struct {
	Name               string            `yaml:"name"`
	Subject            string            `yaml:"subject"`
	DisplayName        string            `yaml:"display_name,omitempty"`
	Profile            string            `yaml:"profile,omitempty"`
	Workflow           string            `yaml:"workflow,omitempty"`
	RuntimeType        string            `yaml:"runtime_type"`
	Autonomy           string            `yaml:"autonomy"`
	User               string            `yaml:"user"`
	ContainerCaps      []string          `yaml:"container_capabilities,omitempty"`
	Docker             *manifestDocker   `yaml:"docker,omitempty"`
	BrokerRepositories map[string]string `yaml:"broker_repositories,omitempty"`
}

type manifestDocker struct {
	KernelLogDevice  bool                        `yaml:"kernel_log_device,omitempty"`
	RequiredNetworks []resolvedrun.DockerNetwork `yaml:"required_networks,omitempty"`
}

type Options struct {
	ManifestPath string
	AgentsRoot   string
	BrokerAgents string
	BrokerConfig string
}

type outputDocument struct {
	APIVersion        string                           `json:"api_version"`
	ResolvedRunConfig resolvedrun.TrustedConfiguration `json:"resolved_run_config"`
	LocalRuns         []outputLocalRun                 `json:"local_runs"`
}

type outputLocalRun struct {
	RunID     string                `json:"run_id"`
	Principal resolvedrun.Principal `json:"principal"`
	Profile   string                `json:"profile"`
	Workflow  string                `json:"workflow"`
	Retention string                `json:"retention"`
	Backend   string                `json:"backend"`
}

type brokerAgentDocument struct {
	Agents []brokerAgent `yaml:"agents"`
}
type brokerAgent struct {
	ID          string        `yaml:"id"`
	Role        string        `yaml:"role,omitempty"`
	TokenSHA256 string        `yaml:"token-sha256"`
	PairedAgent string        `yaml:"paired-agent,omitempty"`
	Grants      []brokerGrant `yaml:"grants"`
}
type brokerGrant struct {
	Provider              string                        `yaml:"provider"`
	Repositories          []string                      `yaml:"repositories"`
	Capabilities          []string                      `yaml:"capabilities"`
	Preparations          []string                      `yaml:"preparations"`
	Materialization       string                        `yaml:"materialization"`
	EgressHosts           []string                      `yaml:"egress-hosts"`
	Git                   bool                          `yaml:"git"`
	Permissions           map[string]string             `yaml:"permissions"`
	Quota                 *resolvedrun.BrokerGrantQuota `yaml:"quota"`
	AllowInsecureUpstream bool                          `yaml:"allow-insecure-upstream"`
}

type hostConfig struct {
	DefaultProvider string         `json:"default-provider,omitempty"`
	Providers       []hostProvider `json:"providers"`
}
type hostProvider struct {
	Name           string   `json:"name"`
	Type           string   `json:"type"`
	BrokerProvider string   `json:"broker-provider"`
	CredentialKind string   `json:"credential-kind,omitempty"`
	Match          []string `json:"match,omitempty"`
}
type credentialConfig struct {
	Credentials []credentialRule `json:"credentials"`
}
type credentialRule struct {
	Match    string                          `json:"match"`
	Provider string                          `json:"provider"`
	Identity *resolvedrun.RepositoryIdentity `json:"identity,omitempty"`
}
type checkoutConfig struct {
	Repos []checkout `json:"repos"`
}
type checkout struct {
	URL      string `json:"url"`
	Path     string `json:"path,omitempty"`
	Upstream string `json:"upstream,omitempty"`
}

func Generate(options Options) ([]byte, error) {
	if !absoluteClean(options.ManifestPath) || !absoluteClean(options.AgentsRoot) ||
		!absoluteClean(options.BrokerAgents) || !absoluteClean(options.BrokerConfig) {
		return nil, ErrInvalidInput
	}
	var manifest Manifest
	if err := decodeStrictYAMLFile(options.ManifestPath, 256<<10, &manifest); err != nil ||
		manifest.APIVersion != ManifestVersion || len(manifest.Agents) == 0 || len(manifest.Agents) > resolvedrun.MaxProfiles {
		return nil, ErrInvalidInput
	}
	var agents brokerAgentDocument
	if err := decodeStrictYAMLFile(options.BrokerAgents, 1<<20, &agents); err != nil {
		return nil, ErrInvalidInput
	}
	providerNames, err := loadProviderNames(options.BrokerConfig)
	if err != nil {
		return nil, ErrInvalidInput
	}
	sort.Slice(manifest.Agents, func(i, j int) bool { return manifest.Agents[i].Name < manifest.Agents[j].Name })
	document := outputDocument{APIVersion: "nvt.local-scheduling/v1"}
	document.ResolvedRunConfig.Defaults = resolvedrun.PlatformDefaults{
		Image:       manifest.Image,
		Runtime:     resolvedrun.Runtime{Type: "local-agent", Autonomy: "interactive", User: "root"},
		AgentConfig: json.RawMessage(`{"runtime":{"command":"true"},"plugins":[]}`),
	}
	document.ResolvedRunConfig.ExecutionBackends = []resolvedrun.ExecutionBackend{{Name: manifest.Backend, Kind: "docker"}}
	document.ResolvedRunConfig.RetentionPolicies = []resolvedrun.RetentionPolicy{{
		Name:        manifest.Retention,
		Persistence: resolvedrun.Persistence{Workspace: true, RuntimeState: true, DockerData: true},
	}}
	seenNames := map[string]struct{}{}
	for _, configured := range manifest.Agents {
		if _, duplicate := seenNames[configured.Name]; duplicate {
			return nil, ErrInvalidInput
		}
		seenNames[configured.Name] = struct{}{}
		profile, workflow, localRun, convertErr := convertAgent(manifest, configured, options.AgentsRoot, agents.Agents, providerNames)
		if convertErr != nil {
			return nil, ErrInvalidInput
		}
		if !appendProfile(&document.ResolvedRunConfig.Profiles, profile) || !appendWorkflow(&document.ResolvedRunConfig.Workflows, workflow) {
			return nil, ErrInvalidInput
		}
		document.LocalRuns = append(document.LocalRuns, localRun)
	}
	if _, err := resolvedrun.NewResolver(document.ResolvedRunConfig); err != nil {
		return nil, ErrInvalidInput
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil || len(encoded)+1 > resolvedrun.MaxDocumentBytes {
		return nil, ErrInvalidInput
	}
	return append(encoded, '\n'), nil
}

func appendProfile(values *[]resolvedrun.Profile, candidate resolvedrun.Profile) bool {
	for _, value := range *values {
		if value.Name == candidate.Name {
			return reflect.DeepEqual(value, candidate)
		}
	}
	*values = append(*values, candidate)
	return true
}

func appendWorkflow(values *[]resolvedrun.Workflow, candidate resolvedrun.Workflow) bool {
	for _, value := range *values {
		if value.Name == candidate.Name {
			return reflect.DeepEqual(value, candidate)
		}
	}
	*values = append(*values, candidate)
	return true
}

func convertAgent(manifest Manifest, configured ManifestAgent, root string, brokerAgents []brokerAgent, providers map[string]struct{}) (resolvedrun.Profile, resolvedrun.Workflow, outputLocalRun, error) {
	profileName, workflowName := configured.Profile, configured.Workflow
	if profileName == "" {
		profileName = configured.Name
	}
	if workflowName == "" {
		workflowName = configured.Name
	}
	if configured.Subject == "" || configured.RuntimeType == "" || configured.Autonomy == "" || configured.User == "" {
		return resolvedrun.Profile{}, resolvedrun.Workflow{}, outputLocalRun{}, ErrInvalidInput
	}
	staticAgent, ok := exactBrokerAgent(brokerAgents, configured.Name)
	if !ok {
		return resolvedrun.Profile{}, resolvedrun.Workflow{}, outputLocalRun{}, ErrInvalidInput
	}
	for _, grant := range staticAgent.Grants {
		if _, exists := providers[grant.Provider]; !exists {
			return resolvedrun.Profile{}, resolvedrun.Workflow{}, outputLocalRun{}, ErrInvalidInput
		}
	}
	agentPath := filepath.Join(root, configured.Name, "agent.yaml")
	base, mappings, defaultProvider, repositories, egress, err := convertAgentConfig(agentPath, staticAgent.Grants, configured.BrokerRepositories)
	if err != nil {
		return resolvedrun.Profile{}, resolvedrun.Workflow{}, outputLocalRun{}, err
	}
	grants := make([]resolvedrun.BrokerGrant, 0, len(staticAgent.Grants))
	for _, grant := range staticAgent.Grants {
		materialization := grant.Materialization
		if materialization == "" {
			materialization = "file-bundle"
		}
		grants = append(grants, resolvedrun.BrokerGrant{
			Provider: grant.Provider, Repositories: grant.Repositories, Capabilities: grant.Capabilities,
			Preparations: grant.Preparations, Materialization: materialization, EgressHosts: grant.EgressHosts,
			Git: grant.Git, Permissions: grant.Permissions, Quota: grant.Quota, AllowInsecureUpstream: grant.AllowInsecureUpstream,
		})
	}
	runtime := resolvedrun.Runtime{Type: configured.RuntimeType, Autonomy: configured.Autonomy, User: configured.User}
	if len(configured.ContainerCaps) != 0 {
		runtime.Container = &resolvedrun.RuntimeContainer{Capabilities: configured.ContainerCaps}
	}
	if configured.Docker != nil {
		runtime.Docker = &resolvedrun.RuntimeDocker{KernelLogDevice: configured.Docker.KernelLogDevice, RequiredNetworks: configured.Docker.RequiredNetworks}
	}
	profile := resolvedrun.Profile{
		Name: profileName, Image: manifest.Image, Runtime: &runtime, AgentConfig: base,
		CredentialProviders: mappings, DefaultCredentialProvider: defaultProvider, Broker: resolvedrun.Broker{Grants: grants}, Egress: egress,
		AllowedBackends: []string{manifest.Backend}, DefaultBackend: manifest.Backend,
		AllowedRetentions: []string{manifest.Retention},
	}
	workflow := resolvedrun.Workflow{Name: workflowName, Repositories: repositories}
	localRun := outputLocalRun{RunID: configured.Name, Principal: resolvedrun.Principal{
		Issuer: manifest.PrincipalIssuer, Subject: configured.Subject, DisplayName: configured.DisplayName,
	}, Profile: profileName, Workflow: workflowName, Retention: manifest.Retention, Backend: manifest.Backend}
	return profile, workflow, localRun, nil
}

func convertAgentConfig(path string, grants []brokerGrant, overrides map[string]string) (json.RawMessage, []resolvedrun.CredentialProviderMapping, string, []resolvedrun.Repository, resolvedrun.Egress, error) {
	root, err := loadYAMLObject(path, resolvedrun.MaxAgentConfigBytes)
	if err != nil {
		return nil, nil, "", nil, resolvedrun.Egress{}, err
	}
	runtime, ok := root["runtime"].(map[string]any)
	if !ok {
		return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
	}
	proxyProvider := ""
	if rawProxy, present := runtime["proxy"]; present {
		proxy, ok := rawProxy.(map[string]any)
		if !ok || len(proxy) != 1 {
			return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
		}
		proxyProvider, ok = proxy["provider"].(string)
		if !ok || proxyProvider == "" {
			return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
		}
		delete(runtime, "proxy")
	}
	egress := resolvedrun.Egress{Mode: "direct"}
	if rawEgress, present := root["egress"]; present {
		egressMap, ok := rawEgress.(map[string]any)
		if !ok || !validManagedEgressSource(egressMap) {
			return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
		}
		mode, _ := egressMap["mode"].(string)
		transport, _ := egressMap["transport"].(string)
		if mode != "mediated" || transport != "transparent" || proxyProvider == "" {
			return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
		}
		egress = resolvedrun.Egress{Mode: "mediated", Transport: "transparent", Enforced: true, ProxyProvider: proxyProvider, PairedEgressRequired: true}
		delete(root, "egress")
	} else if proxyProvider != "" {
		return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
	}

	plugins, ok := root["plugins"].([]any)
	if !ok {
		return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
	}
	var hosts hostConfig
	var credentials credentialConfig
	var checkouts checkoutConfig
	seenManaged := map[string]bool{}
	retained := make([]any, 0, len(plugins))
	for _, raw := range plugins {
		plugin, ok := raw.(map[string]any)
		if !ok {
			return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
		}
		name, _ := plugin["name"].(string)
		if name != "git-host-credentials" && name != "git-credentials" && name != "checkout-repos" {
			retained = append(retained, raw)
			continue
		}
		if seenManaged[name] {
			return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
		}
		seenManaged[name] = true
		config, ok := plugin["config"].(map[string]any)
		if !ok {
			return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
		}
		switch name {
		case "git-host-credentials":
			err = decodeStrictJSONValue(config, &hosts)
		case "git-credentials":
			err = decodeStrictJSONValue(config, &credentials)
		case "checkout-repos":
			err = decodeStrictJSONValue(config, &checkouts)
		}
		if err != nil {
			return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
		}
	}
	root["plugins"] = retained
	mappings := make([]resolvedrun.CredentialProviderMapping, 0, len(hosts.Providers))
	grantByProvider := map[string]brokerGrant{}
	for _, grant := range grants {
		if _, duplicate := grantByProvider[grant.Provider]; duplicate {
			return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
		}
		grantByProvider[grant.Provider] = grant
	}
	for _, provider := range hosts.Providers {
		if provider.Type != "broker" {
			return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
		}
		grant, exists := grantByProvider[provider.BrokerProvider]
		if !exists {
			return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
		}
		kind := provider.CredentialKind
		if egress.Mode == "mediated" && grant.Git {
			if kind != "" && kind != "mediated" {
				return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
			}
			kind = "mediated"
		}
		mappings = append(mappings, resolvedrun.CredentialProviderMapping{Name: provider.Name, BrokerProvider: provider.BrokerProvider, CredentialKind: kind, MatchTargets: provider.Match})
	}
	rules := map[string]credentialRule{}
	for _, rule := range credentials.Credentials {
		if _, duplicate := rules[rule.Match]; duplicate {
			return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
		}
		rules[rule.Match] = rule
	}
	repositories := make([]resolvedrun.Repository, 0, len(checkouts.Repos))
	usedOverrides := map[string]struct{}{}
	for _, item := range checkouts.Repos {
		target := repositoryTarget(item.URL)
		if target == "" {
			return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
		}
		repository := resolvedrun.Repository{CheckoutTarget: target, URL: item.URL, Path: item.Path, Upstream: item.Upstream}
		if rule, exists := rules[item.URL]; exists {
			repository.CredentialProvider, repository.Identity = rule.Provider, rule.Identity
			mapping, found := findMapping(mappings, rule.Provider)
			if !found {
				return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
			}
			grant := grantByProvider[mapping.BrokerProvider]
			repository.BrokerRepository = overrides[target]
			if repository.BrokerRepository != "" {
				usedOverrides[target] = struct{}{}
			}
			if repository.BrokerRepository == "" {
				if len(grant.Repositories) != 1 {
					return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
				}
				repository.BrokerRepository = grant.Repositories[0]
			}
		}
		repositories = append(repositories, repository)
	}
	if len(usedOverrides) != len(overrides) {
		return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
	}
	for match := range rules {
		found := false
		for _, item := range checkouts.Repos {
			if item.URL == match {
				found = true
			}
		}
		if !found {
			return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
		}
	}
	if containsSensitiveConfig(root) {
		return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
	}
	base, err := json.Marshal(root)
	if err != nil {
		return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
	}
	return base, mappings, hosts.DefaultProvider, repositories, egress, nil
}

func validManagedEgressSource(value map[string]any) bool {
	allowed := map[string]struct{}{
		"mode": {}, "transport": {}, "placeholder": {}, "forward-proxy-url": {},
		"grants": {}, "enforcement": {}, "operator-prepared": {},
	}
	for key := range value {
		if _, ok := allowed[key]; !ok {
			return false
		}
	}
	placeholder, placeholderOK := value["placeholder"].(string)
	forwardProxy, proxyOK := value["forward-proxy-url"].(string)
	grants, grantsOK := value["grants"].([]any)
	if !placeholderOK || placeholder != "NVT-PLACEHOLDER-NOT-A-KEY" || !proxyOK || forwardProxy != "http://127.0.0.1:15002" || !grantsOK {
		return false
	}
	for _, key := range []string{"enforcement", "operator-prepared"} {
		if raw, present := value[key]; present {
			if _, ok := raw.(bool); !ok {
				return false
			}
		}
	}
	return len(grants) <= resolvedrun.MaxBrokerGrants
}

func containsSensitiveConfig(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.ToLower(strings.NewReplacer("_", "-", ".", "-").Replace(key))
			for _, segment := range strings.Split(normalized, "-") {
				switch segment {
				case "token", "secret", "password", "credential", "credentials", "authorization":
					return true
				}
			}
			if strings.Contains(normalized, "private-key") || strings.Contains(normalized, "api-key") || containsSensitiveConfig(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsSensitiveConfig(child) {
				return true
			}
		}
	}
	return false
}

func exactBrokerAgent(agents []brokerAgent, name string) (brokerAgent, bool) {
	var result brokerAgent
	found := false
	for _, agent := range agents {
		if agent.ID == name {
			if found || agent.Role == "egress" {
				return brokerAgent{}, false
			}
			result, found = agent, true
		}
	}
	return result, found
}

func findMapping(values []resolvedrun.CredentialProviderMapping, name string) (resolvedrun.CredentialProviderMapping, bool) {
	for _, value := range values {
		if value.Name == name {
			return value, true
		}
	}
	return resolvedrun.CredentialProviderMapping{}, false
}

func repositoryTarget(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	clean := strings.Trim(strings.TrimSuffix(parsed.EscapedPath(), ".git"), "/")
	if clean == "" || strings.Contains(clean, "%") {
		return ""
	}
	return strings.ToLower(parsed.Hostname()) + "/" + clean
}

func absoluteClean(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func decodeStrictYAMLFile(path string, maximum int64, target any) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum {
		return ErrInvalidInput
	}
	data, err := os.ReadFile(path)
	if err != nil || !utf8.Valid(data) {
		return ErrInvalidInput
	}
	defer clear(data)
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return ErrInvalidInput
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return ErrInvalidInput
	}
	return nil
}

func loadYAMLObject(path string, maximum int64) (map[string]any, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum {
		return nil, ErrInvalidInput
	}
	data, err := os.ReadFile(path)
	if err != nil || !utf8.Valid(data) {
		return nil, ErrInvalidInput
	}
	defer clear(data)
	var node yaml.Node
	if yaml.Unmarshal(data, &node) != nil || validateYAMLNode(&node) != nil {
		return nil, ErrInvalidInput
	}
	var value any
	if node.Decode(&value) != nil {
		return nil, ErrInvalidInput
	}
	normalized, ok := normalizeYAML(value).(map[string]any)
	if !ok {
		return nil, ErrInvalidInput
	}
	return normalized, nil
}

func validateYAMLNode(node *yaml.Node) error {
	if node.Kind == yaml.AliasNode || node.Tag == "!!binary" {
		return ErrInvalidInput
	}
	if node.Kind == yaml.MappingNode {
		seen := map[string]struct{}{}
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return ErrInvalidInput
			}
			if _, duplicate := seen[key.Value]; duplicate {
				return ErrInvalidInput
			}
			seen[key.Value] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if err := validateYAMLNode(child); err != nil {
			return err
		}
	}
	return nil
}

func normalizeYAML(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := map[string]any{}
		for key, item := range typed {
			result[key] = normalizeYAML(item)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = normalizeYAML(item)
		}
		return result
	default:
		return value
	}
}

func decodeStrictJSONValue(value any, target any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return ErrInvalidInput
	}
	return nil
}

func loadProviderNames(path string) (map[string]struct{}, error) {
	root, err := loadYAMLObject(path, 1<<20)
	if err != nil {
		return nil, err
	}
	raw, ok := root["providers"].([]any)
	if !ok {
		return nil, ErrInvalidInput
	}
	result := map[string]struct{}{}
	for _, item := range raw {
		provider, ok := item.(map[string]any)
		if !ok {
			return nil, ErrInvalidInput
		}
		name, ok := provider["name"].(string)
		if !ok || name == "" {
			return nil, ErrInvalidInput
		}
		if _, duplicate := result[name]; duplicate {
			return nil, ErrInvalidInput
		}
		result[name] = struct{}{}
	}
	return result, nil
}
