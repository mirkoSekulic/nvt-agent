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
	APIVersion          string           `yaml:"api_version"`
	Image               string           `yaml:"image"`
	PrincipalIssuer     string           `yaml:"principal_issuer"`
	Backend             string           `yaml:"backend"`
	Retention           string           `yaml:"retention"`
	RuntimeAllowlist    runtimeAllowlist `yaml:"runtime_allowlist"`
	CredentialUsernames []string         `yaml:"credential_usernames,omitempty"`
	Agents              []ManifestAgent  `yaml:"agents"`
}

type runtimeAllowlist struct {
	Commands        []string          `yaml:"commands"`
	Arguments       []string          `yaml:"arguments,omitempty"`
	ResumeCommands  []string          `yaml:"resume_commands,omitempty"`
	ResumeArguments []string          `yaml:"resume_arguments,omitempty"`
	Environment     map[string]string `yaml:"environment,omitempty"`
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
	Username string                          `json:"username,omitempty"`
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
	if !validRuntimeAllowlist(manifest.RuntimeAllowlist) ||
		!validAllowlistStrings(manifest.CredentialUsernames, 0, 32, func(value string) bool { return len(value) <= 256 && safeToken(value) }) {
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
	base, mappings, defaultProvider, repositories, egress, err := convertAgentConfig(
		agentPath, staticAgent.Grants, configured.BrokerRepositories, manifest.RuntimeAllowlist, manifest.CredentialUsernames, configured.User,
	)
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

func convertAgentConfig(path string, grants []brokerGrant, overrides map[string]string, runtimeAllowlist runtimeAllowlist, credentialUsernames []string, runtimeUser string) (json.RawMessage, []resolvedrun.CredentialProviderMapping, string, []resolvedrun.Repository, resolvedrun.Egress, error) {
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
		target := repositoryTarget(rule.Match)
		if target == "" || rule.Username != "" && !containsString(credentialUsernames, rule.Username) {
			return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
		}
		if _, duplicate := rules[target]; duplicate {
			return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
		}
		rules[target] = rule
	}
	repositories := make([]resolvedrun.Repository, 0, len(checkouts.Repos))
	usedOverrides := map[string]struct{}{}
	for _, item := range checkouts.Repos {
		target := repositoryTarget(item.URL)
		if target == "" {
			return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
		}
		repository := resolvedrun.Repository{CheckoutTarget: target, URL: item.URL, Path: item.Path, Upstream: item.Upstream}
		if rule, exists := rules[target]; exists {
			repository.CredentialProvider, repository.CredentialUsername, repository.Identity = rule.Provider, rule.Username, rule.Identity
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
				repository.BrokerRepository = exactBrokerRepository(target, grant.Repositories)
				if repository.BrokerRepository == "" && len(grant.Repositories) == 1 {
					repository.BrokerRepository = grant.Repositories[0]
				}
				if repository.BrokerRepository == "" {
					return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
				}
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
			if repositoryTarget(item.URL) == match {
				found = true
			}
		}
		if !found {
			return nil, nil, "", nil, resolvedrun.Egress{}, ErrInvalidInput
		}
	}
	if !sanitizePortableAgentConfig(root, runtimeAllowlist, runtimeUser, grantByProvider) {
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

func exactBrokerRepository(checkoutTarget string, repositories []string) string {
	separator := strings.IndexByte(checkoutTarget, '/')
	if separator < 1 || separator == len(checkoutTarget)-1 {
		return ""
	}
	providerNative := checkoutTarget[separator+1:]
	result := ""
	for _, repository := range repositories {
		if repository == providerNative {
			if result != "" {
				return ""
			}
			result = repository
		}
	}
	return result
}

// sanitizePortableAgentConfig accepts only source fields whose runtime meaning
// is explicitly non-secret and bounded. Runtime arguments/environment must be
// enumerated by the administrator-owned migration manifest. Arbitrary plugin
// configuration, shell hooks, editor settings, and other value-bearing escape
// hatches stay on the static Compose rollback path.
func sanitizePortableAgentConfig(root map[string]any, allow runtimeAllowlist, runtimeUser string, grants map[string]brokerGrant) bool {
	if !onlyKeys(root, "runtime", "tools", "code-server", "expose", "preseed", "plugins") {
		return false
	}
	runtime, ok := root["runtime"].(map[string]any)
	if !ok || !validPortableRuntime(runtime, allow, runtimeUser) {
		return false
	}
	if tools, present := root["tools"]; present && !validPortableTools(tools) {
		return false
	}
	if codeServer, present := root["code-server"]; present && !validPortableCodeServer(codeServer) {
		return false
	}
	if expose, present := root["expose"]; present && !validPortableExpose(expose) {
		return false
	}
	if preseed, present := root["preseed"]; present && !validGeneratedPreseed(preseed) {
		return false
	}
	plugins, ok := root["plugins"].([]any)
	if !ok || len(plugins) > 64 {
		return false
	}
	for _, raw := range plugins {
		plugin, ok := raw.(map[string]any)
		if !ok || !validReferenceOnlyPlugin(plugin, grants) {
			return false
		}
	}
	return true
}

func validRuntimeAllowlist(value runtimeAllowlist) bool {
	return validAllowlistStrings(value.Commands, 1, 32, validPortableCommand) &&
		validAllowlistStrings(value.Arguments, 0, 64, validPortableArgument) &&
		validAllowlistStrings(value.ResumeCommands, 0, 32, validPortableCommand) &&
		validAllowlistStrings(value.ResumeArguments, 0, 64, validPortableArgument) &&
		validAllowedEnvironment(value.Environment)
}

func validAllowlistStrings(values []string, minimum, maximum int, valid func(string) bool) bool {
	if len(values) < minimum || len(values) > maximum {
		return false
	}
	seen := map[string]struct{}{}
	for _, value := range values {
		if !valid(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validPortableRuntime(value map[string]any, allow runtimeAllowlist, runtimeUser string) bool {
	if !onlyKeys(value, "command", "args", "user", "env", "resume") {
		return false
	}
	command, commandOK := value["command"].(string)
	user, userOK := value["user"].(string)
	if !commandOK || !containsString(allow.Commands, command) || !userOK || user != runtimeUser ||
		!allowedStringArray(value["args"], allow.Arguments) {
		return false
	}
	if environment, present := value["env"]; present && !allowedEnvironment(environment, allow.Environment) {
		return false
	}
	if resumeValue, present := value["resume"]; present {
		resume, ok := resumeValue.(map[string]any)
		if !ok || !onlyKeys(resume, "command", "args") {
			return false
		}
		resumeCommand, ok := resume["command"].(string)
		if !ok || !containsString(allow.ResumeCommands, resumeCommand) || !allowedOptionalStringArray(resume, "args", allow.ResumeArguments) {
			return false
		}
	}
	return true
}

func validPortableTools(raw any) bool {
	value, ok := raw.(map[string]any)
	if !ok || !onlyKeys(value, "packages", "mise", "additional-paths", "shell") {
		return false
	}
	for _, key := range []string{"packages", "mise"} {
		if item, present := value[key]; present && !stringArray(item, 128, func(entry string) bool {
			return len(entry) <= 128 && safeToken(entry)
		}) {
			return false
		}
	}
	if item, present := value["additional-paths"]; present && !stringArray(item, 64, validPortablePath) {
		return false
	}
	if item, present := value["shell"]; present && !emptyArray(item) {
		return false
	}
	return true
}

func validPortableCodeServer(raw any) bool {
	value, ok := raw.(map[string]any)
	if !ok || !onlyKeys(value, "extensions", "settings", "agentTerminal") {
		return false
	}
	if extensions, present := value["extensions"]; present && !stringArray(extensions, 128, func(entry string) bool {
		return len(entry) <= 256 && safeToken(entry)
	}) {
		return false
	}
	if settingsValue, present := value["settings"]; present {
		settings, ok := settingsValue.(map[string]any)
		if !ok || !onlyKeys(settings, "overwrite", "values") {
			return false
		}
		if overwrite, exists := settings["overwrite"]; exists {
			if _, ok := overwrite.(bool); !ok {
				return false
			}
		}
		if values, exists := settings["values"]; exists {
			object, ok := values.(map[string]any)
			if !ok || len(object) != 0 {
				return false
			}
		}
	}
	if terminalValue, present := value["agentTerminal"]; present {
		terminal, ok := terminalValue.(map[string]any)
		if !ok || !onlyKeys(terminal, "openOnStartup") {
			return false
		}
		if enabled, exists := terminal["openOnStartup"]; exists {
			if _, ok := enabled.(bool); !ok {
				return false
			}
		}
	}
	return true
}

func validPortableExpose(raw any) bool {
	value, ok := raw.(map[string]any)
	if !ok || !onlyKeys(value, "http") {
		return false
	}
	routes, ok := value["http"].([]any)
	if !ok || len(routes) > 64 {
		return false
	}
	seen := map[string]struct{}{}
	for _, rawRoute := range routes {
		route, ok := rawRoute.(map[string]any)
		if !ok || !onlyKeys(route, "name", "targetPort", "source") {
			return false
		}
		name, nameOK := route["name"].(string)
		port, portOK := route["targetPort"].(int)
		source, sourceOK := route["source"].(string)
		if !sourceOK {
			source = "agent"
		}
		if !nameOK || !safeDNSLabel(name) || !portOK || port < 1 || port > 65535 || source != "agent" {
			return false
		}
		if _, duplicate := seen[name]; duplicate {
			return false
		}
		seen[name] = struct{}{}
	}
	return true
}

func validGeneratedPreseed(raw any) bool {
	value, ok := raw.(map[string]any)
	if !ok || !onlyKeys(value, "files") {
		return false
	}
	files, ok := value["files"].([]any)
	if !ok || len(files) > 8 {
		return false
	}
	for _, rawFile := range files {
		file, ok := rawFile.(map[string]any)
		if !ok || !onlyKeys(file, "path", "mode", "overwrite", "content", "json") {
			return false
		}
		path, pathOK := file["path"].(string)
		mode, modeOK := file["mode"].(string)
		overwrite, overwriteOK := file["overwrite"].(bool)
		if !pathOK || !modeOK || mode != "0600" || !overwriteOK || overwrite {
			return false
		}
		content, hasContent := file["content"]
		jsonValue, hasJSON := file["json"]
		if hasContent == hasJSON {
			return false
		}
		if hasContent {
			text, ok := content.(string)
			if !ok || path != "$HOME/.codex/config.toml" || strings.TrimSuffix(text, "\n") != "check_for_update_on_startup = false" {
				return false
			}
		}
		if hasJSON {
			object, ok := jsonValue.(map[string]any)
			if !ok || path != "$HOME/.claude/settings.json" || !onlyKeys(object, "theme", "skipDangerousModePermissionPrompt") || object["theme"] != "dark-daltonized" || object["skipDangerousModePermissionPrompt"] != true {
				return false
			}
		}
	}
	return true
}

func validReferenceOnlyPlugin(plugin map[string]any, grants map[string]brokerGrant) bool {
	if !onlyKeys(plugin, "name", "source", "when", "restart", "health", "egress", "config") {
		return false
	}
	name, nameOK := plugin["name"].(string)
	source, sourceOK := plugin["source"].(string)
	if !nameOK || !safeDNSLabel(name) || !sourceOK || source != "builtin" {
		return false
	}
	if when, present := plugin["when"]; present && when != "before-agent" && when != "after-agent" {
		return false
	}
	if restart, present := plugin["restart"]; present && restart != "never" && restart != "always" && restart != "on-failure" {
		return false
	}
	if healthValue, present := plugin["health"]; present {
		health, ok := healthValue.(map[string]any)
		if !ok || !onlyKeys(health, "readiness") {
			return false
		}
		if readiness, exists := health["readiness"]; exists {
			if _, ok := readiness.(bool); !ok {
				return false
			}
		}
	}
	if egressValue, present := plugin["egress"]; present {
		egress, ok := egressValue.(map[string]any)
		if !ok || !onlyKeys(egress, "provider") {
			return false
		}
		provider, ok := egress["provider"].(string)
		if !ok {
			return false
		}
		if _, granted := grants[provider]; !granted {
			return false
		}
	}
	if configValue, present := plugin["config"]; present {
		config, ok := configValue.(map[string]any)
		if !ok || !validReferenceOnlyPluginConfig(name, config) {
			return false
		}
	}
	return true
}

func validReferenceOnlyPluginConfig(name string, config map[string]any) bool {
	if len(config) == 0 {
		return true
	}
	// The watcher registry and credential transport remain outside this static
	// config. Only its bounded cadence is portable reference-free policy.
	if name != "github-watcher" || !onlyKeys(config, "poll-seconds") {
		return false
	}
	seconds, ok := config["poll-seconds"].(int)
	return ok && seconds >= 5 && seconds <= 3600
}

func validAllowedEnvironment(value map[string]string) bool {
	if len(value) > 32 {
		return false
	}
	for name, entry := range value {
		if !validEnvironmentName(name) || len(entry) > 4096 || strings.ContainsAny(entry, "\x00\r\n") {
			return false
		}
	}
	return true
}

func allowedEnvironment(raw any, allowed map[string]string) bool {
	value, ok := raw.(map[string]any)
	if !ok || len(value) > len(allowed) {
		return false
	}
	for name, rawEntry := range value {
		entry, ok := rawEntry.(string)
		if !ok || allowed[name] != entry {
			return false
		}
	}
	return true
}

func allowedStringArray(raw any, allowed []string) bool {
	return stringArray(raw, 64, func(value string) bool { return containsString(allowed, value) })
}

func allowedOptionalStringArray(value map[string]any, key string, allowed []string) bool {
	raw, present := value[key]
	return !present || allowedStringArray(raw, allowed)
}

func stringArray(raw any, maximum int, valid func(string) bool) bool {
	values, ok := raw.([]any)
	if !ok || len(values) > maximum {
		return false
	}
	for _, rawValue := range values {
		value, ok := rawValue.(string)
		if !ok || !valid(value) {
			return false
		}
	}
	return true
}

func emptyArray(raw any) bool {
	values, ok := raw.([]any)
	return ok && len(values) == 0
}

func onlyKeys(value map[string]any, allowed ...string) bool {
	set := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		set[key] = struct{}{}
	}
	for key := range value {
		if _, ok := set[key]; !ok {
			return false
		}
	}
	return true
}

func containsString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func validPortableCommand(value string) bool {
	return len(value) > 0 && len(value) <= 128 && safeToken(value) && !strings.Contains(value, "/")
}

func validPortableArgument(value string) bool {
	return len(value) > 0 && len(value) <= 256 && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func safeToken(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._@:+/-$", character) {
			continue
		}
		return false
	}
	return true
}

func validPortablePath(value string) bool {
	if len(value) == 0 || len(value) > 512 || strings.ContainsAny(value, "\x00\r\n") || strings.Contains(value, "..") {
		return false
	}
	if !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "$HOME/") {
		return false
	}
	return safeToken(value)
}

func validEnvironmentName(value string) bool {
	if value == "" || len(value) > 128 || value[0] != '_' && (value[0] < 'A' || value[0] > 'Z') && (value[0] < 'a' || value[0] > 'z') {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if character != '_' && (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func safeDNSLabel(value string) bool {
	if len(value) == 0 || len(value) > 63 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return value[len(value)-1] != '-'
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
