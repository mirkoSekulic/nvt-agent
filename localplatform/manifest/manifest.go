// Package manifest defines the behavior-inactive, administrator-authored
// nvt.dev/local/v1 local-platform contract.
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/distribution/reference"
	"gopkg.in/yaml.v3"
)

const (
	APIVersion       = "nvt.dev/local/v1"
	MaxDocumentBytes = 1 << 20
	MaxDocumentNodes = 32768
	MaxDocumentDepth = 64
	MaxItems         = 256
	MaxProducers     = 64
	MaxNameBytes     = 63
	MaxStringBytes   = 4096
	MaxTTLSeconds    = 365 * 24 * 60 * 60
)

var (
	namePattern       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$`)
	runIDPattern      = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	integerPattern    = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)$`)
	eventPattern      = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
	configKeyPattern  = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	secretKeyPattern  = regexp.MustCompile(`(?i)(secret|token|password|passwd|private.?key|credential|api.?key)`)
)

type Manifest struct {
	APIVersion        string                     `json:"apiVersion"`
	Reconciliation    Reconciliation             `json:"reconciliation,omitempty"`
	Secrets           map[string]Secret          `json:"secrets,omitempty"`
	Accounts          map[string]Account         `json:"accounts,omitempty"`
	BrokerProviders   map[string]BrokerProvider  `json:"brokerProviders,omitempty"`
	RetentionPolicies map[string]RetentionPolicy `json:"retentionPolicies"`
	Profiles          map[string]Profile         `json:"profiles"`
	Repositories      map[string]Repository      `json:"repositories"`
	Workstations      []Workstation              `json:"workstations,omitempty"`
	Workflows         map[string]Workflow        `json:"workflows"`
	Producers         []Producer                 `json:"producers,omitempty"`
}

// Reconciliation gates the two destructive workstation convergence modes.
// Both remain disabled when omitted.
type Reconciliation struct {
	Workstations WorkstationReconciliation `json:"workstations,omitempty"`
}

type WorkstationReconciliation struct {
	Prune                    bool `json:"prune,omitempty"`
	ReplaceOnImmutableChange bool `json:"replaceOnImmutableChange,omitempty"`
}

type RetentionPolicy struct {
	Persistence Persistence `json:"persistence,omitempty"`
	TTL         TTL         `json:"ttl,omitempty"`
}

type Persistence struct {
	Workspace    bool `json:"workspace,omitempty"`
	RuntimeState bool `json:"runtimeState,omitempty"`
	DockerData   bool `json:"dockerData,omitempty"`
}

type TTL struct {
	ActiveSeconds       int64 `json:"activeSeconds,omitempty"`
	CompletedSeconds    int64 `json:"completedSeconds,omitempty"`
	FailedSeconds       int64 `json:"failedSeconds,omitempty"`
	RunRetentionSeconds int64 `json:"runRetentionSeconds,omitempty"`
}

type Secret struct {
	File string `json:"file"`
}

type Account struct {
	Preset           string            `json:"preset"`
	AppID            string            `json:"appId,omitempty"`
	PrivateKeySecret string            `json:"privateKeySecret,omitempty"`
	Installations    map[string]string `json:"installations,omitempty"`
}

// BrokerProvider is an opaque broker plugin instance plus compiler-owned
// secret and mediation metadata. Config is public; secret bindings are
// resolved to broker-private paths only after validation.
type BrokerProvider struct {
	Plugin    string                  `json:"plugin"`
	Config    map[string]any          `json:"config,omitempty"`
	Secrets   map[string]string       `json:"secrets,omitempty"`
	Mediation BrokerProviderMediation `json:"mediation"`
}

type BrokerProviderMediation struct {
	Hosts           []string `json:"hosts"`
	Materialization string   `json:"materialization"`
	Git             bool     `json:"git"`
	Username        string   `json:"username"`
	TargetMode      string   `json:"targetMode"`
}

type Profile struct {
	Runtime                   Runtime            `json:"runtime"`
	Accounts                  []string           `json:"accounts,omitempty"`
	CredentialProviders       []string           `json:"credentialProviders,omitempty"`
	DefaultCredentialProvider string             `json:"defaultCredentialProvider,omitempty"`
	Tools                     Tools              `json:"tools,omitempty"`
	Capabilities              []string           `json:"capabilities,omitempty"`
	Instructions              *FileRef           `json:"instructions,omitempty"`
	Editor                    Editor             `json:"editor,omitempty"`
	Plugins                   []Plugin           `json:"plugins,omitempty"`
	Egress                    *ProfileEgress     `json:"egress,omitempty"`
	Kubernetes                []KubernetesAccess `json:"kubernetes,omitempty"`
}

// KubernetesAccess selects an exact set of context resources from one generic
// kubeconfig provider.  It carries names only, never kubeconfig data.
type KubernetesAccess struct {
	Provider      string                   `json:"provider"`
	Contexts      []string                 `json:"contexts"`
	Authorization *KubernetesAuthorization `json:"authorization,omitempty"`
}

// KubernetesAuthorization is high-level local intent. Presets are resolved by
// the compiler and never cross the broker/provider protocol boundary.
type KubernetesAuthorization struct {
	Preset        string                        `json:"preset,omitempty"`
	DefaultAction string                        `json:"defaultAction,omitempty"`
	Rules         []KubernetesAuthorizationRule `json:"rules,omitempty"`
}

type KubernetesAuthorizationRule struct {
	Operation string `json:"operation"`
	Resource  string `json:"resource"`
}

type ProfileEgress struct {
	DomainPolicy *DomainPolicy `json:"domainPolicy"`
}

type DomainPolicy struct {
	DefaultAction string   `json:"defaultAction"`
	Allow         []string `json:"allow,omitempty"`
	Deny          []string `json:"deny,omitempty"`
}

type Plugin struct {
	Name    string         `json:"name"`
	When    string         `json:"when,omitempty"`
	Restart string         `json:"restart,omitempty"`
	Config  map[string]any `json:"config,omitempty"`
	Egress  *PluginEgress  `json:"egress,omitempty"`
}

type PluginEgress struct {
	Provider string `json:"provider"`
}

func (p *Plugin) UnmarshalJSON(data []byte) error {
	var shorthand string
	if err := json.Unmarshal(data, &shorthand); err == nil {
		*p = Plugin{Name: shorthand}
		return nil
	}
	type plain Plugin
	var value plain
	if err := strictJSON(data, &value); err != nil {
		return err
	}
	*p = Plugin(value)
	return nil
}

type Runtime struct {
	Preset   string `json:"preset"`
	Autonomy string `json:"autonomy"`
	Account  string `json:"account,omitempty"`
	Model    string `json:"model,omitempty"`
	Effort   string `json:"effort,omitempty"`
}
type Tools struct {
	Packages []string `json:"packages,omitempty"`
	Mise     []string `json:"mise,omitempty"`
}

type FileRef struct {
	File string `json:"file"`
}
type Editor struct {
	Preset string `json:"preset,omitempty"`
}

type Workstation struct {
	Name         string   `json:"name"`
	Profile      string   `json:"profile"`
	Repositories []string `json:"repositories,omitempty"`
}

// Repository is provider-neutral checkout intent. GitHub is an optional
// shorthand expanded by Compile; otherwise URL and CheckoutTarget are exact.
type Repository struct {
	GitHub             string            `json:"github,omitempty"`
	URL                string            `json:"url,omitempty"`
	CheckoutTarget     string            `json:"checkoutTarget,omitempty"`
	BrokerRepository   string            `json:"brokerRepository,omitempty"`
	Path               string            `json:"path,omitempty"`
	Upstream           string            `json:"upstream,omitempty"`
	Account            string            `json:"account,omitempty"`
	CredentialProvider string            `json:"credentialProvider,omitempty"`
	Access             *RepositoryAccess `json:"access,omitempty"`
}

type RepositoryAccess struct {
	Permissions map[string]string `json:"permissions"`
}

type Workflow struct {
	Profile    string    `json:"profile"`
	Repository string    `json:"repository"`
	Retention  string    `json:"retention"`
	Lifecycle  Lifecycle `json:"lifecycle"`
}

type Lifecycle struct {
	CompleteOn []string `json:"completeOn,omitempty"`
	FailOn     []string `json:"failOn,omitempty"`
}

type Producer struct {
	Name                    string            `json:"name"`
	Preset                  string            `json:"preset,omitempty"`
	Image                   string            `json:"image,omitempty"`
	RuntimeIdentity         *RuntimeIdentity  `json:"runtimeIdentity,omitempty"`
	Account                 string            `json:"account,omitempty"`
	Repository              string            `json:"repository,omitempty"`
	Prefix                  string            `json:"prefix,omitempty"`
	AllowedAuthors          []string          `json:"allowedAuthors,omitempty"`
	Workflow                string            `json:"workflow"`
	CommandWorkflows        map[string]string `json:"commandWorkflows,omitempty"`
	AllowedPrincipalIssuers []string          `json:"allowedPrincipalIssuers,omitempty"`
	PublicConfig            map[string]any    `json:"publicConfig,omitempty"`
	Secrets                 map[string]string `json:"secrets,omitempty"`
}

type RuntimeIdentity struct {
	UID int `json:"uid"`
	GID int `json:"gid"`
}

// Decode parses exactly one bounded YAML document and validates all references.
// It deliberately does not open referenced files.
func Decode(reader io.Reader) (Manifest, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxDocumentBytes+1))
	if err != nil || len(data) == 0 || len(data) > MaxDocumentBytes || !utf8.Valid(data) {
		return Manifest{}, errors.New("invalid local manifest document")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil || len(document.Content) != 1 {
		return Manifest{}, errors.New("invalid local manifest YAML")
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("local manifest must contain exactly one document")
	}
	nodes := 0
	if err := validateNode(document.Content[0], 0, &nodes); err != nil {
		return Manifest{}, err
	}
	var raw any
	if err := document.Content[0].Decode(&raw); err != nil {
		return Manifest{}, errors.New("invalid local manifest value")
	}
	canonical, err := json.Marshal(raw)
	if err != nil || len(canonical) > MaxDocumentBytes {
		return Manifest{}, errors.New("invalid local manifest value")
	}
	var result Manifest
	if err := strictJSON(canonical, &result); err != nil {
		return Manifest{}, fmt.Errorf("invalid local manifest schema: %w", err)
	}
	if err := result.Validate(); err != nil {
		return Manifest{}, err
	}
	return result, nil
}

func strictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) {
		return errors.New("trailing value")
	}
	return nil
}

func validateNode(node *yaml.Node, depth int, nodes *int) error {
	if node == nil || depth > MaxDocumentDepth {
		return errors.New("local manifest exceeds maximum depth")
	}
	*nodes++
	if *nodes > MaxDocumentNodes || node.Alias != nil || node.Anchor != "" {
		return errors.New("local manifest has too many nodes or uses aliases")
	}
	switch node.Kind {
	case yaml.MappingNode:
		if len(node.Content)%2 != 0 {
			return errors.New("invalid mapping")
		}
		seen := map[string]struct{}{}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "" {
				return errors.New("mapping keys must be non-empty strings")
			}
			if _, ok := seen[key.Value]; ok {
				return fmt.Errorf("duplicate key %q", key.Value)
			}
			seen[key.Value] = struct{}{}
			if err := validateNode(node.Content[i+1], depth+1, nodes); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if err := validateNode(child, depth+1, nodes); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		if node.Tag != "!!str" && node.Tag != "!!bool" && node.Tag != "!!int" && node.Tag != "!!null" {
			return fmt.Errorf("unsupported scalar tag %q", node.Tag)
		}
		if len(node.Value) > MaxStringBytes {
			return errors.New("local manifest scalar is too large")
		}
	default:
		return errors.New("unsupported YAML node")
	}
	return nil
}

func (m Manifest) Validate() error {
	if m.APIVersion != APIVersion {
		return fmt.Errorf("apiVersion must be %q", APIVersion)
	}
	if len(m.RetentionPolicies) == 0 || len(m.Profiles) == 0 || len(m.Workflows) == 0 {
		return errors.New("retentionPolicies, profiles, and workflows are required")
	}
	for label, count := range map[string]int{"secrets": len(m.Secrets), "accounts": len(m.Accounts), "brokerProviders": len(m.BrokerProviders), "retentionPolicies": len(m.RetentionPolicies), "profiles": len(m.Profiles), "repositories": len(m.Repositories), "workstations": len(m.Workstations), "workflows": len(m.Workflows), "producers": len(m.Producers)} {
		if count > MaxItems {
			return fmt.Errorf("too many %s", label)
		}
	}
	if len(m.Producers) > MaxProducers {
		return errors.New("too many producers")
	}
	for name, secret := range m.Secrets {
		if !validName(name) || !safeRelativePath(secret.File, ".nvt-local/secrets/") {
			return fmt.Errorf("invalid secret %q", name)
		}
	}
	for name, account := range m.Accounts {
		if !validName(name) || !oneOf(account.Preset, "codex-oauth", "claude-oauth", "github-app") {
			return fmt.Errorf("invalid account %q", name)
		}
		if account.PrivateKeySecret != "" && !has(m.Secrets, account.PrivateKeySecret) {
			return fmt.Errorf("account %q references an unknown secret", name)
		}
		if account.Preset == "github-app" && (account.AppID == "" || account.PrivateKeySecret == "" || len(account.Installations) == 0) {
			return fmt.Errorf("github-app account %q is incomplete", name)
		}
		if account.Preset == "github-app" {
			if _, err := positiveID(account.AppID); err != nil {
				return fmt.Errorf("github-app account %q has an invalid appId", name)
			}
		}
		if account.Preset != "github-app" && (account.AppID != "" || account.PrivateKeySecret != "" || len(account.Installations) != 0) {
			return fmt.Errorf("account %q has fields not valid for its preset", name)
		}
		seenOwners := map[string]struct{}{}
		for owner, installation := range account.Installations {
			if !validName(strings.ToLower(owner)) {
				return fmt.Errorf("account %q has an invalid installation", name)
			}
			canonicalOwner := strings.ToLower(owner)
			if _, duplicate := seenOwners[canonicalOwner]; duplicate {
				return fmt.Errorf("account %q has duplicate installation owners", name)
			}
			seenOwners[canonicalOwner] = struct{}{}
			if _, err := positiveID(installation); err != nil {
				return fmt.Errorf("account %q has an invalid installation ID", name)
			}
		}
	}
	for name, provider := range m.BrokerProviders {
		if !validName(name) || has(m.Accounts, name) || !validName(provider.Plugin) {
			return fmt.Errorf("invalid broker provider %q", name)
		}
		if err := validateBrokerProvider(name, provider, m.Secrets); err != nil {
			return err
		}
	}
	for name, policy := range m.RetentionPolicies {
		if !validRunIDName(name) {
			return fmt.Errorf("invalid retention policy %q", name)
		}
		for _, seconds := range []int64{policy.TTL.ActiveSeconds, policy.TTL.CompletedSeconds, policy.TTL.FailedSeconds, policy.TTL.RunRetentionSeconds} {
			if seconds < 0 || seconds > MaxTTLSeconds {
				return fmt.Errorf("retention policy %q has an invalid TTL", name)
			}
		}
	}
	if len(m.Workstations) > 0 {
		persistent, ok := m.RetentionPolicies["persistent"]
		if !ok || !persistent.Persistence.Workspace || !persistent.Persistence.RuntimeState || !persistent.Persistence.DockerData || persistent.TTL != (TTL{}) {
			return errors.New("workstations require a non-expiring persistent retention policy")
		}
	}
	for name, profile := range m.Profiles {
		if !validRunIDName(name) || !oneOf(profile.Runtime.Preset, "codex", "claude", "shell") || !oneOf(profile.Runtime.Autonomy, "trusted-local", "approval-required") {
			return fmt.Errorf("invalid profile %q", name)
		}
		if !validRuntimeSelection(profile.Runtime) {
			return fmt.Errorf("profile %q has an invalid runtime model or effort", name)
		}
		if profile.Egress != nil {
			if profile.Egress.DomainPolicy == nil || validateDomainPolicy(*profile.Egress.DomainPolicy) != nil {
				return fmt.Errorf("profile %q has an invalid egress domain policy", name)
			}
		}
		if err := uniqueRefs(profile.Accounts, m.Accounts, "account"); err != nil {
			return fmt.Errorf("profile %q: %w", name, err)
		}
		if err := uniqueRefs(profile.CredentialProviders, m.BrokerProviders, "credential provider"); err != nil {
			return fmt.Errorf("profile %q: %w", name, err)
		}
		seenKubeProviders := map[string]bool{}
		for _, access := range profile.Kubernetes {
			provider, ok := m.BrokerProviders[access.Provider]
			if !ok || provider.Plugin != "kubeconfig" || seenKubeProviders[access.Provider] || len(access.Contexts) == 0 || len(access.Contexts) > MaxItems {
				return fmt.Errorf("profile %q has invalid Kubernetes access", name)
			}
			seenKubeProviders[access.Provider] = true
			if err := uniqueStrings(access.Contexts); err != nil {
				return fmt.Errorf("profile %q Kubernetes contexts: %w", name, err)
			}
			for _, contextName := range access.Contexts {
				if contextName == "" || len(contextName) > MaxStringBytes || strings.ContainsAny(contextName, "\x00\r\n") {
					return fmt.Errorf("profile %q has invalid Kubernetes context", name)
				}
			}
			if err := validateKubernetesAuthorization(access.Authorization); err != nil {
				return fmt.Errorf("profile %q Kubernetes authorization: %w", name, err)
			}
		}
		if !validRuntimeAccount(profile, m.Accounts) {
			return fmt.Errorf("profile %q has an invalid runtime account", name)
		}
		if err := uniqueStrings(profile.Tools.Packages); err != nil {
			return fmt.Errorf("profile %q packages: %w", name, err)
		}
		if err := uniqueStrings(profile.Tools.Mise); err != nil {
			return fmt.Errorf("profile %q mise: %w", name, err)
		}
		for _, capability := range profile.Capabilities {
			if !oneOf(capability, "SYS_PTRACE", "NET_ADMIN", "NET_RAW") {
				return fmt.Errorf("profile %q has invalid capability", name)
			}
		}
		if err := uniqueStrings(profile.Capabilities); err != nil {
			return err
		}
		seenPlugins := map[string]struct{}{}
		for _, plugin := range profile.Plugins {
			if !validName(plugin.Name) || !oneOf(plugin.When, "", "before-agent", "after-agent") || !oneOf(plugin.Restart, "", "never", "on-failure", "always") {
				return fmt.Errorf("profile %q has an invalid plugin", name)
			}
			if _, duplicate := seenPlugins[plugin.Name]; duplicate {
				return fmt.Errorf("profile %q has duplicate plugin %q", name, plugin.Name)
			}
			seenPlugins[plugin.Name] = struct{}{}
			if err := validateConfig(plugin.Config, 0); err != nil {
				return fmt.Errorf("profile %q plugin %q config: %w", name, plugin.Name, err)
			}
			if plugin.Egress != nil && !((has(m.Accounts, plugin.Egress.Provider) && contains(profile.Accounts, plugin.Egress.Provider)) || (has(m.BrokerProviders, plugin.Egress.Provider) && contains(profile.CredentialProviders, plugin.Egress.Provider))) {
				return fmt.Errorf("profile %q plugin %q has an invalid egress provider", name, plugin.Name)
			}
		}
		if profile.Instructions != nil && !safeRelativePath(profile.Instructions.File, "") {
			return fmt.Errorf("profile %q has unsafe instruction path", name)
		}
		if profile.Editor.Preset != "" && !oneOf(profile.Editor.Preset, "code-server", "none") {
			return fmt.Errorf("profile %q has invalid editor preset", name)
		}
	}
	if len(m.Repositories) == 0 {
		return errors.New("repositories are required")
	}
	for name, repository := range m.Repositories {
		if !validName(name) {
			return fmt.Errorf("invalid repository %q", name)
		}
		if err := validateRepository(repository, m.Accounts, m.BrokerProviders); err != nil {
			return fmt.Errorf("invalid repository %q: %w", name, err)
		}
	}
	seenWorkstations := map[string]struct{}{}
	for _, workstation := range m.Workstations {
		if !validName(workstation.Name) || !has(m.Profiles, workstation.Profile) {
			return fmt.Errorf("invalid workstation %q", workstation.Name)
		}
		if _, ok := seenWorkstations[workstation.Name]; ok {
			return fmt.Errorf("duplicate workstation %q", workstation.Name)
		}
		seenWorkstations[workstation.Name] = struct{}{}
		if err := uniqueRefs(workstation.Repositories, m.Repositories, "repository"); err != nil {
			return fmt.Errorf("workstation %q: %w", workstation.Name, err)
		}
		for _, repositoryName := range workstation.Repositories {
			if !profileAllowsRepository(m.Profiles[workstation.Profile], m.Repositories[repositoryName]) {
				return fmt.Errorf("workstation %q profile does not allow repository account", workstation.Name)
			}
		}
	}
	for name, workflow := range m.Workflows {
		if !validRunIDName(name) || !has(m.Profiles, workflow.Profile) || !has(m.Repositories, workflow.Repository) || !has(m.RetentionPolicies, workflow.Retention) {
			return fmt.Errorf("invalid workflow %q", name)
		}
		if !profileAllowsRepository(m.Profiles[workflow.Profile], m.Repositories[workflow.Repository]) {
			return fmt.Errorf("workflow %q profile does not allow repository account", name)
		}
		if err := validateLifecycle(workflow.Lifecycle); err != nil {
			return fmt.Errorf("workflow %q lifecycle: %w", name, err)
		}
	}
	for name, profile := range m.Profiles {
		repositoryProviders := profileRepositoryProviders(m, name)
		if profile.DefaultCredentialProvider != "" && !contains(repositoryProviders, profile.DefaultCredentialProvider) || len(repositoryProviders) > 1 && profile.DefaultCredentialProvider == "" || len(repositoryProviders) == 0 && profile.DefaultCredentialProvider != "" {
			return fmt.Errorf("profile %q has an invalid default credential provider", name)
		}
		accessByProvider := map[string]string{}
		checkAccess := func(repositoryName string) error {
			repository := m.Repositories[repositoryName]
			if repository.Account == "" || m.Accounts[repository.Account].Preset != "github-app" {
				return nil
			}
			provider := repository.Account
			if m.Accounts[repository.Account].Preset == "github-app" && len(m.Accounts[repository.Account].Installations) > 1 {
				owner, _, _ := githubCoordinates(repository)
				provider += "/" + strings.ToLower(owner)
			}
			permissions := repository.Access
			if permissions == nil {
				permissions = &RepositoryAccess{Permissions: map[string]string{"contents": "write", "pull_requests": "write"}}
			}
			encoded, _ := json.Marshal(permissions.Permissions)
			if previous, ok := accessByProvider[provider]; ok && previous != string(encoded) {
				return errors.New("contradictory repository access declarations for one profile provider")
			}
			accessByProvider[provider] = string(encoded)
			return nil
		}
		for _, workflow := range m.Workflows {
			if workflow.Profile == name {
				if err := checkAccess(workflow.Repository); err != nil {
					return fmt.Errorf("profile %q: %w", name, err)
				}
			}
		}
		for _, workstation := range m.Workstations {
			if workstation.Profile == name {
				for _, repository := range workstation.Repositories {
					if err := checkAccess(repository); err != nil {
						return fmt.Errorf("profile %q: %w", name, err)
					}
				}
			}
		}
	}
	seenProducers := map[string]struct{}{}
	for _, producer := range m.Producers {
		if !validRunIDName(producer.Name) || !has(m.Workflows, producer.Workflow) {
			return fmt.Errorf("invalid producer %q", producer.Name)
		}
		if _, ok := seenProducers[producer.Name]; ok {
			return fmt.Errorf("duplicate producer %q", producer.Name)
		}
		seenProducers[producer.Name] = struct{}{}
		if (producer.Preset == "") == (producer.Image == "") {
			return fmt.Errorf("producer %q must set exactly one of preset or image", producer.Name)
		}
		if producer.Preset != "" && producer.Preset != "github-comments" {
			return fmt.Errorf("producer %q has unknown preset", producer.Name)
		}
		if producer.Image != "" && !validDigestImage(producer.Image) {
			return fmt.Errorf("producer %q image must use an immutable sha256 digest", producer.Name)
		}
		if producer.Image != "" && !validExternalRuntimeIdentity(producer.RuntimeIdentity) {
			return fmt.Errorf("external producer %q must declare a non-root runtime identity", producer.Name)
		}
		if producer.Preset != "" && producer.RuntimeIdentity != nil {
			return fmt.Errorf("built-in producer %q cannot override its runtime identity", producer.Name)
		}
		if producer.Preset == "github-comments" && !validGitHubProducer(producer, m.Accounts, m.Repositories) {
			return fmt.Errorf("built-in producer %q is incomplete", producer.Name)
		}
		if producer.Preset == "github-comments" && (len(producer.PublicConfig) != 0 || len(producer.Secrets) != 0) {
			return fmt.Errorf("built-in producer %q uses external-only fields", producer.Name)
		}
		if producer.Preset == "github-comments" {
			for command, workflow := range producer.CommandWorkflows {
				if !oneOf(command, "pr-create", "review", "run", "pr-continue") || !has(m.Workflows, workflow) {
					return fmt.Errorf("built-in producer %q has invalid command workflow mapping", producer.Name)
				}
			}
		} else if len(producer.CommandWorkflows) != 0 {
			return fmt.Errorf("external producer %q uses built-in fields", producer.Name)
		}
		if producer.Image != "" && (producer.Account != "" || producer.Repository != "" || producer.Prefix != "" || len(producer.AllowedAuthors) != 0) {
			return fmt.Errorf("external producer %q uses built-in fields", producer.Name)
		}
		if err := uniqueStrings(producer.AllowedAuthors); err != nil {
			return err
		}
		if producer.Preset == "github-comments" && len(producer.AllowedPrincipalIssuers) != 0 {
			return fmt.Errorf("built-in producer %q overrides its issuer policy", producer.Name)
		}
		if producer.Image != "" {
			if len(producer.AllowedPrincipalIssuers) == 0 || len(producer.AllowedPrincipalIssuers) > 32 || uniqueStrings(producer.AllowedPrincipalIssuers) != nil {
				return fmt.Errorf("external producer %q has invalid issuer policy", producer.Name)
			}
			for _, issuer := range producer.AllowedPrincipalIssuers {
				if !validIssuer(issuer) {
					return fmt.Errorf("external producer %q has invalid issuer", producer.Name)
				}
			}
		}
		for _, ref := range producer.Secrets {
			if !has(m.Secrets, ref) {
				return fmt.Errorf("producer %q references an unknown secret", producer.Name)
			}
		}
		for mountName := range producer.Secrets {
			if !validName(mountName) {
				return fmt.Errorf("producer %q has an invalid secret mount name", producer.Name)
			}
		}
		if err := validateConfig(producer.PublicConfig, 0); err != nil {
			return fmt.Errorf("producer %q publicConfig: %w", producer.Name, err)
		}
	}
	return nil
}

func validateDomainPolicy(policy DomainPolicy) error {
	if !oneOf(policy.DefaultAction, "allow", "deny") || len(policy.Allow) > MaxItems || len(policy.Deny) > MaxItems {
		return errors.New("invalid domain policy")
	}
	for _, entries := range [][]string{policy.Allow, policy.Deny} {
		seen := map[string]bool{}
		for _, entry := range entries {
			normalized, ok := normalizeDomain(entry)
			if !ok || seen[normalized] {
				return errors.New("invalid or duplicate domain policy entry")
			}
			seen[normalized] = true
		}
	}
	return nil
}

func validateKubernetesAuthorization(policy *KubernetesAuthorization) error {
	if policy == nil {
		return nil
	}
	if policy.Preset != "" {
		if policy.Preset != "observe" || policy.DefaultAction != "" || policy.Rules != nil {
			return errors.New("preset must be observe and is mutually exclusive with defaultAction/rules")
		}
		return nil
	}
	if policy.DefaultAction != "allow" && policy.DefaultAction != "deny" {
		return errors.New("defaultAction must be allow or deny")
	}
	if len(policy.Rules) > MaxItems {
		return errors.New("rules exceed their limit")
	}
	seen := map[string]struct{}{}
	for _, rule := range policy.Rules {
		if rule.Operation == "" || len(rule.Operation) > MaxStringBytes || !utf8.ValidString(rule.Operation) ||
			rule.Resource == "" || len(rule.Resource) > 8192 || !utf8.ValidString(rule.Resource) {
			return errors.New("rules require bounded operation and resource")
		}
		key := rule.Operation + "\x00" + rule.Resource
		if _, duplicate := seen[key]; duplicate {
			return errors.New("rules contain a duplicate")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func normalizeDomain(value string) (string, bool) {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 254 || strings.ContainsAny(value, "/\\@?#: \t\r\n%") {
		return "", false
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if parsed := net.ParseIP(value); parsed != nil {
		return "", false
	}
	if value == "" || len(value) > 253 {
		return "", false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return "", false
		}
	}
	return value, true
}

func validName(v string) bool { return len(v) <= MaxNameBytes && namePattern.MatchString(v) }
func validRunIDName(v string) bool {
	return len(v) <= MaxNameBytes && runIDPattern.MatchString(v)
}
func validExternalRuntimeIdentity(identity *RuntimeIdentity) bool {
	return identity != nil && identity.UID > 0 && identity.UID <= 1<<31-1 && identity.GID > 0 && identity.GID <= 1<<31-1
}
func validIssuer(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == value && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\x00\r\n")
}
func validRuntimeAccount(profile Profile, accounts map[string]Account) bool {
	if profile.Runtime.Preset == "shell" {
		return profile.Runtime.Account == ""
	}
	want := profile.Runtime.Preset + "-oauth"
	account, ok := accounts[profile.Runtime.Account]
	if !ok || account.Preset != want {
		return false
	}
	for _, selected := range profile.Accounts {
		if selected == profile.Runtime.Account {
			return true
		}
	}
	return false
}
func validRuntimeSelection(runtime Runtime) bool {
	if runtime.Model != "" && (len(runtime.Model) > 256 || runtime.Model != strings.TrimSpace(runtime.Model) ||
		!utf8.ValidString(runtime.Model) || strings.ContainsAny(runtime.Model, "\x00\r\n")) {
		return false
	}
	switch runtime.Preset {
	case "codex":
		return runtime.Effort == "" || oneOf(runtime.Effort, "minimal", "low", "medium", "high", "xhigh")
	case "claude":
		return runtime.Effort == "" || oneOf(runtime.Effort, "low", "medium", "high", "xhigh", "max")
	case "shell":
		return runtime.Model == "" && runtime.Effort == ""
	default:
		return false
	}
}
func profileAllowsRepository(profile Profile, repository Repository) bool {
	if repository.Account == "" && repository.CredentialProvider == "" {
		return true
	}
	for _, account := range profile.Accounts {
		if repository.Account != "" && account == repository.Account {
			return true
		}
	}
	for _, provider := range profile.CredentialProviders {
		if repository.CredentialProvider != "" && provider == repository.CredentialProvider {
			return true
		}
	}
	return false
}
func profileRepositoryProviders(m Manifest, profileName string) []string {
	seen := map[string]struct{}{}
	add := func(repositoryName string) {
		repository := m.Repositories[repositoryName]
		if repository.Account != "" {
			seen[repository.Account] = struct{}{}
		}
		if repository.CredentialProvider != "" {
			seen[repository.CredentialProvider] = struct{}{}
		}
	}
	for _, workflow := range m.Workflows {
		if workflow.Profile == profileName {
			add(workflow.Repository)
		}
	}
	for _, workstation := range m.Workstations {
		if workstation.Profile == profileName {
			for _, repository := range workstation.Repositories {
				add(repository)
			}
		}
	}
	return SortedNames(seen)
}
func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func validateRepository(value Repository, accounts map[string]Account, providers map[string]BrokerProvider) error {
	if value.Account != "" && !has(accounts, value.Account) || value.CredentialProvider != "" && !has(providers, value.CredentialProvider) || value.Account != "" && value.CredentialProvider != "" || value.Path != "" && !safeRelativePath(value.Path, "") {
		return errors.New("invalid repository account or path")
	}
	if value.Access != nil {
		if value.Account == "" || accounts[value.Account].Preset != "github-app" || value.CredentialProvider != "" {
			return errors.New("repository access requires a GitHub account")
		}
		if len(value.Access.Permissions) == 0 {
			return errors.New("repository access permissions must not be empty")
		}
		for permission, level := range value.Access.Permissions {
			if !oneOf(permission, "contents", "pull_requests", "workflows") || !oneOf(level, "read", "write") {
				return errors.New("repository access has an unsupported permission or level")
			}
		}
		if !oneOf(value.Access.Permissions["contents"], "read", "write") {
			return errors.New("repository access requires contents read or write for checkout")
		}
		if value.Access.Permissions["workflows"] == "write" && value.Access.Permissions["contents"] != "write" {
			return errors.New("workflow write access requires contents write access")
		}
	}
	if value.GitHub != "" {
		if !repositoryPattern.MatchString(value.GitHub) || value.URL != "" || value.CheckoutTarget != "" || value.BrokerRepository != "" || value.CredentialProvider != "" {
			return errors.New("invalid GitHub shorthand")
		}
		if value.Upstream != "" && !validHTTPSRepositoryURL(value.Upstream) {
			return errors.New("invalid upstream")
		}
		if value.Account != "" && accounts[value.Account].Preset != "github-app" {
			return errors.New("GitHub repository requires a GitHub account")
		}
		if value.Account != "" && accounts[value.Account].Preset == "github-app" {
			owner, _, _ := githubCoordinates(value)
			if _, err := githubInstallationID(accounts[value.Account], owner); err != nil {
				return errors.New("GitHub App repository owner has no installation")
			}
		}
		return nil
	}
	if !validHTTPSRepositoryURL(value.URL) || repositoryTarget(value.URL) != value.CheckoutTarget || value.CheckoutTarget == "" {
		return errors.New("invalid repository URL or checkout target")
	}
	credentialed := value.Account != "" || value.CredentialProvider != ""
	if !credentialed && value.BrokerRepository != "" || credentialed && value.BrokerRepository == "" {
		return errors.New("broker repository requires a credential provider")
	}
	if value.BrokerRepository != "" && !validRepositoryID(value.BrokerRepository) || value.Upstream != "" && !validHTTPSRepositoryURL(value.Upstream) {
		return errors.New("invalid broker repository or upstream")
	}
	if value.Account != "" {
		parsed, _ := url.Parse(value.URL)
		if parsed.Host != "github.com" || accounts[value.Account].Preset != "github-app" {
			return errors.New("account-backed repository requires a GitHub App on github.com")
		}
		owner, repository, coordinatesOK := githubCoordinates(value)
		if !coordinatesOK || value.BrokerRepository != owner+"/"+repository {
			return errors.New("GitHub broker repository must match the URL coordinates")
		}
		if _, err := githubInstallationID(accounts[value.Account], owner); err != nil {
			return errors.New("GitHub App repository owner has no installation")
		}
	}
	if value.CredentialProvider != "" {
		parsed, _ := url.Parse(value.URL)
		provider := providers[value.CredentialProvider]
		if parsed.Host != parsed.Hostname() || !contains(provider.Mediation.Hosts, parsed.Hostname()) {
			return errors.New("repository host is not mediated by its credential provider")
		}
		expected, ok := brokerRepositoryTarget(value, provider.Mediation.TargetMode)
		if !ok || value.BrokerRepository != expected {
			return errors.New("broker repository must exactly match the normalized checkout target")
		}
	}
	return nil
}

func brokerRepositoryTarget(repository Repository, targetMode string) (string, bool) {
	if targetMode == "literal" {
		value := repositoryTarget(repository.URL)
		return value, value != ""
	}
	if targetMode == "github" {
		owner, name, ok := githubCoordinates(repository)
		if !ok {
			return "", false
		}
		return owner + "/" + name, true
	}
	return "", false
}

func validGitHubProducer(producer Producer, accounts map[string]Account, repositories map[string]Repository) bool {
	account, ok := accounts[producer.Account]
	if !ok || account.Preset != "github-app" || producer.Prefix == "" || len(producer.AllowedAuthors) == 0 {
		return false
	}
	repository, ok := repositories[producer.Repository]
	if !ok {
		return false
	}
	owner, _, ok := githubCoordinates(repository)
	if !ok {
		return false
	}
	_, appErr := positiveID(account.AppID)
	_, installationErr := githubInstallationID(account, owner)
	return appErr == nil && installationErr == nil
}

func githubInstallationID(account Account, owner string) (int64, error) {
	for configuredOwner, value := range account.Installations {
		if strings.EqualFold(configuredOwner, owner) {
			return positiveID(value)
		}
	}
	return 0, errors.New("GitHub owner has no configured installation")
}

func positiveID(value string) (int64, error) {
	result, err := strconv.ParseInt(value, 10, 64)
	if err != nil || result < 1 || strconv.FormatInt(result, 10) != value {
		return 0, errors.New("ID must be a positive canonical decimal integer")
	}
	return result, nil
}

func githubCoordinates(repository Repository) (string, string, bool) {
	value := repository.GitHub
	if value == "" {
		parsed, err := url.Parse(repository.URL)
		if err != nil || parsed.Host != "github.com" {
			return "", "", false
		}
		value = strings.TrimSuffix(strings.TrimPrefix(parsed.Path, "/"), ".git")
	}
	parts := strings.Split(value, "/")
	if len(parts) != 2 || !repositoryPattern.MatchString(value) {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func validHTTPSRepositoryURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.Host == strings.ToLower(parsed.Host) && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Path != "" && parsed.Path != "/" && !strings.HasSuffix(parsed.Path, "/") && !strings.Contains(parsed.Path, "//") && !strings.Contains(parsed.Path, "/../") && !strings.Contains(parsed.Path, "/./")
}

func repositoryTarget(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || !validHTTPSRepositoryURL(value) {
		return ""
	}
	return parsed.Host + strings.TrimSuffix(parsed.Path, ".git")
}

func validRepositoryID(value string) bool {
	return value != "" && len(value) <= 1024 && value == strings.Trim(value, "/") && !strings.Contains(value, "//") && !strings.ContainsAny(value, "?#@\\\x00\r\n")
}
func validDigestImage(value string) bool {
	parsed, err := reference.ParseNamed(value)
	if err != nil || parsed.String() != value {
		return false
	}
	digested, ok := parsed.(reference.Digested)
	return ok && digested.Digest().Algorithm() == "sha256" && len(digested.Digest().Encoded()) == 64
}
func oneOf(v string, values ...string) bool {
	for _, candidate := range values {
		if v == candidate {
			return true
		}
	}
	return false
}
func has[T any](values map[string]T, key string) bool { _, ok := values[key]; return ok }
func safeRelativePath(value, requiredPrefix string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") || strings.ContainsRune(value, 0) {
		return false
	}
	normalized := strings.TrimPrefix(value, "./")
	return normalized != "." && normalized == path.Clean(normalized) && (requiredPrefix == "" || strings.HasPrefix(normalized, requiredPrefix))
}
func uniqueStrings(values []string) error {
	if len(values) > MaxItems {
		return errors.New("too many values")
	}
	seen := map[string]struct{}{}
	for _, v := range values {
		if v == "" || len(v) > MaxStringBytes {
			return errors.New("invalid value")
		}
		if _, ok := seen[v]; ok {
			return fmt.Errorf("duplicate value %q", v)
		}
		seen[v] = struct{}{}
	}
	return nil
}

func validateLifecycle(value Lifecycle) error {
	if len(value.CompleteOn) > 128 || len(value.FailOn) > 128 {
		return errors.New("too many lifecycle events")
	}
	seen := map[string]struct{}{}
	for _, events := range [][]string{value.CompleteOn, value.FailOn} {
		for _, event := range events {
			if len(event) > 256 || !eventPattern.MatchString(event) {
				return errors.New("invalid lifecycle event")
			}
			if _, exists := seen[event]; exists {
				return errors.New("duplicate lifecycle event")
			}
			seen[event] = struct{}{}
		}
	}
	return nil
}
func uniqueRefs[T any](refs []string, values map[string]T, kind string) error {
	if err := uniqueStrings(refs); err != nil {
		return err
	}
	for _, ref := range refs {
		if !has(values, ref) {
			return fmt.Errorf("unknown %s %q", kind, ref)
		}
	}
	return nil
}
func validateConfig(value any, depth int) error {
	if depth > 16 {
		return errors.New("config is too deep")
	}
	switch typed := value.(type) {
	case nil, bool, string:
		if s, ok := typed.(string); ok && len(s) > MaxStringBytes {
			return errors.New("value too large")
		}
		return nil
	case json.Number:
		if !integerPattern.MatchString(typed.String()) {
			return errors.New("config numbers must be canonical integers")
		}
		return nil
	case []any:
		if len(typed) > MaxItems {
			return errors.New("too many values")
		}
		for _, v := range typed {
			if err := validateConfig(v, depth+1); err != nil {
				return err
			}
		}
	case map[string]any:
		if len(typed) > MaxItems {
			return errors.New("too many keys")
		}
		for k, v := range typed {
			if k == "" || len(k) > MaxNameBytes || secretKeyPattern.MatchString(k) {
				return fmt.Errorf("secret-bearing or invalid key %q", k)
			}
			if err := validateConfig(v, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unsupported config value")
	}
	return nil
}

func validateBrokerProvider(name string, provider BrokerProvider, secrets map[string]Secret) error {
	if err := validateProviderConfig(provider.Config, 0); err != nil {
		return fmt.Errorf("broker provider %q config: %w", name, err)
	}
	if containsUnsafePublicPath(provider.Config) {
		return fmt.Errorf("broker provider %q config contains a filesystem path", name)
	}
	if containsSecretReference(provider.Config, secrets) {
		return fmt.Errorf("broker provider %q config contains an undeclared secret reference", name)
	}
	if len(provider.Secrets) == 0 {
		return fmt.Errorf("broker provider %q must declare secret bindings", name)
	}
	for configKey, secretName := range provider.Secrets {
		secretKey := secretKeyPattern.MatchString(configKey) || provider.Plugin == "kubeconfig" && configKey == "private-kubeconfig"
		if !validConfigKey(configKey) || !secretKey || !has(secrets, secretName) {
			return fmt.Errorf("broker provider %q has an invalid secret binding", name)
		}
		if _, exists := provider.Config[configKey]; exists {
			return fmt.Errorf("broker provider %q config duplicates secret binding %q", name, configKey)
		}
	}
	if provider.Plugin == "kubeconfig" {
		mediation := provider.Mediation
		if len(provider.Secrets) != 1 || provider.Secrets["private-kubeconfig"] == "" || len(mediation.Hosts) != 0 || mediation.Materialization != "" || mediation.Git || mediation.Username != "" || mediation.TargetMode != "" {
			return fmt.Errorf("broker provider %q has invalid kubeconfig provider configuration", name)
		}
		return nil
	}
	mediation := provider.Mediation
	if len(mediation.Hosts) == 0 || mediation.Materialization != "header-inject" || !mediation.Git || mediation.Username == "" || strings.ContainsAny(mediation.Username, ":\x00\r\n") || !oneOf(mediation.TargetMode, "github", "literal") {
		return fmt.Errorf("broker provider %q has invalid static Git mediation", name)
	}
	if err := uniqueStrings(mediation.Hosts); err != nil {
		return fmt.Errorf("broker provider %q hosts: %w", name, err)
	}
	for _, host := range mediation.Hosts {
		parsed, err := url.Parse("https://" + host)
		if err != nil || parsed.Host != host || parsed.Hostname() != host || parsed.Port() != "" || strings.ToLower(host) != host {
			return fmt.Errorf("broker provider %q has invalid mediated host", name)
		}
	}
	return nil
}

func validateProviderConfig(value any, depth int) error {
	if depth > 16 {
		return errors.New("config is too deep")
	}
	switch typed := value.(type) {
	case nil, bool, string:
		if value, ok := typed.(string); ok && len(value) > MaxStringBytes {
			return errors.New("value too large")
		}
		return nil
	case json.Number:
		if !integerPattern.MatchString(typed.String()) {
			return errors.New("config numbers must be canonical integers")
		}
		return nil
	case []any:
		if len(typed) > MaxItems {
			return errors.New("too many values")
		}
		for _, item := range typed {
			if err := validateProviderConfig(item, depth+1); err != nil {
				return err
			}
		}
	case map[string]any:
		if len(typed) > MaxItems {
			return errors.New("too many keys")
		}
		for key, item := range typed {
			if !validConfigKey(key) {
				return fmt.Errorf("invalid key %q", key)
			}
			if err := validateProviderConfig(item, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unsupported config value")
	}
	return nil
}

func containsUnsafePublicPath(value any) bool {
	switch typed := value.(type) {
	case string:
		return strings.HasPrefix(typed, "/") || strings.HasPrefix(typed, "./") || strings.HasPrefix(typed, "../")
	case []any:
		for _, item := range typed {
			if containsUnsafePublicPath(item) {
				return true
			}
		}
	case map[string]any:
		for _, item := range typed {
			if containsUnsafePublicPath(item) {
				return true
			}
		}
	}
	return false
}

func containsSecretReference(value any, secrets map[string]Secret) bool {
	switch typed := value.(type) {
	case string:
		return has(secrets, typed)
	case []any:
		for _, item := range typed {
			if containsSecretReference(item, secrets) {
				return true
			}
		}
	case map[string]any:
		for _, item := range typed {
			if containsSecretReference(item, secrets) {
				return true
			}
		}
	}
	return false
}

func validConfigKey(value string) bool {
	return value != "" && len(value) <= MaxNameBytes && configKeyPattern.MatchString(value)
}

// SortedNames returns map keys in the canonical compiler order.
func SortedNames[T any](values map[string]T) []string {
	result := make([]string, 0, len(values))
	for name := range values {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}
