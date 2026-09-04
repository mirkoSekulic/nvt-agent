package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Compiled is deterministic intent for the later renderer slices. It contains
// no resolved private-input contents; declared publicConfig is copied verbatim.
// Each section names its sole output owner; it is not a runtime protocol.
type Compiled struct {
	Version                string                        `json:"version"`
	Broker                 BrokerIntent                  `json:"broker"`
	Controller             ControllerIntent              `json:"localController"`
	Gateway                GatewayIntent                 `json:"gateway"`
	Producers              []ProducerIntent              `json:"producers,omitempty"`
	PrivateInputs          []PrivateInputIntent          `json:"privateInputs,omitempty"`
	GeneratedPrivateInputs []GeneratedPrivateInputIntent `json:"generatedPrivateInputs,omitempty"`
}

type BrokerIntent struct {
	Owner        string                   `json:"owner"`
	Accounts     []NamedAccount           `json:"accounts,omitempty"`
	Providers    []NamedBrokerProvider    `json:"providers,omitempty"`
	Profiles     []BrokerProfileIntent    `json:"profiles"`
	Repositories []BrokerRepositoryIntent `json:"repositories"`
}
type ControllerIntent struct {
	Owner                   string                       `json:"owner"`
	Reconciliation          WorkstationReconciliation    `json:"reconciliation,omitempty"`
	DestructiveAcknowledged bool                         `json:"destructiveAcknowledged,omitempty"`
	RetentionPolicies       []NamedRetentionPolicy       `json:"retentionPolicies"`
	Profiles                []ControllerProfileIntent    `json:"profiles"`
	Repositories            []ControllerRepositoryIntent `json:"repositories"`
	Workstations            []Workstation                `json:"workstations,omitempty"`
	Workflows               []NamedWorkflow              `json:"workflows"`
	ProducerAdmissions      []ProducerAdmissionIntent    `json:"producerAdmissions,omitempty"`
}
type GatewayIntent struct {
	Owner                    string                `json:"owner"`
	Workstations             []string              `json:"workstations,omitempty"`
	CredentialPortalAccounts []PortalAccountIntent `json:"credentialPortalAccounts,omitempty"`
}
type PortalAccountIntent struct {
	Name   string `json:"name"`
	Preset string `json:"preset"`
}
type ProducerIntent struct {
	Owner               string                `json:"owner"`
	Name                string                `json:"name"`
	Kind                string                `json:"kind"`
	Image               string                `json:"image,omitempty"`
	RuntimeIdentity     RuntimeIdentityIntent `json:"runtimeIdentity"`
	Workflow            string                `json:"workflow"`
	CommandWorkflows    map[string]string     `json:"commandWorkflows,omitempty"`
	PublicConfig        map[string]any        `json:"publicConfig,omitempty"`
	Secrets             map[string]string     `json:"secrets,omitempty"`
	GitHub              *GitHubProducerIntent `json:"github,omitempty"`
	AdmissionCredential string                `json:"admissionCredential"`
}
type RuntimeIdentityIntent struct {
	UID int `json:"uid"`
	GID int `json:"gid"`
}
type GitHubProducerIntent struct {
	AppID            int64    `json:"appID"`
	InstallationID   int64    `json:"installationID"`
	PrivateKeySecret string   `json:"privateKeySecret"`
	RepositoryOwner  string   `json:"repositoryOwner"`
	RepositoryName   string   `json:"repositoryName"`
	Prefix           string   `json:"prefix"`
	AllowedAuthors   []string `json:"allowedAuthors"`
}
type PrivateInputIntent struct{ Owner, Name, File, Purpose string }
type GeneratedPrivateInputIntent struct {
	Owner     string   `json:"owner"`
	Name      string   `json:"name"`
	Purpose   string   `json:"purpose"`
	Consumers []string `json:"consumers"`
}

func (p PrivateInputIntent) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Owner   string `json:"owner"`
		Name    string `json:"name"`
		File    string `json:"file"`
		Purpose string `json:"purpose"`
	}{p.Owner, p.Name, p.File, p.Purpose})
}

type NamedAccount struct {
	Name    string  `json:"name"`
	Account Account `json:"account"`
}
type NamedBrokerProvider struct {
	Name     string         `json:"name"`
	Provider BrokerProvider `json:"provider"`
}
type BrokerProfileIntent struct {
	Name     string              `json:"name"`
	Accounts []string            `json:"accounts,omitempty"`
	Grants   []BrokerGrantIntent `json:"grants,omitempty"`
}
type BrokerGrantIntent struct {
	Provider      string                    `json:"provider"`
	Preset        string                    `json:"preset"`
	Mediation     *BrokerProviderMediation  `json:"mediation,omitempty"`
	Purpose       string                    `json:"purpose"`
	Repositories  []string                  `json:"repositories"`
	Resources     []string                  `json:"resources,omitempty"`
	AllContexts   bool                      `json:"allContexts,omitempty"`
	Permissions   map[string]string         `json:"permissions,omitempty"`
	Authorization *BrokerGrantAuthorization `json:"authorization,omitempty"`
}
type BrokerGrantAuthorization struct {
	DefaultAction string                         `json:"defaultAction"`
	Rules         []BrokerGrantAuthorizationRule `json:"rules,omitempty"`
}
type BrokerGrantAuthorizationRule struct {
	Operation string `json:"operation"`
	Resource  string `json:"resource"`
}
type ControllerProfileIntent struct {
	Name                      string                               `json:"name"`
	Profile                   Profile                              `json:"profile"`
	RuntimeProvider           *ControllerCredentialProviderIntent  `json:"runtimeProvider,omitempty"`
	CredentialProviders       []ControllerCredentialProviderIntent `json:"credentialProviders,omitempty"`
	DefaultCredentialProvider string                               `json:"defaultCredentialProvider,omitempty"`
	EgressProxyProvider       string                               `json:"egressProxyProvider,omitempty"`
	BrokerGrants              []BrokerGrantIntent                  `json:"brokerGrants,omitempty"`
}
type ControllerCredentialProviderIntent struct {
	Name     string `json:"name"`
	Preset   string `json:"preset"`
	Username string `json:"username,omitempty"`
}
type ProducerAdmissionIntent struct {
	Producer                string            `json:"producer"`
	Identity                string            `json:"identity"`
	Workflow                string            `json:"workflow"`
	CommandWorkflows        map[string]string `json:"commandWorkflows,omitempty"`
	Credential              string            `json:"credential"`
	AllowedPrincipalIssuers []string          `json:"allowedPrincipalIssuers"`
}
type BrokerRepositoryIntent struct {
	Name             string            `json:"name"`
	BrokerRepository string            `json:"brokerRepository,omitempty"`
	Provider         string            `json:"provider,omitempty"`
	Permissions      map[string]string `json:"permissions,omitempty"`
}
type ControllerRepositoryIntent struct {
	Name               string `json:"name"`
	URL                string `json:"url"`
	CheckoutTarget     string `json:"checkoutTarget"`
	BrokerRepository   string `json:"brokerRepository,omitempty"`
	Path               string `json:"path,omitempty"`
	Upstream           string `json:"upstream,omitempty"`
	Account            string `json:"account,omitempty"`
	CredentialProvider string `json:"credentialProvider,omitempty"`
}
type NamedWorkflow struct {
	Name     string   `json:"name"`
	Workflow Workflow `json:"workflow"`
}
type NamedRetentionPolicy struct {
	Name   string          `json:"name"`
	Policy RetentionPolicy `json:"policy"`
}

// Compile normalizes every unordered collection and returns only references to
// private inputs. It never reads files or embeds referenced private contents.
func Compile(m Manifest) (Compiled, error) {
	if err := m.Validate(); err != nil {
		return Compiled{}, err
	}
	result := Compiled{Version: APIVersion, Broker: BrokerIntent{Owner: "broker", Profiles: []BrokerProfileIntent{}, Repositories: []BrokerRepositoryIntent{}}, Controller: ControllerIntent{Owner: "local-controller", RetentionPolicies: []NamedRetentionPolicy{}, Profiles: []ControllerProfileIntent{}, Repositories: []ControllerRepositoryIntent{}, Workflows: []NamedWorkflow{}}, Gateway: GatewayIntent{Owner: "gateway"}}
	result.Controller.Reconciliation = m.Reconciliation.Workstations
	for _, name := range SortedNames(m.RetentionPolicies) {
		result.Controller.RetentionPolicies = append(result.Controller.RetentionPolicies, NamedRetentionPolicy{Name: name, Policy: m.RetentionPolicies[name]})
	}
	for _, name := range SortedNames(m.Accounts) {
		account := m.Accounts[name]
		account.Installations = sortedMap(account.Installations)
		result.Broker.Accounts = append(result.Broker.Accounts, NamedAccount{name, account})
	}
	for _, name := range SortedNames(m.BrokerProviders) {
		provider := m.BrokerProviders[name]
		provider.Config = cloneConfig(provider.Config)
		provider.Secrets = sortedMap(provider.Secrets)
		provider.Mediation.Hosts = append([]string(nil), provider.Mediation.Hosts...)
		sort.Strings(provider.Mediation.Hosts)
		result.Broker.Providers = append(result.Broker.Providers, NamedBrokerProvider{Name: name, Provider: provider})
	}
	for _, name := range SortedNames(m.Profiles) {
		profile := m.Profiles[name]
		profile.Accounts = append([]string(nil), profile.Accounts...)
		profile.CredentialProviders = append([]string(nil), profile.CredentialProviders...)
		profile.Tools.Packages = append([]string(nil), profile.Tools.Packages...)
		profile.Tools.Mise = append([]string(nil), profile.Tools.Mise...)
		profile.Capabilities = append([]string(nil), profile.Capabilities...)
		profile.Kubernetes = append([]KubernetesAccess(nil), profile.Kubernetes...)
		for index := range profile.Kubernetes {
			profile.Kubernetes[index].Contexts = append([]string(nil), profile.Kubernetes[index].Contexts...)
			if profile.Kubernetes[index].AllContexts != nil {
				value := *profile.Kubernetes[index].AllContexts
				profile.Kubernetes[index].AllContexts = &value
			}
			sort.Strings(profile.Kubernetes[index].Contexts)
		}
		profile.Plugins = append([]Plugin(nil), profile.Plugins...)
		if profile.Egress != nil {
			egress := *profile.Egress
			if egress.DomainPolicy != nil {
				policy := *egress.DomainPolicy
				policy.Allow = normalizeDomains(policy.Allow)
				policy.Deny = normalizeDomains(policy.Deny)
				egress.DomainPolicy = &policy
			}
			profile.Egress = &egress
		}
		for index := range profile.Plugins {
			profile.Plugins[index].Config = cloneConfig(profile.Plugins[index].Config)
			if profile.Plugins[index].Egress != nil {
				egress := *profile.Plugins[index].Egress
				profile.Plugins[index].Egress = &egress
			}
		}
		sort.Strings(profile.Accounts)
		sort.Strings(profile.CredentialProviders)
		sort.Strings(profile.Tools.Packages)
		sort.Strings(profile.Tools.Mise)
		sort.Strings(profile.Capabilities)
		sort.Slice(profile.Kubernetes, func(i, j int) bool { return profile.Kubernetes[i].Provider < profile.Kubernetes[j].Provider })
		sort.Slice(profile.Plugins, func(i, j int) bool { return profile.Plugins[i].Name < profile.Plugins[j].Name })
		grants := compileBrokerGrants(m, name)
		result.Broker.Profiles = append(result.Broker.Profiles, BrokerProfileIntent{Name: name, Accounts: append([]string(nil), profile.Accounts...), Grants: grants})
		controllerProfile := ControllerProfileIntent{Name: name, Profile: profile, DefaultCredentialProvider: defaultCredentialProvider(m, name), EgressProxyProvider: profile.Runtime.Account, BrokerGrants: cloneBrokerGrants(grants)}
		if profile.Runtime.Account != "" {
			controllerProfile.RuntimeProvider = &ControllerCredentialProviderIntent{Name: profile.Runtime.Account, Preset: m.Accounts[profile.Runtime.Account].Preset}
		}
		for _, providerName := range profileRepositoryProviders(m, name) {
			if account, ok := m.Accounts[providerName]; ok {
				controllerProfile.CredentialProviders = append(controllerProfile.CredentialProviders, ControllerCredentialProviderIntent{Name: providerName, Preset: account.Preset})
			} else {
				controllerProfile.CredentialProviders = append(controllerProfile.CredentialProviders, ControllerCredentialProviderIntent{Name: providerName, Username: m.BrokerProviders[providerName].Mediation.Username})
			}
		}
		result.Controller.Profiles = append(result.Controller.Profiles, controllerProfile)
	}
	for _, name := range SortedNames(m.Repositories) {
		repository := compileRepository(name, m.Repositories[name])
		result.Controller.Repositories = append(result.Controller.Repositories, repository)
		result.Broker.Repositories = append(result.Broker.Repositories, BrokerRepositoryIntent{name, repository.BrokerRepository, repositoryProvider(repository), repositoryPermissions(m.Repositories[name], m.Accounts)})
	}
	result.Controller.Workstations = append([]Workstation(nil), m.Workstations...)
	for i := range result.Controller.Workstations {
		result.Controller.Workstations[i].Repositories = append([]string(nil), result.Controller.Workstations[i].Repositories...)
		sort.Strings(result.Controller.Workstations[i].Repositories)
	}
	sort.Slice(result.Controller.Workstations, func(i, j int) bool {
		return result.Controller.Workstations[i].Name < result.Controller.Workstations[j].Name
	})
	for _, name := range SortedNames(m.Workflows) {
		result.Controller.Workflows = append(result.Controller.Workflows, NamedWorkflow{name, m.Workflows[name]})
	}
	for _, workstation := range result.Controller.Workstations {
		result.Gateway.Workstations = append(result.Gateway.Workstations, workstation.Name)
	}
	for _, name := range SortedNames(m.Accounts) {
		account := m.Accounts[name]
		if oneOf(account.Preset, "codex-oauth", "claude-oauth") {
			result.Gateway.CredentialPortalAccounts = append(result.Gateway.CredentialPortalAccounts, PortalAccountIntent{name, account.Preset})
		}
	}
	producers := append([]Producer(nil), m.Producers...)
	sort.Slice(producers, func(i, j int) bool { return producers[i].Name < producers[j].Name })
	for _, producer := range producers {
		credential := "producer-admission:" + producer.Name
		identity := RuntimeIdentityIntent{UID: 65532, GID: 65532}
		if producer.RuntimeIdentity != nil {
			identity = RuntimeIdentityIntent{UID: producer.RuntimeIdentity.UID, GID: producer.RuntimeIdentity.GID}
		}
		intent := ProducerIntent{Owner: "producer:" + producer.Name, Name: producer.Name, Kind: producer.Preset, Image: producer.Image, RuntimeIdentity: identity, Workflow: producer.Workflow, CommandWorkflows: sortedMap(producer.CommandWorkflows), PublicConfig: producer.PublicConfig, Secrets: sortedMap(producer.Secrets), AdmissionCredential: credential}
		if producer.Preset == "github-comments" {
			account := m.Accounts[producer.Account]
			owner, repository, _ := githubCoordinates(m.Repositories[producer.Repository])
			appID, _ := positiveID(account.AppID)
			installationID, _ := githubInstallationID(account, owner)
			authors := append([]string(nil), producer.AllowedAuthors...)
			sort.Strings(authors)
			intent.GitHub = &GitHubProducerIntent{appID, installationID, account.PrivateKeySecret, owner, repository, producer.Prefix, authors}
		}
		if intent.Kind == "" {
			intent.Kind = "oci"
		}
		result.Producers = append(result.Producers, intent)
		issuers := append([]string(nil), producer.AllowedPrincipalIssuers...)
		if producer.Preset == "github-comments" {
			issuers = []string{"https://github.com"}
		}
		sort.Strings(issuers)
		workflows := sortedMap(producer.CommandWorkflows)
		result.Controller.ProducerAdmissions = append(result.Controller.ProducerAdmissions, ProducerAdmissionIntent{Producer: producer.Name, Identity: "producer:" + producer.Name, Workflow: producer.Workflow, CommandWorkflows: workflows, Credential: credential, AllowedPrincipalIssuers: issuers})
		result.GeneratedPrivateInputs = append(result.GeneratedPrivateInputs, GeneratedPrivateInputIntent{"local-platform-state", credential, "schedule-admission-token", []string{"local-controller", "producer:" + producer.Name}})
	}
	brokerSecretPurposes := map[string]string{}
	for _, name := range SortedNames(m.Accounts) {
		account := m.Accounts[name]
		for _, secretName := range []string{account.PrivateKeySecret} {
			if secretName != "" {
				brokerSecretPurposes[secretName] = "secret"
			}
		}
	}
	for _, name := range SortedNames(m.BrokerProviders) {
		provider := m.BrokerProviders[name]
		for _, configKey := range SortedNames(provider.Secrets) {
			secretName := provider.Secrets[configKey]
			purpose := "secret"
			if provider.Plugin == "kubeconfig" && configKey == "private-kubeconfig" {
				purpose = "kubeconfig"
			}
			if previous := brokerSecretPurposes[secretName]; previous == "secret" || previous != "" && previous != purpose {
				purpose = "secret"
			}
			brokerSecretPurposes[secretName] = purpose
		}
	}
	for _, secretName := range SortedNames(brokerSecretPurposes) {
		result.PrivateInputs = append(result.PrivateInputs, PrivateInputIntent{"broker", secretName, m.Secrets[secretName].File, brokerSecretPurposes[secretName]})
	}
	for _, name := range SortedNames(m.Profiles) {
		if ref := m.Profiles[name].Instructions; ref != nil {
			result.PrivateInputs = append(result.PrivateInputs, PrivateInputIntent{"local-controller", name, ref.File, "instructions"})
		}
	}
	for _, producer := range producers {
		if producer.Preset == "github-comments" {
			account := m.Accounts[producer.Account]
			result.PrivateInputs = append(result.PrivateInputs, PrivateInputIntent{"producer:" + producer.Name, account.PrivateKeySecret, m.Secrets[account.PrivateKeySecret].File, "github-app-private-key"})
		}
		for _, mountName := range SortedNames(producer.Secrets) {
			secretName := producer.Secrets[mountName]
			result.PrivateInputs = append(result.PrivateInputs, PrivateInputIntent{"producer:" + producer.Name, secretName, m.Secrets[secretName].File, "secret:" + mountName})
		}
	}
	sort.Slice(result.PrivateInputs, func(i, j int) bool {
		a, b := result.PrivateInputs[i], result.PrivateInputs[j]
		if a.Owner != b.Owner {
			return a.Owner < b.Owner
		}
		if a.Purpose != b.Purpose {
			return a.Purpose < b.Purpose
		}
		return a.Name < b.Name
	})
	return result, nil
}

// ResolveKubernetesSelections expands trusted all-context selections into the
// same concrete grants produced for explicit context lists. The caller owns
// kubeconfig discovery; this function only accepts bounded, non-secret names.
func ResolveKubernetesSelections(compiled Compiled, catalogs map[string][]string) (Compiled, error) {
	encoded, err := compiled.CanonicalJSON()
	if err != nil {
		return Compiled{}, errors.New("compiled Kubernetes selection is unavailable")
	}
	var resolved Compiled
	if err := json.Unmarshal(encoded, &resolved); err != nil {
		return Compiled{}, errors.New("compiled Kubernetes selection is unavailable")
	}
	brokerProfiles := map[string]*BrokerProfileIntent{}
	for index := range resolved.Broker.Profiles {
		brokerProfiles[resolved.Broker.Profiles[index].Name] = &resolved.Broker.Profiles[index]
	}
	usedCatalogs := map[string]bool{}
	for profileIndex := range resolved.Controller.Profiles {
		profile := &resolved.Controller.Profiles[profileIndex]
		brokerProfile := brokerProfiles[profile.Name]
		if brokerProfile == nil {
			return Compiled{}, errors.New("compiled Kubernetes profile is inconsistent")
		}
		for _, access := range profile.Profile.Kubernetes {
			if access.AllContexts == nil || !*access.AllContexts {
				continue
			}
			contexts, ok := catalogs[access.Provider]
			if !ok || len(contexts) == 0 || len(contexts) > MaxItems || uniqueStrings(contexts) != nil {
				return Compiled{}, fmt.Errorf("Kubernetes provider %q returned an invalid context catalog", access.Provider)
			}
			for _, contextName := range contexts {
				if contextName == "" || len(contextName) > MaxStringBytes || strings.ContainsAny(contextName, "*\x00\r\n") {
					return Compiled{}, fmt.Errorf("Kubernetes provider %q returned an invalid context catalog", access.Provider)
				}
			}
			contexts = append([]string(nil), contexts...)
			sort.Strings(contexts)
			usedCatalogs[access.Provider] = true
			resolvedAuthorization := resolveKubernetesAuthorization(access.Authorization, contexts)
			if err := resolveKubernetesGrant(profile.BrokerGrants, access.Provider, contexts, resolvedAuthorization); err != nil {
				return Compiled{}, err
			}
			if err := resolveKubernetesGrant(brokerProfile.Grants, access.Provider, contexts, resolvedAuthorization); err != nil {
				return Compiled{}, err
			}
		}
	}
	for provider := range catalogs {
		if !usedCatalogs[provider] {
			return Compiled{}, fmt.Errorf("unexpected Kubernetes context catalog for provider %q", provider)
		}
	}
	return resolved, nil
}

func resolveKubernetesGrant(grants []BrokerGrantIntent, provider string, contexts []string, authorization *BrokerGrantAuthorization) error {
	for index := range grants {
		grant := &grants[index]
		if grant.Provider != provider || grant.Purpose != "catalog" {
			continue
		}
		if !grant.AllContexts || len(grant.Resources) != 0 || grant.Authorization != nil {
			return fmt.Errorf("compiled Kubernetes grant for provider %q is inconsistent", provider)
		}
		grant.Resources = append([]string(nil), contexts...)
		grant.Authorization = cloneGrantAuthorization(authorization)
		return nil
	}
	return fmt.Errorf("compiled Kubernetes grant for provider %q is missing", provider)
}

func normalizeDomains(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if normalized, ok := normalizeDomain(value); ok {
			result = append(result, normalized)
		}
	}
	sort.Strings(result)
	return result
}

func cloneBrokerGrants(input []BrokerGrantIntent) []BrokerGrantIntent {
	result := make([]BrokerGrantIntent, len(input))
	for index, grant := range input {
		result[index] = BrokerGrantIntent{Provider: grant.Provider, Preset: grant.Preset, Mediation: cloneMediation(grant.Mediation), Purpose: grant.Purpose, Repositories: append([]string(nil), grant.Repositories...), Resources: append([]string(nil), grant.Resources...), AllContexts: grant.AllContexts, Permissions: sortedMap(grant.Permissions), Authorization: cloneGrantAuthorization(grant.Authorization)}
	}
	return result
}

func compileBrokerGrants(m Manifest, profileName string) []BrokerGrantIntent {
	type group struct {
		provider     string
		permissions  map[string]string
		repositories map[string]struct{}
	}
	groups := map[string]*group{}
	add := func(repositoryName string) {
		repository := compileRepository(repositoryName, m.Repositories[repositoryName])
		provider := repositoryProvider(repository)
		if provider == "" || repository.BrokerRepository == "" {
			return
		}
		permissions := repositoryPermissions(m.Repositories[repositoryName], m.Accounts)
		encoded, _ := json.Marshal(permissions)
		key := provider + "\x00" + string(encoded)
		if groups[key] == nil {
			groups[key] = &group{provider, permissions, map[string]struct{}{}}
		}
		groups[key].repositories[repository.BrokerRepository] = struct{}{}
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
	result := make([]BrokerGrantIntent, 0, len(groups)+1)
	if runtimeAccount := m.Profiles[profileName].Runtime.Account; runtimeAccount != "" {
		result = append(result, BrokerGrantIntent{Provider: runtimeAccount, Preset: m.Accounts[runtimeAccount].Preset, Purpose: "runtime-injection"})
	}
	accesses := append([]KubernetesAccess(nil), m.Profiles[profileName].Kubernetes...)
	sort.Slice(accesses, func(i, j int) bool { return accesses[i].Provider < accesses[j].Provider })
	for _, access := range accesses {
		contexts := append([]string(nil), access.Contexts...)
		sort.Strings(contexts)
		allContexts := access.AllContexts != nil && *access.AllContexts
		var authorization *BrokerGrantAuthorization
		if !allContexts {
			authorization = resolveKubernetesAuthorization(access.Authorization, contexts)
		}
		result = append(result, BrokerGrantIntent{Provider: access.Provider, Preset: "kubeconfig", Purpose: "catalog", Resources: contexts, AllContexts: allContexts, Authorization: authorization})
	}
	for _, key := range SortedNames(groups) {
		entry := groups[key]
		grant := BrokerGrantIntent{Provider: entry.provider, Purpose: "repository", Repositories: SortedNames(entry.repositories), Permissions: entry.permissions}
		if account, ok := m.Accounts[entry.provider]; ok {
			grant.Preset = account.Preset
		} else {
			mediation := m.BrokerProviders[entry.provider].Mediation
			grant.Mediation = &mediation
		}
		result = append(result, grant)
	}
	return result
}

func resolveKubernetesAuthorization(policy *KubernetesAuthorization, contexts []string) *BrokerGrantAuthorization {
	if policy == nil {
		return nil
	}
	if policy.Preset == "observe" {
		resolved := &BrokerGrantAuthorization{DefaultAction: "deny", Rules: make([]BrokerGrantAuthorizationRule, 0, len(contexts))}
		for _, contextName := range contexts {
			resolved.Rules = append(resolved.Rules, BrokerGrantAuthorizationRule{Operation: "observe", Resource: "context/" + contextName})
		}
		return resolved
	}
	resolved := &BrokerGrantAuthorization{DefaultAction: policy.DefaultAction, Rules: make([]BrokerGrantAuthorizationRule, len(policy.Rules))}
	for index, rule := range policy.Rules {
		resolved.Rules[index] = BrokerGrantAuthorizationRule{Operation: rule.Operation, Resource: rule.Resource}
	}
	return resolved
}

func cloneGrantAuthorization(policy *BrokerGrantAuthorization) *BrokerGrantAuthorization {
	if policy == nil {
		return nil
	}
	result := &BrokerGrantAuthorization{DefaultAction: policy.DefaultAction, Rules: make([]BrokerGrantAuthorizationRule, len(policy.Rules))}
	copy(result.Rules, policy.Rules)
	return result
}

func repositoryPermissions(repository Repository, accounts map[string]Account) map[string]string {
	if repository.Access != nil {
		return sortedMap(repository.Access.Permissions)
	}
	if repository.Account != "" && accounts[repository.Account].Preset == "github-app" {
		return map[string]string{"contents": "write", "pull_requests": "write"}
	}
	return nil
}

func defaultCredentialProvider(m Manifest, profileName string) string {
	if configured := m.Profiles[profileName].DefaultCredentialProvider; configured != "" {
		return configured
	}
	providers := profileRepositoryProviders(m, profileName)
	if len(providers) == 1 {
		return providers[0]
	}
	return ""
}

func compileRepository(name string, repository Repository) ControllerRepositoryIntent {
	result := ControllerRepositoryIntent{Name: name, URL: repository.URL, CheckoutTarget: repository.CheckoutTarget, BrokerRepository: repository.BrokerRepository, Path: repository.Path, Upstream: repository.Upstream, Account: repository.Account, CredentialProvider: repository.CredentialProvider}
	if repository.GitHub != "" {
		result.URL = "https://github.com/" + repository.GitHub + ".git"
		result.CheckoutTarget = "github.com/" + repository.GitHub
		if repository.Account != "" {
			result.BrokerRepository = repository.GitHub
		}
	}
	return result
}

func repositoryProvider(repository ControllerRepositoryIntent) string {
	if repository.CredentialProvider != "" {
		return repository.CredentialProvider
	}
	return repository.Account
}

func cloneMediation(value *BrokerProviderMediation) *BrokerProviderMediation {
	if value == nil {
		return nil
	}
	result := *value
	result.Hosts = append([]string(nil), value.Hosts...)
	return &result
}

func sortedMap[T any](input map[string]T) map[string]T {
	if input == nil {
		return nil
	}
	result := make(map[string]T, len(input))
	for _, key := range SortedNames(input) {
		result[key] = input[key]
	}
	return result
}

func cloneConfig(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	result := make(map[string]any, len(input))
	for key, value := range input {
		result[key] = cloneConfigValue(value)
	}
	return result
}

func cloneConfigValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneConfig(typed)
	case []any:
		result := make([]any, len(typed))
		for index := range typed {
			result[index] = cloneConfigValue(typed[index])
		}
		return result
	default:
		return value
	}
}

// CanonicalJSON is the stable serialization used for equality, hashing, and
// handoff to the private generated-config volume owned by later slices.
func (c Compiled) CanonicalJSON() ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(c); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}
