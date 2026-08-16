// Package config renders the existing local service contracts from compiled
// local-manifest intent. These documents are private packaging details, not new
// protocols.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
	plancontract "github.com/mirkoSekulic/nvt-agent/localplatform/plan"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

const controllerAPIVersion = "nvt.local-platform/v1"

type Instructions map[string]string

type nativeConfiguration struct {
	APIVersion        string                         `json:"api_version"`
	Defaults          resolvedrun.PlatformDefaults   `json:"defaults"`
	Profiles          []resolvedrun.Profile          `json:"profiles"`
	Workflows         []resolvedrun.Workflow         `json:"workflows"`
	ExecutionBackends []resolvedrun.ExecutionBackend `json:"execution_backends"`
	RetentionPolicies []resolvedrun.RetentionPolicy  `json:"retention_policies"`
	Workstations      []workstation                  `json:"workstations,omitempty"`
	Schedules         []schedule                     `json:"schedules,omitempty"`
}

type workstation struct {
	Name, Profile, Workflow, Retention, Backend string
	Principal                                   resolvedrun.Principal `json:"principal"`
}

func (value workstation) MarshalJSON() ([]byte, error) {
	type document struct {
		Name      string                `json:"name"`
		Principal resolvedrun.Principal `json:"principal"`
		Profile   string                `json:"profile"`
		Workflow  string                `json:"workflow"`
		Retention string                `json:"retention"`
		Backend   string                `json:"backend"`
	}
	return json.Marshal(document{value.Name, value.Principal, value.Profile, value.Workflow, value.Retention, value.Backend})
}

type schedule struct {
	Name      string             `json:"name"`
	Producers []scheduleProducer `json:"producers"`
}
type scheduleProducer struct {
	Identity                string              `json:"identity"`
	TokenFile               string              `json:"token_file"`
	AllowedPrincipalIssuers []string            `json:"allowed_principal_issuers"`
	Selections              []scheduleSelection `json:"selections"`
	DefaultWorkflow         string              `json:"default_workflow"`
	Retention               string              `json:"retention"`
	Backend                 string              `json:"backend"`
}
type scheduleSelection struct {
	Profile  string `json:"profile"`
	Workflow string `json:"workflow"`
}

// Controller renders the strict native controller document already consumed
// by nvt-local-controller.
func Controller(compiled manifest.Compiled, instructions Instructions) ([]byte, error) {
	if compiled.Version != manifest.APIVersion || compiled.Controller.Owner != "local-controller" {
		return nil, errors.New("compiled controller intent is invalid")
	}
	profiles := map[string]manifest.ControllerProfileIntent{}
	accounts := accountMap(compiled)
	repositories := repositoryMap(compiled)
	result := nativeConfiguration{
		APIVersion: controllerAPIVersion,
		Defaults: resolvedrun.PlatformDefaults{
			Image:       "nvt-agent-runtime:latest",
			Runtime:     resolvedrun.Runtime{Type: "shell", Autonomy: "interactive", User: "root"},
			AgentConfig: mustJSON(map[string]any{"runtime": map[string]any{"command": "bash", "args": []string{"-l"}, "resume": map[string]any{"command": "bash", "args": []string{"-l"}}}, "plugins": []any{}}),
		},
		ExecutionBackends: []resolvedrun.ExecutionBackend{{Name: "local-docker", Kind: "container"}},
		RetentionPolicies: []resolvedrun.RetentionPolicy{
			{Name: "persistent", Persistence: resolvedrun.Persistence{Workspace: true, RuntimeState: true, DockerData: true}},
			{Name: "retained", Persistence: resolvedrun.Persistence{Workspace: true, RuntimeState: true, DockerData: true}, TTL: resolvedrun.TTL{ActiveSeconds: 86400}},
			{Name: "disposable", TTL: resolvedrun.TTL{ActiveSeconds: 3600, CompletedSeconds: 300, FailedSeconds: 900, RunRetentionSeconds: 86400}},
		},
	}
	for _, intent := range compiled.Controller.Profiles {
		profiles[intent.Name] = intent
		profile, err := renderProfile(intent, accounts, repositories, instructions[intent.Name])
		if err != nil {
			return nil, err
		}
		result.Profiles = append(result.Profiles, profile)
	}
	for _, item := range compiled.Controller.Workflows {
		profile, ok := profiles[item.Workflow.Profile]
		repository, repositoryOK := repositories[item.Workflow.Repository]
		if !ok || !repositoryOK {
			return nil, errors.New("compiled workflow references are invalid")
		}
		result.Workflows = append(result.Workflows, resolvedrun.Workflow{Name: item.Name, Repositories: []resolvedrun.Repository{renderRepository(repository, profile, accounts)}})
	}
	for _, item := range compiled.Controller.Workstations {
		profile, ok := profiles[item.Profile]
		if !ok {
			return nil, errors.New("compiled workstation profile is invalid")
		}
		workflowName := workstationWorkflowName(item.Name)
		workflow := resolvedrun.Workflow{Name: workflowName}
		for _, name := range item.Repositories {
			repository, ok := repositories[name]
			if !ok {
				return nil, errors.New("compiled workstation repository is invalid")
			}
			workflow.Repositories = append(workflow.Repositories, renderRepository(repository, profile, accounts))
		}
		result.Workflows = append(result.Workflows, workflow)
		result.Workstations = append(result.Workstations, workstation{
			Name: item.Name, Profile: item.Profile, Workflow: workflowName, Retention: "persistent", Backend: "local-docker",
			Principal: resolvedrun.Principal{Issuer: "https://local.nvt.invalid", Subject: "workstation-" + item.Name, DisplayName: item.Name},
		})
	}
	workflowProfiles := map[string]string{}
	workflowRetentions := map[string]string{}
	for _, item := range compiled.Controller.Workflows {
		workflowProfiles[item.Name] = item.Workflow.Profile
		workflowRetentions[item.Name] = item.Workflow.Retention
	}
	for _, admission := range compiled.Controller.ProducerAdmissions {
		profile := workflowProfiles[admission.Workflow]
		retention := workflowRetentions[admission.Workflow]
		if profile == "" || retention == "" {
			return nil, errors.New("compiled producer admission is invalid")
		}
		result.Schedules = append(result.Schedules, schedule{Name: admission.Producer, Producers: []scheduleProducer{{
			Identity: admission.Identity, TokenFile: plancontract.PrivateTarget(admission.Credential),
			AllowedPrincipalIssuers: append([]string(nil), admission.AllowedPrincipalIssuers...),
			Selections:              []scheduleSelection{{Profile: profile, Workflow: admission.Workflow}}, DefaultWorkflow: admission.Workflow,
			Retention: retention, Backend: "local-docker",
		}}})
	}
	sort.Slice(result.Workflows, func(i, j int) bool { return result.Workflows[i].Name < result.Workflows[j].Name })
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > manifest.MaxDocumentBytes {
		return nil, errors.New("controller configuration is unavailable")
	}
	return encoded, nil
}

func renderProfile(intent manifest.ControllerProfileIntent, accounts map[string]manifest.Account, repositories map[string]manifest.ControllerRepositoryIntent, instructions string) (resolvedrun.Profile, error) {
	runtimeType := intent.Profile.Runtime.Preset
	autonomy := "interactive"
	if intent.Profile.Runtime.Autonomy == "trusted-local" {
		autonomy = "trusted-local"
	}
	command := runtimeType
	args := []string{}
	resumeArgs := []string{}
	switch runtimeType {
	case "codex":
		if autonomy == "trusted-local" {
			args = append(args, "--dangerously-bypass-approvals-and-sandbox")
			resumeArgs = append(resumeArgs, "--dangerously-bypass-approvals-and-sandbox")
		}
	case "claude":
		if autonomy == "trusted-local" {
			args = append(args, "--dangerously-skip-permissions")
			resumeArgs = append(resumeArgs, "--dangerously-skip-permissions")
		}
	case "shell":
		command = "bash"
		args = []string{"-lc", "while :; do sleep 3600; done"}
		resumeArgs = append([]string(nil), args...)
	default:
		return resolvedrun.Profile{}, errors.New("compiled runtime preset is invalid")
	}
	plugins := make([]any, 0, len(intent.Profile.Plugins))
	for _, name := range intent.Profile.Plugins {
		plugins = append(plugins, map[string]any{"name": name, "source": "builtin"})
	}
	agentConfig := mustJSON(map[string]any{
		"runtime":     map[string]any{"command": command, "args": args, "resume": map[string]any{"command": command, "args": resumeArgs}},
		"tools":       map[string]any{"packages": intent.Profile.Tools.Packages, "mise": intent.Profile.Tools.Mise},
		"code-server": map[string]any{"agentTerminal": map[string]any{"openOnStartup": intent.Profile.Editor.Preset != "none"}},
		"plugins":     plugins,
	})
	profile := resolvedrun.Profile{
		Name: intent.Name, Runtime: &resolvedrun.Runtime{Type: runtimeType, Autonomy: autonomy, User: "root", Container: &resolvedrun.RuntimeContainer{Capabilities: append([]string(nil), intent.Profile.Capabilities...)}, Docker: &resolvedrun.RuntimeDocker{}},
		AgentConfig: agentConfig, WorkspaceInstructions: instructions, AllowedBackends: []string{"local-docker"}, DefaultBackend: "local-docker", AllowedRetentions: []string{"persistent", "retained", "disposable"},
	}
	grantProviders := map[string]struct{}{}
	repositoryGrants := map[string]struct {
		preset       string
		repositories []string
	}{}
	for _, grant := range intent.BrokerGrants {
		if grant.Purpose == "runtime-injection" {
			provider := grant.Account
			profile.Broker.Grants = append(profile.Broker.Grants, runtimeGrant(provider, grant.Preset))
			grantProviders[provider] = struct{}{}
			profile.Egress.ProxyProvider = provider
			continue
		}
		for _, repositoryName := range grant.Repositories {
			repository := brokerRepositoryByIdentity(repositories, repositoryName, grant.Account)
			provider := providerFor(grant.Account, repository.BrokerRepository, accounts[grant.Account])
			entry := repositoryGrants[provider]
			entry.preset = grant.Preset
			entry.repositories = append(entry.repositories, repository.BrokerRepository)
			repositoryGrants[provider] = entry
		}
	}
	for _, provider := range sortedNames(repositoryGrants) {
		entry := repositoryGrants[provider]
		sort.Strings(entry.repositories)
		profile.Broker.Grants = append(profile.Broker.Grants, repositoryGrant(provider, entry.preset, entry.repositories))
		grantProviders[provider] = struct{}{}
	}
	mappingTargets := map[string]map[string]struct{}{}
	for _, account := range intent.CredentialProviders {
		for _, repository := range repositories {
			if repository.Account != account.Name {
				continue
			}
			provider := providerFor(account.Name, repository.BrokerRepository, accounts[account.Name])
			if _, exists := repositoryGrants[provider]; !exists {
				continue
			}
			if mappingTargets[provider] == nil {
				mappingTargets[provider] = map[string]struct{}{}
			}
			mappingTargets[provider][repository.CheckoutTarget] = struct{}{}
		}
	}
	for _, provider := range sortedNames(mappingTargets) {
		profile.CredentialProviders = append(profile.CredentialProviders, resolvedrun.CredentialProviderMapping{
			Name: provider, BrokerProvider: provider, CredentialKind: "mediated", MatchTargets: sortedNames(mappingTargets[provider]),
		})
	}
	if len(profile.Broker.Grants) == 0 {
		profile.Egress = resolvedrun.Egress{Mode: "direct"}
	} else {
		if profile.Egress.ProxyProvider == "" {
			profile.Egress.ProxyProvider = profile.Broker.Grants[0].Provider
		}
		profile.Egress.Mode, profile.Egress.Transport, profile.Egress.Enforced, profile.Egress.PairedEgressRequired = "mediated", "transparent", true, true
		profile.Egress.AllowInsecureBroker = true
		profile.Egress.MaxConcurrentTunnels = 128
	}
	return profile, nil
}

func renderRepository(item manifest.ControllerRepositoryIntent, profile manifest.ControllerProfileIntent, accounts map[string]manifest.Account) resolvedrun.Repository {
	provider := ""
	if item.Account != "" {
		provider = providerFor(item.Account, item.BrokerRepository, accounts[item.Account])
	}
	return resolvedrun.Repository{
		CheckoutTarget: item.CheckoutTarget, BrokerRepository: item.BrokerRepository, URL: item.URL, Path: item.Path, Upstream: item.Upstream,
		CredentialProvider: provider, CredentialUsername: credentialUsername(accounts[item.Account]),
	}
}

func runtimeGrant(provider, preset string) resolvedrun.BrokerGrant {
	hosts := []string{"chatgpt.com:443"}
	if preset == "claude-oauth" {
		hosts = []string{"api.anthropic.com:443", "mcp-proxy.anthropic.com:443"}
	}
	return resolvedrun.BrokerGrant{Provider: provider, Capabilities: []string{"injection.headers"}, Materialization: "placeholder-file", EgressHosts: hosts}
}

func repositoryGrant(provider, preset string, repositories []string) resolvedrun.BrokerGrant {
	host := "github.com:443"
	if preset == "azure-devops-pat" {
		host = "dev.azure.com:443"
	}
	grant := resolvedrun.BrokerGrant{Provider: provider, Repositories: repositories, Capabilities: []string{"injection.headers"}, Materialization: "header-inject", EgressHosts: []string{host}, Git: true}
	if preset == "github-app" {
		grant.Preparations = []string{"identity"}
		grant.Permissions = map[string]string{"contents": "write"}
	}
	return grant
}

// Broker renders the existing broker provider document. Secret values are
// referenced only by fixed in-container file paths.
func Broker(compiled manifest.Compiled) ([]byte, error) {
	if compiled.Version != manifest.APIVersion || compiled.Broker.Owner != "broker" {
		return nil, errors.New("compiled broker intent is invalid")
	}
	providers := []map[string]any{}
	for _, named := range compiled.Broker.Accounts {
		account := named.Account
		switch account.Preset {
		case "codex-oauth":
			providers = append(providers, map[string]any{"name": named.Name, "plugin": "codex-oauth", "config": map[string]any{
				"auth-file": "/private/portal/" + plancontract.CredentialSlotName(named.Name) + ".json", "injection-hosts": []string{"chatgpt.com"},
			}})
		case "claude-oauth":
			providers = append(providers, map[string]any{"name": named.Name, "plugin": "claude-oauth", "config": map[string]any{
				"credentials-file": "/private/portal/" + plancontract.CredentialSlotName(named.Name) + ".json", "injection-hosts": []string{"api.anthropic.com", "mcp-proxy.anthropic.com"},
				"injection-extra-headers": map[string]string{"anthropic-beta": "oauth-2025-04-20"},
				"placeholder-file":        map[string]any{"path": ".claude/.credentials.json", "hosts": []string{"api.anthropic.com", "mcp-proxy.anthropic.com"}},
			}})
		case "github-app":
			appID, parseErr := strconv.Atoi(account.AppID)
			if parseErr != nil || appID <= 0 {
				return nil, errors.New("compiled GitHub App account is invalid")
			}
			owners := sortedNames(account.Installations)
			for _, owner := range owners {
				installationID, parseErr := strconv.Atoi(account.Installations[owner])
				if parseErr != nil || installationID <= 0 {
					return nil, errors.New("compiled GitHub App installation is invalid")
				}
				provider := named.Name
				if len(owners) > 1 {
					provider = providerFor(named.Name, owner+"/repository", account)
				}
				allowed := brokerRepositoriesFor(compiled, named.Name, owner)
				providers = append(providers, map[string]any{"name": provider, "plugin": "github-app", "config": map[string]any{
					"app-id": appID, "installation-id": installationID, "private-key-file": plancontract.PrivateTarget(account.PrivateKeySecret), "injection-hosts": []string{"github.com"},
				}, "allow": map[string]any{"repositories": allowed, "permissions": map[string]string{"contents": "write", "pull_requests": "write", "workflows": "write"}, "methods": []string{"GET", "POST", "PUT", "PATCH", "DELETE"}}})
			}
		case "github-pat", "azure-devops-pat":
			host, mode := "github.com", "github"
			if account.Preset == "azure-devops-pat" {
				host, mode = "dev.azure.com", "literal"
			}
			providers = append(providers, map[string]any{"name": named.Name, "plugin": "token", "config": map[string]any{
				"token-file": plancontract.PrivateTarget(account.TokenSecret), "injection-hosts": []string{host}, "injection-git": true, "injection-basic-username": "git", "target-mode": mode,
			}, "allow": map[string]any{"repositories": brokerRepositoriesFor(compiled, named.Name, "")}})
		default:
			return nil, errors.New("compiled broker account preset is invalid")
		}
	}
	encoded, err := json.Marshal(map[string]any{"provider-plugins": []any{}, "providers": providers})
	if err != nil || len(encoded) > manifest.MaxDocumentBytes {
		return nil, errors.New("broker configuration is unavailable")
	}
	return encoded, nil
}

func Gateway(compiled manifest.Compiled) ([]byte, error) {
	if compiled.Version != manifest.APIVersion || compiled.Gateway.Owner != "gateway" {
		return nil, errors.New("compiled gateway intent is invalid")
	}
	return json.Marshal(compiled.Gateway)
}

func accountMap(compiled manifest.Compiled) map[string]manifest.Account {
	result := map[string]manifest.Account{}
	for _, item := range compiled.Broker.Accounts {
		result[item.Name] = item.Account
	}
	return result
}

func repositoryMap(compiled manifest.Compiled) map[string]manifest.ControllerRepositoryIntent {
	result := map[string]manifest.ControllerRepositoryIntent{}
	for _, item := range compiled.Controller.Repositories {
		result[item.Name] = item
	}
	return result
}

func providerFor(account, repository string, value manifest.Account) string {
	if value.Preset != "github-app" || len(value.Installations) <= 1 {
		return account
	}
	owner := strings.SplitN(repository, "/", 2)[0]
	digest := sha256.Sum256([]byte(strings.ToLower(owner)))
	return account + "-" + hex.EncodeToString(digest[:4])
}

func brokerRepositoriesFor(compiled manifest.Compiled, account, owner string) []string {
	result := []string{}
	for _, repository := range compiled.Broker.Repositories {
		if repository.Account != account || repository.BrokerRepository == "" {
			continue
		}
		if owner != "" && !strings.EqualFold(strings.SplitN(repository.BrokerRepository, "/", 2)[0], owner) {
			continue
		}
		result = append(result, repository.BrokerRepository)
	}
	sort.Strings(result)
	return result
}

func brokerRepositoryByIdentity(repositories map[string]manifest.ControllerRepositoryIntent, identity, account string) manifest.ControllerRepositoryIntent {
	for _, repository := range repositories {
		if repository.BrokerRepository == identity && repository.Account == account {
			return repository
		}
	}
	return manifest.ControllerRepositoryIntent{BrokerRepository: identity, Account: account}
}

func credentialUsername(account manifest.Account) string {
	if account.Preset == "github-app" {
		return "x-access-token"
	}
	if account.Preset == "github-pat" || account.Preset == "azure-devops-pat" {
		return "git"
	}
	return ""
}

func workstationWorkflowName(name string) string {
	digest := sha256.Sum256([]byte("nvt.local-workstation-workflow/v1\x00" + name))
	return "ws-" + hex.EncodeToString(digest[:12])
}

func sortedNames[V any](values map[string]V) []string {
	result := make([]string, 0, len(values))
	for name := range values {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func mustJSON(value any) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}
