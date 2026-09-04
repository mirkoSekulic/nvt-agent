// Package config renders the existing local service contracts from compiled
// local-manifest intent. These documents are private packaging details, not new
// protocols.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	Reconciliation    reconciliation                 `json:"reconciliation,omitempty"`
	Defaults          resolvedrun.PlatformDefaults   `json:"defaults"`
	Profiles          []resolvedrun.Profile          `json:"profiles"`
	Workflows         []resolvedrun.Workflow         `json:"workflows"`
	ExecutionBackends []resolvedrun.ExecutionBackend `json:"execution_backends"`
	RetentionPolicies []resolvedrun.RetentionPolicy  `json:"retention_policies"`
	Workstations      []workstation                  `json:"workstations,omitempty"`
	Schedules         []schedule                     `json:"schedules,omitempty"`
}

type reconciliation struct {
	Prune                    bool `json:"prune,omitempty"`
	ReplaceOnImmutableChange bool `json:"replace_on_immutable_change,omitempty"`
	DestructiveAcknowledged  bool `json:"destructive_acknowledged,omitempty"`
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
	retentionPolicies, retentionNames, err := renderRetentionPolicies(compiled.Controller.RetentionPolicies)
	if err != nil {
		return nil, err
	}
	profiles := map[string]manifest.ControllerProfileIntent{}
	accounts := accountMap(compiled)
	repositories := repositoryMap(compiled)
	result := nativeConfiguration{
		APIVersion:     controllerAPIVersion,
		Reconciliation: reconciliation{Prune: compiled.Controller.Reconciliation.Prune, ReplaceOnImmutableChange: compiled.Controller.Reconciliation.ReplaceOnImmutableChange, DestructiveAcknowledged: compiled.Controller.DestructiveAcknowledged},
		Defaults: resolvedrun.PlatformDefaults{
			Image:       "nvt-agent-runtime:latest",
			Runtime:     resolvedrun.Runtime{Type: "shell", Autonomy: "interactive", User: "root"},
			AgentConfig: mustJSON(map[string]any{"runtime": map[string]any{"command": "bash", "args": []string{"-l"}, "resume": map[string]any{"command": "bash", "args": []string{"-l"}}}, "plugins": []any{}}),
		},
		ExecutionBackends: []resolvedrun.ExecutionBackend{{Name: "local-docker", Kind: "container"}},
		RetentionPolicies: retentionPolicies,
	}
	for _, intent := range compiled.Controller.Profiles {
		profiles[intent.Name] = intent
		profile, err := renderProfile(intent, accounts, repositories, retentionNames, instructions[intent.Name])
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
		lifecycle := &resolvedrun.Lifecycle{CompleteOn: append([]string(nil), item.Workflow.Lifecycle.CompleteOn...), FailOn: append([]string(nil), item.Workflow.Lifecycle.FailOn...)}
		if len(lifecycle.CompleteOn) == 0 && len(lifecycle.FailOn) == 0 {
			lifecycle = nil
		}
		result.Workflows = append(result.Workflows, resolvedrun.Workflow{Name: item.Name, Repositories: []resolvedrun.Repository{renderRepository(repository, profile, accounts)}, Lifecycle: lifecycle})
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
		for command := range admission.CommandWorkflows {
			if command != "pr-create" && command != "review" && command != "run" && command != "pr-continue" {
				return nil, errors.New("compiled producer admission has unsupported command mapping")
			}
		}
		profile := workflowProfiles[admission.Workflow]
		retention := workflowRetentions[admission.Workflow]
		if profile == "" || retention == "" {
			return nil, errors.New("compiled producer admission is invalid")
		}
		selected := map[string]struct{}{admission.Workflow: {}}
		for _, workflow := range admission.CommandWorkflows {
			selected[workflow] = struct{}{}
		}
		selections := make([]scheduleSelection, 0, len(selected))
		for workflow := range selected {
			selectedProfile, ok := workflowProfiles[workflow]
			if !ok || workflowRetentions[workflow] != retention {
				return nil, errors.New("compiled producer admission has incompatible workflow policy")
			}
			selections = append(selections, scheduleSelection{Profile: selectedProfile, Workflow: workflow})
		}
		sort.Slice(selections, func(i, j int) bool { return selections[i].Workflow < selections[j].Workflow })
		result.Schedules = append(result.Schedules, schedule{Name: admission.Producer, Producers: []scheduleProducer{{
			Identity: admission.Identity, TokenFile: plancontract.PrivateTarget(admission.Credential),
			AllowedPrincipalIssuers: append([]string(nil), admission.AllowedPrincipalIssuers...),
			Selections:              selections, DefaultWorkflow: admission.Workflow,
			Retention: retention, Backend: "local-docker",
		}}})
	}
	sort.Slice(result.Workflows, func(i, j int) bool { return result.Workflows[i].Name < result.Workflows[j].Name })
	if validateNativeProjection(result) != nil {
		return nil, errors.New("controller configuration is invalid")
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > manifest.MaxDocumentBytes {
		return nil, errors.New("controller configuration is unavailable")
	}
	return encoded, nil
}

func validateNativeProjection(configuration nativeConfiguration) error {
	if (len(configuration.Workstations) == 0 && len(configuration.Schedules) == 0 && !configuration.Reconciliation.Prune) || len(configuration.Workstations) > 128 || len(configuration.Schedules) > 64 {
		return errors.New("local scheduling projection exceeds native bounds")
	}
	resolver, err := resolvedrun.NewResolver(resolvedrun.TrustedConfiguration{
		Defaults: configuration.Defaults, Profiles: configuration.Profiles, Workflows: configuration.Workflows,
		ExecutionBackends: configuration.ExecutionBackends, RetentionPolicies: configuration.RetentionPolicies,
	})
	if err != nil {
		return err
	}
	for _, item := range configuration.Workstations {
		authorization := resolvedrun.AuthorizationContext{
			Principal: item.Principal, Selections: []resolvedrun.AuthorizedSelection{{Profile: item.Profile, Workflows: []string{item.Workflow}}},
		}
		resolved, err := resolver.Resolve(authorization, resolvedrun.LocalRunRequest{
			RunID: item.Name, Profile: item.Profile, Workflow: item.Workflow, Retention: item.Retention, Backend: item.Backend,
		})
		if err != nil || !resolved.Persistence.Workspace || !resolved.Persistence.RuntimeState || !resolved.Persistence.DockerData || resolved.TTL != (resolvedrun.TTL{}) {
			return errors.New("workstation projection is invalid")
		}
	}
	for _, item := range configuration.Schedules {
		if len(item.Producers) == 0 || len(item.Producers) > 32 {
			return errors.New("schedule projection is invalid")
		}
		for _, producer := range item.Producers {
			if producer.Identity == "" || producer.TokenFile == "" || len(producer.AllowedPrincipalIssuers) == 0 || len(producer.Selections) == 0 || len(producer.Selections) > 32 || producer.DefaultWorkflow == "" || producer.Retention == "" || producer.Backend == "" {
				return errors.New("schedule producer projection is invalid")
			}
			for _, selection := range producer.Selections {
				authorization := resolvedrun.AuthorizationContext{
					Principal:  resolvedrun.Principal{Issuer: producer.AllowedPrincipalIssuers[0], Subject: "projection-validation"},
					Selections: []resolvedrun.AuthorizedSelection{{Profile: selection.Profile, Workflows: []string{selection.Workflow}}},
				}
				if _, err := resolver.Resolve(authorization, resolvedrun.LocalRunRequest{
					RunID: "projection-validation", Profile: selection.Profile, Workflow: selection.Workflow, Retention: producer.Retention, Backend: producer.Backend,
				}); err != nil {
					return errors.New("schedule selection projection is invalid")
				}
			}
		}
	}
	return nil
}

func renderRetentionPolicies(policies []manifest.NamedRetentionPolicy) ([]resolvedrun.RetentionPolicy, []string, error) {
	if len(policies) == 0 {
		return nil, nil, errors.New("compiled retention policies are missing")
	}
	result := make([]resolvedrun.RetentionPolicy, 0, len(policies))
	names := make([]string, 0, len(policies))
	previous := ""
	for _, item := range policies {
		if item.Name == "" || previous != "" && item.Name <= previous {
			return nil, nil, errors.New("compiled retention policies are invalid")
		}
		previous = item.Name
		names = append(names, item.Name)
		result = append(result, resolvedrun.RetentionPolicy{
			Name: item.Name,
			Persistence: resolvedrun.Persistence{
				Workspace: item.Policy.Persistence.Workspace, RuntimeState: item.Policy.Persistence.RuntimeState, DockerData: item.Policy.Persistence.DockerData,
			},
			TTL: resolvedrun.TTL{
				ActiveSeconds: item.Policy.TTL.ActiveSeconds, CompletedSeconds: item.Policy.TTL.CompletedSeconds,
				FailedSeconds: item.Policy.TTL.FailedSeconds, RunRetentionSeconds: item.Policy.TTL.RunRetentionSeconds,
			},
		})
	}
	return result, names, nil
}

func renderProfile(intent manifest.ControllerProfileIntent, accounts map[string]manifest.Account, repositories map[string]manifest.ControllerRepositoryIntent, retentionNames []string, instructions string) (resolvedrun.Profile, error) {
	runtimeType := intent.Profile.Runtime.Preset
	autonomy := ""
	switch intent.Profile.Runtime.Autonomy {
	case "trusted-local":
		autonomy = "trusted-local"
	case "approval-required":
		autonomy = "interactive"
	default:
		return resolvedrun.Profile{}, errors.New("compiled runtime autonomy is unsupported")
	}
	command := runtimeType
	args := []string{}
	resumeArgs := []string(nil)
	switch runtimeType {
	case "codex":
		resumeArgs = []string{"resume", "--last"}
		if autonomy == "trusted-local" {
			args = append(args, "--dangerously-bypass-approvals-and-sandbox")
			resumeArgs = append(resumeArgs, "--dangerously-bypass-approvals-and-sandbox")
		}
	case "claude":
		resumeArgs = []string{"--continue"}
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
	for _, plugin := range intent.Profile.Plugins {
		rendered := map[string]any{"name": plugin.Name, "source": "builtin"}
		if plugin.When != "" {
			rendered["when"] = plugin.When
		}
		if plugin.Restart != "" {
			rendered["restart"] = plugin.Restart
		}
		if len(plugin.Config) != 0 {
			rendered["config"] = plugin.Config
		}
		if plugin.Egress != nil {
			provider, err := pluginEgressProvider(intent, plugin.Egress.Provider, accounts, repositories)
			if err != nil {
				return resolvedrun.Profile{}, err
			}
			rendered["egress"] = map[string]any{"provider": provider}
		}
		plugins = append(plugins, rendered)
	}
	codeServerEnabled := intent.Profile.Editor.Preset != "none"
	codeServer := map[string]any{
		"agentTerminal": map[string]any{"openOnStartup": codeServerEnabled},
	}
	if codeServerEnabled {
		codeServer["settings"] = map[string]any{
			"overwrite": true,
			"values": map[string]any{
				"workbench.colorTheme":             "Default Dark Modern",
				"workbench.startupEditor":          "none",
				"security.workspace.trust.enabled": false,
				"extensions.ignoreRecommendations": true,
				"editor.minimap.enabled":           false,
				"keyboard.dispatch":                "keyCode",
			},
		}
	}
	agentConfig := mustJSON(map[string]any{
		"runtime":     map[string]any{"command": command, "args": args, "resume": map[string]any{"command": command, "args": resumeArgs}},
		"preseed":     runtimePreseed(runtimeType),
		"tools":       map[string]any{"packages": intent.Profile.Tools.Packages, "mise": intent.Profile.Tools.Mise},
		"code-server": codeServer,
		"plugins":     plugins,
	})
	profile := resolvedrun.Profile{
		Name: intent.Name, Runtime: &resolvedrun.Runtime{Type: runtimeType, Autonomy: autonomy, Model: intent.Profile.Runtime.Model, Effort: intent.Profile.Runtime.Effort, User: "root", Container: &resolvedrun.RuntimeContainer{Capabilities: append([]string(nil), intent.Profile.Capabilities...)}, Docker: &resolvedrun.RuntimeDocker{}},
		AgentConfig: agentConfig, WorkspaceInstructions: instructions, AllowedBackends: []string{"local-docker"}, DefaultBackend: "local-docker", AllowedRetentions: append([]string(nil), retentionNames...),
	}
	repositoryGrants := map[string]struct {
		preset       string
		mediation    *manifest.BrokerProviderMediation
		repositories []string
		permissions  map[string]string
	}{}
	for _, grant := range intent.BrokerGrants {
		if grant.Purpose == "runtime-injection" {
			provider := grant.Provider
			profile.Broker.Grants = append(profile.Broker.Grants, runtimeGrant(provider, grant.Preset))
			profile.Egress.ProxyProvider = provider
			continue
		}
		if grant.Purpose == "catalog" {
			if grant.AllContexts && len(grant.Resources) == 0 {
				return resolvedrun.Profile{}, errors.New("compiled Kubernetes all-context selection is unresolved")
			}
			profile.Broker.Grants = append(profile.Broker.Grants, kubeconfigGrant(grant.Provider, grant.Resources, grant.Authorization))
			continue
		}
		for _, repositoryName := range grant.Repositories {
			repository := brokerRepositoryByIdentity(repositories, repositoryName, grant.Provider)
			provider := grant.Provider
			if account, ok := accounts[grant.Provider]; ok {
				provider = providerFor(grant.Provider, repository.BrokerRepository, account)
			}
			key := provider + "\x00" + permissionsKey(grant.Permissions)
			entry := repositoryGrants[key]
			entry.preset = grant.Preset
			entry.mediation = grant.Mediation
			entry.repositories = append(entry.repositories, repository.BrokerRepository)
			entry.permissions = grant.Permissions
			repositoryGrants[key] = entry
		}
	}
	for _, key := range sortedNames(repositoryGrants) {
		entry := repositoryGrants[key]
		provider := strings.SplitN(key, "\x00", 2)[0]
		sort.Strings(entry.repositories)
		profile.Broker.Grants = append(profile.Broker.Grants, repositoryGrant(provider, entry.preset, entry.mediation, entry.repositories, entry.permissions))
	}
	mappingTargets := map[string]map[string]struct{}{}
	defaultProviders := map[string]struct{}{}
	for _, account := range intent.CredentialProviders {
		for _, repository := range repositories {
			if repositoryProvider(repository) != account.Name {
				continue
			}
			provider := account.Name
			if value, ok := accounts[account.Name]; ok {
				provider = providerFor(account.Name, repository.BrokerRepository, value)
			}
			found := false
			for key := range repositoryGrants {
				if strings.HasPrefix(key, provider+"\x00") {
					found = true
					break
				}
			}
			if !found {
				continue
			}
			if mappingTargets[provider] == nil {
				mappingTargets[provider] = map[string]struct{}{}
			}
			mappingTargets[provider][repository.CheckoutTarget] = struct{}{}
			if account.Name == intent.DefaultCredentialProvider {
				defaultProviders[provider] = struct{}{}
			}
		}
	}
	for _, provider := range sortedNames(mappingTargets) {
		profile.CredentialProviders = append(profile.CredentialProviders, resolvedrun.CredentialProviderMapping{
			Name: provider, BrokerProvider: provider, CredentialKind: "mediated", MatchTargets: sortedNames(mappingTargets[provider]),
		})
	}
	if intent.DefaultCredentialProvider != "" {
		providers := sortedNames(defaultProviders)
		if len(providers) != 1 {
			return resolvedrun.Profile{}, errors.New("compiled default credential provider is ambiguous")
		}
		profile.DefaultCredentialProvider = providers[0]
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
	if intent.Profile.Egress != nil && intent.Profile.Egress.DomainPolicy != nil {
		if profile.Egress.Mode != "mediated" {
			return resolvedrun.Profile{}, errors.New("egress domain policy requires a mediated profile")
		}
		policy := intent.Profile.Egress.DomainPolicy
		profile.Egress.DomainPolicy = &resolvedrun.DomainPolicy{
			DefaultAction: policy.DefaultAction,
			Allow:         append([]string(nil), policy.Allow...),
			Deny:          append([]string(nil), policy.Deny...),
		}
	}
	return profile, nil
}

func pluginEgressProvider(intent manifest.ControllerProfileIntent, account string, accounts map[string]manifest.Account, repositories map[string]manifest.ControllerRepositoryIntent) (string, error) {
	provider := ""
	for _, grant := range intent.BrokerGrants {
		if grant.Provider != account {
			continue
		}
		candidates := []string{account}
		if grant.Purpose != "runtime-injection" {
			candidates = candidates[:0]
			for _, repositoryName := range grant.Repositories {
				repository := brokerRepositoryByIdentity(repositories, repositoryName, account)
				candidates = append(candidates, providerFor(account, repository.BrokerRepository, accounts[account]))
			}
		}
		for _, candidate := range candidates {
			if provider != "" && provider != candidate {
				return "", errors.New("compiled plugin egress provider is ambiguous")
			}
			provider = candidate
		}
	}
	if provider == "" {
		return "", errors.New("compiled plugin egress provider is unavailable")
	}
	return provider, nil
}

func runtimePreseed(runtimeType string) map[string]any {
	files := []any{}
	switch runtimeType {
	case "codex":
		files = append(files, map[string]any{
			"path":      "$HOME/.codex/config.toml",
			"mode":      "0600",
			"overwrite": false,
			"content": "check_for_update_on_startup = false\n\n" +
				"[projects.\"/workspace\"]\ntrust_level = \"trusted\"\n\n" +
				"[notice]\nhide_rate_limit_model_nudge = true\n",
		})
	case "claude":
		files = append(files,
			map[string]any{
				"path":      "$HOME/.claude/settings.json",
				"mode":      "0600",
				"overwrite": false,
				"json": map[string]any{
					"theme":                             "dark-daltonized",
					"skipDangerousModePermissionPrompt": true,
				},
			},
			map[string]any{
				"path":      "$HOME/.claude.json",
				"mode":      "0600",
				"overwrite": false,
				"json": map[string]any{
					"hasCompletedOnboarding": true,
					"theme":                  "dark",
					"projects": map[string]any{
						"/workspace": map[string]any{"hasTrustDialogAccepted": true},
					},
				},
			},
		)
	}
	return map[string]any{"files": files}
}

func renderRepository(item manifest.ControllerRepositoryIntent, profile manifest.ControllerProfileIntent, accounts map[string]manifest.Account) resolvedrun.Repository {
	provider := ""
	username := ""
	if item.Account != "" {
		provider = providerFor(item.Account, item.BrokerRepository, accounts[item.Account])
		username = credentialUsername(accounts[item.Account])
	} else if item.CredentialProvider != "" {
		provider = item.CredentialProvider
		for _, candidate := range profile.CredentialProviders {
			if candidate.Name == provider {
				username = candidate.Username
				break
			}
		}
	}
	return resolvedrun.Repository{
		CheckoutTarget: item.CheckoutTarget, BrokerRepository: item.BrokerRepository, URL: item.URL, Path: item.Path, Upstream: item.Upstream,
		CredentialProvider: provider, CredentialUsername: username,
	}
}

func runtimeGrant(provider, preset string) resolvedrun.BrokerGrant {
	hosts := []string{"chatgpt.com:443", "api.openai.com:443", "auth.openai.com:443"}
	if preset == "claude-oauth" {
		hosts = []string{"api.anthropic.com:443", "mcp-proxy.anthropic.com:443"}
	}
	return resolvedrun.BrokerGrant{Provider: provider, Capabilities: []string{"injection.headers"}, Materialization: "placeholder-file", EgressHosts: hosts}
}

func kubeconfigGrant(provider string, contexts []string, authorization *manifest.BrokerGrantAuthorization) resolvedrun.BrokerGrant {
	hosts := make([]string, 0, len(contexts))
	for _, contextName := range contexts {
		digest := sha256.Sum256([]byte(provider + "\x00" + contextName))
		hosts = append(hosts, "k-"+hex.EncodeToString(digest[:10])+".kube.nvt.invalid:443")
	}
	grant := resolvedrun.BrokerGrant{
		Provider: provider, Resources: append([]string(nil), contexts...),
		Capabilities: []string{"catalog", "injection.headers"}, Preparations: []string{"catalog"},
		Materialization: "header-inject", EgressHosts: hosts,
	}
	if authorization != nil {
		grant.Authorization = &resolvedrun.BrokerGrantAuthorization{DefaultAction: authorization.DefaultAction}
		for _, rule := range authorization.Rules {
			grant.Authorization.Rules = append(grant.Authorization.Rules, resolvedrun.BrokerGrantAuthorizationRule{Operation: rule.Operation, Resource: rule.Resource})
		}
	}
	return grant
}

func repositoryGrant(provider, preset string, mediation *manifest.BrokerProviderMediation, repositories []string, permissions map[string]string) resolvedrun.BrokerGrant {
	hosts := []string{"github.com:443", "api.github.com:443"}
	materialization, git := "header-inject", true
	if mediation != nil {
		hosts = make([]string, len(mediation.Hosts))
		for index, host := range mediation.Hosts {
			hosts[index] = host + ":443"
		}
		materialization, git = mediation.Materialization, mediation.Git
	}
	grant := resolvedrun.BrokerGrant{Provider: provider, Repositories: repositories, Capabilities: []string{"injection.headers"}, Materialization: materialization, EgressHosts: hosts, Git: git}
	if preset == "github-app" {
		grant.Preparations = []string{"identity"}
		grant.Permissions = permissions
	}
	return grant
}

// Broker renders the existing broker provider document. Secret values are
// referenced only by fixed in-container file paths.
func Broker(compiled manifest.Compiled) ([]byte, error) {
	if compiled.Version != manifest.APIVersion || compiled.Broker.Owner != "broker" {
		return nil, errors.New("compiled broker intent is invalid")
	}
	for _, profile := range compiled.Broker.Profiles {
		for _, grant := range profile.Grants {
			if grant.Purpose == "catalog" && grant.AllContexts && len(grant.Resources) == 0 {
				return nil, errors.New("compiled Kubernetes all-context selection is unresolved")
			}
		}
	}
	providers := []map[string]any{}
	providerPlugins := []any{}
	for _, named := range compiled.Broker.Accounts {
		account := named.Account
		switch account.Preset {
		case "codex-oauth":
			providers = append(providers, map[string]any{"name": named.Name, "plugin": "codex-oauth", "config": map[string]any{
				"auth-file": "/private/portal/" + plancontract.CredentialSlotName(named.Name), "refresh-margin-seconds": 3600,
				"injection-hosts": []string{"chatgpt.com", "api.openai.com", "auth.openai.com"},
				"placeholder-file": map[string]any{
					"path": ".codex/auth.json", "hosts": []string{"chatgpt.com", "api.openai.com", "auth.openai.com"},
					"id-token-claims": []map[string]any{{"claim": "chatgpt_account_id", "claim-path": []string{"https://api.openai.com/auth", "chatgpt_account_id"}}},
				},
				"injection-claim-headers": []map[string]any{{"header": "ChatGPT-Account-ID", "claim-path": []string{"https://api.openai.com/auth", "chatgpt_account_id"}}},
			}})
		case "claude-oauth":
			providers = append(providers, map[string]any{"name": named.Name, "plugin": "claude-oauth", "config": map[string]any{
				"credentials-file": "/private/portal/" + plancontract.CredentialSlotName(named.Name), "injection-hosts": []string{"api.anthropic.com", "mcp-proxy.anthropic.com"},
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
					"app-id": appID, "installation-id": installationID, "private-key-file": plancontract.PrivateTarget(account.PrivateKeySecret), "injection-hosts": []string{"github.com", "api.github.com"},
				}, "allow": map[string]any{"repositories": allowed, "permissions": brokerPermissionsFor(compiled, named.Name, owner), "methods": []string{"GET", "POST", "PUT", "PATCH", "DELETE"}}})
			}
		default:
			return nil, errors.New("compiled broker account preset is invalid")
		}
	}
	for _, named := range compiled.Broker.Providers {
		provider := named.Provider
		config, err := clonePublicConfig(provider.Config)
		if err != nil {
			return nil, errors.New("compiled broker provider config is invalid")
		}
		for configKey, secretName := range provider.Secrets {
			if _, exists := config[configKey]; exists || secretName == "" {
				return nil, errors.New("compiled broker provider secret binding is invalid")
			}
			config[configKey] = plancontract.PrivateTarget(secretName)
		}
		allow := map[string]any{"repositories": brokerRepositoriesFor(compiled, named.Name, "")}
		if provider.Plugin == "kubeconfig" {
			config["state-dir"] = "/var/lib/nvt/broker/providers/" + named.Name
			allow = map[string]any{"resources": brokerResourcesFor(compiled, named.Name)}
			if len(providerPlugins) == 0 {
				providerPlugins = append(providerPlugins, map[string]any{"name": "kubeconfig", "command": []string{"/opt/nvt-broker/broker/providers/kubeconfig/provider.py"}, "initialize-timeout-seconds": 30, "request-timeout-seconds": 60})
			}
		}
		providers = append(providers, map[string]any{"name": named.Name, "plugin": provider.Plugin, "config": config, "allow": allow})
	}
	providerNames := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		name, ok := provider["name"].(string)
		if !ok || name == "" {
			return nil, errors.New("rendered broker provider name is invalid")
		}
		if _, exists := providerNames[name]; exists {
			return nil, fmt.Errorf("rendered broker provider name %q is not unique", name)
		}
		providerNames[name] = struct{}{}
	}
	encoded, err := json.Marshal(map[string]any{"provider-plugins": providerPlugins, "providers": providers})
	if err != nil || len(encoded) > manifest.MaxDocumentBytes {
		return nil, errors.New("broker configuration is unavailable")
	}
	return encoded, nil
}

func brokerResourcesFor(compiled manifest.Compiled, provider string) []string {
	values := map[string]struct{}{}
	for _, profile := range compiled.Broker.Profiles {
		for _, grant := range profile.Grants {
			if grant.Provider == provider {
				for _, resource := range grant.Resources {
					values[resource] = struct{}{}
				}
			}
		}
	}
	return sortedNames(values)
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
		if repository.Provider != account || repository.BrokerRepository == "" {
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

func brokerPermissionsFor(compiled manifest.Compiled, account, owner string) map[string]string {
	result := map[string]string{}
	levels := map[string]int{"read": 1, "write": 2}
	for _, repository := range compiled.Broker.Repositories {
		if repository.Provider != account || owner != "" && !strings.EqualFold(strings.SplitN(repository.BrokerRepository, "/", 2)[0], owner) {
			continue
		}
		for permission, level := range repository.Permissions {
			if levels[level] > levels[result[permission]] {
				result[permission] = level
			}
		}
	}
	return result
}

func permissionsKey(permissions map[string]string) string {
	encoded, _ := json.Marshal(permissions)
	return string(encoded)
}

func brokerRepositoryByIdentity(repositories map[string]manifest.ControllerRepositoryIntent, identity, account string) manifest.ControllerRepositoryIntent {
	for _, repository := range repositories {
		if repository.BrokerRepository == identity && repositoryProvider(repository) == account {
			return repository
		}
	}
	return manifest.ControllerRepositoryIntent{BrokerRepository: identity, Account: account}
}

func repositoryProvider(repository manifest.ControllerRepositoryIntent) string {
	if repository.CredentialProvider != "" {
		return repository.CredentialProvider
	}
	return repository.Account
}

func clonePublicConfig(input map[string]any) (map[string]any, error) {
	if input == nil {
		return map[string]any{}, nil
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(encoded, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func credentialUsername(account manifest.Account) string {
	if account.Preset == "github-app" {
		return "x-access-token"
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
