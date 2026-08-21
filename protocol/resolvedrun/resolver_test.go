package resolvedrun

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const secretNeedle = "RESOLVED-RUN-SECRET-NEEDLE"

func TestDefaultCredentialProviderMustReferenceApprovedMapping(t *testing.T) {
	configuration := validConfiguration()
	configuration.Profiles[0].DefaultCredentialProvider = "unapproved"
	if _, err := NewResolver(configuration); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("unknown default provider = %v", err)
	}
}

func TestResolvedRunSnapshotsStrictDomainPolicy(t *testing.T) {
	configuration := validConfiguration()
	configuration.Profiles[0].Egress.DomainPolicy = &DomainPolicy{
		DefaultAction: "deny",
		Allow:         []string{"GitHub.COM.", "runtime.example"},
		Deny:          []string{"pastebin.com"},
	}
	resolver, err := NewResolver(configuration)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.Resolve(validAuthorization(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
	configuration.Profiles[0].Egress.DomainPolicy.Allow[0] = "changed.example"
	if resolved.Egress.DomainPolicy == nil || resolved.Egress.DomainPolicy.Allow[0] != "GitHub.COM." {
		t.Fatalf("domain policy was not immutably snapshotted: %#v", resolved.Egress.DomainPolicy)
	}
}

func TestResolvedRunRejectsContradictoryAndMalformedDomainPolicies(t *testing.T) {
	for _, policy := range []*DomainPolicy{
		{DefaultAction: "deny", Allow: []string{"runtime.example"}},
		{DefaultAction: "invalid"},
		{DefaultAction: "deny", Allow: []string{"127.0.0.1"}},
		{DefaultAction: "deny", Allow: []string{"8.8.8.8."}},
		{DefaultAction: "deny", Allow: []string{"github.com", "GITHUB.COM."}},
	} {
		configuration := validConfiguration()
		configuration.Profiles[0].Egress.DomainPolicy = policy
		if _, err := NewResolver(configuration); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("invalid domain policy accepted: %#v, %v", policy, err)
		}
	}
}

func TestWorkflowLifecycleCompletelyReplacesProfileLifecycle(t *testing.T) {
	configuration := validConfiguration()
	configuration.Workflows[0].Lifecycle = &Lifecycle{
		CompleteOn: []string{"plugin.github.pr.merged", "plugin.github.pr.closed"},
		FailOn:     []string{"plugin.work.failed"},
	}
	resolver, err := NewResolver(configuration)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.Resolve(validAuthorization(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resolved.Lifecycle, *configuration.Workflows[0].Lifecycle) {
		t.Fatalf("workflow lifecycle was not snapshotted as a replacement: %#v", resolved.Lifecycle)
	}
	configuration.Workflows[0].Lifecycle.CompleteOn[0] = "plugin.mutated"
	if resolved.Lifecycle.CompleteOn[0] != "plugin.github.pr.merged" {
		t.Fatal("resolved workflow lifecycle was not immutable")
	}
}

func TestWorkflowLifecycleValidationAndOmittedCompatibility(t *testing.T) {
	configuration := validConfiguration()
	resolver, err := NewResolver(configuration)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.Resolve(validAuthorization(), validRequest())
	if err != nil || !reflect.DeepEqual(resolved.Lifecycle, *configuration.Profiles[0].Lifecycle) {
		t.Fatalf("omitted workflow lifecycle changed profile lifecycle: %#v, %v", resolved.Lifecycle, err)
	}
	for _, lifecycle := range []Lifecycle{
		{CompleteOn: []string{"Invalid Event"}},
		{CompleteOn: []string{"plugin.work.completed", "plugin.work.completed"}},
		{CompleteOn: []string{"plugin.work.completed"}, FailOn: []string{"plugin.work.completed"}},
	} {
		invalid := validConfiguration()
		invalid.Workflows[0].Lifecycle = &lifecycle
		if _, err := NewResolver(invalid); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("invalid workflow lifecycle accepted: %#v, %v", lifecycle, err)
		}
	}
}

func TestRuntimeModelAndEffortRenderFreshAndResume(t *testing.T) {
	configuration := validConfiguration()
	configuration.Defaults.Runtime = Runtime{Type: "codex", Autonomy: "trusted-local", User: "root", Model: "gpt-5.6-sol", Effort: "high"}
	configuration.Profiles[0].Runtime = nil
	resolver, err := NewResolver(configuration)
	if err != nil {
		t.Fatal(err)
	}
	run, err := resolver.Resolve(validAuthorization(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if run.Runtime.Model != "gpt-5.6-sol" || run.Runtime.Effort != "high" {
		t.Fatalf("typed runtime selection was not propagated: %#v", run.Runtime)
	}
	rendered, err := RenderAgentConfig(run, AgentConfigBindings{ForwardProxyURL: "http://127.0.0.1:15002"})
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(rendered, &root); err != nil {
		t.Fatal(err)
	}
	runtime := root["runtime"].(map[string]any)
	wantSelectors := []any{"--model", "gpt-5.6-sol", "--config", "model_reasoning_effort=high"}
	args := runtime["args"].([]any)
	if !reflect.DeepEqual(args[len(args)-4:], wantSelectors) {
		t.Fatalf("fresh selectors = %#v", args)
	}
	resume := runtime["resume"].(map[string]any)
	resumeArgs := resume["args"].([]any)
	if !reflect.DeepEqual(resumeArgs[len(resumeArgs)-4:], wantSelectors) {
		t.Fatalf("resume selectors = %#v", resumeArgs)
	}
}

func TestRuntimeSelectionRejectsUnsupportedEffortAndRawConflicts(t *testing.T) {
	configuration := validConfiguration()
	configuration.Defaults.Runtime = Runtime{Type: "codex", Autonomy: "trusted-local", User: "root", Effort: "max"}
	configuration.Profiles[0].Runtime = nil
	if _, err := NewResolver(configuration); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("unsupported effort error = %v", err)
	}

	configuration = validConfiguration()
	configuration.Defaults.Runtime = Runtime{Type: "codex", Autonomy: "trusted-local", User: "root", Model: "typed"}
	configuration.Defaults.AgentConfig = json.RawMessage(`{"runtime":{"command":"codex","args":["--model","raw"]},"plugins":[]}`)
	configuration.Profiles[0].Runtime = nil
	configuration.Profiles[0].AgentConfig = nil
	resolver, err := NewResolver(configuration)
	if err != nil {
		t.Fatal(err)
	}
	run, err := resolver.Resolve(validAuthorization(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RenderAgentConfig(run, AgentConfigBindings{ForwardProxyURL: "http://127.0.0.1:15002"}); !errors.Is(err, ErrInvalidRenderBinding) {
		t.Fatalf("raw selector conflict error = %v", err)
	}
}

func TestResolveProducesCompleteTrustedNonSecretContract(t *testing.T) {
	t.Parallel()
	resolver, err := NewResolver(validConfiguration())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	request := validRequest()
	authorization := validAuthorization()
	resolved, err := resolver.Resolve(authorization, request)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved.ContractVersion != ContractVersion || resolved.RunID != request.RunID || resolved.Principal != authorization.Principal || resolved.SourceURL != request.SourceURL {
		t.Fatalf("trusted identity was not frozen exactly: %#v", resolved)
	}
	if resolved.Image != "registry.example/nvt-profile:sha256-deadbeef" || resolved.Runtime.Type != "generic-agent" ||
		resolved.Runtime.Container == nil || !reflect.DeepEqual(resolved.Runtime.Container.Capabilities, []string{"SYS_PTRACE"}) ||
		resolved.Runtime.Docker == nil || !resolved.Runtime.Docker.KernelLogDevice ||
		resolved.Runtime.Docker.RequiredNetworks[0].Subnet != "172.31.250.0/24" {
		t.Fatalf("runtime policy was not retained: %#v", resolved.Runtime)
	}
	var agentConfig map[string]any
	if err := json.Unmarshal(resolved.AgentConfig, &agentConfig); err != nil {
		t.Fatal(err)
	}
	runtime := agentConfig["runtime"].(map[string]any)
	if runtime["command"] != "agent-cli" || runtime["resume"].(map[string]any)["command"] != "agent-cli" ||
		agentConfig["preseed"] == nil || agentConfig["tools"] == nil || agentConfig["code-server"] == nil ||
		agentConfig["plugins"] == nil || agentConfig["expose"] == nil {
		t.Fatalf("complete provider-neutral agent configuration was not retained: %#v", agentConfig)
	}
	if runtime["initial-prompt"] != nil || runtime["proxy"] != nil || agentConfig["egress"] != nil {
		t.Fatalf("base agent configuration contains controller-owned fields: %#v", agentConfig)
	}
	if resolved.Prompt != request.Prompt || !reflect.DeepEqual(resolved.Lifecycle.CompleteOn, []string{"plugin.work.completed"}) ||
		!reflect.DeepEqual(resolved.Lifecycle.FailOn, []string{"plugin.work.failed"}) {
		t.Fatalf("prompt/lifecycle behavior was not retained: %#v", resolved)
	}
	repository := resolved.Repositories[0]
	if repository.CheckoutTarget != "github.com/Altinn/altinn-studio" || repository.BrokerRepository != "Altinn/altinn-studio" ||
		resolved.CredentialProviders[0].MatchTargets[0] != "github.com/Altinn/*" ||
		resolved.Broker.Grants[0].Repositories[0] != "Altinn/*" {
		t.Fatalf("checkout and provider-native repository namespaces were conflated: %#v", resolved)
	}
	if resolved.Egress.Mode != "mediated" || !resolved.Egress.PairedEgressRequired || resolved.Egress.ProxyProvider != "runtime-main" {
		t.Fatalf("trusted egress policy was not retained: %#v", resolved.Egress)
	}
	if resolved.WorkspaceInstructions.Profile != "Profile-owned guidance.\n" ||
		resolved.WorkspaceInstructions.Workflow != "Workflow-owned guidance.\n" ||
		resolved.Retention != "persistent" || !resolved.Persistence.Workspace || resolved.Execution.Name != "container" {
		t.Fatalf("resolved policy is incomplete: %#v", resolved)
	}
	rendered, err := RenderAgentConfig(resolved, AgentConfigBindings{ForwardProxyURL: "http://127.0.0.1:15002"})
	if err != nil {
		t.Fatalf("RenderAgentConfig: %v", err)
	}
	var renderedConfig map[string]any
	if err := json.Unmarshal(rendered, &renderedConfig); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rendered, []byte(request.SourceURL)) {
		t.Fatalf("display-only source URL entered executable agent config: %s", rendered)
	}
	renderedRuntime := renderedConfig["runtime"].(map[string]any)
	if renderedRuntime["initial-prompt"].(map[string]any)["text"] != request.Prompt ||
		renderedRuntime["proxy"].(map[string]any)["provider"] != "runtime-main" {
		t.Fatalf("typed prompt/proxy were not rendered authoritatively: %#v", renderedRuntime)
	}
	renderedEgress := renderedConfig["egress"].(map[string]any)
	if renderedEgress["mode"] != "mediated" || renderedEgress["transport"] != "forward-proxy" ||
		renderedEgress["forward-proxy-url"] != "http://127.0.0.1:15002" {
		t.Fatalf("typed egress was not rendered authoritatively: %#v", renderedEgress)
	}
	pluginNames := renderedPluginNames(t, renderedConfig)
	if !reflect.DeepEqual(pluginNames[:3], []string{"git-host-credentials", "git-credentials", "checkout-repos"}) {
		t.Fatalf("typed repositories were not rendered before base plugins: %#v", pluginNames)
	}
	hostConfig := renderedConfig["plugins"].([]any)[0].(map[string]any)["config"].(map[string]any)
	if hostConfig["default-provider"] != "source" {
		t.Fatalf("default credential provider was not preserved: %#v", hostConfig)
	}
	credentialConfig := renderedConfig["plugins"].([]any)[1].(map[string]any)["config"].(map[string]any)
	credentialRule := credentialConfig["credentials"].([]any)[0].(map[string]any)
	if credentialRule["username"] != "git-user" {
		t.Fatalf("credential username was not preserved: %#v", credentialRule)
	}
	if bytes.Contains(rendered, []byte("lifecycle-termination")) || bytes.Contains(rendered, []byte("/dev/termination-log")) {
		t.Fatalf("portable rendering injected a backend-specific lifecycle adapter: %s", rendered)
	}
	plugins := renderedConfig["plugins"].([]any)
	provider := plugins[0].(map[string]any)["config"].(map[string]any)["providers"].([]any)[0].(map[string]any)
	credential := plugins[1].(map[string]any)["config"].(map[string]any)["credentials"].([]any)[0].(map[string]any)
	checkout := plugins[2].(map[string]any)["config"].(map[string]any)["repos"].([]any)[0].(map[string]any)
	if provider["credential-kind"] != "mediated" || credential["identity"].(map[string]any)["mode"] != "provider" ||
		checkout["upstream"] != "https://github.com/Altinn/altinn-studio-upstream.git" {
		t.Fatalf("managed repository behavior was rendered incompletely: provider=%#v credential=%#v checkout=%#v", provider, credential, checkout)
	}
	encoded, err := json.Marshal(resolved)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{secretNeedle, "access_token", "refresh_token", "private_key"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("resolved contract contains credential material %q", forbidden)
		}
	}
	decoded, err := DecodeResolvedAgentRun(encoded)
	if err != nil || !reflect.DeepEqual(decoded, resolved) {
		t.Fatalf("resolved contract did not strictly round trip: err=%v got=%#v", err, decoded)
	}
}

func TestCallerCannotSupplyPrincipalOrUnauthorizedProfileWorkflow(t *testing.T) {
	t.Parallel()
	validJSON := `{"run_id":"infra","profile":"engineering","workflow":"development","retention":"persistent","prompt":"do the work"}`
	if _, err := DecodeLocalRunRequest([]byte(validJSON)); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	spoofed := `{"run_id":"infra","principal":{"issuer":"https://attacker.example","subject":"victim"},"profile":"engineering","workflow":"development","retention":"persistent"}`
	if _, err := DecodeLocalRunRequest([]byte(spoofed)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("caller-supplied principal was accepted")
	}
	resolver, err := NewResolver(validConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	for name, request := range map[string]LocalRunRequest{
		"profile":  {RunID: "infra", Profile: "restricted", Workflow: "development", Retention: "persistent"},
		"workflow": {RunID: "infra", Profile: "engineering", Workflow: "restricted", Retention: "persistent"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := resolver.Resolve(validAuthorization(), request); !errors.Is(err, ErrSelectionDenied) {
				t.Fatalf("unauthorized selection error = %v", err)
			}
		})
	}
	invalidContext := validAuthorization()
	invalidContext.Principal.Subject = ""
	if _, err := resolver.Resolve(invalidContext, validRequest()); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid trusted principal error = %v", err)
	}
}

func TestSourceURLValidationPreservesExactFragmentAndFailsClosed(t *testing.T) {
	t.Parallel()
	const sourceURL = "https://github.com/acme/widget/issues/7?view=all#issuecomment-5307105878"
	request := validRequest()
	request.SourceURL = sourceURL
	resolver, err := NewResolver(validConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.Resolve(validAuthorization(), request)
	if err != nil || resolved.SourceURL != sourceURL {
		t.Fatalf("exact source URL was not resolved: %#v, %v", resolved, err)
	}
	encoded, err := json.Marshal(resolved)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeResolvedAgentRun(encoded)
	if err != nil || decoded.SourceURL != sourceURL {
		t.Fatalf("exact source URL did not round trip: %#v, %v", decoded, err)
	}
	for name, source := range map[string]string{
		"insecure":         "http://github.example/acme/widget/issues/7",
		"userinfo":         "https://user@github.example/acme/widget/issues/7",
		"encoded control":  "https://github.example/acme/widget/issues/7#issuecomment%0a7",
		"encoded non-UTF8": "https://github.example/acme/widget/issues/7#issuecomment%ff7",
		"malformed escape": "https://github.example/acme/widget/issues/%zz",
		"oversized":        "https://github.example/" + strings.Repeat("x", MaxSourceURLBytes),
	} {
		t.Run(name, func(t *testing.T) {
			candidate := validRequest()
			candidate.SourceURL = source
			if _, err := resolver.Resolve(validAuthorization(), candidate); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("malformed source URL accepted: %q, %v", source, err)
			}
		})
	}
}

func TestStrictRequestDecoderRejectsProtectedOverridesAndAmbiguity(t *testing.T) {
	t.Parallel()
	validJSON := `{"run_id":"infra","profile":"engineering","workflow":"development","retention":"persistent"}`
	for _, field := range []string{
		`"repositories":[{"url":"https://attacker.example/repo"}]`, `"provider":"attacker-provider"`,
		`"broker":{"grants":[]}`, `"capabilities":["SYS_ADMIN"]`, `"execution":{"name":"attacker"}`,
		`"runtime":{"type":"attacker"}`, `"agent_config":{"runtime":{"command":"attacker"}}`,
		`"egress":{"mode":"direct"}`, `"profile":"other"`,
	} {
		candidate := strings.TrimSuffix(validJSON, "}") + "," + field + "}"
		if _, err := DecodeLocalRunRequest([]byte(candidate)); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("protected/duplicate field accepted: %s", field)
		}
	}
	if _, err := DecodeLocalRunRequest(bytes.Repeat([]byte{' '}, MaxDocumentBytes+1)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("oversized request was accepted")
	}
	request := validRequest()
	request.Prompt = strings.Repeat("x", MaxPromptBytes+1)
	if err := ValidateLocalRunRequest(request); err == nil {
		t.Fatal("oversized prompt was accepted")
	}
}

func TestResolveUsesDefaultsAndOnlyApprovedBackendRetention(t *testing.T) {
	t.Parallel()
	configuration := validConfiguration()
	profile := &configuration.Profiles[0]
	profile.Image, profile.Runtime, profile.AgentConfig, profile.Resources, profile.Lifecycle = "", nil, nil, nil, nil
	profile.AllowedBackends = append(profile.AllowedBackends, "sandbox")
	configuration.ExecutionBackends = append(configuration.ExecutionBackends, ExecutionBackend{Name: "sandbox", Kind: "microvm"})
	resolver, err := NewResolver(configuration)
	if err != nil {
		t.Fatal(err)
	}
	request := validRequest()
	request.Backend = "sandbox"
	resolved, err := resolver.Resolve(validAuthorization(), request)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Image != configuration.Defaults.Image || resolved.Runtime.Type != "default-agent" ||
		resolved.Execution.Name != "sandbox" || resolved.Execution.Kind != "microvm" ||
		!bytes.Equal(resolved.AgentConfig, configuration.Defaults.AgentConfig) {
		t.Fatalf("default/approved override precedence is wrong: %#v", resolved)
	}
	for name, mutate := range map[string]func(*LocalRunRequest){
		"backend":   func(value *LocalRunRequest) { value.Backend = "administrator-never-approved" },
		"retention": func(value *LocalRunRequest) { value.Retention = "disposable" },
	} {
		t.Run(name, func(t *testing.T) {
			denied := request
			mutate(&denied)
			if _, err := resolver.Resolve(validAuthorization(), denied); !errors.Is(err, ErrSelectionDenied) {
				t.Fatalf("selection error = %v", err)
			}
		})
	}
}

func TestConfigurationAndRepositoryFailuresFailClosed(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*TrustedConfiguration){
		"duplicate profile":   func(value *TrustedConfiguration) { value.Profiles = append(value.Profiles, value.Profiles[0]) },
		"duplicate workflow":  func(value *TrustedConfiguration) { value.Workflows = append(value.Workflows, value.Workflows[0]) },
		"unknown backend":     func(value *TrustedConfiguration) { value.Profiles[0].AllowedBackends[0] = "missing" },
		"unknown retention":   func(value *TrustedConfiguration) { value.Profiles[0].AllowedRetentions[0] = "missing" },
		"ungranted mapping":   func(value *TrustedConfiguration) { value.Profiles[0].CredentialProviders[0].BrokerProvider = "other" },
		"mediated file grant": func(value *TrustedConfiguration) { value.Profiles[0].Broker.Grants[0].Materialization = "file-bundle" },
		"credential environment": func(value *TrustedConfiguration) {
			value.Profiles[0].AgentConfig = replaceAgentConfigRuntimeEnv(t, value.Profiles[0].AgentConfig, map[string]any{"PROVIDER_ACCESS_TOKEN": secretNeedle})
		},
		"checkout URL mismatch": func(value *TrustedConfiguration) {
			value.Workflows[0].Repositories[0].URL = "https://attacker.example/Altinn/altinn-studio.git"
		},
		"credentialed checkout missing broker repository": func(value *TrustedConfiguration) {
			value.Workflows[0].Repositories[0].BrokerRepository = ""
		},
		"invalid egress port": func(value *TrustedConfiguration) {
			value.Profiles[0].Broker.Grants[0].EgressHosts[0] = "github.com:not-a-port"
		},
		"invalid credential kind": func(value *TrustedConfiguration) {
			value.Profiles[0].CredentialProviders[0].CredentialKind = "executable"
		},
		"mediated git defaults to token": func(value *TrustedConfiguration) {
			value.Profiles[0].CredentialProviders[0].CredentialKind = ""
		},
		"provider identity contains explicit fields": func(value *TrustedConfiguration) {
			value.Workflows[0].Repositories[0].Identity.Name = "unexpected"
		},
		"credential-less identity": func(value *TrustedConfiguration) {
			value.Workflows[0].Repositories[0].CredentialProvider = ""
			value.Workflows[0].Repositories[0].BrokerRepository = ""
		},
		"credential-bearing upstream URL": func(value *TrustedConfiguration) {
			value.Workflows[0].Repositories[0].Upstream = "https://user:password@github.com/Altinn/upstream.git"
		},
	} {
		t.Run(name, func(t *testing.T) {
			configuration := validConfiguration()
			mutate(&configuration)
			if _, err := NewResolver(configuration); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("NewResolver error = %v", err)
			}
		})
	}

	for name, mutate := range map[string]func(*TrustedConfiguration){
		"checkout outside mapping": func(value *TrustedConfiguration) {
			value.Workflows[0].Repositories[0].CheckoutTarget = "github.com/Other/project"
			value.Workflows[0].Repositories[0].URL = "https://github.com/Other/project.git"
		},
		"provider-native repository outside grant": func(value *TrustedConfiguration) {
			value.Workflows[0].Repositories[0].BrokerRepository = "Other/project"
		},
		"unknown provider alias": func(value *TrustedConfiguration) { value.Workflows[0].Repositories[0].CredentialProvider = "untrusted" },
		"provider identity lacks preparation": func(value *TrustedConfiguration) {
			value.Profiles[0].Broker.Grants[0].Preparations = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			configuration := validConfiguration()
			mutate(&configuration)
			resolver, err := NewResolver(configuration)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolver.Resolve(validAuthorization(), validRequest()); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("Resolve error = %v", err)
			}
		})
	}
}

func TestAgentConfigRejectsControllerOwnedFieldConflicts(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(map[string]any){
		"initial prompt": func(root map[string]any) {
			root["runtime"].(map[string]any)["initial-prompt"] = map[string]any{"delivery": "argument", "text": "other"}
		},
		"runtime proxy": func(root map[string]any) {
			root["runtime"].(map[string]any)["proxy"] = map[string]any{"provider": "other"}
		},
		"egress": func(root map[string]any) { root["egress"] = map[string]any{"mode": "direct"} },
		"checkout plugin": func(root map[string]any) {
			root["plugins"] = append(root["plugins"].([]any), map[string]any{"name": "checkout-repos", "source": "builtin"})
		},
		"credential mapping plugin": func(root map[string]any) {
			root["plugins"] = append(root["plugins"].([]any), map[string]any{"name": "git-host-credentials", "source": "builtin"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			configuration := validConfiguration()
			var root map[string]any
			if err := json.Unmarshal(configuration.Profiles[0].AgentConfig, &root); err != nil {
				t.Fatal(err)
			}
			mutate(root)
			configuration.Profiles[0].AgentConfig = mustJSON(t, root)
			if _, err := NewResolver(configuration); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("conflicting base config error = %v", err)
			}
		})
	}
}

func TestRepositoryExplicitIdentityRendersWithoutProviderPreparation(t *testing.T) {
	t.Parallel()
	configuration := validConfiguration()
	repository := &configuration.Workflows[0].Repositories[0]
	repository.Identity = &RepositoryIdentity{Mode: "explicit", Name: "Automation Bot", Email: "automation@example.test"}
	configuration.Profiles[0].Broker.Grants[0].Preparations = nil
	resolver, err := NewResolver(configuration)
	if err != nil {
		t.Fatal(err)
	}
	run, err := resolver.Resolve(validAuthorization(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := RenderAgentConfig(run, AgentConfigBindings{ForwardProxyURL: "http://127.0.0.1:15002"})
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(rendered, &root); err != nil {
		t.Fatal(err)
	}
	plugins := root["plugins"].([]any)
	identity := plugins[1].(map[string]any)["config"].(map[string]any)["credentials"].([]any)[0].(map[string]any)["identity"].(map[string]any)
	if identity["mode"] != "explicit" || identity["name"] != "Automation Bot" || identity["email"] != "automation@example.test" {
		t.Fatalf("explicit repository identity was not preserved: %#v", identity)
	}
}

func TestBrokerOperationAuthorizationResolvesImmutably(t *testing.T) {
	configuration := validConfiguration()
	policy := &BrokerGrantAuthorization{DefaultAction: "deny", Rules: []BrokerGrantAuthorizationRule{{Operation: "execute", Resource: "workflow/deploy"}}}
	configuration.Profiles[0].Broker.Grants[0].Authorization = policy
	resolver, err := NewResolver(configuration)
	if err != nil {
		t.Fatal(err)
	}
	policy.Rules[0].Resource = "workflow/mutated"
	run, err := resolver.Resolve(validAuthorization(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
	got := run.Broker.Grants[0].Authorization
	if got == nil || got.DefaultAction != "deny" || len(got.Rules) != 1 || got.Rules[0].Resource != "workflow/deploy" {
		t.Fatalf("resolved authorization policy was not immutable: %#v", got)
	}
}

func TestEgressTransportContractMatchesRuntime(t *testing.T) {
	t.Parallel()
	for _, transport := range []string{"redirect", "forward-proxy", "transparent"} {
		t.Run(transport+" valid", func(t *testing.T) {
			configuration := validConfiguration()
			configureTransport(&configuration, transport)
			if transport == "redirect" {
				configuration.Profiles[0].Egress.Enforced = true
			}
			configuration.Profiles[0].Broker.Grants = append(configuration.Profiles[0].Broker.Grants, BrokerGrant{
				Provider: "placeholder-main", Capabilities: []string{"injection.files"}, Materialization: "placeholder-file",
			})
			resolver, err := NewResolver(configuration)
			if err != nil {
				t.Fatal(err)
			}
			run, err := resolver.Resolve(validAuthorization(), validRequest())
			if err != nil {
				t.Fatal(err)
			}
			bindings := AgentConfigBindings{ForwardProxyURL: "http://127.0.0.1:15002"}
			if transport == "redirect" {
				bindings = AgentConfigBindings{RedirectBaseURLs: map[string]string{
					"source-app": "https://egress-source.internal:14431", "runtime-main": "https://egress-runtime.internal:14432",
				}}
			}
			rendered, err := RenderAgentConfig(run, bindings)
			if err != nil {
				t.Fatalf("render %s: %v", transport, err)
			}
			var root map[string]any
			if err := json.Unmarshal(rendered, &root); err != nil {
				t.Fatal(err)
			}
			runtime := root["runtime"].(map[string]any)
			egress := root["egress"].(map[string]any)
			if transport == "redirect" {
				if runtime["proxy"] != nil || egress["forward-proxy-url"] != nil {
					t.Fatalf("redirect rendered tunnel selector: runtime=%#v egress=%#v", runtime, egress)
				}
				firstGrant := egress["grants"].([]any)[0].(map[string]any)
				if firstGrant["base-url"] != "https://egress-source.internal:14431" ||
					egress["operator-prepared"] != true || len(firstGrant["hosts"].([]any)) == 0 {
					t.Fatalf("enforced redirect is not bootstrap-consumable without broker lookup: egress=%#v grant=%#v", egress, firstGrant)
				}
			} else if runtime["proxy"].(map[string]any)["provider"] != "runtime-main" || egress["enforcement"] != true {
				t.Fatalf("tunnel transport lacks enforced proxy rendering: runtime=%#v egress=%#v", runtime, egress)
			}
		})
	}

	resolver, err := NewResolver(validConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	forwardRun, err := resolver.Resolve(validAuthorization(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
	for name, bindings := range map[string]AgentConfigBindings{
		"missing forward endpoint":    {},
		"redirect endpoint on tunnel": {ForwardProxyURL: "http://127.0.0.1:15002", RedirectBaseURLs: map[string]string{"runtime-main": "https://egress.internal:14431"}},
		"credential in endpoint":      {ForwardProxyURL: "http://user:password@127.0.0.1:15002"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := RenderAgentConfig(forwardRun, bindings); !errors.Is(err, ErrInvalidRenderBinding) {
				t.Fatalf("render binding error = %v", err)
			}
		})
	}

	for name, mutate := range map[string]func(*TrustedConfiguration){
		"redirect proxy selector": func(value *TrustedConfiguration) {
			configureTransport(value, "redirect")
			value.Profiles[0].Egress.ProxyProvider = "runtime-main"
		},
		"forward proxy without enforcement": func(value *TrustedConfiguration) {
			configureTransport(value, "forward-proxy")
			value.Profiles[0].Egress.Enforced = false
		},
		"transparent without enforcement": func(value *TrustedConfiguration) {
			configureTransport(value, "transparent")
			value.Profiles[0].Egress.Enforced = false
		},
		"tunnel without proxy": func(value *TrustedConfiguration) {
			configureTransport(value, "forward-proxy")
			value.Profiles[0].Egress.ProxyProvider = ""
		},
		"ungranted proxy": func(value *TrustedConfiguration) {
			configureTransport(value, "transparent")
			value.Profiles[0].Egress.ProxyProvider = "not-granted"
		},
		"redirect without header route": func(value *TrustedConfiguration) {
			configureTransport(value, "redirect")
			for index := range value.Profiles[0].Broker.Grants {
				value.Profiles[0].Broker.Grants[index].Materialization = "placeholder-file"
				value.Profiles[0].Broker.Grants[index].Git = false
			}
		},
		"tunnel without injection route": func(value *TrustedConfiguration) {
			configureTransport(value, "forward-proxy")
			for index := range value.Profiles[0].Broker.Grants {
				value.Profiles[0].Broker.Grants[index].Materialization = "placeholder-file"
				value.Profiles[0].Broker.Grants[index].EgressHosts = nil
				value.Profiles[0].Broker.Grants[index].Git = false
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			configuration := validConfiguration()
			mutate(&configuration)
			if _, err := NewResolver(configuration); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("invalid transport error = %v", err)
			}
		})
	}
}

func TestPublicRepositoryNeedsNoBrokerNamespace(t *testing.T) {
	t.Parallel()
	configuration := validConfiguration()
	configuration.Workflows[0].Repositories = append(configuration.Workflows[0].Repositories, Repository{
		CheckoutTarget: "github.com/Altinn/public-repository", URL: "https://github.com/Altinn/public-repository.git", Path: "public-repository",
	})
	resolver, err := NewResolver(configuration)
	if err != nil {
		t.Fatal(err)
	}
	run, err := resolver.Resolve(validAuthorization(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if run.Repositories[1].BrokerRepository != "" || run.Repositories[1].CredentialProvider != "" {
		t.Fatalf("public repository gained broker authorization: %#v", run.Repositories[1])
	}
	rendered, err := RenderAgentConfig(run, AgentConfigBindings{ForwardProxyURL: "http://127.0.0.1:15002"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rendered, []byte(`"url":"https://github.com/Altinn/public-repository.git"`)) {
		t.Fatalf("public checkout was not rendered: %s", rendered)
	}
	configuration.Workflows[0].Repositories[1].BrokerRepository = "Altinn/public-repository"
	if _, err := NewResolver(configuration); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("uncredentialed broker repository error = %v", err)
	}
}

func TestWorkflowSwitchRendersOnlyTheAuthorizedRepositories(t *testing.T) {
	t.Parallel()
	configuration := validConfiguration()
	configuration.Workflows[1] = Workflow{
		Name: "restricted", Repositories: []Repository{{
			CheckoutTarget: "git.example/public/project", URL: "https://git.example/public/project.git", Path: "public-project",
		}},
	}
	resolver, err := NewResolver(configuration)
	if err != nil {
		t.Fatal(err)
	}
	authorization := validAuthorization()
	authorization.Selections[0].Workflows = append(authorization.Selections[0].Workflows, "restricted")
	request := validRequest()
	request.Workflow = "restricted"
	run, err := resolver.Resolve(authorization, request)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := RenderAgentConfig(run, AgentConfigBindings{ForwardProxyURL: "http://127.0.0.1:15002"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rendered, []byte("https://git.example/public/project.git")) ||
		bytes.Contains(rendered, []byte("https://github.com/Altinn/altinn-studio.git")) ||
		bytes.Count(rendered, []byte(`"name":"checkout-repos"`)) != 1 {
		t.Fatalf("workflow repository rendering was not authoritative: %s", rendered)
	}
}

func TestResolverSnapshotsInputsAndIsDeterministic(t *testing.T) {
	t.Parallel()
	configuration := validConfiguration()
	resolver, err := NewResolver(configuration)
	if err != nil {
		t.Fatal(err)
	}
	configuration.Profiles[0].Broker.Grants[0].Provider = "mutated-provider"
	configuration.Workflows[0].Repositories[0].CheckoutTarget = "github.com/mutated/repository"
	first, err := resolver.Resolve(validAuthorization(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
	first.Broker.Grants[0].Provider = "mutated-result"
	first.Repositories[0].CheckoutTarget = "github.com/mutated/result"
	first.AgentConfig[0] = '['
	second, err := resolver.Resolve(validAuthorization(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if second.Broker.Grants[0].Provider != "source-app" || second.Repositories[0].CheckoutTarget != "github.com/Altinn/altinn-studio" || second.AgentConfig[0] != '{' {
		t.Fatalf("resolver/result aliasing changed the snapshot: %#v", second)
	}
	firstJSON, _ := json.Marshal(second)
	third, _ := resolver.Resolve(validAuthorization(), validRequest())
	thirdJSON, _ := json.Marshal(third)
	if !bytes.Equal(firstJSON, thirdJSON) {
		t.Fatalf("resolution is not deterministic:\n%s\n%s", firstJSON, thirdJSON)
	}
}

func validRequest() LocalRunRequest {
	return LocalRunRequest{
		RunID: "infra", Profile: "engineering", Workflow: "development", Retention: "persistent",
		Prompt: "Implement the requested change.", SourceURL: "https://github.example/acme/widget/issues/7#issuecomment-1",
	}
}

func validAuthorization() AuthorizationContext {
	return AuthorizationContext{
		Principal:  Principal{Issuer: "https://issuer.example", Subject: "subject-1", DisplayName: "Engineer"},
		Selections: []AuthorizedSelection{{Profile: "engineering", Workflows: []string{"development"}}},
	}
}

func validConfiguration() TrustedConfiguration {
	defaultAgentConfig := json.RawMessage(`{"runtime":{"command":"default-agent","args":[]},"tools":{"packages":["git"]},"code-server":{"extensions":[]},"plugins":[],"expose":{"http":[]}}`)
	profileAgentConfig := json.RawMessage(`{
  "runtime":{"command":"agent-cli","args":["run","--non-interactive"],"resume":{"command":"agent-cli","args":["resume","--last"]},"env":{"NO_PROXY":"localhost,127.0.0.1"}},
  "preseed":{"files":[{"path":"$HOME/.agent/config","mode":"0600","overwrite":false,"content":"check_for_update_on_startup = false\n"}]},
  "tools":{"packages":["git","jq"],"mise":["go@1.26"],"additional-paths":["/opt/tools/bin"],"shell":[]},
  "code-server":{"extensions":["redhat.vscode-yaml"],"settings":{"overwrite":false,"values":{"workbench.startupEditor":"none"}},"agentTerminal":{"openOnStartup":true}},
  "plugins":[{"name":"smoke-complete","source":"builtin","when":"after-agent","config":{}}],
  "expose":{"http":[{"name":"app","targetPort":3000}]}
}`)
	profileRuntime := Runtime{
		Type: "generic-agent", Autonomy: "trusted-local", User: "root",
		Container: &RuntimeContainer{Capabilities: []string{"SYS_PTRACE"}},
		Docker:    &RuntimeDocker{KernelLogDevice: true, RequiredNetworks: []DockerNetwork{{Name: "kind", Subnet: "172.31.250.0/24"}}},
	}
	profileResources := Resources{CPURequest: "2", CPULimit: "2", MemoryRequest: "8Gi", MemoryLimit: "8Gi"}
	profileLifecycle := Lifecycle{CompleteOn: []string{"plugin.work.completed"}, FailOn: []string{"plugin.work.failed"}}
	return TrustedConfiguration{
		Defaults: PlatformDefaults{
			Image:       "registry.example/nvt-default:sha256-deadbeef",
			Runtime:     Runtime{Type: "default-agent", Autonomy: "interactive", User: "root"},
			AgentConfig: defaultAgentConfig, Resources: Resources{CPURequest: "1", MemoryRequest: "2Gi"},
		},
		Profiles: []Profile{{
			Name: "engineering", Image: "registry.example/nvt-profile:sha256-deadbeef", Runtime: &profileRuntime,
			AgentConfig: profileAgentConfig, Resources: &profileResources, Lifecycle: &profileLifecycle,
			CredentialProviders: []CredentialProviderMapping{{Name: "source", BrokerProvider: "source-app", CredentialKind: "mediated", MatchTargets: []string{"github.com/Altinn/*"}}}, DefaultCredentialProvider: "source",
			Broker: Broker{Grants: []BrokerGrant{
				{Provider: "source-app", Repositories: []string{"Altinn/*"}, Capabilities: []string{"injection.headers"}, Preparations: []string{"identity"}, Materialization: "header-inject", EgressHosts: []string{"github.com:443"}, Git: true, Permissions: map[string]string{"contents": "write"}},
				{Provider: "runtime-main", Capabilities: []string{"injection.headers"}, Materialization: "header-inject", EgressHosts: []string{"runtime.example:443"}},
			}},
			Egress:                Egress{Mode: "mediated", Transport: "forward-proxy", Enforced: true, ProxyProvider: "runtime-main", PairedEgressRequired: true, MaxConcurrentTunnels: 128},
			WorkspaceInstructions: "Profile-owned guidance.\n", AllowedBackends: []string{"container"}, DefaultBackend: "container", AllowedRetentions: []string{"persistent"},
		}, {
			Name: "restricted", Runtime: &profileRuntime, AgentConfig: profileAgentConfig,
			Broker:          Broker{Grants: []BrokerGrant{{Provider: "runtime-main", Capabilities: []string{"injection.headers"}, Materialization: "header-inject", EgressHosts: []string{"runtime.example:443"}}}},
			Egress:          Egress{Mode: "mediated", Transport: "forward-proxy", Enforced: true, ProxyProvider: "runtime-main", PairedEgressRequired: true},
			AllowedBackends: []string{"container"}, DefaultBackend: "container", AllowedRetentions: []string{"persistent"},
		}},
		Workflows: []Workflow{{
			Name: "development", WorkspaceInstructions: "Workflow-owned guidance.\n",
			Repositories: []Repository{{CheckoutTarget: "github.com/Altinn/altinn-studio", BrokerRepository: "Altinn/altinn-studio", URL: "https://github.com/Altinn/altinn-studio.git", Path: "altinn-studio", Upstream: "https://github.com/Altinn/altinn-studio-upstream.git", CredentialProvider: "source", CredentialUsername: "git-user", Identity: &RepositoryIdentity{Mode: "provider"}}},
		}, {Name: "restricted"}},
		ExecutionBackends: []ExecutionBackend{{Name: "container", Kind: "container"}},
		RetentionPolicies: []RetentionPolicy{{Name: "persistent", Persistence: Persistence{Workspace: true, RuntimeState: true, DockerData: true}, TTL: TTL{ActiveSeconds: 14400, FailedSeconds: 3600}}, {Name: "disposable", TTL: TTL{ActiveSeconds: 3600}}},
	}
}

func configureTransport(configuration *TrustedConfiguration, transport string) {
	profile := &configuration.Profiles[0]
	profile.Egress.Transport = transport
	profile.Egress.Enforced = transport != "redirect"
	profile.Egress.ProxyProvider = "runtime-main"
	profile.Egress.MaxConcurrentTunnels = 0
	if transport == "redirect" {
		profile.Egress.ProxyProvider = ""
	}
}

func renderedPluginNames(t *testing.T, config map[string]any) []string {
	t.Helper()
	raw, ok := config["plugins"].([]any)
	if !ok {
		t.Fatalf("rendered plugins are invalid: %#v", config["plugins"])
	}
	result := make([]string, 0, len(raw))
	for _, entry := range raw {
		plugin, ok := entry.(map[string]any)
		name, nameOK := plugin["name"].(string)
		if !ok || !nameOK {
			t.Fatalf("rendered plugin is invalid: %#v", entry)
		}
		result = append(result, name)
	}
	return result
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func replaceAgentConfigRuntimeEnv(t *testing.T, raw json.RawMessage, environment map[string]any) json.RawMessage {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["runtime"].(map[string]any)["env"] = environment
	encoded, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
