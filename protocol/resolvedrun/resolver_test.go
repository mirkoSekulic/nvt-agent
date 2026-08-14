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
	if resolved.ContractVersion != ContractVersion || resolved.RunID != request.RunID || resolved.Principal != authorization.Principal {
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
		"invalid egress port": func(value *TrustedConfiguration) {
			value.Profiles[0].Broker.Grants[0].EgressHosts[0] = "github.com:not-a-port"
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
	return LocalRunRequest{RunID: "infra", Profile: "engineering", Workflow: "development", Retention: "persistent", Prompt: "Implement the requested change."}
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
  "plugins":[{"name":"checkout-repos","source":"builtin","when":"before-agent","restart":"never","config":{"repos":[{"url":"https://github.com/Altinn/altinn-studio.git","path":"altinn-studio"}]}}],
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
			CredentialProviders: []CredentialProviderMapping{{Name: "source", BrokerProvider: "source-app", MatchTargets: []string{"github.com/Altinn/*"}}},
			Broker: Broker{Grants: []BrokerGrant{
				{Provider: "source-app", Repositories: []string{"Altinn/*"}, Capabilities: []string{"injection.headers"}, Materialization: "header-inject", EgressHosts: []string{"github.com:443"}, Git: true, Permissions: map[string]string{"contents": "write"}},
				{Provider: "runtime-main", Capabilities: []string{"injection.headers"}, Materialization: "header-inject", EgressHosts: []string{"runtime.example:443"}},
			}},
			Egress:                Egress{Mode: "mediated", Transport: "forward-proxy", Enforced: true, ProxyProvider: "runtime-main", PairedEgressRequired: true, MaxConcurrentTunnels: 128},
			WorkspaceInstructions: "Profile-owned guidance.\n", AllowedBackends: []string{"container"}, DefaultBackend: "container", AllowedRetentions: []string{"persistent"},
		}, {
			Name: "restricted", Runtime: &profileRuntime, AgentConfig: profileAgentConfig,
			Broker:          Broker{Grants: []BrokerGrant{{Provider: "runtime-main", Capabilities: []string{"injection.headers"}, Materialization: "header-inject", EgressHosts: []string{"runtime.example:443"}}}},
			Egress:          Egress{Mode: "mediated", Transport: "forward-proxy", ProxyProvider: "runtime-main", PairedEgressRequired: true},
			AllowedBackends: []string{"container"}, DefaultBackend: "container", AllowedRetentions: []string{"persistent"},
		}},
		Workflows: []Workflow{{
			Name: "development", WorkspaceInstructions: "Workflow-owned guidance.\n",
			Repositories: []Repository{{CheckoutTarget: "github.com/Altinn/altinn-studio", BrokerRepository: "Altinn/altinn-studio", URL: "https://github.com/Altinn/altinn-studio.git", Path: "altinn-studio", CredentialProvider: "source"}},
		}, {Name: "restricted"}},
		ExecutionBackends: []ExecutionBackend{{Name: "container", Kind: "container"}},
		RetentionPolicies: []RetentionPolicy{{Name: "persistent", Persistence: Persistence{Workspace: true, RuntimeState: true, DockerData: true}, TTL: TTL{ActiveSeconds: 14400, FailedSeconds: 3600}}, {Name: "disposable", TTL: TTL{ActiveSeconds: 3600}}},
	}
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
