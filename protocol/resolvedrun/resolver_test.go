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

func TestResolveAppliesTrustedPrecedenceAndProducesCompleteNonSecretContract(t *testing.T) {
	t.Parallel()
	configuration := validConfiguration()
	resolver, err := NewResolver(configuration)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	request := validRequest()
	resolved, err := resolver.Resolve(request)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved.ContractVersion != ContractVersion || resolved.RunID != request.RunID || resolved.Principal != request.Principal {
		t.Fatalf("identity was not frozen exactly: %#v", resolved)
	}
	if resolved.Image != "registry.example/nvt-profile:sha256-deadbeef" || resolved.Runtime.Command != "agent-cli" ||
		resolved.Runtime.Resume == nil || resolved.Runtime.Resume.Command != "agent-cli" || resolved.Runtime.Resume.Args[0] != "resume" {
		t.Fatalf("profile runtime did not replace platform defaults: %#v", resolved.Runtime)
	}
	if !reflect.DeepEqual(resolved.Tools.Packages, []string{"git", "jq"}) ||
		!resolved.CodeServer.AgentTerminalOpenOnStartup || resolved.Resources.MemoryLimit != "8Gi" {
		t.Fatalf("profile tool/code-server/resource precedence was not applied: %#v", resolved)
	}
	if resolved.Repositories[0].ID != "git.example/approved/project" ||
		resolved.Repositories[0].CredentialProvider != "source" ||
		resolved.CredentialProviders[0].BrokerProvider != "source-app" {
		t.Fatalf("trusted workflow/provider mapping was not retained: %#v", resolved)
	}
	if resolved.Egress.Mode != "mediated" || !resolved.Egress.PairedEgressRequired ||
		resolved.Egress.ProxyProvider != "runtime-main" || resolved.Broker.Grants[0].Provider != "source-app" {
		t.Fatalf("trusted broker/egress policy was not retained: %#v", resolved)
	}
	if resolved.WorkspaceInstructions.Profile != "Profile-owned guidance.\n" ||
		resolved.WorkspaceInstructions.Workflow != "Workflow-owned guidance.\n" {
		t.Fatalf("workspace guidance precedence was not retained: %#v", resolved.WorkspaceInstructions)
	}
	if resolved.Retention != "persistent" || !resolved.Persistence.Workspace || !resolved.Persistence.RuntimeState ||
		resolved.TTL.ActiveSeconds != 14400 || resolved.Execution.Name != "container" || resolved.Execution.Kind != "container" {
		t.Fatalf("retention/backend selection was not resolved: %#v", resolved)
	}
	encoded, err := json.Marshal(resolved)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(secretNeedle)) || bytes.Contains(encoded, []byte("access_token")) ||
		bytes.Contains(encoded, []byte("private_key")) {
		t.Fatalf("resolved contract contains credential material: %s", encoded)
	}
	decoded, err := DecodeResolvedAgentRun(encoded)
	if err != nil || !reflect.DeepEqual(decoded, resolved) {
		t.Fatalf("resolved contract did not strictly round trip: err=%v got=%#v", err, decoded)
	}
}

func TestResolveUsesDefaultsAndAllowsOnlyApprovedBackendAndRetentionSelections(t *testing.T) {
	t.Parallel()
	configuration := validConfiguration()
	profile := &configuration.Profiles[0]
	profile.Image = ""
	profile.Runtime = nil
	profile.Tools = nil
	profile.CodeServer = nil
	profile.Resources = nil
	profile.AllowedBackends = append(profile.AllowedBackends, "sandbox")
	configuration.ExecutionBackends = append(configuration.ExecutionBackends, ExecutionBackend{Name: "sandbox", Kind: "microvm"})
	resolver, err := NewResolver(configuration)
	if err != nil {
		t.Fatal(err)
	}
	request := validRequest()
	request.Backend = "sandbox"
	resolved, err := resolver.Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Image != configuration.Defaults.Image || resolved.Runtime.Command != "default-agent" ||
		resolved.Execution.Name != "sandbox" || resolved.Execution.Kind != "microvm" {
		t.Fatalf("default/approved override precedence is wrong: %#v", resolved)
	}

	for name, mutate := range map[string]func(*LocalRunRequest){
		"backend":   func(value *LocalRunRequest) { value.Backend = "administrator-never-approved" },
		"retention": func(value *LocalRunRequest) { value.Retention = "disposable" },
	} {
		t.Run(name, func(t *testing.T) {
			denied := request
			mutate(&denied)
			if _, err := resolver.Resolve(denied); !errors.Is(err, ErrSelectionDenied) {
				t.Fatalf("selection error = %v, want ErrSelectionDenied", err)
			}
		})
	}
}

func TestResolveRejectsUnknownAndConflictingTrustedInputs(t *testing.T) {
	t.Parallel()
	resolver, err := NewResolver(validConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	request := validRequest()
	request.Profile = "missing"
	if _, err := resolver.Resolve(request); !errors.Is(err, ErrUnknownProfile) {
		t.Fatalf("unknown profile error = %v", err)
	}
	request = validRequest()
	request.Workflow = "missing"
	if _, err := resolver.Resolve(request); !errors.Is(err, ErrUnknownWorkflow) {
		t.Fatalf("unknown workflow error = %v", err)
	}

	for name, mutate := range map[string]func(*TrustedConfiguration){
		"duplicate profile": func(value *TrustedConfiguration) {
			value.Profiles = append(value.Profiles, value.Profiles[0])
		},
		"duplicate workflow": func(value *TrustedConfiguration) {
			value.Workflows = append(value.Workflows, value.Workflows[0])
		},
		"unknown backend": func(value *TrustedConfiguration) {
			value.Profiles[0].AllowedBackends[0] = "missing"
		},
		"unknown retention": func(value *TrustedConfiguration) {
			value.Profiles[0].AllowedRetentions[0] = "missing"
		},
		"ungranted mapping provider": func(value *TrustedConfiguration) {
			value.Profiles[0].CredentialProviders[0].BrokerProvider = "other"
		},
		"mediated file grant": func(value *TrustedConfiguration) {
			value.Profiles[0].Broker.Grants[0].Materialization = "file-bundle"
		},
		"credential environment": func(value *TrustedConfiguration) {
			value.Profiles[0].Runtime.Env["PROVIDER_ACCESS_TOKEN"] = secretNeedle
		},
		"invalid egress port": func(value *TrustedConfiguration) {
			value.Profiles[0].Broker.Grants[0].EgressHosts[0] = "git.example:not-a-port"
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
}

func TestWorkflowRepositoriesCannotEscapeProfileProviderAndGrantPolicy(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*TrustedConfiguration){
		"repository ID URL mismatch": func(value *TrustedConfiguration) {
			value.Workflows[0].Repositories[0].URL = "https://attacker.example/approved/project.git"
		},
		"repository outside mapping": func(value *TrustedConfiguration) {
			value.Workflows[0].Repositories[0].ID = "git.example/other/project"
			value.Workflows[0].Repositories[0].URL = "https://git.example/other/project.git"
		},
		"caller-like provider alias": func(value *TrustedConfiguration) {
			value.Workflows[0].Repositories[0].CredentialProvider = "untrusted"
		},
		"repository outside grant": func(value *TrustedConfiguration) {
			value.Profiles[0].Broker.Grants[0].Repositories = []string{"git.example/different/*"}
		},
		"duplicate checkout destination": func(value *TrustedConfiguration) {
			copy := value.Workflows[0].Repositories[0]
			copy.ID = "git.example/approved/second"
			copy.URL = "https://git.example/approved/second.git"
			value.Workflows[0].Repositories = append(value.Workflows[0].Repositories, copy)
		},
	} {
		t.Run(name, func(t *testing.T) {
			configuration := validConfiguration()
			mutate(&configuration)
			resolver, err := NewResolver(configuration)
			if err != nil {
				// Configuration-level mapping failures are also fail closed.
				return
			}
			if _, err := resolver.Resolve(validRequest()); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("Resolve error = %v, want ErrInvalidConfiguration", err)
			}
		})
	}
}

func TestResolverSnapshotsConfigurationAndReturnsIndependentValues(t *testing.T) {
	t.Parallel()
	configuration := validConfiguration()
	resolver, err := NewResolver(configuration)
	if err != nil {
		t.Fatal(err)
	}
	configuration.Defaults.Runtime.Command = "mutated-default"
	configuration.Profiles[0].Broker.Grants[0].Provider = "mutated-provider"
	configuration.Workflows[0].Repositories[0].ID = "git.example/mutated/repository"
	first, err := resolver.Resolve(validRequest())
	if err != nil {
		t.Fatal(err)
	}
	first.Runtime.Args[0] = "mutated-argument"
	first.Broker.Grants[0].Provider = "mutated-result"
	first.Repositories[0].ID = "git.example/mutated/result"
	second, err := resolver.Resolve(validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if second.Runtime.Args[0] != "run" || second.Broker.Grants[0].Provider != "source-app" ||
		second.Repositories[0].ID != "git.example/approved/project" {
		t.Fatalf("resolver/result aliasing changed the snapshot: %#v", second)
	}
	firstJSON, _ := json.Marshal(second)
	third, _ := resolver.Resolve(validRequest())
	thirdJSON, _ := json.Marshal(third)
	if !bytes.Equal(firstJSON, thirdJSON) {
		t.Fatalf("resolution is not deterministic:\n%s\n%s", firstJSON, thirdJSON)
	}
}

func TestStrictRequestDecoderRejectsProtectedOverridesAndAmbiguity(t *testing.T) {
	t.Parallel()
	validJSON := `{"run_id":"infra","principal":{"issuer":"https://issuer.example","subject":"subject-1"},"profile":"engineering","workflow":"development","retention":"persistent"}`
	if _, err := DecodeLocalRunRequest([]byte(validJSON)); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	for _, field := range []string{
		`"repositories":[{"url":"https://attacker.example/repo"}]`,
		`"provider":"attacker-provider"`,
		`"broker":{"grants":[]}`,
		`"capabilities":["SYS_ADMIN"]`,
		`"execution":{"name":"attacker"}`,
		`"runtime":{"command":"attacker"}`,
		`"egress":{"mode":"direct"}`,
		`"profile":"other"`,
	} {
		candidate := strings.TrimSuffix(validJSON, "}") + "," + field + "}"
		if _, err := DecodeLocalRunRequest([]byte(candidate)); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("protected/duplicate field accepted: %s", field)
		}
	}
	oversized := bytes.Repeat([]byte{' '}, MaxDocumentBytes+1)
	if _, err := DecodeLocalRunRequest(oversized); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("oversized request was accepted")
	}
}

func TestInvalidPrincipalAndSecretShapedUnknownFieldsFailClosed(t *testing.T) {
	t.Parallel()
	for _, principal := range []Principal{
		{Issuer: "http://issuer.example", Subject: "subject"},
		{Issuer: "https://issuer.example?tenant=one", Subject: "subject"},
		{Issuer: "https://issuer.example", Subject: ""},
		{Issuer: "https://issuer.example", Subject: "subject\nother"},
	} {
		request := validRequest()
		request.Principal = principal
		if err := ValidateLocalRunRequest(request); err == nil {
			t.Fatalf("invalid principal accepted: %#v", principal)
		}
	}
	requestJSON := `{"run_id":"infra","principal":{"issuer":"https://issuer.example","subject":"subject-1","access_token":"` + secretNeedle + `"},"profile":"engineering","workflow":"development","retention":"persistent"}`
	if _, err := DecodeLocalRunRequest([]byte(requestJSON)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("credential-bearing principal request was accepted")
	}
	if strings.Contains(ErrInvalidRequest.Error(), secretNeedle) {
		t.Fatal("stable request error disclosed credential material")
	}
}

func validRequest() LocalRunRequest {
	return LocalRunRequest{
		RunID: "infra", Principal: Principal{Issuer: "https://issuer.example", Subject: "subject-1", DisplayName: "Engineer"},
		Profile: "engineering", Workflow: "development", Retention: "persistent",
	}
}

func validConfiguration() TrustedConfiguration {
	preseed := "check_for_update_on_startup = false\n"
	profileRuntime := Runtime{
		RuntimeCommand: RuntimeCommand{Command: "agent-cli", Args: []string{"run", "--non-interactive"}},
		Resume:         &RuntimeCommand{Command: "agent-cli", Args: []string{"resume", "--last"}},
		Env:            map[string]string{"NO_PROXY": "localhost,127.0.0.1"}, Autonomy: "trusted-local", User: "root",
		Preseed: []PreseedFile{{Path: "$HOME/.agent/config", Mode: "0600", Content: &preseed}},
	}
	profileTools := Tools{Packages: []string{"git", "jq"}, Mise: []string{"go@1.26"}, AdditionalPaths: []string{"/opt/tools/bin"}}
	profileCodeServer := CodeServer{
		Extensions:                 []string{"redhat.vscode-yaml"},
		Settings:                   map[string]json.RawMessage{"workbench.startupEditor": json.RawMessage(`"none"`)},
		AgentTerminalOpenOnStartup: true,
	}
	profileResources := Resources{CPURequest: "2", CPULimit: "2", MemoryRequest: "8Gi", MemoryLimit: "8Gi"}
	return TrustedConfiguration{
		Defaults: PlatformDefaults{
			Image:   "registry.example/nvt-default:sha256-deadbeef",
			Runtime: Runtime{RuntimeCommand: RuntimeCommand{Command: "default-agent"}, Autonomy: "interactive", User: "root"},
			Tools:   Tools{Packages: []string{"git"}}, CodeServer: CodeServer{},
			Resources: Resources{CPURequest: "1", MemoryRequest: "2Gi"},
		},
		Profiles: []Profile{{
			Name: "engineering", Image: "registry.example/nvt-profile:sha256-deadbeef", Runtime: &profileRuntime,
			Tools: &profileTools, CodeServer: &profileCodeServer, Resources: &profileResources,
			CredentialProviders: []CredentialProviderMapping{{
				Name: "source", BrokerProvider: "source-app", Repositories: []string{"git.example/approved/*"},
			}},
			Broker: Broker{Grants: []BrokerGrant{
				{Provider: "source-app", Repositories: []string{"git.example/approved/*"}, Capabilities: []string{"injection.headers"},
					Materialization: "header-inject", EgressHosts: []string{"git.example:443"}, Git: true, Permissions: map[string]string{"contents": "write"}},
				{Provider: "runtime-main", Capabilities: []string{"injection.headers"}, Materialization: "header-inject", EgressHosts: []string{"runtime.example:443"}},
			}},
			Egress:                Egress{Mode: "mediated", Transport: "forward-proxy", Enforced: true, ProxyProvider: "runtime-main", PairedEgressRequired: true, MaxConcurrentTunnels: 128},
			WorkspaceInstructions: "Profile-owned guidance.\n", AllowedBackends: []string{"container"}, DefaultBackend: "container",
			AllowedRetentions: []string{"persistent"},
		}},
		Workflows: []Workflow{{
			Name: "development", WorkspaceInstructions: "Workflow-owned guidance.\n",
			Repositories: []Repository{{
				ID: "git.example/approved/project", URL: "https://git.example/approved/project.git", Path: "project", CredentialProvider: "source",
			}},
		}},
		ExecutionBackends: []ExecutionBackend{{Name: "container", Kind: "container"}},
		RetentionPolicies: []RetentionPolicy{{
			Name: "persistent", Persistence: Persistence{Workspace: true, RuntimeState: true, DockerData: true},
			TTL: TTL{ActiveSeconds: 14400, FailedSeconds: 3600},
		}, {Name: "disposable", TTL: TTL{ActiveSeconds: 3600, CompletedSeconds: 300, FailedSeconds: 900, RunRetentionSeconds: 900}}},
	}
}
