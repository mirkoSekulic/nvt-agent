package config_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	serviceconfig "github.com/mirkoSekulic/nvt-agent/localplatform/config"
	"github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
	plancontract "github.com/mirkoSekulic/nvt-agent/localplatform/plan"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

func TestRenderValidManifestUsesContainerPrivateFilesAndNativePolicy(t *testing.T) {
	path := filepath.Join("..", "manifest", "testdata", "valid.yaml")
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := manifest.Decode(file)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := manifest.Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}

	broker, err := serviceconfig.Broker(compiled)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range [][]byte{
		[]byte(`"private-key-file":"` + plancontract.PrivateTarget("github-key") + `"`),
		[]byte(`"injection-hosts":["github.com","api.github.com"]`),
		[]byte(`"token-file":"` + plancontract.PrivateTarget("azure-token") + `"`),
		[]byte(`"injection-basic-username":"git"`),
		[]byte(`"target-mode":"literal"`),
		[]byte(`"app-id":3912708`),
		[]byte(`"installation-id":123`),
		[]byte(`"auth-file":"/private/portal/` + plancontract.CredentialSlotName("codex") + `"`),
		[]byte(`"injection-hosts":["chatgpt.com","api.openai.com","auth.openai.com"]`),
		[]byte(`"path":".codex/auth.json"`),
		[]byte(`"header":"ChatGPT-Account-ID"`),
		[]byte(`"repositories":["dev.azure.com/example/platform/_git/infrastructure"]`),
	} {
		if !bytes.Contains(broker, expected) {
			t.Fatalf("broker configuration omitted private file reference %s: %s", expected, broker)
		}
	}
	if bytes.Contains(broker, []byte(".nvt-local")) || bytes.Contains(broker, []byte("PRIVATE KEY")) {
		t.Fatalf("host path or credential entered broker configuration: %s", broker)
	}
	if !bytes.Contains(broker, []byte(`"permissions":{"contents":"write","pull_requests":"write"}`)) || bytes.Contains(broker, []byte(`"workflows":"write"`)) {
		t.Fatalf("broker provider did not preserve least privilege: %s", broker)
	}
	if bytes.Contains(broker, []byte(plancontract.CredentialSlotName("codex")+".json")) {
		t.Fatalf("broker OAuth path does not match the portal-persisted slot name: %s", broker)
	}
	claudeCompiled := compiled
	claudeCompiled.Broker.Accounts = append(append([]manifest.NamedAccount(nil), compiled.Broker.Accounts...), manifest.NamedAccount{Name: "claude", Account: manifest.Account{Preset: "claude-oauth"}})
	claudeBroker, err := serviceconfig.Broker(claudeCompiled)
	if err != nil || !bytes.Contains(claudeBroker, []byte(`"credentials-file":"/private/portal/`+plancontract.CredentialSlotName("claude")+`"`)) || bytes.Contains(claudeBroker, []byte(plancontract.CredentialSlotName("claude")+".json")) {
		t.Fatalf("Claude broker path does not match the portal-persisted slot name: %v %s", err, claudeBroker)
	}

	controller, err := serviceconfig.Controller(compiled, serviceconfig.Instructions{"development": "bounded instructions"})
	if err != nil {
		t.Fatal(err)
	}
	var trusted resolvedrun.TrustedConfiguration
	if err := json.Unmarshal(controller, &trusted); err != nil {
		t.Fatal(err)
	}
	retentionPolicies := map[string]resolvedrun.RetentionPolicy{}
	for _, policy := range trusted.RetentionPolicies {
		retentionPolicies[policy.Name] = policy
	}
	if got := retentionPolicies["disposable"].TTL; got != (resolvedrun.TTL{ActiveSeconds: 604800, CompletedSeconds: 300, FailedSeconds: 900, RunRetentionSeconds: 86400}) {
		t.Fatalf("manifest retention TTL was not projected: %#v", got)
	}
	if got := retentionPolicies["persistent"].Persistence; got != (resolvedrun.Persistence{Workspace: true, RuntimeState: true, DockerData: true}) {
		t.Fatalf("manifest persistence was not projected: %#v", got)
	}
	resolver, err := resolvedrun.NewResolver(trusted)
	if err != nil {
		t.Fatalf("native controller policy is invalid: %v\n%s", err, controller)
	}
	workflows := map[string]resolvedrun.Workflow{}
	for _, workflow := range trusted.Workflows {
		workflows[workflow.Name] = workflow
	}
	if got := workflows["nvt-review"].Lifecycle; got == nil || strings.Join(got.CompleteOn, ",") != "plugin.work.completed" || strings.Join(got.FailOn, ",") != "plugin.work.failed" {
		t.Fatalf("review lifecycle was not projected: %#v", got)
	}
	if got := workflows["nvt-development"].Lifecycle; got == nil || strings.Join(got.CompleteOn, ",") != "plugin.github.pr.merged,plugin.github.pr.closed" || len(got.FailOn) != 0 {
		t.Fatalf("PR lifecycle was not projected: %#v", got)
	}
	authorization := resolvedrun.AuthorizationContext{Principal: resolvedrun.Principal{Issuer: "https://github.com", Subject: "owner"}, Selections: []resolvedrun.AuthorizedSelection{{Profile: "development", Workflows: []string{"nvt-development", "nvt-review"}}}}
	for _, test := range []struct {
		workflow string
		complete []string
		fail     []string
	}{
		{"nvt-review", []string{"plugin.work.completed"}, []string{"plugin.work.failed"}},
		{"nvt-development", []string{"plugin.github.pr.merged", "plugin.github.pr.closed"}, nil},
	} {
		resolved, resolveErr := resolver.Resolve(authorization, resolvedrun.LocalRunRequest{RunID: "snapshot-" + test.workflow, Profile: "development", Workflow: test.workflow, Retention: "disposable", Backend: "local-docker"})
		if resolveErr != nil || strings.Join(resolved.Lifecycle.CompleteOn, ",") != strings.Join(test.complete, ",") || strings.Join(resolved.Lifecycle.FailOn, ",") != strings.Join(test.fail, ",") {
			t.Fatalf("resolved %s lifecycle = %#v err=%v", test.workflow, resolved.Lifecycle, resolveErr)
		}
	}
	var native struct {
		Schedules []struct {
			Producers []struct {
				Selections      []struct{ Profile, Workflow string }
				DefaultWorkflow string `json:"default_workflow"`
			}
		} `json:"schedules"`
	}
	if err := json.Unmarshal(controller, &native); err != nil || len(native.Schedules) != 2 {
		t.Fatalf("native schedules = %#v err=%v", native, err)
	}
	var githubSelections map[string]string
	for _, schedule := range native.Schedules {
		if len(schedule.Producers) > 0 && schedule.Producers[0].DefaultWorkflow == "nvt-development" {
			githubSelections = map[string]string{}
			for _, selection := range schedule.Producers[0].Selections {
				githubSelections[selection.Workflow] = selection.Profile
			}
		}
	}
	if githubSelections["nvt-development"] != "development" || githubSelections["nvt-review"] != "development" || len(githubSelections) != 2 {
		t.Fatalf("authorized GitHub selections = %#v", githubSelections)
	}
	if len(trusted.Profiles) != 1 || trusted.Profiles[0].Runtime == nil || trusted.Profiles[0].Runtime.Docker == nil ||
		trusted.Profiles[0].Egress.Transport != "transparent" || !trusted.Profiles[0].Egress.AllowInsecureBroker || trusted.Profiles[0].DefaultCredentialProvider != "github" {
		t.Fatalf("local Docker or mediated transport policy missing: %#v", trusted.Profiles)
	}
	if trusted.Profiles[0].Runtime.Model != "gpt-5.6-sol" || trusted.Profiles[0].Runtime.Effort != "high" {
		t.Fatalf("runtime model and effort policy missing: %#v", trusted.Profiles[0].Runtime)
	}
	if policy := trusted.Profiles[0].Egress.DomainPolicy; policy == nil || policy.DefaultAction != "deny" ||
		strings.Join(policy.Allow, ",") != "chatgpt.com,dev.azure.com,github.com,openai.com" || strings.Join(policy.Deny, ",") != "pastebin.com" {
		t.Fatalf("normalized profile domain policy missing: %#v", policy)
	}
	githubGrantFound, codexGrantFound, azureGrantFound := false, false, false
	for _, grant := range trusted.Profiles[0].Broker.Grants {
		if grant.Provider == "codex" {
			codexGrantFound = true
			if grant.Materialization != "placeholder-file" || strings.Join(grant.EgressHosts, ",") != "chatgpt.com:443,api.openai.com:443,auth.openai.com:443" {
				t.Fatalf("Codex grant omitted placeholder mediation hosts: %#v", grant)
			}
		}
		if grant.Provider == "github" {
			githubGrantFound = true
			if strings.Join(grant.EgressHosts, ",") != "github.com:443,api.github.com:443" {
				t.Fatalf("GitHub grant omitted the API injection route: %#v", grant)
			}
			if grant.Permissions["contents"] != "write" || grant.Permissions["pull_requests"] != "write" || grant.Permissions["workflows"] != "" {
				t.Fatalf("GitHub grant did not preserve the least-privilege repository access: %#v", grant)
			}
		}
		if grant.Provider == "azure" {
			azureGrantFound = true
			if grant.Materialization != "header-inject" || !grant.Git || strings.Join(grant.EgressHosts, ",") != "dev.azure.com:443" || strings.Join(grant.Repositories, ",") != "dev.azure.com/example/platform/_git/infrastructure" {
				t.Fatalf("generic Azure-shaped grant is not exact: %#v", grant)
			}
		}
	}
	if !githubGrantFound {
		t.Fatalf("GitHub repository grant is missing: %#v", trusted.Profiles[0].Broker.Grants)
	}
	if !codexGrantFound {
		t.Fatalf("Codex runtime grant is missing: %#v", trusted.Profiles[0].Broker.Grants)
	}
	if !azureGrantFound || bytes.Contains(controller, []byte("azure-token")) || bytes.Contains(controller, []byte("/private/")) {
		t.Fatalf("generic static Git mediation exposed or omitted broker-only state: %s", controller)
	}
	var agentConfig struct {
		Plugins []struct {
			Name    string         `json:"name"`
			When    string         `json:"when"`
			Restart string         `json:"restart"`
			Config  map[string]any `json:"config"`
			Egress  struct {
				Provider string `json:"provider"`
			} `json:"egress"`
		} `json:"plugins"`
		Runtime struct {
			Args   []string `json:"args"`
			Resume struct {
				Args []string `json:"args"`
			} `json:"resume"`
		} `json:"runtime"`
		Preseed struct {
			Files []struct {
				Path      string         `json:"path"`
				Mode      string         `json:"mode"`
				Overwrite bool           `json:"overwrite"`
				Content   string         `json:"content"`
				JSON      map[string]any `json:"json"`
			} `json:"files"`
		} `json:"preseed"`
		CodeServer struct {
			AgentTerminal struct {
				OpenOnStartup bool `json:"openOnStartup"`
			} `json:"agentTerminal"`
			Settings struct {
				Overwrite bool           `json:"overwrite"`
				Values    map[string]any `json:"values"`
			} `json:"settings"`
		} `json:"code-server"`
	}
	if err := json.Unmarshal(trusted.Profiles[0].AgentConfig, &agentConfig); err != nil {
		t.Fatal(err)
	}
	pluginByName := map[string]struct {
		when, restart, provider string
		config                  map[string]any
	}{}
	for _, plugin := range agentConfig.Plugins {
		pluginByName[plugin.Name] = struct {
			when, restart, provider string
			config                  map[string]any
		}{plugin.When, plugin.Restart, plugin.Egress.Provider, plugin.Config}
	}
	watcher := pluginByName["github-watcher"]
	if watcher.when != "after-agent" || watcher.restart != "always" || watcher.provider != "github" || fmt.Sprint(watcher.config["poll-seconds"]) != "30" {
		t.Fatalf("mediated github-watcher plugin policy = %#v", watcher)
	}
	if workControl, exists := pluginByName["work-control"]; !exists || workControl.provider != "" {
		t.Fatalf("ordinary work-control plugin policy = %#v", workControl)
	}
	if got := agentConfig.Runtime.Resume.Args; len(got) != 3 || got[0] != "resume" || got[1] != "--last" || got[2] != "--dangerously-bypass-approvals-and-sandbox" {
		t.Fatalf("Codex resume command is incomplete: %#v", got)
	}
	if len(agentConfig.Preseed.Files) != 1 || agentConfig.Preseed.Files[0].Path != "$HOME/.codex/config.toml" ||
		agentConfig.Preseed.Files[0].Mode != "0600" || agentConfig.Preseed.Files[0].Overwrite ||
		!strings.Contains(agentConfig.Preseed.Files[0].Content, `[projects."/workspace"]`) ||
		!strings.Contains(agentConfig.Preseed.Files[0].Content, `trust_level = "trusted"`) ||
		!strings.Contains(agentConfig.Preseed.Files[0].Content, "hide_rate_limit_model_nudge = true") {
		t.Fatalf("Codex first-run preseed is incomplete: %#v", agentConfig.Preseed.Files)
	}
	if !agentConfig.CodeServer.AgentTerminal.OpenOnStartup || !agentConfig.CodeServer.Settings.Overwrite {
		t.Fatalf("managed code-server defaults are incomplete: %#v", agentConfig.CodeServer)
	}
	for key, expected := range map[string]any{
		"workbench.colorTheme":             "Default Dark Modern",
		"workbench.startupEditor":          "none",
		"security.workspace.trust.enabled": false,
		"extensions.ignoreRecommendations": true,
		"editor.minimap.enabled":           false,
		"keyboard.dispatch":                "keyCode",
	} {
		if got := agentConfig.CodeServer.Settings.Values[key]; got != expected {
			t.Fatalf("code-server setting %q = %#v, want %#v", key, got, expected)
		}
	}
	claudeRuntimeCompiled := compiled
	claudeRuntimeCompiled.Controller.Profiles = append([]manifest.ControllerProfileIntent(nil), compiled.Controller.Profiles...)
	claudeRuntimeCompiled.Controller.Profiles[0].Profile.Runtime.Preset = "claude"
	claudeController, err := serviceconfig.Controller(claudeRuntimeCompiled, serviceconfig.Instructions{"development": "bounded instructions"})
	if err != nil {
		t.Fatal(err)
	}
	var claudeTrusted resolvedrun.TrustedConfiguration
	if err := json.Unmarshal(claudeController, &claudeTrusted); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(claudeTrusted.Profiles[0].AgentConfig, &agentConfig); err != nil {
		t.Fatal(err)
	}
	if got := agentConfig.Runtime.Resume.Args; len(got) != 2 || got[0] != "--continue" || got[1] != "--dangerously-skip-permissions" {
		t.Fatalf("Claude resume command is incomplete: %#v", got)
	}
	if len(agentConfig.Preseed.Files) != 2 || agentConfig.Preseed.Files[0].Path != "$HOME/.claude/settings.json" || agentConfig.Preseed.Files[1].Path != "$HOME/.claude.json" {
		t.Fatalf("Claude first-run preseed is incomplete: %#v", agentConfig.Preseed.Files)
	}
	projects, ok := agentConfig.Preseed.Files[1].JSON["projects"].(map[string]any)
	if !ok {
		t.Fatalf("Claude workspace trust projects are missing: %#v", agentConfig.Preseed.Files[1].JSON)
	}
	workspace, ok := projects["/workspace"].(map[string]any)
	if !ok || workspace["hasTrustDialogAccepted"] != true {
		t.Fatalf("Claude workspace trust is incomplete: %#v", projects)
	}
	if _, err := serviceconfig.Controller(compiled, serviceconfig.Instructions{"development": strings.Repeat("x", resolvedrun.MaxWorkspaceInstructionsBytes+1)}); err == nil {
		t.Fatal("controller projection accepted oversized native workspace instructions")
	}
	overpopulated := compiled
	overpopulated.Controller.Workstations = make([]manifest.Workstation, 129)
	for index := range overpopulated.Controller.Workstations {
		overpopulated.Controller.Workstations[index] = manifest.Workstation{Name: fmt.Sprintf("workstation-%03d", index), Profile: "development"}
	}
	if _, err := serviceconfig.Controller(overpopulated, serviceconfig.Instructions{"development": "bounded instructions"}); err == nil {
		t.Fatal("controller projection accepted too many native workstations")
	}
	readOnly := compiled
	readOnly.Controller.Profiles = append([]manifest.ControllerProfileIntent(nil), compiled.Controller.Profiles...)
	readOnly.Controller.Profiles[0].Profile.Runtime.Autonomy = "read-only"
	if _, err := serviceconfig.Controller(readOnly, serviceconfig.Instructions{"development": "bounded instructions"}); err == nil || !strings.Contains(err.Error(), "compiled runtime autonomy is unsupported") {
		t.Fatalf("unsupported compiled read-only autonomy did not fail closed: %v", err)
	}
	incompatible := compiled
	incompatible.Controller.Workflows = append([]manifest.NamedWorkflow(nil), compiled.Controller.Workflows...)
	for index := range incompatible.Controller.Workflows {
		if incompatible.Controller.Workflows[index].Name == "nvt-review" {
			incompatible.Controller.Workflows[index].Workflow.Retention = "retained"
		}
	}
	if _, err := serviceconfig.Controller(incompatible, serviceconfig.Instructions{"development": "bounded instructions"}); err == nil || !strings.Contains(err.Error(), "incompatible workflow policy") {
		t.Fatalf("mixed-retention command workflows did not fail closed: %v", err)
	}
	unsupported := compiled
	unsupported.Controller.ProducerAdmissions = append([]manifest.ProducerAdmissionIntent(nil), compiled.Controller.ProducerAdmissions...)
	unsupported.Controller.ProducerAdmissions[1].CommandWorkflows = map[string]string{"deploy": "nvt-review"}
	if _, err := serviceconfig.Controller(unsupported, serviceconfig.Instructions{"development": "bounded instructions"}); err == nil || !strings.Contains(err.Error(), "unsupported command mapping") {
		t.Fatalf("unsupported compiled command mapping did not fail closed: %v", err)
	}
	github := decoded.Accounts["github"]
	github.Installations["other"] = "456"
	decoded.Accounts["github"] = github
	decoded.Repositories["other"] = manifest.Repository{GitHub: "other/repository", Account: "github"}
	decoded.Workstations[0].Repositories = append(decoded.Workstations[0].Repositories, "other")
	ambiguous, err := manifest.Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serviceconfig.Controller(ambiguous, serviceconfig.Instructions{"development": "bounded instructions"}); err == nil || !bytes.Contains([]byte(err.Error()), []byte("plugin egress provider is ambiguous")) {
		t.Fatalf("multi-installation plugin egress policy did not fail closed: %v", err)
	}
}

func TestExplicitWorkflowWriteRendersForGitHubApp(t *testing.T) {
	raw, err := os.ReadFile("../manifest/testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Replace(string(raw), "    account: github\n  infrastructure:", "    account: github\n    access:\n      permissions:\n        contents: write\n        pull_requests: write\n        workflows: write\n  infrastructure:", 1)
	decoded, err := manifest.Decode(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := manifest.Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := serviceconfig.Broker(compiled)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := serviceconfig.Controller(compiled, serviceconfig.Instructions{"development": "test"})
	if err != nil {
		t.Fatal(err)
	}
	for label, rendered := range map[string][]byte{"broker": broker, "controller": controller} {
		if !bytes.Contains(rendered, []byte(`"workflows":"write"`)) {
			t.Fatalf("%s omitted explicit workflow write: %s", label, rendered)
		}
	}
}

func TestGenericStaticGitProviderRendersSelfHostedWithoutSecretDisclosure(t *testing.T) {
	raw, err := os.ReadFile("../manifest/testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := manifest.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	decoded.Secrets["studio-token"] = manifest.Secret{File: "./.nvt-local/secrets/studio/token"}
	decoded.BrokerProviders["studio"] = manifest.BrokerProvider{Plugin: "token", Config: map[string]any{"label": "studio-provider", "injection-hosts": []any{"altinn.studio"}, "injection-git": true, "injection-basic-username": "oauth2", "target-mode": "literal"}, Secrets: map[string]string{"token-file": "studio-token"}, Mediation: manifest.BrokerProviderMediation{Hosts: []string{"altinn.studio"}, Materialization: "header-inject", Git: true, Username: "oauth2", TargetMode: "literal"}}
	profile := decoded.Profiles["development"]
	profile.CredentialProviders = append(profile.CredentialProviders, "studio")
	profile.Egress.DomainPolicy.Allow = append(profile.Egress.DomainPolicy.Allow, "altinn.studio")
	decoded.Profiles["development"] = profile
	decoded.Repositories["studio"] = manifest.Repository{URL: "https://altinn.studio/repos/digdir/oed.git", CheckoutTarget: "altinn.studio/repos/digdir/oed", BrokerRepository: "altinn.studio/repos/digdir/oed", Path: "studio", CredentialProvider: "studio"}
	decoded.Workstations[0].Repositories = append(decoded.Workstations[0].Repositories, "studio")
	compiled, err := manifest.Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := serviceconfig.Broker(compiled)
	for _, expected := range [][]byte{[]byte(`"name":"studio"`), []byte(`"plugin":"token"`), []byte(`"label":"studio-provider"`), []byte(`"token-file":"` + plancontract.PrivateTarget("studio-token") + `"`), []byte(`"injection-hosts":["altinn.studio"]`), []byte(`"injection-basic-username":"oauth2"`), []byte(`"target-mode":"literal"`), []byte(`"repositories":["altinn.studio/repos/digdir/oed"]`)} {
		if err != nil || !bytes.Contains(broker, expected) {
			t.Fatalf("generic provider omitted %s: %v %s", expected, err, broker)
		}
	}
	if bytes.Contains(broker, []byte("./.nvt-local")) || bytes.Contains(broker, []byte("studio-readonly-token")) {
		t.Fatalf("host path or secret entered broker config: %s", broker)
	}
	controller, err := serviceconfig.Controller(compiled, serviceconfig.Instructions{"development": "test"})
	if err != nil {
		t.Fatal(err)
	}
	var trusted resolvedrun.TrustedConfiguration
	if err := json.Unmarshal(controller, &trusted); err != nil {
		t.Fatal(err)
	}
	for _, grant := range trusted.Profiles[0].Broker.Grants {
		if grant.Provider == "studio" && (len(grant.Permissions) != 0 || strings.Join(grant.Repositories, ",") != "altinn.studio/repos/digdir/oed" || strings.Join(grant.EgressHosts, ",") != "altinn.studio:443") {
			t.Fatalf("generic grant is not exact: %#v", grant)
		}
	}
	foundRepository := false
	for _, workflow := range trusted.Workflows {
		for _, repository := range workflow.Repositories {
			if repository.BrokerRepository == "altinn.studio/repos/digdir/oed" {
				foundRepository = true
				if repository.CredentialProvider != "studio" || repository.CredentialUsername != "oauth2" {
					t.Fatalf("self-hosted repository omitted provider-scoped placeholder identity: %#v", repository)
				}
			}
		}
	}
	if !foundRepository {
		t.Fatal("self-hosted repository was not rendered")
	}
}

func TestGenericStaticGitProviderRendersGitHubTargetIdentity(t *testing.T) {
	raw, err := os.ReadFile("../manifest/testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := manifest.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	decoded.Secrets["github-token"] = manifest.Secret{File: "./.nvt-local/secrets/github/token"}
	decoded.BrokerProviders["github-token"] = manifest.BrokerProvider{
		Plugin:    "token",
		Config:    map[string]any{"injection-hosts": []any{"github.com"}, "injection-git": true, "injection-basic-username": "git", "target-mode": "github"},
		Secrets:   map[string]string{"token-file": "github-token"},
		Mediation: manifest.BrokerProviderMediation{Hosts: []string{"github.com"}, Materialization: "header-inject", Git: true, Username: "git", TargetMode: "github"},
	}
	profile := decoded.Profiles["development"]
	profile.CredentialProviders = append(profile.CredentialProviders, "github-token")
	decoded.Profiles["development"] = profile
	decoded.Repositories["github-static"] = manifest.Repository{URL: "https://github.com/example/project.git", CheckoutTarget: "github.com/example/project", BrokerRepository: "example/project", Path: "github-static", CredentialProvider: "github-token"}
	decoded.Workstations[0].Repositories = append(decoded.Workstations[0].Repositories, "github-static")
	compiled, err := manifest.Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := serviceconfig.Broker(compiled)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range [][]byte{[]byte(`"name":"github-token"`), []byte(`"target-mode":"github"`), []byte(`"repositories":["example/project"]`)} {
		if !bytes.Contains(broker, expected) {
			t.Fatalf("GitHub provider omitted %s: %s", expected, broker)
		}
	}
	controller, err := serviceconfig.Controller(compiled, serviceconfig.Instructions{"development": "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(controller, []byte(`"broker_repository":"example/project"`)) || !bytes.Contains(controller, []byte(`"repositories":["example/project"]`)) {
		t.Fatalf("controller did not preserve normalized GitHub identity: %s", controller)
	}
}

func TestGenericBrokerProviderConfigPassesThroughWithoutPluginSchemaMutation(t *testing.T) {
	raw, err := os.ReadFile("../manifest/testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := manifest.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	provider := decoded.BrokerProviders["azure"]
	provider.Plugin = "installed-custom"
	provider.Config = map[string]any{"public-option": "unchanged"}
	decoded.BrokerProviders["azure"] = provider
	compiled, err := manifest.Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := serviceconfig.Broker(compiled)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Providers []struct {
			Name   string         `json:"name"`
			Plugin string         `json:"plugin"`
			Config map[string]any `json:"config"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(rendered, &document); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range document.Providers {
		if candidate.Name != "azure" {
			continue
		}
		if candidate.Plugin != "installed-custom" || candidate.Config["public-option"] != "unchanged" || candidate.Config["token-file"] != plancontract.PrivateTarget("azure-token") || len(candidate.Config) != 2 {
			t.Fatalf("provider config was interpreted or mutated: %#v", candidate)
		}
		return
	}
	t.Fatal("generic provider was not rendered")
}

func TestBrokerRejectsDerivedProviderNameCollision(t *testing.T) {
	file, err := os.Open(filepath.Join("..", "manifest", "testdata", "valid.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := manifest.Decode(file)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	github := decoded.Accounts["github"]
	github.Installations = map[string]string{"mirkoSekulic": "123", "owner-one": "456", "owner-two": "789"}
	decoded.Accounts["github"] = github
	decoded.Secrets["collision-token"] = manifest.Secret{File: "./.nvt-local/secrets/collision-token"}
	decoded.BrokerProviders["github-70864727"] = manifest.BrokerProvider{Plugin: "token", Secrets: map[string]string{"token-file": "collision-token"}, Mediation: manifest.BrokerProviderMediation{Hosts: []string{"git.example"}, Materialization: "header-inject", Git: true, Username: "git", TargetMode: "literal"}}
	compiled, err := manifest.Compile(decoded)
	if err != nil {
		t.Fatalf("collision fixture is not schema-valid: %v", err)
	}
	if _, err := serviceconfig.Broker(compiled); err == nil || !strings.Contains(err.Error(), `provider name "github-70864727" is not unique`) {
		t.Fatalf("derived provider collision did not fail closed: %v", err)
	}
}
