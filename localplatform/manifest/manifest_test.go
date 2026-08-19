package manifest

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

func cloneMap[K comparable, V any](source map[K]V) map[K]V {
	result := make(map[K]V, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func TestValidFixtureCompilesDeterministically(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	first, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	compiled, err := Compile(first)
	if err != nil {
		t.Fatalf("compile fixture: %v", err)
	}
	want, err := compiled.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}

	reordered := strings.ReplaceAll(string(raw), "accounts: [github, codex]", "accounts: [codex, github]")
	reordered = strings.ReplaceAll(reordered, "packages: [jq, git]", "packages: [git, jq]")
	second, err := Decode(strings.NewReader(reordered))
	if err != nil {
		t.Fatalf("decode equivalent: %v", err)
	}
	secondCompiled, err := Compile(second)
	if err != nil {
		t.Fatal(err)
	}
	got, err := secondCompiled.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("equivalent manifests differ:\n%s\n%s", want, got)
	}
	if bytes.Contains(got, []byte("PRIVATE")) {
		t.Fatal("compiled output contains secret material")
	}
}

func TestDecodeRejectsUnsafeInput(t *testing.T) {
	valid, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dottedProfile := strings.Replace(string(valid), "  development:\n    runtime:", "  engineering.team:\n    runtime:", 1)
	dottedProfile = strings.ReplaceAll(dottedProfile, "profile: development", "profile: engineering.team")
	cases := map[string]string{
		"unknown field":                              strings.Replace(string(valid), "apiVersion:", "unexpected: true\napiVersion:", 1),
		"duplicate key":                              strings.Replace(string(valid), "apiVersion: nvt.dev/local/v1", "apiVersion: nvt.dev/local/v1\napiVersion: nvt.dev/local/v1", 1),
		"second document":                            string(valid) + "\n---\n{}\n",
		"unsafe secret":                              strings.Replace(string(valid), "./.nvt-local/secrets/github/main-app.pem", "../private-key", 1),
		"unresolved reference":                       strings.Replace(string(valid), "privateKeySecret: github-key", "privateKeySecret: absent", 1),
		"mutable image":                              strings.Replace(string(valid), "ghcr.io/example/chat-producer@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ghcr.io/example/chat-producer:latest", 1),
		"invalid OCI image":                          strings.Replace(string(valid), "ghcr.io/example/chat-producer@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "https://host/repo?x@sha256:"+strings.Repeat("a", 64), 1),
		"secret config":                              strings.Replace(string(valid), "commandPrefix: /agent", "apiToken: embedded", 1),
		"unsupported scalar":                         strings.Replace(string(valid), "appId: \"3912708\"", "appId: 2026-01-01", 1),
		"incompatible producer account":              strings.Replace(string(valid), "preset: github-comments\n    account: github", "preset: github-comments\n    account: codex", 1),
		"missing installation":                       strings.Replace(string(valid), "mirkoSekulic: \"123\"", "another-owner: \"123\"", 1),
		"unknown repository":                         strings.Replace(string(valid), "repository: nvt-agent", "repository: absent", 1),
		"non-DNS workflow name":                      strings.ReplaceAll(string(valid), "nvt-development", "nvt.development"),
		"non-DNS producer name":                      strings.Replace(string(valid), "name: nvt-comments", "name: nvt.comments", 1),
		"non-DNS profile name":                       dottedProfile,
		"undeclared external config":                 strings.Replace(string(valid), "publicConfig:", "config:", 1),
		"GitHub repository generic provider":         strings.Replace(string(valid), "github: mirkoSekulic/nvt-agent\n    account: github", "github: mirkoSekulic/nvt-agent\n    credentialProvider: azure", 1),
		"custom repository GitHub account":           strings.Replace(string(valid), "path: infrastructure\n    credentialProvider: azure", "path: infrastructure\n    account: github", 1),
		"built-in public config":                     strings.Replace(string(valid), "prefix: /nvtagent", "prefix: /nvtagent\n    publicConfig: {mode: public}", 1),
		"built-in manual secret":                     strings.Replace(string(valid), "prefix: /nvtagent", "prefix: /nvtagent\n    secrets: {key: github-key}", 1),
		"missing runtime account":                    strings.Replace(string(valid), "      account: codex", "      account: github", 1),
		"unsupported runtime effort":                 strings.Replace(string(valid), "      effort: high", "      effort: max", 1),
		"runtime model with surrounding whitespace":  strings.Replace(string(valid), "      model: gpt-5.6-sol", "      model: ' gpt-5.6-sol'", 1),
		"GitHub App missing checkout installation":   strings.Replace(string(valid), "github: mirkoSekulic/nvt-agent", "github: Altinn/nvt-agent", 1),
		"external producer missing issuer":           strings.Replace(string(valid), "    allowedPrincipalIssuers: [https://chat.example]\n", "", 1),
		"external producer unsafe issuer":            strings.Replace(string(valid), "https://chat.example", "http://chat.example", 1),
		"external producer missing runtime identity": strings.Replace(string(valid), "    runtimeIdentity:\n      uid: 1000\n      gid: 1000\n", "", 1),
		"external producer root runtime identity":    strings.Replace(string(valid), "      uid: 1000\n      gid: 1000", "      uid: 0\n      gid: 0", 1),
		"built-in producer issuer override":          strings.Replace(string(valid), "    prefix: /nvtagent\n", "    prefix: /nvtagent\n    allowedPrincipalIssuers: [https://github.com]\n", 1),
		"built-in producer runtime override":         strings.Replace(string(valid), "    prefix: /nvtagent\n", "    prefix: /nvtagent\n    runtimeIdentity: {uid: 1000, gid: 1000}\n", 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(raw)); err == nil {
				t.Fatal("unsafe input accepted")
			}
		})
	}
	if _, err := Decode(bytes.NewReader(bytes.Repeat([]byte{'x'}, MaxDocumentBytes+1))); err == nil {
		t.Fatal("oversized input accepted")
	}
}

func TestProducerLimitMatchesControllerScheduleCapacity(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	prototype := decoded.Producers[1]
	decoded.Producers = make([]Producer, 0, MaxProducers+1)
	for index := 0; index < MaxProducers; index++ {
		producer := prototype
		producer.Name = fmt.Sprintf("producer-%02d", index)
		decoded.Producers = append(decoded.Producers, producer)
	}
	compiled, err := Compile(decoded)
	if err != nil || len(compiled.Producers) != MaxProducers {
		t.Fatalf("compile producer boundary: producers=%d err=%v", len(compiled.Producers), err)
	}
	producer := prototype
	producer.Name = "producer-64"
	decoded.Producers = append(decoded.Producers, producer)
	if _, err := Compile(decoded); err == nil {
		t.Fatal("manifest exceeding controller schedule capacity was accepted")
	}
}

func TestCompiledSectionsAreOwnerSufficient(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	controllerProfile := compiled.Controller.Profiles[0]
	if len(compiled.Controller.RetentionPolicies) != 3 || compiled.Controller.RetentionPolicies[0].Name != "disposable" || compiled.Controller.RetentionPolicies[0].Policy.TTL.ActiveSeconds != 604800 {
		t.Fatalf("controller retention policy projection is incomplete: %#v", compiled.Controller.RetentionPolicies)
	}
	if len(compiled.Controller.Profiles) != 1 || controllerProfile.Profile.Runtime.Preset != "codex" || controllerProfile.Profile.Runtime.Model != "gpt-5.6-sol" || controllerProfile.Profile.Runtime.Effort != "high" || controllerProfile.RuntimeProvider == nil || controllerProfile.RuntimeProvider.Name != "codex" || controllerProfile.DefaultCredentialProvider != "github" || controllerProfile.EgressProxyProvider != "codex" || len(controllerProfile.CredentialProviders) != 2 || len(controllerProfile.BrokerGrants) != 3 || controllerProfile.BrokerGrants[0].Purpose != "runtime-injection" || len(compiled.Controller.Repositories) != 2 {
		t.Fatalf("controller projection is incomplete: %#v", compiled.Controller)
	}
	if len(compiled.Broker.Profiles) != 1 || len(compiled.Broker.Profiles[0].Accounts) != 2 || len(compiled.Broker.Providers) != 1 || len(compiled.Broker.Repositories) != 2 {
		t.Fatalf("broker projection is incomplete: %#v", compiled.Broker)
	}
	var github, external *ProducerIntent
	for index := range compiled.Producers {
		if compiled.Producers[index].Kind == "github-comments" {
			github = &compiled.Producers[index]
		} else if compiled.Producers[index].Kind == "oci" {
			external = &compiled.Producers[index]
		}
	}
	if github == nil || github.GitHub == nil || github.GitHub.AppID != 3912708 || github.GitHub.InstallationID != 123 || github.GitHub.RepositoryOwner != "mirkoSekulic" || github.GitHub.PrivateKeySecret != "github-key" {
		t.Fatalf("GitHub producer projection is incomplete: %#v", github)
	}
	if github.RuntimeIdentity != (RuntimeIdentityIntent{UID: 65532, GID: 65532}) || external == nil || external.RuntimeIdentity != (RuntimeIdentityIntent{UID: 1000, GID: 1000}) {
		t.Fatalf("producer runtime identities are incomplete: github=%#v external=%#v", github, external)
	}
	ownedKey := false
	for _, input := range compiled.PrivateInputs {
		if input.Owner == github.Owner && input.Name == "github-key" {
			ownedKey = true
		}
	}
	if !ownedKey {
		t.Fatal("GitHub producer does not own its private-key input")
	}
	if len(compiled.Gateway.CredentialPortalAccounts) != 1 || compiled.Gateway.CredentialPortalAccounts[0] != (PortalAccountIntent{"codex", "codex-oauth"}) {
		t.Fatalf("gateway credential portal projection is incomplete: %#v", compiled.Gateway)
	}
}

func TestRetentionPoliciesAreExplicitAndReferenced(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got := decoded.RetentionPolicies["disposable"].TTL.ActiveSeconds; got != 604800 {
		t.Fatalf("disposable active TTL = %d, want 604800", got)
	}

	unknown := decoded
	unknown.Workflows = cloneMap(decoded.Workflows)
	workflow := unknown.Workflows["nvt-development"]
	workflow.Retention = "missing"
	unknown.Workflows["nvt-development"] = workflow
	if err := unknown.Validate(); err == nil {
		t.Fatal("workflow referencing an unknown retention policy was accepted")
	}

	for name, mutate := range map[string]func(*Manifest){
		"negative TTL": func(value *Manifest) {
			policy := value.RetentionPolicies["disposable"]
			policy.TTL.ActiveSeconds = -1
			value.RetentionPolicies["disposable"] = policy
		},
		"oversized TTL": func(value *Manifest) {
			policy := value.RetentionPolicies["disposable"]
			policy.TTL.ActiveSeconds = MaxTTLSeconds + 1
			value.RetentionPolicies["disposable"] = policy
		},
		"expiring workstation policy": func(value *Manifest) {
			policy := value.RetentionPolicies["persistent"]
			policy.TTL.ActiveSeconds = 1
			value.RetentionPolicies["persistent"] = policy
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := decoded
			value.RetentionPolicies = cloneMap(decoded.RetentionPolicies)
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("invalid retention policy was accepted")
			}
		})
	}
}

func TestControllerProfileProjectionSatisfiesResolvedRunContract(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	intent := compiled.Controller.Profiles[0]
	profile := resolvedrun.Profile{Name: intent.Name, DefaultCredentialProvider: intent.DefaultCredentialProvider, AllowedBackends: []string{"local"}, DefaultBackend: "local", AllowedRetentions: []string{"disposable"}}
	for _, provider := range intent.CredentialProviders {
		var targets []string
		for _, repository := range compiled.Controller.Repositories {
			if repositoryProvider(repository) == provider.Name {
				targets = append(targets, repository.CheckoutTarget)
			}
		}
		profile.CredentialProviders = append(profile.CredentialProviders, resolvedrun.CredentialProviderMapping{Name: provider.Name, BrokerProvider: provider.Name, CredentialKind: "mediated", MatchTargets: targets})
	}
	for _, grant := range intent.BrokerGrants {
		hosts := []string{map[string]string{"codex-oauth": "api.openai.com:443", "github-app": "github.com:443"}[grant.Preset]}
		if grant.Mediation != nil {
			hosts = []string{grant.Mediation.Hosts[0] + ":443"}
		}
		profile.Broker.Grants = append(profile.Broker.Grants, resolvedrun.BrokerGrant{Provider: grant.Provider, Repositories: grant.Repositories, Capabilities: []string{"injection.headers"}, Materialization: "header-inject", EgressHosts: hosts, Git: grant.Purpose == "repository"})
	}
	profile.Egress = resolvedrun.Egress{Mode: "mediated", Transport: "forward-proxy", Enforced: true, ProxyProvider: intent.EgressProxyProvider, PairedEgressRequired: true}
	configuration := resolvedrun.TrustedConfiguration{
		Defaults: resolvedrun.PlatformDefaults{Image: "nvt-agent-runtime:latest", Runtime: resolvedrun.Runtime{Type: "local-agent", Autonomy: "trusted-local", User: "root"}, AgentConfig: []byte(`{"runtime":{"command":"bash","args":[]},"plugins":[]}`)},
		Profiles: []resolvedrun.Profile{profile}, Workflows: []resolvedrun.Workflow{{Name: "development"}},
		ExecutionBackends: []resolvedrun.ExecutionBackend{{Name: "local", Kind: "container"}}, RetentionPolicies: []resolvedrun.RetentionPolicy{{Name: "disposable"}},
	}
	if _, err := resolvedrun.NewResolver(configuration); err != nil {
		t.Fatalf("controller-only projection produced invalid resolvedrun profile: %v profile=%#v", err, profile)
	}
}

func TestControllerAdmissionsAreExactlyProducerScoped(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	for index := range decoded.Producers {
		if decoded.Producers[index].Name == "external-chat" {
			decoded.Producers[index].Workflow = "infrastructure"
		}
	}
	compiled, err := Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.Controller.ProducerAdmissions) != 2 || len(compiled.GeneratedPrivateInputs) != 2 {
		t.Fatalf("admission projection is incomplete: %#v", compiled.Controller.ProducerAdmissions)
	}
	want := map[string]string{"external-chat": "infrastructure", "nvt-comments": "nvt-development"}
	wantIssuer := map[string]string{"external-chat": "https://chat.example", "nvt-comments": "https://github.com"}
	for _, binding := range compiled.Controller.ProducerAdmissions {
		if want[binding.Producer] != binding.Workflow || binding.Identity != "producer:"+binding.Producer || binding.Credential != "producer-admission:"+binding.Producer || strings.Join(binding.AllowedPrincipalIssuers, ",") != wantIssuer[binding.Producer] {
			t.Fatalf("invalid admission binding: %#v", binding)
		}
		delete(want, binding.Producer)
	}
	if len(want) != 0 {
		t.Fatalf("missing producer bindings: %#v", want)
	}
	for _, credential := range compiled.GeneratedPrivateInputs {
		producer := strings.TrimPrefix(credential.Name, "producer-admission:")
		if credential.Owner != "local-platform-state" || strings.Join(credential.Consumers, ",") != "local-controller,producer:"+producer {
			t.Fatalf("invalid generated credential ownership: %#v", credential)
		}
	}
}

func TestRuntimeAccountIsExplicitWithMultipleCompatibleAccounts(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	decoded.Accounts["codex-b"] = Account{Preset: "codex-oauth"}
	profile := decoded.Profiles["development"]
	profile.Accounts = append(profile.Accounts, "codex-b")
	decoded.Profiles["development"] = profile
	compiled, err := Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Controller.Profiles[0].Profile.Runtime.Account != "codex" {
		t.Fatalf("runtime account selection changed: %#v", compiled.Controller.Profiles[0])
	}
}

func TestReadOnlyAutonomyIsRejected(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	profile := decoded.Profiles["development"]
	profile.Runtime.Autonomy = "read-only"
	decoded.Profiles["development"] = profile
	if err := decoded.Validate(); err == nil {
		t.Fatal("manifest accepted unsupported read-only autonomy")
	}
}

func TestRuntimeModelAndEffortAreOptionalAndPresetSpecific(t *testing.T) {
	tests := []struct {
		name    string
		runtime Runtime
		valid   bool
	}{
		{name: "codex omitted", runtime: Runtime{Preset: "codex"}, valid: true},
		{name: "codex model only", runtime: Runtime{Preset: "codex", Model: "gpt-5.6-sol"}, valid: true},
		{name: "codex effort only", runtime: Runtime{Preset: "codex", Effort: "xhigh"}, valid: true},
		{name: "claude omitted", runtime: Runtime{Preset: "claude"}, valid: true},
		{name: "claude model and effort", runtime: Runtime{Preset: "claude", Model: "claude-opus", Effort: "max"}, valid: true},
		{name: "codex rejects claude max", runtime: Runtime{Preset: "codex", Effort: "max"}},
		{name: "claude rejects codex minimal", runtime: Runtime{Preset: "claude", Effort: "minimal"}},
		{name: "shell rejects model", runtime: Runtime{Preset: "shell", Model: "custom"}},
		{name: "shell rejects effort", runtime: Runtime{Preset: "shell", Effort: "high"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validRuntimeSelection(test.runtime); got != test.valid {
				t.Fatalf("validRuntimeSelection(%#v) = %t, want %t", test.runtime, got, test.valid)
			}
		})
	}
}

func TestExplicitGitHubRepositoryRequiresAppInstallation(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	decoded.Repositories["explicit"] = Repository{URL: "https://github.com/Altinn/repository.git", CheckoutTarget: "github.com/Altinn/repository", BrokerRepository: "Altinn/repository", Account: "github"}
	if err := decoded.Validate(); err == nil {
		t.Fatal("explicit GitHub repository without an owner installation was accepted")
	}
}

func TestExplicitRepositoryBrokerIdentityMustMatchProviderTarget(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	github := decoded.Accounts["github"]
	github.Installations["owner-one"] = "456"
	decoded.Accounts["github"] = github
	decoded.Repositories["explicit"] = Repository{URL: "https://github.com/owner-one/repo.git", CheckoutTarget: "github.com/owner-one/repo", BrokerRepository: "alias/repo", Account: "github"}
	if err := decoded.Validate(); err == nil || !strings.Contains(err.Error(), "must match the URL coordinates") {
		t.Fatalf("mismatched GitHub broker identity was accepted: %v", err)
	}
	azure := decoded.Repositories["infrastructure"]
	azure.BrokerRepository = "example/platform/infrastructure"
	decoded.Repositories["explicit"] = Repository{URL: "https://github.com/owner-one/repo.git", CheckoutTarget: "github.com/owner-one/repo", BrokerRepository: "owner-one/repo", Account: "github"}
	decoded.Repositories["infrastructure"] = azure
	if err := decoded.Validate(); err == nil || !strings.Contains(err.Error(), "must exactly match the normalized checkout target") {
		t.Fatalf("non-normalized Azure broker identity was accepted: %v", err)
	}
}

func TestBrokerGrantsDoNotCrossProfilesSharingAnAccount(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	decoded.Profiles["other"] = Profile{Runtime: Runtime{Preset: "shell", Autonomy: "approval-required"}, Accounts: []string{"github"}}
	decoded.Repositories["other"] = Repository{GitHub: "mirkoSekulic/other", Account: "github", Access: &RepositoryAccess{Permissions: map[string]string{"contents": "write", "pull_requests": "write", "workflows": "write"}}}
	decoded.Workflows["other"] = Workflow{Profile: "other", Repository: "other", Retention: "disposable"}
	compiled, err := Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	grants := map[string][]BrokerGrantIntent{}
	for _, profile := range compiled.Broker.Profiles {
		grants[profile.Name] = profile.Grants
	}
	if len(grants["other"]) != 1 || strings.Join(grants["other"][0].Repositories, ",") != "mirkoSekulic/other" {
		t.Fatalf("other profile grants = %#v", grants["other"])
	}
	if grants["other"][0].Permissions["workflows"] != "write" {
		t.Fatalf("opted-in profile omitted workflow authority: %#v", grants["other"])
	}
	for _, grant := range grants["development"] {
		if grant.Purpose == "repository" && grant.Permissions["workflows"] != "" {
			t.Fatalf("default profile inherited workflow authority: %#v", grant)
		}
		for _, repository := range grant.Repositories {
			if repository == "mirkoSekulic/other" {
				t.Fatal("repository grant crossed profile boundary")
			}
		}
	}
}

func TestRepositoryAccessValidationAndCompilation(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	base := string(raw)
	withAccess := strings.Replace(base, "    account: github\n  infrastructure:", "    account: github\n    access:\n      permissions:\n        contents: write\n        pull_requests: write\n        workflows: write\n  infrastructure:", 1)
	decoded, err := Decode(strings.NewReader(withAccess))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if got := compiled.Broker.Repositories[1].Permissions["workflows"]; got != "write" {
		t.Fatalf("compiled workflow permission = %q", got)
	}

	for name, mutation := range map[string]string{
		"unknown permission":             strings.Replace(withAccess, "workflows: write", "administration: write", 1),
		"invalid level":                  strings.Replace(withAccess, "workflows: write", "workflows: admin", 1),
		"contradictory workflow write":   strings.Replace(withAccess, "contents: write", "contents: read", 1),
		"pull requests without checkout": strings.Replace(base, "    account: github\n  infrastructure:", "    account: github\n    access:\n      permissions:\n        pull_requests: write\n  infrastructure:", 1),
		"workflow read without checkout": strings.Replace(base, "    account: github\n  infrastructure:", "    account: github\n    access:\n      permissions:\n        workflows: read\n  infrastructure:", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(mutation)); err == nil {
				t.Fatal("invalid repository access was accepted")
			}
		})
	}
}

func TestGenericStaticGitProviderCompilesExactSelfHostedGrant(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	decoded.Secrets["studio-token"] = Secret{File: "./.nvt-local/secrets/studio/token"}
	decoded.BrokerProviders["studio"] = BrokerProvider{Plugin: "token", Secrets: map[string]string{"token-file": "studio-token"}, Mediation: BrokerProviderMediation{Hosts: []string{"altinn.studio"}, Materialization: "header-inject", Git: true, Username: "oauth2", TargetMode: "literal"}}
	profile := decoded.Profiles["development"]
	profile.CredentialProviders = append(profile.CredentialProviders, "studio")
	decoded.Profiles["development"] = profile
	decoded.Repositories["studio"] = Repository{URL: "https://altinn.studio/repos/digdir/oed.git", CheckoutTarget: "altinn.studio/repos/digdir/oed", BrokerRepository: "altinn.studio/repos/digdir/oed", CredentialProvider: "studio"}
	decoded.Workstations[0].Repositories = append(decoded.Workstations[0].Repositories, "studio")
	compiled, err := Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range compiled.Broker.Profiles {
		for _, grant := range profile.Grants {
			if grant.Provider == "studio" && (grant.Purpose != "repository" || grant.Preset != "" || grant.Mediation == nil || strings.Join(grant.Repositories, ",") != "altinn.studio/repos/digdir/oed") {
				t.Fatalf("generic repository grant = %#v", grant)
			}
		}
	}
}

func TestGenericStaticGitProviderValidationFailsClosed(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Manifest){
		"unknown bound secret": func(value *Manifest) {
			provider := value.BrokerProviders["azure"]
			provider.Secrets = map[string]string{"token-file": "missing"}
			value.BrokerProviders["azure"] = provider
		},
		"secret in public config": func(value *Manifest) {
			provider := value.BrokerProviders["azure"]
			provider.Config = map[string]any{"token-file": "embedded"}
			value.BrokerProviders["azure"] = provider
		},
		"undeclared secret reference": func(value *Manifest) {
			provider := value.BrokerProviders["azure"]
			provider.Config = map[string]any{"source": "azure-token"}
			value.BrokerProviders["azure"] = provider
		},
		"host path in public config": func(value *Manifest) {
			provider := value.BrokerProviders["azure"]
			provider.Config = map[string]any{"helper": "/home/user/token"}
			value.BrokerProviders["azure"] = provider
		},
		"compiler-owned public config": func(value *Manifest) {
			provider := value.BrokerProviders["azure"]
			provider.Config = map[string]any{"target-mode": "literal"}
			value.BrokerProviders["azure"] = provider
		},
		"ambiguous provider namespace": func(value *Manifest) {
			value.BrokerProviders["github"] = value.BrokerProviders["azure"]
		},
		"ambiguous repository binding": func(value *Manifest) {
			repository := value.Repositories["infrastructure"]
			repository.Account = "github"
			value.Repositories["infrastructure"] = repository
		},
		"undeclared profile provider": func(value *Manifest) {
			profile := value.Profiles["development"]
			profile.CredentialProviders = nil
			value.Profiles["development"] = profile
		},
		"host mismatch": func(value *Manifest) {
			repository := value.Repositories["infrastructure"]
			repository.URL = "https://git.example/org/repository"
			repository.CheckoutTarget = "git.example/org/repository"
			repository.BrokerRepository = "git.example/org/repository"
			value.Repositories["infrastructure"] = repository
		},
		"repository mismatch": func(value *Manifest) {
			repository := value.Repositories["infrastructure"]
			repository.BrokerRepository = "dev.azure.com/example/platform/_git/other"
			value.Repositories["infrastructure"] = repository
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			value, err := Decode(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("invalid generic provider input was accepted")
			}
		})
	}
}

func TestProducerPublicConfigPreservesLargeIntegers(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	compileValue := func(value string) []byte {
		t.Helper()
		input := strings.Replace(string(raw), "commandPrefix: /agent", "value: "+value, 1)
		decoded, decodeErr := Decode(strings.NewReader(input))
		if decodeErr != nil {
			t.Fatalf("decode %s: %v", value, decodeErr)
		}
		compiled, compileErr := Compile(decoded)
		if compileErr != nil {
			t.Fatal(compileErr)
		}
		result, encodeErr := compiled.CanonicalJSON()
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		return result
	}
	first := compileValue("9007199254740992")
	second := compileValue("9007199254740993")
	if bytes.Equal(first, second) {
		t.Fatal("distinct integer configurations compiled identically")
	}
	if !bytes.Contains(second, []byte(`"value":9007199254740993`)) {
		t.Fatalf("large integer was not preserved: %s", second)
	}
}

func TestExternalProducerPublicConfigIsAnExplicitTrustBoundary(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Replace(string(raw), "commandPrefix: /agent", "auth: deliberately-public", 1)
	decoded, err := Decode(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := compiled.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(canonical, []byte(`"publicConfig":{"auth":"deliberately-public"}`)) {
		t.Fatalf("declared public config was not emitted: %s", canonical)
	}
}

func TestGitHubCommandWorkflowMappingsCompileExactlyAndFailClosed(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	got := compiled.Controller.ProducerAdmissions[1].CommandWorkflows
	if got["review"] != "nvt-review" || got["run"] != "nvt-review" || got["pr-continue"] != "nvt-development" || len(got) != 3 {
		t.Fatalf("compiled command workflows = %#v", got)
	}
	for name, mapping := range map[string]string{"unsupported": "deploy: nvt-review", "unknown": "review: missing"} {
		t.Run(name, func(t *testing.T) {
			input := strings.Replace(string(raw), "review: nvt-review", mapping, 1)
			if _, err := Decode(strings.NewReader(input)); err == nil {
				t.Fatal("malformed command workflow mapping was accepted")
			}
		})
	}
}

func TestProfilePluginShorthandAndStructuredPolicyCompileExactly(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	plugins := decoded.Profiles["development"].Plugins
	if len(plugins) != 2 || plugins[0].Name != "work-control" || plugins[0].Egress != nil || plugins[1].Name != "github-watcher" || plugins[1].Egress == nil || plugins[1].Egress.Provider != "github" {
		t.Fatalf("decoded plugins = %#v", plugins)
	}
	compiled, err := Compile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	got := compiled.Controller.Profiles[0].Profile.Plugins
	if len(got) != 2 || got[0].Name != "github-watcher" || got[0].When != "after-agent" || got[0].Restart != "always" || got[0].Egress == nil || got[0].Egress.Provider != "github" || got[1].Name != "work-control" {
		t.Fatalf("compiled plugins = %#v", got)
	}
	for name, replacement := range map[string]string{
		"unknown provider": "provider: missing",
		"unknown field":    "provider: github\n          capability: guessed",
	} {
		t.Run(name, func(t *testing.T) {
			input := strings.Replace(string(raw), "provider: github", replacement, 1)
			if _, err := Decode(strings.NewReader(input)); err == nil {
				t.Fatal("invalid structured plugin policy was accepted")
			}
		})
	}
	profile := decoded.Profiles["development"]
	profile.Plugins = append([]Plugin(nil), profile.Plugins...)
	profile.Plugins[1].Restart = "sometimes"
	decoded.Profiles["development"] = profile
	if err := decoded.Validate(); err == nil {
		t.Fatal("invalid plugin restart policy was accepted")
	}
}

func TestDecodeRejectsDepthAndNodeBounds(t *testing.T) {
	deep := "apiVersion: nvt.dev/local/v1\nprofiles:\n  p:\n    runtime: {preset: shell, autonomy: approval-required}\nworkflows:\n  w: {profile: p, repository: a/b, retention: disposable}\nproducers:\n  - name: p\n    image: ghcr.io/a/b@sha256:" + strings.Repeat("a", 64) + "\n    workflow: w\n    config:\n      value: " + strings.Repeat("[", MaxDocumentDepth+1) + "null" + strings.Repeat("]", MaxDocumentDepth+1) + "\n"
	if _, err := Decode(strings.NewReader(deep)); err == nil {
		t.Fatal("deep input accepted")
	}
	manyNodes := "apiVersion: nvt.dev/local/v1\nprofiles:\n  p:\n    runtime: {preset: shell, autonomy: approval-required}\nworkflows:\n  w: {profile: p, repository: a/b, retention: disposable}\nproducers:\n  - name: p\n    image: ghcr.io/a/b@sha256:" + strings.Repeat("a", 64) + "\n    workflow: w\n    config:\n      values: [" + strings.Repeat("null,", MaxDocumentNodes) + "null]\n"
	if _, err := Decode(strings.NewReader(manyNodes)); err == nil {
		t.Fatal("excessive node count accepted")
	}
}
