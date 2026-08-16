package manifest

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

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

	reordered := strings.ReplaceAll(string(raw), "accounts: [github, codex, azure]", "accounts: [azure, codex, github]")
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
	cases := map[string]string{
		"unknown field":                            strings.Replace(string(valid), "apiVersion:", "unexpected: true\napiVersion:", 1),
		"duplicate key":                            strings.Replace(string(valid), "apiVersion: nvt.dev/local/v1", "apiVersion: nvt.dev/local/v1\napiVersion: nvt.dev/local/v1", 1),
		"second document":                          string(valid) + "\n---\n{}\n",
		"unsafe secret":                            strings.Replace(string(valid), "./.nvt-local/secrets/github/main-app.pem", "../private-key", 1),
		"unresolved reference":                     strings.Replace(string(valid), "privateKeySecret: github-key", "privateKeySecret: absent", 1),
		"mutable image":                            strings.Replace(string(valid), "ghcr.io/example/chat-producer@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ghcr.io/example/chat-producer:latest", 1),
		"invalid OCI image":                        strings.Replace(string(valid), "ghcr.io/example/chat-producer@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "https://host/repo?x@sha256:"+strings.Repeat("a", 64), 1),
		"secret config":                            strings.Replace(string(valid), "commandPrefix: /agent", "apiToken: embedded", 1),
		"unsupported scalar":                       strings.Replace(string(valid), "appId: \"3912708\"", "appId: 2026-01-01", 1),
		"incompatible producer account":            strings.Replace(string(valid), "preset: github-comments\n    account: github", "preset: github-comments\n    account: codex", 1),
		"missing installation":                     strings.Replace(string(valid), "mirkoSekulic: \"123\"", "another-owner: \"123\"", 1),
		"unknown repository":                       strings.Replace(string(valid), "repository: nvt-agent", "repository: absent", 1),
		"undeclared external config":               strings.Replace(string(valid), "publicConfig:", "config:", 1),
		"GitHub repository Azure account":          strings.Replace(string(valid), "github: mirkoSekulic/nvt-agent\n    account: github", "github: mirkoSekulic/nvt-agent\n    account: azure", 1),
		"Azure repository GitHub account":          strings.Replace(string(valid), "path: infrastructure\n    account: azure", "path: infrastructure\n    account: github", 1),
		"built-in public config":                   strings.Replace(string(valid), "prefix: /nvtagent", "prefix: /nvtagent\n    publicConfig: {mode: public}", 1),
		"built-in manual secret":                   strings.Replace(string(valid), "prefix: /nvtagent", "prefix: /nvtagent\n    secrets: {key: github-key}", 1),
		"missing runtime account":                  strings.Replace(string(valid), "      account: codex", "      account: github", 1),
		"GitHub App missing checkout installation": strings.Replace(string(valid), "github: mirkoSekulic/nvt-agent", "github: Altinn/nvt-agent", 1),
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
	if len(compiled.Controller.Profiles) != 1 || compiled.Controller.Profiles[0].Profile.Runtime.Preset != "codex" || compiled.Controller.Profiles[0].DefaultCredentialProvider != "codex" || compiled.Controller.Profiles[0].EgressProxyProvider != "codex" || len(compiled.Controller.Profiles[0].CredentialProviders) != 3 || len(compiled.Controller.Profiles[0].BrokerGrants) != 2 || len(compiled.Controller.Repositories) != 2 {
		t.Fatalf("controller projection is incomplete: %#v", compiled.Controller)
	}
	if len(compiled.Broker.Profiles) != 1 || len(compiled.Broker.Profiles[0].Accounts) != 3 || len(compiled.Broker.Repositories) != 2 {
		t.Fatalf("broker projection is incomplete: %#v", compiled.Broker)
	}
	var github *ProducerIntent
	for index := range compiled.Producers {
		if compiled.Producers[index].Kind == "github-comments" {
			github = &compiled.Producers[index]
		}
	}
	if github == nil || github.GitHub == nil || github.GitHub.AppID != 3912708 || github.GitHub.InstallationID != 123 || github.GitHub.RepositoryOwner != "mirkoSekulic" || github.GitHub.PrivateKeySecret != "github-key" {
		t.Fatalf("GitHub producer projection is incomplete: %#v", github)
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
	for _, binding := range compiled.Controller.ProducerAdmissions {
		if want[binding.Producer] != binding.Workflow || binding.Identity != "producer:"+binding.Producer || binding.Credential != "producer-admission:"+binding.Producer {
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

func TestBrokerGrantsDoNotCrossProfilesSharingAnAccount(t *testing.T) {
	raw, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	decoded.Profiles["other"] = Profile{Runtime: Runtime{Preset: "shell", Autonomy: "read-only"}, Accounts: []string{"github"}}
	decoded.Repositories["other"] = Repository{GitHub: "mirkoSekulic/other", Account: "github"}
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
	for _, grant := range grants["development"] {
		for _, repository := range grant.Repositories {
			if repository == "mirkoSekulic/other" {
				t.Fatal("repository grant crossed profile boundary")
			}
		}
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

func TestDecodeRejectsDepthAndNodeBounds(t *testing.T) {
	deep := "apiVersion: nvt.dev/local/v1\nprofiles:\n  p:\n    runtime: {preset: shell, autonomy: read-only}\nworkflows:\n  w: {profile: p, repository: a/b, retention: disposable}\nproducers:\n  - name: p\n    image: ghcr.io/a/b@sha256:" + strings.Repeat("a", 64) + "\n    workflow: w\n    config:\n      value: " + strings.Repeat("[", MaxDocumentDepth+1) + "null" + strings.Repeat("]", MaxDocumentDepth+1) + "\n"
	if _, err := Decode(strings.NewReader(deep)); err == nil {
		t.Fatal("deep input accepted")
	}
	manyNodes := "apiVersion: nvt.dev/local/v1\nprofiles:\n  p:\n    runtime: {preset: shell, autonomy: read-only}\nworkflows:\n  w: {profile: p, repository: a/b, retention: disposable}\nproducers:\n  - name: p\n    image: ghcr.io/a/b@sha256:" + strings.Repeat("a", 64) + "\n    workflow: w\n    config:\n      values: [" + strings.Repeat("null,", MaxDocumentNodes) + "null]\n"
	if _, err := Decode(strings.NewReader(manyNodes)); err == nil {
		t.Fatal("excessive node count accepted")
	}
}
