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
		"unknown field":                 strings.Replace(string(valid), "apiVersion:", "unexpected: true\napiVersion:", 1),
		"duplicate key":                 strings.Replace(string(valid), "apiVersion: nvt.dev/local/v1", "apiVersion: nvt.dev/local/v1\napiVersion: nvt.dev/local/v1", 1),
		"second document":               string(valid) + "\n---\n{}\n",
		"unsafe secret":                 strings.Replace(string(valid), "./.nvt-local/secrets/github/main-app.pem", "../private-key", 1),
		"unresolved reference":          strings.Replace(string(valid), "privateKeySecret: github-key", "privateKeySecret: absent", 1),
		"mutable image":                 strings.Replace(string(valid), "ghcr.io/example/chat-producer@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ghcr.io/example/chat-producer:latest", 1),
		"invalid OCI image":             strings.Replace(string(valid), "ghcr.io/example/chat-producer@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "https://host/repo?x@sha256:"+strings.Repeat("a", 64), 1),
		"secret config":                 strings.Replace(string(valid), "commandPrefix: /agent", "apiToken: embedded", 1),
		"unsupported scalar":            strings.Replace(string(valid), "appId: \"3912708\"", "appId: 2026-01-01", 1),
		"incompatible producer account": strings.Replace(string(valid), "preset: github-comments\n    account: github", "preset: github-comments\n    account: codex", 1),
		"missing installation":          strings.Replace(string(valid), "mirkoSekulic: \"123\"", "another-owner: \"123\"", 1),
		"unknown repository":            strings.Replace(string(valid), "repository: nvt-agent", "repository: absent", 1),
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
	if len(compiled.Controller.Profiles) != 1 || compiled.Controller.Profiles[0].Profile.Runtime.Preset != "codex" || len(compiled.Controller.Repositories) != 2 {
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
}

func TestProducerConfigPreservesLargeIntegers(t *testing.T) {
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
