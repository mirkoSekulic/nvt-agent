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
	cases := map[string]string{
		"unknown field":        strings.Replace(string(valid), "apiVersion:", "unexpected: true\napiVersion:", 1),
		"duplicate key":        strings.Replace(string(valid), "apiVersion: nvt.dev/local/v1", "apiVersion: nvt.dev/local/v1\napiVersion: nvt.dev/local/v1", 1),
		"second document":      string(valid) + "\n---\n{}\n",
		"unsafe secret":        strings.Replace(string(valid), "./.nvt-local/secrets/github/main-app.pem", "../private-key", 1),
		"unresolved reference": strings.Replace(string(valid), "privateKeySecret: github-key", "privateKeySecret: absent", 1),
		"mutable image":        strings.Replace(string(valid), "ghcr.io/example/chat-producer@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ghcr.io/example/chat-producer:latest", 1),
		"secret config":        strings.Replace(string(valid), "commandPrefix: /agent", "apiToken: embedded", 1),
		"unsupported scalar":   strings.Replace(string(valid), "appId: \"3912708\"", "appId: 2026-01-01", 1),
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
