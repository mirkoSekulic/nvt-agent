package lifecycle_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mirkoSekulic/nvt-agent/localplatform/lifecycle"
	"github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
	"github.com/mirkoSekulic/nvt-agent/localplatform/producer"
	"github.com/mirkoSekulic/nvt-agent/localplatform/state"
	"gopkg.in/yaml.v3"
)

func TestRenderCompleteComposeWithoutHostAuthoredState(t *testing.T) {
	examplePath := filepath.Join("..", "..", "nvt.local.example.yaml")
	example, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "nvt.local.yaml")
	secretDirectory := filepath.Join(root, ".nvt-local", "secrets", "github")
	if err := os.MkdirAll(secretDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secretDirectory, "token"), []byte("test-private-input"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, example, 0o600); err != nil {
		t.Fatal(err)
	}
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
	inputs, err := state.Resolve(path, compiled)
	if err != nil {
		t.Fatal(err)
	}
	defer inputs.Close()
	plan, err := state.BuildPlan("nvt-local", compiled, inputs)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := lifecycle.Render(context.Background(), compiled, plan, lifecycle.RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range [][]byte{[]byte("local-controller:"), []byte("gateway:"), []byte("broker:"), []byte("registry-init:"), []byte("nvt-local-controller-data")} {
		if !bytes.Contains(encoded, expected) {
			t.Fatalf("render omitted %q\n%s", expected, encoded)
		}
	}
	for _, forbidden := range [][]byte{[]byte(".broker"), []byte("env_file:"), []byte("compose.infra"), []byte("./nvt.local.yaml")} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatalf("render contains legacy or host-authored state %q", forbidden)
		}
	}
	var document struct {
		Services map[string]struct {
			Command     []string          `yaml:"command"`
			Networks    []string          `yaml:"networks"`
			Environment map[string]string `yaml:"environment"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	command := document.Services["registry-init"].Command
	if len(command) != 1 || !bytes.Contains([]byte(command[0]), []byte("agents.yaml")) {
		t.Fatalf("registry initializer must remain one shell argv entry: %#v", command)
	}
	brokerNetworks := document.Services["broker"].Networks
	if len(brokerNetworks) != 2 || brokerNetworks[0] != "agents-proxy" || brokerNetworks[1] != "local-control-plane" {
		t.Fatalf("broker must join trusted egress and control networks: %#v", brokerNetworks)
	}
	if capacity := document.Services["local-controller"].Environment["NVT_LOCAL_CONTROLLER_MAX_ACTIVE_RUNS"]; capacity != "128" {
		t.Fatalf("controller capacity does not match the validated workstation bound: %q", capacity)
	}
}

func TestRenderPortalAndProducerServicesFromManifest(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "manifest", "testdata", "valid.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "nvt.local.yaml")
	for _, path := range []string{
		filepath.Join(directory, ".nvt-local", "secrets", "github"),
		filepath.Join(directory, ".nvt-local", "secrets", "azure"),
		filepath.Join(directory, ".nvt-local", "instructions"),
	} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for path, content := range map[string]string{
		filepath.Join(directory, ".nvt-local", "secrets", "github", "main-app.pem"): "private-key-fixture",
		filepath.Join(directory, ".nvt-local", "secrets", "azure", "infra-pat"):     "pat-fixture",
		filepath.Join(directory, ".nvt-local", "instructions", "development.md"):    "instructions",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(manifestPath, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(manifestPath)
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
	inputs, err := state.Resolve(manifestPath, compiled)
	if err != nil {
		t.Fatal(err)
	}
	defer inputs.Close()
	plan, err := state.BuildPlan("nvt-local", compiled, inputs)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := lifecycle.Render(context.Background(), compiled, plan, lifecycle.RenderOptions{
		ProducerInspector: producer.ImageInspectorFunc(func(context.Context, string) (producer.ResolvedImage, error) {
			return producer.ResolvedImage{ID: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range [][]byte{[]byte("credential-runner:"), []byte("credential-portal:"), []byte("producer-nvt-comments:"), []byte("producer-external-chat:"), []byte("nvt-local-credential-seeds")} {
		if !bytes.Contains(encoded, expected) {
			t.Fatalf("render omitted manifest service or state %q\n%s", expected, encoded)
		}
	}
}
