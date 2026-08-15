package migration

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/controller"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

const secretNeedle = "REAL-CREDENTIAL-MUST-NOT-MIGRATE"

func TestGenerateMigratesRepresentativeAgentsDeterministicallyWithoutSecrets(t *testing.T) {
	root, options := migrationFixture(t)
	originals := map[string][]byte{}
	for _, name := range []string{"nvt-dev", "studio", "infra"} {
		data, err := os.ReadFile(filepath.Join(root, ".agents", name, "agent.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		originals[name] = data
	}
	first, err := Generate(options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(options)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("migration is not deterministic: %v", err)
	}
	if bytes.Contains(first, []byte(secretNeedle)) || bytes.Contains(first, []byte("token-sha256")) || bytes.Contains(first, []byte("private-key")) {
		t.Fatalf("credential/provider configuration entered output:\n%s", first)
	}
	var document outputDocument
	if err := json.Unmarshal(first, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.ResolvedRunConfig.Profiles) != 3 || len(document.ResolvedRunConfig.Workflows) != 3 || len(document.LocalRuns) != 3 {
		t.Fatalf("representative output = %#v", document)
	}
	resolver, err := resolvedrun.NewResolver(document.ResolvedRunConfig)
	if err != nil {
		t.Fatal(err)
	}
	for _, localRun := range document.LocalRuns {
		resolved, err := resolver.Resolve(resolvedrun.AuthorizationContext{
			Principal:  localRun.Principal,
			Selections: []resolvedrun.AuthorizedSelection{{Profile: localRun.Profile, Workflows: []string{localRun.Workflow}}},
		}, resolvedrun.LocalRunRequest{RunID: localRun.RunID, Profile: localRun.Profile, Workflow: localRun.Workflow, Retention: localRun.Retention, Backend: localRun.Backend})
		if err != nil {
			t.Fatalf("resolve %s: %v", localRun.RunID, err)
		}
		if resolved.Egress.Mode != "mediated" || resolved.Egress.Transport != "transparent" || !resolved.Egress.Enforced || !resolved.Persistence.Workspace || !resolved.Persistence.RuntimeState {
			t.Fatalf("resolved policy %s = %#v", localRun.RunID, resolved)
		}
		rendered, err := resolvedrun.RenderAgentConfig(resolved, resolvedrun.AgentConfigBindings{ForwardProxyURL: "http://127.0.0.1:15002"})
		if err != nil || bytes.Contains(rendered, []byte(secretNeedle)) || !bytes.Contains(rendered, []byte(`"credential-kind":"mediated"`)) || !bytes.Contains(rendered, []byte(`"default-provider":"source"`)) {
			t.Fatalf("render %s = %s err=%v", localRun.RunID, rendered, err)
		}
	}
	for _, name := range []string{"nvt-dev", "studio", "infra"} {
		original, err := os.ReadFile(filepath.Join(root, ".agents", name, "agent.yaml"))
		if err != nil || !bytes.Equal(original, originals[name]) {
			t.Fatalf("source changed for %s: %v", name, err)
		}
	}
	configPath := filepath.Join(root, ".broker", "local-controller.json")
	if err := os.WriteFile(configPath, first, 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, "state", "local-controller.sqlite3")
	store, err := controller.OpenStore(context.Background(), statePath, controller.StoreOptions{MaxActiveRuns: 10, MaxClaimLease: 3 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	scheduler, err := controller.LoadScheduler(configPath, store)
	if err != nil || scheduler.BootstrapLocalRuns(context.Background()) != nil {
		t.Fatalf("bootstrap migrated runs: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := controller.OpenStore(context.Background(), statePath, controller.StoreOptions{MaxActiveRuns: 10, MaxClaimLease: 3 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restartedScheduler, err := controller.LoadScheduler(configPath, restarted)
	if err != nil || restartedScheduler.BootstrapLocalRuns(context.Background()) != nil {
		t.Fatalf("restart bootstrap: %v", err)
	}
	listed, err := restarted.List(context.Background(), 10, "")
	if err != nil || len(listed.Runs) != 3 || listed.Runs[0].RunID != "infra" || listed.Runs[1].RunID != "nvt-dev" || listed.Runs[2].RunID != "studio" {
		t.Fatalf("durable migrated runs = %#v err=%v", listed, err)
	}
	backend := &migrationBackend{}
	reconciler, err := controller.NewReconciler(restarted, backend, "migration-proof-controller-a", 30*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := reconciler.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	listed, err = restarted.List(context.Background(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range listed.Runs {
		if run.State != controller.StateRunning {
			t.Fatalf("migrated run did not reach running: %#v", run)
		}
	}
	restartedController, err := controller.NewReconciler(restarted, backend, "migration-proof-controller-b", 30*time.Second, nil)
	if err != nil || restartedController.Recover(context.Background()) != nil {
		t.Fatalf("controller recovery: %v", err)
	}
	for range 2 {
		if err := restartedController.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	listed, err = restarted.List(context.Background(), 10, "")
	if err != nil || len(listed.Runs) != 3 {
		t.Fatalf("recovered runs = %#v %v", listed, err)
	}
	for _, run := range listed.Runs {
		if run.State != controller.StateRunning {
			t.Fatalf("stable run did not recover: %#v", run)
		}
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		persisted, readErr := os.ReadFile(statePath + suffix)
		if readErr == nil && bytes.Contains(persisted, []byte(secretNeedle)) {
			t.Fatalf("credential needle entered controller persistence %s", suffix)
		}
	}
}

type migrationBackend struct{}

func (*migrationBackend) Ready(context.Context) bool { return true }
func (*migrationBackend) Ensure(_ context.Context, _ controller.BackendRun) (controller.BackendObservation, error) {
	return controller.BackendObservation{Ready: true}, nil
}
func (*migrationBackend) Inspect(_ context.Context, _ controller.BackendRun) (controller.BackendObservation, error) {
	return controller.BackendObservation{Ready: true}, nil
}
func (*migrationBackend) Delete(context.Context, controller.BackendRun) error { return nil }

func TestGenerateFailsClosedForAmbiguousAndUnsupportedInput(t *testing.T) {
	_, options := migrationFixture(t)
	t.Run("ambiguous broker repositories", func(t *testing.T) {
		data, err := os.ReadFile(options.BrokerAgents)
		if err != nil {
			t.Fatal(err)
		}
		data = bytes.Replace(data, []byte("repositories: [Altinn/nvt-dev]"), []byte("repositories: [Altinn/nvt-dev, Altinn/other]"), 1)
		if err := os.WriteFile(options.BrokerAgents, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := Generate(options); err == nil || output != nil {
			t.Fatal("ambiguous repository mapping was accepted")
		}
	})
	t.Run("provider not configured", func(t *testing.T) {
		_, isolated := migrationFixture(t)
		data, err := os.ReadFile(isolated.BrokerConfig)
		if err != nil {
			t.Fatal(err)
		}
		data = bytes.Replace(data, []byte("name: claude-main"), []byte("name: missing-claude"), 1)
		if err := os.WriteFile(isolated.BrokerConfig, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Generate(isolated); err == nil {
			t.Fatal("unknown provider was accepted")
		}
	})
	t.Run("credential-bearing provider plugin", func(t *testing.T) {
		root, isolated := migrationFixture(t)
		path := filepath.Join(root, ".agents", "nvt-dev", "agent.yaml")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data = bytes.Replace(data, []byte("type: broker"), []byte("type: github-app"), 1)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Generate(isolated); err == nil {
			t.Fatal("non-broker credential plugin was accepted")
		}
	})
	t.Run("credential field in retained plugin", func(t *testing.T) {
		root, isolated := migrationFixture(t)
		path := filepath.Join(root, ".agents", "studio", "agent.yaml")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data = bytes.Replace(data, []byte("config: {}"), []byte("config:\n      access-token: "+secretNeedle), 1)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Generate(isolated); err == nil {
			t.Fatal("credential-bearing retained plugin was accepted")
		}
	})
}

func migrationFixture(t *testing.T) (string, Options) {
	t.Helper()
	root := t.TempDir()
	agentsRoot := filepath.Join(root, ".agents")
	brokerRoot := filepath.Join(root, ".broker")
	if err := os.MkdirAll(brokerRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := `api_version: nvt.local-agent-migration/v1
image: nvt-agent-runtime:test
principal_issuer: https://local.nvt.test
backend: local-docker
retention: persistent
agents:
  - name: nvt-dev
    subject: workstation-nvt-dev
    display_name: NVT development
    runtime_type: codex
    autonomy: trusted-local
    user: root
  - name: studio
    subject: workstation-studio
    runtime_type: claude
    autonomy: trusted-local
    user: root
  - name: infra
    subject: workstation-infra
    runtime_type: codex
    autonomy: interactive
    user: root
`
	manifestPath := filepath.Join(root, "migration.yaml")
	writeTestFile(t, manifestPath, manifest)
	agentTemplates := map[string][3]string{
		"nvt-dev": {"codex", "github-app-main", "Altinn/nvt-dev"},
		"studio":  {"claude", "github-pat-main", "Altinn/studio"},
		"infra":   {"codex", "github-app-main", "Altinn/infra"},
	}
	for name, values := range agentTemplates {
		directory := filepath.Join(agentsRoot, name)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		config := "runtime:\n  command: " + values[0] + "\n  args: []\n  user: root\n  env:\n    NODE_EXTRA_CA_CERTS: /nvt-egress-ca/ca.crt\n  proxy:\n    provider: " + values[0] + "-main\n" +
			"tools:\n  packages: []\ncode-server:\n  extensions: []\nexpose:\n  http:\n    - name: app\n      targetPort: 3000\n" +
			"plugins:\n  - name: git-host-credentials\n    source: builtin\n    config:\n      default-provider: source\n      providers:\n        - name: source\n          type: broker\n          broker-provider: " + values[1] + "\n          match: [github.com/Altinn/" + name + "]\n" +
			"  - name: git-credentials\n    source: builtin\n    when: before-agent\n    config:\n      credentials:\n        - match: https://github.com/Altinn/" + name + ".git\n          provider: source\n          identity:\n            mode: provider\n" +
			"  - name: checkout-repos\n    source: builtin\n    when: before-agent\n    restart: never\n    config:\n      repos:\n        - url: https://github.com/Altinn/" + name + ".git\n" +
			"  - name: github-watcher\n    source: builtin\n    config: {}\n" +
			"egress:\n  mode: mediated\n  transport: transparent\n  placeholder: NVT-PLACEHOLDER-NOT-A-KEY\n  forward-proxy-url: http://127.0.0.1:15002\n  grants: []\n"
		writeTestFile(t, filepath.Join(directory, "agent.yaml"), config)
	}
	agents := `agents:
  - id: nvt-dev
    token-sha256: sha256:` + strings.Repeat("1", 64) + `
    grants:
      - provider: github-app-main
        repositories: [Altinn/nvt-dev]
        materialization: header-inject
        egress-hosts: [github.com:443]
        git: true
        preparations: [identity]
      - provider: codex-main
        repositories: []
        materialization: placeholder-file
        egress-hosts: [api.openai.example:443]
  - id: studio
    token-sha256: sha256:` + strings.Repeat("2", 64) + `
    grants:
      - provider: github-pat-main
        repositories: [Altinn/studio]
        materialization: header-inject
        egress-hosts: [github.com:443]
        git: true
        preparations: [identity]
      - provider: claude-main
        repositories: []
        materialization: placeholder-file
        egress-hosts: [api.anthropic.example:443]
  - id: infra
    token-sha256: sha256:` + strings.Repeat("3", 64) + `
    grants:
      - provider: github-app-main
        repositories: [Altinn/infra]
        materialization: header-inject
        egress-hosts: [github.com:443]
        git: true
        preparations: [identity]
      - provider: codex-main
        repositories: []
        materialization: placeholder-file
        egress-hosts: [api.openai.example:443]
`
	brokerAgents := filepath.Join(brokerRoot, "agents.yaml")
	writeTestFile(t, brokerAgents, agents)
	brokerConfig := filepath.Join(brokerRoot, "broker.yaml")
	writeTestFile(t, brokerConfig, `providers:
  - name: github-app-main
    plugin: github-app
    config:
      private-key-env: `+secretNeedle+`
  - name: github-pat-main
    plugin: static-token
    config:
      token-env: `+secretNeedle+`
  - name: codex-main
    plugin: codex-oauth
    config:
      credential-file: /secret/`+secretNeedle+`
  - name: claude-main
    plugin: claude-oauth
    config:
      credential-file: /secret/`+secretNeedle+`
`)
	return root, Options{ManifestPath: manifestPath, AgentsRoot: agentsRoot, BrokerAgents: brokerAgents, BrokerConfig: brokerConfig}
}

func writeTestFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}
