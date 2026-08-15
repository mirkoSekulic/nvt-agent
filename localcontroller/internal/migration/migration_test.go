package migration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		if (localRun.RunID == "studio" || localRun.RunID == "infra") && !bytes.Contains(rendered, []byte(`"username":"oauth-user"`)) {
			t.Fatalf("render %s lost the non-secret credential username: %s", localRun.RunID, rendered)
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

func TestGeneratedNamedRunsComposeWithDisposableProducerSchedule(t *testing.T) {
	root, options := migrationFixture(t)
	generated, err := Generate(options)
	if err != nil {
		t.Fatal(err)
	}
	var named outputDocument
	if err := json.Unmarshal(generated, &named); err != nil {
		t.Fatal(err)
	}
	namedPath := filepath.Join(root, ".broker", "local-controller.json")
	if err := os.WriteFile(namedPath, generated, 0o600); err != nil {
		t.Fatal(err)
	}
	producerToken := "MIGRATION-PRODUCER-TOKEN-0123456789abcdef"
	tokenPath := filepath.Join(root, ".broker", "producer-token")
	writeTestFile(t, tokenPath, producerToken+"\n")
	scheduleTrusted := named.ResolvedRunConfig
	for index := range scheduleTrusted.Profiles {
		if scheduleTrusted.Profiles[index].Name == "nvt-dev" {
			scheduleTrusted.Profiles[index].AllowedRetentions = append(scheduleTrusted.Profiles[index].AllowedRetentions, "disposable")
		}
	}
	scheduleTrusted.RetentionPolicies = append(scheduleTrusted.RetentionPolicies, resolvedrun.RetentionPolicy{
		Name: "disposable", TTL: resolvedrun.TTL{ActiveSeconds: 900, CompletedSeconds: 60, FailedSeconds: 60},
	})
	schedulePath := filepath.Join(root, ".broker", "producer-schedules.json")
	scheduleDocument := map[string]any{
		"api_version": "nvt.local-scheduling/v1", "resolved_run_config": scheduleTrusted,
		"schedules": []any{map[string]any{
			"name": "github", "producers": []any{map[string]any{
				"identity": "github-comments", "token_file": tokenPath,
				"allowed_principal_issuers": []string{"https://identity.example.test"},
				"selections":                []any{map[string]any{"profile": "nvt-dev", "workflow": "nvt-dev"}},
				"default_workflow":          "nvt-dev", "retention": "disposable", "backend": "local-docker",
			}},
		}},
	}
	writeTestFile(t, schedulePath, string(mustMarshal(t, scheduleDocument)))
	statePath := filepath.Join(root, "combined-state", "local-controller.sqlite3")
	store, err := controller.OpenStore(context.Background(), statePath, controller.StoreOptions{MaxActiveRuns: 8, MaxClaimLease: 3 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	scheduler, err := controller.LoadSchedulers([]string{schedulePath, namedPath}, store)
	if err != nil || scheduler.BootstrapLocalRuns(context.Background()) != nil {
		t.Fatalf("combined startup: %#v %v", scheduler, err)
	}
	handler := controller.NewHTTPHandlerWithServices(store, nil, nil, nil, scheduler)
	admission := map[string]any{
		"work": map[string]any{
			"id": "migration/project/issues/230", "title": "Migration proof", "url": "https://example.test/migration/project/issues/230", "repository": "migration/project",
			"principal": map[string]any{"issuer": "https://identity.example.test", "subject": "developer-1", "displayName": "Developer"},
		},
		"input": map[string]any{"prompt": "Run disposable work"},
	}
	response := migrationScheduleRequest(t, handler, http.MethodPost, "/v1/schedules/github/admissions", mustMarshal(t, admission), producerToken)
	if response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"scheduled":true`) {
		t.Fatalf("combined admission = %d %s", response.Code, response.Body.String())
	}
	status := migrationScheduleRequest(t, handler, http.MethodGet, "/v1/schedules/github/work?work_id=migration/project/issues/230", nil, producerToken)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"state":"pending"`) {
		t.Fatalf("combined status = %d %s", status.Code, status.Body.String())
	}
	cancelled := migrationScheduleRequest(t, handler, http.MethodPost, "/v1/schedules/github/work/cancel?work_id=migration/project/issues/230", nil, producerToken)
	if cancelled.Code != http.StatusAccepted || !strings.Contains(cancelled.Body.String(), `"state":"stopping"`) {
		t.Fatalf("combined cancellation = %d %s", cancelled.Code, cancelled.Body.String())
	}
	backend := &migrationBackend{}
	reconciler, err := controller.NewReconciler(store, backend, "combined-migration-controller", 30*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		if err := reconciler.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if backend.deleteCalls != 1 {
		t.Fatalf("disposable cancellation cleanup calls = %d", backend.deleteCalls)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := controller.OpenStore(context.Background(), statePath, controller.StoreOptions{MaxActiveRuns: 8, MaxClaimLease: 3 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restartedScheduler, err := controller.LoadSchedulers([]string{schedulePath, namedPath}, restarted)
	if err != nil || restartedScheduler.BootstrapLocalRuns(context.Background()) != nil {
		t.Fatalf("combined restart: %#v %v", restartedScheduler, err)
	}
	listed, err := restarted.List(context.Background(), 10, "")
	if err != nil || len(listed.Runs) != 4 {
		t.Fatalf("combined durable state = %#v %v", listed, err)
	}
	for _, run := range listed.Runs {
		if run.RunID == "nvt-dev" && (!run.Persistent || run.DeadlineAt != nil) {
			t.Fatalf("named run lost persistent policy: %#v", run)
		}
		if strings.HasPrefix(run.RunID, "local-") && (run.Persistent || run.DeadlineAt == nil || run.State != controller.StateFailed || run.LastReason != "backend-cleanup-complete") {
			t.Fatalf("scheduled run lost disposable lifecycle: %#v", run)
		}
	}
}

func migrationScheduleRequest(t *testing.T, handler http.Handler, method, path string, body []byte, token string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, "http://local-controller.test"+path, bytes.NewReader(body))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

type migrationBackend struct{ deleteCalls int }

func (*migrationBackend) Ready(context.Context) bool { return true }
func (*migrationBackend) Ensure(_ context.Context, _ controller.BackendRun) (controller.BackendObservation, error) {
	return controller.BackendObservation{Ready: true}, nil
}
func (*migrationBackend) Inspect(_ context.Context, _ controller.BackendRun) (controller.BackendObservation, error) {
	return controller.BackendObservation{Ready: true}, nil
}
func (backend *migrationBackend) Delete(context.Context, controller.BackendRun) error {
	backend.deleteCalls++
	return nil
}

func TestGenerateFailsClosedForAmbiguousAndUnsupportedInput(t *testing.T) {
	_, options := migrationFixture(t)
	t.Run("ambiguous broker repositories", func(t *testing.T) {
		data, err := os.ReadFile(options.BrokerAgents)
		if err != nil {
			t.Fatal(err)
		}
		data = bytes.Replace(data, []byte("repositories: [Altinn/nvt-dev, Altinn/shared]"), []byte("repositories: [Altinn/other, Altinn/shared]"), 1)
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
	for name, mutate := range map[string]func([]byte) []byte{
		"innocuous plugin value": func(data []byte) []byte {
			return bytes.Replace(data, []byte("config: {}"), []byte("config:\n      value: "+secretNeedle), 1)
		},
		"runtime argument": func(data []byte) []byte {
			return bytes.Replace(data, []byte("    - --sandbox"), []byte("    - "+secretNeedle), 1)
		},
		"runtime environment": func(data []byte) []byte {
			return bytes.Replace(data, []byte("/nvt-egress-ca/ca.crt"), []byte(secretNeedle), 1)
		},
		"credential username": func(data []byte) []byte {
			return bytes.Replace(data, []byte("username: oauth-user"), []byte("username: "+secretNeedle), 1)
		},
		"nested shell array": func(data []byte) []byte {
			return bytes.Replace(data, []byte("  shell: []"), []byte("  shell:\n    - [echo, "+secretNeedle+"]"), 1)
		},
		"camel case credential field": func(data []byte) []byte {
			return bytes.Replace(data, []byte("config: {}"), []byte("config:\n      accessToken: "+secretNeedle), 1)
		},
		"innocuous preseed path": func(data []byte) []byte {
			return bytes.Replace(data, []byte("$HOME/.codex/config.toml"), []byte("$HOME/"+secretNeedle), 1)
		},
		"custom plugin config": func(data []byte) []byte {
			data = bytes.Replace(data, []byte("name: github-watcher\n    source: builtin"), []byte("name: github-watcher\n    source: custom"), 1)
			return bytes.Replace(data, []byte("config: {}"), []byte("config:\n      value: "+secretNeedle), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			root, isolated := migrationFixture(t)
			path := filepath.Join(root, ".agents", "nvt-dev", "agent.yaml")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, mutate(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if output, err := Generate(isolated); err == nil || output != nil {
				t.Fatal("unsafe source value was accepted")
			}
		})
	}
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
runtime_allowlist:
  commands: [codex, claude]
  arguments: [--sandbox, danger-full-access, --ask-for-approval, never, --dangerously-skip-permissions]
  resume_commands: [codex, claude]
  resume_arguments: [exec, resume, --last, --continue]
  environment:
    NODE_EXTRA_CA_CERTS: /nvt-egress-ca/ca.crt
    NO_PROXY: localhost,127.0.0.1,::1,broker,egressd
credential_usernames: [x-access-token, oauth2, oauth-user]
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
		args := "[]"
		if name == "nvt-dev" {
			args = "\n    - --sandbox\n    - danger-full-access\n    - --ask-for-approval\n    - never"
		} else if name == "studio" {
			args = "\n    - --dangerously-skip-permissions"
		}
		resume := ""
		if name == "nvt-dev" {
			resume = "  resume:\n    command: codex\n    args: [resume, --last]\n"
		}
		username := ""
		if name != "nvt-dev" {
			username = "          username: oauth-user\n"
		}
		extraProvider, extraCredential, extraCheckout := "", "", ""
		if name == "nvt-dev" {
			extraProvider = "        - name: secondary\n          type: broker\n          broker-provider: github-pat-main\n          match: [github.com/Altinn/shared]\n"
			extraCredential = "        - match: https://github.com/Altinn/shared\n          provider: secondary\n          username: oauth-user\n          identity:\n            mode: provider\n"
			extraCheckout = "        - url: https://github.com/Altinn/shared.git\n          path: shared\n"
		}
		preseed := "preseed:\n  files:\n    - path: $HOME/.codex/config.toml\n      mode: \"0600\"\n      overwrite: false\n      content: |\n        check_for_update_on_startup = false\n"
		if values[0] == "claude" {
			preseed = "preseed:\n  files:\n    - path: $HOME/.claude/settings.json\n      mode: \"0600\"\n      overwrite: false\n      json:\n        theme: dark-daltonized\n        skipDangerousModePermissionPrompt: true\n"
		}
		config := "runtime:\n  command: " + values[0] + "\n  args: " + args + "\n  user: root\n" + resume + "  env:\n    NODE_EXTRA_CA_CERTS: /nvt-egress-ca/ca.crt\n    NO_PROXY: localhost,127.0.0.1,::1,broker,egressd\n  proxy:\n    provider: " + values[0] + "-main\n" +
			"tools:\n  packages: []\n  mise: []\n  additional-paths: []\n  shell: []\ncode-server:\n  extensions: []\n  settings:\n    overwrite: false\n    values: {}\nexpose:\n  http:\n    - name: app\n      targetPort: 3000\n" +
			preseed +
			"plugins:\n  - name: git-host-credentials\n    source: builtin\n    config:\n      default-provider: source\n      providers:\n        - name: source\n          type: broker\n          broker-provider: " + values[1] + "\n          match: [github.com/Altinn/" + name + "]\n" + extraProvider +
			"  - name: git-credentials\n    source: builtin\n    when: before-agent\n    config:\n      credentials:\n        - match: https://github.com/Altinn/" + name + "\n          provider: source\n" + username + "          identity:\n            mode: provider\n" +
			extraCredential +
			"  - name: checkout-repos\n    source: builtin\n    when: before-agent\n    restart: never\n    config:\n      repos:\n        - url: https://github.com/Altinn/" + name + ".git\n" +
			extraCheckout +
			"  - name: github-watcher\n    source: builtin\n    config: {}\n" +
			"egress:\n  mode: mediated\n  transport: transparent\n  placeholder: NVT-PLACEHOLDER-NOT-A-KEY\n  forward-proxy-url: http://127.0.0.1:15002\n  grants: []\n"
		writeTestFile(t, filepath.Join(directory, "agent.yaml"), config)
	}
	agents := `agents:
  - id: nvt-dev
    token-sha256: sha256:` + strings.Repeat("1", 64) + `
    grants:
      - provider: github-app-main
        repositories: [Altinn/nvt-dev, Altinn/shared]
        materialization: header-inject
        egress-hosts: [github.com:443]
        git: true
        preparations: [identity]
      - provider: codex-main
        repositories: []
        materialization: placeholder-file
        egress-hosts: [api.openai.example:443]
      - provider: github-pat-main
        repositories: [Altinn/shared]
        materialization: header-inject
        egress-hosts: [github.com:443]
        git: true
        preparations: [identity]
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
        repositories: [Altinn/infra, Altinn/shared]
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
