package config_test

import (
	"bytes"
	"encoding/json"
	serviceconfig "github.com/mirkoSekulic/nvt-agent/localplatform/config"
	"github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
	"os"
	"testing"
)

func TestPiLocalManifestRendersInjectionOnly(t *testing.T) {
	raw, err := os.ReadFile("../../examples/pi/manifest.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := manifest.Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := serviceconfig.Broker(compiled)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(broker, []byte(`"plugin":"token"`)) || !bytes.Contains(broker, []byte(`"token-file":"/run/nvt-private/`)) {
		t.Fatalf("missing broker-only key binding: %s", broker)
	}
	controller, err := serviceconfig.Controller(compiled, nil)
	if err != nil {
		t.Fatal(err)
	}
	var config resolvedrun.TrustedConfiguration
	if err := json.Unmarshal(controller, &config); err != nil {
		t.Fatal(err)
	}
	resolver, err := resolvedrun.NewResolver(config)
	if err != nil {
		t.Fatal(err)
	}
	run, err := resolver.Resolve(resolvedrun.AuthorizationContext{Principal: resolvedrun.Principal{Issuer: "https://example.test", Subject: "admin"}, Selections: []resolvedrun.AuthorizedSelection{{Profile: "pi-custom", Workflows: []string{"pi-task"}}}}, resolvedrun.LocalRunRequest{RunID: "pi-test", Profile: "pi-custom", Workflow: "pi-task", Retention: "persistent", Backend: "local-docker", Prompt: "initial task"})
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := resolvedrun.RenderAgentConfig(run, resolvedrun.AgentConfigBindings{ForwardProxyURL: "http://egressd:8443"})
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(rendered, &document); err != nil {
		t.Fatal(err)
	}
	runtime := document["runtime"].(map[string]any)
	if runtime["initial-prompt"] == nil || runtime["pi"] == nil || runtime["resume"].(map[string]any)["initial-prompt"] != nil {
		t.Fatal("missing typed public config or initial prompt entered resume")
	}

	p := config.Profiles[0]
	if p.Runtime.Type != "pi" || p.Runtime.CredentialProvider != "model-api" || p.Egress.ProxyProvider != "model-api" || len(p.CredentialProviders) != 0 {
		t.Fatalf("model/repository bindings mixed: %#v", p)
	}
	if len(p.Broker.Grants) != 1 || p.Broker.Grants[0].Materialization != "header-inject" || len(p.Broker.Grants[0].Capabilities) != 1 || p.Broker.Grants[0].Capabilities[0] != "injection.headers" {
		t.Fatalf("non-injection grant: %#v", p.Broker)
	}
	for _, bad := range [][]byte{[]byte("token-file"), []byte("/run/nvt-private/"), []byte("apiKey"), []byte("model-api-key")} {
		if bytes.Contains(controller, bad) {
			t.Fatalf("private field entered controller: %s", bad)
		}
	}
}
