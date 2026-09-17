package config_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	serviceconfig "github.com/mirkoSekulic/nvt-agent/localplatform/config"
	"github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

func TestHTTPOnlyRenderUsesPortableGrantAndBrokerOnlyBinding(t *testing.T) {
	raw, err := os.ReadFile("../../examples/http-credentials/manifest.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	p := m.Profiles["api-only"]
	p.Plugins = []manifest.Plugin{{Name: "work-control", Egress: &manifest.PluginEgress{Provider: "forge-api"}}}
	m.Profiles["api-only"] = p
	c, err := manifest.Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := serviceconfig.Controller(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Profiles  []resolvedrun.Profile  `json:"profiles"`
		Workflows []resolvedrun.Workflow `json:"workflows"`
	}
	if err := json.Unmarshal(controller, &doc); err != nil {
		t.Fatal(err)
	}
	for _, p := range doc.Profiles {
		if p.Name == "api-only" && !bytes.Contains(p.AgentConfig, []byte(`"provider":"forge-api"`)) {
			t.Fatal("plugin lost explicit HTTP credential selection")
		}
		if len(p.CredentialProviders) != 0 || p.DefaultCredentialProvider != "" {
			t.Fatal("HTTP access created Git credential exports")
		}
		for _, g := range p.Broker.Grants {
			if g.Materialization != "header-inject" || g.Git || len(g.Repositories) != 0 || g.Authorization != nil || len(g.EgressHosts) != 1 || g.EgressHosts[0] != "forge.example.test:443" {
				t.Fatalf("wrong HTTP grant: %#v", g)
			}
		}
	}
	for _, workflow := range doc.Workflows {
		if len(workflow.Repositories) != 0 {
			t.Fatal("automatic checkout generated")
		}
	}
	for _, private := range []string{"token-file", "injection-basic-username", ".nvt-local/secrets", "/private/", "forge-pat"} {
		if bytes.Contains(controller, []byte(private)) {
			t.Fatalf("broker-only detail %s leaked", private)
		}
	}
	broker, err := serviceconfig.Broker(c)
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		Providers []struct {
			Config map[string]any `json:"config"`
			Allow  map[string]any `json:"allow"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(broker, &b); err != nil {
		t.Fatal(err)
	}
	if len(b.Providers) != 2 || b.Providers[0].Config["token-file"] != b.Providers[1].Config["token-file"] {
		t.Fatal("shared PAT was duplicated")
	}
	for _, p := range b.Providers {
		if r, ok := p.Allow["repositories"].([]any); ok && len(r) > 0 {
			t.Fatal("host scope became repository wildcard")
		}
	}
}
