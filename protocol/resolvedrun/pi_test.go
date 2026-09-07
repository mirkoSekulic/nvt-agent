package resolvedrun

import (
	"encoding/json"
	"strings"
	"testing"
)

func piFixture() (Runtime, Egress, Broker) {
	r := Runtime{Type: "pi", Autonomy: "trusted-local", Model: "custom/example-model", Effort: "off", CredentialProvider: "model-api", Pi: &PiConfig{Provider: "custom", BaseURL: "https://models.example.test/v1", API: "openai-completions", Models: []PiModel{{ID: "example-model"}}}}
	return r, Egress{Mode: "mediated", Transport: "forward-proxy", ProxyProvider: "model-api"}, Broker{Grants: []BrokerGrant{{Provider: "model-api", Materialization: "header-inject", Capabilities: []string{"injection.headers"}, EgressHosts: []string{"models.example.test:443"}}}}
}
func TestPiManagedContract(t *testing.T) {
	r, e, b := piFixture()
	if err := ValidatePiBinding(r, e, b); err != nil {
		t.Fatal(err)
	}
	config, err := ManagedPiRuntime(map[string]any{"command": "pi", "args": []any{}}, r)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(config)
	if strings.Contains(string(encoded), "apiKey") || strings.Contains(string(encoded), "--continue") {
		t.Fatal("unexpected credential or unscoped resume")
	}
	for _, raw := range []map[string]any{{"args": []any{"--provider", "other"}}, {"args": []any{"--thinking=high"}}, {"resume": map[string]any{}}, {"env": map[string]any{"OPENAI_API_KEY": "fake"}}, {"command": "bash"}} {
		if _, err := ManagedPiRuntime(raw, r); err == nil {
			t.Fatal("raw Pi override accepted")
		}
	}
}
func TestPiValidationFailsClosed(t *testing.T) {
	tests := map[string]func(*Runtime, *Egress, *Broker){
		"approval": func(r *Runtime, e *Egress, b *Broker) { r.Autonomy = "interactive" },
		"effort":   func(r *Runtime, e *Egress, b *Broker) { r.Effort = "max" },
		"model":    func(r *Runtime, e *Egress, b *Broker) { r.Model = "other/model" },
		"provider": func(r *Runtime, e *Egress, b *Broker) { r.CredentialProvider = "missing" },
		"direct":   func(r *Runtime, e *Egress, b *Broker) { e.Mode = "direct" },
		"redirect": func(r *Runtime, e *Egress, b *Broker) { e.Transport = "redirect" },
		"raw token": func(r *Runtime, e *Egress, b *Broker) {
			b.Grants[0].Capabilities = append(b.Grants[0].Capabilities, "token")
		},
		"bundle":            func(r *Runtime, e *Egress, b *Broker) { b.Grants[0].Materialization = "file-bundle" },
		"host":              func(r *Runtime, e *Egress, b *Broker) { b.Grants[0].EgressHosts = []string{"other.test:443"} },
		"settings resolver": func(r *Runtime, e *Egress, b *Broker) { r.Pi.Settings = map[string]bool{"shellPath": true} },
		"compat resolver":   func(r *Runtime, e *Egress, b *Broker) { r.Pi.Compat = map[string]bool{"headers": true} },
		"extension path": func(r *Runtime, e *Egress, b *Broker) {
			r.Pi.Extensions = []PiExtension{{Name: "../evil.ts", Content: "code"}}
		},
	}
	for _, u := range []string{"https://fake-secret@models.example.test/v1", "https://models.example.test/v1?key=fake-secret", "http://models.example.test/v1", "https://models.example.test/$SECRET", "https://models.example.test/!command", "https://models.example.test/v1#fake-secret"} {
		tests[u] = func(r *Runtime, e *Egress, b *Broker) { r.Pi.BaseURL = u }
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			r, e, b := piFixture()
			mutate(&r, &e, &b)
			err := ValidatePiBinding(r, e, b)
			if err == nil {
				t.Fatal("invalid binding accepted")
			}
			if strings.Contains(err.Error(), "fake-secret") {
				t.Fatal("credential leaked in error")
			}
		})
	}
}
