package egress

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadForwardProxyInjectConfig pins that egressd accepts the forward-proxy
// inject-route config shape the operator renders (Phase 6.2).
func TestLoadForwardProxyInjectConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	config := `{
  "broker_url": "https://nvt-broker.nvt.svc.cluster.local:7347",
  "allow_insecure_broker": false,
  "broker_ca_file": "/nvt-broker-ca/ca.crt",
  "routes": [],
  "forward_proxy": {
    "listen": "0.0.0.0:8473",
    "inject_routes": [
      {"host": "chatgpt.com", "capability": "codex-main", "upstream": "chatgpt.com:443"},
      {"host": "auth.openai.com", "capability": "codex-main", "upstream": "auth.openai.com:443"}
    ]
  },
  "ca": {"cert_file": "/nvt-egress-ca-secret/ca.crt", "key_file": "/nvt-egress-ca-secret/ca.key", "serve_addr": "0.0.0.0:8470"}
}`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("egressd rejected the operator forward-proxy config: %v", err)
	}
	if loaded.ForwardProxy == nil || len(loaded.ForwardProxy.InjectRoutes) != 2 {
		t.Fatalf("inject routes not parsed: %#v", loaded.ForwardProxy)
	}
	if names := loaded.ForwardProxyUpstreamLeafNames(); len(names) != 2 || names[0] != "chatgpt.com" {
		t.Fatalf("upstream leaf names = %v", names)
	}

	// inject_routes without a ca block are rejected (MITM needs the CA).
	noCA := `{"broker_url":"https://b:7347","routes":[],"forward_proxy":{"listen":"0.0.0.0:8473","inject_routes":[{"host":"chatgpt.com","capability":"c","upstream":"chatgpt.com:443"}]}}`
	if err := os.WriteFile(path, []byte(noCA), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("inject routes without a ca block must be rejected")
	}
}

func TestForwardProxyInjectRoutesAllowSameHostWithExplicitCapabilities(t *testing.T) {
	base := &Config{
		BrokerURL: "https://broker:7347",
		Routes:    []Route{},
		CA:        &CAConfig{ServeAddr: "0.0.0.0:8470"},
		ForwardProxy: &ForwardProxyConfig{
			Listen: "0.0.0.0:8473",
			InjectRoutes: []ForwardProxyInjectRoute{
				{Host: "api.github.com", Capability: "github-main-app", Upstream: "api.github.com:443"},
				{Host: "api.github.com", Capability: "github-altinn-app", Upstream: "api.github.com:443"},
			},
		},
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("same host with distinct capabilities should be valid: %v", err)
	}

	base.ForwardProxy.InjectRoutes[1].Capability = "github-main-app"
	if err := base.Validate(); err == nil {
		t.Fatal("same host with duplicate capability must be rejected")
	}
}
