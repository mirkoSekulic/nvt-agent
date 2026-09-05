package config_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	serviceconfig "github.com/mirkoSekulic/nvt-agent/localplatform/config"
	"github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
)

func TestAzureExampleCompilesWithExplicitCeilingAndPublicRuntimeMetadata(t *testing.T) {
	raw, err := os.ReadFile("../../examples/azure/manifest.example.yaml")
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
	if len(compiled.PrivateInputs) != 0 {
		t.Fatal("Azure account metadata became a secret input")
	}
	broker, err := serviceconfig.Broker(compiled)
	if err != nil {
		t.Fatal(err)
	}
	var rendered map[string]any
	if err := json.Unmarshal(broker, &rendered); err != nil {
		t.Fatal(err)
	}
	provider := rendered["providers"].([]any)[0].(map[string]any)
	if provider["allow"].(map[string]any)["authorization"] == nil {
		t.Fatal("provider ceiling omitted")
	}
	if provider["config"].(map[string]any)["state-dir"] != "/var/lib/nvt/broker/providers/azure-dev" {
		t.Fatal("state not isolated")
	}
	controller, err := serviceconfig.Controller(compiled, serviceconfig.Instructions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`azure/arm:/subscriptions/`, `"materialization":"header-inject"`, `"name":"azure-cli"`, `"provider":"azure-dev"`} {
		if !bytes.Contains(controller, []byte(want)) {
			t.Fatalf("missing %s", want)
		}
	}
	for _, forbidden := range []string{"state-dir", "accessToken", "refresh_token", "private-kubeconfig"} {
		if bytes.Contains(controller, []byte(forbidden)) {
			t.Fatalf("private provider detail %s entered controller", forbidden)
		}
	}
	// Azure and kubeconfig executable registrations coexist without changing the
	// kubeconfig resources, catalog preparation, or secret-binding contract.
	m.Secrets = map[string]manifest.Secret{"kube-fixture": {File: "./.nvt-local/secrets/kube-fixture"}}
	m.BrokerProviders["zz-clusters"] = manifest.BrokerProvider{Plugin: "kubeconfig", Secrets: map[string]string{"private-kubeconfig": "kube-fixture"}}
	profile := m.Profiles["azure-investigation"]
	profile.Egress.DomainPolicy.Allow = append(profile.Egress.DomainPolicy.Allow, "kube.nvt.invalid")
	profile.Kubernetes = []manifest.KubernetesAccess{{Provider: "zz-clusters", Contexts: []string{"dev"}, Authorization: &manifest.KubernetesAuthorization{Preset: "observe"}}}
	m.Profiles["azure-investigation"] = profile
	mixed, err := manifest.Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	mixedBroker, err := serviceconfig.Broker(mixed)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(mixedBroker, &rendered); err != nil {
		t.Fatal(err)
	}
	if len(rendered["provider-plugins"].([]any)) != 2 {
		t.Fatal("provider registration was lost")
	}
	mixedController, err := serviceconfig.Controller(mixed, serviceconfig.Instructions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(mixedController, []byte("context/dev")) || !bytes.Contains(mixedController, []byte("azure/arm:")) || !bytes.Contains(mixedController, []byte(`"preparations":["catalog"]`)) {
		t.Fatalf("mixed provider contracts lost: %s", mixedController)
	}
}
