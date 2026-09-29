package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestAzureManifestRejectsAmbiguousOrUnsafeDeclarations(t *testing.T) {
	raw, err := os.ReadFile("../../examples/azure/manifest.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	for _, replacement := range [][2]string{
		{"preset: observe", "preset: mutate"},
		{"preset: observe", "preset: observe, defaultAction: allow"},
		{"cloud: AzureCloud", "cloud: ArbitraryCloud"},
		{"plugin: azure", "plugin: kubeconfig"},
		{"config:\n      cloud:", "config:\n      audience: https://evil.invalid\n      cloud:"},
		{"arm:/subscriptions/11111111-1111-1111-1111-111111111111", "arm:/subscriptions/*"},
		{"query-identity/22222222-2222-2222-2222-222222222222", "query-identity/33333333-3333-3333-3333-333333333333"},
	} {
		invalid := strings.ReplaceAll(string(raw), replacement[0], replacement[1])
		if _, err := Decode(strings.NewReader(invalid)); err == nil {
			t.Fatalf("accepted %s", replacement[1])
		}
	}
}

func TestAzureCompactConfigurationIsExplicitAndDeterministic(t *testing.T) {
	raw, err := os.ReadFile("../../examples/azure/compact.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(m)
	first, err := Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	after, _ := json.Marshal(m)
	if !bytes.Equal(before, after) || !bytes.Equal(a, b) {
		t.Fatal("compile mutated input or was nondeterministic")
	}
	grants := first.Broker.Profiles[0].Grants
	if len(grants) != 2 {
		t.Fatalf("grants=%#v", grants)
	}
	for _, grant := range grants {
		tenant := m.BrokerProviders[grant.Provider].Config["tenant"].(string)
		if !contains(grant.Resources, "provider-scope/"+tenant) || !contains(grant.Resources, "query-identity/"+tenant) || len(grant.Resources) != 2 || grant.Authorization.DefaultAction != "deny" || len(grant.Authorization.Rules) != 2 {
			t.Fatalf("incorrect compact grant: %#v", grant)
		}
	}
	if len(strings.Split(strings.TrimSpace(string(raw)), "\n")) > 60 {
		t.Fatal("compact two-identity example exceeded budget")
	}
	for _, replacement := range [][2]string{
		{"allSubscriptions: true", "allSubscriptions: false"},
		{"allSubscriptions: true", "allSubscriptions: true\n      subscriptions: []"},
		{"allow:\n", "allow:\n      resources: []\n"},
		{"inheritProviderScope: true", "inheritProviderScope: false"},
		{"inheritProviderScope: true", "inheritProviderScope: true\n        resources: []"},
		{"inheritProviderScope: true", "resources: []"},
		{"queryIdentity: true", "queryIdentity: false"},
		{"authorization: {preset: observe}", "authorization: {preset: observe, defaultAction: allow}"},
	} {
		if _, err := Decode(strings.NewReader(strings.ReplaceAll(string(raw), replacement[0], replacement[1]))); err == nil {
			t.Fatalf("accepted %q", replacement[1])
		}
	}
}

func TestAzureSubscriptionLimitMatchesProvider(t *testing.T) {
	subscriptions := make([]string, 257)
	for index := range subscriptions {
		subscriptions[index] = fmt.Sprintf("%08x-1111-1111-1111-111111111111", index)
	}
	provider := BrokerProvider{Plugin: "azure", Config: map[string]any{
		"tenant": "22222222-2222-2222-2222-222222222222", "subscriptions": subscriptions[:256],
	}, Allow: map[string]any{"resources": []string{"arm:/subscriptions/" + subscriptions[0]}}}
	if err := validateAzureProvider(provider); err != nil {
		t.Fatal(err)
	}
	provider.Config["subscriptions"] = subscriptions
	if validateAzureProvider(provider) == nil {
		t.Fatal("accepted more subscriptions than the trusted provider supports")
	}
}

func TestAzureInheritanceDoesNotImplyQueryAndExplicitScopesRemainNarrow(t *testing.T) {
	raw, err := os.ReadFile("../../examples/azure/compact.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	profile := m.Profiles["azure-investigation"]
	profile.Azure[0].QueryIdentity = nil
	profile.Azure[1].InheritProviderScope = nil
	profile.Azure[1].QueryIdentity = nil
	profile.Azure[1].Resources = []string{"arm:/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/narrow"}
	m.Profiles["azure-investigation"] = profile
	compiled, err := Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range compiled.Broker.Profiles[0].Grants {
		if len(grant.Resources) != 1 || len(grant.Authorization.Rules) != 1 {
			t.Fatalf("scope was broadened: %#v", grant)
		}
		if grant.Provider == "azure-one" && grant.Resources[0] != "provider-scope/22222222-2222-2222-2222-222222222222" {
			t.Fatal("incorrect inheritance")
		}
		if grant.Provider == "azure-two" && grant.Resources[0] != profile.Azure[1].Resources[0] {
			t.Fatal("narrow scope changed")
		}
	}
}
