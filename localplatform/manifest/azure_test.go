package manifest

import (
	"bytes"
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
