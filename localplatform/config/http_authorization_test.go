package config_test

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	serviceconfig "github.com/mirkoSekulic/nvt-agent/localplatform/config"
	"github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

func TestHTTPAuthorizationRendererPreservesBothPolicies(t *testing.T) {
	raw, err := os.ReadFile("../../examples/http-authorization/manifest.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	other := m.Profiles["api-client"]
	other.HTTPCredentials = nil
	other.Egress = nil
	m.Profiles["ungranted"] = other
	c, err := manifest.Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := serviceconfig.Broker(c)
	if err != nil {
		t.Fatal(err)
	}
	var brokerConfig struct {
		Providers []struct {
			Allow map[string]any `json:"allow"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(broker, &brokerConfig); err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(m.BrokerProviders["api"].Allow["authorization"])
	got, _ := json.Marshal(brokerConfig.Providers[0].Allow["authorization"])
	if !bytes.Equal(want, got) {
		t.Fatal("provider ceiling was dropped")
	}
	encoded, err := serviceconfig.Controller(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	var native resolvedrun.TrustedConfiguration
	if err := json.Unmarshal(encoded, &native); err != nil {
		t.Fatal(err)
	}
	if _, err := resolvedrun.NewResolver(native); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range native.Profiles {
		if p.Name == "api-client" {
			found = true
			g := p.Broker.Grants[0]
			if len(p.Broker.Grants) != 1 || g.Authorization == nil || g.Authorization.DefaultAction != "deny" || !reflect.DeepEqual(g.Authorization.Rules, []resolvedrun.BrokerGrantAuthorizationRule{{Operation: "http.POST", Resource: "http/api.example.test/graphql"}}) {
				t.Fatal("grant policy lost")
			}
		}
		if p.Name == "ungranted" && len(p.Broker.Grants) != 0 {
			t.Fatal("grant escaped selected profile")
		}
	}
	if !found || bytes.Contains(encoded, []byte("/private/")) || bytes.Contains(encoded, []byte(".nvt-local")) {
		t.Fatal("missing profile or private reference in agent configuration")
	}
}
