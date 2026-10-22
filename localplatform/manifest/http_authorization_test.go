package manifest

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func httpPolicyExample(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../examples/http-authorization/manifest.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestHTTPAuthorizationCompilesConcretePolicyWithoutCheckout(t *testing.T) {
	raw := httpPolicyExample(t)
	m, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(m)
	compiled, err := Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	grant := compiled.Broker.Profiles[0].Grants[0]
	if grant.Authorization == nil || grant.Authorization.DefaultAction != "deny" || len(grant.Authorization.Rules) != 1 || len(grant.Repositories) != 0 || len(compiled.Controller.Repositories) != 0 {
		t.Fatal("policy omitted or checkout invented")
	}
	if compiled.Controller.Profiles[0].BrokerGrants[0].Authorization.Rules[0].Resource != "http/api.example.test/graphql" {
		t.Fatal("controller grant lost policy")
	}
	compiled.Controller.Profiles[0].Profile.HTTPCredentials[0].Authorization.Rules[0].Resource = "changed"
	after, _ := json.Marshal(m)
	if !bytes.Equal(before, after) {
		t.Fatal("compiler aliased authored policy")
	}
	// Default-deny omission has the same concrete compiled grant.
	m.Profiles["api-client"].HTTPCredentials[0].Authorization.DefaultAction = ""
	compiled, err = Compile(m)
	if err != nil || compiled.Broker.Profiles[0].Grants[0].Authorization.DefaultAction != "deny" {
		t.Fatal("default deny not expanded")
	}
}

func TestHTTPAuthorizationInvalidPolicies(t *testing.T) {
	raw := string(httpPolicyExample(t))
	for _, invalid := range []string{
		strings.ReplaceAll(raw, "defaultAction: deny", "defaultAction: null"),
		strings.Replace(raw, "defaultAction: deny", "defaultAction: allow", 1),
		strings.ReplaceAll(raw, "http.POST", "http.*"),
		strings.ReplaceAll(raw, "http.POST", "http.post"),
		strings.ReplaceAll(raw, "http/api.example.test/graphql", "http/*.example.test/graphql"),
		strings.ReplaceAll(raw, "http/api.example.test/graphql", "http/api.example.test/%67raphql"),
		strings.ReplaceAll(raw, "http/api.example.test/graphql", "http/api.example.test/graphql?query=x"),
		strings.ReplaceAll(raw, "http/api.example.test/graphql", "http/api.example.test/graphql/"),
		strings.ReplaceAll(raw, "http/api.example.test/graphql", "http/api.example.test/.."),
		strings.ReplaceAll(raw, "/*/*/", "/**/"),
		strings.Replace(raw, "- provider: api", "- provider: api\n        unexpected: true", 1),
		strings.Replace(raw, "- provider: api", "- provider: missing", 1),
		strings.Replace(raw, "httpCredentials:", "httpCredentials: [api]\n    unused:", 1),
	} {
		if _, err := Decode(strings.NewReader(invalid)); err == nil {
			t.Fatalf("invalid policy accepted:\n%s", invalid)
		}
	}
	for _, mutate := range []func(*Manifest){
		func(m *Manifest) { p := m.BrokerProviders["api"]; p.Allow = nil; m.BrokerProviders["api"] = p },
		func(m *Manifest) { m.Profiles["api-client"].HTTPCredentials[0].Authorization = nil },
		func(m *Manifest) {
			p := m.BrokerProviders["api"]
			p.Allow["repositories"] = []any{"*"}
			m.BrokerProviders["api"] = p
		},
		func(m *Manifest) { p := m.BrokerProviders["api"]; p.Mediation.Git = true; m.BrokerProviders["api"] = p },
		func(m *Manifest) { p := m.BrokerProviders["api"]; p.Plugin = "headers"; m.BrokerProviders["api"] = p },
		func(m *Manifest) {
			a := m.Profiles["api-client"].HTTPCredentials[0].Authorization
			a.Rules = append(a.Rules, a.Rules[0])
		},
		func(m *Manifest) {
			a := m.Profiles["api-client"].HTTPCredentials[0].Authorization
			a.Rules = make([]BrokerGrantAuthorizationRule, 129)
		},
	} {
		m, err := Decode(strings.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		mutate(&m)
		if m.Validate() == nil {
			t.Fatal("contradictory policy accepted")
		}
	}
}

func TestHTTPAuthorizationRejectsNullFields(t *testing.T) {
	for _, raw := range []string{
		`{"provider":"api","authorization":null}`,
		`{"provider":"api","authorization":{"rules":null}}`,
		`{"provider":"api","authorization":{"defaultAction":null}}`,
	} {
		var access HTTPCredentialAccess
		if err := json.Unmarshal([]byte(raw), &access); err == nil {
			t.Fatalf("accepted null policy: %s", raw)
		}
	}
}
