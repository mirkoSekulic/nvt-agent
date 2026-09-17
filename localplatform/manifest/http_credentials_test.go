package manifest

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func httpExample(t *testing.T) Manifest {
	t.Helper()
	data, err := os.ReadFile("../../examples/http-credentials/manifest.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m, err := Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestHTTPCredentialsCompileWithoutCheckout(t *testing.T) {
	m := httpExample(t)
	before, _ := json.Marshal(m)
	c, err := Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(m)
	if !bytes.Equal(before, after) {
		t.Fatal("compiler mutated input")
	}
	if len(c.PrivateInputs) != 1 || len(c.Controller.Repositories) != 0 {
		t.Fatal("secret duplication or synthetic repository")
	}
	for _, p := range c.Broker.Profiles {
		want := map[string]int{"api-only": 1, "git-and-api": 2, "ungranted": 0}[p.Name]
		if len(p.Grants) != want {
			t.Fatalf("profile %s grants = %d", p.Name, len(p.Grants))
		}
		for _, g := range p.Grants {
			if g.Purpose != "http-injection" || len(g.Repositories) != 0 || g.Mediation.Git {
				t.Fatal("HTTP access became checkout/repository intent")
			}
		}
	}
	p := m.Profiles["git-and-api"]
	p.HTTPCredentials = []string{"forge-api", "forge-git"}
	m.Profiles["git-and-api"] = p
	c2, err := Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := c.CanonicalJSON()
	b, _ := c2.CanonicalJSON()
	if !bytes.Equal(a, b) {
		t.Fatal("selection order changed compiled configuration")
	}
	if !reflect.DeepEqual(c.Broker.Providers[0].Provider.Secrets, c.Broker.Providers[1].Provider.Secrets) {
		t.Fatal("providers do not share secret binding")
	}
}

func TestHTTPInvalidAndContradictoryBindings(t *testing.T) {
	for name, mutate := range map[string]func(*Manifest){
		"unknown": func(m *Manifest) {
			p := m.Profiles["api-only"]
			p.HTTPCredentials = []string{"missing"}
			m.Profiles["api-only"] = p
		},
		"duplicate": func(m *Manifest) {
			p := m.Profiles["api-only"]
			p.HTTPCredentials = append(p.HTTPCredentials, "forge-api")
			m.Profiles["api-only"] = p
		},
		"repository-scope": func(m *Manifest) {
			p := m.Profiles["api-only"]
			p.CredentialProviders = []string{"forge-api"}
			m.Profiles["api-only"] = p
		},
		"git-mode": func(m *Manifest) {
			p := m.BrokerProviders["forge-api"]
			p.Config["injection-git"] = true
			m.BrokerProviders["forge-api"] = p
		},
		"host-mismatch": func(m *Manifest) {
			p := m.BrokerProviders["forge-api"]
			p.Config["injection-hosts"] = []any{"elsewhere.example.test"}
			m.BrokerProviders["forge-api"] = p
		},
		"wildcard": func(m *Manifest) {
			p := m.BrokerProviders["forge-api"]
			p.Mediation.Hosts = []string{"*.example.test"}
			m.BrokerProviders["forge-api"] = p
		},
		"url": func(m *Manifest) {
			p := m.BrokerProviders["forge-api"]
			p.Mediation.Hosts = []string{"https://forge.example.test/api"}
			m.BrokerProviders["forge-api"] = p
		},
		"wire-conflict": func(m *Manifest) { m.BrokerProviders["forge-git"].Config["injection-scheme"] = "Bearer" },
		"env-secret":    func(m *Manifest) { m.BrokerProviders["forge-git"].Config["token-env"] = "PAT" },
		"inline-secret": func(m *Manifest) { m.BrokerProviders["forge-git"].Config["token"] = "fake-inline-canary" },
		"repository-metadata": func(m *Manifest) {
			p := m.BrokerProviders["forge-api"]
			p.Mediation.TargetMode = "literal"
			m.BrokerProviders["forge-api"] = p
		},
		"no-secret": func(m *Manifest) {
			p := m.BrokerProviders["forge-api"]
			p.Secrets = nil
			m.BrokerProviders["forge-api"] = p
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := httpExample(t)
			mutate(&m)
			if m.Validate() == nil {
				t.Fatal("accepted invalid binding")
			}
		})
	}
}

func TestHTTPAndRepositoryScopedGitShareSecretWithoutBroadeningGit(t *testing.T) {
	m := httpExample(t)
	git := m.BrokerProviders["forge-git"]
	git.Mediation.Git = true
	git.Mediation.Username = "git"
	git.Mediation.TargetMode = "literal"
	git.Config["injection-git"] = true
	git.Config["target-mode"] = "literal"
	m.BrokerProviders["forge-git"] = git
	p := m.Profiles["git-and-api"]
	p.HTTPCredentials = []string{"forge-api"}
	p.CredentialProviders = []string{"forge-git"}
	m.Profiles["git-and-api"] = p
	m.Repositories = map[string]Repository{"project": {URL: "https://forge.example.test/team/project.git", CheckoutTarget: "forge.example.test/team/project", BrokerRepository: "forge.example.test/team/project", CredentialProvider: "forge-git"}}
	m.Workstations[1].Repositories = []string{"project"}
	c, err := Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range c.Broker.Profiles {
		if p.Name == "git-and-api" {
			if len(p.Grants) != 2 {
				t.Fatal("unexpected combined grants")
			}
			for _, g := range p.Grants {
				if g.Provider == "forge-git" && (!reflect.DeepEqual(g.Repositories, []string{"forge.example.test/team/project"}) || g.Purpose != "repository" || !g.Mediation.Git) {
					t.Fatal("repository grant broadened")
				}
			}
		}
	}
}
