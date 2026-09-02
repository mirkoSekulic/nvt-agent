package dockerbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

func TestCatalogPreparationSeedsSanitizedConfigAndPinnedRoute(t *testing.T) {
	const host = "k-01234567890123456789.kube.nvt.invalid"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/catalog" || r.Header.Get("Authorization") != "Bearer agent-token" {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"files": []map[string]any{{
				"path": ".kube/config", "mode": "0600",
				"content": "apiVersion: v1\nkind: Config\npreferences: {}\nclusters:\n- name: preserved-cluster\n  cluster:\n    server: https://" + host + "\nusers:\n- name: preserved-user\n  user: {}\ncontexts:\n- name: development\n  context: {cluster: preserved-cluster, user: preserved-user}\ncurrent-context: development\n",
			}},
			"routes": []map[string]any{{
				"id": "development", "host": host, "upstream": "10.20.30.40:6443",
				"server_name": "kubernetes.internal", "ca_pem": "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n",
				"allow_private_upstream": true,
			}},
			"expires_at": nil,
		})
	}))
	defer server.Close()
	preparer, err := newBrokerPreparer(server.URL, "", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	run := resolvedrun.ResolvedAgentRun{
		Broker: resolvedrun.Broker{Grants: []resolvedrun.BrokerGrant{{
			Provider: "clusters", Resources: []string{"development"}, Preparations: []string{"catalog"},
			Materialization: "header-inject", EgressHosts: []string{host + ":443"},
		}}},
		Egress: resolvedrun.Egress{Mode: "mediated", Transport: "transparent"},
	}
	rendered, _, routes, err := preparer.prepare(context.Background(), run, "agent-token", json.RawMessage(`{"preseed":{"files":[]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rendered), `"path":"$HOME/.kube/config"`) || !strings.Contains(string(rendered), "clusters:x@127.0.0.1:15002") || strings.Contains(string(rendered), "agent-token") || len(routes) != 1 {
		t.Fatalf("catalog preparation = %s routes=%#v", rendered, routes)
	}
	egress, err := renderEgressdConfig(Config{BrokerURL: "http://broker"}, run, routes)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{host, "10.20.30.40:6443", "kubernetes.internal", `"allow_private_upstream": true`} {
		if !strings.Contains(string(egress), expected) {
			t.Fatalf("egress config omitted %q: %s", expected, egress)
		}
	}
	run.Egress.Transport = "redirect"
	redirectEgress, err := renderEgressdConfig(Config{BrokerURL: "http://broker"}, run, routes)
	if err != nil {
		t.Fatal(err)
	}
	var redirectConfig struct {
		Routes       []map[string]any `json:"routes"`
		ForwardProxy map[string]any   `json:"forward_proxy"`
	}
	if err := json.Unmarshal(redirectEgress, &redirectConfig); err != nil {
		t.Fatal(err)
	}
	if len(redirectConfig.Routes) != 0 || redirectConfig.ForwardProxy == nil || redirectConfig.ForwardProxy["allow_unmatched_hosts"] != false {
		t.Fatalf("redirect catalog route was not isolated to the forward proxy: %s", redirectEgress)
	}
}

func TestCatalogPreparationMergesSeparateProviderInstances(t *testing.T) {
	type fixture struct{ contextName, clusterName, host string }
	fixtures := map[string]fixture{
		"clusters-a": {contextName: "development", clusterName: "development-cluster", host: "k-aaaaaaaaaaaaaaaaaaaa.kube.nvt.invalid"},
		"clusters-b": {contextName: "production", clusterName: "production-cluster", host: "k-bbbbbbbbbbbbbbbbbbbb.kube.nvt.invalid"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]string
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		provider := request["provider"]
		entry, ok := fixtures[provider]
		if !ok {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"files": []map[string]any{{"path": ".kube/config", "mode": "0600", "content": fmt.Sprintf(
				"apiVersion: v1\nkind: Config\npreferences: {}\nclusters:\n- name: %s\n  cluster: {server: https://%s}\nusers:\n- name: shared-auth-info\n  user: {}\ncontexts:\n- name: %s\n  context: {cluster: %s, user: shared-auth-info}\ncurrent-context: %s\n",
				entry.clusterName, entry.host, entry.contextName, entry.clusterName, entry.contextName)}},
			"routes": []map[string]any{{
				"id": entry.contextName, "host": entry.host, "upstream": "10.20.30.40:6443",
				"server_name": "kubernetes.internal", "ca_pem": "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n",
				"allow_private_upstream": true,
			}},
			"expires_at": nil,
		})
	}))
	defer server.Close()
	preparer, err := newBrokerPreparer(server.URL, "", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	grants := []resolvedrun.BrokerGrant{}
	for _, provider := range []string{"clusters-a", "clusters-b"} {
		entry := fixtures[provider]
		grants = append(grants, resolvedrun.BrokerGrant{
			Provider: provider, Resources: []string{entry.contextName}, Preparations: []string{"catalog"},
			Materialization: "header-inject", EgressHosts: []string{entry.host + ":443"},
		})
	}
	run := resolvedrun.ResolvedAgentRun{Broker: resolvedrun.Broker{Grants: grants}, Egress: resolvedrun.Egress{Mode: "mediated", Transport: "transparent"}}
	rendered, _, routes, err := preparer.prepare(context.Background(), run, "agent-token", json.RawMessage(`{"preseed":{"files":[]}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"development", "production", "clusters-a:x@127.0.0.1:15002", "clusters-b:x@127.0.0.1:15002"} {
		if !strings.Contains(string(rendered), expected) {
			t.Fatalf("merged kubeconfig omitted %q: %s", expected, rendered)
		}
	}
	if strings.Count(string(rendered), "shared-auth-info") != 3 || len(routes) != 2 {
		// One users entry and two context references survive the merge.
		t.Fatalf("merged kubeconfig/routes are invalid: %s routes=%#v", rendered, routes)
	}
}

func TestRedirectCatalogRendersReachableProxyAndMatchingCAConstraints(t *testing.T) {
	const host = "k-01234567890123456789.kube.nvt.invalid"
	run := testMediatedRun(t)
	catalogGrant := resolvedrun.BrokerGrant{
		Provider: "clusters", Resources: []string{"development"}, Capabilities: []string{"catalog", "injection.headers"},
		Preparations: []string{"catalog"}, Materialization: "header-inject", EgressHosts: []string{host + ":443"},
	}
	run.Broker.Grants = append([]resolvedrun.BrokerGrant{catalogGrant}, run.Broker.Grants...)
	run.Egress = resolvedrun.Egress{Mode: "mediated", Transport: "redirect", PairedEgressRequired: true, AllowInsecureBroker: true}
	config := Config{
		Owner: "test-controller", ExternalNetwork: "agents-proxy", ProxyPort: 4090, ProtectedCIDRs: "127.0.0.0/8 169.254.0.0/16",
		DindImage: "nvt-dind:test", EgressdImage: "nvt-egressd:test", CapturedImage: "nvt-captured:test", SeedImage: "nvt-runtime:test",
	}
	names := namesFor(Config{RunsDir: t.TempDir()}, run.RunID, strings.Repeat("c", 64))
	compose, err := renderCompose(config, run, strings.Repeat("c", 64), names)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range [][]byte{[]byte("captured:"), []byte("--leaf-dns-name"), []byte("--upstream-leaf-name"), []byte(host)} {
		if !bytes.Contains(compose, expected) {
			t.Fatalf("redirect catalog compose omitted %q:\n%s", expected, compose)
		}
	}
	routes := []catalogRoute{{
		ID: "development", Host: host, Upstream: "10.20.30.40:6443", ServerName: "kubernetes.internal",
		CAPEM: "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n", AllowPrivateUpstream: true,
	}}
	egress, err := renderEgressdConfig(Config{BrokerURL: "http://broker"}, run, routes)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"leaf_dns_names": [`, `"egressd"`, `"listen": "0.0.0.0:8470"`, host} {
		if !strings.Contains(string(egress), expected) {
			t.Fatalf("redirect catalog egress config omitted %q: %s", expected, egress)
		}
	}
	bindings := renderBindings(run)
	if _, exists := bindings.RedirectBaseURLs["clusters"]; exists || bindings.RedirectBaseURLs["git-provider"] != "https://egressd:8471" {
		t.Fatalf("redirect bindings do not match listener allocation: %#v", bindings.RedirectBaseURLs)
	}
}
