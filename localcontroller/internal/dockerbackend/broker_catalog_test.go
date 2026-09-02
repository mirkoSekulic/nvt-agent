package dockerbackend

import (
	"context"
	"encoding/json"
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
				"content": "apiVersion: v1\nkind: Config\nclusters:\n- name: preserved-cluster\n  cluster:\n    server: https://" + host + "\nusers:\n- name: preserved-user\n  user: {}\ncontexts:\n- name: development\n  context: {cluster: preserved-cluster, user: preserved-user}\ncurrent-context: development\n",
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
