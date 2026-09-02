package broker_test

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKubeconfigCatalogAndInjectionIdentityBoundary(t *testing.T) {
	f := newBrokerFixtureBase(t, "", "")
	privateConfig := filepath.Join(f.home, "private-kubeconfig.yaml")
	ca := base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n"))
	document := fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: allowed
clusters:
  - name: allowed-cluster
    cluster: {server: "https://10.20.30.40:6443", tls-server-name: kubernetes.internal, certificate-authority-data: %q}
  - name: denied-cluster
    cluster: {server: "https://10.20.30.41:6443", tls-server-name: kubernetes.internal, certificate-authority-data: %q}
users:
  - name: preserved-user
    user: {token: real-kubernetes-token}
contexts:
  - name: allowed
    context: {cluster: allowed-cluster, user: preserved-user, namespace: development}
  - name: denied
    context: {cluster: denied-cluster, user: preserved-user}
`, ca, ca)
	if err := os.WriteFile(privateConfig, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	provider := filepath.Join(f.root, "broker", "providers", "kubeconfig", "provider.py")
	config := fmt.Sprintf(`provider-plugins:
  - name: kubeconfig
    command: [%q]
providers:
  - name: clusters
    plugin: kubeconfig
    config:
      private-kubeconfig: %q
      state-dir: %q
    allow:
      resources: [allowed, denied]
`, provider, privateConfig, filepath.Join(f.home, "provider-state"))
	if err := os.WriteFile(f.config, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	f.writeRoleIdentities(map[string]roleIdentity{
		"agent":  {Token: "agent-token", Role: "agent", Grants: []roleGrant{{Provider: "clusters", Resources: []string{"allowed"}, Materialization: "header-inject"}}},
		"egress": {Token: "egress-token", Role: "egress", PairedAgent: "agent"},
	})
	f.start()
	t.Cleanup(f.stop)

	status, catalog := f.postJSONWithToken("agent-token", "/v1/catalog", map[string]any{"provider": "clusters"})
	if status != 200 || catalog["ok"] != true {
		t.Fatalf("catalog status=%d body=%v stderr=%s", status, catalog, f.stderr.String())
	}
	raw := fmt.Sprint(catalog)
	for _, forbidden := range []string{"real-kubernetes-token", "client-key", "exec:"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("catalog leaked %q: %s", forbidden, raw)
		}
	}
	if status, body := f.postJSONWithToken("egress-token", "/v1/catalog", map[string]any{"provider": "clusters"}); status == 200 || body["error"] != "role-not-allowed" {
		t.Fatalf("egress identity obtained catalog: status=%d body=%v", status, body)
	}
	allowedHost := kubeRouteHost("clusters", "allowed")
	status, injected := f.postJSONWithToken("egress-token", "/v1/injection/headers", map[string]any{
		"capability": "clusters", "host": allowedHost, "method": "GET", "path": "/api/v1/pods",
	})
	if status != 200 || fmt.Sprint(injected["headers"]) != "map[authorization:Bearer real-kubernetes-token]" {
		t.Fatalf("paired injection status=%d body=%v", status, injected)
	}
	deniedHost := kubeRouteHost("clusters", "denied")
	if status, body := f.postJSONWithToken("egress-token", "/v1/injection/headers", map[string]any{
		"capability": "clusters", "host": deniedHost, "method": "GET", "path": "/api",
	}); status == 200 || body["error"] != "resource-not-granted" {
		t.Fatalf("undeclared context injection status=%d body=%v", status, body)
	}
}

func kubeRouteHost(provider, context string) string {
	digest := sha256.Sum256([]byte(provider + "\x00" + context))
	return "k-" + fmt.Sprintf("%x", digest[:10]) + ".kube.nvt.invalid"
}
