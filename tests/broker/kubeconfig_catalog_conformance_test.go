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
	ca := base64.StdEncoding.EncodeToString([]byte(kubeconfigTestCAPEM))
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
      authorization:
        defaultAction: deny
        rules:
          - {operation: observe, resource: context/allowed}
`, provider, privateConfig, filepath.Join(f.home, "provider-state"))
	if err := os.WriteFile(f.config, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	f.writeRoleIdentities(map[string]roleIdentity{
		"agent": {Token: "agent-token", Role: "agent", Grants: []roleGrant{{
			Provider: "clusters", Resources: []string{"allowed"}, Materialization: "header-inject",
			Authorization: map[string]any{"defaultAction": "deny", "rules": []any{map[string]any{"operation": "observe", "resource": "context/allowed"}}},
		}}},
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
	for _, denied := range []struct{ method, path string }{
		{"GET", "/api/v1/secrets"},
		{"POST", "/api/v1/namespaces/development/configmaps"},
		{"GET", "/api/v1/namespaces/development/pods/name/exec"},
		{"GET", "/apis/example.dev/v1/namespaces/development/widgets/name/proxy"},
	} {
		status, body := f.postJSONWithToken("egress-token", "/v1/injection/headers", map[string]any{
			"capability": "clusters", "host": allowedHost, "method": denied.method, "path": denied.path,
		})
		if status == 200 || body["error"] != "operation-not-allowed" {
			t.Fatalf("unsafe Kubernetes request %s %s status=%d body=%v", denied.method, denied.path, status, body)
		}
	}
	var normalizedDenial map[string]any
	for _, entry := range readAudit(t, f.audit) {
		if entry["operation"] == "injection.headers" && entry["allowed"] == false && entry["normalized_operation"] == "unclassified" {
			normalizedDenial = entry
		}
	}
	if normalizedDenial == nil || normalizedDenial["normalized_resource"] != "context/allowed" ||
		strings.Contains(fmt.Sprint(normalizedDenial), "real-kubernetes-token") {
		t.Fatalf("sanitized normalized Kubernetes denial missing from audit: %v", normalizedDenial)
	}
	deniedHost := kubeRouteHost("clusters", "denied")
	if status, body := f.postJSONWithToken("egress-token", "/v1/injection/headers", map[string]any{
		"capability": "clusters", "host": deniedHost, "method": "GET", "path": "/api",
	}); status == 200 || body["error"] != "resource-not-granted" {
		t.Fatalf("undeclared context injection status=%d body=%v", status, body)
	}
}

const kubeconfigTestCAPEM = `-----BEGIN CERTIFICATE-----
MIIDFTCCAf2gAwIBAgIUPx17Hd63iAmiPI8cJl4gykAppSYwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPa3ViZXJuZXRlcy50ZXN0MB4XDTI2MDkwMjIzMzYyMloX
DTM2MDgzMDIzMzYyMlowGjEYMBYGA1UEAwwPa3ViZXJuZXRlcy50ZXN0MIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnXgPpqHukq/WVndzrqUcsYMCwNfF
THbbJfY+smn2ERX0OtYNPpBZuouyUdFhRq5qoHA8J0/Iq5lV5Yqeu7YHvIFPPmfV
E4gp9bi3vpKMWTvxwvVPItaR7JYHdELnqICJHVDrHm8QBkMaDPTYYL3aA8yM+Ub3
tI5bSdkW8ImxvNA7DVs59OsZO1ZL92l0vQFoG2mSk2W1FQugbdTsN+rg52LI3hKN
BfVMHGfh4Z2EGqcNo38ExpMzh8RbiwqErOwMnhvDgZZ+a1HwxmNvbEx6G5nJ9bsS
RzSr3ffhaU7/F9Z1swjt2rCq80TSPZG8k3KXB+4iLh9Ga4WyuxeZ/aQb8QIDAQAB
o1MwUTAdBgNVHQ4EFgQUuLSECsJdYO4XYAGhQZU5XhinrJowHwYDVR0jBBgwFoAU
uLSECsJdYO4XYAGhQZU5XhinrJowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAdhjsMBCygCSBLuGl62sqjurycifi8ezqMarWuoNoAbXw6aNNl7ZO
hF14c8Ar3ITUYkEg+IqBGu29kC2oANmBmT1WAGEpuWSddQ+m6Ma4lCjVK48nFHqH
MCjuvhFPo+QuCbjZPrk9O7T7ow/aknA+ueCRls71em+K4SzriUpPEQq7h1I/nia8
mfmw2jtaM1EZdUUB3i+38VXjYwZ127y0K2qd+Tx0JgSdAOAtNyzzrzLalbZq7qKN
3vCjF8ECZQPIoRHDImumImIlYI+SuDhBfrOlDXZ48YCtcXc3/L5iK1ZK2GzOfzCj
F1Pc0azl1YVeuuP+URvLRmF+Pp1HSFWLog==
-----END CERTIFICATE-----
`

func kubeRouteHost(provider, context string) string {
	digest := sha256.Sum256([]byte(provider + "\x00" + context))
	return "k-" + fmt.Sprintf("%x", digest[:10]) + ".kube.nvt.invalid"
}
