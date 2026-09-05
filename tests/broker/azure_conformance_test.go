package broker_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAzureBrokerBoundaryScopeAndRefresh(t *testing.T) {
	f := newBrokerFixtureBase(t, "", "")
	state := filepath.Join(f.home, "azure-one")
	if err := os.MkdirAll(state, 0700); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`provider-plugins:
  - name: azure
    command: [/usr/bin/python3, %q]
providers:
  - name: azure-one
    plugin: azure
    config:
      tenant: 22222222-2222-2222-2222-222222222222
      subscriptions: [11111111-1111-1111-1111-111111111111]
      state-dir: %q
    allow:
      resources: [arm:/subscriptions/11111111-1111-1111-1111-111111111111, query-identity/22222222-2222-2222-2222-222222222222]
      authorization:
        defaultAction: deny
        rules:
          - {operation: observe, resource: azure/arm:/subscriptions/11111111-1111-1111-1111-111111111111}
          - {operation: observe, resource: azure/query-identity/22222222-2222-2222-2222-222222222222}
`, filepath.Join(f.root, "tests", "azure-cli", "token_fixture.py"), state)
	if err := os.WriteFile(f.config, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	f.writeRoleIdentities(map[string]roleIdentity{
		"agent":  {Token: "agent-token", Role: "agent", Grants: []roleGrant{{Provider: "azure-one", Materialization: "header-inject", Resources: []string{"arm:/subscriptions/11111111-1111-1111-1111-111111111111", "query-identity/22222222-2222-2222-2222-222222222222"}}}},
		"egress": {Token: "egress-token", Role: "egress", PairedAgent: "agent"},
	})
	f.start()
	t.Cleanup(f.stop)
	arm := "/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups?api-version=2024-11-01"
	request := func(method, host, path string) (int, map[string]any) {
		return f.postJSONWithToken("egress-token", "/v1/injection/headers", map[string]any{"capability": "azure-one", "host": host, "method": method, "path": path})
	}
	for _, item := range []struct{ method, host, path string }{{"GET", "management.azure.com", arm}, {"POST", "api.loganalytics.io", "/v1/workspaces/33333333-3333-3333-3333-333333333333/query"}} {
		status, body := request(item.method, item.host, item.path)
		if status != 200 || !strings.Contains(fmt.Sprint(body["headers"]), "fixture-trusted-azure-one") {
			t.Fatalf("injection failed %d %v", status, body)
		}
	}
	for _, item := range []struct{ method, host, path string }{
		{"DELETE", "management.azure.com", arm},
		{"GET", "management.azure.com", strings.ReplaceAll(arm, "11111111", "99999999")},
		{"POST", "management.azure.com", "/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/r/providers/Microsoft.Storage/storageAccounts/s/listKeys?api-version=2025-08-01"},
		{"GET", "api.loganalytics.io", "/v1/workspaces/33333333-3333-3333-3333-333333333333/query?query=PRIVATE_QUERY_CANARY"},
	} {
		status, body := request(item.method, item.host, item.path)
		if status != 403 || body["error"] != "operation-not-allowed" {
			t.Fatalf("unsafe operation accepted %d %v", status, body)
		}
	}
	for _, endpoint := range []string{"/v1/token", "/v1/headers", "/v1/files", "/v1/injection/headers"} {
		status, body := f.postJSONWithToken("agent-token", endpoint, map[string]any{"provider": "azure-one", "capability": "azure-one", "target": "management.azure.com", "host": "management.azure.com", "method": "GET", "path": arm})
		if status == 200 || strings.Contains(fmt.Sprint(body), "fixture-trusted") {
			t.Fatalf("credential export %s: %d %v", endpoint, status, body)
		}
	}
	if err := os.WriteFile(filepath.Join(state, "unavailable"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if status, body := request("GET", "management.azure.com", arm); status != 503 || body["error"] != "azure-credentials-unavailable" {
		t.Fatalf("stale token fallback %d %v", status, body)
	}
	for _, entry := range readAudit(t, f.audit) {
		if strings.Contains(fmt.Sprint(entry), "fixture-trusted") || strings.Contains(fmt.Sprint(entry), "PRIVATE_QUERY_CANARY") {
			t.Fatal("audit captured credential or query")
		}
	}
	// Revocation denies even while the token source is unavailable, rather than
	// consulting provider credentials or using an old successful result.
	f.writeRoleIdentities(map[string]roleIdentity{"agent": {Token: "agent-token", Role: "agent"}, "egress": {Token: "egress-token", Role: "egress", PairedAgent: "agent"}})
	if status, _ := request("GET", "management.azure.com", arm); status == 200 {
		t.Fatal("revoked grant retained access")
	}
}
