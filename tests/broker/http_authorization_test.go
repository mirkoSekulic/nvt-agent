package broker_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestTokenHTTPAuthorizationConformance(t *testing.T) {
	f := newBrokerFixtureBase(t, "", "")
	rule := func(method, path string) map[string]any {
		return map[string]any{"operation": "http." + method, "resource": "http/api.example.test" + path}
	}
	policy := func(rules ...map[string]any) map[string]any {
		return map[string]any{"defaultAction": "deny", "rules": rules}
	}
	ceiling := policy(rule("POST", "/graphql"), rule("POST", "/designer/api/*/*/deployments/undeploy"))
	config := map[string]any{"providers": []any{
		map[string]any{"name": "api", "plugin": "token", "config": map[string]any{"token-env": "TEST_PAT_TOKEN", "injection-hosts": []string{"api.example.test"}}, "allow": map[string]any{"authorization": ceiling}},
		map[string]any{"name": "export-test", "plugin": "token", "config": map[string]any{"token-env": "TEST_PAT_TOKEN", "injection-hosts": []string{"api.example.test"}}, "allow": map[string]any{"authorization": ceiling, "repositories": []string{"org/repo"}}},
	}}
	raw, _ := json.Marshal(config)
	if err := os.WriteFile(f.config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	// TEST_PAT_TOKEN is the existing isolated fixture token, not a workstation credential.
	f.writeRoleIdentities(map[string]roleIdentity{
		"raw-export":       {Token: "export-token", Role: "agent", Grants: []roleGrant{{Provider: "export-test", Materialization: "file-bundle", Repositories: []string{"org/repo"}}}},
		"agent":            {Token: "agent-token", Role: "agent", Grants: []roleGrant{{Provider: "api", Materialization: "header-inject", Authorization: policy(rule("POST", "/graphql"), rule("POST", "/designer/api/*/*/deployments/undeploy"), rule("DELETE", "/graphql"))}}},
		"egress":           {Token: "egress-token", Role: "egress", PairedAgent: "agent"},
		"narrow":           {Token: "narrow-token", Role: "agent", Grants: []roleGrant{{Provider: "api", Materialization: "header-inject", Authorization: policy(rule("POST", "/graphql"))}}},
		"narrow-egress":    {Token: "narrow-egress-token", Role: "egress", PairedAgent: "narrow"},
		"absent":           {Token: "absent-token", Role: "agent", Grants: []roleGrant{{Provider: "api", Materialization: "header-inject"}}},
		"absent-egress":    {Token: "absent-egress-token", Role: "egress", PairedAgent: "absent"},
		"other":            {Token: "other-token", Role: "agent"},
		"other-egress":     {Token: "other-egress-token", Role: "egress", PairedAgent: "other"},
		"malformed":        {Token: "malformed-token", Role: "agent", Grants: []roleGrant{{Provider: "api", Materialization: "header-inject", Authorization: map[string]any{"defaultAction": "allow"}}}},
		"malformed-egress": {Token: "malformed-egress-token", Role: "egress", PairedAgent: "malformed"},
	})
	f.start()
	t.Cleanup(f.stop)
	status, body := f.postJSONWithToken("export-token", "/v1/token", map[string]any{"provider": "export-test", "target": "org/repo"})
	if status != 403 || body["error"] != "http-policy-requires-injection" || strings.Contains(bodyText(body), "pat-secret") {
		t.Fatalf("raw token export bypassed endpoint policy: %d", status)
	}
	for _, tc := range []struct {
		token, host, method, path string
		upgrade                   bool
		status                    int
	}{
		{"egress-token", "api.example.test", "POST", "/graphql", false, 200},
		{"egress-token", "api.example.test", "POST", "/designer/api/org/app/deployments/undeploy", false, 200},
		{"egress-token", "api.example.test", "DELETE", "/graphql", false, 403},
		{"egress-token", "api.example.test", "GET", "/graphql", false, 403},
		{"egress-token", "api.example.test", "post", "/graphql", false, 403},
		{"egress-token", "other.example.test", "POST", "/graphql", false, 403},
		{"egress-token", "api.example.test", "POST", "/%67raphql", false, 403},
		{"egress-token", "api.example.test", "POST", "/graphql?q=1", false, 403},
		{"egress-token", "api.example.test", "POST", "/graphql", true, 403},
		{"narrow-egress-token", "api.example.test", "POST", "/designer/api/org/app/deployments/undeploy", false, 403},
		{"other-egress-token", "api.example.test", "POST", "/graphql", false, 403},
		{"absent-egress-token", "api.example.test", "POST", "/graphql", false, 403},
		{"agent-token", "api.example.test", "POST", "/graphql", false, 403},
		{"malformed-egress-token", "api.example.test", "POST", "/graphql", false, 403},
	} {
		status, body := f.postJSONWithToken(tc.token, "/v1/injection/headers", map[string]any{"capability": "api", "host": tc.host, "method": tc.method, "path": tc.path, "upgrade": tc.upgrade, "agent_id": "agent"})
		if status != tc.status {
			t.Fatalf("%s %s %s: status %d expected %d: %v", tc.token, tc.method, tc.path, status, tc.status, body)
		}
		if status != 200 && (body["headers"] != nil || strings.Contains(bodyText(body), "pat-secret")) {
			t.Fatal("denial leaked material")
		}
	}
}

func TestTokenHTTPPolicyValidation(t *testing.T) {
	f := newBrokerFixtureBase(t, "", "")
	cmd := exec.Command("python3", "-m", "unittest", "broker.plugins.static_token.http_policy_test")
	cmd.Dir = f.root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("HTTP policy tests: %v\n%s", err, out)
	}
}

func bodyText(value any) string { raw, _ := json.Marshal(value); return string(raw) }
