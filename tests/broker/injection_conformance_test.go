package broker_test

// Conformance suite for the mediated credential egress injection contract
// (protocol/injection.md, docs/mediated-egress-plan.md), live as of plan
// Phase 1.

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// nvtPlaceholder is the documented zero-entropy placeholder constant from
// protocol/injection.md.
const nvtPlaceholder = "NVT-PLACEHOLDER-NOT-A-KEY"

type roleGrant struct {
	Provider        string
	Repositories    []string
	Materialization string
	Permissions     map[string]string
	QuotaRequests   int
}

type roleIdentity struct {
	Token       string
	Role        string
	PairedAgent string
	Grants      []roleGrant
}

// writeRoleIdentities writes an agents config using the role/pairing schema
// from protocol/injection.md. It mirrors writeAgents but supports role,
// paired-agent, and per-grant materialization fields.
func (f *brokerFixture) writeRoleIdentities(identities map[string]roleIdentity) {
	f.t.Helper()
	var builder strings.Builder
	builder.WriteString("agents:\n")
	for id, identity := range identities {
		builder.WriteString("  - id: ")
		builder.WriteString(id)
		builder.WriteString("\n")
		hash := sha256.Sum256([]byte(identity.Token))
		builder.WriteString(fmt.Sprintf("    token-sha256: sha256:%x\n", hash[:]))
		if identity.Role != "" {
			builder.WriteString("    role: ")
			builder.WriteString(identity.Role)
			builder.WriteString("\n")
		}
		if identity.PairedAgent != "" {
			builder.WriteString("    paired-agent: ")
			builder.WriteString(identity.PairedAgent)
			builder.WriteString("\n")
		}
		if len(identity.Grants) == 0 {
			builder.WriteString("    grants: []\n")
			continue
		}
		builder.WriteString("    grants:\n")
		for _, grant := range identity.Grants {
			builder.WriteString("      - provider: ")
			builder.WriteString(grant.Provider)
			builder.WriteString("\n")
			if grant.Materialization != "" {
				builder.WriteString("        materialization: ")
				builder.WriteString(grant.Materialization)
				builder.WriteString("\n")
			}
			if len(grant.Repositories) > 0 {
				builder.WriteString("        repositories:\n")
				for _, repo := range grant.Repositories {
					builder.WriteString("          - ")
					builder.WriteString(repo)
					builder.WriteString("\n")
				}
			}
			if len(grant.Permissions) > 0 {
				builder.WriteString("        permissions:\n")
				keys := make([]string, 0, len(grant.Permissions))
				for key := range grant.Permissions {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				for _, key := range keys {
					builder.WriteString(fmt.Sprintf("          %s: %s\n", key, grant.Permissions[key]))
				}
			}
			if grant.QuotaRequests > 0 {
				builder.WriteString(fmt.Sprintf("        quota:\n          requests: %d\n", grant.QuotaRequests))
			}
		}
	}
	tmp := f.agents + ".tmp"
	if err := os.WriteFile(tmp, []byte(builder.String()), 0o600); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Rename(tmp, f.agents); err != nil {
		f.t.Fatal(err)
	}
}

// postJSONWithToken performs a raw HTTP POST against the broker, returning
// status code and decoded body. Injection conformance is pinned at the HTTP
// layer, not through brokerctl: brokerctl is the agent-side client and must
// never grow an injection command.
func (f *brokerFixture) postJSONWithToken(token, path string, payload map[string]any) (int, map[string]any) {
	f.t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		f.t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, f.url+path, bytes.NewReader(body))
	if err != nil {
		f.t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	var decoded map[string]any
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		f.t.Fatalf("decode %s response: %v", path, err)
	}
	return response.StatusCode, decoded
}

// mediatedIdentities is the standard fixture layout for injection tests:
// one agent with a header-inject grant, its paired egress identity, a second
// unrelated agent, and an egress identity paired to that second agent.
func mediatedIdentities() map[string]roleIdentity {
	return map[string]roleIdentity{
		"frontend": {
			Token: "frontend-token",
			Role:  "agent",
			Grants: []roleGrant{
				{Provider: "codex-main", Materialization: "header-inject"},
			},
		},
		"frontend-egress": {
			Token:       "frontend-egress-token",
			Role:        "egress",
			PairedAgent: "frontend",
		},
		"backend": {
			Token:  "backend-token",
			Role:   "agent",
			Grants: []roleGrant{},
		},
		"backend-egress": {
			Token:       "backend-egress-token",
			Role:        "egress",
			PairedAgent: "backend",
		},
	}
}

func injectionRequest() map[string]any {
	return map[string]any{
		"capability": "codex-main",
		"host":       "chatgpt.com",
		"method":     "POST",
		"path":       "/backend-api/responses",
	}
}

// TestInjectionRequiresEgressRole pins the core identity split: the paired
// egress identity obtains injectable headers; the agent identity holding the
// grant itself is refused. This is the load-bearing non-possession property.
func TestInjectionRequiresEgressRole(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(mediatedIdentities())

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", injectionRequest())
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("egress identity denied: status=%d body=%v", status, body)
	}
	headers, ok := body["headers"].(map[string]any)
	if !ok || len(headers) == 0 {
		t.Fatalf("expected injectable headers, got %v", body)
	}

	status, body = f.postJSONWithToken("frontend-token", "/v1/injection/headers", injectionRequest())
	if status == http.StatusOK || body["ok"] == true {
		t.Fatalf("agent identity must not obtain injectable headers: status=%d body=%v", status, body)
	}
}

// TestInjectionDeniesUnpairedEgressIdentity pins pairing: an egress identity
// paired to a different agent cannot fetch material for this agent's grants.
func TestInjectionDeniesUnpairedEgressIdentity(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(mediatedIdentities())

	status, body := f.postJSONWithToken("backend-egress-token", "/v1/injection/headers", injectionRequest())
	if status == http.StatusOK || body["ok"] == true {
		t.Fatalf("egress identity paired to another agent must be denied: status=%d body=%v", status, body)
	}
}

// TestEgressRoleCannotCallSecretBearingEndpoints pins the role restriction in
// the other direction: egress identities are injection-only and must be
// denied on every compatibility endpoint that returns secrets to the caller.
func TestEgressRoleCannotCallSecretBearingEndpoints(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(mediatedIdentities())

	calls := []struct {
		path    string
		payload map[string]any
	}{
		{"/v1/token", map[string]any{"provider": "fork-app", "target": "github.com/my-user/my-repo", "purpose": "git-push"}},
		{"/v1/headers", map[string]any{"provider": "header-provider", "target": "github.com/my-user/my-repo"}},
		{"/v1/files", map[string]any{"provider": "codex-main"}},
		{"/v1/http/request", map[string]any{"provider": "fork-app", "method": "GET", "url": "https://api.github.com/repos/my-user/my-repo/pulls/123"}},
	}
	for _, call := range calls {
		status, body := f.postJSONWithToken("frontend-egress-token", call.path, call.payload)
		if status == http.StatusOK || body["ok"] == true {
			t.Fatalf("egress identity must be denied on %s: status=%d body=%v", call.path, status, body)
		}
	}
}

// TestAgentRoleReceivesRoutingConfigOnly pins /v1/injection/routing: agents
// may discover hosts and the placeholder constant, and the response never
// contains secret material.
func TestAgentRoleReceivesRoutingConfigOnly(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(mediatedIdentities())

	status, body := f.postJSONWithToken("frontend-token", "/v1/injection/routing", map[string]any{"capability": "codex-main"})
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("agent identity denied routing config: status=%d body=%v", status, body)
	}
	if body["placeholder"] != nvtPlaceholder {
		t.Fatalf("expected documented placeholder constant, got %v", body["placeholder"])
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	// The routing response must never carry credential material. The fixture's
	// canonical codex auth file uses a JWT access token; assert no fragment of
	// it appears.
	if strings.Contains(string(raw), "eyJ") {
		t.Fatalf("routing response appears to contain token material: %s", raw)
	}
}

// TestRoutingDeniesUngrantedCapability pins routing authorization: an agent
// identity without a header-inject grant for the capability is denied,
// including for unknown capabilities.
func TestRoutingDeniesUngrantedCapability(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(mediatedIdentities())

	for _, capability := range []string{"codex-main", "no-such-capability"} {
		status, body := f.postJSONWithToken("backend-token", "/v1/injection/routing", map[string]any{"capability": capability})
		if status == http.StatusOK || body["ok"] == true {
			t.Fatalf("ungranted capability %q must deny routing: status=%d body=%v", capability, status, body)
		}
	}
}

// TestRoutingDeniesWrongPairedEgress pins routing scoping for egress callers:
// an egress identity is authorized against its paired agent's grants only.
func TestRoutingDeniesWrongPairedEgress(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(mediatedIdentities())

	status, body := f.postJSONWithToken("backend-egress-token", "/v1/injection/routing", map[string]any{"capability": "codex-main"})
	if status == http.StatusOK || body["ok"] == true {
		t.Fatalf("egress identity paired to an ungranted agent must deny routing: status=%d body=%v", status, body)
	}
}

// TestRoutingDeniesFileBundleGrant pins the materialization rule for routing:
// a file-bundle grant is a direct-mode grant with no sidecar to route to, so
// routing denies rather than acting as a cross-mode probe.
func TestRoutingDeniesFileBundleGrant(t *testing.T) {
	f := newBrokerFixture(t)
	identities := mediatedIdentities()
	identities["frontend"] = roleIdentity{
		Token: "frontend-token",
		Role:  "agent",
		Grants: []roleGrant{
			{Provider: "codex-main", Materialization: "file-bundle"},
		},
	}
	f.writeRoleIdentities(identities)

	status, body := f.postJSONWithToken("frontend-token", "/v1/injection/routing", map[string]any{"capability": "codex-main"})
	if status == http.StatusOK || body["ok"] == true {
		t.Fatalf("file-bundle grant must deny routing: status=%d body=%v", status, body)
	}
}

// TestHeaderInjectGrantExcludesFileBundle pins materialization mutual
// exclusion: a header-inject grant makes the compatibility file endpoint deny
// for that provider and agent. No hybrid mode exists.
func TestHeaderInjectGrantExcludesFileBundle(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(mediatedIdentities())

	status, body := f.postJSONWithToken("frontend-token", "/v1/files", map[string]any{"provider": "codex-main"})
	if status == http.StatusOK || body["ok"] == true {
		t.Fatalf("file bundle must be denied for header-inject grant: status=%d body=%v", status, body)
	}
}

// TestFileBundleGrantExcludesInjection pins the reverse direction: a
// file-bundle grant (the default) denies injection for the paired egress
// identity.
func TestFileBundleGrantExcludesInjection(t *testing.T) {
	f := newBrokerFixture(t)
	identities := mediatedIdentities()
	identities["frontend"] = roleIdentity{
		Token: "frontend-token",
		Role:  "agent",
		Grants: []roleGrant{
			{Provider: "codex-main", Materialization: "file-bundle"},
		},
	}
	f.writeRoleIdentities(identities)

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", injectionRequest())
	if status == http.StatusOK || body["ok"] == true {
		t.Fatalf("injection must be denied for file-bundle grant: status=%d body=%v", status, body)
	}
}

// TestEgressIdentityWithGrantsIsConfigError pins config validation: grants on
// an egress identity are a validation error, not an ignored field — the
// degeneration into "two tokens with the same grants" must be unrepresentable.
func TestEgressIdentityWithGrantsIsConfigError(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(map[string]roleIdentity{
		"frontend": {
			Token: "frontend-token",
			Role:  "agent",
			Grants: []roleGrant{
				{Provider: "codex-main", Materialization: "header-inject"},
			},
		},
		"frontend-egress": {
			Token:       "frontend-egress-token",
			Role:        "egress",
			PairedAgent: "frontend",
			Grants: []roleGrant{
				{Provider: "codex-main", Materialization: "header-inject"},
			},
		},
	})

	// The live-reloaded config must reject the invalid identity: its token
	// must not authenticate.
	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", injectionRequest())
	if status == http.StatusOK || body["ok"] == true {
		t.Fatalf("egress identity carrying grants must be rejected: status=%d body=%v", status, body)
	}
}

// TestDeniedInjectionAuditIncludesContext pins the audit guarantee on denial
// paths: a denied injection request is audited with the capability, host,
// method, path, and operation the caller named — denials are exactly where
// audit context matters most.
func TestDeniedInjectionAuditIncludesContext(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(mediatedIdentities())

	payload := injectionRequest()
	payload["host"] = "evil.example.com"
	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", payload)
	if status == http.StatusOK || body["ok"] == true {
		t.Fatalf("disallowed host must deny: status=%d body=%v", status, body)
	}

	audit, err := os.ReadFile(f.audit)
	if err != nil {
		t.Fatal(err)
	}
	var entry map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(string(audit)), "\n") {
		var candidate map[string]any
		if err := json.Unmarshal([]byte(line), &candidate); err != nil {
			t.Fatal(err)
		}
		if candidate["reason"] == "host-not-allowed" {
			entry = candidate
			break
		}
	}
	if entry == nil {
		t.Fatalf("no host-not-allowed audit entry found: %s", audit)
	}
	expectations := map[string]any{
		"provider":  "codex-main",
		"operation": "injection.headers",
		"host":      "evil.example.com",
		"method":    "POST",
		"path":      "/backend-api/responses",
		"allowed":   false,
	}
	for key, want := range expectations {
		if entry[key] != want {
			t.Fatalf("audit entry %s = %v, want %v (entry: %v)", key, entry[key], want, entry)
		}
	}
}

// TestInjectionComputesClaimDerivedHeaders pins that a codex-oauth provider
// configured with injection-claim-headers computes those headers from the
// real access-token claims (e.g. the ChatGPT account-id header), returns them
// in the injection response, and lists them in strip_request_headers so the
// agent's placeholder versions are removed. Load-bearing for plan-auth, where
// the backend requires a claim-derived header alongside the bearer.
func TestInjectionComputesClaimDerivedHeaders(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(mediatedIdentities())

	// Reconfigure codex-main with a claim-derived header whose claim key
	// itself contains dots (the OpenAI account claim key is a URL).
	f.codexClaimHeaders = "" +
		"      injection-claim-headers:\n" +
		"        - header: chatgpt-account-id\n" +
		"          claim-path:\n" +
		"            - https://api.openai.com/auth\n" +
		"            - chatgpt_account_id\n"
	token := testJWTWithClaims(time.Now().Add(time.Hour), map[string]any{
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "acct-real-123"},
	})
	f.writeCodexAuth(token, "real-refresh-1")
	f.config = f.writeConfig([]string{"my-user/my-repo", "my-user/other-repo"}, "", 0, 0)
	f.stop()
	f.start()

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", injectionRequest())
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("injection denied: status=%d body=%v", status, body)
	}
	headers, ok := body["headers"].(map[string]any)
	if !ok {
		t.Fatalf("expected headers, got %v", body)
	}
	if headers["chatgpt-account-id"] != "acct-real-123" {
		t.Fatalf("claim-derived header = %v, want acct-real-123", headers["chatgpt-account-id"])
	}
	if _, present := headers["authorization"]; !present {
		t.Fatal("authorization header missing alongside claim header")
	}
	strip, ok := body["strip_request_headers"].([]any)
	if !ok {
		t.Fatalf("expected strip_request_headers, got %v", body["strip_request_headers"])
	}
	stripped := map[string]bool{}
	for _, name := range strip {
		if text, ok := name.(string); ok {
			stripped[text] = true
		}
	}
	if !stripped["chatgpt-account-id"] || !stripped["authorization"] {
		t.Fatalf("both injected headers must be stripped from the request, got %v", strip)
	}
}

// TestInjectionServesEveryProviderTypeWithInjectionHosts exercises one
// injection fetch against every provider *type* that declares
// injection-hosts. Providers are called with a shared positional signature
// (host, method, path, agent_id, audit, request_id, grant); a provider
// missing a parameter fails only at call time, invisible to type-specific
// tests — static_token shipped broken exactly this way when the grant
// parameter was added.
func TestInjectionServesEveryProviderTypeWithInjectionHosts(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(map[string]roleIdentity{
		"frontend": {
			Token: "frontend-token",
			Role:  "agent",
			Grants: []roleGrant{
				{Provider: "codex-main", Materialization: "header-inject"},
				{Provider: "git-app", Materialization: "header-inject", Repositories: []string{"my-user/my-repo"}},
				{Provider: "pat-provider", Materialization: "header-inject", Repositories: []string{"my-user/my-repo"}},
			},
		},
		"frontend-egress": {
			Token:       "frontend-egress-token",
			Role:        "egress",
			PairedAgent: "frontend",
		},
	})

	cases := []struct {
		capability string
		host       string
		method     string
		path       string
		wantPrefix string
	}{
		// codex-oauth
		{"codex-main", "chatgpt.com", "POST", "/backend-api/responses", "Bearer "},
		// github-app
		{"git-app", "github.com", "GET", "/my-user/my-repo.git/info/refs", "Basic "},
		// token (static bearer)
		{"pat-provider", "api.example.test", "GET", "/v1/anything", "Bearer pat-secret"},
	}
	for _, tt := range cases {
		payload := map[string]any{
			"capability": tt.capability,
			"host":       tt.host,
			"method":     tt.method,
			"path":       tt.path,
		}
		status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", payload)
		if status != http.StatusOK || body["ok"] != true {
			t.Fatalf("injection for provider type %s denied: status=%d body=%v", tt.capability, status, body)
		}
		headers, _ := body["headers"].(map[string]any)
		value, _ := headers["authorization"].(string)
		if !strings.HasPrefix(value, tt.wantPrefix) {
			t.Fatalf("provider %s authorization = %q, want prefix %q", tt.capability, value, tt.wantPrefix)
		}
		strip, _ := body["strip_request_headers"].([]any)
		if len(strip) == 0 {
			t.Fatalf("provider %s returned no strip_request_headers: %v", tt.capability, body)
		}
	}
}

// TestInjectionAuditOmitsSecretValues pins the audit rule: injection requests
// are audited with metadata only; header values never appear in the audit
// log on allow or deny paths.
func TestInjectionAuditOmitsSecretValues(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(mediatedIdentities())

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", injectionRequest())
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("injection denied: status=%d body=%v", status, body)
	}
	headers, ok := body["headers"].(map[string]any)
	if !ok {
		t.Fatalf("expected headers in response, got %v", body)
	}

	audit, err := os.ReadFile(f.audit)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(audit, []byte("injection")) {
		t.Fatalf("expected an injection audit entry, audit log: %s", audit)
	}
	for name, value := range headers {
		text, ok := value.(string)
		if !ok || text == "" {
			continue
		}
		if bytes.Contains(audit, []byte(text)) {
			t.Fatalf("audit log contains injected header value for %q", name)
		}
	}
}

// TestAnthropicProviderAgnosticismProof pins the provider-agnosticism proof
// (docs/phase5-6b-observability-pr-plan.md item 5): a generalized static_token
// provider injects Anthropic's x-api-key (no Bearer scheme) plus a static
// anthropic-version header, both stripped from the request — with zero egressd
// changes. The whole point of the proof is that adding Anthropic is broker
// config only.
func TestAnthropicProviderAgnosticismProof(t *testing.T) {
	f := newBrokerFixture(t)
	identities := mediatedIdentities()
	frontend := identities["frontend"]
	frontend.Grants = []roleGrant{{Provider: "anthropic-main", Materialization: "header-inject"}}
	identities["frontend"] = frontend
	f.writeRoleIdentities(identities)

	payload := map[string]any{
		"capability": "anthropic-main",
		"host":       "api.anthropic.com",
		"method":     "POST",
		"path":       "/v1/messages",
	}
	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", payload)
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("anthropic injection must succeed: status=%d body=%v", status, body)
	}
	headers, ok := body["headers"].(map[string]any)
	if !ok {
		t.Fatalf("headers missing: %v", body)
	}
	if headers["x-api-key"] != "anthropic-secret-key" {
		t.Fatalf("expected x-api-key with the raw token, got %v", headers["x-api-key"])
	}
	if headers["anthropic-version"] != "2023-06-01" {
		t.Fatalf("expected anthropic-version extra header, got %v", headers["anthropic-version"])
	}
	// Key-header providers must not carry a Bearer authorization header.
	if _, present := headers["authorization"]; present {
		t.Fatalf("x-api-key provider must not inject authorization: %v", headers)
	}
	strip := map[string]bool{}
	for _, name := range body["strip_request_headers"].([]any) {
		strip[name.(string)] = true
	}
	if !strip["x-api-key"] || !strip["anthropic-version"] {
		t.Fatalf("every injected header must be stripped, got %v", body["strip_request_headers"])
	}
}
