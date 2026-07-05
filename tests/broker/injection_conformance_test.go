package broker_test

// Phase 0 skeletons for the mediated credential egress injection contract
// (protocol/injection.md, docs/mediated-egress-plan.md).
//
// Every test here is skipped pending its implementation phase. The bodies are
// written against the intended black-box behavior so the contract is
// reviewable as code and unskipping is the only change needed when the
// implementation lands (plan Phase 1 for the broker side).

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
)

const injectionPending = "pending Phase 1 (docs/mediated-egress-plan.md): /v1/injection endpoints and identity roles not implemented"

// nvtPlaceholder is the documented zero-entropy placeholder constant from
// protocol/injection.md.
const nvtPlaceholder = "NVT-PLACEHOLDER-NOT-A-KEY"

type roleGrant struct {
	Provider        string
	Repositories    []string
	Materialization string
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
	t.Skip(injectionPending)
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
	t.Skip(injectionPending)
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
	t.Skip(injectionPending)
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
	t.Skip(injectionPending)
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

// TestHeaderInjectGrantExcludesFileBundle pins materialization mutual
// exclusion: a header-inject grant makes the compatibility file endpoint deny
// for that provider and agent. No hybrid mode exists.
func TestHeaderInjectGrantExcludesFileBundle(t *testing.T) {
	t.Skip(injectionPending)
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
	t.Skip(injectionPending)
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
	t.Skip(injectionPending)
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

// TestInjectionAuditOmitsSecretValues pins the audit rule: injection requests
// are audited with metadata only; header values never appear in the audit
// log on allow or deny paths.
func TestInjectionAuditOmitsSecretValues(t *testing.T) {
	t.Skip(injectionPending)
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
