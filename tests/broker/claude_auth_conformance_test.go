package broker_test

// Conformance for the Claude Code OAuth provider (claude-oauth), the Claude
// analogue of the Codex broker auth direction (protocol/broker.md "Claude OAuth
// Provider Rules", protocol/injection.md). It proves the load-bearing security
// properties: mediated placeholder files never carry real Claude credentials,
// direct file bundles are gated to file-bundle mode, and edge injection is
// scoped to the paired egress identity.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// realClaudeSecrets are the exact broker-side token strings seeded by the
// fixture. None may appear in any mediated response or audit line.
var realClaudeSecrets = []string{
	"real-claude-access-token-secret",
	"real-claude-refresh-token-secret",
}

// claudePlaceholderIdentities: an agent holding a placeholder-file grant for
// claude-main, its paired egress, plus the standard second agent/egress pair.
func claudePlaceholderIdentities() map[string]roleIdentity {
	identities := mediatedIdentities()
	frontend := identities["frontend"]
	frontend.Grants = []roleGrant{
		{Provider: "claude-main", Materialization: "placeholder-file"},
	}
	identities["frontend"] = frontend
	return identities
}

// TestClaudePlaceholderFileMaterializesWithoutRealSecrets is the load-bearing
// test: the vended .claude/.credentials.json carries only inert placeholders,
// and none of the real broker-side Claude token strings appear anywhere.
func TestClaudePlaceholderFileMaterializesWithoutRealSecrets(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(claudePlaceholderIdentities())

	status, body := f.postJSONWithToken("frontend-token", "/v1/placeholder-files",
		map[string]any{"provider": "claude-main"})
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("claude placeholder-files must succeed for a granted agent: status=%d body=%v", status, body)
	}

	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range realClaudeSecrets {
		if strings.Contains(string(raw), needle) {
			t.Fatalf("real Claude secret %q leaked into the placeholder response: %s", needle, raw)
		}
	}

	files, ok := body["files"].([]any)
	if !ok || len(files) != 1 {
		t.Fatalf("expected one placeholder file, got %v", body["files"])
	}
	file := files[0].(map[string]any)
	if file["path"] != ".claude/.credentials.json" || file["mode"] != "0600" {
		t.Fatalf("unexpected file path/mode: %v", file)
	}
	var content map[string]any
	if err := json.Unmarshal([]byte(file["content"].(string)), &content); err != nil {
		t.Fatalf("placeholder file content is not valid JSON: %v", err)
	}
	oauth, ok := content["claudeAiOauth"].(map[string]any)
	if !ok {
		t.Fatalf("placeholder file missing claudeAiOauth object: %v", content)
	}
	if oauth["accessToken"] != nvtPlaceholder || oauth["refreshToken"] != nvtPlaceholder {
		t.Fatalf("accessToken/refreshToken must be the zero-entropy placeholder, got %v", oauth)
	}
	// Non-secret subscription metadata is copied through verbatim.
	if oauth["subscriptionType"] != "max" || oauth["rateLimitTier"] != "default_claude_max_20x" {
		t.Fatalf("non-secret subscription metadata must be copied through, got %v", oauth)
	}
	// expiresAt is a far-future millisecond epoch so Claude Code does not try a
	// local refresh before its first request.
	exp, ok := oauth["expiresAt"].(float64)
	if !ok || exp < 2_000_000_000_000 { // ~2033 in ms
		t.Fatalf("expiresAt must be a far-future millisecond epoch, got %v", oauth["expiresAt"])
	}

	hosts, ok := body["hosts"].([]any)
	if !ok || len(hosts) != 1 || hosts[0] != "api.anthropic.com" {
		t.Fatalf("unexpected host bindings: %v", body["hosts"])
	}
}

// TestClaudeDirectFileBundleReturnsRealCredential pins the direct/file-bundle
// dev/fallback path: a plain (file-bundle default) grant vends the real
// credentials file, including the access token, into the agent.
func TestClaudeDirectFileBundleReturnsRealCredential(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeAgents(map[string]agentGrant{
		"frontend": {
			Token:  f.token,
			Grants: map[string][]string{"claude-main": {}},
		},
	})
	status, body := f.postJSONWithToken(f.token, "/v1/files", map[string]any{"provider": "claude-main"})
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("file-bundle mode must vend the credentials file: status=%d body=%v", status, body)
	}
	files := body["files"].([]any)
	if len(files) != 1 {
		t.Fatalf("expected one bundle file, got %v", files)
	}
	authFile := files[0].(map[string]any)
	if authFile["name"] != ".credentials.json" || authFile["mode"] != "0600" {
		t.Fatalf("unexpected bundle file metadata: %v", authFile)
	}
	var creds map[string]any
	if err := json.Unmarshal([]byte(authFile["content"].(string)), &creds); err != nil {
		t.Fatal(err)
	}
	oauth := creds["claudeAiOauth"].(map[string]any)
	if oauth["accessToken"] != "real-claude-access-token-secret" {
		t.Fatalf("direct file bundle must carry the real access token (possession mode), got %v", oauth["accessToken"])
	}
}

// TestClaudePlaceholderGrantDeniesSecretEndpoints pins that a placeholder-file
// (mediated) grant is denied on every secret-bearing endpoint — the real
// credential is unreachable through /v1/files, /v1/token, and /v1/headers — and
// no denial leaks a real Claude secret.
func TestClaudePlaceholderGrantDeniesSecretEndpoints(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(claudePlaceholderIdentities())
	for _, endpoint := range []string{"/v1/files", "/v1/token", "/v1/headers"} {
		status, body := f.postJSONWithToken("frontend-token", endpoint,
			map[string]any{"provider": "claude-main", "target": "my-user/my-repo"})
		if status == http.StatusOK || body["error"] != "materialization-mismatch" {
			t.Fatalf("placeholder-file grant must be rejected on %s: status=%d body=%v", endpoint, status, body)
		}
		raw, _ := json.Marshal(body)
		for _, needle := range realClaudeSecrets {
			if strings.Contains(string(raw), needle) {
				t.Fatalf("denied %s must not leak a real Claude secret: %s", endpoint, raw)
			}
		}
	}
}

// TestClaudeInjectionIsEgressIdentityScoped pins the non-possession property:
// only the paired egress identity obtains the real Bearer token; the agent
// holding the grant and an egress paired to a different agent are refused.
func TestClaudeInjectionIsEgressIdentityScoped(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(claudePlaceholderIdentities())

	req := map[string]any{
		"capability": "claude-main",
		"host":       "api.anthropic.com",
		"method":     "POST",
		"path":       "/v1/messages",
	}

	// Paired egress: real Bearer token plus configured extra header, both
	// stripped from the incoming request.
	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", req)
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("paired egress must obtain injection headers: status=%d body=%v", status, body)
	}
	headers := body["headers"].(map[string]any)
	if headers["authorization"] != "Bearer real-claude-access-token-secret" {
		t.Fatalf("expected the real Bearer access token, got %v", headers["authorization"])
	}
	if headers["anthropic-beta"] != "oauth-2025-04-20" {
		t.Fatalf("expected the configured anthropic-beta extra header, got %v", headers["anthropic-beta"])
	}
	strip := map[string]bool{}
	for _, name := range body["strip_request_headers"].([]any) {
		strip[name.(string)] = true
	}
	if !strip["authorization"] || !strip["anthropic-beta"] {
		t.Fatalf("every injected header must be stripped, got %v", body["strip_request_headers"])
	}

	// The agent holding the grant may not obtain injectable headers.
	status, body = f.postJSONWithToken("frontend-token", "/v1/injection/headers", req)
	if status == http.StatusOK || body["ok"] == true {
		t.Fatalf("agent identity must not obtain injection headers: status=%d body=%v", status, body)
	}

	// An egress identity paired to a different agent is refused.
	status, body = f.postJSONWithToken("backend-egress-token", "/v1/injection/headers", req)
	if status == http.StatusOK || body["ok"] == true {
		t.Fatalf("egress paired to another agent must be denied: status=%d body=%v", status, body)
	}
}

// TestClaudePlaceholderFileGrantIsInjectionCapable pins the 6.1<->6.2 contract:
// a single placeholder-file grant both materializes the placeholder file (agent
// side) and authorizes edge injection (egress side); the agent still cannot
// reach the real credential through any secret-bearing endpoint.
func TestClaudePlaceholderFileGrantIsInjectionCapable(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(claudePlaceholderIdentities())

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers",
		map[string]any{"capability": "claude-main", "host": "api.anthropic.com", "method": "POST", "path": "/v1/messages"})
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("placeholder-file grant must be injection-capable: status=%d body=%v", status, body)
	}

	status, body = f.postJSONWithToken("frontend-token", "/v1/files", map[string]any{"provider": "claude-main"})
	if status == http.StatusOK || body["error"] != "materialization-mismatch" {
		t.Fatalf("placeholder-file grant must stay denied on /v1/files: status=%d body=%v", status, body)
	}
}

// TestClaudeInjectionDeniedHostDoesNotLeakSecret pins the denial-path guarantee:
// a disallowed host denies with host-not-allowed, and neither the response nor
// the audit log carries any real Claude credential material.
func TestClaudeInjectionDeniedHostDoesNotLeakSecret(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(claudePlaceholderIdentities())

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers",
		map[string]any{"capability": "claude-main", "host": "evil.example.com", "method": "POST", "path": "/v1/messages"})
	if status == http.StatusOK || body["error"] != "host-not-allowed" {
		t.Fatalf("disallowed host must deny with host-not-allowed: status=%d body=%v", status, body)
	}
	raw, _ := json.Marshal(body)
	for _, needle := range realClaudeSecrets {
		if strings.Contains(string(raw), needle) {
			t.Fatalf("denied injection response leaked a real Claude secret: %s", raw)
		}
	}

	events := readAudit(t, f.audit)
	for _, event := range events {
		line, _ := json.Marshal(event)
		for _, needle := range realClaudeSecrets {
			if strings.Contains(string(line), needle) {
				t.Fatalf("audit log leaked a real Claude secret: %s", line)
			}
		}
	}
	// The denial itself is audited with the request context.
	var denied map[string]any
	for _, event := range events {
		if event["reason"] == "host-not-allowed" && event["provider"] == "claude-main" {
			denied = event
			break
		}
	}
	if denied == nil {
		t.Fatalf("expected a host-not-allowed audit entry for claude-main, got %v", events)
	}
}

// TestClaudeInjectionAuditOmitsRealToken pins that the allow path audits with
// metadata only: the real access token never appears in the audit log.
func TestClaudeInjectionAuditOmitsRealToken(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(claudePlaceholderIdentities())

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers",
		map[string]any{"capability": "claude-main", "host": "api.anthropic.com", "method": "POST", "path": "/v1/messages"})
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("injection denied: status=%d body=%v", status, body)
	}
	events := readAudit(t, f.audit)
	for _, event := range events {
		line, _ := json.Marshal(event)
		for _, needle := range realClaudeSecrets {
			if strings.Contains(string(line), needle) {
				t.Fatalf("audit log leaked a real Claude secret on the allow path: %s", line)
			}
		}
	}
}

func TestClaudeOAuthRefreshPersistsRotatedTokenForFileBundles(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeAgents(map[string]agentGrant{
		"frontend": {
			Token:  f.token,
			Grants: map[string][]string{"claude-main": {}},
		},
	})
	f.writeClaudeCredentialsExp("real-claude-access-token-secret", "real-claude-refresh-token-secret", time.Now().Add(2*time.Minute))

	status, body := f.postJSONWithToken(f.token, "/v1/files", map[string]any{"provider": "claude-main"})
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("files must refresh and vend Claude credentials: status=%d body=%v", status, body)
	}
	if count := f.oauth.requestCount(); count != 1 {
		t.Fatalf("expected one Claude refresh request, got %d", count)
	}
	request := f.oauth.lastRequest()
	if request["grant_type"] != "refresh_token" || request["client_id"] != "test-claude-client" || request["refresh_token"] != "real-claude-refresh-token-secret" {
		t.Fatalf("unexpected Claude refresh request metadata: %#v", request)
	}

	var canonical map[string]any
	decodeJSONFile(t, f.claudeCreds, &canonical)
	oauth := canonical["claudeAiOauth"].(map[string]any)
	if oauth["refreshToken"] != "real-refresh-2" {
		t.Fatalf("rotated Claude refresh token was not persisted: %#v", oauth)
	}
	if oauth["accessToken"] == "real-claude-access-token-secret" {
		t.Fatalf("expected Claude access token to be refreshed: %#v", oauth)
	}
	if expiresAt, ok := oauth["expiresAt"].(float64); !ok || expiresAt < float64(time.Now().Add(50*time.Minute).UnixMilli()) {
		t.Fatalf("expected refreshed Claude expiresAt to be persisted, got %#v", oauth["expiresAt"])
	}

	files := body["files"].([]any)
	var vended map[string]any
	if err := json.Unmarshal([]byte(files[0].(map[string]any)["content"].(string)), &vended); err != nil {
		t.Fatal(err)
	}
	vendedOauth := vended["claudeAiOauth"].(map[string]any)
	if vendedOauth["refreshToken"] != "real-refresh-2" || vendedOauth["accessToken"] != oauth["accessToken"] {
		t.Fatalf("direct file bundle must contain refreshed credential state, got %#v canonical=%#v", vendedOauth, oauth)
	}

	events := readAudit(t, f.audit)
	if !hasAuditOperation(events, "files.vend") || !hasAuditOperation(events, "files.refresh") {
		t.Fatalf("expected Claude files vend and refresh audit entries, got %#v", events)
	}
}

func TestClaudeOAuthPlaceholderRefreshDoesNotLeakRealTokens(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(claudePlaceholderIdentities())
	f.writeClaudeCredentialsExp("real-claude-access-token-secret", "real-claude-refresh-token-secret", time.Now().Add(2*time.Minute))

	status, body := f.postJSONWithToken("frontend-token", "/v1/placeholder-files", map[string]any{"provider": "claude-main"})
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("placeholder-files must refresh broker-side Claude credentials: status=%d body=%v", status, body)
	}
	if count := f.oauth.requestCount(); count != 1 {
		t.Fatalf("expected one Claude refresh request, got %d", count)
	}
	raw, _ := json.Marshal(body)
	for _, needle := range []string{"real-claude-access-token-secret", "real-claude-refresh-token-secret", "real-refresh-2"} {
		if strings.Contains(string(raw), needle) {
			t.Fatalf("Claude placeholder response leaked token %q: %s", needle, raw)
		}
	}
	files := body["files"].([]any)
	var content map[string]any
	if err := json.Unmarshal([]byte(files[0].(map[string]any)["content"].(string)), &content); err != nil {
		t.Fatal(err)
	}
	oauth := content["claudeAiOauth"].(map[string]any)
	if oauth["accessToken"] != nvtPlaceholder || oauth["refreshToken"] != nvtPlaceholder {
		t.Fatalf("refreshed placeholder file must still contain only placeholders, got %#v", oauth)
	}
}

func TestClaudeOAuthRefreshFailureServesValidButRejectsExpired(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(claudePlaceholderIdentities())
	f.oauth.setFail(true)

	req := map[string]any{"capability": "claude-main", "host": "api.anthropic.com", "method": "POST", "path": "/v1/messages"}
	f.writeClaudeCredentialsExp("real-claude-access-token-secret", "real-claude-refresh-token-secret", time.Now().Add(2*time.Minute))
	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", req)
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("expected current valid Claude token to be served after refresh failure: status=%d body=%v", status, body)
	}
	headers := body["headers"].(map[string]any)
	if headers["authorization"] != "Bearer real-claude-access-token-secret" {
		t.Fatalf("expected current valid Claude token, got %v", headers["authorization"])
	}

	f.writeClaudeCredentialsExp("real-claude-access-token-secret", "real-claude-refresh-token-secret", time.Now().Add(-time.Minute))
	status, body = f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", req)
	if status == http.StatusOK || body["error"] != "token-refresh-failed" {
		t.Fatalf("expected expired Claude token refresh failure, status=%d body=%v", status, body)
	}
}

func TestClaudeOAuthInjectionRefreshesAndReusesToken(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(claudePlaceholderIdentities())
	f.writeClaudeCredentialsExp("real-claude-access-token-secret", "real-claude-refresh-token-secret", time.Now().Add(2*time.Minute))

	req := map[string]any{"capability": "claude-main", "host": "api.anthropic.com", "method": "POST", "path": "/v1/messages"}
	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", req)
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("injection must refresh Claude credentials: status=%d body=%v", status, body)
	}
	if count := f.oauth.requestCount(); count != 1 {
		t.Fatalf("expected one Claude refresh request, got %d", count)
	}
	headers := body["headers"].(map[string]any)
	firstAuth := headers["authorization"].(string)
	if firstAuth == "Bearer real-claude-access-token-secret" || !strings.HasPrefix(firstAuth, "Bearer ") {
		t.Fatalf("expected refreshed Claude Bearer token, got %v", firstAuth)
	}

	status, body = f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", req)
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("second injection must reuse refreshed Claude credentials: status=%d body=%v", status, body)
	}
	if count := f.oauth.requestCount(); count != 1 {
		t.Fatalf("expected refreshed Claude token to be reused, got %d refreshes", count)
	}
	headers = body["headers"].(map[string]any)
	if headers["authorization"] != firstAuth {
		t.Fatalf("expected second injection to reuse refreshed token, first=%v second=%v", firstAuth, headers["authorization"])
	}
}
