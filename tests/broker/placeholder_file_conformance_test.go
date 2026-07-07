package broker_test

// Conformance for the placeholder-file materialization mode
// (docs/phase6.1-placeholder-file-materialization-pr-plan.md, protocol/broker.md):
// the agent fetches a syntactically valid auth file containing only inert
// placeholders; the real secret values stay broker-side and never appear.

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// placeholderIdentities: an agent holding a placeholder-file grant for
// fixture-auth, its paired egress, plus the standard second agent.
func placeholderIdentities() map[string]roleIdentity {
	identities := mediatedIdentities()
	frontend := identities["frontend"]
	frontend.Grants = []roleGrant{
		{Provider: "fixture-auth", Materialization: "placeholder-file", Repositories: []string{"my-user/my-repo"}},
	}
	identities["frontend"] = frontend
	return identities
}

// TestPlaceholderFileMaterializesWithoutRealSecrets is the load-bearing test:
// the vended file contains placeholders only, and none of the real broker-side
// secret strings appear anywhere in the response.
func TestPlaceholderFileMaterializesWithoutRealSecrets(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(placeholderIdentities())

	status, body := f.postJSONWithToken("frontend-token", "/v1/placeholder-files",
		map[string]any{"provider": "fixture-auth"})
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("placeholder-files must succeed for a granted agent: status=%d body=%v", status, body)
	}

	rawResponse, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"real-placeholder-access-token-secret", "real-placeholder-id-token-secret"} {
		if strings.Contains(string(rawResponse), needle) {
			t.Fatalf("real secret %q leaked into the placeholder response: %s", needle, rawResponse)
		}
	}

	files, ok := body["files"].([]any)
	if !ok || len(files) != 1 {
		t.Fatalf("expected one file, got %v", body["files"])
	}
	file := files[0].(map[string]any)
	if file["path"] != ".fixture/auth.json" || file["mode"] != "0600" {
		t.Fatalf("unexpected file path/mode: %v", file)
	}
	var content map[string]any
	if err := json.Unmarshal([]byte(file["content"].(string)), &content); err != nil {
		t.Fatalf("placeholder file content is not valid JSON: %v", err)
	}
	if content["access_token"] != nvtPlaceholder {
		t.Fatalf("access_token must be the zero-entropy placeholder, got %v", content["access_token"])
	}
	if content["account_id"] != "acct-fixture-123" {
		t.Fatalf("non-secret literal must be emitted verbatim, got %v", content["account_id"])
	}

	// Host bindings are returned for 6.2's route/injection map.
	hosts, ok := body["hosts"].([]any)
	if !ok || len(hosts) != 2 || hosts[0] != "api.fixture.test" {
		t.Fatalf("unexpected host bindings: %v", body["hosts"])
	}
}

// TestPlaceholderFileJWTShape pins the jwt placeholder shape: a valid JWT with
// real non-secret claims and a far-future exp, and a placeholder signature.
func TestPlaceholderFileJWTShape(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(placeholderIdentities())

	_, body := f.postJSONWithToken("frontend-token", "/v1/placeholder-files",
		map[string]any{"provider": "fixture-auth"})
	file := body["files"].([]any)[0].(map[string]any)
	var content map[string]any
	if err := json.Unmarshal([]byte(file["content"].(string)), &content); err != nil {
		t.Fatal(err)
	}
	idToken, ok := content["id_token"].(string)
	if !ok {
		t.Fatalf("id_token missing: %v", content)
	}
	segments := strings.Split(idToken, ".")
	if len(segments) != 3 {
		t.Fatalf("id_token is not a three-segment JWT: %q", idToken)
	}
	if segments[2] != "nvt-placeholder-signature" {
		t.Fatalf("id_token signature must be the placeholder, got %q", segments[2])
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		t.Fatalf("id_token payload not base64url: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		t.Fatalf("id_token payload not JSON: %v", err)
	}
	if claims["sub"] != "acct-fixture-123" || claims["plan"] != "pro" {
		t.Fatalf("id_token must carry the non-secret identity claims, got %v", claims)
	}
	exp, ok := claims["exp"].(float64)
	if !ok || exp < 2000000000 { // ~2033; well beyond any session
		t.Fatalf("id_token exp must be far-future, got %v", claims["exp"])
	}
}

// TestPlaceholderFileRequiresGrant pins scoping: an agent without the grant is
// denied, and the placeholder-file grant is denied on secret-bearing endpoints.
func TestPlaceholderFileRequiresGrant(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(placeholderIdentities())

	// backend holds no grant for fixture-auth.
	status, body := f.postJSONWithToken("backend-token", "/v1/placeholder-files",
		map[string]any{"provider": "fixture-auth"})
	if status == http.StatusOK || body["ok"] == true {
		t.Fatalf("ungranted agent must be denied: status=%d body=%v", status, body)
	}
	if body["error"] != "provider-not-granted" {
		t.Fatalf("expected provider-not-granted, got %v", body["error"])
	}

	// The placeholder-file grant must not reach ANY secret-bearing endpoint.
	for _, endpoint := range []string{"/v1/files", "/v1/token", "/v1/headers"} {
		status, body = f.postJSONWithToken("frontend-token", endpoint,
			map[string]any{"provider": "fixture-auth", "target": "my-user/my-repo"})
		if status == http.StatusOK || body["error"] != "materialization-mismatch" {
			t.Fatalf("placeholder-file grant must be rejected on %s: status=%d body=%v", endpoint, status, body)
		}
	}
}

// TestGenericPlaceholderProviderNotInjectionCapable pins review finding 1: the
// generic placeholder provider is materialization-only, so injection is
// refused for it even though placeholder-file is an injection-eligible mode.
func TestGenericPlaceholderProviderNotInjectionCapable(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(placeholderIdentities())

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers",
		map[string]any{"capability": "fixture-auth", "host": "api.fixture.test", "method": "GET", "path": "/x"})
	if status == http.StatusOK || body["error"] != "injection-not-supported" {
		t.Fatalf("generic placeholder provider must not support injection: status=%d body=%v", status, body)
	}
}

// TestPlaceholderFileEgressRoleDenied pins that the agent (not egress) is the
// caller: an egress identity is refused (the file is inert, agent-owned).
func TestPlaceholderFileEgressRoleDenied(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(placeholderIdentities())

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/placeholder-files",
		map[string]any{"provider": "fixture-auth"})
	if status == http.StatusOK || body["error"] != "role-not-allowed" {
		t.Fatalf("egress identity must be refused on placeholder-files: status=%d body=%v", status, body)
	}
}

// TestCodexPlaceholderFile pins the Codex preset: .codex/auth.json with
// placeholder access/refresh tokens, a jwt id_token carrying the real
// (non-secret) chatgpt account id + far-future exp + placeholder signature,
// and host bindings including auth.openai.com — with no real token bytes.
func TestCodexPlaceholderFile(t *testing.T) {
	f := newBrokerFixtureWithCodexConfig(t, ""+
		"      placeholder-file:\n"+
		"        path: .codex/auth.json\n"+
		"        hosts:\n"+
		"          - chatgpt.com\n"+
		"          - api.openai.com\n"+
		"          - auth.openai.com\n"+
		"        id-token-claims:\n"+
		"          - claim: chatgpt_account_id\n"+
		"            claim-path:\n"+
		"              - https://api.openai.com/auth\n"+
		"              - chatgpt_account_id\n")

	realAccessToken := testJWTWithClaims(time.Now().Add(24*time.Hour), map[string]any{
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "acct-real-123"},
	})
	f.writeCodexAuth(realAccessToken, "real-codex-refresh-token-secret")

	identities := mediatedIdentities()
	frontend := identities["frontend"]
	frontend.Grants = []roleGrant{{Provider: "codex-main", Materialization: "placeholder-file"}}
	identities["frontend"] = frontend
	f.writeRoleIdentities(identities)

	status, body := f.postJSONWithToken("frontend-token", "/v1/placeholder-files",
		map[string]any{"provider": "codex-main"})
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("codex placeholder-files must succeed: status=%d body=%v", status, body)
	}

	raw, _ := json.Marshal(body)
	for _, needle := range []string{"real-codex-refresh-token-secret", realAccessToken} {
		if strings.Contains(string(raw), needle) {
			t.Fatalf("real Codex credential leaked into the placeholder response: %s", raw)
		}
	}

	file := body["files"].([]any)[0].(map[string]any)
	if file["path"] != ".codex/auth.json" || file["mode"] != "0600" {
		t.Fatalf("unexpected file path/mode: %v", file)
	}
	var content map[string]any
	if err := json.Unmarshal([]byte(file["content"].(string)), &content); err != nil {
		t.Fatalf("auth.json is not valid JSON: %v", err)
	}
	tokens, ok := content["tokens"].(map[string]any)
	if !ok {
		t.Fatalf("auth.json missing tokens object: %v", content)
	}
	if tokens["access_token"] != nvtPlaceholder || tokens["refresh_token"] != nvtPlaceholder {
		t.Fatalf("access/refresh tokens must be placeholders, got %v", tokens)
	}
	idToken, _ := tokens["id_token"].(string)
	segments := strings.Split(idToken, ".")
	if len(segments) != 3 || segments[2] != "nvt-placeholder-signature" {
		t.Fatalf("id_token must be a jwt with a placeholder signature: %q", idToken)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["chatgpt_account_id"] != "acct-real-123" {
		t.Fatalf("id_token must carry the real non-secret account id, got %v", claims)
	}
	if exp, ok := claims["exp"].(float64); !ok || exp < 2000000000 {
		t.Fatalf("id_token exp must be far-future, got %v", claims["exp"])
	}

	hosts := body["hosts"].([]any)
	found := false
	for _, h := range hosts {
		if h == "auth.openai.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("host bindings must include the refresh endpoint auth.openai.com, got %v", hosts)
	}
}

// TestPlaceholderFileGrantIsInjectionCapable pins the load-bearing 6.1↔6.2
// contract (review finding 1): a single placeholder-file grant both
// materializes the placeholder file (agent side) and authorizes edge injection
// (egress side) — so 6.2's egressd can call /v1/injection/headers for it. No
// second header-inject grant for the same provider is needed. Secret-bearing
// endpoints stay denied.
func TestPlaceholderFileGrantIsInjectionCapable(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeCodexAuth(testJWT(time.Now().Add(time.Hour)), "codex-refresh-token")

	identities := mediatedIdentities()
	frontend := identities["frontend"]
	frontend.Grants = []roleGrant{{Provider: "codex-main", Materialization: "placeholder-file"}}
	identities["frontend"] = frontend
	f.writeRoleIdentities(identities)

	// The paired egress identity injects for the placeholder-file grant.
	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers",
		map[string]any{"capability": "codex-main", "host": "chatgpt.com", "method": "GET", "path": "/v1/responses"})
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("placeholder-file grant must be injection-capable: status=%d body=%v", status, body)
	}

	// But the agent still cannot pull the real credential from any
	// secret-bearing endpoint.
	status, body = f.postJSONWithToken("frontend-token", "/v1/files",
		map[string]any{"provider": "codex-main"})
	if status == http.StatusOK || body["error"] != "materialization-mismatch" {
		t.Fatalf("placeholder-file grant must stay denied on /v1/files: status=%d body=%v", status, body)
	}
}

// TestCodexPlaceholderClaimGuard pins review finding 4: a configured
// id-token-claim whose real value is token-shaped is refused rather than
// copied into the placeholder file.
func TestCodexPlaceholderClaimGuard(t *testing.T) {
	f := newBrokerFixtureWithCodexConfig(t, ""+
		"      placeholder-file:\n"+
		"        path: .codex/auth.json\n"+
		"        hosts:\n"+
		"          - chatgpt.com\n"+
		"        id-token-claims:\n"+
		"          - claim: leaked\n"+
		"            claim-path: secret_blob\n")

	access := testJWTWithClaims(time.Now().Add(time.Hour), map[string]any{"secret_blob": strings.Repeat("x", 200)})
	f.writeCodexAuth(access, "codex-refresh")

	identities := mediatedIdentities()
	frontend := identities["frontend"]
	frontend.Grants = []roleGrant{{Provider: "codex-main", Materialization: "placeholder-file"}}
	identities["frontend"] = frontend
	f.writeRoleIdentities(identities)

	status, body := f.postJSONWithToken("frontend-token", "/v1/placeholder-files",
		map[string]any{"provider": "codex-main"})
	if status == http.StatusOK || body["error"] != "placeholder-claim-unsafe" {
		t.Fatalf("token-shaped id-token-claim must be refused: status=%d body=%v", status, body)
	}
}
