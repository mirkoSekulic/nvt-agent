package broker_test

// Conformance for git-over-HTTPS injection through the github-app
// provider (protocol/injection.md): git smart-HTTP path
// shapes, repo scoping, the Basic/Bearer header dialects, and the
// read/write permission mapping — the first method/path-based authorization
// decision in the injection path.

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

// gitIdentities is the standard fixture layout for git injection tests: one
// agent with a header-inject grant on the git-capable github-app provider
// (read-only by default), and its paired egress identity.
func gitIdentities(permissions map[string]string) map[string]roleIdentity {
	return map[string]roleIdentity{
		"frontend": {
			Token: "frontend-token",
			Role:  "agent",
			Grants: []roleGrant{
				{
					Provider:        "git-app",
					Materialization: "header-inject",
					Repositories:    []string{"my-user/my-repo"},
					Permissions:     permissions,
				},
			},
		},
		"frontend-egress": {
			Token:       "frontend-egress-token",
			Role:        "egress",
			PairedAgent: "frontend",
		},
	}
}

func gitInjectionRequest(method, path string) map[string]any {
	return map[string]any{
		"capability": "git-app",
		"host":       "github.com",
		"method":     method,
		"path":       path,
	}
}

func decodeBasicAuth(t *testing.T, body map[string]any) string {
	t.Helper()
	headers, ok := body["headers"].(map[string]any)
	if !ok {
		t.Fatalf("expected headers, got %v", body)
	}
	value, _ := headers["authorization"].(string)
	if !strings.HasPrefix(value, "Basic ") {
		t.Fatalf("expected Basic authorization for git path, got %q", value)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, "Basic "))
	if err != nil {
		t.Fatal(err)
	}
	return string(decoded)
}

func (f *brokerFixture) lastTokenRequest(t *testing.T) map[string]any {
	t.Helper()
	f.fake.mu.Lock()
	defer f.fake.mu.Unlock()
	if len(f.fake.tokenRequests) == 0 {
		t.Fatal("fake GitHub minted no tokens")
	}
	return f.fake.tokenRequests[len(f.fake.tokenRequests)-1]
}

func mintedPermissions(t *testing.T, request map[string]any) map[string]any {
	t.Helper()
	permissions, ok := request["permissions"].(map[string]any)
	if !ok {
		t.Fatalf("token mint request has no permissions: %v", request)
	}
	return permissions
}

// TestGitInjectionFetchMintsScopedBasicAuth pins the fetch path: info/refs
// and git-upload-pack mint a single-repo installation token, delivered as
// Basic x-access-token credentials, scoped to contents: read even though the
// provider ceiling is write.
func TestGitInjectionFetchMintsScopedBasicAuth(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(gitIdentities(nil))

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", gitInjectionRequest("GET", "/my-user/my-repo.git/info/refs"))
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("info/refs injection denied: status=%d body=%v", status, body)
	}
	credentials := decodeBasicAuth(t, body)
	if !strings.HasPrefix(credentials, "x-access-token:token-my-repo-") {
		t.Fatalf("unexpected Basic credentials %q", credentials)
	}
	if expires, _ := body["expires_at"].(string); expires == "" {
		t.Fatalf("expected expires_at, got %v", body)
	}
	strip, _ := body["strip_request_headers"].([]any)
	if len(strip) != 1 || strip[0] != "authorization" {
		t.Fatalf("expected authorization strip, got %v", body["strip_request_headers"])
	}
	minted := mintedPermissions(t, f.lastTokenRequest(t))
	if minted["contents"] != "read" || len(minted) != 1 {
		t.Fatalf("info/refs must mint the narrowed read scope, got %v", minted)
	}

	status, body = f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", gitInjectionRequest("POST", "/my-user/my-repo.git/git-upload-pack"))
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("git-upload-pack injection denied: status=%d body=%v", status, body)
	}
	minted = mintedPermissions(t, f.lastTokenRequest(t))
	if minted["contents"] != "read" {
		t.Fatalf("git-upload-pack must mint contents: read, got %v", minted)
	}
}

// TestGitInjectionPushRequiresWriteGrant pins the write mapping: a
// git-receive-pack request is denied for a read grant (the default), and a
// contents: write grant mints a write-scoped token.
func TestGitInjectionPushRequiresWriteGrant(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(gitIdentities(nil))

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", gitInjectionRequest("POST", "/my-user/my-repo.git/git-receive-pack"))
	if status != http.StatusForbidden || body["error"] != "write-not-allowed" {
		t.Fatalf("push without write grant must deny: status=%d body=%v", status, body)
	}

	f.writeRoleIdentities(gitIdentities(map[string]string{"contents": "write"}))
	status, body = f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", gitInjectionRequest("POST", "/my-user/my-repo.git/git-receive-pack"))
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("push with write grant denied: status=%d body=%v", status, body)
	}
	credentials := decodeBasicAuth(t, body)
	if !strings.HasPrefix(credentials, "x-access-token:") {
		t.Fatalf("unexpected Basic credentials %q", credentials)
	}
	minted := mintedPermissions(t, f.lastTokenRequest(t))
	if minted["contents"] != "write" || len(minted) != 1 {
		t.Fatalf("git-receive-pack must mint contents: write, got %v", minted)
	}
}

// TestGitInjectionPushPreservesGrantedWorkflowPermission pins GitHub's
// workflow-file rule: smart-HTTP push tokens retain explicitly granted
// non-content permissions while upload-pack remains read-only.
func TestGitInjectionPushPreservesGrantedWorkflowPermission(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(gitIdentities(map[string]string{
		"contents":  "write",
		"workflows": "write",
	}))

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", gitInjectionRequest("GET", "/my-user/my-repo.git/info/refs"))
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("push advertisement denied: status=%d body=%v", status, body)
	}
	minted := mintedPermissions(t, f.lastTokenRequest(t))
	if minted["contents"] != "write" || minted["workflows"] != "write" || len(minted) != 2 {
		t.Fatalf("push advertisement must retain the granted workflow permission, got %v", minted)
	}

	status, body = f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", gitInjectionRequest("POST", "/my-user/my-repo.git/git-receive-pack"))
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("push denied: status=%d body=%v", status, body)
	}
	minted = mintedPermissions(t, f.lastTokenRequest(t))
	if minted["contents"] != "write" || minted["workflows"] != "write" || len(minted) != 2 {
		t.Fatalf("push must retain the granted workflow permission, got %v", minted)
	}

	status, body = f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", gitInjectionRequest("POST", "/my-user/my-repo.git/git-upload-pack"))
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("fetch denied: status=%d body=%v", status, body)
	}
	minted = mintedPermissions(t, f.lastTokenRequest(t))
	if minted["contents"] != "read" || len(minted) != 1 {
		t.Fatalf("fetch must remain contents: read only, got %v", minted)
	}
}

func TestGitInjectionRejectsExtraPermissionAboveProviderCeiling(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(map[string]roleIdentity{
		"frontend": {
			Token: "frontend-token",
			Role:  "agent",
			Grants: []roleGrant{{
				Provider:        "git-app-ro",
				Materialization: "header-inject",
				Repositories:    []string{"my-user/my-repo"},
				Permissions:     map[string]string{"contents": "read", "workflows": "write"},
			}},
		},
		"frontend-egress": {
			Token:       "frontend-egress-token",
			Role:        "egress",
			PairedAgent: "frontend",
		},
	})

	request := gitInjectionRequest("GET", "/my-user/my-repo.git/info/refs")
	request["capability"] = "git-app-ro"
	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", request)
	if status != http.StatusForbidden || body["error"] != "permission-not-allowed" {
		t.Fatalf("permission above provider ceiling must deny: status=%d body=%v", status, body)
	}
}

// TestGitInjectionProviderCeilingCapsGrantWrite pins the two-layer
// intersection: a grant asking for contents: write cannot push through a
// provider whose own permissions ceiling is read, and fetch through that
// provider mints only the narrowed read scope.
func TestGitInjectionProviderCeilingCapsGrantWrite(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(map[string]roleIdentity{
		"frontend": {
			Token: "frontend-token",
			Role:  "agent",
			Grants: []roleGrant{
				{
					// git-app-ro's provider permissions ceiling is contents: read.
					Provider:        "git-app-ro",
					Materialization: "header-inject",
					Repositories:    []string{"my-user/my-repo"},
					Permissions:     map[string]string{"contents": "write"},
				},
			},
		},
		"frontend-egress": {
			Token:       "frontend-egress-token",
			Role:        "egress",
			PairedAgent: "frontend",
		},
	})

	request := map[string]any{
		"capability": "git-app-ro",
		"host":       "github.com",
		"method":     "POST",
		"path":       "/my-user/my-repo.git/git-receive-pack",
	}
	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", request)
	if status != http.StatusForbidden || body["error"] != "write-not-allowed" {
		t.Fatalf("write grant above provider ceiling must be denied: status=%d body=%v", status, body)
	}

	request["method"] = "GET"
	request["path"] = "/my-user/my-repo.git/info/refs"
	status, body = f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", request)
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("fetch under read ceiling denied: status=%d body=%v", status, body)
	}
	minted := mintedPermissions(t, f.lastTokenRequest(t))
	if minted["contents"] != "read" {
		t.Fatalf("ceiling must narrow the minted scope to read, got %v", minted)
	}
}

// TestGitInjectionRepoScopeDenies pins repo scoping on git paths through
// both layers: a repo outside the grant scope and a repo outside the
// provider allowlist are denied.
func TestGitInjectionRepoScopeDenies(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(gitIdentities(nil))

	for _, path := range []string{
		"/my-user/other-repo.git/info/refs",  // allowed by provider, not by grant
		"/evil-user/evil-repo.git/info/refs", // outside the provider allowlist
	} {
		status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", gitInjectionRequest("GET", path))
		if status == http.StatusOK || body["ok"] == true {
			t.Fatalf("path %s must be denied: status=%d body=%v", path, status, body)
		}
		if body["error"] != "repo-not-allowed" {
			t.Fatalf("path %s expected repo-not-allowed, got %v", path, body)
		}
	}
}

// TestGitInjectionPathAndMethodShapes pins the accepted git smart-HTTP
// shapes: the .git suffix is optional, anything outside the three smart-HTTP
// shapes is path-not-allowed, and each shape is bound to its protocol method.
func TestGitInjectionPathAndMethodShapes(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(gitIdentities(map[string]string{"contents": "write"}))

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", gitInjectionRequest("GET", "/my-user/my-repo/info/refs"))
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("suffix-less repo path denied: status=%d body=%v", status, body)
	}

	denied := []struct {
		method string
		path   string
		reason string
	}{
		{"GET", "/my-user/my-repo.git/HEAD", "path-not-allowed"},
		{"GET", "/my-user/my-repo.git/objects/info/packs", "path-not-allowed"},
		{"GET", "/my-user.git/info/refs", "path-not-allowed"},
		{"POST", "/my-user/my-repo.git/info/refs", "method-not-allowed"},
		{"GET", "/my-user/my-repo.git/git-upload-pack", "method-not-allowed"},
		{"GET", "/my-user/my-repo.git/git-receive-pack", "method-not-allowed"},
		{"GET", "/my-user/..%2fmy-repo.git/info/refs", "path-not-allowed"},
	}
	for _, tt := range denied {
		status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", gitInjectionRequest(tt.method, tt.path))
		if status == http.StatusOK || body["ok"] == true || body["error"] != tt.reason {
			t.Fatalf("%s %s expected %s, got status=%d body=%v", tt.method, tt.path, tt.reason, status, body)
		}
	}
}

// TestGitInjectionAPIPathUsesBearerDialect pins the header dialect split: an
// API path through the same provider gets a Bearer header, not Basic.
func TestGitInjectionAPIPathUsesBearerDialect(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(gitIdentities(nil))

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", gitInjectionRequest("GET", "/repos/my-user/my-repo/pulls/123"))
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("API path injection denied: status=%d body=%v", status, body)
	}
	headers, _ := body["headers"].(map[string]any)
	value, _ := headers["authorization"].(string)
	if !strings.HasPrefix(value, "Bearer token-my-repo-") {
		t.Fatalf("API path must use Bearer dialect, got %q", value)
	}
}

// TestGitInjectionGraphQLUsesSingleRepoGrant pins the only supported GraphQL
// injection shape: GitHub GraphQL has no repo in the URL, so the provider can
// mint a token only when the agent grant is a single concrete repository.
func TestGitInjectionGraphQLUsesSingleRepoGrant(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(gitIdentities(nil))

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", gitInjectionRequest("POST", "/graphql"))
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("GraphQL injection denied: status=%d body=%v", status, body)
	}
	headers, _ := body["headers"].(map[string]any)
	value, _ := headers["authorization"].(string)
	if !strings.HasPrefix(value, "Bearer token-my-repo-") {
		t.Fatalf("GraphQL path must use Bearer dialect, got %q", value)
	}
	minted := f.lastTokenRequest(t)
	repos, _ := minted["repositories"].([]any)
	if len(repos) != 1 || repos[0] != "my-repo" {
		t.Fatalf("GraphQL token must be minted for the granted repo only, got %v", minted)
	}
}

func TestGitInjectionGraphQLRejectsAmbiguousGrants(t *testing.T) {
	tests := []struct {
		name         string
		repositories []string
		method       string
		want         string
	}{
		{
			name:         "multi repo",
			repositories: []string{"my-user/my-repo", "my-user/other-repo"},
			method:       "POST",
			want:         "repo-not-allowed",
		},
		{
			name:         "wildcard repo",
			repositories: []string{"my-user/*"},
			method:       "POST",
			want:         "repo-not-allowed",
		},
		{
			name:         "wrong method",
			repositories: []string{"my-user/my-repo"},
			method:       "GET",
			want:         "method-not-allowed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newBrokerFixture(t)
			identities := gitIdentities(nil)
			frontend := identities["frontend"]
			frontend.Grants[0].Repositories = tt.repositories
			identities["frontend"] = frontend
			f.writeRoleIdentities(identities)

			status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", gitInjectionRequest(tt.method, "/graphql"))
			if status == http.StatusOK || body["ok"] == true || body["error"] != tt.want {
				t.Fatalf("expected %s, got status=%d body=%v", tt.want, status, body)
			}
		})
	}
}

func TestGitInjectionGraphQLRespectsAllowedMethods(t *testing.T) {
	f := newBrokerFixture(t)
	identities := gitIdentities(nil)
	frontend := identities["frontend"]
	frontend.Grants[0].Provider = "git-app-ro"
	identities["frontend"] = frontend
	f.writeRoleIdentities(identities)

	request := gitInjectionRequest("POST", "/graphql")
	request["capability"] = "git-app-ro"
	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", request)
	if status == http.StatusOK || body["ok"] == true || body["error"] != "method-not-allowed" {
		t.Fatalf("GET-only provider must deny GraphQL POST, got status=%d body=%v", status, body)
	}
}

// TestGitInjectionDeniedForAgentIdentity pins non-possession for git tokens:
// the agent identity holding the grant can never obtain the installation
// token, through the injection endpoint or the compatibility endpoints.
func TestGitInjectionDeniedForAgentIdentity(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(gitIdentities(nil))

	status, body := f.postJSONWithToken("frontend-token", "/v1/injection/headers", gitInjectionRequest("GET", "/my-user/my-repo.git/info/refs"))
	if status == http.StatusOK || body["ok"] == true {
		t.Fatalf("agent identity must not obtain git injection headers: status=%d body=%v", status, body)
	}

	status, body = f.postJSONWithToken("frontend-token", "/v1/token", map[string]any{
		"provider": "git-app",
		"target":   "github.com/my-user/my-repo",
	})
	if status == http.StatusOK || body["ok"] == true {
		t.Fatalf("header-inject grant must deny /v1/token to the agent identity: status=%d body=%v", status, body)
	}
}

// TestGitInjectionRoutingAdvertisesGit pins the non-secret routing hint that
// drives runtime git wiring: a git-capable provider reports git: true, the
// codex provider does not.
func TestGitInjectionRoutingAdvertisesGit(t *testing.T) {
	f := newBrokerFixture(t)
	identities := gitIdentities(nil)
	frontend := identities["frontend"]
	frontend.Grants = append(frontend.Grants, roleGrant{Provider: "codex-main", Materialization: "header-inject"})
	frontend.Grants = append(frontend.Grants, roleGrant{
		Provider:        "basic-pat-provider",
		Materialization: "header-inject",
		Repositories:    []string{"dev.azure.com/org/project/_git/repo"},
	})
	identities["frontend"] = frontend
	f.writeRoleIdentities(identities)

	status, body := f.postJSONWithToken("frontend-token", "/v1/injection/routing", map[string]any{"capability": "git-app"})
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("routing denied: status=%d body=%v", status, body)
	}
	if body["git"] != true {
		t.Fatalf("git-capable provider routing must set git: true, got %v", body)
	}
	hosts, _ := body["hosts"].([]any)
	if len(hosts) != 1 || hosts[0] != "github.com" {
		t.Fatalf("unexpected routing hosts %v", body["hosts"])
	}

	status, body = f.postJSONWithToken("frontend-token", "/v1/injection/routing", map[string]any{"capability": "basic-pat-provider"})
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("basic PAT routing denied: status=%d body=%v", status, body)
	}
	if body["git"] != true {
		t.Fatalf("basic PAT provider routing must set git: true, got %v", body)
	}
	hosts, _ = body["hosts"].([]any)
	if len(hosts) != 1 || hosts[0] != "dev.azure.com" {
		t.Fatalf("unexpected basic PAT routing hosts %v", body["hosts"])
	}

	status, body = f.postJSONWithToken("frontend-token", "/v1/injection/routing", map[string]any{"capability": "codex-main"})
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("codex routing denied: status=%d body=%v", status, body)
	}
	if _, present := body["git"]; present {
		t.Fatalf("non-git provider routing must not set git, got %v", body)
	}
}

// TestGitInjectionAuditsWithoutTokenMaterial pins the audit rules on the git
// path: allowed and denied requests are audited with host/method/path
// context and the minted installation token never appears in the audit log.
func TestGitInjectionAuditsWithoutTokenMaterial(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeRoleIdentities(gitIdentities(nil))

	status, body := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", gitInjectionRequest("GET", "/my-user/my-repo.git/info/refs"))
	if status != http.StatusOK || body["ok"] != true {
		t.Fatalf("injection denied: status=%d body=%v", status, body)
	}
	credentials := decodeBasicAuth(t, body)
	token := strings.TrimPrefix(credentials, "x-access-token:")

	status, denyBody := f.postJSONWithToken("frontend-egress-token", "/v1/injection/headers", gitInjectionRequest("POST", "/my-user/my-repo.git/git-receive-pack"))
	if status == http.StatusOK || denyBody["ok"] == true {
		t.Fatalf("push must be denied for read grant: status=%d body=%v", status, denyBody)
	}

	audit, err := os.ReadFile(f.audit)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(audit), token) {
		t.Fatal("audit log contains the minted installation token")
	}
	var allowedEntry, deniedEntry map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(string(audit)), "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		if entry["operation"] == "injection.headers" && entry["provider"] == "git-app" {
			if entry["allowed"] == true {
				allowedEntry = entry
			}
			if entry["allowed"] == false && entry["reason"] == "write-not-allowed" {
				deniedEntry = entry
			}
		}
	}
	if allowedEntry == nil {
		t.Fatalf("missing allowed git injection audit entry: %s", audit)
	}
	if allowedEntry["host"] != "github.com" || allowedEntry["method"] != "GET" || allowedEntry["path"] != "/my-user/my-repo.git/info/refs" {
		t.Fatalf("allowed audit entry missing context: %v", allowedEntry)
	}
	if deniedEntry == nil {
		t.Fatalf("missing denied git injection audit entry: %s", audit)
	}
	if deniedEntry["path"] != "/my-user/my-repo.git/git-receive-pack" {
		t.Fatalf("denied audit entry missing path context: %v", deniedEntry)
	}
}
