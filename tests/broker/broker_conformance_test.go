package broker_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeGitHub struct {
	server        *httptest.Server
	mu            sync.Mutex
	tokenRequests []map[string]any
	apiRequests   []*http.Request
	appRequests   int
	userRequests  int
}

type fakeOAuth struct {
	server          *httptest.Server
	mu              sync.Mutex
	fail            bool
	malformedAccess bool
	requests        []map[string]string
}

func newFakeOAuth(t *testing.T) *fakeOAuth {
	t.Helper()
	fake := &fakeOAuth{}
	fake.server = httptest.NewServer(http.HandlerFunc(fake.handleToken))
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *fakeOAuth) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	request := map[string]string{
		"grant_type":    r.Form.Get("grant_type"),
		"client_id":     r.Form.Get("client_id"),
		"refresh_token": r.Form.Get("refresh_token"),
	}
	f.requests = append(f.requests, request)
	count := len(f.requests)
	fail := f.fail
	malformedAccess := f.malformedAccess
	f.mu.Unlock()
	if fail {
		http.Error(w, "refresh failed", http.StatusBadGateway)
		return
	}
	accessToken := testJWT(time.Now().Add(time.Hour))
	if malformedAccess {
		accessToken = "not-a-jwt"
	}
	writeJSON(w, map[string]any{
		"access_token":  accessToken,
		"refresh_token": fmt.Sprintf("real-refresh-%d", count+1),
		"id_token":      fmt.Sprintf("id-token-%d", count),
		"expires_in":    3600,
	})
}

func (f *fakeOAuth) setFail(value bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = value
}

func (f *fakeOAuth) setMalformedAccess(value bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.malformedAccess = value
}

func (f *fakeOAuth) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *fakeOAuth) lastRequest() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		return nil
	}
	return f.requests[len(f.requests)-1]
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	fake := &fakeGitHub{}
	mux := http.NewServeMux()
	mux.HandleFunc("/app", fake.handleApp)
	mux.HandleFunc("/app/installations/42/access_tokens", fake.handleToken)
	mux.HandleFunc("/users/local-agent[bot]", fake.handleUser)
	mux.HandleFunc("/repos/my-user/my-repo/pulls/123", fake.handleAPI)
	mux.HandleFunc("/repos/my-user/my-repo/issues/123/comments", fake.handleComments)
	mux.HandleFunc("/repos/my-user/my-repo/redirect", fake.handleRedirect)
	mux.HandleFunc("/repos/my-user/other-repo/pulls/1", fake.handleAPI)
	fake.server = httptest.NewServer(mux)
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *fakeGitHub) handleApp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if auth := r.Header.Get("Authorization"); !isBearerJWT(auth) {
		http.Error(w, "missing app jwt", http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	f.appRequests++
	f.mu.Unlock()
	writeJSON(w, map[string]any{"id": 123, "slug": "local-agent"})
}

func (f *fakeGitHub) handleUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		http.Error(w, "bot user lookup must be unauthenticated", http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	f.userRequests++
	f.mu.Unlock()
	writeJSON(w, map[string]any{"id": 987654321, "login": "local-agent[bot]"})
}

func isBearerJWT(auth string) bool {
	token, ok := strings.CutPrefix(auth, "Bearer ")
	return ok && strings.Count(token, ".") == 2
}

func (f *fakeGitHub) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	repos, _ := body["repositories"].([]any)
	repo := "unknown"
	if len(repos) > 0 {
		repo, _ = repos[0].(string)
	}
	f.mu.Lock()
	f.tokenRequests = append(f.tokenRequests, body)
	count := len(f.tokenRequests)
	f.mu.Unlock()
	writeJSON(w, map[string]any{
		"token":      fmt.Sprintf("token-%s-%d", repo, count),
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
}

func (f *fakeGitHub) handleAPI(w http.ResponseWriter, r *http.Request) {
	f.recordAPI(r)
	w.Header().Set("Link", `<`+f.server.URL+`/repos/my-user/my-repo/pulls/123?page=2>; rel="next"`)
	w.Header().Set("X-RateLimit-Remaining", "4999")
	writeJSON(w, map[string]any{"ok": true, "path": r.URL.Path})
}

func (f *fakeGitHub) handleComments(w http.ResponseWriter, r *http.Request) {
	f.recordAPI(r)
	page := r.URL.Query().Get("page")
	if page == "" || page == "1" {
		writeJSON(w, []map[string]any{{"id": 1}, {"id": 2}})
		return
	}
	writeJSON(w, []map[string]any{{"id": 3}})
}

func (f *fakeGitHub) handleRedirect(w http.ResponseWriter, r *http.Request) {
	f.recordAPI(r)
	http.Redirect(w, r, "http://127.0.0.1:1/leak", http.StatusFound)
}

func (f *fakeGitHub) recordAPI(r *http.Request) {
	clone := r.Clone(r.Context())
	f.mu.Lock()
	defer f.mu.Unlock()
	f.apiRequests = append(f.apiRequests, clone)
}

func (f *fakeGitHub) tokenRequestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.tokenRequests)
}

func (f *fakeGitHub) identityRequestCounts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.appRequests, f.userRequests
}

func (f *fakeGitHub) lastAPIRequest() *http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.apiRequests) == 0 {
		return nil
	}
	return f.apiRequests[len(f.apiRequests)-1]
}

type brokerFixture struct {
	t                 *testing.T
	root              string
	home              string
	bind              string
	url               string
	audit             string
	agents            string
	broker            *exec.Cmd
	fake              *fakeGitHub
	oauth             *fakeOAuth
	keyPEM            string
	config            string
	token             string
	auth              string
	claudeCreds       string
	extra             string
	codexClaimHeaders string
	codexExtraConfig  string
	stdout            bytes.Buffer
	stderr            bytes.Buffer
}

func newBrokerFixture(t *testing.T) *brokerFixture {
	return newBrokerFixtureWithCodexConfig(t, "")
}

func newBrokerFixtureWithCodexConfig(t *testing.T, codexExtraConfig string) *brokerFixture {
	t.Helper()
	fake := newFakeGitHub(t)
	oauth := newFakeOAuth(t)
	home := t.TempDir()
	keyPEM := generateRSAKey(t)
	port := freePort(t)
	f := &brokerFixture{
		t:                t,
		root:             repoRoot(t),
		home:             home,
		bind:             fmt.Sprintf("127.0.0.1:%d", port),
		url:              fmt.Sprintf("http://127.0.0.1:%d", port),
		audit:            filepath.Join(home, "audit.jsonl"),
		agents:           filepath.Join(home, "agents.yaml"),
		fake:             fake,
		oauth:            oauth,
		keyPEM:           keyPEM,
		token:            "frontend-token",
		auth:             filepath.Join(home, "auth.json"),
		claudeCreds:      filepath.Join(home, "claude-credentials.json"),
		extra:            filepath.Join(home, "config.toml"),
		codexExtraConfig: codexExtraConfig,
	}
	f.writeCodexAuth(testJWT(time.Now().Add(time.Hour)), "real-refresh-1")
	f.writeClaudeCredentials("real-claude-access-token-secret", "real-claude-refresh-token-secret")
	if err := os.WriteFile(f.extra, []byte("model = \"gpt-5\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.config = f.writeConfig([]string{"my-user/my-repo", "my-user/other-repo"}, "", 0, 0)
	f.writeAgents(map[string]agentGrant{
		"frontend": {
			Token: f.token,
			Grants: map[string][]string{
				"fork-app":   {"my-user/my-repo", "my-user/other-repo"},
				"codex-main": {},
			},
		},
	})
	f.start()
	t.Cleanup(f.stop)
	return f
}

func (f *brokerFixture) writeConfig(repos []string, methods string, perPage, maxResponseBytes int) string {
	f.t.Helper()
	if methods == "" {
		methods = `
        - GET`
	}
	if perPage == 0 {
		perPage = 2
	}
	if maxResponseBytes == 0 {
		maxResponseBytes = 1048576
	}
	var repoLines strings.Builder
	for _, repo := range repos {
		repoLines.WriteString("        - ")
		repoLines.WriteString(repo)
		repoLines.WriteString("\n")
	}
	config := fmt.Sprintf(`
providers:
  - name: fork-app
    plugin: github-app
    config:
      app-id: 123
      installation-id: 42
      private-key-base64-env: TEST_PRIVATE_KEY_B64
      api-url: %q
      per-page: %d
      max-response-bytes: %d
    allow:
      repositories:
%s      permissions:
        contents: read
        pull_requests: read
        checks: read
      methods:%s
  - name: git-app
    plugin: github-app
    config:
      app-id: 123
      installation-id: 42
      private-key-base64-env: TEST_PRIVATE_KEY_B64
      api-url: %[1]q
      injection-hosts:
        - github.com
    allow:
      repositories:
%[4]s      permissions:
        contents: write
      methods:
        - GET
  - name: git-app-ro
    plugin: github-app
    config:
      app-id: 123
      installation-id: 42
      private-key-base64-env: TEST_PRIVATE_KEY_B64
      api-url: %[1]q
      injection-hosts:
        - github.com
    allow:
      repositories:
%[4]s      permissions:
        contents: read
      methods:
        - GET
  - name: pat-provider
    plugin: token
    config:
      token-env: TEST_PAT_TOKEN
      injection-hosts:
        - api.example.test
    allow:
      repositories:
        - my-user/my-repo
  - name: basic-pat-provider
    plugin: token
    config:
      token-env: TEST_PAT_TOKEN
      injection-hosts:
        - dev.azure.com
      injection-basic-username: pat
      injection-git: true
    allow:
      repositories:
        - dev.azure.com/org/project/_git/repo
  - name: anthropic-main
    plugin: token
    config:
      token-env: TEST_ANTHROPIC_KEY
      injection-hosts:
        - api.anthropic.com
      injection-header: x-api-key
      injection-scheme: ""
      injection-extra-headers:
        anthropic-version: "2023-06-01"
    allow:
      repositories:
        - my-user/my-repo
  - name: fixture-auth
    plugin: placeholder
    config:
      file:
        path: .fixture/auth.json
        mode: "0600"
      hosts:
        - api.fixture.test
        - auth.fixture.test
      fields:
        access_token:
          secret-env: TEST_PLACEHOLDER_ACCESS
          shape: plain
        id_token:
          secret-env: TEST_PLACEHOLDER_ID
          shape: jwt
          claims:
            sub: acct-fixture-123
            plan: pro
        account_id: acct-fixture-123
    allow:
      repositories:
        - my-user/my-repo
  - name: header-provider
    plugin: headers
    config:
      headers:
        - header-env: TEST_AUTH_HEADER
        - header-env: TEST_EXTRA_HEADER
    allow:
      repositories:
        - my-user/my-repo
  - name: altinn-headers
    plugin: headers
    config:
      target-mode: literal
      headers:
        - header-env: TEST_ALTINN_API_KEY_HEADER
    allow:
      repositories:
        - altinn.studio/repos/digdir/oed
  - name: codex-main
    plugin: codex-oauth
    config:
      injection-hosts:
        - chatgpt.com
        - api.openai.com
        - auth.openai.com
%[6]s      auth-file: %[7]q
      token-url: %[8]q
      client-id: test-client
      refresh-margin-seconds: 600
%[9]s
      stub-refresh-token: nvt-broker-stub
      extra-files:
        - name: config.toml
          path: %[10]q
  - name: claude-main
    plugin: claude-oauth
    config:
      credentials-file: %[11]q
      token-url: %[8]q
      client-id: test-claude-client
      refresh-margin-seconds: 600
      injection-hosts:
        - api.anthropic.com
      injection-extra-headers:
        anthropic-beta: oauth-2025-04-20
      placeholder-file:
        path: .claude/.credentials.json
        hosts:
          - api.anthropic.com
`, f.fake.server.URL, perPage, maxResponseBytes, repoLines.String(), methods, f.codexClaimHeaders, f.auth, f.oauth.server.URL, f.codexExtraConfig, f.extra, f.claudeCreds)
	path := filepath.Join(f.home, "broker.yaml")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		f.t.Fatal(err)
	}
	return path
}

func (f *brokerFixture) writeCodexAuth(accessToken, refreshToken string) {
	f.t.Helper()
	writeJSONFile(f.t, f.auth, map[string]any{
		"tokens": map[string]any{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"id_token":      "initial-id-token",
		},
		"last_refresh": "2026-01-01T00:00:00Z",
	})
}

func (f *brokerFixture) writeClaudeCredentials(accessToken, refreshToken string) {
	f.t.Helper()
	f.writeClaudeCredentialsExp(accessToken, refreshToken, time.Now().Add(time.Hour))
}

func (f *brokerFixture) writeClaudeCredentialsExp(accessToken, refreshToken string, expiresAt time.Time) {
	f.t.Helper()
	writeJSONFile(f.t, f.claudeCreds, map[string]any{
		"claudeAiOauth": map[string]any{
			"accessToken":      accessToken,
			"refreshToken":     refreshToken,
			"expiresAt":        expiresAt.UnixMilli(),
			"scopes":           []string{"user:inference", "user:profile"},
			"subscriptionType": "max",
			"rateLimitTier":    "default_claude_max_20x",
		},
	})
}

func (f *brokerFixture) start() {
	f.t.Helper()
	cmd := exec.Command("python3", filepath.Join(f.root, "broker", "brokerd.py"))
	cmd.Env = append(os.Environ(),
		"NVT_BROKER_CONFIG="+f.config,
		"NVT_BROKER_AGENTS_CONFIG="+f.agents,
		"NVT_BROKER_BIND="+f.bind,
		"NVT_BROKER_AUDIT_LOG="+f.audit,
		"TEST_PRIVATE_KEY_B64="+base64.StdEncoding.EncodeToString([]byte(f.keyPEM)),
		"TEST_PAT_TOKEN=pat-secret",
		"TEST_AUTH_HEADER=Authorization: Bearer header-secret",
		"TEST_EXTRA_HEADER=X-Api-Key: extra-secret",
		"TEST_ALTINN_API_KEY_HEADER=X-API-Key: altinn-secret",
		"TEST_ANTHROPIC_KEY=anthropic-secret-key",
		"TEST_PLACEHOLDER_ACCESS=real-placeholder-access-token-secret",
		"TEST_PLACEHOLDER_ID=real-placeholder-id-token-secret",
	)
	cmd.Stdout = &f.stdout
	cmd.Stderr = &f.stderr
	if err := cmd.Start(); err != nil {
		f.t.Fatal(err)
	}
	f.broker = cmd
	waitFor(f.t, 3*time.Second, func() bool {
		resp, err := http.Get(f.url + "/health")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
}

func (f *brokerFixture) stop() {
	if f.broker == nil || f.broker.Process == nil {
		return
	}
	_ = f.broker.Process.Kill()
	_ = f.broker.Wait()
}

type agentGrant struct {
	Token  string
	Grants map[string][]string
}

func (f *brokerFixture) writeAgents(agents map[string]agentGrant) {
	f.t.Helper()
	var builder strings.Builder
	builder.WriteString("agents:\n")
	for id, agent := range agents {
		builder.WriteString("  - id: ")
		builder.WriteString(id)
		builder.WriteString("\n")
		builder.WriteString("    token-sha256: sha256:")
		hash := sha256.Sum256([]byte(agent.Token))
		builder.WriteString(fmt.Sprintf("%x", hash[:]))
		builder.WriteString("\n")
		builder.WriteString("    grants:\n")
		for provider, repos := range agent.Grants {
			builder.WriteString("      - provider: ")
			builder.WriteString(provider)
			builder.WriteString("\n")
			builder.WriteString("        repositories:\n")
			for _, repo := range repos {
				builder.WriteString("          - ")
				builder.WriteString(repo)
				builder.WriteString("\n")
			}
		}
		if len(agent.Grants) == 0 {
			builder.WriteString("      []\n")
		}
	}
	if len(agents) == 0 {
		builder.WriteString("  []\n")
	}
	tmp := f.agents + ".tmp"
	if err := os.WriteFile(tmp, []byte(builder.String()), 0o600); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Rename(tmp, f.agents); err != nil {
		f.t.Fatal(err)
	}
}

func (f *brokerFixture) brokerctl(args ...string) (map[string]any, string, int) {
	return f.brokerctlWithToken(f.token, args...)
}

func (f *brokerFixture) brokerctlWithToken(token string, args ...string) (map[string]any, string, int) {
	f.t.Helper()
	cmd := exec.Command("python3", append([]string{filepath.Join(f.root, "runtime", "core", "brokerctl.py")}, args...)...)
	env := append(os.Environ(), "NVT_BROKER_URL="+f.url, "NVT_BROKER_TOKEN=")
	if token != "" {
		env = append(env, "NVT_BROKER_TOKEN="+token)
	}
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	status := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			status = exit.ExitCode()
		} else {
			f.t.Fatalf("brokerctl failed: %v\n%s", err, output)
		}
	}
	var payload map[string]any
	trimmed := bytes.TrimSpace(output)
	if len(trimmed) > 0 && bytes.HasPrefix(trimmed, []byte("{")) {
		if decodeErr := json.Unmarshal(trimmed, &payload); decodeErr != nil {
			f.t.Fatalf("decode brokerctl output %q: %v", output, decodeErr)
		}
	}
	return payload, string(output), status
}

func TestHealth(t *testing.T) {
	f := newBrokerFixture(t)
	payload, _, status := f.brokerctlWithToken("", "health")
	if status != 0 || payload["ok"] != true {
		t.Fatalf("health failed status=%d payload=%#v stderr=%s", status, payload, f.stderr.String())
	}
}

func TestBrokerctlRequiresTokenForCapabilityCalls(t *testing.T) {
	f := newBrokerFixture(t)
	_, output, status := f.brokerctlWithToken("", "http", "request", "--provider", "fork-app", "--method", "GET", "--url", f.fake.server.URL+"/repos/my-user/my-repo/pulls/123")
	if status != 2 || !strings.Contains(output, "NVT_BROKER_TOKEN is not set") {
		t.Fatalf("expected local missing-token error, status=%d output=%q", status, output)
	}
}

func TestBrokerRejectsInvalidToken(t *testing.T) {
	f := newBrokerFixture(t)
	payload, _, status := f.brokerctlWithToken("wrong-token", "http", "request", "--provider", "fork-app", "--method", "GET", "--url", f.fake.server.URL+"/repos/my-user/my-repo/pulls/123")
	if status == 0 || payload["error"] != "unauthorized" {
		t.Fatalf("expected unauthorized, status=%d payload=%#v", status, payload)
	}
}

func TestHTTPRequestInjectsAuthAndReturnsHeaders(t *testing.T) {
	f := newBrokerFixture(t)
	payload, _, status := f.brokerctl(
		"http", "request",
		"--provider", "fork-app",
		"--method", "GET",
		"--url", f.fake.server.URL+"/repos/my-user/my-repo/pulls/123",
		"--header", "Accept:application/vnd.github+json",
		"--header", "If-None-Match:abc",
		"--header", "Authorization:Bearer attacker",
	)
	if status != 0 || payload["ok"] != true {
		t.Fatalf("request failed status=%d payload=%#v", status, payload)
	}
	headers := payload["headers"].(map[string]any)
	if headers["link"] == nil || headers["x-ratelimit-remaining"] != "4999" {
		t.Fatalf("expected lowercase response headers, got %#v", headers)
	}
	request := f.fake.lastAPIRequest()
	if request == nil {
		t.Fatal("fake server did not receive API request")
	}
	if got := request.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer token-my-repo-") {
		t.Fatalf("broker did not inject token, got %q", got)
	}
	if got := request.Header.Get("If-None-Match"); got != "abc" {
		t.Fatalf("If-None-Match not forwarded, got %q", got)
	}
}

func TestHTTPDenyValidationFailures(t *testing.T) {
	f := newBrokerFixture(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "host",
			args: []string{"http", "request", "--provider", "fork-app", "--method", "GET", "--url", "http://evil.example/repos/my-user/my-repo/pulls/123"},
			want: "host-not-allowed",
		},
		{
			name: "userinfo",
			args: []string{"http", "request", "--provider", "fork-app", "--method", "GET", "--url", strings.Replace(f.fake.server.URL, "http://", "http://api.github.com@evil@", 1) + "/repos/my-user/my-repo/pulls/123"},
			want: "url-userinfo-not-allowed",
		},
		{
			name: "metadata",
			args: []string{"http", "request", "--provider", "fork-app", "--method", "GET", "--url", "http://169.254.169.254/repos/my-user/my-repo/pulls/123"},
			want: "host-not-allowed",
		},
		{
			name: "repo",
			args: []string{"http", "request", "--provider", "fork-app", "--method", "GET", "--url", f.fake.server.URL + "/repos/other/repo/pulls/123"},
			want: "repo-not-allowed",
		},
		{
			name: "encoded-slash",
			args: []string{"http", "request", "--provider", "fork-app", "--method", "GET", "--url", f.fake.server.URL + "/repos/my-user/foo%2f..%2f..%2fother-user%2fsecret/pulls/123"},
			want: "path-not-allowed",
		},
		{
			name: "method",
			args: []string{"http", "request", "--provider", "fork-app", "--method", "POST", "--url", f.fake.server.URL + "/repos/my-user/my-repo/pulls/123"},
			want: "method-not-allowed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, _, status := f.brokerctl(tt.args...)
			if status == 0 || payload["error"] != tt.want {
				t.Fatalf("expected %s failure, status=%d payload=%#v", tt.want, status, payload)
			}
		})
	}
}

func TestAgentGrantsNarrowProviderCeiling(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeAgents(map[string]agentGrant{
		"frontend": {
			Token: f.token,
			Grants: map[string][]string{
				"fork-app": {"my-user/my-repo"},
			},
		},
	})
	payload, _, status := f.brokerctl("http", "request", "--provider", "fork-app", "--method", "GET", "--url", f.fake.server.URL+"/repos/my-user/other-repo/pulls/1")
	if status == 0 || payload["error"] != "repo-not-allowed" {
		t.Fatalf("expected grant repo denial, status=%d payload=%#v", status, payload)
	}
}

func TestEmptyAndMismatchedGrantsDeny(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeAgents(map[string]agentGrant{
		"frontend": {Token: f.token, Grants: map[string][]string{}},
	})
	payload, _, status := f.brokerctl("http", "request", "--provider", "fork-app", "--method", "GET", "--url", f.fake.server.URL+"/repos/my-user/my-repo/pulls/123")
	if status == 0 || payload["error"] != "provider-not-granted" {
		t.Fatalf("expected provider-not-granted for empty grants, status=%d payload=%#v", status, payload)
	}

	f.writeAgents(map[string]agentGrant{
		"frontend": {
			Token: f.token,
			Grants: map[string][]string{
				"fork-app": {"other-user/*"},
			},
		},
	})
	payload, _, status = f.brokerctl("http", "request", "--provider", "fork-app", "--method", "GET", "--url", f.fake.server.URL+"/repos/my-user/my-repo/pulls/123")
	if status == 0 || payload["error"] != "repo-not-allowed" {
		t.Fatalf("expected empty-intersection denial, status=%d payload=%#v", status, payload)
	}
}

func TestRedirectDoesNotLeakAuth(t *testing.T) {
	f := newBrokerFixture(t)
	payload, _, status := f.brokerctl(
		"http", "request",
		"--provider", "fork-app",
		"--method", "GET",
		"--url", f.fake.server.URL+"/repos/my-user/my-repo/redirect",
	)
	if status != 0 || payload["status"].(float64) != 302 {
		t.Fatalf("expected upstream redirect response, status=%d payload=%#v", status, payload)
	}
	f.fake.mu.Lock()
	requests := len(f.fake.apiRequests)
	f.fake.mu.Unlock()
	if requests != 1 {
		t.Fatalf("expected no redirect follow, got %d API requests", requests)
	}
}

func TestProviderOwnedPagination(t *testing.T) {
	f := newBrokerFixture(t)
	payload, _, status := f.brokerctl(
		"http", "request",
		"--provider", "fork-app",
		"--method", "GET",
		"--url", f.fake.server.URL+"/repos/my-user/my-repo/issues/123/comments",
		"--paginate",
	)
	if status != 0 || payload["ok"] != true {
		t.Fatalf("pagination failed status=%d payload=%#v", status, payload)
	}
	var comments []map[string]any
	if err := json.Unmarshal([]byte(payload["body"].(string)), &comments); err != nil {
		t.Fatal(err)
	}
	if len(comments) != 3 {
		t.Fatalf("expected 3 aggregated comments, got %#v", comments)
	}
}

func TestTokenCacheReuseAndSeparation(t *testing.T) {
	f := newBrokerFixture(t)
	for i := 0; i < 2; i++ {
		payload, _, status := f.brokerctl("token", "--provider", "fork-app", "--target", "github.com/my-user/my-repo", "--purpose", "git-push")
		if status != 0 || payload["ok"] != true {
			t.Fatalf("token failed: status=%d payload=%#v", status, payload)
		}
	}
	if count := f.fake.tokenRequestCount(); count != 1 {
		t.Fatalf("expected cache reuse, got %d token mints", count)
	}
	payload, _, status := f.brokerctl("token", "--provider", "fork-app", "--target", "github.com/my-user/other-repo")
	if status != 0 || payload["ok"] != true {
		t.Fatalf("second repo token failed: status=%d payload=%#v", status, payload)
	}
	if count := f.fake.tokenRequestCount(); count != 2 {
		t.Fatalf("expected separate repo cache key, got %d token mints", count)
	}
}

func TestTokenCacheIsAgentIndependent(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeAgents(map[string]agentGrant{
		"frontend": {
			Token: "frontend-token",
			Grants: map[string][]string{
				"fork-app": {"my-user/my-repo"},
			},
		},
		"backend": {
			Token: "backend-token",
			Grants: map[string][]string{
				"fork-app": {"my-user/my-repo"},
			},
		},
	})
	for _, token := range []string{"frontend-token", "backend-token"} {
		payload, _, status := f.brokerctlWithToken(token, "token", "--provider", "fork-app", "--target", "github.com/my-user/my-repo")
		if status != 0 || payload["ok"] != true {
			t.Fatalf("token failed for %s: status=%d payload=%#v", token, status, payload)
		}
	}
	if count := f.fake.tokenRequestCount(); count != 1 {
		t.Fatalf("expected shared repo cache across agents, got %d token mints", count)
	}
}

func TestStaticTokenProviderRequiresAgentGrant(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeAgents(map[string]agentGrant{
		"frontend": {
			Token: f.token,
			Grants: map[string][]string{
				"pat-provider": {"my-user/my-repo"},
			},
		},
	})
	payload, _, status := f.brokerctl("token", "--provider", "pat-provider", "--target", "github.com/my-user/my-repo")
	if status != 0 || payload["ok"] != true || payload["token"] != "pat-secret" {
		t.Fatalf("static token failed: status=%d payload=%#v", status, payload)
	}
	payload, _, status = f.brokerctl("token", "--provider", "pat-provider", "--target", "github.com/my-user/other-repo")
	if status == 0 || payload["error"] != "repo-not-allowed" {
		t.Fatalf("expected repo denial, status=%d payload=%#v", status, payload)
	}
}

func TestStaticHeadersProviderRequiresAgentGrant(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeAgents(map[string]agentGrant{
		"frontend": {
			Token: f.token,
			Grants: map[string][]string{
				"header-provider": {"my-user/my-repo"},
			},
		},
	})
	payload, _, status := f.brokerctl("headers", "--provider", "header-provider", "--target", "github.com/my-user/my-repo")
	if status != 0 || payload["ok"] != true {
		t.Fatalf("static headers failed: status=%d payload=%#v", status, payload)
	}
	headers := payload["headers"].([]any)
	if len(headers) != 2 || headers[0] != "Authorization: Bearer header-secret" || headers[1] != "X-Api-Key: extra-secret" {
		t.Fatalf("unexpected headers: %#v", headers)
	}
	payload, _, status = f.brokerctl("headers", "--provider", "header-provider", "--target", "github.com/my-user/other-repo")
	if status == 0 || payload["error"] != "repo-not-allowed" {
		t.Fatalf("expected repo denial, status=%d payload=%#v", status, payload)
	}
}

func TestStaticHeadersLiteralTargetModeSupportsSelfHostedGit(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeAgents(map[string]agentGrant{
		"frontend": {
			Token: f.token,
			Grants: map[string][]string{
				"altinn-headers": {"altinn.studio/repos/digdir/oed"},
			},
		},
	})
	for _, target := range []string{
		"https://altinn.studio/repos/digdir/oed.git",
		"git@altinn.studio:repos/digdir/oed.git",
		"altinn.studio/repos/digdir/oed",
	} {
		payload, _, status := f.brokerctl("headers", "--provider", "altinn-headers", "--target", target)
		if status != 0 || payload["ok"] != true {
			t.Fatalf("literal target %s failed: status=%d payload=%#v", target, status, payload)
		}
		headers := payload["headers"].([]any)
		if len(headers) != 1 || headers[0] != "X-API-Key: altinn-secret" {
			t.Fatalf("unexpected literal target headers: %#v", headers)
		}
	}
	payload, _, status := f.brokerctl("headers", "--provider", "altinn-headers", "--target", "https://altinn.studio/repos/digdir/other.git")
	if status == 0 || payload["error"] != "repo-not-allowed" {
		t.Fatalf("expected literal target denial, status=%d payload=%#v", status, payload)
	}
}

func TestUnsupportedStaticProviderOperationsFailCleanly(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeAgents(map[string]agentGrant{
		"frontend": {
			Token: f.token,
			Grants: map[string][]string{
				"pat-provider":    {"my-user/my-repo"},
				"header-provider": {"my-user/my-repo"},
			},
		},
	})
	payload, _, status := f.brokerctl("headers", "--provider", "pat-provider", "--target", "github.com/my-user/my-repo")
	if status == 0 || payload["error"] != "headers-not-supported" {
		t.Fatalf("expected headers-not-supported, status=%d payload=%#v", status, payload)
	}
	payload, _, status = f.brokerctl("token", "--provider", "header-provider", "--target", "github.com/my-user/my-repo")
	if status == 0 || payload["error"] != "token-not-supported" {
		t.Fatalf("expected token-not-supported, status=%d payload=%#v", status, payload)
	}
}

func TestIdentityReturnsGitHubAppBotIdentityAndCachesMetadata(t *testing.T) {
	f := newBrokerFixture(t)
	for i := 0; i < 2; i++ {
		payload, _, status := f.brokerctl("identity", "--provider", "fork-app", "--target", "github.com/my-user/my-repo")
		if status != 0 || payload["ok"] != true {
			t.Fatalf("identity failed: status=%d payload=%#v", status, payload)
		}
		if payload["name"] != "local-agent[bot]" {
			t.Fatalf("expected bot name, got %#v", payload["name"])
		}
		if payload["email"] != "987654321+local-agent[bot]@users.noreply.github.com" {
			t.Fatalf("expected bot user id in email, got %#v", payload["email"])
		}
	}
	appRequests, userRequests := f.fake.identityRequestCounts()
	if appRequests != 1 || userRequests != 1 {
		t.Fatalf("expected identity metadata cache, app=%d user=%d", appRequests, userRequests)
	}
}

func TestIdentityDeniedOutsideAgentGrant(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeAgents(map[string]agentGrant{
		"frontend": {
			Token: f.token,
			Grants: map[string][]string{
				"fork-app": {"my-user/my-repo"},
			},
		},
	})
	payload, _, status := f.brokerctl("identity", "--provider", "fork-app", "--target", "github.com/my-user/other-repo")
	if status == 0 || payload["error"] != "repo-not-allowed" {
		t.Fatalf("expected identity repo denial, status=%d payload=%#v", status, payload)
	}
}

func TestCodexOAuthFilesVendStubsRefreshTokenAndExtraFiles(t *testing.T) {
	f := newBrokerFixture(t)
	payload, output, status := f.brokerctl("files", "--provider", "codex-main")
	if status != 0 || payload["ok"] != true {
		t.Fatalf("files failed: status=%d payload=%#v", status, payload)
	}
	if strings.Contains(output, "real-refresh-1") {
		t.Fatalf("real refresh token appeared in response body")
	}
	files := payload["files"].([]any)
	if len(files) != 2 {
		t.Fatalf("expected auth.json plus extra file, got %#v", files)
	}
	authFile := files[0].(map[string]any)
	if authFile["name"] != "auth.json" || authFile["mode"] != "0600" {
		t.Fatalf("unexpected auth file metadata: %#v", authFile)
	}
	var auth map[string]any
	if err := json.Unmarshal([]byte(authFile["content"].(string)), &auth); err != nil {
		t.Fatal(err)
	}
	tokens := auth["tokens"].(map[string]any)
	if tokens["refresh_token"] != "nvt-broker-stub" {
		t.Fatalf("expected stub refresh token, got %#v", tokens["refresh_token"])
	}
	if tokens["access_token"] == "" || payload["expires_at"] == "" {
		t.Fatalf("expected access token and expiry, payload=%#v auth=%#v", payload, auth)
	}
	extra := files[1].(map[string]any)
	if extra["name"] != "config.toml" || extra["content"] != "model = \"gpt-5\"\n" {
		t.Fatalf("unexpected extra file: %#v", extra)
	}
}

func TestBrokerFilesExpiryIsCappedByDefaultBundleTTL(t *testing.T) {
	f := newBrokerFixture(t)
	before := time.Now().UTC()
	payload, _, status := f.brokerctl("files", "--provider", "codex-main")
	if status != 0 || payload["ok"] != true {
		t.Fatalf("files failed: status=%d payload=%#v", status, payload)
	}
	expiresAt, err := time.Parse(time.RFC3339, payload["expires_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if expiresAt.Before(before) || expiresAt.After(before.Add(1220*time.Second)) {
		t.Fatalf("expected bundle expiry near default TTL, before=%s expires_at=%s", before, expiresAt)
	}
	files := payload["files"].([]any)
	var auth map[string]any
	if err := json.Unmarshal([]byte(files[0].(map[string]any)["content"].(string)), &auth); err != nil {
		t.Fatal(err)
	}
	tokens := auth["tokens"].(map[string]any)
	accessExpUnix, err := parseJWTExpForTest(tokens["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	accessExp := time.Unix(accessExpUnix, 0).UTC()
	if !accessExp.After(expiresAt.Add(30 * time.Minute)) {
		t.Fatalf("test expected provider JWT expiry to exceed bundle expiry, access=%s bundle=%s", accessExp, expiresAt)
	}
	events := readAudit(t, f.audit)
	vend := lastAuditOperation(events, "files.vend")
	if vend == nil {
		t.Fatalf("expected files.vend audit entry, got %#v", events)
	}
	if vend["expires_at"] != payload["expires_at"] || vend["bundle_expires_at"] != payload["expires_at"] {
		t.Fatalf("expected core files.vend audit to use capped bundle expiry, payload=%#v vend=%#v", payload, vend)
	}
	if vend["access_token_expires_at"] == payload["expires_at"] {
		t.Fatalf("expected provider access token expiry to remain distinct from capped bundle expiry, payload=%#v vend=%#v", payload, vend)
	}
}

func TestCodexOAuthFilesExpiryUsesConfiguredBundleTTL(t *testing.T) {
	f := newBrokerFixtureWithCodexConfig(t, "      bundle-ttl-seconds: 300\n")
	before := time.Now().UTC()
	payload, _, status := f.brokerctl("files", "--provider", "codex-main")
	if status != 0 || payload["ok"] != true {
		t.Fatalf("files failed: status=%d payload=%#v", status, payload)
	}
	expiresAt, err := time.Parse(time.RFC3339, payload["expires_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if expiresAt.Before(before) || expiresAt.After(before.Add(320*time.Second)) {
		t.Fatalf("expected bundle expiry near configured TTL, before=%s expires_at=%s", before, expiresAt)
	}
}

func TestCodexOAuthFilesExpiryUsesAccessTokenExpiryWhenSoonerThanBundleTTL(t *testing.T) {
	f := newBrokerFixture(t)
	f.oauth.setFail(true)
	accessExp := time.Now().Add(10 * time.Minute).UTC()
	f.writeCodexAuth(testJWT(accessExp), "real-refresh-1")
	payload, _, status := f.brokerctl("files", "--provider", "codex-main")
	if status != 0 || payload["ok"] != true {
		t.Fatalf("expected current valid token to be served after refresh failure, status=%d payload=%#v", status, payload)
	}
	expiresAt, err := time.Parse(time.RFC3339, payload["expires_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	want := accessExp.Truncate(time.Second)
	if !expiresAt.Equal(want) {
		t.Fatalf("expected expiry to use access token expiry when sooner than bundle TTL, want=%s got=%s", want, expiresAt)
	}
}

func TestCodexOAuthRefreshPersistsRotatedTokenAndAudits(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeCodexAuth(testJWT(time.Now().Add(2*time.Minute)), "real-refresh-1")
	payload, output, status := f.brokerctl("files", "--provider", "codex-main")
	if status != 0 || payload["ok"] != true {
		t.Fatalf("files failed: status=%d payload=%#v output=%s", status, payload, output)
	}
	if strings.Contains(output, "real-refresh-1") || strings.Contains(output, "real-refresh-2") {
		t.Fatalf("real refresh token appeared in response body")
	}
	if count := f.oauth.requestCount(); count != 1 {
		t.Fatalf("expected one refresh request, got %d", count)
	}
	request := f.oauth.lastRequest()
	if request["grant_type"] != "refresh_token" || request["client_id"] != "test-client" || request["refresh_token"] != "real-refresh-1" {
		t.Fatalf("unexpected refresh request metadata: %#v", request)
	}
	var canonical map[string]any
	decodeJSONFile(t, f.auth, &canonical)
	tokens := canonical["tokens"].(map[string]any)
	if tokens["refresh_token"] != "real-refresh-2" || tokens["id_token"] != "id-token-1" {
		t.Fatalf("canonical auth was not rotated: %#v", tokens)
	}
	payload, _, status = f.brokerctl("files", "--provider", "codex-main")
	if status != 0 || payload["ok"] != true {
		t.Fatalf("second files failed: status=%d payload=%#v", status, payload)
	}
	if count := f.oauth.requestCount(); count != 1 {
		t.Fatalf("expected refreshed access token to be reused, got %d refreshes", count)
	}
	events := readAudit(t, f.audit)
	if !hasAuditOperation(events, "files.vend") || !hasAuditOperation(events, "files.refresh") {
		t.Fatalf("expected vend and refresh audit entries, got %#v", events)
	}
	var vend map[string]any
	vend = lastAuditOperation(events, "files.vend")
	if vend == nil {
		t.Fatalf("expected vend audit entry, got %#v", events)
	}
	accessTokenExpiresAt, ok := vend["access_token_expires_at"]
	if !ok || accessTokenExpiresAt == "" {
		t.Fatalf("expected vend audit to include access_token_expires_at, got %#v", vend)
	}
	if vend["bundle_expires_at"] != vend["expires_at"] {
		t.Fatalf("expected vend audit bundle_expires_at to match expires_at, got %#v", vend)
	}
	if vend["bundle_expires_at"] == accessTokenExpiresAt {
		t.Fatalf("expected vend audit to distinguish bundle and access token expiry, got %#v", vend)
	}
}

func TestCodexOAuthFilesRefreshesBeforeBundleTTLRunway(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeCodexAuth(testJWT(time.Now().Add(15*time.Minute)), "real-refresh-1")
	payload, output, status := f.brokerctl("files", "--provider", "codex-main")
	if status != 0 || payload["ok"] != true {
		t.Fatalf("files failed: status=%d payload=%#v output=%s", status, payload, output)
	}
	if count := f.oauth.requestCount(); count != 1 {
		t.Fatalf("expected refresh before vending a bundle with less than bundle TTL runway, got %d refreshes", count)
	}
	if strings.Contains(output, "real-refresh-1") || strings.Contains(output, "real-refresh-2") {
		t.Fatalf("real refresh token appeared in response body")
	}
}

func TestCodexOAuthRefreshFailureServesValidButRejectsExpired(t *testing.T) {
	f := newBrokerFixture(t)
	f.oauth.setFail(true)
	f.writeCodexAuth(testJWT(time.Now().Add(2*time.Minute)), "real-refresh-1")
	payload, _, status := f.brokerctl("files", "--provider", "codex-main")
	if status != 0 || payload["ok"] != true {
		t.Fatalf("expected valid current token to be served, status=%d payload=%#v", status, payload)
	}
	f.writeCodexAuth(testJWT(time.Now().Add(-time.Minute)), "real-refresh-1")
	payload, _, status = f.brokerctl("files", "--provider", "codex-main")
	if status == 0 || payload["error"] != "token-refresh-failed" {
		t.Fatalf("expected expired token refresh failure, status=%d payload=%#v", status, payload)
	}
}

func TestCodexOAuthPersistsRotatedRefreshTokenBeforeNewAccessValidation(t *testing.T) {
	f := newBrokerFixture(t)
	f.oauth.setMalformedAccess(true)
	oldAccessToken := testJWT(time.Now().Add(2 * time.Minute))
	f.writeCodexAuth(oldAccessToken, "real-refresh-1")
	payload, _, status := f.brokerctl("files", "--provider", "codex-main")
	if status != 0 || payload["ok"] != true {
		t.Fatalf("expected old valid token to be served after malformed refreshed access token, status=%d payload=%#v", status, payload)
	}
	files := payload["files"].([]any)
	var vended map[string]any
	if err := json.Unmarshal([]byte(files[0].(map[string]any)["content"].(string)), &vended); err != nil {
		t.Fatal(err)
	}
	vendedTokens := vended["tokens"].(map[string]any)
	if vendedTokens["access_token"] != oldAccessToken {
		t.Fatalf("expected old valid access token to be vended, got %#v", vendedTokens["access_token"])
	}

	var canonical map[string]any
	decodeJSONFile(t, f.auth, &canonical)
	tokens := canonical["tokens"].(map[string]any)
	if tokens["refresh_token"] != "real-refresh-2" {
		t.Fatalf("rotated refresh token was not persisted: %#v", tokens)
	}
	if tokens["access_token"] != "not-a-jwt" {
		t.Fatalf("expected malformed refreshed access token to be persisted with rotated token: %#v", tokens)
	}
}

func TestCodexOAuthRefreshesMalformedCanonicalAccessToken(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeCodexAuth("not-a-jwt", "real-refresh-1")
	payload, _, status := f.brokerctl("files", "--provider", "codex-main")
	if status != 0 || payload["ok"] != true {
		t.Fatalf("expected malformed canonical access token to self-heal, status=%d payload=%#v", status, payload)
	}
	if count := f.oauth.requestCount(); count != 1 {
		t.Fatalf("expected one refresh request, got %d", count)
	}

	var canonical map[string]any
	decodeJSONFile(t, f.auth, &canonical)
	tokens := canonical["tokens"].(map[string]any)
	accessToken, _ := tokens["access_token"].(string)
	if accessToken == "" || accessToken == "not-a-jwt" {
		t.Fatalf("expected canonical access token to be repaired: %#v", tokens)
	}
	if _, err := parseJWTExpForTest(accessToken); err != nil {
		t.Fatalf("expected repaired canonical access token to be parseable: %v", err)
	}
	if tokens["refresh_token"] != "real-refresh-2" {
		t.Fatalf("expected refresh token rotation to persist: %#v", tokens)
	}
}

func TestCodexOAuthFilesRequireProviderGrant(t *testing.T) {
	f := newBrokerFixture(t)
	f.writeAgents(map[string]agentGrant{
		"frontend": {Token: f.token, Grants: map[string][]string{}},
	})
	payload, _, status := f.brokerctl("files", "--provider", "codex-main")
	if status == 0 || payload["error"] != "provider-not-granted" {
		t.Fatalf("expected provider-not-granted, status=%d payload=%#v", status, payload)
	}
}

func TestAgentsConfigReloadKeepsLastGoodOnFailure(t *testing.T) {
	f := newBrokerFixture(t)
	payload, _, status := f.brokerctl("http", "request", "--provider", "fork-app", "--method", "GET", "--url", f.fake.server.URL+"/repos/my-user/my-repo/pulls/123")
	if status != 0 || payload["ok"] != true {
		t.Fatalf("baseline request failed: status=%d payload=%#v", status, payload)
	}
	if err := os.WriteFile(f.agents, []byte("agents: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload, _, status = f.brokerctl("http", "request", "--provider", "fork-app", "--method", "GET", "--url", f.fake.server.URL+"/repos/my-user/my-repo/pulls/123")
	if status != 0 || payload["ok"] != true {
		t.Fatalf("last-good agents config was not preserved: status=%d payload=%#v", status, payload)
	}

	f.writeAgents(map[string]agentGrant{
		"frontend": {
			Token: f.token,
			Grants: map[string][]string{
				"fork-app": {"my-user/other-repo"},
			},
		},
	})
	payload, _, status = f.brokerctl("http", "request", "--provider", "fork-app", "--method", "GET", "--url", f.fake.server.URL+"/repos/my-user/my-repo/pulls/123")
	if status == 0 || payload["error"] != "repo-not-allowed" {
		t.Fatalf("updated agents config was not reloaded: status=%d payload=%#v", status, payload)
	}
}

func TestAuditRecordsAllowedAndDenied(t *testing.T) {
	f := newBrokerFixture(t)
	f.brokerctl("http", "request", "--provider", "fork-app", "--method", "GET", "--url", f.fake.server.URL+"/repos/my-user/my-repo/pulls/123")
	f.brokerctl("http", "request", "--provider", "fork-app", "--method", "GET", "--url", f.fake.server.URL+"/repos/not/allowed/pulls/123")
	f.writeAgents(map[string]agentGrant{
		"frontend": {
			Token: f.token,
			Grants: map[string][]string{
				"altinn-headers": {"altinn.studio/repos/digdir/oed"},
			},
		},
	})
	f.brokerctl("headers", "--provider", "altinn-headers", "--target", "https://altinn.studio/repos/digdir/oed.git")

	file, err := os.Open(f.audit)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var allowed, denied, literal bool
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		if event["agent"] == "frontend" && event["allowed"] == true {
			allowed = true
		}
		if event["agent"] == "frontend" && event["allowed"] == false && event["reason"] == "repo-not-allowed" {
			denied = true
		}
		if event["agent"] == "frontend" && event["allowed"] == true && event["target"] == "altinn.studio/repos/digdir/oed" {
			literal = true
		}
	}
	if !allowed || !denied || !literal {
		t.Fatalf("expected allowed, denied, and literal audit entries, allowed=%v denied=%v literal=%v", allowed, denied, literal)
	}
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func decodeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, value); err != nil {
		t.Fatal(err)
	}
}

func testJWT(exp time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{"exp": exp.Unix()})
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func testJWTWithClaims(exp time.Time, claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	body := map[string]any{"exp": exp.Unix()}
	for key, value := range claims {
		body[key] = value
	}
	payload, _ := json.Marshal(body)
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func parseJWTExpForTest(token string) (int64, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return 0, fmt.Errorf("token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, err
	}
	var data map[string]any
	if err := json.Unmarshal(payload, &data); err != nil {
		return 0, err
	}
	exp, ok := data["exp"].(float64)
	if !ok {
		return 0, fmt.Errorf("missing exp")
	}
	return int64(exp), nil
}

func readAudit(t *testing.T, path string) []map[string]any {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var events []map[string]any
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return events
}

func hasAuditOperation(events []map[string]any, operation string) bool {
	for _, event := range events {
		if event["operation"] == operation && event["allowed"] == true {
			return true
		}
	}
	return false
}

func lastAuditOperation(events []map[string]any, operation string) map[string]any {
	var last map[string]any
	for _, event := range events {
		if event["operation"] == operation && event["allowed"] == true {
			last = event
		}
	}
	return last
}

func generateRSAKey(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("openssl", "genrsa", "2048")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl genrsa failed: %v\n%s", err, output)
	}
	return string(output)
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("condition did not become true within %s", timeout)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	if value := os.Getenv("GITHUB_WORKSPACE"); value != "" {
		return value
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve test file path")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(file), "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}
