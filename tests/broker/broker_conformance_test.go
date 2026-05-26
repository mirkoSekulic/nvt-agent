package broker_test

import (
	"bufio"
	"bytes"
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
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	fake := &fakeGitHub{}
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations/42/access_tokens", fake.handleToken)
	mux.HandleFunc("/repos/my-user/my-repo/pulls/123", fake.handleAPI)
	mux.HandleFunc("/repos/my-user/my-repo/issues/123/comments", fake.handleComments)
	mux.HandleFunc("/repos/my-user/my-repo/redirect", fake.handleRedirect)
	mux.HandleFunc("/repos/my-user/other-repo/pulls/1", fake.handleAPI)
	fake.server = httptest.NewServer(mux)
	t.Cleanup(fake.server.Close)
	return fake
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

func (f *fakeGitHub) lastAPIRequest() *http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.apiRequests) == 0 {
		return nil
	}
	return f.apiRequests[len(f.apiRequests)-1]
}

type brokerFixture struct {
	t      *testing.T
	root   string
	home   string
	bind   string
	url    string
	audit  string
	broker *exec.Cmd
	fake   *fakeGitHub
	keyPEM string
	config string
	stdout bytes.Buffer
	stderr bytes.Buffer
}

func newBrokerFixture(t *testing.T) *brokerFixture {
	t.Helper()
	fake := newFakeGitHub(t)
	home := t.TempDir()
	keyPEM := generateRSAKey(t)
	port := freePort(t)
	f := &brokerFixture{
		t:      t,
		root:   repoRoot(t),
		home:   home,
		bind:   fmt.Sprintf("127.0.0.1:%d", port),
		url:    fmt.Sprintf("http://127.0.0.1:%d", port),
		audit:  filepath.Join(home, "audit.jsonl"),
		fake:   fake,
		keyPEM: keyPEM,
	}
	f.config = f.writeConfig([]string{"my-user/my-repo", "my-user/other-repo"}, "", 0, 0)
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
`, f.fake.server.URL, perPage, maxResponseBytes, repoLines.String(), methods)
	path := filepath.Join(f.home, "broker.yaml")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		f.t.Fatal(err)
	}
	return path
}

func (f *brokerFixture) start() {
	f.t.Helper()
	cmd := exec.Command("python3", filepath.Join(f.root, "broker", "brokerd.py"))
	cmd.Env = append(os.Environ(),
		"NVT_BROKER_CONFIG="+f.config,
		"NVT_BROKER_BIND="+f.bind,
		"NVT_BROKER_AUDIT_LOG="+f.audit,
		"TEST_PRIVATE_KEY_B64="+base64.StdEncoding.EncodeToString([]byte(f.keyPEM)),
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

func (f *brokerFixture) brokerctl(args ...string) (map[string]any, string, int) {
	f.t.Helper()
	cmd := exec.Command("python3", append([]string{filepath.Join(f.root, "runtime", "core", "brokerctl.py")}, args...)...)
	cmd.Env = append(os.Environ(), "NVT_BROKER_URL="+f.url)
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
	if len(bytes.TrimSpace(output)) > 0 {
		if decodeErr := json.Unmarshal(bytes.TrimSpace(output), &payload); decodeErr != nil {
			f.t.Fatalf("decode brokerctl output %q: %v", output, decodeErr)
		}
	}
	return payload, string(output), status
}

func TestHealth(t *testing.T) {
	f := newBrokerFixture(t)
	payload, _, status := f.brokerctl("health")
	if status != 0 || payload["ok"] != true {
		t.Fatalf("health failed status=%d payload=%#v stderr=%s", status, payload, f.stderr.String())
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

func TestAuditRecordsAllowedAndDenied(t *testing.T) {
	f := newBrokerFixture(t)
	f.brokerctl("http", "request", "--provider", "fork-app", "--method", "GET", "--url", f.fake.server.URL+"/repos/my-user/my-repo/pulls/123")
	f.brokerctl("http", "request", "--provider", "fork-app", "--method", "GET", "--url", f.fake.server.URL+"/repos/not/allowed/pulls/123")

	file, err := os.Open(f.audit)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var allowed, denied bool
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		if event["allowed"] == true {
			allowed = true
		}
		if event["allowed"] == false && event["reason"] == "repo-not-allowed" {
			denied = true
		}
	}
	if !allowed || !denied {
		t.Fatalf("expected allowed and denied audit entries, allowed=%v denied=%v", allowed, denied)
	}
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
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
