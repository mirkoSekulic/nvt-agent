package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Real static-token provider + broker role boundary + egress TLS + git/curl.
// Only the upstream service and credential are fixtures; no cloud is contacted.
func TestSharedPATForHostScopedGitAndHTTP(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Fatal(err)
	}
	_, source, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(source), "../../.."))
	private := t.TempDir()
	agentHome := t.TempDir()
	const pat = "fake-shared-pat-canary"
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("git:"+pat))
	write := func(path string, value []byte) {
		t.Helper()
		if err := os.WriteFile(path, value, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeJSON := func(path string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		write(path, data)
	}
	secret := filepath.Join(private, "pat")
	write(secret, []byte(pat))
	providers := []any{}
	for _, name := range []string{"forge-api", "forge-git", "ungranted"} {
		config := map[string]any{"token-file": secret, "injection-hosts": []string{"forge.example.test"}, "injection-git": false}
		if name == "forge-git" {
			config["injection-basic-username"] = "git"
		}
		providers = append(providers, map[string]any{"name": name, "plugin": "token", "config": config})
	}
	configPath := filepath.Join(private, "broker.json")
	writeJSON(configPath, map[string]any{"providers": providers})
	identity := func(id, role, pair string, grants []any) map[string]any {
		h := sha256.Sum256([]byte(id + "-role-fixture"))
		v := map[string]any{"id": id, "role": role, "token-sha256": fmt.Sprintf("sha256:%x", h), "grants": grants}
		if pair != "" {
			v["paired-agent"] = pair
		}
		return v
	}
	agentsPath := filepath.Join(private, "agents.json")
	writeJSON(agentsPath, map[string]any{"agents": []any{
		identity("agent", "agent", "", []any{map[string]any{"provider": "forge-api", "materialization": "header-inject"}, map[string]any{"provider": "forge-git", "materialization": "header-inject"}}),
		identity("egress", "egress", "agent", []any{}), identity("denied", "agent", "", []any{}), identity("denied-egress", "egress", "denied", []any{}),
	}})
	audit := filepath.Join(private, "audit.jsonl")
	logs, err := os.Create(filepath.Join(private, "broker.log"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	command := httpCredentialFixturePython(t, ctx, filepath.Join(repo, "tests/http-credentials/broker_fixture.py"))
	command.Env = append(command.Env, "HOME="+private, "NVT_BROKER_CONFIG="+configPath, "NVT_BROKER_AGENTS_CONFIG="+agentsPath, "NVT_BROKER_AUDIT_LOG="+audit)
	command.Stderr = logs
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait(); _ = logs.Close() })
	reader := bufio.NewReader(stdout)
	brokerURL, err := reader.ReadString('\n')
	if err != nil {
		diagnostic := make([]byte, 4096)
		n, _ := logs.ReadAt(diagnostic, 0)
		redact := strings.NewReplacer(pat, "[redacted]", strings.TrimPrefix(basic, "Basic "), "[redacted]")
		t.Fatalf("fixture broker startup failed (%s): %v; stderr=%q", command.Path, err, redact.Replace(string(diagnostic[:n])))
	}
	brokerURL = strings.TrimSpace(brokerURL)

	seed := filepath.Join(private, "seed")
	if err := os.Mkdir(seed, 0700); err != nil {
		t.Fatal(err)
	}
	gitEnv := []string{"HOME=" + agentHome, "GIT_CONFIG_GLOBAL=/dev/null", "HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "http_proxy=", "https_proxy=", "all_proxy=", "NO_PROXY=", "no_proxy="}
	runGit(t, seed, gitEnv, "init", "--initial-branch=main", ".")
	write(filepath.Join(seed, "README"), []byte("first\n"))
	runGit(t, seed, gitEnv, "add", ".")
	runGit(t, seed, gitEnv, "commit", "-qm", "first")
	upstreamRoot := filepath.Join(private, "repos")
	if err := os.Mkdir(upstreamRoot, 0700); err != nil {
		t.Fatal(err)
	}
	bare := filepath.Join(upstreamRoot, "not-enumerated.git")
	runGit(t, seed, gitEnv, "clone", "--bare", ".", bare)
	gitBackend := &cgi.Handler{Path: git, Args: []string{"http-backend"}, Env: []string{"GIT_PROJECT_ROOT=" + upstreamRoot, "GIT_HTTP_EXPORT_ALL=1", "REMOTE_USER=git"}}
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy selector leaked upstream")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Header.Get("Authorization") != "Bearer "+pat {
				http.Error(w, "wrong fixture credential", 401)
				return
			}
			if r.URL.Path == "/api/redirect" {
				http.Redirect(w, r, "https://elsewhere.example.test/stolen", 302)
				return
			}
			_, _ = io.WriteString(w, "api-ok")
			return
		}
		if r.Header.Get("Authorization") != basic {
			http.Error(w, "wrong fixture credential", 401)
			return
		}
		gitBackend.ServeHTTP(w, r)
	}))
	defer upstream.Close()
	ca, err := NewCAWithUpstreams(nil, []string{"forge.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join(agentHome, "public-ca.pem")
	write(cert, ca.CertPEM())
	routes := []ForwardProxyInjectRoute{}
	for _, provider := range []string{"forge-api", "forge-git", "ungranted"} {
		routes = append(routes, ForwardProxyInjectRoute{Host: "forge.example.test", Capability: provider, Upstream: strings.TrimPrefix(upstream.URL, "http://"), AllowInsecureUpstream: true})
	}
	newProxy := func(token string) *httptest.Server {
		return httptest.NewServer(&ForwardProxy{Config: ForwardProxyConfig{Listen: "unused", InjectRoutes: routes}, CA: ca, Broker: &BrokerClient{URL: brokerURL, Token: token, Client: http.DefaultClient}, Transport: &http.Transport{}, Resolver: &staticResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}})
	}
	proxy := newProxy("egress-role-fixture")
	defer proxy.Close()
	selector := func(base, provider string) string {
		u, _ := url.Parse(base)
		u.User = url.UserPassword(provider, "x")
		return u.String()
	}
	gitEnv = append(gitEnv, "GIT_SSL_CAINFO="+cert)
	clone := filepath.Join(agentHome, "clone")
	runGit(t, agentHome, gitEnv, "-c", "http.proxyAuthMethod=basic", "-c", "http.proxy="+selector(proxy.URL, "forge-git"), "clone", "https://forge.example.test/not-enumerated.git", clone)
	write(filepath.Join(seed, "README"), []byte("second\n"))
	runGit(t, seed, gitEnv, "commit", "-qam", "second")
	runGit(t, seed, gitEnv, "push", bare, "main")
	runGit(t, clone, gitEnv, "-c", "http.proxyAuthMethod=basic", "-c", "http.proxy="+selector(proxy.URL, "forge-git"), "fetch", "origin")
	if value := runGit(t, clone, gitEnv, "show", "origin/main:README"); value != "second\n" {
		t.Fatal("fetch did not receive new commit")
	}
	request := exec.Command(curl, "--silent", "--show-error", "--fail", "--noproxy", "", "--proxy", selector(proxy.URL, "forge-api"), "--cacert", cert, "https://forge.example.test/api/projects")
	request.Env = []string{"HOME=" + agentHome, "PATH=/usr/bin:/bin"}
	output, err := request.CombinedOutput()
	if err != nil || string(output) != "api-ok" {
		t.Fatalf("curl fixture failed: %v", err)
	}
	before := calls.Load()
	deniedProxy := newProxy("denied-egress-role-fixture")
	defer deniedProxy.Close()
	for _, test := range []struct{ base, provider, target string }{
		{proxy.URL, "ungranted", "https://forge.example.test/api/projects"},
		{deniedProxy.URL, "forge-api", "https://forge.example.test/api/projects"},
		{proxy.URL, "forge-api", "https://elsewhere.example.test/api/projects"},
	} {
		u, _ := url.Parse(selector(test.base, test.provider))
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u), TLSClientConfig: &tls.Config{RootCAs: caCertPool(t, ca)}}}
		response, err := client.Get(test.target)
		if err == nil {
			response.Body.Close()
			if response.StatusCode < 400 {
				t.Fatal("denied request succeeded")
			}
		}
	}
	if calls.Load() != before {
		t.Fatal("denied request reached credentialed upstream")
	}
	u, _ := url.Parse(selector(proxy.URL, "forge-api"))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u), TLSClientConfig: &tls.Config{RootCAs: caCertPool(t, ca)}}}
	response, err := client.Get("https://forge.example.test/api/redirect")
	if err == nil {
		response.Body.Close()
		if response.StatusCode < 400 {
			t.Fatal("redirect escaped host ceiling")
		}
	}
	if calls.Load() != before+1 {
		t.Fatal("redirect reached another upstream")
	}
	// Agent role cannot export raw credentials, even with a selected provider.
	for _, endpoint := range []string{"/v1/token", "/v1/headers", "/v1/injection/headers"} {
		body := `{"provider":"forge-api","capability":"forge-api","target":"forge.example.test/repo","host":"forge.example.test","method":"GET","path":"/api/projects"}`
		req, _ := http.NewRequest("POST", brokerURL+endpoint, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer agent-role-fixture")
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode < 400 || bytes.Contains(data, []byte(pat)) {
			t.Fatal("agent obtained broker material")
		}
	}
	assertClean := func(path string) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(pat)) || bytes.Contains(data, []byte(strings.TrimPrefix(basic, "Basic "))) {
			t.Fatal("credential present in agent state or logs")
		}
	}
	if err := filepath.WalkDir(agentHome, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			assertClean(path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertClean(audit)
	assertClean(filepath.Join(private, "broker.log"))
}
