package egress

// Phase 4 git smart-HTTP streaming proof (docs/phase4-git-mediation-plan.md
// §4 spike item): a real git client clones and pushes through the
// TLS-terminated egressd route against a local `git http-backend` upstream —
// pack POSTs stream through buildOutbound, no GitHub dependency. The
// upstream enforces the broker-injected Basic credential, so a passing
// clone/push proves injection end to end.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runGit(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=nvt-test",
		"GIT_AUTHOR_EMAIL=nvt-test@example.invalid",
		"GIT_COMMITTER_NAME=nvt-test",
		"GIT_COMMITTER_EMAIL=nvt-test@example.invalid",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
	)
	cmd.Env = append(cmd.Env, env...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

// TestGitSmartHTTPThroughTLSRoute drives `git ls-remote`, `git clone`, and
// `git push` through the CA-backed TLS route. The upstream is git
// http-backend behind an auth check that accepts only the broker-injected
// credential; the git client itself holds none.
func TestGitSmartHTTPThroughTLSRoute(t *testing.T) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git binary not available")
	}

	root := t.TempDir()

	// Upstream bare repo with one commit and pushes enabled.
	seed := filepath.Join(root, "seed")
	if err := os.MkdirAll(seed, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, seed, nil, "init", "--initial-branch=main", ".")
	if err := os.WriteFile(filepath.Join(seed, "README.md"), []byte("phase 4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A multi-megabyte blob so the upload-pack/receive-pack bodies exercise
	// real streaming, not a trivial buffer.
	large := make([]byte, 3*1024*1024)
	for i := range large {
		large[i] = byte(i % 251)
	}
	if err := os.WriteFile(filepath.Join(seed, "blob.bin"), large, 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, seed, nil, "add", ".")
	runGit(t, seed, nil, "commit", "-m", "seed", "--quiet")
	bare := filepath.Join(root, "upstream", "my-user", "my-repo.git")
	if err := os.MkdirAll(filepath.Dir(bare), 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, seed, nil, "clone", "--bare", "--quiet", ".", bare)
	runGit(t, bare, nil, "config", "http.receivepack", "true")

	// Upstream server: git http-backend, accepting only the injected Basic
	// credential the broker vends for this route.
	injected := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:fixture-installation-token"))
	backend := &cgi.Handler{
		Path: gitPath,
		Args: []string{"http-backend"},
		Dir:  root,
		Env: []string{
			"GIT_PROJECT_ROOT=" + filepath.Join(root, "upstream"),
			"GIT_HTTP_EXPORT_ALL=1",
			"REMOTE_USER=x-access-token",
		},
	}
	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != injected {
			w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
			http.Error(w, "credential required", http.StatusUnauthorized)
			return
		}
		backend.ServeHTTP(w, r)
	})
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &http.Server{Handler: upstreamHandler}
	go func() { _ = upstreamServer.Serve(upstreamListener) }()
	t.Cleanup(func() { _ = upstreamServer.Close() })

	// egressd: broker-injected credentials, CA-backed TLS listener. The
	// upstream hop is plain HTTP here; the re-originated TLS leg is proven
	// by TestGitRouteTLSEndToEnd.
	broker := gitBrokerServer(t, injected)
	proxy := &Proxy{
		Route: Route{
			Listen:                "unused",
			Capability:            "git-app",
			Upstream:              upstreamListener.Addr().String(),
			AllowInsecureUpstream: true,
			ListenTLS:             RouteListenTLSCA,
		},
		Broker:    &BrokerClient{URL: broker.URL, Token: "egress-role-token", Client: broker.Client()},
		Transport: http.DefaultTransport,
	}
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	publishDir := t.TempDir()
	if err := ca.PublishCert(publishDir); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(publishDir, CACertFileName)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: proxy}
	go func() { _ = server.Serve(tls.NewListener(listener, ca.ServerTLSConfig())) }()
	t.Cleanup(func() { _ = server.Close() })

	base := "https://" + listener.Addr().String()
	remote := base + "/my-user/my-repo.git"
	gitEnv := []string{"GIT_SSL_CAINFO=" + caFile, "HOME=" + t.TempDir()}

	// ls-remote: GET info/refs advertisement.
	output := runGit(t, root, gitEnv, "ls-remote", remote)
	if !strings.Contains(output, "refs/heads/main") {
		t.Fatalf("ls-remote did not list main:\n%s", output)
	}

	// clone: streams the multi-megabyte pack through a POST git-upload-pack.
	clone := filepath.Join(root, "clone")
	runGit(t, root, gitEnv, "clone", "--quiet", remote, clone)
	content, err := os.ReadFile(filepath.Join(clone, "README.md"))
	if err != nil || string(content) != "phase 4\n" {
		t.Fatalf("cloned content mismatch: %v %q", err, content)
	}
	cloned, err := os.ReadFile(filepath.Join(clone, "blob.bin"))
	if err != nil || len(cloned) != len(large) {
		t.Fatalf("large blob did not stream through clone: %v (%d bytes)", err, len(cloned))
	}

	// push: streams a pack through a POST git-receive-pack.
	if err := os.WriteFile(filepath.Join(clone, "pushed.txt"), []byte("pushed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, clone, gitEnv, "add", "pushed.txt")
	runGit(t, clone, gitEnv, "commit", "-m", "push through egressd", "--quiet")
	runGit(t, clone, gitEnv, "push", "--quiet", "origin", "main")
	log := runGit(t, bare, nil, "log", "-1", "--format=%s", "main")
	if strings.TrimSpace(log) != "push through egressd" {
		t.Fatalf("push did not land upstream, log: %q", log)
	}

	// The clone directory must hold no credential material: git never saw
	// the injected token, only egressd did.
	gitConfig, err := os.ReadFile(filepath.Join(clone, ".git", "config"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(gitConfig), "fixture-installation-token") {
		t.Fatal("installation token leaked into the clone's git config")
	}
}

// TestGitRouteRefusesUntrustedClient pins the trust boundary from the other
// side: a client that does not trust the published CA cannot even complete
// a handshake with the git route.
func TestGitRouteRefusesUntrustedClient(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.NotFoundHandler()}
	go func() { _ = server.Serve(tls.NewListener(listener, ca.ServerTLSConfig())) }()
	t.Cleanup(func() { _ = server.Close() })

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12},
	}}
	_, err = client.Get("https://" + listener.Addr().String() + "/")
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected certificate verification failure, got %v", err)
	}
}
