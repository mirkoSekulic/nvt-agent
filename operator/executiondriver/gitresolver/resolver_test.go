package gitresolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const remoteOutputCanary = "REMOTE-SECRET-CANARY"

var (
	testGitPath       string
	testWrapperBinary string
)

type wrapperConfig struct {
	RealGit      string `json:"real_git"`
	LogPath      string `json:"log_path"`
	Mode         string `json:"mode"`
	MutationPath string `json:"mutation_path"`
	PIDPath      string `json:"pid_path"`
}

type recordedInvocation struct {
	Arguments   []string `json:"arguments"`
	Environment []string `json:"environment"`
}

type repositoryFixture struct {
	t              *testing.T
	root           string
	work           string
	bare           string
	revision       string
	artifactMarker string
	server         *httptest.Server
	baseURL        string
	port           uint16
	requests       atomic.Int64
	infoRequests   atomic.Int64
}

type resolverFixture struct {
	repository *repositoryFixture
	resolver   *Resolver
	cache      string
	wrapper    string
	logPath    string
	pidPath    string
	source     Source
}

func TestMain(testMain *testing.M) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		fmt.Fprintln(os.Stderr, "git is required for execution-driver Git resolver tests")
		os.Exit(1)
	}
	testGitPath, err = filepath.Abs(gitPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve Git executable")
		os.Exit(1)
	}
	temporary, err := os.MkdirTemp("", "nvt-execution-driver-git-resolver-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "create Git resolver test directory")
		os.Exit(1)
	}
	testWrapperBinary = filepath.Join(temporary, "git-wrapper")
	build := exec.Command("go", "build", "-trimpath", "-o", testWrapperBinary, "./testdata/git-wrapper")
	if output, buildErr := build.CombinedOutput(); buildErr != nil {
		fmt.Fprintf(os.Stderr, "build Git resolver wrapper: %v\n%s", buildErr, output)
		_ = os.RemoveAll(temporary)
		os.Exit(1)
	}
	exitCode := testMain.Run()
	if err := os.RemoveAll(temporary); err != nil && exitCode == 0 {
		fmt.Fprintln(os.Stderr, "remove Git resolver test directory")
		exitCode = 1
	}
	os.Exit(exitCode)
}

func TestResolveAcquiresCachesAndNeverStartsArtifact(t *testing.T) {
	fixture := newResolverFixture(t, "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", remoteOutputCanary)
	t.Setenv("HTTPS_PROXY", "https://user:"+remoteOutputCanary+"@proxy.invalid")
	ambientMarker := filepath.Join(t.TempDir(), "ambient-command-ran")
	ambientCommand := filepath.Join(t.TempDir(), "ambient-command")
	if err := os.WriteFile(ambientCommand, []byte(fmt.Sprintf("#!/bin/sh\ntouch %q\ncat\n", ambientMarker)), 0o700); err != nil {
		t.Fatal(err)
	}
	ambientHooks := t.TempDir()
	if err := os.WriteFile(filepath.Join(ambientHooks, "post-checkout"), []byte(fmt.Sprintf("#!/bin/sh\ntouch %q\n", ambientMarker)), 0o700); err != nil {
		t.Fatal(err)
	}
	ambientConfig := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(ambientConfig, []byte(fmt.Sprintf("[filter \"evil\"]\n\tsmudge = %s\n[credential]\n\thelper = %s\n[core]\n\thooksPath = %s\n", ambientCommand, ambientCommand, ambientHooks)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", ambientConfig)

	first, err := fixture.resolver.Resolve(testContext(t), fixture.source)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	requireArtifact(t, first, fixture)
	if _, err := os.Stat(fixture.repository.artifactMarker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resolver started selected driver: %v", err)
	}
	if _, err := os.Stat(ambientMarker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resolver ran an ambient hook/filter/credential helper: %v", err)
	}
	requests := fixture.repository.requests.Load()
	infoRequests := fixture.repository.infoRequests.Load()
	second, err := fixture.resolver.Resolve(testContext(t), fixture.source)
	if err != nil {
		t.Fatalf("cached resolve: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("cache descriptor changed:\nfirst=%#v\nsecond=%#v", first, second)
	}
	if fixture.repository.requests.Load() != requests || fixture.repository.infoRequests.Load() != infoRequests {
		t.Fatal("cache reuse contacted the remote repository")
	}

	changed := fixture.source
	changed.Command = []string{"driver", "--mode", "other"}
	third, err := fixture.resolver.Resolve(testContext(t), changed)
	if err != nil {
		t.Fatalf("resolve command-specific artifact: %v", err)
	}
	if third.CacheKey == first.CacheKey || third.ExecutablePath == first.ExecutablePath {
		t.Fatalf("artifact cache identity ignored command fields: first=%#v third=%#v", first, third)
	}
	if fixture.repository.infoRequests.Load() != infoRequests+1 {
		t.Fatalf("new complete source did not acquire independently: before=%d after=%d", infoRequests, fixture.repository.infoRequests.Load())
	}
	requireCleanGitContract(t, readInvocations(t, fixture.logPath))
}

func TestCacheIdentityIncludesEveryArtifactSourceField(t *testing.T) {
	fixture := newResolverFixture(t, "")
	base, err := fixture.resolver.normalizeSource(fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	variants := []Source{
		withURL(fixture.source, fixture.repository.baseURL+"/other.git"),
		withRevision(fixture.source, strings.Repeat("0", len(fixture.source.Git.Revision))),
		withSubdirectory(fixture.source, "drivers/other"),
		withCommand(fixture.source, []string{"other-driver", "--mode", "test"}),
		withCommand(fixture.source, []string{"driver", "--mode", "different"}),
	}
	seen := map[string]struct{}{base.CacheKey: {}}
	for index, source := range variants {
		normalized, err := fixture.resolver.normalizeSource(source)
		if err != nil {
			t.Fatalf("variant %d: %v", index, err)
		}
		if _, duplicate := seen[normalized.CacheKey]; duplicate {
			t.Fatalf("variant %d did not affect cache identity", index)
		}
		seen[normalized.CacheKey] = struct{}{}
	}
}

func TestResolveConcurrentCallersPublishOneArtifact(t *testing.T) {
	fixture := newResolverFixture(t, "")
	const callers = 16
	artifacts := make(chan Artifact, callers)
	errorsFound := make(chan error, callers)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := 0; index < callers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			artifact, err := fixture.resolver.Resolve(testContext(t), fixture.source)
			if err != nil {
				errorsFound <- err
				return
			}
			artifacts <- artifact
		}()
	}
	close(start)
	wait.Wait()
	close(artifacts)
	close(errorsFound)
	for err := range errorsFound {
		t.Fatalf("concurrent resolve: %v", err)
	}
	var expected Artifact
	count := 0
	for artifact := range artifacts {
		if count == 0 {
			expected = artifact
		} else if !reflect.DeepEqual(expected, artifact) {
			t.Fatalf("concurrent descriptor mismatch: expected=%#v actual=%#v", expected, artifact)
		}
		count++
	}
	if count != callers {
		t.Fatalf("resolved artifacts=%d, want %d", count, callers)
	}
	if requests := fixture.repository.infoRequests.Load(); requests != 1 {
		t.Fatalf("concurrent acquisition count=%d, want 1", requests)
	}
}

func TestResolveRejectsDisallowedURLsAndMutableSourcesBeforeGit(t *testing.T) {
	fixture := newResolverFixture(t, "")
	valid := fixture.source
	parsed, err := url.Parse(fixture.repository.baseURL)
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string]Source{
		"http":                 withURL(valid, strings.Replace(valid.Git.URL, "https://", "http://", 1)),
		"ssh":                  withURL(valid, "ssh://localhost/repo.git"),
		"git":                  withURL(valid, "git://localhost/repo.git"),
		"userinfo":             withURL(valid, "https://user:secret@"+parsed.Host+"/repo.git"),
		"query":                withURL(valid, valid.Git.URL+"?ref=main"),
		"fragment":             withURL(valid, valid.Git.URL+"#main"),
		"wrong host":           withURL(valid, "https://git.invalid/repo.git"),
		"unlisted subdomain":   withURL(valid, "https://sub.localhost:"+parsed.Port()+"/repo.git"),
		"IP literal":           withURL(valid, strings.Replace(valid.Git.URL, "localhost", "127.0.0.1", 1)),
		"unapproved port":      withURL(valid, "https://localhost:444/repo.git"),
		"uppercase host":       withURL(valid, strings.Replace(valid.Git.URL, "localhost", "LOCALHOST", 1)),
		"trailing host dot":    withURL(valid, strings.Replace(valid.Git.URL, "localhost", "localhost.", 1)),
		"encoded path":         withURL(valid, fixture.repository.baseURL+"/repo%2egit"),
		"dot path":             withURL(valid, fixture.repository.baseURL+"/one/../repo.git"),
		"duplicate slash":      withURL(valid, fixture.repository.baseURL+"//repo.git"),
		"branch":               withRevision(valid, "main"),
		"abbreviated revision": withRevision(valid, valid.Git.Revision[:12]),
		"uppercase revision":   withRevision(valid, strings.ToUpper(valid.Git.Revision)),
		"empty subdirectory":   withSubdirectory(valid, ""),
		"subdirectory escape":  withSubdirectory(valid, "../driver"),
		"absolute executable":  withCommand(valid, []string{"/bin/driver"}),
		"command escape":       withCommand(valid, []string{"../driver"}),
		"invalid argument":     withCommand(valid, []string{"driver", "bad\x00argument"}),
	}
	for name, source := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := fixture.resolver.Resolve(testContext(t), source)
			if !errors.Is(err, ErrInvalidSource) {
				t.Fatalf("error=%v, want ErrInvalidSource", err)
			}
			if strings.Contains(err.Error(), source.Git.URL) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("source error disclosed input: %v", err)
			}
		})
	}
	if invocations := readInvocations(t, fixture.logPath); len(invocations) != 0 {
		t.Fatalf("invalid source started Git %d times", len(invocations))
	}
}

func TestResolveRejectsRedirectCommitMismatchAndWrongObjectType(t *testing.T) {
	t.Run("redirect", func(t *testing.T) {
		fixture := newResolverFixture(t, "")
		source := fixture.source
		source.Git.URL = fixture.repository.baseURL + "/redirect/repo.git"
		_, err := fixture.resolver.Resolve(testContext(t), source)
		if !errors.Is(err, ErrAcquisition) {
			t.Fatalf("redirect error=%v", err)
		}
		if fixture.repository.requests.Load() == 0 {
			t.Fatal("redirect fixture was not contacted")
		}
	})
	for _, mode := range []string{"mismatch", "wrong-type"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newResolverFixture(t, mode)
			_, err := fixture.resolver.Resolve(testContext(t), fixture.source)
			if !errors.Is(err, ErrAcquisition) {
				t.Fatalf("verification error=%v", err)
			}
			requireNoPublishedOrTemporary(t, fixture)
		})
	}
}

func TestResolveRejectsUnsafeOrUnavailableArtifacts(t *testing.T) {
	tests := []struct {
		name   string
		mode   string
		mutate func(Source) Source
		want   error
	}{
		{"escaping executable symlink", "", func(source Source) Source { return withCommand(source, []string{"escape"}) }, ErrInvalidArtifact},
		{"escaping intermediate symlink", "", func(source Source) Source { return withCommand(source, []string{"escape-dir/driver"}) }, ErrInvalidArtifact},
		{"escaping subdirectory symlink", "", func(source Source) Source {
			source.Git.Subdir = "drivers/escape-dir"
			return source
		}, ErrInvalidArtifact},
		{"missing subdirectory", "", func(source Source) Source {
			source.Git.Subdir = "drivers/missing"
			return source
		}, ErrInvalidArtifact},
		{"missing executable", "", func(source Source) Source { return withCommand(source, []string{"missing"}) }, ErrInvalidArtifact},
		{"non-executable file", "", func(source Source) Source { return withCommand(source, []string{"nonexec"}) }, ErrInvalidArtifact},
		{"LFS pointer", "", func(source Source) Source { return withCommand(source, []string{"lfs-driver"}) }, ErrInvalidArtifact},
		{"special file", "special-artifact", func(source Source) Source { return source }, ErrInvalidArtifact},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newResolverFixture(t, test.mode)
			fixture.source = test.mutate(fixture.source)
			_, err := fixture.resolver.Resolve(testContext(t), fixture.source)
			if !errors.Is(err, test.want) {
				t.Fatalf("error=%v, want %v", err, test.want)
			}
			requireNoPublishedOrTemporary(t, fixture)
		})
	}
}

func TestResolveRejectsSubmodulesAndResourceOverflow(t *testing.T) {
	t.Run("submodule", func(t *testing.T) {
		repository := newRepositoryFixture(t)
		repository.addGitlink()
		repository.startServer()
		fixture := newResolverForRepository(t, repository, "", nil)
		_, err := fixture.resolver.Resolve(testContext(t), fixture.source)
		if !errors.Is(err, ErrAcquisition) {
			t.Fatalf("gitlink error=%v", err)
		}
	})
	t.Run("resource bound", func(t *testing.T) {
		fixture := newResolverFixture(t, "", func(config *Config) {
			config.MaxCacheBytes = 1024
		})
		_, err := fixture.resolver.Resolve(testContext(t), fixture.source)
		if !errors.Is(err, ErrCache) {
			t.Fatalf("resource error=%v", err)
		}
		requireNoPublishedOrTemporary(t, fixture)
	})
}

func TestResolveTimeoutProcessFailureAndOutputRemainBounded(t *testing.T) {
	t.Run("timeout reaps process group", func(t *testing.T) {
		fixture := newResolverFixture(t, "hang", func(config *Config) {
			config.Timeout = 120 * time.Millisecond
		})
		started := time.Now()
		_, err := fixture.resolver.Resolve(context.Background(), fixture.source)
		if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrAcquisition) {
			t.Fatalf("timeout error=%v", err)
		}
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Fatalf("timeout was not bounded: %s", elapsed)
		}
		for _, path := range []string{fixture.pidPath, fixture.pidPath + ".child"} {
			pid := waitForPID(t, path)
			requireProcessGone(t, pid)
		}
		requireNoPublishedOrTemporary(t, fixture)
	})
	for _, mode := range []string{"fail", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newResolverFixture(t, mode)
			_, err := fixture.resolver.Resolve(testContext(t), fixture.source)
			if !errors.Is(err, ErrAcquisition) {
				t.Fatalf("process error=%v", err)
			}
			if strings.Contains(err.Error(), remoteOutputCanary) || strings.Contains(err.Error(), fixture.source.Git.URL) || len(err.Error()) > 256 {
				t.Fatalf("error was not bounded and redacted: %q", err)
			}
			requireNoPublishedOrTemporary(t, fixture)
		})
	}
}

func TestResolveRevalidatesCacheAndCleansInterruptedState(t *testing.T) {
	fixture := newResolverFixture(t, "")
	artifact, err := fixture.resolver.Resolve(testContext(t), fixture.source)
	if err != nil {
		t.Fatalf("initial resolve: %v", err)
	}
	initialFetches := fixture.repository.infoRequests.Load()
	stale := filepath.Join(fixture.cache, "."+artifact.CacheKey+".tmp-interrupted")
	if err := os.Mkdir(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.resolver.Resolve(testContext(t), fixture.source); err != nil {
		t.Fatalf("resolve with stale temporary: %v", err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale temporary was not removed: %v", err)
	}
	if fixture.repository.infoRequests.Load() != initialFetches {
		t.Fatal("stale temporary forced unnecessary reacquisition")
	}

	metadata := filepath.Join(fixture.cache, artifact.CacheKey, ".git", completionFileName)
	if err := os.WriteFile(metadata, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.resolver.Resolve(testContext(t), fixture.source); err != nil {
		t.Fatalf("recover tampered metadata: %v", err)
	}
	if fixture.repository.infoRequests.Load() != initialFetches+1 {
		t.Fatal("tampered completion metadata was reused")
	}

	if err := os.WriteFile(artifact.ExecutablePath, []byte("tampered\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.resolver.Resolve(testContext(t), fixture.source); err != nil {
		t.Fatalf("recover tampered checkout: %v", err)
	}
	if fixture.repository.infoRequests.Load() != initialFetches+2 {
		t.Fatal("tampered checkout was reused")
	}
}

func TestResolverConfigurationFailsClosed(t *testing.T) {
	temporary := t.TempDir()
	executable := filepath.Join(temporary, "git")
	if err := os.WriteFile(executable, []byte("not executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []Config{
		{},
		{CacheDirectory: temporary, AllowedHosts: []string{"github.com"}, GitExecutable: "git"},
		{CacheDirectory: temporary, AllowedHosts: []string{"*.github.com"}, GitExecutable: testGitPath},
		{CacheDirectory: temporary, AllowedHosts: []string{"github.com", "github.com"}, GitExecutable: testGitPath},
		{CacheDirectory: temporary, AllowedHosts: []string{"github.com"}, AllowedPorts: []uint16{443, 443}, GitExecutable: testGitPath},
		{CacheDirectory: temporary, AllowedHosts: []string{"github.com"}, GitExecutable: executable},
		{CacheDirectory: temporary, AllowedHosts: []string{"github.com"}, GitExecutable: testGitPath, Timeout: 11 * time.Minute},
	}
	for index, config := range tests {
		if resolver, err := New(config); resolver != nil || !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("case %d resolver=%v error=%v", index, resolver, err)
		}
	}
}

func newResolverFixture(t *testing.T, mode string, mutate ...func(*Config)) *resolverFixture {
	t.Helper()
	repository := newRepositoryFixture(t)
	repository.startServer()
	return newResolverForRepository(t, repository, mode, mutate)
}

func newResolverForRepository(t *testing.T, repository *repositoryFixture, mode string, mutate []func(*Config)) *resolverFixture {
	t.Helper()
	root := t.TempDir()
	wrapper := filepath.Join(root, "git-wrapper")
	copyFile(t, testWrapperBinary, wrapper, 0o700)
	logPath := filepath.Join(root, "git-invocations.jsonl")
	pidPath := filepath.Join(root, "git.pid")
	configuration := wrapperConfig{
		RealGit:      testGitPath,
		LogPath:      logPath,
		Mode:         mode,
		MutationPath: filepath.FromSlash("drivers/fake/driver"),
		PIDPath:      pidPath,
	}
	writeJSON(t, wrapper+".json", configuration)
	cache := filepath.Join(root, "cache")
	config := Config{
		CacheDirectory:  cache,
		AllowedHosts:    []string{"localhost"},
		AllowedPorts:    []uint16{repository.port},
		GitExecutable:   wrapper,
		Timeout:         5 * time.Second,
		MaxCacheEntries: 4096,
		MaxCacheBytes:   128 << 20,
	}
	for _, change := range mutate {
		change(&config)
	}
	resolver, err := New(config)
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	return &resolverFixture{
		repository: repository,
		resolver:   resolver,
		cache:      cache,
		wrapper:    wrapper,
		logPath:    logPath,
		pidPath:    pidPath,
		source: Source{
			Git: GitSource{
				URL:      repository.baseURL + "/repo.git",
				Revision: repository.revision,
				Subdir:   "drivers/fake",
			},
			Command: []string{"driver", "--mode", "test"},
		},
	}
}

func newRepositoryFixture(t *testing.T) *repositoryFixture {
	t.Helper()
	root := t.TempDir()
	work := filepath.Join(root, "work")
	bare := filepath.Join(root, "repositories", "repo.git")
	if err := os.MkdirAll(filepath.Dir(bare), 0o700); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "init", "--quiet", work)
	runGit(t, work, "config", "user.name", "Resolver Fixture")
	runGit(t, work, "config", "user.email", "resolver@example.invalid")
	driverDirectory := filepath.Join(work, "drivers", "fake")
	if err := os.MkdirAll(driverDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "driver-started")
	driver := filepath.Join(driverDirectory, "driver")
	if err := os.WriteFile(driver, []byte(fmt.Sprintf("#!/bin/sh\nprintf started > %q\n", marker)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(driverDirectory, "nonexec"), []byte("not executable\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(driverDirectory, "lfs-driver"), append(append([]byte(nil), lfsHeader...), []byte("\noid sha256:"+strings.Repeat("0", 64)+"\nsize 1\n")...), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, ".gitattributes"), []byte("drivers/fake/driver filter=evil\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside-driver")
	if err := os.WriteFile(outside, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(driverDirectory, "escape")); err != nil {
		t.Fatal(err)
	}
	outsideDirectory := filepath.Join(root, "outside-directory")
	if err := os.Mkdir(outsideDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outsideDirectory, "driver"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDirectory, filepath.Join(driverDirectory, "escape-dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDirectory, filepath.Join(work, "drivers", "escape-dir")); err != nil {
		t.Fatal(err)
	}
	runGit(t, work, "add", "--all")
	runGit(t, work, "commit", "--quiet", "-m", "fixture")
	revision := strings.TrimSpace(runGit(t, work, "rev-parse", "HEAD"))
	runGit(t, root, "clone", "--quiet", "--bare", work, bare)
	runGit(t, root, "--git-dir", bare, "config", "http.receivepack", "false")
	runGit(t, root, "--git-dir", bare, "config", "uploadpack.allowReachableSHA1InWant", "true")
	return &repositoryFixture{t: t, root: root, work: work, bare: bare, revision: revision, artifactMarker: marker}
}

func (f *repositoryFixture) addGitlink() {
	f.t.Helper()
	runGit(f.t, f.work, "update-index", "--add", "--cacheinfo", "160000,"+f.revision+",drivers/fake/nested")
	runGit(f.t, f.work, "commit", "--quiet", "-m", "gitlink")
	f.revision = strings.TrimSpace(runGit(f.t, f.work, "rev-parse", "HEAD"))
	runGit(f.t, f.work, "push", "--quiet", "--force", f.bare, "HEAD:refs/heads/master")
}

func (f *repositoryFixture) startServer() {
	f.t.Helper()
	backend := &cgi.Handler{
		Path: testGitPath,
		Args: []string{"http-backend"},
		Dir:  f.root,
		Env: []string{
			"GIT_PROJECT_ROOT=" + filepath.Dir(f.bare),
			"GIT_HTTP_EXPORT_ALL=1",
		},
		Stderr: io.Discard,
	}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		f.requests.Add(1)
		if strings.Contains(request.URL.Path, "/info/refs") {
			f.infoRequests.Add(1)
		}
		if strings.HasPrefix(request.URL.Path, "/redirect/") {
			target := "/" + strings.TrimPrefix(request.URL.Path, "/redirect/")
			if request.URL.RawQuery != "" {
				target += "?" + request.URL.RawQuery
			}
			http.Redirect(response, request, target, http.StatusFound)
			return
		}
		backend.ServeHTTP(response, request)
	})
	f.server = httptest.NewTLSServer(handler)
	f.t.Cleanup(f.server.Close)
	parsed, err := url.Parse(f.server.URL)
	if err != nil {
		f.t.Fatal(err)
	}
	port, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil {
		f.t.Fatal(err)
	}
	f.port = uint16(port)
	f.baseURL = "https://localhost:" + parsed.Port()
}

func requireArtifact(t *testing.T, artifact Artifact, fixture *resolverFixture) {
	t.Helper()
	if !filepath.IsAbs(artifact.ExecutablePath) || artifact.Revision != fixture.source.Git.Revision || artifact.CacheKey == "" {
		t.Fatalf("invalid descriptor: %#v", artifact)
	}
	if !reflect.DeepEqual(artifact.Arguments, fixture.source.Command[1:]) {
		t.Fatalf("arguments=%q, want %q", artifact.Arguments, fixture.source.Command[1:])
	}
	info, err := os.Lstat(artifact.ExecutablePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("resolved executable is invalid: %v %#v", err, info)
	}
	if !containedPath(fixture.cache, artifact.ExecutablePath) || !containedPath(fixture.cache, artifact.SourceDirectory) {
		t.Fatalf("artifact escaped cache: %#v", artifact)
	}
}

func requireCleanGitContract(t *testing.T, invocations []recordedInvocation) {
	t.Helper()
	if len(invocations) == 0 {
		t.Fatal("Git was not invoked")
	}
	expectedEnvironment := []string{
		"GCM_INTERACTIVE=Never",
		"GIT_ASKPASS=/bin/false",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_LFS_SKIP_SMUDGE=1",
		"GIT_PROTOCOL_FROM_USER=0",
		"GIT_TERMINAL_PROMPT=0",
		"HOME=/nonexistent",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"SSH_ASKPASS=/bin/false",
		"TZ=UTC",
	}
	sort.Strings(expectedEnvironment)
	for index, invocation := range invocations {
		actualEnvironment := append([]string(nil), invocation.Environment...)
		sort.Strings(actualEnvironment)
		if !reflect.DeepEqual(actualEnvironment, expectedEnvironment) {
			t.Fatalf("invocation %d environment:\nactual=%q\nexpected=%q", index, actualEnvironment, expectedEnvironment)
		}
		if len(invocation.Arguments) < len(fixedGitOptions) || !reflect.DeepEqual(invocation.Arguments[:len(fixedGitOptions)], fixedGitOptions) {
			t.Fatalf("invocation %d missing fixed Git policy: %q", index, invocation.Arguments)
		}
		joined := strings.Join(invocation.Arguments, " ")
		for _, forbidden := range []string{"submodule update", "git-lfs", remoteOutputCanary} {
			if strings.Contains(joined, forbidden) {
				t.Fatalf("invocation %d contains forbidden behavior %q: %s", index, forbidden, joined)
			}
		}
		command := invocation.Arguments[len(fixedGitOptions)]
		switch command {
		case "init", "remote", "fetch", "rev-parse", "cat-file", "checkout", "fsck", "ls-files", "diff-index":
		default:
			t.Fatalf("invocation %d ran an unapproved Git operation %q", index, command)
		}
	}
}

func requireNoPublishedOrTemporary(t *testing.T, fixture *resolverFixture) {
	t.Helper()
	normalized, err := fixture.resolver.normalizeSource(fixture.source)
	if err != nil {
		t.Fatalf("normalize fixture source: %v", err)
	}
	if _, err := os.Stat(filepath.Join(fixture.cache, normalized.CacheKey)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed source was published: %v", err)
	}
	entries, err := os.ReadDir(fixture.cache)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "."+normalized.CacheKey+".tmp-") {
			t.Fatalf("incomplete temporary cache remains: %s", entry.Name())
		}
	}
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	context, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return context
}

func runGit(t *testing.T, directory string, arguments ...string) string {
	t.Helper()
	command := exec.Command(testGitPath, arguments...)
	command.Dir = directory
	command.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_DATE=2000-01-01T00:00:00Z",
		"GIT_COMMITTER_DATE=2000-01-01T00:00:00Z",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %q: %v\n%s", arguments, err, output)
	}
	return string(output)
}

func writeJSON(t *testing.T, file string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

func copyFile(t *testing.T, source, destination string, mode os.FileMode) {
	t.Helper()
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, contents, mode); err != nil {
		t.Fatal(err)
	}
}

func readInvocations(t *testing.T, file string) []recordedInvocation {
	t.Helper()
	handle, err := os.Open(file)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	decoder := json.NewDecoder(handle)
	var values []recordedInvocation
	for decoder.More() {
		var value recordedInvocation
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		values = append(values, value)
	}
	return values
}

func waitForPID(t *testing.T, file string) int {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		contents, err := os.ReadFile(file)
		if err == nil {
			pid, conversionErr := strconv.Atoi(strings.TrimSpace(string(contents)))
			if conversionErr == nil && pid > 0 {
				return pid
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("PID file was not populated: %s", file)
	return 0
}

func requireProcessGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process %d remains after acquisition timeout", pid)
}

func withURL(source Source, value string) Source {
	source.Git.URL = value
	return source
}

func withRevision(source Source, value string) Source {
	source.Git.Revision = value
	return source
}

func withSubdirectory(source Source, value string) Source {
	source.Git.Subdir = value
	return source
}

func withCommand(source Source, value []string) Source {
	source.Command = value
	return source
}
