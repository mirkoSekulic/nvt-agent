// Package gitresolver acquires one explicitly selected executable artifact from
// an immutable public HTTPS Git source. It is topology-neutral and deliberately
// independent from execution-driver process hosting and AgentRun reconciliation.
package gitresolver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	cacheFormatVersion        = 1
	defaultTimeout            = 2 * time.Minute
	maximumTimeout            = 10 * time.Minute
	defaultMaxEntries         = 4096
	maximumMaxEntries         = 100000
	defaultMaxBytes     int64 = 128 << 20
	maximumMaxBytes     int64 = 4 << 30
	maxSourceFieldBytes       = 4096
	maxCommandArguments       = 128
	maxCommandBytes           = 16 << 10
	maxGitOutputBytes         = 4 << 20
	maxMetadataBytes          = 32 << 10
	maxDiagnosticBytes        = 4 << 10
	lockRetryInterval         = 10 * time.Millisecond
	processWaitDelay          = time.Second
	completionFileName        = "nvt-execution-driver-source.json"
)

var (
	// ErrInvalidConfiguration identifies invalid trusted resolver configuration.
	ErrInvalidConfiguration = errors.New("execution driver Git resolver configuration is invalid")
	// ErrInvalidSource identifies a malformed or disallowed source declaration.
	ErrInvalidSource = errors.New("execution driver Git source is invalid")
	// ErrAcquisition identifies a bounded Git transport or checkout failure.
	ErrAcquisition = errors.New("execution driver Git acquisition failed")
	// ErrInvalidArtifact identifies a missing, unsafe, or non-executable artifact.
	ErrInvalidArtifact = errors.New("execution driver Git artifact is invalid")
	// ErrCache identifies a local cache operation that failed closed.
	ErrCache = errors.New("execution driver Git cache operation failed")

	hostPattern     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
	revisionPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	lfsHeader       = []byte("version https://git-lfs.github.com/spec/v1")
)

// GitSource is one immutable unauthenticated HTTPS repository selection.
type GitSource struct {
	URL      string `json:"url"`
	Revision string `json:"revision"`
	Subdir   string `json:"subdir"`
}

// Source is the complete operator-approved artifact selection. Command[0] is
// a relative executable beneath Git.Subdir; remaining entries are inert
// arguments returned in the descriptor for a later process host.
type Source struct {
	Git     GitSource `json:"git"`
	Command []string  `json:"command"`
}

// Artifact is a verified immutable cache entry. Resolving an artifact never
// starts the executable.
type Artifact struct {
	ExecutablePath  string
	Arguments       []string
	SourceDirectory string
	Revision        string
	CacheKey        string
}

// Config is trusted host configuration, not an AgentRun or producer surface.
// AllowedPorts defaults to 443 when omitted. Non-standard HTTPS ports must be
// approved explicitly, for example by hermetic tests or an approved public
// HTTPS service.
type Config struct {
	CacheDirectory  string
	AllowedHosts    []string
	AllowedPorts    []uint16
	GitExecutable   string
	Timeout         time.Duration
	MaxCacheEntries int
	MaxCacheBytes   int64
}

// Resolver verifies and atomically caches immutable Git artifacts. It contains
// no execution-driver process or controller dependency.
type Resolver struct {
	cacheDirectory string
	allowedHosts   map[string]struct{}
	allowedPorts   map[uint16]struct{}
	timeout        time.Duration
	maxEntries     int
	maxBytes       int64
	git            gitRunner
}

type normalizedSource struct {
	URL      string   `json:"url"`
	Revision string   `json:"revision"`
	Subdir   string   `json:"subdir"`
	Command  []string `json:"command"`
	CacheKey string   `json:"-"`
}

type cacheMetadata struct {
	Version  int      `json:"version"`
	CacheKey string   `json:"cache_key"`
	URL      string   `json:"url"`
	Revision string   `json:"revision"`
	Subdir   string   `json:"subdir"`
	Command  []string `json:"command"`
}

type gitResult struct {
	Output   []byte
	ExitCode int
}

type gitRunner interface {
	Run(context.Context, string, int, ...string) (gitResult, error)
}

type executableGit struct {
	path string
}

// New validates trusted resolver configuration and prepares its private cache
// root. It does not access a repository or start a driver.
func New(config Config) (*Resolver, error) {
	validated, err := validateConfig(config)
	if err != nil {
		return nil, err
	}
	if err := ensureCacheRoot(validated.CacheDirectory); err != nil {
		return nil, err
	}
	hosts := make(map[string]struct{}, len(validated.AllowedHosts))
	for _, host := range validated.AllowedHosts {
		hosts[host] = struct{}{}
	}
	ports := make(map[uint16]struct{}, len(validated.AllowedPorts))
	for _, port := range validated.AllowedPorts {
		ports[port] = struct{}{}
	}
	return &Resolver{
		cacheDirectory: validated.CacheDirectory,
		allowedHosts:   hosts,
		allowedPorts:   ports,
		timeout:        validated.Timeout,
		maxEntries:     validated.MaxCacheEntries,
		maxBytes:       validated.MaxCacheBytes,
		git:            executableGit{path: validated.GitExecutable},
	}, nil
}

func validateConfig(config Config) (Config, error) {
	if config.CacheDirectory == "" || !filepath.IsAbs(config.CacheDirectory) || strings.IndexByte(config.CacheDirectory, 0) >= 0 {
		return Config{}, ErrInvalidConfiguration
	}
	if config.GitExecutable == "" || !filepath.IsAbs(config.GitExecutable) || strings.IndexByte(config.GitExecutable, 0) >= 0 {
		return Config{}, ErrInvalidConfiguration
	}
	gitInfo, err := os.Lstat(config.GitExecutable)
	if err != nil || !gitInfo.Mode().IsRegular() || gitInfo.Mode().Perm()&0o111 == 0 {
		return Config{}, ErrInvalidConfiguration
	}
	if len(config.AllowedHosts) == 0 {
		return Config{}, ErrInvalidConfiguration
	}
	hosts := make([]string, 0, len(config.AllowedHosts))
	seenHosts := make(map[string]struct{}, len(config.AllowedHosts))
	for _, configured := range config.AllowedHosts {
		host := strings.ToLower(configured)
		if host != configured || !validDNSHost(host) || net.ParseIP(host) != nil {
			return Config{}, ErrInvalidConfiguration
		}
		if _, duplicate := seenHosts[host]; duplicate {
			return Config{}, ErrInvalidConfiguration
		}
		seenHosts[host] = struct{}{}
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	ports := append([]uint16(nil), config.AllowedPorts...)
	if len(ports) == 0 {
		ports = []uint16{443}
	}
	seenPorts := make(map[uint16]struct{}, len(ports))
	for _, port := range ports {
		if port == 0 {
			return Config{}, ErrInvalidConfiguration
		}
		if _, duplicate := seenPorts[port]; duplicate {
			return Config{}, ErrInvalidConfiguration
		}
		seenPorts[port] = struct{}{}
	}
	sort.Slice(ports, func(left, right int) bool { return ports[left] < ports[right] })
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	if config.Timeout < time.Millisecond || config.Timeout > maximumTimeout {
		return Config{}, ErrInvalidConfiguration
	}
	if config.MaxCacheEntries == 0 {
		config.MaxCacheEntries = defaultMaxEntries
	}
	if config.MaxCacheEntries < 1 || config.MaxCacheEntries > maximumMaxEntries {
		return Config{}, ErrInvalidConfiguration
	}
	if config.MaxCacheBytes == 0 {
		config.MaxCacheBytes = defaultMaxBytes
	}
	if config.MaxCacheBytes < 1 || config.MaxCacheBytes > maximumMaxBytes {
		return Config{}, ErrInvalidConfiguration
	}
	config.CacheDirectory = filepath.Clean(config.CacheDirectory)
	config.AllowedHosts = hosts
	config.AllowedPorts = ports
	return config, nil
}

func validDNSHost(host string) bool {
	if len(host) > 253 || strings.HasSuffix(host, ".") || !hostPattern.MatchString(host) {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

func ensureCacheRoot(root string) error {
	_, initialErr := os.Lstat(root)
	created := errors.Is(initialErr, os.ErrNotExist)
	if initialErr != nil && !created {
		return ErrCache
	}
	if created {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return ErrCache
		}
		// MkdirAll honors the process umask. Normalize only a cache root this
		// resolver created; an insecure pre-existing root fails closed below.
		if err := os.Chmod(root, 0o700); err != nil {
			return ErrCache
		}
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return ErrCache
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return ErrCache
	}
	return nil
}

// Resolve returns one verified artifact or a sanitized error. Concurrent
// callers for the same complete source converge through a process-safe lock.
func (r *Resolver) Resolve(ctx context.Context, source Source) (Artifact, error) {
	normalized, err := r.normalizeSource(source)
	if err != nil {
		return Artifact{}, err
	}
	resolveContext, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	lock, err := acquireFileLock(resolveContext, filepath.Join(r.cacheDirectory, normalized.CacheKey+".lock"))
	if err != nil {
		return Artifact{}, err
	}
	defer releaseFileLock(lock)
	if err := r.removeStaleTemporary(normalized.CacheKey); err != nil {
		return Artifact{}, err
	}

	destination := filepath.Join(r.cacheDirectory, normalized.CacheKey)
	artifact, valid, err := r.validatePublished(resolveContext, destination, normalized)
	if err != nil {
		return Artifact{}, err
	}
	if valid {
		return artifact, nil
	}
	if err := removeCachePath(destination); err != nil {
		return Artifact{}, err
	}
	return r.populate(resolveContext, destination, normalized)
}

func (r *Resolver) normalizeSource(source Source) (normalizedSource, error) {
	canonicalURL, err := r.validateURL(source.Git.URL)
	if err != nil || !revisionPattern.MatchString(source.Git.Revision) {
		return normalizedSource{}, ErrInvalidSource
	}
	if !validRelativeSourcePath(source.Git.Subdir, true) || len(source.Command) == 0 || len(source.Command) > maxCommandArguments {
		return normalizedSource{}, ErrInvalidSource
	}
	if !validRelativeSourcePath(source.Command[0], true) {
		return normalizedSource{}, ErrInvalidSource
	}
	commandBytes := 0
	command := append([]string(nil), source.Command...)
	for _, argument := range command {
		if !utf8.ValidString(argument) || strings.IndexByte(argument, 0) >= 0 {
			return normalizedSource{}, ErrInvalidSource
		}
		commandBytes += len(argument)
		if commandBytes > maxCommandBytes {
			return normalizedSource{}, ErrInvalidSource
		}
	}
	normalized := normalizedSource{
		URL:      canonicalURL,
		Revision: source.Git.Revision,
		Subdir:   source.Git.Subdir,
		Command:  command,
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return normalizedSource{}, ErrInvalidSource
	}
	digest := sha256.Sum256(encoded)
	normalized.CacheKey = hex.EncodeToString(digest[:])
	return normalized, nil
}

func (r *Resolver) validateURL(raw string) (string, error) {
	if raw == "" || len(raw) > maxSourceFieldBytes || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\x00\\%\r\n\t") {
		return "", ErrInvalidSource
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return "", ErrInvalidSource
	}
	host := parsed.Hostname()
	if host == "" || host != strings.ToLower(host) || !validDNSHost(host) || net.ParseIP(host) != nil {
		return "", ErrInvalidSource
	}
	if _, allowed := r.allowedHosts[host]; !allowed {
		return "", ErrInvalidSource
	}
	port := uint16(443)
	if rawPort := parsed.Port(); rawPort != "" {
		value, conversionErr := strconv.ParseUint(rawPort, 10, 16)
		if conversionErr != nil || value == 0 {
			return "", ErrInvalidSource
		}
		port = uint16(value)
	}
	if _, allowed := r.allowedPorts[port]; !allowed {
		return "", ErrInvalidSource
	}
	expectedAuthority := host
	if parsed.Port() != "" {
		expectedAuthority = net.JoinHostPort(host, strconv.Itoa(int(port)))
	}
	if parsed.Host != expectedAuthority {
		return "", ErrInvalidSource
	}
	if parsed.Path == "" || parsed.Path == "/" || !strings.HasPrefix(parsed.Path, "/") || path.Clean(parsed.Path) != parsed.Path || strings.Contains(parsed.Path, "//") || parsed.EscapedPath() != parsed.Path {
		return "", ErrInvalidSource
	}
	authority := host
	if port != 443 || parsed.Port() != "" {
		authority = net.JoinHostPort(host, strconv.Itoa(int(port)))
	}
	return (&url.URL{Scheme: "https", Host: authority, Path: parsed.Path}).String(), nil
}

func validRelativeSourcePath(value string, requireNonEmpty bool) bool {
	if !utf8.ValidString(value) || len(value) > maxSourceFieldBytes || strings.IndexByte(value, 0) >= 0 || strings.Contains(value, "\\") {
		return false
	}
	if requireNonEmpty && value == "" {
		return false
	}
	if value == "." || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || path.Clean(value) != value {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
		for _, character := range component {
			if character < 0x20 || character == 0x7f {
				return false
			}
		}
	}
	return true
}

func acquireFileLock(ctx context.Context, lockPath string) (*os.File, error) {
	fileDescriptor, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, ErrCache
	}
	lock := os.NewFile(uintptr(fileDescriptor), lockPath)
	if lock == nil {
		_ = syscall.Close(fileDescriptor)
		return nil, ErrCache
	}
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = lock.Close()
		return nil, ErrCache
	}
	for {
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return lock, nil
		} else if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = lock.Close()
			return nil, ErrCache
		}
		timer := time.NewTimer(lockRetryInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			_ = lock.Close()
			return nil, fmt.Errorf("%w: %w", ErrAcquisition, ctx.Err())
		case <-timer.C:
		}
	}
}

func releaseFileLock(lock *os.File) {
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	_ = lock.Close()
}

func (r *Resolver) populate(ctx context.Context, destination string, source normalizedSource) (Artifact, error) {
	temporary, err := os.MkdirTemp(r.cacheDirectory, "."+source.CacheKey+".tmp-")
	if err != nil {
		return Artifact{}, ErrCache
	}
	if err := os.Chmod(temporary, 0o700); err != nil {
		_ = os.RemoveAll(temporary)
		return Artifact{}, ErrCache
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(temporary)
		}
	}()
	objectFormat := "sha1"
	if len(source.Revision) == sha256.Size*2 {
		objectFormat = "sha256"
	}
	commands := [][]string{
		{"init", "--quiet", "--object-format=" + objectFormat},
		{"remote", "add", "origin", source.URL},
		{"fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "--depth=1", "origin", source.Revision},
	}
	for _, command := range commands {
		if _, err := r.requireGitSuccess(ctx, temporary, maxGitOutputBytes, command...); err != nil {
			return Artifact{}, err
		}
	}
	resolved, err := r.requireGitSuccess(ctx, temporary, 256, "rev-parse", "--verify", "FETCH_HEAD")
	if err != nil || strings.TrimSpace(string(resolved)) != source.Revision {
		return Artifact{}, ErrAcquisition
	}
	objectType, err := r.requireGitSuccess(ctx, temporary, 64, "cat-file", "-t", "FETCH_HEAD")
	if err != nil || strings.TrimSpace(string(objectType)) != "commit" {
		return Artifact{}, ErrAcquisition
	}
	peeled, err := r.requireGitSuccess(ctx, temporary, 256, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
	if err != nil || strings.TrimSpace(string(peeled)) != source.Revision {
		return Artifact{}, ErrAcquisition
	}
	for _, command := range [][]string{
		{"checkout", "--quiet", "--detach", "--no-recurse-submodules", source.Revision},
		{"remote", "remove", "origin"},
		{"fsck", "--strict", "--no-reflogs", "--no-dangling", source.Revision},
	} {
		if _, err := r.requireGitSuccess(ctx, temporary, maxGitOutputBytes, command...); err != nil {
			return Artifact{}, err
		}
	}
	staged, err := r.requireGitSuccess(ctx, temporary, maxGitOutputBytes, "ls-files", "--stage", "-z")
	if err != nil || containsGitlink(staged) {
		return Artifact{}, ErrAcquisition
	}
	if _, err := artifactFromCheckout(temporary, source); err != nil {
		return Artifact{}, err
	}
	metadata := expectedMetadata(source)
	if err := writeCompletionMetadata(temporary, metadata); err != nil {
		return Artifact{}, err
	}
	// Completion metadata is part of the published cache entry and therefore
	// must be included in both entry and byte accounting.
	if err := r.validateBounds(temporary); err != nil {
		return Artifact{}, err
	}
	if err := syncDirectory(temporary); err != nil {
		return Artifact{}, ErrCache
	}
	if err := os.Rename(temporary, destination); err != nil {
		return Artifact{}, ErrCache
	}
	published = true
	if err := syncDirectory(r.cacheDirectory); err != nil {
		return Artifact{}, ErrCache
	}
	artifact, err := artifactFromCheckout(destination, source)
	if err != nil {
		return Artifact{}, err
	}
	return artifact, nil
}

func (r *Resolver) validatePublished(ctx context.Context, checkout string, source normalizedSource) (Artifact, bool, error) {
	info, err := os.Lstat(checkout)
	if errors.Is(err, os.ErrNotExist) {
		return Artifact{}, false, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return Artifact{}, false, nil
	}
	gitInfo, err := os.Lstat(filepath.Join(checkout, ".git"))
	if err != nil || !gitInfo.IsDir() || gitInfo.Mode()&os.ModeSymlink != 0 {
		return Artifact{}, false, nil
	}
	metadataPath := filepath.Join(checkout, ".git", completionFileName)
	metadataBytes, err := readBoundedRegularFile(metadataPath, maxMetadataBytes)
	if err != nil || !bytes.Equal(metadataBytes, encodedMetadata(expectedMetadata(source))) {
		return Artifact{}, false, nil
	}
	for _, check := range []struct {
		arguments []string
		output    string
	}{
		{[]string{"rev-parse", "--verify", "HEAD"}, source.Revision},
		{[]string{"cat-file", "-t", "HEAD"}, "commit"},
	} {
		result, runErr := r.git.Run(ctx, checkout, 256, check.arguments...)
		if runErr != nil {
			return Artifact{}, false, sanitizeGitError(ctx, runErr)
		}
		if result.ExitCode != 0 || strings.TrimSpace(string(result.Output)) != check.output {
			return Artifact{}, false, nil
		}
	}
	for _, arguments := range [][]string{
		{"fsck", "--strict", "--no-reflogs", "--no-dangling", source.Revision},
		{"diff-index", "--quiet", "HEAD", "--"},
	} {
		result, runErr := r.git.Run(ctx, checkout, maxGitOutputBytes, arguments...)
		if runErr != nil {
			return Artifact{}, false, sanitizeGitError(ctx, runErr)
		}
		if result.ExitCode != 0 {
			return Artifact{}, false, nil
		}
	}
	untracked, runErr := r.git.Run(ctx, checkout, maxGitOutputBytes, "ls-files", "--others", "-z")
	if runErr != nil {
		return Artifact{}, false, sanitizeGitError(ctx, runErr)
	}
	if untracked.ExitCode != 0 || len(untracked.Output) != 0 {
		return Artifact{}, false, nil
	}
	staged, runErr := r.git.Run(ctx, checkout, maxGitOutputBytes, "ls-files", "--stage", "-z")
	if runErr != nil {
		return Artifact{}, false, sanitizeGitError(ctx, runErr)
	}
	if staged.ExitCode != 0 || containsGitlink(staged.Output) {
		return Artifact{}, false, nil
	}
	if err := r.validateBounds(checkout); err != nil {
		return Artifact{}, false, nil
	}
	artifact, err := artifactFromCheckout(checkout, source)
	if err != nil {
		return Artifact{}, false, nil
	}
	return artifact, true, nil
}

func (r *Resolver) requireGitSuccess(ctx context.Context, directory string, limit int, arguments ...string) ([]byte, error) {
	result, err := r.git.Run(ctx, directory, limit, arguments...)
	if err != nil {
		return nil, sanitizeGitError(ctx, err)
	}
	if result.ExitCode != 0 {
		return nil, ErrAcquisition
	}
	return result.Output, nil
}

func sanitizeGitError(ctx context.Context, err error) error {
	if contextError := ctx.Err(); contextError != nil {
		return fmt.Errorf("%w: %w", ErrAcquisition, contextError)
	}
	return ErrAcquisition
}

func (r *Resolver) validateBounds(root string) error {
	entries := 0
	var bytesUsed int64
	err := filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > r.maxEntries {
			return ErrCache
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		switch {
		case info.IsDir(), info.Mode().IsRegular():
			bytesUsed += info.Size()
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(current)
			if err != nil {
				return err
			}
			bytesUsed += int64(len(target))
		default:
			return ErrInvalidArtifact
		}
		if bytesUsed > r.maxBytes {
			return ErrCache
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrInvalidArtifact) {
			return ErrInvalidArtifact
		}
		return ErrCache
	}
	return nil
}

func artifactFromCheckout(checkout string, source normalizedSource) (Artifact, error) {
	checkoutRoot, err := filepath.EvalSymlinks(checkout)
	if err != nil {
		return Artifact{}, ErrInvalidArtifact
	}
	checkoutRoot, err = filepath.Abs(checkoutRoot)
	if err != nil {
		return Artifact{}, ErrInvalidArtifact
	}
	subdirectoryCandidate := filepath.Join(checkout, filepath.FromSlash(source.Subdir))
	subdirectory, err := filepath.EvalSymlinks(subdirectoryCandidate)
	if err != nil || !containedPath(checkoutRoot, subdirectory) {
		return Artifact{}, ErrInvalidArtifact
	}
	subdirectoryInfo, err := os.Stat(subdirectory)
	if err != nil || !subdirectoryInfo.IsDir() {
		return Artifact{}, ErrInvalidArtifact
	}
	executableCandidate := filepath.Join(subdirectory, filepath.FromSlash(source.Command[0]))
	executableInfo, err := os.Lstat(executableCandidate)
	if err != nil || !executableInfo.Mode().IsRegular() || executableInfo.Mode().Perm()&0o111 == 0 {
		return Artifact{}, ErrInvalidArtifact
	}
	executable, err := filepath.EvalSymlinks(executableCandidate)
	if err != nil {
		return Artifact{}, ErrInvalidArtifact
	}
	executable, err = filepath.Abs(executable)
	if err != nil || !containedPath(subdirectory, executable) || !containedPath(checkoutRoot, executable) {
		return Artifact{}, ErrInvalidArtifact
	}
	prefix, err := readFilePrefix(executable, len(lfsHeader))
	if err != nil || bytes.Equal(prefix, lfsHeader) {
		return Artifact{}, ErrInvalidArtifact
	}
	return Artifact{
		ExecutablePath:  executable,
		Arguments:       append([]string(nil), source.Command[1:]...),
		SourceDirectory: subdirectory,
		Revision:        source.Revision,
		CacheKey:        source.CacheKey,
	}, nil
}

func containedPath(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func readFilePrefix(file string, length int) ([]byte, error) {
	handle, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	buffer := make([]byte, length)
	count, err := io.ReadFull(handle, buffer)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	return buffer[:count], nil
}

func containsGitlink(staged []byte) bool {
	for _, record := range bytes.Split(staged, []byte{0}) {
		if bytes.HasPrefix(record, []byte("160000 ")) {
			return true
		}
	}
	return false
}

func expectedMetadata(source normalizedSource) cacheMetadata {
	return cacheMetadata{
		Version:  cacheFormatVersion,
		CacheKey: source.CacheKey,
		URL:      source.URL,
		Revision: source.Revision,
		Subdir:   source.Subdir,
		Command:  append([]string(nil), source.Command...),
	}
}

func encodedMetadata(metadata cacheMetadata) []byte {
	encoded, err := json.Marshal(metadata)
	if err != nil {
		panic("fixed execution-driver Git metadata failed to encode")
	}
	return append(encoded, '\n')
}

func writeCompletionMetadata(checkout string, metadata cacheMetadata) error {
	metadataPath := filepath.Join(checkout, ".git", completionFileName)
	file, err := os.OpenFile(metadataPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrCache
	}
	failed := true
	defer func() {
		_ = file.Close()
		if failed {
			_ = os.Remove(metadataPath)
		}
	}()
	if _, err := file.Write(encodedMetadata(metadata)); err != nil {
		return ErrCache
	}
	if err := file.Sync(); err != nil {
		return ErrCache
	}
	if err := file.Close(); err != nil {
		return ErrCache
	}
	failed = false
	return nil
}

func readBoundedRegularFile(file string, limit int) ([]byte, error) {
	info, err := os.Lstat(file)
	if err != nil || !info.Mode().IsRegular() || info.Size() > int64(limit) {
		return nil, ErrCache
	}
	contents, err := os.ReadFile(file)
	if err != nil || len(contents) > limit {
		return nil, ErrCache
	}
	return contents, nil
}

func syncDirectory(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

func removeCachePath(target string) error {
	if _, err := os.Lstat(target); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return ErrCache
	}
	if err := os.RemoveAll(target); err != nil {
		return ErrCache
	}
	return nil
}

func (r *Resolver) removeStaleTemporary(cacheKey string) error {
	entries, err := os.ReadDir(r.cacheDirectory)
	if err != nil {
		return ErrCache
	}
	prefix := "." + cacheKey + ".tmp-"
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			if err := os.RemoveAll(filepath.Join(r.cacheDirectory, entry.Name())); err != nil {
				return ErrCache
			}
		}
	}
	return nil
}

var fixedGitOptions = []string{
	"-c", "credential.helper=",
	"-c", "credential.interactive=false",
	"-c", "core.askPass=/bin/false",
	"-c", "core.hooksPath=/dev/null",
	"-c", "core.excludesFile=/dev/null",
	"-c", "core.fsmonitor=false",
	"-c", "core.untrackedCache=false",
	"-c", "http.followRedirects=false",
	"-c", "submodule.recurse=false",
	"-c", "filter.lfs.smudge=",
	"-c", "filter.lfs.clean=",
	"-c", "filter.lfs.process=",
	"-c", "filter.lfs.required=false",
	"-c", "protocol.file.allow=never",
	"-c", "protocol.ext.allow=never",
}

func (g executableGit) Run(ctx context.Context, directory string, outputLimit int, arguments ...string) (gitResult, error) {
	argv := make([]string, 0, len(fixedGitOptions)+len(arguments))
	argv = append(argv, fixedGitOptions...)
	argv = append(argv, arguments...)
	command := exec.CommandContext(ctx, g.path, argv...)
	command.Dir = directory
	command.Env = []string{
		"HOME=/nonexistent",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"TZ=UTC",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GCM_INTERACTIVE=Never",
		"GIT_ASKPASS=/bin/false",
		"SSH_ASKPASS=/bin/false",
		"GIT_LFS_SKIP_SMUDGE=1",
		"GIT_PROTOCOL_FROM_USER=0",
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	command.WaitDelay = processWaitDelay
	stdout := &boundedOutput{limit: outputLimit}
	stderr := &boundedDiagnostic{limit: maxDiagnosticBytes}
	command.Stdout = stdout
	command.Stderr = stderr
	command.Stdin = nil
	err := command.Run()
	if contextError := ctx.Err(); contextError != nil {
		return gitResult{}, contextError
	}
	if stdout.overflow {
		return gitResult{}, ErrAcquisition
	}
	if err == nil {
		return gitResult{Output: stdout.bytes(), ExitCode: 0}, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return gitResult{Output: stdout.bytes(), ExitCode: exitError.ExitCode()}, nil
	}
	return gitResult{}, ErrAcquisition
}

type boundedOutput struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (b *boundedOutput) Write(value []byte) (int, error) {
	if b.buffer.Len()+len(value) > b.limit {
		remaining := b.limit - b.buffer.Len()
		if remaining > 0 {
			_, _ = b.buffer.Write(value[:remaining])
		}
		b.overflow = true
		return 0, ErrAcquisition
	}
	return b.buffer.Write(value)
}

func (b *boundedOutput) bytes() []byte {
	return append([]byte(nil), b.buffer.Bytes()...)
}

type boundedDiagnostic struct {
	buffer bytes.Buffer
	limit  int
}

func (b *boundedDiagnostic) Write(value []byte) (int, error) {
	remaining := b.limit - b.buffer.Len()
	if remaining > 0 {
		keep := len(value)
		if keep > remaining {
			keep = remaining
		}
		_, _ = b.buffer.Write(value[:keep])
	}
	return len(value), nil
}
