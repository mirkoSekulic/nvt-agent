package hostbundle_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/bundle"
	"github.com/mirkoSekulic/nvt-agent/hostbundle/contract"
	"github.com/mirkoSekulic/nvt-agent/hostbundle/oci"
)

func TestNativeGuestLifecycleEndToEnd(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native guest lifecycle requires Linux")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	tmux, err := exec.LookPath("tmux")
	if err != nil {
		t.Skip("tmux is unavailable")
	}
	moduleRoot, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	repositoryRoot := filepath.Dir(moduleRoot)
	work := t.TempDir()
	binaries := filepath.Join(work, "bin")
	if err := os.MkdirAll(binaries, 0o755); err != nil {
		t.Fatal(err)
	}
	buildBinary(t, moduleRoot, "./cmd/nvt-guest-supervisor", filepath.Join(binaries, "nvt-guest-supervisor"))
	buildBinary(t, moduleRoot, "./cmd/nvt-host-bootstrap", filepath.Join(binaries, "nvt-host-bootstrap"))
	testBootstrap := filepath.Join(binaries, "nvt-host-bootstrap-test")
	buildBinaryWithTags(t, moduleRoot, "./cmd/nvt-host-bootstrap", testBootstrap, "hostbundletest")
	buildBinary(t, moduleRoot, "./cmd/nvt-guest-session-fixture", filepath.Join(binaries, "nvt-guest-session-fixture"))

	archive := filepath.Join(work, "nvt-host-bundle.tar.gz")
	manifest := contract.Manifest{
		ContractVersion: contract.Version, OS: "linux", Architecture: runtime.GOARCH,
		BundleVersion: "0.8.33-e2e", BuildID: strings.Repeat("a", 40),
		NativeEntrypoint: "bin/nvt-guest-supervisor", ServiceIdentity: "nvt-agent-guest.service",
		Compatibility: contract.Compatibility{AgentdProtocol: contract.AgentdProtocolVersion},
	}
	inputs := []bundle.InputFile{
		{Path: "bin/nvt-guest-supervisor", Source: filepath.Join(binaries, "nvt-guest-supervisor"), Mode: 0o755},
		{Path: "bin/nvt-host-bootstrap", Source: filepath.Join(binaries, "nvt-host-bootstrap"), Mode: 0o755},
		{Path: "bin/nvt-guest-session-fixture", Source: filepath.Join(binaries, "nvt-guest-session-fixture"), Mode: 0o755},
		{Path: "bin/agentd", Source: filepath.Join(repositoryRoot, "runtime", "agentd", "agentd.py"), Mode: 0o755},
		{Path: "bin/agentdctl", Source: filepath.Join(repositoryRoot, "runtime", "agentd", "agentdctl.py"), Mode: 0o755},
		{Path: "share/systemd/nvt-agent-guest.service", Source: filepath.Join(moduleRoot, "files", "nvt-agent-guest.service"), Mode: 0o644},
		{Path: "share/examples/guest.json", Source: filepath.Join(moduleRoot, "files", "guest.json"), Mode: 0o644},
	}
	if _, err := bundle.BuildArchive(archive, manifest, inputs); err != nil {
		t.Fatal(err)
	}
	layout := filepath.Join(work, "oci")
	digest, err := oci.BuildLayout(layout, manifest.BundleVersion, archive, "linux", runtime.GOARCH, map[string]string{
		"org.opencontainers.image.source":   "https://github.com/mirkoSekulic/nvt-agent",
		"org.opencontainers.image.revision": manifest.BuildID,
		"org.opencontainers.image.version":  manifest.BundleVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	server, _ := serveLayout(t, layout)
	defer server.Close()
	certificatePath := filepath.Join(work, "registry-ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(certificatePath, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(work, "opt", "nvt")
	repository := "https://example.com/nvt/host-bundle"
	bootstrapEnvironment := append(os.Environ(),
		"NVT_HOST_BUNDLE_TEST_EUID=0",
		"NVT_HOST_BUNDLE_TEST_CA_FILE="+certificatePath,
		"NVT_HOST_BUNDLE_TEST_DIAL_ADDRESS="+server.Listener.Addr().String(),
	)
	bootstrapArguments := []string{"--repository", repository, "--digest", digest, "--root", root, "--os", "linux", "--arch", runtime.GOARCH, "--timeout", "10s"}
	output, err := runBootstrap(testBootstrap, bootstrapEnvironment, bootstrapArguments...)
	if err != nil || !bytes.Contains(output, []byte("installed host bundle")) || !bytes.Contains(output, []byte(digest)) {
		t.Fatalf("bootstrap CLI install failed: %v %s", err, output)
	}

	wrongDigest := "sha256:" + strings.Repeat("f", 64)
	wrongOutput, wrongErr := runBootstrap(testBootstrap, bootstrapEnvironment,
		"--repository", repository, "--digest", wrongDigest, "--root", filepath.Join(work, "wrong"), "--timeout", "2s")
	if wrongErr == nil || bytes.Contains(wrongOutput, []byte(repository)) || bytes.Contains(wrongOutput, []byte(wrongDigest)) {
		t.Fatalf("wrong digest did not fail safely: %v %s", wrongErr, wrongOutput)
	}
	invalidOutput, invalidErr := runBootstrap(testBootstrap, bootstrapEnvironment,
		"--repository", repository, "--digest", digest, "--root", filepath.Join(work, "invalid"), "--timeout", "0s")
	if invalidErr == nil || !bytes.Contains(invalidOutput, []byte("invalid bootstrap configuration")) {
		t.Fatalf("invalid bootstrap configuration was accepted: %v %s", invalidErr, invalidOutput)
	}
	nonRootEnvironment := append([]string(nil), bootstrapEnvironment...)
	nonRootEnvironment = append(nonRootEnvironment, "NVT_HOST_BUNDLE_TEST_EUID=1000")
	nonRootPath := filepath.Join(work, "non-root")
	nonRootArguments := append([]string(nil), bootstrapArguments...)
	for index := range nonRootArguments {
		if index > 0 && nonRootArguments[index-1] == "--root" {
			nonRootArguments[index] = nonRootPath
		}
	}
	nonRootOutput, nonRootErr := runBootstrap(testBootstrap, nonRootEnvironment, nonRootArguments...)
	if nonRootErr == nil || !bytes.Contains(nonRootOutput, []byte("requires root")) {
		t.Fatalf("non-root bootstrap was accepted: %v %s", nonRootErr, nonRootOutput)
	}
	if _, err := os.Stat(nonRootPath); !os.IsNotExist(err) {
		t.Fatal("non-root bootstrap mutated the install root")
	}

	state := filepath.Join(work, "state")
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "run")
	for _, directory := range []string{state, workspace, runtimeDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	socket := filepath.Join(runtimeDir, "agentd.sock")
	capture := filepath.Join(state, "session-input.log")
	session := fmt.Sprintf("guest%d", time.Now().UnixNano())
	config := map[string]any{
		"version": 1, "python_path": python, "tmux_path": tmux,
		"state_dir": state, "socket_path": socket, "workspace": workspace,
		"session_name": session, "session_startup_grace_seconds": 0,
		"session_command": []string{"@release/bin/nvt-guest-session-fixture", "--output", capture},
	}
	configBytes, _ := json.Marshal(config)
	configPath := filepath.Join(work, "guest.json")
	if err := os.WriteFile(configPath, append(configBytes, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(root, "current")
	var logs bytes.Buffer
	start := func() (*exec.Cmd, chan error) {
		command := exec.Command(filepath.Join(current, "bin", "nvt-guest-supervisor"), "--config", configPath)
		command.Env = append(os.Environ(), "NVT_TEST_SECRET_CANARY=must-not-propagate")
		command.Stdout = &logs
		command.Stderr = &logs
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		waitForFile(t, filepath.Join(state, "guest-ready"), 15*time.Second)
		return command, done
	}
	stop := func(command *exec.Cmd, done chan error) {
		if err := command.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("supervisor stop failed: %v\n%s", err, logs.String())
			}
		case <-time.After(10 * time.Second):
			_ = command.Process.Kill()
			t.Fatal("supervisor did not stop")
		}
	}

	command, done := start()
	assertAgentdHealthAndPrompt(t, current, socket, state, capture, "first-native-prompt")
	stop(command, done)
	command, done = start()
	assertAgentdHealthAndPrompt(t, current, socket, state, capture, "restart-native-prompt")
	stop(command, done)
	command, done = start()
	assertAgentdHealthAndPrompt(t, current, socket, state, capture, "session-exit-prompt")
	kill := exec.Command(tmux, "kill-session", "-t", session)
	kill.Env = []string{"HOME=" + state, "PATH=/usr/bin:/bin"}
	if output, err := kill.CombinedOutput(); err != nil {
		t.Fatalf("kill guest session: %v %s", err, output)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("supervisor exited successfully after unexpected session loss")
		}
	case <-time.After(10 * time.Second):
		_ = command.Process.Kill()
		t.Fatal("supervisor did not exit after session loss")
	}
	waitForAbsent(t, filepath.Join(state, "guest-ready"), 5*time.Second)

	repeatedOutput, err := runBootstrap(testBootstrap, bootstrapEnvironment, bootstrapArguments...)
	if err != nil || !bytes.Contains(repeatedOutput, []byte("verified host bundle")) {
		t.Fatalf("repeated bootstrap CLI install was not idempotent: %v %s", err, repeatedOutput)
	}
	service, err := os.ReadFile(filepath.Join(current, "share", "systemd", "nvt-agent-guest.service"))
	if err != nil || !bytes.Contains(service, []byte("nvt-guest-supervisor")) {
		t.Fatal("installed systemd boundary is missing")
	}
	canary := []byte("NVT_TEST_SECRET_CANARY")
	archiveBytes, _ := os.ReadFile(archive)
	if bytes.Contains(archiveBytes, canary) || bytes.Contains(logs.Bytes(), canary) || treeContains(t, state, canary) {
		t.Fatal("credential canary entered the bundle or normal logs")
	}
}

func treeContains(t *testing.T, root string, value []byte) bool {
	t.Helper()
	found := false
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !entry.Type().IsRegular() {
			return err
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		found = found || bytes.Contains(content, value)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return found
}

func buildBinary(t *testing.T, moduleRoot, pkg, output string) {
	t.Helper()
	command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=", "-o", output, pkg)
	command.Dir = moduleRoot
	if outputBytes, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, outputBytes)
	}
}

func buildBinaryWithTags(t *testing.T, moduleRoot, pkg, output, tags string) {
	t.Helper()
	command := exec.Command("go", "build", "-tags", tags, "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=", "-o", output, pkg)
	command.Dir = moduleRoot
	if outputBytes, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build %s with tags: %v\n%s", pkg, err, outputBytes)
	}
}

func runBootstrap(binary string, environment []string, arguments ...string) ([]byte, error) {
	command := exec.Command(binary, arguments...)
	command.Env = environment
	return command.CombinedOutput()
}

func serveLayout(t *testing.T, layout string) (*httptest.Server, *http.Transport) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		digest := filepath.Base(request.URL.Path)
		content, err := os.ReadFile(filepath.Join(layout, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:")))
		if err != nil {
			http.NotFound(writer, request)
			return
		}
		if strings.Contains(request.URL.Path, "/manifests/") {
			var probe struct {
				MediaType string `json:"mediaType"`
			}
			_ = json.Unmarshal(content, &probe)
			writer.Header().Set("Content-Type", probe.MediaType)
		}
		_, _ = writer.Write(content)
	}))
	transport := server.Client().Transport.(*http.Transport).Clone()
	address := server.Listener.Addr().String()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} // test server only
	return server, transport
}

func waitForFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", filepath.Base(path))
}

func waitForAbsent(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s removal", filepath.Base(path))
}

func assertAgentdHealthAndPrompt(t *testing.T, current, socket, state, capture, prompt string) {
	t.Helper()
	environment := append(os.Environ(), "NVT_AGENTD_SOCKET="+socket, "NVT_STATE_DIR="+state)
	health := exec.Command(filepath.Join(current, "bin", "agentdctl"), "health")
	health.Env = environment
	if output, err := health.CombinedOutput(); err != nil || !bytes.Contains(output, []byte(`"status":"ready"`)) {
		t.Fatalf("agentd health failed: %v %s", err, output)
	}
	command := exec.Command(filepath.Join(current, "bin", "agentdctl"), "prompt", "--no-external", prompt)
	command.Env = environment
	if output, err := command.CombinedOutput(); err != nil || !bytes.Contains(output, []byte(`"status":"queued"`)) {
		t.Fatalf("prompt failed: %v %s", err, output)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		content, _ := os.ReadFile(capture)
		if bytes.Contains(content, []byte(prompt)) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("prompt %q was not delivered", prompt)
}
