package hostbundle_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
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
	"syscall"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/bundle"
	"github.com/mirkoSekulic/nvt-agent/hostbundle/contract"
	"github.com/mirkoSekulic/nvt-agent/hostbundle/guestidentity"
	"github.com/mirkoSekulic/nvt-agent/hostbundle/oci"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
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
	buildBinaryWithTags(t, moduleRoot, "./cmd/nvt-guest-identityd", filepath.Join(binaries, "nvt-guest-identityd"), "hostbundleidentitytest")
	buildBinaryWithTags(t, moduleRoot, "./cmd/nvt-guest-sessiond", filepath.Join(binaries, "nvt-guest-sessiond"), "hostbundlesessiontest")
	buildBinaryWithTags(t, moduleRoot, "./cmd/nvt-guest-egressd", filepath.Join(binaries, "nvt-guest-egressd"), "hostbundleegresstest")
	buildBinary(t, moduleRoot, "./cmd/nvt-host-bootstrap", filepath.Join(binaries, "nvt-host-bootstrap"))
	testBootstrap := filepath.Join(binaries, "nvt-host-bootstrap-test")
	buildBinaryWithTags(t, moduleRoot, "./cmd/nvt-host-bootstrap", testBootstrap, "hostbundletest")
	buildBinary(t, moduleRoot, "./cmd/nvt-guest-session-fixture", filepath.Join(binaries, "nvt-guest-session-fixture"))

	archive := filepath.Join(work, "nvt-host-bundle.tar.gz")
	manifest := contract.Manifest{
		ContractVersion: contract.Version, OS: "linux", Architecture: runtime.GOARCH,
		BundleVersion: "0.8.33-e2e", BuildID: strings.Repeat("a", 40),
		NativeEntrypoint: "bin/nvt-guest-supervisor", ServiceIdentity: "nvt-agent-guest.service",
		Compatibility: contract.Compatibility{
			AgentdProtocol: contract.AgentdProtocolVersion, NativeSessionProtocol: contract.NativeSessionProtocolVersion,
			NativeWorkspaceProtocol: contract.NativeWorkspaceProtocolVersion, NativeEgressProtocol: contract.NativeEgressProtocolVersion,
		},
	}
	inputs := []bundle.InputFile{
		{Path: "bin/nvt-guest-supervisor", Source: filepath.Join(binaries, "nvt-guest-supervisor"), Mode: 0o755},
		{Path: "bin/nvt-guest-identityd", Source: filepath.Join(binaries, "nvt-guest-identityd"), Mode: 0o755},
		{Path: "bin/nvt-guest-sessiond", Source: filepath.Join(binaries, "nvt-guest-sessiond"), Mode: 0o755},
		{Path: "bin/nvt-guest-egressd", Source: filepath.Join(binaries, "nvt-guest-egressd"), Mode: 0o755},
		{Path: "bin/nvt-host-bootstrap", Source: filepath.Join(binaries, "nvt-host-bootstrap"), Mode: 0o755},
		{Path: "bin/nvt-guest-session-fixture", Source: filepath.Join(binaries, "nvt-guest-session-fixture"), Mode: 0o755},
		{Path: "bin/agentd", Source: filepath.Join(repositoryRoot, "runtime", "agentd", "agentd.py"), Mode: 0o755},
		{Path: "bin/agentdctl", Source: filepath.Join(repositoryRoot, "runtime", "agentd", "agentdctl.py"), Mode: 0o755},
		{Path: "share/systemd/nvt-agent-guest.service", Source: filepath.Join(moduleRoot, "files", "nvt-agent-guest.service"), Mode: 0o644},
		{Path: "share/systemd/nvt-guest-identity.service", Source: filepath.Join(moduleRoot, "files", "nvt-guest-identity.service"), Mode: 0o644},
		{Path: "share/systemd/nvt-guest-session.service", Source: filepath.Join(moduleRoot, "files", "nvt-guest-session.service"), Mode: 0o644},
		{Path: "share/systemd/nvt-guest-egress.service", Source: filepath.Join(moduleRoot, "files", "nvt-guest-egress.service"), Mode: 0o644},
		{Path: "share/examples/guest.json", Source: filepath.Join(moduleRoot, "files", "guest.json"), Mode: 0o644},
		{Path: "share/examples/identity.json", Source: filepath.Join(moduleRoot, "files", "identity.json"), Mode: 0o644},
		{Path: "share/examples/session.json", Source: filepath.Join(moduleRoot, "files", "session.json"), Mode: 0o644},
		{Path: "share/examples/session-workspace.json", Source: filepath.Join(moduleRoot, "files", "session-workspace.json"), Mode: 0o644},
		{Path: "share/examples/native-egress.json", Source: filepath.Join(moduleRoot, "files", "native-egress.json"), Mode: 0o644},
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

	identityLogs, identityCanaries := exerciseInstalledIdentityDaemon(t, filepath.Join(root, "current"), work)
	nativeSessionLogs, nativeSessionCanaries := exerciseInstalledNativeSession(t, filepath.Join(root, "current"), work)

	state := filepath.Join(work, "state")
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "run")
	sessionRuntimeDir := filepath.Join(work, "supervisor-session-run")
	egressRuntimeDir := filepath.Join(work, "supervisor-egress-run")
	for _, directory := range []string{state, workspace, runtimeDir, sessionRuntimeDir, egressRuntimeDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	socket := filepath.Join(runtimeDir, "agentd.sock")
	sessionReadiness := filepath.Join(sessionRuntimeDir, "session-ready")
	egressReadiness := filepath.Join(egressRuntimeDir, "egress-ready")
	if err := os.WriteFile(sessionReadiness, []byte("ready\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	capture := filepath.Join(state, "session-input.log")
	session := fmt.Sprintf("guest%d", time.Now().UnixNano())
	config := map[string]any{
		"version": 1, "python_path": python, "tmux_path": tmux,
		"state_dir": state, "socket_path": socket, "workspace": workspace,
		"session_name": session, "session_readiness_path": sessionReadiness, "egress_readiness_path": egressReadiness, "session_startup_grace_seconds": 0,
		"session_command": []string{"@release/bin/nvt-guest-session-fixture", "--output", capture},
	}
	configBytes, _ := json.Marshal(config)
	configPath := filepath.Join(work, "guest.json")
	if err := os.WriteFile(configPath, append(configBytes, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(root, "current")
	var logs synchronizedBuffer
	launch := func() (*exec.Cmd, chan error) {
		command := exec.Command(filepath.Join(current, "bin", "nvt-guest-supervisor"), "--config", configPath)
		command.Env = append(os.Environ(), "NVT_TEST_SECRET_CANARY=must-not-propagate")
		command.Stdout = &logs
		command.Stderr = &logs
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		return command, done
	}
	start := func() (*exec.Cmd, chan error) {
		command, done := launch()
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

	// Native egress capture readiness is an optional pre-session gate. Agentd
	// may start, but the untrusted tmux session and guest readiness remain absent
	// until the root-owned marker appears.
	command, done := launch()
	socketDeadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("supervisor exited before egress readiness gate: %v\n%s", err, logs.String())
		default:
		}
		if time.Now().After(socketDeadline) {
			t.Fatalf("agentd socket was not published before egress gate\n%s", logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond)
	probe := exec.Command(tmux, "has-session", "-t", session)
	probe.Env = []string{"HOME=" + state, "PATH=/usr/bin:/bin"}
	if probe.Run() == nil {
		t.Fatal("agent session started before native egress capture readiness")
	}
	if _, err := os.Stat(filepath.Join(state, "guest-ready")); !os.IsNotExist(err) {
		t.Fatal("guest readiness was published before native egress capture readiness")
	}
	if err := os.WriteFile(egressReadiness, []byte("ready\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	waitForFile(t, filepath.Join(state, "guest-ready"), 15*time.Second)
	if info, err := os.Stat(socket); err != nil || info.Mode().Perm() != 0o660 {
		t.Fatalf("native agentd socket permission contract = %v, %v", info, err)
	}
	assertAgentdHealthAndPrompt(t, current, socket, state, capture, "first-native-prompt")
	stop(command, done)
	command, done = start()
	assertAgentdHealthAndPrompt(t, current, socket, state, capture, "restart-native-prompt")
	stop(command, done)
	command, done = start()
	if err := os.Remove(egressReadiness); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("supervisor exited successfully after native egress withdrawal")
		}
	case <-time.After(10 * time.Second):
		_ = command.Process.Kill()
		t.Fatal("supervisor did not stop after native egress withdrawal")
	}
	waitForAbsent(t, filepath.Join(state, "guest-ready"), 5*time.Second)
	if err := os.WriteFile(egressReadiness, []byte("ready\n"), 0o640); err != nil {
		t.Fatal(err)
	}
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
	delete(config, "session_readiness_path")
	delete(config, "egress_readiness_path")
	legacyConfigBytes, _ := json.Marshal(config)
	if err := os.WriteFile(configPath, append(legacyConfigBytes, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(sessionReadiness); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	command, done = start()
	if info, err := os.Stat(socket); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("legacy agentd socket permission contract = %v, %v", info, err)
	}
	assertAgentdHealthAndPrompt(t, current, socket, state, capture, "legacy-v1-native-prompt")
	stop(command, done)

	repeatedOutput, err := runBootstrap(testBootstrap, bootstrapEnvironment, bootstrapArguments...)
	if err != nil || !bytes.Contains(repeatedOutput, []byte("verified host bundle")) {
		t.Fatalf("repeated bootstrap CLI install was not idempotent: %v %s", err, repeatedOutput)
	}
	service, err := os.ReadFile(filepath.Join(current, "share", "systemd", "nvt-agent-guest.service"))
	identityService, identityServiceErr := os.ReadFile(filepath.Join(current, "share", "systemd", "nvt-guest-identity.service"))
	sessionService, sessionServiceErr := os.ReadFile(filepath.Join(current, "share", "systemd", "nvt-guest-session.service"))
	egressService, egressServiceErr := os.ReadFile(filepath.Join(current, "share", "systemd", "nvt-guest-egress.service"))
	if err != nil || !bytes.Contains(service, []byte("nvt-guest-supervisor")) || !bytes.Contains(service, []byte("Requires=nvt-guest-identity.service")) || !bytes.Contains(service, []byte("RuntimeDirectoryMode=0750")) || identityServiceErr != nil ||
		!bytes.Contains(identityService, []byte("User=root")) || !bytes.Contains(identityService, []byte("Type=notify")) ||
		!bytes.Contains(identityService, []byte("TimeoutStartSec=0")) || !bytes.Contains(identityService, []byte("nvt-guest-identityd")) ||
		sessionServiceErr != nil || !bytes.Contains(sessionService, []byte("User=root")) || !bytes.Contains(sessionService, []byte("Group=nvt-agent")) ||
		!bytes.Contains(sessionService, []byte("RuntimeDirectoryMode=0750")) || !bytes.Contains(sessionService, []byte("CapabilityBoundingSet=\n")) || !bytes.Contains(sessionService, []byte("nvt-guest-sessiond")) ||
		!bytes.Contains(sessionService, []byte("Requires=nvt-guest-identity.service nvt-agent-guest.service")) ||
		egressServiceErr != nil || !bytes.Contains(egressService, []byte("User=root")) || !bytes.Contains(egressService, []byte("Group=nvt-agent")) ||
		!bytes.Contains(egressService, []byte("RuntimeDirectoryMode=0750")) || !bytes.Contains(egressService, []byte("CapabilityBoundingSet=\n")) ||
		!bytes.Contains(egressService, []byte("nvt-guest-egressd")) || !bytes.Contains(egressService, []byte("Requires=nvt-guest-identity.service")) {
		t.Fatal("installed systemd boundaries are missing")
	}
	workspaceExample, workspaceExampleErr := os.ReadFile(filepath.Join(current, "share", "examples", "session-workspace.json"))
	if workspaceExampleErr != nil || !bytes.Contains(workspaceExample, []byte(`"gateway_endpoint": "tls://workspace-gateway.example.invalid:444"`)) ||
		!bytes.Contains(workspaceExample, []byte(`"loopback_endpoint": "127.0.0.1:4090"`)) {
		t.Fatal("installed bundle is missing the non-secret optional workspace example")
	}
	egressExample, egressExampleErr := os.ReadFile(filepath.Join(current, "share", "examples", "native-egress.json"))
	if egressExampleErr != nil || !bytes.Contains(egressExample, []byte(`"relay_endpoint": "tls://native-egress.example.invalid:7445"`)) ||
		!bytes.Contains(egressExample, []byte(`"listen_address": "127.0.0.1:15001"`)) ||
		bytes.Contains(egressExample, []byte("nvt_eg1_")) || bytes.Contains(egressExample, []byte("runtime_identity")) ||
		bytes.Contains(egressExample, []byte("binding")) || bytes.Contains(egressExample, []byte("audience")) {
		t.Fatal("installed bundle is missing the non-secret optional native-egress example")
	}
	if bytes.Contains(egressService, []byte("Environment=")) || bytes.Contains(egressService, []byte("nvt_eg1_")) ||
		bytes.Contains(egressService, []byte("runtime_identity")) {
		t.Fatal("native-egress unit contains credential-bearing configuration")
	}
	nonRootEgress := exec.Command(filepath.Join(current, "bin", "nvt-guest-egressd"), "--config", filepath.Join(work, "missing-egress.json"))
	nonRootEgress.Env = append(os.Environ(), "NVT_GUEST_EGRESS_TEST_EUID=65532")
	if output, err := nonRootEgress.CombinedOutput(); err == nil || !bytes.Contains(output, []byte("invalid startup configuration")) || bytes.Contains(output, []byte("nvt_eg1_")) {
		t.Fatalf("non-root native egress boundary = %v %s", err, output)
	}
	if _, err := os.Stat(filepath.Join(root, "etc")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bundle install wrote configuration outside the immutable release: %v", err)
	}
	canary := []byte("NVT_TEST_SECRET_CANARY")
	archiveBytes, _ := os.ReadFile(archive)
	if bytes.Contains(archiveBytes, canary) || bytes.Contains(logs.Bytes(), canary) || bytes.Contains(identityLogs, canary) || bytes.Contains(nativeSessionLogs, canary) || treeContains(t, state, canary) {
		t.Fatal("credential canary entered the bundle or normal logs")
	}
	for _, identityCanary := range identityCanaries {
		if bytes.Contains(archiveBytes, identityCanary) || bytes.Contains(logs.Bytes(), identityCanary) || bytes.Contains(identityLogs, identityCanary) || bytes.Contains(nativeSessionLogs, identityCanary) {
			t.Fatal("runtime identity canary entered the bundle or normal logs")
		}
	}
	for _, sessionCanary := range nativeSessionCanaries {
		if bytes.Contains(archiveBytes, sessionCanary) || bytes.Contains(logs.Bytes(), sessionCanary) || bytes.Contains(identityLogs, sessionCanary) || bytes.Contains(nativeSessionLogs, sessionCanary) {
			t.Fatal("session credential canary entered the bundle or normal logs")
		}
	}
}

type identityE2EBroker struct {
	mu                 sync.Mutex
	binding            guestenrollment.Binding
	token              string
	current            string
	issuedAt           time.Time
	expiresAt          time.Time
	rotateCount        int
	sessionIssueCount  uint64
	sessionCredentials map[string]time.Time
}

func (broker *identityE2EBroker) serve(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	switch request.URL.Path {
	case guestenrollment.EnrollmentExchangePath:
		var value guestenrollment.ExchangeRequest
		if json.NewDecoder(request.Body).Decode(&value) != nil || value.Binding != broker.binding || value.Token != broker.token {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		broker.mu.Lock()
		identity := broker.current
		status := broker.statusLocked()
		broker.mu.Unlock()
		writeIdentityJSON(writer, guestenrollment.ExchangeResult{
			ContractVersion: guestenrollment.Version, Binding: broker.binding,
			RuntimeIdentity: guestenrollment.RuntimeIdentity{Type: guestenrollment.RuntimeIdentityType, Opaque: identity, IssuedAt: status.IssuedAt, ExpiresAt: status.ExpiresAt},
		})
	case guestenrollment.RuntimeIdentityStatusPath:
		var value guestenrollment.RuntimeIdentityStatusRequest
		broker.mu.Lock()
		valid := json.NewDecoder(request.Body).Decode(&value) == nil && value.Binding == broker.binding && identityBearer(request) == broker.current
		status := broker.statusLocked()
		broker.mu.Unlock()
		if !valid {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeIdentityJSON(writer, status)
	case guestenrollment.RuntimeIdentityRotatePath:
		var value guestenrollment.RuntimeIdentityRotateRequest
		broker.mu.Lock()
		if json.NewDecoder(request.Body).Decode(&value) != nil || value.Binding != broker.binding || identityBearer(request) != broker.current ||
			guestenrollment.ValidateRuntimeIdentityRotateRequest(value) != nil {
			broker.mu.Unlock()
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		broker.current = value.Successor
		broker.issuedAt = time.Now().UTC().Truncate(time.Second)
		broker.expiresAt = broker.issuedAt.Add(time.Hour)
		broker.rotateCount++
		status := broker.statusLocked()
		broker.mu.Unlock()
		writeIdentityJSON(writer, status)
	case guestenrollment.GuestSessionIdentityIssuePath:
		var value guestenrollment.GuestSessionIssueRequest
		broker.mu.Lock()
		valid := json.NewDecoder(request.Body).Decode(&value) == nil && value.Binding == broker.binding &&
			identityBearer(request) == broker.current && guestenrollment.ValidateGuestSessionIssueRequest(value) == nil
		if !valid {
			broker.mu.Unlock()
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		broker.sessionIssueCount++
		credential, credentialErr := guestenrollment.GenerateGuestSessionCredential(broker.sessionIssueCount)
		issuedAt := time.Now().UTC().Truncate(time.Second)
		expiresAt := issuedAt.Add(5 * time.Minute)
		if expiresAt.After(broker.expiresAt) {
			expiresAt = broker.expiresAt
		}
		if broker.sessionCredentials == nil {
			broker.sessionCredentials = make(map[string]time.Time)
		}
		broker.sessionCredentials[credential] = expiresAt
		broker.mu.Unlock()
		if credentialErr != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeIdentityJSON(writer, guestenrollment.GuestSessionIssueResult{
			ContractVersion: guestenrollment.GuestSessionIdentityVersion,
			Binding:         broker.binding,
			Credential: guestenrollment.GuestSessionCredential{
				Type: guestenrollment.GuestSessionCredentialType, Opaque: credential,
				Audience: guestenrollment.NativeGuestControlAudience,
				IssuedAt: guestenrollment.FormatTimestamp(issuedAt), ExpiresAt: guestenrollment.FormatTimestamp(expiresAt),
			},
		})
	default:
		writer.WriteHeader(http.StatusNotFound)
	}
}

func (broker *identityE2EBroker) authenticateSession(binding guestenrollment.Binding, credential string) bool {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	expiresAt, found := broker.sessionCredentials[credential]
	return found && binding == broker.binding && time.Now().UTC().Before(expiresAt)
}

func (broker *identityE2EBroker) statusLocked() guestenrollment.RuntimeIdentityStatus {
	return guestenrollment.RuntimeIdentityStatus{
		ContractVersion: guestenrollment.RuntimeIdentityVersion, IdentityType: guestenrollment.RuntimeIdentityType,
		Binding: broker.binding, IssuedAt: guestenrollment.FormatTimestamp(broker.issuedAt), ExpiresAt: guestenrollment.FormatTimestamp(broker.expiresAt),
	}
}

func exerciseInstalledIdentityDaemon(t *testing.T, current, work string) ([]byte, [][]byte) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	binding := guestenrollment.Binding{
		AgentRunUID: "11111111-1111-1111-1111-111111111111", ExecutionID: "nvt-native-e2e",
		DriverRegistration: "test-driver", DesiredGeneration: 1, GuestInstanceID: "guest-native-e2e",
	}
	broker := &identityE2EBroker{
		binding: binding, token: identityOpaque(0x21), current: identityOpaque(0x31), issuedAt: now, expiresAt: now.Add(time.Hour),
	}
	server := httptest.NewTLSServer(http.HandlerFunc(broker.serve))
	defer server.Close()
	identityRoot := filepath.Join(work, "identity-state")
	identityRun := filepath.Join(work, "identity-run")
	if err := os.Mkdir(identityRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(work, "identity-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	configuration := guestidentity.Configuration{
		Version: guestidentity.ConfigurationVersion, StateDirectory: identityRoot, RuntimeDirectory: identityRun,
		EnrollmentPath: filepath.Join(identityRoot, "enrollment.json"), CAPEMPath: caPath,
	}
	configBytes, _ := json.Marshal(configuration)
	configPath := filepath.Join(work, "identity-config.json")
	if err := os.WriteFile(configPath, append(configBytes, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	envelope := guestenrollment.BootstrapEnvelope{
		ContractVersion: guestenrollment.Version, Binding: binding,
		ExchangeURL: server.URL + guestenrollment.EnrollmentExchangePath, Token: broker.token,
		IssuedAt: guestenrollment.FormatTimestamp(now.Add(-time.Minute)), ExpiresAt: guestenrollment.FormatTimestamp(now.Add(time.Minute)),
	}
	envelopeBytes, _ := json.Marshal(envelope)
	if err := os.WriteFile(configuration.EnrollmentPath, append(envelopeBytes, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs synchronizedBuffer
	start := func() (*exec.Cmd, chan error) {
		command := exec.Command(filepath.Join(current, "bin", "nvt-guest-identityd"), "--config", configPath)
		command.Env = append(os.Environ(), "NVT_GUEST_IDENTITY_TEST_EUID=0")
		command.Stdout, command.Stderr = &logs, &logs
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		waitForFile(t, filepath.Join(identityRun, guestidentity.ReadinessFileName), 10*time.Second)
		return command, done
	}
	stop := func(command *exec.Cmd, done chan error) {
		if err := command.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("identity daemon stop failed: %v %s", err, logs.String())
			}
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			t.Fatal("identity daemon did not stop")
		}
	}
	command, done := start()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		broker.mu.Lock()
		rotated := broker.rotateCount >= 1
		broker.mu.Unlock()
		if rotated {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	broker.mu.Lock()
	rotations := broker.rotateCount
	identityCanary := broker.current
	broker.mu.Unlock()
	if rotations < 1 {
		t.Fatalf("installed identity daemon never rotated: %s", logs.String())
	}
	stop(command, done)
	command, done = start()
	stop(command, done)
	stateInfo, err := os.Stat(filepath.Join(identityRoot, guestidentity.StateFileName))
	if err != nil || stateInfo.Mode().Perm() != 0o600 {
		t.Fatalf("identity state mode = %v, %v", stateInfo, err)
	}
	directoryInfo, err := os.Stat(identityRoot)
	if err != nil || directoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("identity directory mode = %v, %v", directoryInfo, err)
	}
	if bytes.Contains(logs.Bytes(), []byte(broker.token)) || bytes.Contains(logs.Bytes(), []byte(identityCanary)) {
		t.Fatal("identity daemon logs disclosed bearer material")
	}
	nonRoot := exec.Command(filepath.Join(current, "bin", "nvt-guest-identityd"), "--config", configPath)
	nonRoot.Env = append(os.Environ(), "NVT_GUEST_IDENTITY_TEST_EUID=65532")
	if output, err := nonRoot.CombinedOutput(); err == nil || !bytes.Contains(output, []byte("invalid startup configuration")) || bytes.Contains(output, []byte(identityCanary)) {
		t.Fatalf("non-root identity daemon boundary = %v %s", err, output)
	}
	return logs.Bytes(), [][]byte{[]byte(broker.token), []byte(identityCanary)}
}

func exerciseInstalledNativeSession(t *testing.T, current, work string) ([]byte, [][]byte) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	binding := guestenrollment.Binding{
		AgentRunUID: "22222222-2222-2222-2222-222222222222", ExecutionID: "nvt-session-e2e",
		DriverRegistration: "test-driver", DesiredGeneration: 1, GuestInstanceID: "guest-session-e2e",
	}
	broker := &identityE2EBroker{
		binding: binding, token: identityOpaque(0x41), current: identityOpaque(0x51),
		issuedAt: now, expiresAt: now.Add(time.Hour), sessionCredentials: make(map[string]time.Time),
	}
	brokerServer := httptest.NewTLSServer(http.HandlerFunc(broker.serve))
	defer brokerServer.Close()
	caBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: brokerServer.Certificate().Raw})
	caPath := filepath.Join(work, "session-e2e-ca.pem")
	if err := os.WriteFile(caPath, caBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	identityState := filepath.Join(work, "session-identity-state")
	identityRun := filepath.Join(work, "session-identity-run")
	if err := os.Mkdir(identityState, 0o700); err != nil {
		t.Fatal(err)
	}
	identityConfiguration := guestidentity.Configuration{
		Version: guestidentity.ConfigurationVersion, StateDirectory: identityState, RuntimeDirectory: identityRun,
		EnrollmentPath: filepath.Join(identityState, "enrollment.json"), CAPEMPath: caPath,
	}
	identityConfigBytes, _ := json.Marshal(identityConfiguration)
	identityConfigPath := filepath.Join(work, "session-identity.json")
	if err := os.WriteFile(identityConfigPath, append(identityConfigBytes, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	envelope := guestenrollment.BootstrapEnvelope{
		ContractVersion: guestenrollment.Version, Binding: binding,
		ExchangeURL: brokerServer.URL + guestenrollment.EnrollmentExchangePath, Token: broker.token,
		IssuedAt: guestenrollment.FormatTimestamp(now.Add(-time.Minute)), ExpiresAt: guestenrollment.FormatTimestamp(now.Add(time.Minute)),
	}
	envelopeBytes, _ := json.Marshal(envelope)
	if err := os.WriteFile(identityConfiguration.EnrollmentPath, append(envelopeBytes, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	agentdSocket := filepath.Join(work, "session-agentd.sock")
	stopAgentd := serveNativeSessionE2EAgentd(t, agentdSocket)
	defer stopAgentd()
	gatewayListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(gatewayListener, brokerServer.TLS.Clone())
	defer tlsListener.Close()
	relayed := make(chan struct{}, 4)
	gatewayDone := make(chan struct{})
	go func() {
		defer close(gatewayDone)
		for {
			connection, acceptErr := tlsListener.Accept()
			if acceptErr != nil {
				return
			}
			go serveNativeSessionE2EGateway(connection, broker, binding, relayed)
		}
	}()

	sessionRun := filepath.Join(work, "native-session-run")
	if err := os.Mkdir(sessionRun, 0o750); err != nil {
		t.Fatal(err)
	}
	sessionConfiguration := map[string]any{
		"version": 1, "runtime_directory": sessionRun,
		"identity_socket_path": guestidentity.SessionCredentialSocketPath(identityRun),
		"agentd_socket_path":   agentdSocket, "gateway_endpoint": "tls://example.com:443", "ca_pem_path": caPath,
	}
	sessionConfigBytes, _ := json.Marshal(sessionConfiguration)
	sessionConfigPath := filepath.Join(work, "native-session.json")
	if err := os.WriteFile(sessionConfigPath, append(sessionConfigBytes, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	var logs synchronizedBuffer
	startProcess := func(binary string, arguments []string, environment []string) (*exec.Cmd, chan error) {
		command := exec.Command(filepath.Join(current, "bin", binary), arguments...)
		command.Env = append(os.Environ(), environment...)
		command.Stdout, command.Stderr = &logs, &logs
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		return command, done
	}
	stopProcess := func(name string, command *exec.Cmd, done chan error) {
		if err := command.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatalf("stop %s: %v", name, err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s stop failed: %v %s", name, err, logs.String())
			}
		case <-time.After(8 * time.Second):
			_ = command.Process.Kill()
			t.Fatalf("%s did not stop", name)
		}
	}
	identityCommand, identityDone := startProcess("nvt-guest-identityd", []string{"--config", identityConfigPath}, []string{"NVT_GUEST_IDENTITY_TEST_EUID=0"})
	waitForFile(t, filepath.Join(identityRun, guestidentity.ReadinessFileName), 10*time.Second)
	waitForSocket(t, guestidentity.SessionCredentialSocketPath(identityRun), 10*time.Second)

	startSession := func() (*exec.Cmd, chan error) {
		command, done := startProcess("nvt-guest-sessiond", []string{"--config", sessionConfigPath}, []string{
			"NVT_GUEST_SESSION_TEST_EUID=0", "NVT_GUEST_SESSION_TEST_DIAL_ADDRESS=" + gatewayListener.Addr().String(),
		})
		readinessPath := filepath.Join(sessionRun, "session-ready")
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if info, err := os.Stat(readinessPath); err == nil && info.Mode().IsRegular() {
				break
			}
			select {
			case err := <-done:
				t.Fatalf("native session exited before readiness: %v %s", err, logs.String())
			default:
			}
			time.Sleep(50 * time.Millisecond)
		}
		if _, err := os.Stat(readinessPath); err != nil {
			_ = command.Process.Kill()
			t.Fatalf("native session did not become ready: %v %s", err, logs.String())
		}
		select {
		case <-relayed:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			t.Fatal("installed native session did not relay agentd traffic")
		}
		return command, done
	}
	sessionCommand, sessionDone := startSession()
	stopProcess("native session", sessionCommand, sessionDone)
	waitForAbsent(t, filepath.Join(sessionRun, "session-ready"), 5*time.Second)
	sessionCommand, sessionDone = startSession()
	stopProcess("native session", sessionCommand, sessionDone)
	stopProcess("identity", identityCommand, identityDone)

	nonRoot := exec.Command(filepath.Join(current, "bin", "nvt-guest-sessiond"), "--config", sessionConfigPath)
	nonRoot.Env = append(os.Environ(), "NVT_GUEST_SESSION_TEST_EUID=65532", "NVT_GUEST_SESSION_TEST_DIAL_ADDRESS="+gatewayListener.Addr().String())
	if output, err := nonRoot.CombinedOutput(); err == nil || !bytes.Contains(output, []byte("invalid startup configuration")) {
		t.Fatalf("non-root native session boundary = %v %s", err, output)
	}
	broker.mu.Lock()
	canaries := make([][]byte, 0, len(broker.sessionCredentials)+2)
	canaries = append(canaries, []byte(broker.token), []byte(broker.current))
	for credential := range broker.sessionCredentials {
		canaries = append(canaries, []byte(credential))
	}
	broker.mu.Unlock()
	for _, canary := range canaries {
		if bytes.Contains(logs.Bytes(), canary) || treeContains(t, sessionRun, canary) {
			t.Fatal("native session disclosed credential material")
		}
	}
	_ = tlsListener.Close()
	<-gatewayDone
	return logs.Bytes(), canaries
}

type synchronizedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *synchronizedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(data)
}

func (b *synchronizedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buffer.Bytes())
}

func (b *synchronizedBuffer) String() string {
	return string(b.Bytes())
}

func serveNativeSessionE2EAgentd(t *testing.T, path string) func() {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer connection.Close()
				buffer := make([]byte, guestenrollment.MaxNativeSessionAgentdPayloadBytes)
				count, _ := connection.Read(buffer)
				if count != 0 {
					_, _ = connection.Write([]byte("{\"status\":\"ready\"}\n"))
				}
			}()
		}
	}()
	return func() { _ = listener.Close(); <-done }
}

func serveNativeSessionE2EGateway(connection net.Conn, broker *identityE2EBroker, binding guestenrollment.Binding, relayed chan<- struct{}) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReaderSize(connection, guestenrollment.MaxNativeSessionFrameBytes)
	helloLine, err := reader.ReadSlice('\n')
	if err != nil {
		return
	}
	hello, err := guestenrollment.DecodeNativeSessionMessage(helloLine)
	if err != nil || hello.Type != guestenrollment.NativeSessionHello || hello.Binding == nil ||
		*hello.Binding != binding || hello.Audience != guestenrollment.NativeGuestControlAudience ||
		!broker.authenticateSession(binding, hello.Credential) {
		writeNativeSessionE2EFrame(connection, guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionHelloReject, Reason: "unauthorized",
		})
		return
	}
	hello.Credential = ""
	writeNativeSessionE2EFrame(connection, guestenrollment.NativeSessionMessage{
		ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionHelloAck,
		Binding: &binding, Audience: guestenrollment.NativeGuestControlAudience,
	})
	writeNativeSessionE2EFrame(connection, guestenrollment.NativeSessionMessage{
		ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionAgentdRequest,
		RequestID: "installed-health", Payload: json.RawMessage(`{"type":"health"}`),
	})
	responseLine, err := reader.ReadSlice('\n')
	if err != nil {
		return
	}
	response, err := guestenrollment.DecodeNativeSessionMessage(responseLine)
	if err != nil || response.Type != guestenrollment.NativeSessionAgentdResponse || response.RequestID != "installed-health" ||
		!bytes.Contains(response.Payload, []byte(`"status":"ready"`)) {
		return
	}
	select {
	case relayed <- struct{}{}:
	default:
	}
	for {
		line, readErr := reader.ReadSlice('\n')
		if readErr != nil {
			return
		}
		frame, decodeErr := guestenrollment.DecodeNativeSessionMessage(line)
		if decodeErr != nil {
			return
		}
		if frame.Type == guestenrollment.NativeSessionPing {
			writeNativeSessionE2EFrame(connection, guestenrollment.NativeSessionMessage{
				ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionPong,
			})
		}
	}
}

func writeNativeSessionE2EFrame(connection net.Conn, value guestenrollment.NativeSessionMessage) {
	encoded, err := guestenrollment.EncodeNativeSessionMessage(value)
	if err == nil {
		_, _ = connection.Write(encoded)
	}
}

func identityBearer(request *http.Request) string {
	return strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
}

func identityOpaque(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, guestenrollment.RuntimeIdentityBytes))
}

func writeIdentityJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(value)
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

func waitForSocket(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", filepath.Base(path))
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
