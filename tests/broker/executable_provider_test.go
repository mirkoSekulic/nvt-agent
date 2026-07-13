package broker_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const executableCanary = "EXECUTABLE-PROVIDER-CANARY-CREDENTIAL"

var (
	executableProviderBuildOnce  sync.Once
	executableProviderBinary     string
	executableProviderBuildError error
)

type executableBrokerFixture struct {
	t      *testing.T
	root   string
	bin    string
	dir    string
	url    string
	config string
	agents string
	audit  string
	state  string
	cmd    *exec.Cmd
	stdout bytes.Buffer
	stderr bytes.Buffer
	agent  string
	egress string
}

func buildExecutableProvider(t *testing.T) string {
	t.Helper()
	executableProviderBuildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "nvt-provider-fixture-")
		if err != nil {
			executableProviderBuildError = err
			return
		}
		executableProviderBinary = filepath.Join(dir, "provider-fixture")
		root := repoRoot(t)
		cmd := exec.Command("go", "build", "-race", "-o", executableProviderBinary, "./executable_provider_fixture")
		cmd.Dir = filepath.Join(root, "tests", "broker")
		if out, err := cmd.CombinedOutput(); err != nil {
			executableProviderBuildError = fmt.Errorf("%w: %s", err, out)
		}
	})
	if executableProviderBuildError != nil {
		t.Fatalf("build executable provider fixture: %v", executableProviderBuildError)
	}
	return executableProviderBinary
}

func newExecutableBrokerFixture(t *testing.T) *executableBrokerFixture {
	return newExecutableBrokerFixtureMode(t, "")
}

func newExecutableBrokerFixtureMode(t *testing.T, mode string) *executableBrokerFixture {
	t.Helper()
	f := &executableBrokerFixture{t: t, root: repoRoot(t), bin: buildExecutableProvider(t), dir: t.TempDir(), agent: "agent-secret", egress: "egress-secret"}
	f.config = filepath.Join(f.dir, "broker.yaml")
	f.agents = filepath.Join(f.dir, "agents.yaml")
	f.audit = filepath.Join(f.dir, "audit.jsonl")
	f.state = filepath.Join(f.dir, "state")
	f.url = fmt.Sprintf("http://127.0.0.1:%d", freePort(t))
	f.writeConfigMode(0.35, mode)
	f.writeAgents()
	f.start()
	t.Cleanup(f.stop)
	return f
}

func (f *executableBrokerFixture) writeConfig(timeout float64) {
	f.writeConfigMode(timeout, "")
}

func (f *executableBrokerFixture) writeConfigMode(timeout float64, mode string) {
	f.t.Helper()
	modeLine := ""
	if mode != "" {
		modeLine = fmt.Sprintf("      mode: %q\n", mode)
	}
	config := fmt.Sprintf(`provider-plugins:
  - name: fixture
    command: [%q]
    pass-env: [FIXTURE_CREDENTIAL]
    initialize-timeout-seconds: 2
    request-timeout-seconds: %.2f
providers:
  - name: fixture-direct
    plugin: fixture
    config:
      state-file: %q
%s
    allow:
      repositories: ["*"]
  - name: fixture-inject
    plugin: fixture
    config:
      state-file: %q
%s
    allow:
      repositories: ["*"]
`, f.bin, timeout, f.state+"-direct", modeLine, f.state+"-inject", modeLine)
	if err := os.WriteFile(f.config, []byte(config), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *executableBrokerFixture) writeAgents() {
	f.t.Helper()
	hash := func(value string) string { sum := sha256.Sum256([]byte(value)); return fmt.Sprintf("%x", sum[:]) }
	config := fmt.Sprintf(`agents:
  - id: fixture-agent
    token-sha256: sha256:%s
    grants:
      - provider: fixture-direct
        repositories: ["*"]
      - provider: fixture-inject
        materialization: header-inject
        repositories: ["*"]
  - id: fixture-egress
    role: egress
    paired-agent: fixture-agent
    token-sha256: sha256:%s
`, hash(f.agent), hash(f.egress))
	if err := os.WriteFile(f.agents, []byte(config), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *executableBrokerFixture) start() {
	f.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	f.t.Cleanup(cancel)
	f.cmd = exec.CommandContext(ctx, "python3", filepath.Join(f.root, "broker", "brokerd.py"))
	port := strings.TrimPrefix(f.url, "http://")
	f.cmd.Env = append(os.Environ(), "NVT_BROKER_CONFIG="+f.config, "NVT_BROKER_AGENTS_CONFIG="+f.agents, "NVT_BROKER_AUDIT_LOG="+f.audit, "NVT_BROKER_BIND="+port, "FIXTURE_CREDENTIAL="+executableCanary)
	f.cmd.Stdout, f.cmd.Stderr = &f.stdout, &f.stderr
	if err := f.cmd.Start(); err != nil {
		f.t.Fatal(err)
	}
	waitFor(f.t, 4*time.Second, func() bool {
		resp, err := http.Get(f.url + "/health")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == 200
	})
}

func (f *executableBrokerFixture) stop() {
	if f.cmd == nil || f.cmd.Process == nil {
		return
	}
	_ = f.cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() { _ = f.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = f.cmd.Process.Kill()
		<-done
	}
	f.cmd = nil
}

func (f *executableBrokerFixture) post(token, path string, payload map[string]any) (int, map[string]any) {
	f.t.Helper()
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, f.url+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		f.t.Fatal(err)
	}
	return resp.StatusCode, result
}

func (f *executableBrokerFixture) health() map[string]any {
	f.t.Helper()
	resp, err := http.Get(f.url + "/health")
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		f.t.Fatal(err)
	}
	return result
}

func TestExecutableProviderRealBrokerEndpointsAndCoreEnforcement(t *testing.T) {
	f := newExecutableBrokerFixture(t)
	status, token := f.post(f.agent, "/v1/token", map[string]any{"provider": "fixture-direct", "target": "github.com/example/repo"})
	if status != 200 || token["token"] != executableCanary {
		t.Fatalf("token endpoint: status=%d body=%#v", status, token)
	}
	status, files := f.post(f.agent, "/v1/files", map[string]any{"provider": "fixture-direct"})
	if status != 200 || !strings.Contains(fmt.Sprint(files["files"]), executableCanary) {
		t.Fatalf("files endpoint: status=%d body=%#v", status, files)
	}
	status, injected := f.post(f.egress, "/v1/injection/headers", map[string]any{"capability": "fixture-inject", "host": "api.example.test", "method": "GET", "path": "/v1"})
	if status != 200 || !strings.Contains(fmt.Sprint(injected["headers"]), executableCanary) {
		t.Fatalf("injection endpoint: status=%d body=%#v", status, injected)
	}

	status, denied := f.post(f.agent, "/v1/files", map[string]any{"provider": "fixture-inject"})
	if status != 403 || denied["error"] != "materialization-mismatch" {
		t.Fatalf("core materialization enforcement changed: status=%d body=%#v", status, denied)
	}
	status, denied = f.post(f.agent, "/v1/injection/headers", map[string]any{"capability": "fixture-inject", "host": "api.example.test", "method": "GET", "path": "/v1"})
	if status != 403 || denied["error"] != "role-not-allowed" {
		t.Fatalf("core identity enforcement changed: status=%d body=%#v", status, denied)
	}

	health := f.health()
	counts := health["providers"].(map[string]any)
	if health["status"] != "healthy" || counts["configured"] != float64(2) || counts["ready"] != float64(2) {
		t.Fatalf("unexpected health: %#v", health)
	}
}

func TestExecutableProviderOutOfOrderAndSafeDeclaredError(t *testing.T) {
	f := newExecutableBrokerFixture(t)
	type result struct {
		target  string
		elapsed time.Duration
		status  int
		body    map[string]any
	}
	started := time.Now()
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for _, target := range []string{"slow", "fast"} {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			status, body := f.post(f.agent, "/v1/token", map[string]any{"provider": "fixture-direct", "target": target})
			results <- result{target, time.Since(started), status, body}
		}(target)
	}
	wg.Wait()
	close(results)
	ordered := []result{}
	for item := range results {
		ordered = append(ordered, item)
	}
	if len(ordered) != 2 || ordered[0].target != "fast" || ordered[0].status != 200 || ordered[1].status != 200 {
		t.Fatalf("responses were not correlated out of order: %#v", ordered)
	}

	status, body := f.post(f.agent, "/v1/token", map[string]any{"provider": "fixture-direct", "target": "declared-error"})
	if status != 418 || body["error"] != "fixture-denied" || body["message"] != "safe fixture message" {
		t.Fatalf("declared error mapping changed: status=%d body=%#v", status, body)
	}
}

func TestExecutableProviderRejectsUnsupportedBeforeNormalize(t *testing.T) {
	f := &executableBrokerFixture{t: t, root: repoRoot(t), bin: buildExecutableProvider(t), dir: t.TempDir(), agent: "agent-secret", egress: "egress-secret"}
	f.config = filepath.Join(f.dir, "broker.yaml")
	f.agents = filepath.Join(f.dir, "agents.yaml")
	f.audit = filepath.Join(f.dir, "audit.jsonl")
	f.state = filepath.Join(f.dir, "state")
	f.url = fmt.Sprintf("http://127.0.0.1:%d", freePort(t))
	f.writeConfigMode(.35, "files-only")
	f.writeAgents()
	f.start()
	t.Cleanup(f.stop)
	for _, endpoint := range []string{"token", "identity", "headers"} {
		status, body := f.post(f.agent, "/v1/"+endpoint, map[string]any{"provider": "fixture-direct", "target": "owner/repo"})
		if status != 403 || body["error"] != endpoint+"-not-supported" {
			t.Fatalf("unsupported %s mapping: status=%d body=%#v", endpoint, status, body)
		}
	}
	if _, err := os.Stat(f.state + "-direct.normalized"); !os.IsNotExist(err) {
		t.Fatalf("target.normalize was invoked for unsupported capability: %v", err)
	}
}

func TestExecutableProviderFaultsFailClosedAndRecover(t *testing.T) {
	for _, fault := range []string{"fault-crash", "fault-eof", "fault-timeout", "fault-malformed", "fault-nonobject", "fault-oversized", "fault-unknown-id"} {
		t.Run(fault, func(t *testing.T) {
			f := newExecutableBrokerFixture(t)
			status, body := f.post(f.agent, "/v1/token", map[string]any{"provider": "fixture-direct", "target": fault})
			if status == 200 || (body["error"] != "provider-unavailable" && body["error"] != "provider-protocol-error") {
				t.Fatalf("fault did not fail closed: status=%d body=%#v", status, body)
			}
			waitFor(t, 2*time.Second, func() bool {
				health := f.health()
				return health["status"] == "healthy"
			})
			status, body = f.post(f.agent, "/v1/token", map[string]any{"provider": "fixture-direct", "target": fault})
			if status != 200 || body["token"] != executableCanary {
				t.Fatalf("provider did not recover: status=%d body=%#v", status, body)
			}
			f.stop()
			for _, data := range [][]byte{f.stdout.Bytes(), f.stderr.Bytes(), readOptional(t, f.audit)} {
				if bytes.Contains(data, []byte(executableCanary)) {
					t.Fatalf("canary leaked outside successful credential response")
				}
			}
		})
	}
}

func TestExecutableProviderDuplicateInvalidatesGeneration(t *testing.T) {
	f := newExecutableBrokerFixture(t)
	pending := make(chan map[string]any, 1)
	go func() {
		_, body := f.post(f.agent, "/v1/token", map[string]any{"provider": "fixture-direct", "target": "duplicate-pending"})
		pending <- body
	}()
	waitFor(t, 2*time.Second, func() bool {
		_, err := os.Stat(f.state + "-direct.duplicate-pending")
		return err == nil
	})
	_, _ = f.post(f.agent, "/v1/token", map[string]any{"provider": "fixture-direct", "target": "fault-duplicate-id"})
	waitFor(t, 2*time.Second, func() bool {
		_, err := os.Stat(f.state + "-direct.duplicate-emitted")
		return err == nil
	})
	select {
	case body := <-pending:
		if body["ok"] != false {
			t.Fatalf("duplicate did not fail pending generation request: %#v", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending request hung after duplicate response")
	}
	if health := f.health(); health["status"] != "degraded" {
		t.Fatalf("duplicate generation was not degraded: %#v", health)
	}
	waitFor(t, 3*time.Second, func() bool {
		data, err := os.ReadFile(f.state + "-direct.initializations")
		return err == nil && strings.TrimSpace(string(data)) >= "2"
	})
	waitFor(t, 3*time.Second, func() bool { return f.health()["status"] == "healthy" })
	status, body := f.post(f.agent, "/v1/token", map[string]any{"provider": "fixture-direct", "target": "recovered"})
	if status != 200 || body["token"] != executableCanary {
		t.Fatalf("fresh generation did not recover: status=%d body=%#v", status, body)
	}
}

func TestExecutableProviderPendingRequestsFailOnCrash(t *testing.T) {
	f := newExecutableBrokerFixture(t)
	results := make(chan map[string]any, 2)
	go func() {
		_, body := f.post(f.agent, "/v1/token", map[string]any{"provider": "fixture-direct", "target": "slow"})
		results <- body
	}()
	time.Sleep(40 * time.Millisecond)
	go func() {
		_, body := f.post(f.agent, "/v1/token", map[string]any{"provider": "fixture-direct", "target": "fault-crash"})
		results <- body
	}()
	for i := 0; i < 2; i++ {
		select {
		case body := <-results:
			if body["ok"] != false {
				t.Fatalf("pending request did not fail: %#v", body)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("pending request hung after crash")
		}
	}
}

func TestExecutableProviderConfigurationInitializationAndShutdown(t *testing.T) {
	bin := buildExecutableProvider(t)
	root := repoRoot(t)
	script := fmt.Sprintf(`
import os, tempfile, time
from broker.core.config import BrokerConfigError, provider_plugin_entries
from broker.core.errors import ProviderError
from broker.core.providers import load_providers
from broker.core.provider_adapter import ProviderAdapter

os.environ["FIXTURE_CREDENTIAL"] = %q
binary = %q
base = {"name":"fixture", "command":[binary], "pass-env":["FIXTURE_CREDENTIAL"], "initialize-timeout-seconds":1, "request-timeout-seconds":.2}

bad = [
  ({"provider-plugins":[dict(base, name="token")]}, "collides"),
  ({"provider-plugins":[dict(base, command=[])]}, "non-empty"),
  ({"provider-plugins":[dict(base, command=["relative"])]}, "absolute"),
  ({"provider-plugins":[dict(base, command=["/missing"])]}, "executable"),
  ({"provider-plugins":[{**base, "pass-env":["BAD-NAME"]}]}, "environment variable name"),
  ({"provider-plugins":[{**base, "pass-env":["MISSING_FIXTURE_ENV"]}]}, "not set"),
  ({"provider-plugins":[{**base, "request-timeout-second":1}]}, "unknown keys"),
]
for config, expected in bad:
  try: provider_plugin_entries(config, {"token": object()})
  except BrokerConfigError as error:
    assert expected in str(error), (expected, str(error))
  else: raise AssertionError(expected)

for mode in ("unknown-capability", "duplicate-capability", "bad-metadata", "initialize-error", "duplicate-hosts", "malformed-host", "uppercase-host", "port-host", "trailing-dot-host", "ipv4-host", "ipv6-host"):
  config={"provider-plugins":[base], "providers":[{"name":"one","plugin":"fixture","config":{"mode":mode}}]}
  try: load_providers(config)
  except BrokerConfigError: pass
  else: raise AssertionError("initialize accepted " + mode)

config={"provider-plugins":[base], "providers":[{"name":"one","plugin":"fixture","config":{"mode":"token-only"}}]}
p=load_providers(config)["one"]
assert isinstance(p, ProviderAdapter)
assert p.supports("token") and not p.supports("files")
try: p.files("a", None, "r")
except ProviderError as error: assert error.reason == "files-not-supported"
else: raise AssertionError("unsupported capability was called")
try: p._request("not-a-method", {})
except ProviderError as error: assert error.reason == "method-not-found" and error.status == 404
else: raise AssertionError("unknown method succeeded")
pid=p._process.pid
p.close()
try: os.kill(pid, 0)
except ProcessLookupError: pass
else: raise AssertionError("provider process was not reaped")

config={"provider-plugins":[base], "providers":[{"name":"one","plugin":"fixture","config":{"mode":"empty-injection-hosts"}}]}
p=load_providers(config)["one"]
assert not p.supports("injection")
p.close()

state=tempfile.mktemp(prefix="provider-stop-reading-")
blocked={"provider-plugins":[{**base, "request-timeout-seconds":.2}], "providers":[{"name":"one","plugin":"fixture","config":{"mode":"stop-reading-ignore-sigterm", "state-file":state}}]}
p=load_providers(blocked)["one"]
blocked_pid=int(open(state+".pid").read())
started=time.monotonic()
try: p._request("files", {"blob":"x" * 900000})
except ProviderError as error: assert error.reason == "provider-unavailable"
else: raise AssertionError("blocked stdin request succeeded")
assert time.monotonic() - started < .45
deadline=time.monotonic()+4
while time.monotonic() < deadline:
  try: os.kill(blocked_pid, 0)
  except ProcessLookupError: break
  time.sleep(.02)
else: raise AssertionError("retired blocked provider was not reaped")
while not p.ready and time.monotonic() < deadline: time.sleep(.02)
assert p.ready, "provider did not recover after blocked stdin"
assert p.normalize_target("owner/repo").audit_target == "audit/owner/repo"
p.close()

state=tempfile.mktemp(prefix="provider-close-retirement-")
blocked["providers"][0]["config"]["state-file"]=state
p=load_providers(blocked)["one"]
blocked_pid=int(open(state+".pid").read())
try: p._request("files", {"blob":"x" * 900000})
except ProviderError: pass
else: raise AssertionError("second blocked stdin request succeeded")
p.close()
try: os.kill(blocked_pid, 0)
except ProcessLookupError: pass
else: raise AssertionError("close returned before retired provider was reaped")
print("OK")
`, executableCanary, bin)
	cmd := exec.Command("python3", "-c", script)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "PYTHONPATH="+root)
	out, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("OK")) {
		t.Fatalf("configuration/shutdown conformance failed: %v\n%s", err, out)
	}
}

func readOptional(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return data
}

func assertProviderStopped(t *testing.T, state string) {
	t.Helper()
	data, err := os.ReadFile(state + ".pid")
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); err == nil {
		t.Fatalf("provider child %d survived broker cleanup", pid)
	}
}

func TestExecutableProviderHealthDegradesDuringBackoff(t *testing.T) {
	f := newExecutableBrokerFixture(t)
	_, _ = f.post(f.agent, "/v1/token", map[string]any{"provider": "fixture-direct", "target": "fault-timeout"})
	health := f.health()
	if health["status"] != "degraded" {
		t.Fatalf("expected degraded health, got %#v", health)
	}
	counts := health["providers"].(map[string]any)
	if counts["unavailable"].(float64) < 1 {
		t.Fatalf("expected unavailable provider count, got %#v", health)
	}
	waitFor(t, 2*time.Second, func() bool { return f.health()["status"] == "healthy" })
}

func TestExecutableProviderDurableSupervisorLifecycle(t *testing.T) {
	for _, mode := range []string{"restart-initialize-fail-once", "restart-crash-after-initialize"} {
		t.Run(mode, func(t *testing.T) {
			f := newExecutableBrokerFixtureMode(t, mode)
			_, _ = f.post(f.agent, "/v1/token", map[string]any{"provider": "fixture-direct", "target": "fault-crash"})
			waitFor(t, 4*time.Second, func() bool {
				data, err := os.ReadFile(f.state + "-direct.initializations")
				return err == nil && strings.TrimSpace(string(data)) >= "3"
			})
			waitFor(t, 4*time.Second, func() bool { return f.health()["status"] == "healthy" })
			status, body := f.post(f.agent, "/v1/token", map[string]any{"provider": "fixture-direct", "target": "recovered"})
			if status != 200 || body["token"] != executableCanary {
				t.Fatalf("supervisor did not recover: status=%d body=%#v", status, body)
			}
			data, err := os.ReadFile(f.state + "-direct.initializations")
			if err != nil || strings.TrimSpace(string(data)) < "3" {
				t.Fatalf("expected at least three supervised generations: %q %v", data, err)
			}
		})
	}

	f := newExecutableBrokerFixture(t)
	started := time.Now()
	for i := 0; i < 3; i++ {
		target := fmt.Sprintf("fault-crash-cycle-%d", i)
		_, _ = f.post(f.agent, "/v1/token", map[string]any{"provider": "fixture-direct", "target": target})
		waitFor(t, 5*time.Second, func() bool { return f.health()["status"] == "healthy" })
	}
	if elapsed := time.Since(started); elapsed < 600*time.Millisecond || elapsed > 8*time.Second {
		t.Fatalf("restart backoff was not bounded: %v", elapsed)
	}
	_, _ = f.post(f.agent, "/v1/token", map[string]any{"provider": "fixture-direct", "target": "fault-crash-cycle-close"})
	f.stop()
}

func TestExecutableProviderCleanupOnSetupFailureAndSIGTERM(t *testing.T) {
	newUnstarted := func(t *testing.T) *executableBrokerFixture {
		f := &executableBrokerFixture{t: t, root: repoRoot(t), bin: buildExecutableProvider(t), dir: t.TempDir(), agent: "agent-secret", egress: "egress-secret"}
		f.config = filepath.Join(f.dir, "broker.yaml")
		f.agents = filepath.Join(f.dir, "agents.yaml")
		f.audit = filepath.Join(f.dir, "audit.jsonl")
		f.state = filepath.Join(f.dir, "state")
		f.writeConfig(.35)
		f.writeAgents()
		return f
	}
	runFailure := func(t *testing.T, bind string, extra ...string) {
		f := newUnstarted(t)
		cmd := exec.Command("python3", filepath.Join(f.root, "broker", "brokerd.py"))
		cmd.Env = append(os.Environ(), "NVT_BROKER_CONFIG="+f.config, "NVT_BROKER_AGENTS_CONFIG="+f.agents, "NVT_BROKER_AUDIT_LOG="+f.audit, "NVT_BROKER_BIND="+bind, "FIXTURE_CREDENTIAL="+executableCanary)
		cmd.Env = append(cmd.Env, extra...)
		if err := cmd.Run(); err == nil {
			t.Fatal("broker setup failure unexpectedly succeeded")
		}
		for _, state := range []string{f.state + "-direct.shutdown", f.state + "-inject.shutdown"} {
			if _, err := os.Stat(state); err != nil {
				t.Fatalf("provider shutdown was not attempted: %s: %v", state, err)
			}
		}
		assertProviderStopped(t, f.state+"-direct")
		assertProviderStopped(t, f.state+"-inject")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	runFailure(t, listener.Addr().String())
	_ = listener.Close()
	runFailure(t, fmt.Sprintf("127.0.0.1:%d", freePort(t)), "NVT_BROKER_TLS_CERT=/missing/cert", "NVT_BROKER_TLS_KEY=/missing/key")

	f := newExecutableBrokerFixture(t)
	if err := f.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- f.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("broker did not exit after SIGTERM")
	}
	f.cmd = nil
	for _, state := range []string{f.state + "-direct.shutdown", f.state + "-inject.shutdown"} {
		if _, err := os.Stat(state); err != nil {
			t.Fatalf("SIGTERM did not attempt provider shutdown: %s: %v", state, err)
		}
	}
	assertProviderStopped(t, f.state+"-direct")
	assertProviderStopped(t, f.state+"-inject")
}
