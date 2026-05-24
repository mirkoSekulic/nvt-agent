package agentd_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fixture struct {
	t       *testing.T
	root    string
	socket  string
	state   string
	session string
	cmd     *exec.Cmd
}

// These tests intentionally avoid t.Parallel because agentd talks to the
// default tmux server. Each test gets a unique session, but the server is shared.

func TestHealthAndStatus(t *testing.T) {
	f := startFixture(t, true)

	health := f.request(map[string]any{"type": "health"})
	assertOK(t, health)
	if health["status"] != "ready" {
		t.Fatalf("expected ready health, got %#v", health["status"])
	}

	status := f.request(map[string]any{"type": "status"})
	assertOK(t, status)
	assertString(t, status, "session")
	assertNumber(t, status, "queue_depth")
	assertString(t, status, "state")
	assertNumber(t, status, "uptime_seconds")
	if status["session"] != f.session {
		t.Fatalf("expected session %q, got %#v", f.session, status["session"])
	}
}

func TestPromptInjectionExternalFalse(t *testing.T) {
	f := startFixture(t, true)
	sentinel := "nvt-agentd-external-false-" + uniqueID()

	response := f.request(map[string]any{
		"type":     "prompt",
		"source":   "test",
		"external": false,
		"message":  sentinel,
	})
	assertOK(t, response)
	assertString(t, response, "id")
	if response["status"] != "queued" {
		t.Fatalf("expected queued prompt, got %#v", response["status"])
	}

	waitFor(t, 3*time.Second, func() bool {
		return strings.Contains(capturePane(t, f.session), sentinel)
	})
	pane := capturePane(t, f.session)
	if strings.Contains(pane, "External prompt") {
		t.Fatalf("external preamble should not be present for external=false:\n%s", pane)
	}
}

func TestPromptInjectionExternalTrueAndFIFO(t *testing.T) {
	f := startFixture(t, true)
	first := "nvt-agentd-first-" + uniqueID()
	second := "nvt-agentd-second-" + uniqueID()

	assertOK(t, f.request(map[string]any{
		"type":     "prompt",
		"source":   "plugin:smoke",
		"external": true,
		"message":  first,
	}))
	assertOK(t, f.request(map[string]any{
		"type":     "prompt",
		"source":   "plugin:smoke",
		"external": true,
		"message":  second,
	}))

	waitFor(t, 3*time.Second, func() bool {
		pane := capturePane(t, f.session)
		return strings.Contains(pane, first) && strings.Contains(pane, second)
	})
	pane := capturePane(t, f.session)
	if !strings.Contains(pane, "External prompt from plugin:smoke") {
		t.Fatalf("external preamble missing:\n%s", pane)
	}
	if strings.Index(pane, first) > strings.Index(pane, second) {
		t.Fatalf("expected FIFO prompt order:\n%s", pane)
	}
}

func TestPromptMissingMessageFails(t *testing.T) {
	f := startFixture(t, true)
	response := f.request(map[string]any{"type": "prompt", "source": "test"})
	assertError(t, response)
}

func TestEventPublishValidation(t *testing.T) {
	f := startFixture(t, true)

	valid := f.request(map[string]any{
		"type":    "event.publish",
		"source":  "plugin:smoke",
		"event":   "plugin.smoke.ready",
		"payload": map[string]any{"ok": true},
	})
	assertOK(t, valid)
	if valid["status"] != "published" {
		t.Fatalf("expected published event, got %#v", valid["status"])
	}

	assertError(t, f.request(map[string]any{
		"type":    "event.publish",
		"source":  "plugin:smoke",
		"event":   "session.turn-finished",
		"payload": map[string]any{},
	}))
	assertError(t, f.request(map[string]any{
		"type":    "event.publish",
		"source":  "plugin:smoke",
		"event":   "smoke.ready",
		"payload": map[string]any{},
	}))
	assertError(t, f.request(map[string]any{
		"type":    "event.publish",
		"source":  "plugin:smoke",
		"event":   "plugin.smoke.ready",
		"payload": "not-object",
	}))
}

func TestUnknownAndMalformedRequestsFailWithoutCrash(t *testing.T) {
	f := startFixture(t, true)

	assertError(t, f.request(map[string]any{"type": "unknown"}))

	malformed := f.rawLine("{not json}\n")
	assertError(t, malformed)

	assertOK(t, f.request(map[string]any{"type": "health"}))
}

func TestConcurrentPublishKeepsEventLogValidJSONL(t *testing.T) {
	f := startFixture(t, true)
	const count = 40
	errs := make(chan error, count)

	for i := 0; i < count; i++ {
		i := i
		go func() {
			response := f.request(map[string]any{
				"type":    "event.publish",
				"source":  "plugin:burst",
				"event":   fmt.Sprintf("plugin.burst.event-%d", i),
				"payload": map[string]any{"index": i, "data": strings.Repeat("x", 12000)},
			})
			if response["ok"] != true {
				errs <- fmt.Errorf("publish failed: %#v", response)
				return
			}
			errs <- nil
		}()
	}

	for i := 0; i < count; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}

	waitFor(t, 3*time.Second, func() bool {
		return countEvents(t, f.eventsPath(), "plugin.event") >= count
	})
	for lineNumber, event := range readEvents(t, f.eventsPath()) {
		if _, ok := event["id"].(string); !ok {
			t.Fatalf("event line %d missing string id: %#v", lineNumber+1, event)
		}
	}
}

func TestPromptFailureWhenTmuxSessionMissing(t *testing.T) {
	f := startFixture(t, false)
	sentinel := "nvt-agentd-missing-session-" + uniqueID()

	assertOK(t, f.request(map[string]any{
		"type":     "prompt",
		"source":   "plugin:smoke",
		"external": false,
		"message":  sentinel,
	}))

	waitFor(t, 3*time.Second, func() bool {
		return countEvents(t, f.eventsPath(), "prompt.failed") > 0
	})
	status := f.request(map[string]any{"type": "status"})
	assertOK(t, status)
	if status["last_error"] == nil || status["last_error"] == "" {
		t.Fatalf("expected last_error after failed prompt, got %#v", status)
	}
}

func TestSocketModeAndSigtermCleanup(t *testing.T) {
	f := startFixture(t, true)

	info, err := os.Stat(f.socket)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("expected socket mode 0600, got %04o", mode)
	}

	f.stop()
	waitFor(t, 3*time.Second, func() bool {
		_, err := os.Stat(f.socket)
		return errors.Is(err, os.ErrNotExist)
	})
	waitFor(t, 3*time.Second, func() bool {
		return countEvents(t, f.eventsPath(), "agentd.stopped") > 0
	})
}

func TestAgentdctlAndPromptAgentClients(t *testing.T) {
	f := startFixture(t, true)

	agentdctlSentinel := "nvt-agentdctl-" + uniqueID()
	agentdctl := commandWithEnv(t, agentdctlBin(f.root), append(f.env(), "NVT_AGENTD_SOCKET="+f.socket), "prompt", "--source", "plugin:agentdctl", agentdctlSentinel)
	output, err := agentdctl.CombinedOutput()
	if err != nil {
		t.Fatalf("agentdctl prompt failed: %v\n%s", err, output)
	}
	assertOK(t, decodeJSON(t, output))
	waitFor(t, 3*time.Second, func() bool {
		return strings.Contains(capturePane(t, f.session), agentdctlSentinel)
	})

	promptAgentSentinel := "nvt-prompt-agent-" + uniqueID()
	binDir := installAgentdctlWrapper(t, f)
	promptAgent := commandWithEnv(t, promptAgentBin(f.root), append(f.env(),
		"NVT_AGENTD_SOCKET="+f.socket,
		"NVT_PROMPT_SOURCE=plugin:prompt-agent",
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
	))
	promptAgent.Stdin = strings.NewReader(promptAgentSentinel)
	output, err = promptAgent.CombinedOutput()
	if err != nil {
		t.Fatalf("prompt-agent failed: %v\n%s", err, output)
	}
	assertOK(t, decodeJSON(t, output))
	waitFor(t, 3*time.Second, func() bool {
		pane := capturePane(t, f.session)
		return strings.Contains(pane, promptAgentSentinel) &&
			strings.Contains(pane, "External prompt from plugin:prompt-agent")
	})
}

func startFixture(t *testing.T, startTmux bool) *fixture {
	t.Helper()
	root := repoRoot(t)
	temp, err := os.MkdirTemp("", "nvt-agentd-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(temp) })
	f := &fixture{
		t:       t,
		root:    root,
		socket:  filepath.Join(temp, "agentd.sock"),
		state:   filepath.Join(temp, "state"),
		session: "nvt-agentd-" + uniqueID(),
	}

	if startTmux {
		startTmuxCat(t, f.session)
		t.Cleanup(func() {
			_ = exec.Command("tmux", "kill-session", "-t", f.session).Run()
		})
	}

	cmd := commandWithEnv(t, agentdBin(root), f.env())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start agentd: %v", err)
	}
	f.cmd = cmd
	t.Cleanup(func() { f.stop() })

	waitFor(t, 3*time.Second, func() bool {
		response, err := f.tryRequest(map[string]any{"type": "health"})
		return err == nil && response["ok"] == true
	})
	return f
}

func (f *fixture) env() []string {
	return []string{
		"NVT_AGENTD_SOCKET=" + f.socket,
		"NVT_STATE_DIR=" + f.state,
		"AGENT_SESSION=" + f.session,
		"TERM=screen",
	}
}

func (f *fixture) stop() {
	if f.cmd == nil || f.cmd.Process == nil {
		return
	}
	_ = f.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- f.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = f.cmd.Process.Kill()
		<-done
	}
	f.cmd = nil
}

func (f *fixture) eventsPath() string {
	return filepath.Join(f.state, "agentd", "events.jsonl")
}

func (f *fixture) request(payload map[string]any) map[string]any {
	f.t.Helper()
	response, err := f.tryRequest(payload)
	if err != nil {
		f.t.Fatalf("request %#v: %v", payload, err)
	}
	return response
}

func (f *fixture) tryRequest(payload map[string]any) (map[string]any, error) {
	var buffer bytes.Buffer
	if err := json.NewEncoder(&buffer).Encode(payload); err != nil {
		return nil, err
	}
	return f.rawLineE(buffer.String())
}

func (f *fixture) rawLine(line string) map[string]any {
	f.t.Helper()
	response, err := f.rawLineE(line)
	if err != nil {
		f.t.Fatalf("raw request: %v", err)
	}
	return response
}

func (f *fixture) rawLineE(line string) (map[string]any, error) {
	conn, err := net.DialTimeout("unix", f.socket, time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(line)); err != nil {
		return nil, err
	}
	response, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	return decodeJSONE(response)
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

func agentdBin(root string) string {
	if value := os.Getenv("AGENTD_BIN"); value != "" {
		return value
	}
	return "python3 " + shellQuote(filepath.Join(root, "runtime", "agentd", "agentd.py"))
}

func agentdctlBin(root string) string {
	if value := os.Getenv("AGENTDCTL_BIN"); value != "" {
		return value
	}
	return "python3 " + shellQuote(filepath.Join(root, "runtime", "agentd", "agentdctl.py"))
}

func promptAgentBin(root string) string {
	if value := os.Getenv("PROMPT_AGENT_BIN"); value != "" {
		return value
	}
	return "bash " + shellQuote(filepath.Join(root, "runtime", "core", "prompt-agent.sh"))
}

func installAgentdctlWrapper(t *testing.T, f *fixture) string {
	t.Helper()
	binDir := filepath.Join(f.state, "test-bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create wrapper bin dir: %v", err)
	}
	wrapper := filepath.Join(binDir, "agentdctl")
	content := "#!/usr/bin/env bash\nset -euo pipefail\nexec " + agentdctlBin(f.root) + " \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(content), 0o755); err != nil {
		t.Fatalf("write agentdctl wrapper: %v", err)
	}
	return binDir
}

func commandWithEnv(t *testing.T, command string, env []string, args ...string) *exec.Cmd {
	t.Helper()
	fullCommand := command
	for _, arg := range args {
		fullCommand += " " + shellQuote(arg)
	}
	cmd := exec.Command("sh", "-c", fullCommand)
	cmd.Env = append(os.Environ(), env...)
	return cmd
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func startTmuxCat(t *testing.T, session string) {
	t.Helper()
	cmd := exec.Command("tmux", "new-session", "-d", "-s", session, "cat")
	cmd.Env = append(os.Environ(), "TERM=screen")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("start tmux session: %v\n%s", err, output)
	}
}

func capturePane(t *testing.T, session string) string {
	t.Helper()
	output, err := exec.Command("tmux", "capture-pane", "-p", "-S", "-", "-t", session).CombinedOutput()
	if err != nil {
		t.Fatalf("capture tmux pane: %v\n%s", err, output)
	}
	return string(output)
}

func readEvents(t *testing.T, path string) []map[string]any {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		t.Fatalf("open events: %v", err)
	}
	defer file.Close()

	var events []map[string]any
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		events = append(events, decodeJSON(t, scanner.Bytes()))
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan events: %v", err)
	}
	return events
}

func countEvents(t *testing.T, path string, eventName string) int {
	t.Helper()
	count := 0
	for _, event := range readEvents(t, path) {
		if event["event"] == eventName {
			count++
		}
	}
	return count
}

func decodeJSON(t *testing.T, data []byte) map[string]any {
	t.Helper()
	value, err := decodeJSONE(data)
	if err != nil {
		t.Fatalf("decode JSON %q: %v", data, err)
	}
	return value
}

func decodeJSONE(data []byte) (map[string]any, error) {
	var value map[string]any
	err := json.Unmarshal(bytes.TrimSpace(data), &value)
	return value, err
}

func assertOK(t *testing.T, response map[string]any) {
	t.Helper()
	if response["ok"] != true {
		t.Fatalf("expected ok response, got %#v", response)
	}
}

func assertError(t *testing.T, response map[string]any) {
	t.Helper()
	if response["ok"] != false {
		t.Fatalf("expected error response, got %#v", response)
	}
	if _, ok := response["error"].(string); !ok {
		t.Fatalf("expected string error, got %#v", response)
	}
}

func assertString(t *testing.T, response map[string]any, field string) {
	t.Helper()
	if _, ok := response[field].(string); !ok {
		t.Fatalf("expected %s to be a string in %#v", field, response)
	}
}

func assertNumber(t *testing.T, response map[string]any, field string) {
	t.Helper()
	if _, ok := response[field].(float64); !ok {
		t.Fatalf("expected %s to be a number in %#v", field, response)
	}
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("condition did not become true within %s", timeout)
}

func uniqueID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
