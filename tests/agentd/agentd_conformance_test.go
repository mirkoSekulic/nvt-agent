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
	t            *testing.T
	root         string
	socket       string
	state        string
	session      string
	readyMarker  string
	startupGrace string
	cmd          *exec.Cmd
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

func TestMaximumSessionStartupGraceHasCallerMargin(t *testing.T) {
	root := repoRoot(t)
	temp := t.TempDir()
	script := `import runpy,sys
m=runpy.run_path(sys.argv[1])
a=m["Agentd"](sys.argv[2],sys.argv[3],"test","buffer",30,sys.argv[4])
assert a.session_ready_wait_seconds > 30, a.session_ready_wait_seconds
`
	cmd := exec.Command("python3", "-c", script,
		filepath.Join(root, "runtime", "agentd", "agentd.py"),
		filepath.Join(temp, "agentd.sock"), temp, filepath.Join(temp, "session-launched"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("maximum startup grace has no caller margin: %v\n%s", err, output)
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

func TestPromptWaitsForContinuouslyReadySession(t *testing.T) {
	f := startFixtureWithGrace(t, false, "0.8")
	readyMarker := filepath.Join(f.state, "target-ready")
	command := fmt.Sprintf("sleep 0.1; touch %s; exec cat", shellQuote(readyMarker))
	cmd := exec.Command("tmux", "new-session", "-d", "-s", f.session, "sh", "-c", command)
	cmd.Env = append(os.Environ(), "TERM=screen")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("start delayed tmux target: %v\n%s", err, output)
	}
	t.Cleanup(func() { _ = exec.Command("tmux", "kill-session", "-t", f.session).Run() })
	writeSessionReadyMarker(t, f.readyMarker)

	sentinel := "nvt-agentd-delayed-ready-" + uniqueID()
	response := make(chan map[string]any, 1)
	requestError := make(chan error, 1)
	go func() {
		result, err := f.tryRequest(map[string]any{
			"type":     "prompt",
			"source":   "test",
			"external": false,
			"message":  sentinel,
		})
		if err != nil {
			requestError <- err
			return
		}
		response <- result
	}()

	waitFor(t, 2*time.Second, func() bool {
		_, err := os.Stat(readyMarker)
		return err == nil
	})
	select {
	case result := <-response:
		t.Fatalf("prompt was accepted before the continuous startup grace: %#v", result)
	case err := <-requestError:
		t.Fatalf("prompt request failed before startup grace: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	for _, event := range readEvents(t, f.eventsPath()) {
		if event["event"] == "prompt.queued" || event["event"] == "prompt.injected" {
			t.Fatalf("prompt event emitted before readiness gate: %#v", event)
		}
	}

	select {
	case result := <-response:
		assertOK(t, result)
	case err := <-requestError:
		t.Fatalf("prompt request failed after startup grace: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("prompt was not accepted after the bounded startup grace")
	}
	waitFor(t, 3*time.Second, func() bool {
		return strings.Contains(capturePane(t, f.session), sentinel) &&
			countEvents(t, f.eventsPath(), "prompt.injected") == 1
	})
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

	response := f.request(map[string]any{
		"type":     "prompt",
		"source":   "plugin:smoke",
		"external": false,
		"message":  sentinel,
	})
	if response["ok"] != false || !strings.Contains(fmt.Sprint(response["error"]), "bounded startup window") {
		t.Fatalf("expected bounded readiness failure, got %#v", response)
	}
	for _, event := range readEvents(t, f.eventsPath()) {
		if event["event"] == "prompt.queued" || event["event"] == "prompt.injected" || event["event"] == "prompt.failed" {
			t.Fatalf("missing session must not create a prompt record: %#v", event)
		}
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

func TestSubscribeDefaultSinceEndSeesFutureEventsOnly(t *testing.T) {
	f := startFixture(t, true)
	oldEvent := "plugin.subscribe.old-" + uniqueID()
	f.publishPluginEvent(oldEvent, map[string]any{"old": true})

	subscriber := startSubscriber(t, f, "--filter", "plugin.subscribe.")
	assertNoLine(t, subscriber, 250*time.Millisecond)

	futureEvent := "plugin.subscribe.future-" + uniqueID()
	f.publishPluginEvent(futureEvent, map[string]any{"future": true})
	event := readSubscriberEvent(t, subscriber, time.Second)
	if event["plugin_event"] != futureEvent {
		t.Fatalf("expected future event %q, got %#v", futureEvent, event)
	}
}

func TestSubscribeBeginningReplaysHistoryAndMultipleFilters(t *testing.T) {
	f := startFixture(t, true)
	testEvent := "plugin.tests.failed-" + uniqueID()
	githubEvent := "plugin.github.comment-" + uniqueID()
	otherEvent := "plugin.other.ignored-" + uniqueID()
	f.publishPluginEvent(testEvent, map[string]any{"kind": "tests"})
	f.publishPluginEvent(githubEvent, map[string]any{"kind": "github"})
	f.publishPluginEvent(otherEvent, map[string]any{"kind": "other"})

	subscriber := startSubscriber(t, f,
		"--since", "beginning",
		"--filter", "plugin.tests.",
		"--filter", "plugin.github.",
	)

	seen := map[string]bool{}
	waitFor(t, time.Second, func() bool {
		for {
			select {
			case line := <-subscriber.lines:
				event := decodeJSON(t, []byte(line))
				if pluginEvent, ok := event["plugin_event"].(string); ok {
					seen[pluginEvent] = true
					if pluginEvent == otherEvent {
						t.Fatalf("subscriber received excluded event %#v", event)
					}
				}
			default:
				return seen[testEvent] && seen[githubEvent]
			}
		}
	})
}

func TestSubscribeToleratesMissingEventLog(t *testing.T) {
	root := repoRoot(t)
	temp, err := os.MkdirTemp("", "nvt-agentd-subscribe-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(temp) })

	state := filepath.Join(temp, "state")
	subscriber := startRawSubscriber(t, agentdctlBin(root), []string{"NVT_STATE_DIR=" + state}, "subscribe", "--since", "beginning", "--filter", "plugin.missing.")
	eventPath := filepath.Join(state, "agentd", "events.jsonl")
	if err := os.MkdirAll(filepath.Dir(eventPath), 0o755); err != nil {
		t.Fatalf("create event log dir: %v", err)
	}
	expected := "plugin.missing.created-" + uniqueID()
	appendEventLine(t, eventPath, map[string]any{
		"id":           "evt_" + uniqueID(),
		"event":        "plugin.event",
		"created_at":   "2026-05-24T00:00:00Z",
		"source":       "plugin:missing",
		"plugin_event": expected,
		"payload":      map[string]any{"ok": true},
	})

	event := readSubscriberEvent(t, subscriber, time.Second)
	if event["plugin_event"] != expected {
		t.Fatalf("expected missing-log event %q, got %#v", expected, event)
	}
}

func TestSubscribeDuringConcurrentPublishEmitsValidJSONL(t *testing.T) {
	f := startFixture(t, true)
	subscriber := startSubscriber(t, f, "--since", "beginning", "--filter", "plugin.stream.")
	const count = 20

	for i := 0; i < count; i++ {
		f.publishPluginEvent(fmt.Sprintf("plugin.stream.event-%d-%s", i, uniqueID()), map[string]any{
			"index": i,
			"data":  strings.Repeat("x", 12000),
		})
	}

	received := 0
	waitFor(t, time.Second, func() bool {
		for {
			select {
			case line := <-subscriber.lines:
				event := decodeJSON(t, []byte(line))
				if _, ok := event["id"].(string); !ok {
					t.Fatalf("subscriber event missing id: %#v", event)
				}
				received++
			default:
				return received >= count
			}
		}
	})
}

func TestSignalPublishesAdvisoryAgentSignal(t *testing.T) {
	f := startFixture(t, true)
	output, err := commandWithEnv(t, agentdctlBin(f.root), append(f.env(), "NVT_AGENTD_SOCKET="+f.socket),
		"signal", "done", "--message", "finished",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("agentdctl signal failed: %v\n%s", err, output)
	}
	assertOK(t, decodeJSON(t, output))

	waitFor(t, time.Second, func() bool {
		for _, event := range readEvents(t, f.eventsPath()) {
			if event["plugin_event"] == "plugin.agent.signal.done" {
				payload, ok := event["payload"].(map[string]any)
				if !ok {
					t.Fatalf("signal payload is not object: %#v", event)
				}
				return payload["message"] == "finished"
			}
		}
		return false
	})

	output, err = commandWithEnv(t, agentdctlBin(f.root), append(f.env(), "NVT_AGENTD_SOCKET="+f.socket),
		"signal", "",
	).CombinedOutput()
	if err == nil {
		t.Fatalf("expected empty signal name to fail, got output %s", output)
	}
}

func startFixture(t *testing.T, startTmux bool) *fixture {
	return startFixtureWithGrace(t, startTmux, "0")
}

func startFixtureWithGrace(t *testing.T, startTmux bool, startupGrace string) *fixture {
	t.Helper()
	root := repoRoot(t)
	temp, err := os.MkdirTemp("", "nvt-agentd-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(temp) })
	f := &fixture{
		t:            t,
		root:         root,
		socket:       filepath.Join(temp, "agentd.sock"),
		state:        filepath.Join(temp, "state"),
		session:      "nvt-agentd-" + uniqueID(),
		readyMarker:  filepath.Join(temp, "state", "agentd", "session-launched"),
		startupGrace: startupGrace,
	}

	if startTmux {
		startTmuxCat(t, f.session)
		writeSessionReadyMarker(t, f.readyMarker)
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

func (f *fixture) publishPluginEvent(event string, payload map[string]any) {
	f.t.Helper()
	assertOK(f.t, f.request(map[string]any{
		"type":    "event.publish",
		"source":  "plugin:test",
		"event":   event,
		"payload": payload,
	}))
}

func (f *fixture) env() []string {
	return []string{
		"NVT_AGENTD_SOCKET=" + f.socket,
		"NVT_STATE_DIR=" + f.state,
		"AGENT_SESSION=" + f.session,
		"NVT_AGENT_SESSION_READY_MARKER=" + f.readyMarker,
		"NVT_AGENT_SESSION_STARTUP_GRACE_SECONDS=" + f.startupGrace,
		"TERM=screen",
	}
}

func writeSessionReadyMarker(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("launched\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) stop() {
	if f.cmd == nil || f.cmd.Process == nil {
		return
	}
	signalProcessGroup(f.cmd, syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- f.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		signalProcessGroup(f.cmd, syscall.SIGKILL)
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
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

func signalProcessGroup(cmd *exec.Cmd, signal syscall.Signal) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if err := syscall.Kill(-cmd.Process.Pid, signal); err != nil {
		_ = cmd.Process.Signal(signal)
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

type subscriber struct {
	cmd   *exec.Cmd
	lines chan string
}

func startSubscriber(t *testing.T, f *fixture, args ...string) *subscriber {
	t.Helper()
	return startRawSubscriber(t, agentdctlBin(f.root), append(f.env(), "NVT_STATE_DIR="+f.state), append([]string{"subscribe"}, args...)...)
}

func startRawSubscriber(t *testing.T, command string, env []string, args ...string) *subscriber {
	t.Helper()
	cmd := commandWithEnv(t, command, env, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("create subscriber stdout pipe: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start subscriber: %v", err)
	}

	sub := &subscriber{
		cmd:   cmd,
		lines: make(chan string, 100),
	}
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			sub.lines <- scanner.Text()
		}
		close(sub.lines)
	}()
	t.Cleanup(func() { stopSubscriber(sub) })
	return sub
}

func stopSubscriber(sub *subscriber) {
	if sub == nil || sub.cmd == nil || sub.cmd.Process == nil {
		return
	}
	signalProcessGroup(sub.cmd, syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- sub.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(time.Second):
		signalProcessGroup(sub.cmd, syscall.SIGKILL)
		<-done
	}
	sub.cmd = nil
}

func readSubscriberEvent(t *testing.T, sub *subscriber, timeout time.Duration) map[string]any {
	t.Helper()
	select {
	case line, ok := <-sub.lines:
		if !ok {
			t.Fatal("subscriber exited before emitting an event")
		}
		return decodeJSON(t, []byte(line))
	case <-time.After(timeout):
		t.Fatalf("subscriber did not emit an event within %s", timeout)
	}
	return nil
}

func assertNoLine(t *testing.T, sub *subscriber, timeout time.Duration) {
	t.Helper()
	select {
	case line, ok := <-sub.lines:
		if ok {
			t.Fatalf("expected no subscriber output, got %s", line)
		}
		t.Fatal("subscriber exited unexpectedly")
	case <-time.After(timeout):
	}
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

func appendEventLine(t *testing.T, path string, event map[string]any) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open event log for append: %v", err)
	}
	defer file.Close()
	line, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	if _, err := file.Write(append(line, '\n')); err != nil {
		t.Fatalf("append event: %v", err)
	}
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
