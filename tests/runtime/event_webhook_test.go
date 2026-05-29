package runtime_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type capturedWebhookRequest struct {
	Header http.Header
	Body   map[string]any
}

func TestEventWebhookConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		extra   []string
		wantErr string
	}{
		{
			name:    "missing-url",
			config:  "since: end\n",
			wantErr: "url is required",
		},
		{
			name: "invalid-since",
			config: `
url: http://example.test/events
since: earliest
`,
			wantErr: "since must be end or beginning",
		},
		{
			name: "bearer-missing-env",
			config: `
url: http://example.test/events
auth:
  type: bearer-env
`,
			wantErr: "auth.env is required",
		},
		{
			name: "bearer-missing-token",
			config: `
url: http://example.test/events
auth:
  type: bearer-env
  env: MISSING_EVENT_WEBHOOK_TOKEN
`,
			wantErr: "environment variable MISSING_EVENT_WEBHOOK_TOKEN is not set",
		},
		{
			name: "url-not-string",
			config: `
url: 123
`,
			wantErr: "url must be a string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			config := f.writePluginConfig("event-webhook.yaml", tt.config)
			output := f.runWithEnv(eventWebhookRunBin(f.root), false, append(tt.extra, "NVT_PLUGIN_CONFIG="+config))
			if !strings.Contains(output, tt.wantErr) {
				t.Fatalf("expected %q, got:\n%s", tt.wantErr, output)
			}
		})
	}
}

func TestEventWebhookFiltersEventAndPluginEvent(t *testing.T) {
	f := newFixture(t)
	capture := newWebhookCapture(t, func(_ map[string]any) int { return http.StatusNoContent })
	config := f.writePluginConfig("event-webhook.yaml", fmt.Sprintf(`
url: %s
filters:
  - plugin.github.pr.
  - agent.signal.done
delivery:
  retry:
    backoff-seconds: 0
`, quoteYAML(capture.URL)))
	writeFakeAgentdctl(t, f, []map[string]any{
		{"id": "plugin-match", "event": "plugin.event", "plugin_event": "plugin.github.pr.merged"},
		{"id": "event-match", "event": "agent.signal.done"},
		{"id": "skip", "event": "plugin.event", "plugin_event": "plugin.other.event"},
	})

	f.runWithEnv(eventWebhookRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config})

	requests := capture.Requests()
	if len(requests) != 2 {
		t.Fatalf("expected 2 delivered events, got %d: %#v", len(requests), requests)
	}
	if eventID(requests[0]) != "plugin-match" || eventID(requests[1]) != "event-match" {
		t.Fatalf("unexpected delivered events: %#v", requests)
	}
}

func TestEventWebhookPostsEnvelopeAndAuth(t *testing.T) {
	f := newFixture(t)
	capture := newWebhookCapture(t, func(_ map[string]any) int { return http.StatusNoContent })
	config := f.writePluginConfig("event-webhook.yaml", fmt.Sprintf(`
url: %s
auth:
  type: bearer-env
  env: EVENT_WEBHOOK_TEST_TOKEN
delivery:
  retry:
    backoff-seconds: 0
`, quoteYAML(capture.URL)))
	writeFakeAgentdctl(t, f, []map[string]any{
		{"id": "body-test", "event": "agent.signal.done", "payload": map[string]any{"ok": true}},
	})

	f.runWithEnv(eventWebhookRunBin(f.root), true, []string{
		"NVT_PLUGIN_CONFIG=" + config,
		"NVT_AGENT_NAME=agent-one",
		"EVENT_WEBHOOK_TEST_TOKEN=secret-token",
	})

	requests := capture.Requests()
	if len(requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(requests))
	}
	request := requests[0]
	if request.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("expected JSON content type, got %q", request.Header.Get("Content-Type"))
	}
	if request.Header.Get("Authorization") != "Bearer secret-token" {
		t.Fatalf("expected bearer auth header, got %q", request.Header.Get("Authorization"))
	}
	if request.Body["agent"] != "agent-one" {
		t.Fatalf("expected agent name in body, got %#v", request.Body)
	}
	if eventID(request) != "body-test" {
		t.Fatalf("expected original event in body, got %#v", request.Body)
	}
}

func TestEventWebhookAuthNoneSendsNoAuthorization(t *testing.T) {
	f := newFixture(t)
	capture := newWebhookCapture(t, func(_ map[string]any) int { return http.StatusNoContent })
	config := f.writePluginConfig("event-webhook.yaml", fmt.Sprintf(`
url: %s
auth:
  type: none
delivery:
  retry:
    backoff-seconds: 0
`, quoteYAML(capture.URL)))
	writeFakeAgentdctl(t, f, []map[string]any{{"id": "no-auth", "event": "agent.signal.done"}})

	f.runWithEnv(eventWebhookRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config})

	requests := capture.Requests()
	if len(requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(requests))
	}
	if got := requests[0].Header.Get("Authorization"); got != "" {
		t.Fatalf("expected no authorization header, got %q", got)
	}
}

func TestEventWebhookDedupeSkipsDeliveredEventOnReplay(t *testing.T) {
	f := newFixture(t)
	capture := newWebhookCapture(t, func(_ map[string]any) int { return http.StatusNoContent })
	config := f.writePluginConfig("event-webhook.yaml", fmt.Sprintf(`
url: %s
since: beginning
delivery:
  dedupe: true
  max-delivered-ids: 1000
  retry:
    backoff-seconds: 0
`, quoteYAML(capture.URL)))
	writeFakeAgentdctl(t, f, []map[string]any{{"id": "replayed", "event": "agent.signal.done"}})

	f.runWithEnv(eventWebhookRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config})
	f.runWithEnv(eventWebhookRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config})

	requests := capture.Requests()
	if len(requests) != 1 {
		t.Fatalf("expected replayed event to be delivered once, got %d", len(requests))
	}
	var state map[string][]string
	decodeJSONFile(t, filepath.Join(f.state, "plugins", "event-webhook", "delivery-state.json"), &state)
	if len(state["delivered_ids"]) != 1 || state["delivered_ids"][0] != "replayed" {
		t.Fatalf("unexpected delivery state: %#v", state)
	}
}

func TestEventWebhookRetriesAndContinues(t *testing.T) {
	f := newFixture(t)
	attempts := map[string]int{}
	var attemptsMu sync.Mutex
	capture := newWebhookCapture(t, func(body map[string]any) int {
		id := eventIDFromBody(body)
		attemptsMu.Lock()
		attempts[id]++
		attempt := attempts[id]
		attemptsMu.Unlock()
		if id == "failing" || (id == "retry-then-ok" && attempt == 1) {
			return http.StatusInternalServerError
		}
		return http.StatusNoContent
	})
	config := f.writePluginConfig("event-webhook.yaml", fmt.Sprintf(`
url: %s
delivery:
  retry:
    max-attempts: 2
    backoff-seconds: 0
`, quoteYAML(capture.URL)))
	writeFakeAgentdctl(t, f, []map[string]any{
		{"id": "failing", "event": "agent.signal.done"},
		{"id": "retry-then-ok", "event": "agent.signal.done"},
		{"id": "after-failure", "event": "agent.signal.done"},
	})

	output := f.runWithEnv(eventWebhookRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config})
	if !strings.Contains(output, "failed to deliver event after 2 attempts") {
		t.Fatalf("expected retry exhaustion log, got:\n%s", output)
	}

	attemptsMu.Lock()
	defer attemptsMu.Unlock()
	if attempts["failing"] != 2 || attempts["retry-then-ok"] != 2 || attempts["after-failure"] != 1 {
		t.Fatalf("unexpected attempts: %#v", attempts)
	}
}

type webhookCapture struct {
	URL      string
	server   *httptest.Server
	mu       sync.Mutex
	requests []capturedWebhookRequest
}

func newWebhookCapture(t *testing.T, status func(map[string]any) int) *webhookCapture {
	t.Helper()
	capture := &webhookCapture{}
	capture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		capture.mu.Lock()
		capture.requests = append(capture.requests, capturedWebhookRequest{
			Header: r.Header.Clone(),
			Body:   body,
		})
		capture.mu.Unlock()
		w.WriteHeader(status(body))
	}))
	capture.URL = capture.server.URL
	t.Cleanup(capture.server.Close)
	return capture
}

func (c *webhookCapture) Requests() []capturedWebhookRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	requests := make([]capturedWebhookRequest, len(c.requests))
	copy(requests, c.requests)
	return requests
}

func writeFakeAgentdctl(t *testing.T, f *fixture, events []map[string]any) {
	t.Helper()
	eventsPath := filepath.Join(f.home, "fake-agentd-events.jsonl")
	var lines []string
	for _, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(data))
	}
	if err := os.WriteFile(eventsPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.writeBin("agentdctl", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
if [ "$1" != "subscribe" ]; then
  echo "unexpected command: $*" >&2
  exit 2
fi
cat %s
`, shellQuote(eventsPath)))
}

func eventID(request capturedWebhookRequest) string {
	return eventIDFromBody(request.Body)
}

func eventIDFromBody(body map[string]any) string {
	event, _ := body["event"].(map[string]any)
	id, _ := event["id"].(string)
	return id
}
