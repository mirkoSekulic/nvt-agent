package runtime_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSmokeCompletePublishesDefaultEvent(t *testing.T) {
	f := newFixture(t)
	capturePath := filepath.Join(f.home, "agentdctl-publish.json")
	writeSmokeCompleteAgentdctl(t, f, capturePath)
	writeSmokeCompletePluginState(t, f, "event-webhook", map[string]any{"status": "running", "ready": true})
	config := f.writePluginConfig("smoke-complete.yaml", "delaySeconds: 0\n")

	f.runWithEnv(smokeCompleteRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config})

	capture := readSmokeCompleteCapture(t, capturePath)
	if capture.Event != "plugin.smoke.completed" {
		t.Fatalf("expected default event, got %q", capture.Event)
	}
	if capture.Source != "plugin:smoke-complete" {
		t.Fatalf("expected smoke-complete source, got %q", capture.Source)
	}
	if capture.Payload["ok"] != true {
		t.Fatalf("expected default ok payload, got %#v", capture.Payload)
	}
}

func TestSmokeCompletePublishesCustomEventAndPayload(t *testing.T) {
	f := newFixture(t)
	capturePath := filepath.Join(f.home, "agentdctl-publish.json")
	writeSmokeCompleteAgentdctl(t, f, capturePath)
	writeSmokeCompletePluginState(t, f, "event-webhook", map[string]any{"status": "running", "ready": true})
	config := f.writePluginConfig("smoke-complete.yaml", `
delaySeconds: 0
event: plugin.smoke.custom
payload:
  ok: false
  message: done
  count: 2
`)

	f.runWithEnv(smokeCompleteRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config})

	capture := readSmokeCompleteCapture(t, capturePath)
	if capture.Event != "plugin.smoke.custom" {
		t.Fatalf("expected custom event, got %q", capture.Event)
	}
	if capture.Payload["ok"] != false || capture.Payload["message"] != "done" || capture.Payload["count"].(float64) != 2 {
		t.Fatalf("unexpected custom payload: %#v", capture.Payload)
	}
}

func TestSmokeCompleteRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name:    "payload-list",
			config:  "delaySeconds: 0\npayload: []\n",
			wantErr: "payload must be a YAML object",
		},
		{
			name:    "delay-string",
			config:  "delaySeconds: soon\n",
			wantErr: "delaySeconds must be an integer",
		},
		{
			name:    "delay-negative",
			config:  "delaySeconds: -1\n",
			wantErr: "delaySeconds must be greater than or equal to 0",
		},
		{
			name:    "event-not-plugin-event",
			config:  "delaySeconds: 0\nevent: smoke.completed\n",
			wantErr: "event must start with plugin.",
		},
		{
			name: "payload-not-json",
			config: `
delaySeconds: 0
payload:
  bad: !!set
    ? value
`,
			wantErr: "payload must be JSON-serializable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			writeSmokeCompleteAgentdctl(t, f, filepath.Join(f.home, "agentdctl-publish.json"))
			writeSmokeCompletePluginState(t, f, "event-webhook", map[string]any{"status": "running", "ready": true})
			config := f.writePluginConfig("smoke-complete.yaml", tt.config)

			output := f.runWithEnv(smokeCompleteRunBin(f.root), false, []string{"NVT_PLUGIN_CONFIG=" + config})
			if !strings.Contains(output, tt.wantErr) {
				t.Fatalf("expected %q, got:\n%s", tt.wantErr, output)
			}
		})
	}
}

func TestSmokeCompleteWaitsForEventWebhookReadiness(t *testing.T) {
	f := newFixture(t)
	writeSmokeCompleteAgentdctl(t, f, filepath.Join(f.home, "agentdctl-publish.json"))
	config := f.writePluginConfig("smoke-complete.yaml", `
delaySeconds: 0
waitTimeoutSeconds: 0
`)

	output := f.runWithEnv(smokeCompleteRunBin(f.root), false, []string{"NVT_PLUGIN_CONFIG=" + config})
	if !strings.Contains(output, "timed out waiting for waitForPlugin event-webhook to be ready") {
		t.Fatalf("expected event-webhook readiness timeout, got:\n%s", output)
	}
}

func TestSmokeCompleteCanDisableWaitForPlugin(t *testing.T) {
	f := newFixture(t)
	capturePath := filepath.Join(f.home, "agentdctl-publish.json")
	writeSmokeCompleteAgentdctl(t, f, capturePath)
	config := f.writePluginConfig("smoke-complete.yaml", `
delaySeconds: 0
waitForPlugin: false
`)

	f.runWithEnv(smokeCompleteRunBin(f.root), true, []string{"NVT_PLUGIN_CONFIG=" + config})

	capture := readSmokeCompleteCapture(t, capturePath)
	if capture.Event != "plugin.smoke.completed" {
		t.Fatalf("expected default event, got %q", capture.Event)
	}
}

type smokeCompleteCapture struct {
	Event   string         `json:"event"`
	Source  string         `json:"source"`
	Payload map[string]any `json:"payload"`
}

func writeSmokeCompletePluginState(t *testing.T, f *fixture, name string, state map[string]any) {
	t.Helper()
	path := filepath.Join(f.state, "plugins", name, "state.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeSmokeCompleteAgentdctl(t *testing.T, f *fixture, capturePath string) {
	t.Helper()
	f.writeBin("agentdctl", fmt.Sprintf(`#!/usr/bin/env python3
import json
import sys

args = sys.argv[1:]
if len(args) != 6 or args[0] != "publish" or args[2] != "--source" or args[4] != "--payload":
    print("unexpected args: " + " ".join(args), file=sys.stderr)
    sys.exit(2)
with open(%s, "w", encoding="utf-8") as file:
    json.dump({
        "event": args[1],
        "source": args[3],
        "payload": json.loads(args[5]),
    }, file, sort_keys=True)
    file.write("\n")
`, quoteYAML(capturePath)))
}

func readSmokeCompleteCapture(t *testing.T, path string) smokeCompleteCapture {
	t.Helper()
	var capture smokeCompleteCapture
	decodeJSONFile(t, path, &capture)
	return capture
}
