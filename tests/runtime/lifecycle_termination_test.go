package runtime_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLifecycleTerminationWritesMatchedEventWithoutBearerMaterial(t *testing.T) {
	f := newFixture(t)
	messagePath := filepath.Join(f.home, "termination-log")
	config := f.writePluginConfig("lifecycle-termination.yaml", `
completeOn:
  - plugin.smoke.completed
failOn:
  - plugin.smoke.failed
terminationMessagePath: `+messagePath+`
`)
	writeFakeAgentdctl(t, f, []map[string]any{
		{"event": "plugin.event", "plugin_event": "plugin.unmatched"},
		{"event": "plugin.event", "plugin_event": "plugin.smoke.completed"},
	})

	f.runWithEnv(lifecycleTerminationRunBin(f.root), true, []string{
		"NVT_PLUGIN_CONFIG=" + config,
		"NVT_LIFECYCLE_TERMINATE_PID=0",
	})

	data, err := os.ReadFile(messagePath)
	if err != nil {
		t.Fatal(err)
	}
	var message map[string]string
	if err := json.Unmarshal(data, &message); err != nil {
		t.Fatalf("invalid termination message: %v: %s", err, data)
	}
	if message["nvtLifecycleEvent"] != "plugin.smoke.completed" || message["outcome"] != "completed" {
		t.Fatalf("unexpected termination message: %#v", message)
	}
	if strings.Contains(string(data), "token") || strings.Contains(string(data), "Authorization") {
		t.Fatalf("termination message carried bearer material: %s", data)
	}
}

func TestLifecycleTerminationRejectsMissingEvents(t *testing.T) {
	f := newFixture(t)
	config := f.writePluginConfig("lifecycle-termination.yaml", "terminationMessagePath: /tmp/message\n")
	output := f.runWithEnv(lifecycleTerminationRunBin(f.root), false, []string{"NVT_PLUGIN_CONFIG=" + config})
	if !strings.Contains(output, "at least one completeOn or failOn event is required") {
		t.Fatalf("unexpected validation output: %s", output)
	}
}

func TestOperatorPreparedPlaceholdersNeverFallBackToBrokerctl(t *testing.T) {
	f := newFixture(t)
	called := filepath.Join(f.home, "brokerctl-called")
	f.writeBin("brokerctl", "#!/usr/bin/env sh\ntouch "+shellQuote(called)+"\nexit 99\n")
	config := filepath.Join(f.home, "agent.yaml")
	if err := os.WriteFile(config, []byte(`
preseed:
  files:
    - path: $HOME/.codex/auth.json
      mode: "0600"
      overwrite: true
      content: '{"access_token":"NVT-PLACEHOLDER-NOT-A-KEY"}'
egress:
  mode: mediated
  operator-prepared: true
  placeholder: NVT-PLACEHOLDER-NOT-A-KEY
  grants:
    - provider: codex-main
      materialization: placeholder-file
`), 0o600); err != nil {
		t.Fatal(err)
	}
	f.runWithEnv(bootstrapBin(f.root), true, []string{"NVT_EGRESS_MODE=mediated"}, config)
	if _, err := os.Stat(called); !os.IsNotExist(err) {
		t.Fatalf("zero-secret bootstrap called brokerctl: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(f.home, ".codex", "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "NVT-PLACEHOLDER-NOT-A-KEY") {
		t.Fatalf("prepared inert placeholder missing: %s", data)
	}
}
