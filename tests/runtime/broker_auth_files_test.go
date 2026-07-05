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
	"time"
)

type fakeFilesBroker struct {
	server *httptest.Server
	status int
	body   map[string]any
}

func newFakeFilesBroker(t *testing.T, status int, body map[string]any) *fakeFilesBroker {
	t.Helper()
	fake := &fakeFilesBroker{status: status, body: body}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "status": "ready"})
	})
	mux.HandleFunc("/v1/files", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer broker-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if payload["provider"] != "bundle-provider" {
			http.Error(w, "provider", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(fake.status)
		_ = json.NewEncoder(w).Encode(fake.body)
	})
	fake.server = httptest.NewServer(mux)
	t.Cleanup(fake.server.Close)
	return fake
}

type sequenceFilesBroker struct {
	server   *httptest.Server
	mu       sync.Mutex
	index    int
	statuses []int
	bodies   []map[string]any
}

func newSequenceFilesBroker(t *testing.T, statuses []int, bodies []map[string]any) *sequenceFilesBroker {
	t.Helper()
	broker := &sequenceFilesBroker{statuses: statuses, bodies: bodies}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "status": "ready"})
	})
	mux.HandleFunc("/v1/files", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer broker-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		broker.mu.Lock()
		index := broker.index
		if index >= len(broker.bodies) {
			index = len(broker.bodies) - 1
		}
		broker.index++
		status := broker.statuses[index]
		body := broker.bodies[index]
		broker.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	})
	broker.server = httptest.NewServer(mux)
	t.Cleanup(broker.server.Close)
	return broker
}

func (b *sequenceFilesBroker) requestCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.index
}

func loopExpiry(seconds int) string {
	return time.Now().Add(time.Duration(seconds) * time.Second).UTC().Format(time.RFC3339)
}

func TestBrokerAuthFilesWritesBundleWithModes(t *testing.T) {
	f := newFixture(t)
	f.installBrokerctl()
	target := filepath.Join(f.home, "bundle")
	broker := newFakeFilesBroker(t, http.StatusOK, map[string]any{
		"ok": true,
		"files": []map[string]any{
			{"name": "auth.json", "content": "{\"ok\":true}\n", "mode": "0600"},
			{"name": "config.toml", "content": "mode = \"test\"\n", "mode": "0640"},
		},
		"expires_at": "2026-07-03T00:00:00Z",
	})
	config := f.writePluginConfig("broker-auth-files.yaml", fmt.Sprintf(`
bundles:
  - provider: bundle-provider
    target: %s
    dir-mode: "0700"
    file-mode: "0600"
`, quoteYAML(target)))
	f.runWithEnv(brokerAuthFilesRunBin(f.root), true, []string{
		"NVT_PLUGIN_CONFIG=" + config,
		"NVT_BROKER_URL=" + broker.server.URL,
		"NVT_BROKER_TOKEN=broker-token",
	})
	assertFileContent(t, filepath.Join(target, "auth.json"), "{\"ok\":true}\n")
	assertFileMode(t, target, 0o700)
	assertFileMode(t, filepath.Join(target, "auth.json"), 0o600)
	assertFileMode(t, filepath.Join(target, "config.toml"), 0o640)
}

func TestBrokerAuthFilesRejectsMaliciousNames(t *testing.T) {
	for _, name := range []string{"../x", "a/b"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.installBrokerctl()
			target := filepath.Join(f.home, "bundle")
			broker := newFakeFilesBroker(t, http.StatusOK, map[string]any{
				"ok": true,
				"files": []map[string]any{
					{"name": name, "content": "bad\n", "mode": "0600"},
				},
			})
			config := f.writePluginConfig("broker-auth-files.yaml", fmt.Sprintf(`
bundles:
  - provider: bundle-provider
    target: %s
`, quoteYAML(target)))
			output := f.runWithEnv(brokerAuthFilesRunBin(f.root), false, []string{
				"NVT_PLUGIN_CONFIG=" + config,
				"NVT_BROKER_URL=" + broker.server.URL,
				"NVT_BROKER_TOKEN=broker-token",
			})
			if !strings.Contains(output, "plain relative filenames") {
				t.Fatalf("expected malicious name rejection, got:\n%s", output)
			}
		})
	}
}

func TestBrokerAuthFilesValidatesAllFilesBeforeWriting(t *testing.T) {
	f := newFixture(t)
	f.installBrokerctl()
	target := filepath.Join(f.home, "bundle")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(target, "auth.json")
	if err := os.WriteFile(existing, []byte("existing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	broker := newFakeFilesBroker(t, http.StatusOK, map[string]any{
		"ok": true,
		"files": []map[string]any{
			{"name": "auth.json", "content": "new\n", "mode": "0600"},
			{"name": "../x", "content": "bad\n", "mode": "0600"},
		},
	})
	config := f.writePluginConfig("broker-auth-files.yaml", fmt.Sprintf(`
bundles:
  - provider: bundle-provider
    target: %s
`, quoteYAML(target)))
	output := f.runWithEnv(brokerAuthFilesRunBin(f.root), false, []string{
		"NVT_PLUGIN_CONFIG=" + config,
		"NVT_BROKER_URL=" + broker.server.URL,
		"NVT_BROKER_TOKEN=broker-token",
	})
	if !strings.Contains(output, "plain relative filenames") {
		t.Fatalf("expected malicious name rejection, got:\n%s", output)
	}
	assertFileContent(t, existing, "existing\n")
}

func TestBrokerAuthFilesBrokerErrorDoesNotPartiallyOverwrite(t *testing.T) {
	f := newFixture(t)
	f.installBrokerctl()
	target := filepath.Join(f.home, "bundle")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(target, "auth.json")
	if err := os.WriteFile(existing, []byte("existing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	broker := newFakeFilesBroker(t, http.StatusBadGateway, map[string]any{"ok": false, "error": "provider-failed"})
	config := f.writePluginConfig("broker-auth-files.yaml", fmt.Sprintf(`
bundles:
  - provider: bundle-provider
    target: %s
`, quoteYAML(target)))
	f.runWithEnv(brokerAuthFilesRunBin(f.root), false, []string{
		"NVT_PLUGIN_CONFIG=" + config,
		"NVT_BROKER_URL=" + broker.server.URL,
		"NVT_BROKER_TOKEN=broker-token",
	})
	assertFileContent(t, existing, "existing\n")
}

func TestBrokerAuthFilesDoctorChecksBrokerAndFiles(t *testing.T) {
	f := newFixture(t)
	f.installBrokerctl()
	target := filepath.Join(f.home, "bundle")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "auth.json"), []byte("ok\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	broker := newFakeFilesBroker(t, http.StatusOK, map[string]any{"ok": true, "files": []map[string]any{}})
	config := f.writePluginConfig("broker-auth-files.yaml", fmt.Sprintf(`
bundles:
  - provider: bundle-provider
    target: %s
`, quoteYAML(target)))
	f.runWithEnv(brokerAuthFilesRunBin(f.root), true, []string{
		"NVT_PLUGIN_CONFIG=" + config,
		"NVT_BROKER_URL=" + broker.server.URL,
		"NVT_BROKER_TOKEN=broker-token",
	}, "doctor")
}

func TestBrokerAuthFilesLoopRewritesNearExpiry(t *testing.T) {
	f := newFixture(t)
	f.installBrokerctl()
	target := filepath.Join(f.home, "bundle")
	broker := newSequenceFilesBroker(t,
		[]int{http.StatusOK, http.StatusOK},
		[]map[string]any{
			{
				"ok":         true,
				"files":      []map[string]any{{"name": "auth.json", "content": "cycle-1\n", "mode": "0600"}},
				"expires_at": loopExpiry(1),
			},
			{
				"ok":         true,
				"files":      []map[string]any{{"name": "auth.json", "content": "cycle-2\n", "mode": "0600"}},
				"expires_at": loopExpiry(30),
			},
		},
	)
	config := f.writePluginConfig("broker-auth-files.yaml", fmt.Sprintf(`
bundles:
  - provider: bundle-provider
    target: %s
refresh-slack-seconds: 10
min-sleep-seconds: 0
fallback-sleep-seconds: 1
max-loops: 2
`, quoteYAML(target)))
	f.runWithEnv(brokerAuthFilesRunBin(f.root), true, []string{
		"NVT_PLUGIN_CONFIG=" + config,
		"NVT_BROKER_URL=" + broker.server.URL,
		"NVT_BROKER_TOKEN=broker-token",
	}, "loop")
	assertFileContent(t, filepath.Join(target, "auth.json"), "cycle-2\n")
	if got := broker.requestCount(); got != 2 {
		t.Fatalf("expected two broker requests, got %d", got)
	}
}

func TestBrokerAuthFilesLoopFailedCyclePreservesFiles(t *testing.T) {
	f := newFixture(t)
	f.installBrokerctl()
	target := filepath.Join(f.home, "bundle")
	broker := newSequenceFilesBroker(t,
		[]int{http.StatusOK, http.StatusInternalServerError},
		[]map[string]any{
			{
				"ok":         true,
				"files":      []map[string]any{{"name": "auth.json", "content": "cycle-1\n", "mode": "0600"}},
				"expires_at": loopExpiry(1),
			},
			{"ok": false, "error": "provider-failed"},
		},
	)
	config := f.writePluginConfig("broker-auth-files.yaml", fmt.Sprintf(`
bundles:
  - provider: bundle-provider
    target: %s
refresh-slack-seconds: 10
min-sleep-seconds: 0
fallback-sleep-seconds: 0
max-loops: 2
`, quoteYAML(target)))
	output := f.runWithEnv(brokerAuthFilesRunBin(f.root), true, []string{
		"NVT_PLUGIN_CONFIG=" + config,
		"NVT_BROKER_URL=" + broker.server.URL,
		"NVT_BROKER_TOKEN=broker-token",
	}, "loop")
	assertFileContent(t, filepath.Join(target, "auth.json"), "cycle-1\n")
	if got := broker.requestCount(); got != 2 {
		t.Fatalf("expected two broker requests, got %d", got)
	}
	if !strings.Contains(output, "broker-auth-files: warning: re-materialization failed: broker-auth-files: broker files request failed:") ||
		!strings.Contains(output, `"error":"provider-failed"`) {
		t.Fatalf("expected explicit refresh failure warning, got:\n%s", output)
	}
}

func TestBrokerAuthFilesLoopPublishesEventsAndToleratesMissingAgentdctl(t *testing.T) {
	f := newFixture(t)
	f.installBrokerctl()
	target := filepath.Join(f.home, "bundle")
	capturePath := filepath.Join(f.home, "agentdctl.log")
	f.writeBin("agentdctl", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf 'ARGS:%s\n' "$*" >> %s
`, "%s", shellQuote(capturePath)))
	broker := newSequenceFilesBroker(t,
		[]int{http.StatusOK, http.StatusOK},
		[]map[string]any{
			{
				"ok":         true,
				"files":      []map[string]any{{"name": "auth.json", "content": "cycle-1\n", "mode": "0600"}},
				"expires_at": loopExpiry(1),
			},
			{
				"ok":         true,
				"files":      []map[string]any{{"name": "auth.json", "content": "cycle-2\n", "mode": "0600"}},
				"expires_at": loopExpiry(30),
			},
		},
	)
	config := f.writePluginConfig("broker-auth-files.yaml", fmt.Sprintf(`
bundles:
  - provider: bundle-provider
    target: %s
refresh-slack-seconds: 10
min-sleep-seconds: 0
fallback-sleep-seconds: 1
max-loops: 2
`, quoteYAML(target)))
	f.runWithEnv(brokerAuthFilesRunBin(f.root), true, []string{
		"NVT_PLUGIN_CONFIG=" + config,
		"NVT_BROKER_URL=" + broker.server.URL,
		"NVT_BROKER_TOKEN=broker-token",
		"NVT_PLUGIN_NAME=broker-auth-files-refresher",
	}, "loop")
	capture := string(mustReadFile(t, capturePath))
	if got := strings.Count(capture, "plugin.broker-auth-files.rematerialized"); got != 2 {
		t.Fatalf("expected two rematerialized events, got %d:\n%s", got, capture)
	}
	if !strings.Contains(capture, "--source plugin:broker-auth-files-refresher") ||
		!strings.Contains(capture, `"providers":["bundle-provider"]`) {
		t.Fatalf("unexpected event publish args:\n%s", capture)
	}

	f2 := newFixture(t)
	f2.installBrokerctl()
	target2 := filepath.Join(f2.home, "bundle")
	broker2 := newSequenceFilesBroker(t,
		[]int{http.StatusOK},
		[]map[string]any{{
			"ok":         true,
			"files":      []map[string]any{{"name": "auth.json", "content": "ok\n", "mode": "0600"}},
			"expires_at": loopExpiry(30),
		}},
	)
	config2 := f2.writePluginConfig("broker-auth-files.yaml", fmt.Sprintf(`
bundles:
  - provider: bundle-provider
    target: %s
min-sleep-seconds: 0
fallback-sleep-seconds: 1
max-loops: 1
`, quoteYAML(target2)))
	f2.runWithEnv(brokerAuthFilesRunBin(f2.root), true, []string{
		"NVT_PLUGIN_CONFIG=" + config2,
		"NVT_BROKER_URL=" + broker2.server.URL,
		"NVT_BROKER_TOKEN=broker-token",
		"PATH=" + f2.bin + ":/usr/bin:/bin",
	}, "loop")
	assertFileContent(t, filepath.Join(target2, "auth.json"), "ok\n")
}

func brokerAuthFilesRunBin(root string) string {
	return "python3 " + shellQuote(filepath.Join(root, "runtime", "plugins", "broker-auth-files", "run.py"))
}

func (f *fixture) installBrokerctl() {
	f.writeBin("brokerctl", fmt.Sprintf(`#!/usr/bin/env bash
exec python3 %s "$@"
`, shellQuote(filepath.Join(f.root, "runtime", "core", "brokerctl.py"))))
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != want {
		t.Fatalf("unexpected %s content: %q", path, data)
	}
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("unexpected mode for %s: got %o want %o", path, got, want)
	}
}
