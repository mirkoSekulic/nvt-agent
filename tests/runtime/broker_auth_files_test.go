package runtime_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
