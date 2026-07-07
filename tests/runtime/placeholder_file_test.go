package runtime_test

// Runtime materialization of the placeholder-file mode
// (docs/phase6.1-placeholder-file-materialization-pr-plan.md work item 3):
// bootstrap writes the broker's placeholder auth file verbatim (placeholders
// only) and never reads a host auth file as the source of truth.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newFakePlaceholderBroker(t *testing.T, body map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "status": "ready"})
	})
	mux.HandleFunc("/v1/placeholder-files", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer broker-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if payload["provider"] != "codex-main" {
			http.Error(w, "provider", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

// TestBootstrapMaterializesPlaceholderFile pins that bootstrap writes the
// broker's placeholder auth file (path/mode/content) and that a stray host
// auth file carrying a real token is overwritten — never read as the source.
func TestBootstrapMaterializesPlaceholderFile(t *testing.T) {
	f := newFixture(t)
	f.installBrokerctl()

	realSecret := "real-provider-access-token-secret-xyz"
	placeholderContent := "{\n" +
		"  \"tokens\": {\n" +
		"    \"access_token\": \"NVT-PLACEHOLDER-NOT-A-KEY\",\n" +
		"    \"refresh_token\": \"NVT-PLACEHOLDER-NOT-A-KEY\",\n" +
		"    \"id_token\": \"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhY2N0LTEyMyJ9.nvt-placeholder-signature\"\n" +
		"  }\n" +
		"}\n"
	broker := newFakePlaceholderBroker(t, map[string]any{
		"ok": true,
		"files": []any{map[string]any{
			"path":    ".codex/auth.json",
			"mode":    "0600",
			"content": placeholderContent,
		}},
		"hosts":      []any{"chatgpt.com", "auth.openai.com"},
		"expires_at": nil,
	})

	// A stray host auth file with a real token: bootstrap must overwrite it.
	mustWriteFile(t, filepath.Join(f.home, ".codex", "auth.json"),
		`{"tokens":{"access_token":"`+realSecret+`"}}`)

	config := f.writeAgentConfig(`
egress:
  mode: mediated
  grants:
    - provider: codex-main
      materialization: placeholder-file
runtime:
  command: codex
tools:
  packages: []
  mise: []
  additional-paths: []
  shell: []
code-server:
  extensions: []
`)

	output := f.runWithEnv(bootstrapBin(f.root), true, []string{
		"HOME=" + f.home,
		"PATH=" + f.pathPrefix + string(os.PathListSeparator) + os.Getenv("PATH"),
		"NVT_BROKER_URL=" + broker.URL,
		"NVT_BROKER_TOKEN=broker-token",
	}, config)

	authPath := filepath.Join(f.home, ".codex", "auth.json")
	content := mustReadFile(t, authPath)
	if !strings.Contains(content, mediatedPlaceholder) {
		t.Fatalf("placeholder auth file missing the placeholder:\n%s", content)
	}
	if strings.Contains(content, realSecret) {
		t.Fatalf("stray host real token survived materialization:\n%s", content)
	}
	assertFileMode(t, authPath, 0o600)

	// The real token appears nowhere in the tree or bootstrap output.
	scanTreeForSecretMaterial(t, f.home, []string{realSecret})
	scanTextForSecretMaterial(t, "bootstrap output", output, []string{realSecret})
}

// TestBootstrapPlaceholderFileRefusesSymlinkEscape pins review finding 8: even
// with a traversal-free relative path, a symlinked parent that resolves outside
// HOME is refused rather than written through.
func TestBootstrapPlaceholderFileRefusesSymlinkEscape(t *testing.T) {
	f := newFixture(t)
	f.installBrokerctl()

	// .codex is a symlink to a directory outside HOME.
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(f.home, ".codex")); err != nil {
		t.Fatal(err)
	}

	broker := newFakePlaceholderBroker(t, map[string]any{
		"ok": true,
		"files": []any{map[string]any{
			"path":    ".codex/auth.json",
			"mode":    "0600",
			"content": "{\"tokens\":{}}\n",
		}},
		"hosts":      []any{"chatgpt.com"},
		"expires_at": nil,
	})

	config := f.writeAgentConfig(`
egress:
  mode: mediated
  grants:
    - provider: codex-main
      materialization: placeholder-file
runtime:
  command: codex
tools:
  packages: []
  mise: []
  additional-paths: []
  shell: []
code-server:
  extensions: []
`)

	output := f.runWithEnv(bootstrapBin(f.root), false, []string{
		"HOME=" + f.home,
		"PATH=" + f.pathPrefix + string(os.PathListSeparator) + os.Getenv("PATH"),
		"NVT_BROKER_URL=" + broker.URL,
		"NVT_BROKER_TOKEN=broker-token",
	}, config)

	if !strings.Contains(output, "resolves outside HOME") {
		t.Fatalf("expected symlink-escape refusal, got:\n%s", output)
	}
	if _, err := os.Stat(filepath.Join(outside, "auth.json")); err == nil {
		t.Fatalf("bootstrap wrote through the escaping symlink")
	}
}
