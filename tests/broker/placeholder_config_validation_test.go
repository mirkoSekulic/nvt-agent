package broker_test

// Config-load validation for the placeholder-file mode (review findings 2, 6,
// 7): provider/agents config that is ambiguous or unsafe is rejected at load,
// not silently accepted. These run the broker's own Python validators directly.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runBrokerPython(t *testing.T, script string) (string, error) {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "-c", script)
	// Prepend the repo root so `import broker...` resolves, keeping any existing
	// PYTHONPATH (e.g. site-packages for PyYAML).
	cmd.Env = append(os.Environ(), "PYTHONPATH="+root+string(os.PathListSeparator)+os.Getenv("PYTHONPATH"))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestCodexPlaceholderHostsMustSubsetInjectionHosts pins review finding 2: a
// Codex placeholder host that is not also an injection host is rejected, so
// refresh mediation (auth.openai.com) cannot silently drift.
func TestCodexPlaceholderHostsMustSubsetInjectionHosts(t *testing.T) {
	out, err := runBrokerPython(t, `
from broker.plugins.codex_oauth.provider import CodexOAuthProvider
try:
    CodexOAuthProvider({"name": "codex-main", "config": {
        "auth-file": "/tmp/codex-auth.json",
        "injection-hosts": ["chatgpt.com"],
        "placeholder-file": {"path": ".codex/auth.json", "hosts": ["chatgpt.com", "auth.openai.com"]},
    }})
except Exception as exc:
    print("REJECTED:", type(exc).__name__, exc)
    raise SystemExit(0)
raise SystemExit("expected a config error")
`)
	if err != nil {
		t.Fatalf("expected clean rejection, got err=%v out=%s", err, out)
	}
	if !strings.Contains(out, "REJECTED") || !strings.Contains(out, "injection-hosts") {
		t.Fatalf("expected injection-hosts subset rejection, got %s", out)
	}
}

// TestGenericPlaceholderRejectsAmbiguousSecretSpec pins review finding 6: an
// object field that is not a well-formed secret spec (no secret-env) fails
// closed instead of degrading into a literal object.
func TestGenericPlaceholderRejectsAmbiguousSecretSpec(t *testing.T) {
	out, err := runBrokerPython(t, `
from broker.plugins.placeholder.provider import PlaceholderProvider
try:
    PlaceholderProvider({"name": "p", "config": {
        "file": {"path": ".x/auth.json"},
        "fields": {"token": {"secretenv": "TYPO"}},
    }})
except Exception as exc:
    print("REJECTED:", type(exc).__name__, exc)
    raise SystemExit(0)
raise SystemExit("expected a config error")
`)
	if err != nil {
		t.Fatalf("expected clean rejection, got err=%v out=%s", err, out)
	}
	if !strings.Contains(out, "REJECTED") || !strings.Contains(out, "secret-env") {
		t.Fatalf("expected secret-env rejection, got %s", out)
	}
}

// TestAgentsRejectsConflictingMaterialization pins review finding 7: two grants
// for one provider with differing materializations are rejected, so grant()
// selection is never order-dependent.
func TestAgentsRejectsConflictingMaterialization(t *testing.T) {
	out, err := runBrokerPython(t, `
import tempfile
from broker.core.agents import AgentRegistry
config = """agents:
  - id: a
    token-sha256: sha256:""" + ("a" * 64) + """
    grants:
      - provider: codex-main
        materialization: header-inject
      - provider: codex-main
        materialization: placeholder-file
"""
handle = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
handle.write(config)
handle.close()
registry = AgentRegistry(handle.name)
if registry.last_error and "conflicting materializations" in registry.last_error:
    print("REJECTED:", registry.last_error)
    raise SystemExit(0)
raise SystemExit("expected rejection, last_error=%r" % registry.last_error)
`)
	if err != nil {
		t.Fatalf("expected clean rejection, got err=%v out=%s", err, out)
	}
	if !strings.Contains(out, "REJECTED") {
		t.Fatalf("expected conflicting-materialization rejection, got %s", out)
	}
}
