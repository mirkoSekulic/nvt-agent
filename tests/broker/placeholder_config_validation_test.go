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

// TestClaudeCredentialsSourceMutualExclusion pins that the Claude provider
// requires exactly one broker-side credential source: setting both a host path
// and an env source (or neither) is a config error, so the source of truth is
// never ambiguous.
func TestClaudeCredentialsSourceMutualExclusion(t *testing.T) {
	for _, tc := range []struct{ name, config string }{
		{"both", `{"credentials-file": "/tmp/c.json", "credentials-env": "CLAUDE_CREDS", "injection-hosts": ["api.anthropic.com"]}`},
		{"neither", `{"injection-hosts": ["api.anthropic.com"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runBrokerPython(t, `
from broker.plugins.claude_oauth.provider import ClaudeOAuthProvider
try:
    ClaudeOAuthProvider({"name": "claude-main", "config": `+tc.config+`})
except Exception as exc:
    print("REJECTED:", type(exc).__name__, exc)
    raise SystemExit(0)
raise SystemExit("expected a config error")
`)
			if err != nil {
				t.Fatalf("expected clean rejection, got err=%v out=%s", err, out)
			}
			if !strings.Contains(out, "REJECTED") || !strings.Contains(out, "exactly one") {
				t.Fatalf("expected exactly-one-source rejection, got %s", out)
			}
		})
	}
}

// TestClaudePlaceholderHostsMustSubsetInjectionHosts pins that a Claude
// placeholder host that is not also an injection host is rejected, so the
// materialized host bindings can never drift from what the edge can inject for.
func TestClaudePlaceholderHostsMustSubsetInjectionHosts(t *testing.T) {
	out, err := runBrokerPython(t, `
from broker.plugins.claude_oauth.provider import ClaudeOAuthProvider
try:
    ClaudeOAuthProvider({"name": "claude-main", "config": {
        "credentials-file": "/tmp/claude-credentials.json",
        "injection-hosts": ["api.anthropic.com"],
        "placeholder-file": {"path": ".claude/.credentials.json", "hosts": ["api.anthropic.com", "console.anthropic.com"]},
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

// TestClaudeInjectionExtraHeadersRejectsAuthorizationOverride pins that a
// configured extra header cannot override the injected authorization header,
// so the real Bearer token can never be silently shadowed by config.
func TestClaudeInjectionExtraHeadersRejectsAuthorizationOverride(t *testing.T) {
	out, err := runBrokerPython(t, `
from broker.plugins.claude_oauth.provider import ClaudeOAuthProvider
try:
    ClaudeOAuthProvider({"name": "claude-main", "config": {
        "credentials-file": "/tmp/claude-credentials.json",
        "injection-hosts": ["api.anthropic.com"],
        "injection-extra-headers": {"Authorization": "Bearer nope"},
    }})
except Exception as exc:
    print("REJECTED:", type(exc).__name__, exc)
    raise SystemExit(0)
raise SystemExit("expected a config error")
`)
	if err != nil {
		t.Fatalf("expected clean rejection, got err=%v out=%s", err, out)
	}
	if !strings.Contains(out, "REJECTED") || !strings.Contains(out, "authorization") {
		t.Fatalf("expected authorization-override rejection, got %s", out)
	}
}

// TestClaudePlaceholderGuardRejectsNestedNonScalar pins that copied non-secret
// subscription metadata must be a scalar or a flat list of scalars: a nested
// list/dict is refused rather than copied into the placeholder file without the
// token-shape guard running on its leaves. Defense in depth against a future
// credential-shape change.
func TestClaudePlaceholderGuardRejectsNestedNonScalar(t *testing.T) {
	out, err := runBrokerPython(t, `
import json, tempfile
from broker.plugins.claude_oauth.provider import ClaudeOAuthProvider
creds = {"claudeAiOauth": {
    "accessToken": "real-access",
    "refreshToken": "real-refresh",
    "expiresAt": 4102444800000,
    "scopes": [["nested", "array"]],
}}
handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
json.dump(creds, handle); handle.close()
provider = ClaudeOAuthProvider({"name": "claude-main", "config": {
    "credentials-file": handle.name,
    "injection-hosts": ["api.anthropic.com"],
    "placeholder-file": {"path": ".claude/.credentials.json", "hosts": ["api.anthropic.com"]},
}})
try:
    provider.placeholder_files("agent", None, "rid")
except Exception as exc:
    print("REJECTED:", getattr(exc, "reason", type(exc).__name__), exc)
    raise SystemExit(0)
raise SystemExit("expected a placeholder-claim-unsafe error")
`)
	if err != nil {
		t.Fatalf("expected clean rejection, got err=%v out=%s", err, out)
	}
	if !strings.Contains(out, "REJECTED") || !strings.Contains(out, "placeholder-claim-unsafe") {
		t.Fatalf("expected placeholder-claim-unsafe rejection for nested non-scalar, got %s", out)
	}
}

// TestClaudeDefaultsMatchObservedClaudeCodeOAuth pins the provider defaults for
// the observed Claude Code OAuth app. They are overrideable because Anthropic
// does not document them as stable, but local/dev config can refresh without
// forcing every operator to duplicate the current public client id.
func TestClaudeDefaultsMatchObservedClaudeCodeOAuth(t *testing.T) {
	out, err := runBrokerPython(t, `
import json, tempfile, time
from broker.plugins.claude_oauth.provider import ClaudeOAuthProvider
creds = {"claudeAiOauth": {
    "accessToken": "real-access",
    "refreshToken": "real-refresh",
    "expiresAt": int((time.time() + 60) * 1000),
}}
handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
json.dump(creds, handle); handle.close()
provider = ClaudeOAuthProvider({"name": "claude-main", "config": {
    "credentials-file": handle.name,
}})
print("CLIENT_ID", provider.client_id)
print("TOKEN_URL", provider.token_url)
print("REFRESH_SCOPE", provider.refresh_scope)
print("USER_AGENT", provider.user_agent)
`)
	if err != nil {
		t.Fatalf("expected clean defaults, got err=%v out=%s", err, out)
	}
	if !strings.Contains(out, "CLIENT_ID 9d1c250a-e61b-44d9-88ed-5944d1962f5e") ||
		!strings.Contains(out, "TOKEN_URL https://platform.claude.com/v1/oauth/token") ||
		!strings.Contains(out, "REFRESH_SCOPE user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload") ||
		!strings.Contains(out, "USER_AGENT axios/1.15.2") {
		t.Fatalf("expected observed Claude Code OAuth defaults, got %s", out)
	}
}

// TestClaudeProviderValueResolvesLiteralOrEnv pins that client-id, refresh-scope,
// and user-agent accept a literal or an env indirection (client-id-env, …),
// that the two forms are mutually exclusive, and that the public default is
// preserved when neither is set. This keeps documented client-id-env
// configuration working instead of being silently ignored.
func TestClaudeProviderValueResolvesLiteralOrEnv(t *testing.T) {
	out, err := runBrokerPython(t, `
import json, os, tempfile
from broker.plugins.claude_oauth.provider import ClaudeOAuthProvider
creds = {"claudeAiOauth": {"accessToken": "a", "refreshToken": "r", "expiresAt": 4102444800000}}
handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
json.dump(creds, handle); handle.close()

# Default preserved when neither client-id nor client-id-env is set.
default = ClaudeOAuthProvider({"name": "c", "config": {"credentials-file": handle.name}})
assert default.client_id == "9d1c250a-e61b-44d9-88ed-5944d1962f5e", default.client_id

# client-id-env resolves from the environment.
os.environ["CLAUDE_CID"] = "operator-client-id"
os.environ["CLAUDE_SCOPE"] = "operator-scope"
resolved = ClaudeOAuthProvider({"name": "c", "config": {
    "credentials-file": handle.name,
    "client-id-env": "CLAUDE_CID",
    "refresh-scope-env": "CLAUDE_SCOPE",
}})
assert resolved.client_id == "operator-client-id", resolved.client_id
assert resolved.refresh_scope == "operator-scope", resolved.refresh_scope

literal = ClaudeOAuthProvider({"name": "c", "config": {
    "credentials-file": handle.name,
    "refresh-scope": "literal-scope",
}})
assert literal.refresh_scope == "literal-scope", literal.refresh_scope

# Literal and env forms are mutually exclusive.
try:
    ClaudeOAuthProvider({"name": "c", "config": {
        "credentials-file": handle.name,
        "client-id": "x",
        "client-id-env": "CLAUDE_CID",
    }})
except Exception as exc:
    print("REJECTED:", exc)
else:
    raise SystemExit("expected mutual-exclusion rejection")

try:
    ClaudeOAuthProvider({"name": "c", "config": {
        "credentials-file": handle.name,
        "refresh-scope": "literal",
        "refresh-scope-env": "CLAUDE_SCOPE",
    }})
except Exception as exc:
    print("SCOPE-REJECTED:", exc)
else:
    raise SystemExit("expected refresh-scope mutual-exclusion rejection")

# Empty env value is rejected rather than silently defaulting.
os.environ["CLAUDE_EMPTY"] = ""
try:
    ClaudeOAuthProvider({"name": "c", "config": {
        "credentials-file": handle.name,
        "refresh-scope-env": "CLAUDE_EMPTY",
    }})
except Exception as exc:
    print("EMPTY-REJECTED:", exc)
else:
    raise SystemExit("expected empty-env rejection")
print("OK")
`)
	if err != nil {
		t.Fatalf("expected clean resolver behavior, got err=%v out=%s", err, out)
	}
	if !strings.Contains(out, "REJECTED") || !strings.Contains(out, "cannot set both client-id and client-id-env") {
		t.Fatalf("expected client-id/client-id-env mutual-exclusion rejection, got %s", out)
	}
	if !strings.Contains(out, "EMPTY-REJECTED") || !strings.Contains(out, "OK") {
		t.Fatalf("expected empty-env rejection and OK, got %s", out)
	}
	if !strings.Contains(out, "SCOPE-REJECTED") || !strings.Contains(out, "cannot set both refresh-scope and refresh-scope-env") {
		t.Fatalf("expected refresh-scope mutual-exclusion rejection, got %s", out)
	}
}

// TestClaudeCredentialsEnvNeverNetworkRefreshes pins finding 1: a credentials-env
// source is never network-refreshed (its rotation could not be persisted back to
// an env var and would be lost on restart). Near expiry it serves the current
// token without any upstream call; expired it fails closed on the mediated
// injection path and vends the expired credential on the direct /v1/files path —
// all without ever invoking the refresh exchange. credentials-file remains the
// refreshable source.
func TestClaudeCredentialsEnvNeverNetworkRefreshes(t *testing.T) {
	out, err := runBrokerPython(t, `
import json, os, time, tempfile
from broker.plugins.claude_oauth.provider import ClaudeOAuthProvider

def cred(delta_seconds):
    return json.dumps({"claudeAiOauth": {
        "accessToken": "env-access", "refreshToken": "env-refresh",
        "expiresAt": int((time.time() + delta_seconds) * 1000)}})

# credentials-env cannot refresh; wire _refresh to explode if it is ever called.
os.environ["CLAUDE_ENV_CRED"] = cred(60)  # near expiry (< 900s margin) but valid
env = ClaudeOAuthProvider({"name": "c", "config": {
    "credentials-env": "CLAUDE_ENV_CRED",
    "injection-hosts": ["api.anthropic.com"]}})
assert env._can_refresh() is False
def boom(*a, **k):
    raise AssertionError("credentials-env must never trigger a network refresh")
env._refresh = boom

# Near-expiry valid: mediated injection serves the current token, no refresh.
headers, _exp, _strip = env.injection_headers("api.anthropic.com", "POST", "/v1/messages", "agent", None, "rid")
assert headers["authorization"] == "Bearer env-access", headers

# Expired: mediated injection fails closed (no refresh), direct files vends it.
os.environ["CLAUDE_ENV_CRED"] = cred(-60)
try:
    env.injection_headers("api.anthropic.com", "POST", "/v1/messages", "agent", None, "rid")
except Exception as exc:
    print("ENV-FAILCLOSED:", getattr(exc, "reason", type(exc).__name__))
else:
    raise SystemExit("expected expired credentials-env injection to fail closed")
files, _fexp, meta = env.files("agent", None, "rid")
vended = json.loads(files[0]["content"])
assert vended["claudeAiOauth"]["accessToken"] == "env-access", vended
assert meta["refreshed"] is False, meta

# credentials-file remains refreshable.
handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
handle.write(cred(60)); handle.close()
filed = ClaudeOAuthProvider({"name": "c", "config": {
    "credentials-file": handle.name,
    "injection-hosts": ["api.anthropic.com"]}})
assert filed._can_refresh() is True
print("OK")
`)
	if err != nil {
		t.Fatalf("expected credentials-env to never network-refresh, got err=%v out=%s", err, out)
	}
	if !strings.Contains(out, "ENV-FAILCLOSED: credentials-expired") || !strings.Contains(out, "OK") {
		t.Fatalf("expected env fail-closed and file-refreshable, got %s", out)
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
