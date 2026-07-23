package broker_test

import (
	"strings"
	"testing"
)

func TestProviderBoundary(t *testing.T) {
	out, err := runBrokerPython(t, `
import os
import sys

from broker.core.errors import ProviderError

import broker.plugins.placeholder_file

provider_modules = {
    "broker.plugins.claude_oauth.provider",
    "broker.plugins.codex_oauth.provider",
    "broker.plugins.github_app.provider",
    "broker.plugins.placeholder.provider",
    "broker.plugins.static_headers.provider",
    "broker.plugins.static_token.provider",
}
if provider_modules.intersection(sys.modules):
    raise SystemExit("importing a plugin helper eagerly loaded provider modules")

from broker.core.providers import InProcessProviderAdapter, ProviderAdapter, load_providers
from broker.core.server import Broker

if ProviderError.__module__ != "broker.core.errors":
    raise SystemExit("ProviderError is not core-owned")

os.environ["BOUNDARY_TEST_TOKEN"] = "test-value"
providers = load_providers({"providers": [{
    "name": "test-token",
    "plugin": "token",
    "config": {"token-env": "BOUNDARY_TEST_TOKEN"},
    "allow": {"repositories": ["owner/repo"]},
}]})
adapter = providers["test-token"]
if not isinstance(adapter, ProviderAdapter) or not isinstance(adapter, InProcessProviderAdapter):
    raise SystemExit("load_providers did not return an adapter")

class FullProvider:
    name = "full"
    injection_hosts = ["example.test"]
    injection_git = True
    bundle_ttl_seconds = 17

    def files(self, agent_id, audit, request_id):
        return [agent_id, audit, request_id]

    def placeholder_files(self, agent_id, audit, request_id, grant):
        return [agent_id, audit, request_id, grant]

    def injection_headers(self, host, method, path, agent_id, audit, request_id, grant):
        return [host, method, path, agent_id, audit, request_id, grant]

full_provider = FullProvider()
full = InProcessProviderAdapter(full_provider)
if not all(full.supports(capability) for capability in ("files", "placeholder-files", "injection")):
    raise SystemExit("adapter did not centralize supported capabilities")
if full.supports("unknown"):
    raise SystemExit("adapter reported an unknown capability")
if full.injection_hosts != ["example.test"] or not full.injection_git or full.bundle_ttl_seconds != 17:
    raise SystemExit("adapter did not preserve provider metadata")

full_provider.injection_hosts = []
full_provider.injection_git = False
full_provider.bundle_ttl_seconds = 23
del FullProvider.files
del FullProvider.placeholder_files
full_provider.injection_headers = None
if any(full.supports(capability) for capability in ("files", "placeholder-files", "injection")):
    raise SystemExit("adapter did not reflect removed capabilities")
if full.injection_hosts != [] or full.injection_git or full.bundle_ttl_seconds != 23:
    raise SystemExit("adapter did not reflect changed provider metadata")

full_provider.injection_hosts = ["changed.example.test"]
full_provider.injection_headers = lambda *args: args
if not full.supports("injection") or full.injection_hosts != ["changed.example.test"]:
    raise SystemExit("adapter did not reflect restored injection support")

class EmptyProvider:
    name = "empty"

empty = InProcessProviderAdapter(EmptyProvider())
if any(empty.supports(capability) for capability in ("files", "placeholder-files", "injection")):
    raise SystemExit("adapter reported unsupported capabilities")
if empty.injection_hosts != [] or empty.injection_git or empty.bundle_ttl_seconds is not None:
    raise SystemExit("adapter metadata defaults changed")

class Agents:
    materialization = "file-bundle"

    def authenticate(self, authorization):
        return {"id": "agent", "role": "agent"}

    def ensure_provider_grant(self, agent, provider_name):
        return None

    def grant(self, agent, provider_name):
        return {"materialization": self.materialization}

    def effective_repositories(self, agent, provider_name):
        return ["owner/repo"]

broker = Broker.__new__(Broker)
broker.providers = {"empty": empty}
broker.agents = Agents()

def placeholder_files():
    broker.agents.materialization = "placeholder-file"
    return broker.placeholder_files("request", {"provider": "empty"}, "token")

checks = [
    (lambda: broker.identity("request", {"provider": "empty"}, "token"),
     "identity-not-supported", "identity-not-supported", 400),
    (lambda: broker.files("request", {"provider": "empty"}, "token"),
     "files-not-supported", "provider empty does not support file bundles", 400),
    (placeholder_files,
     "placeholder-files-not-supported", "provider empty does not support placeholder files", 403),
    (lambda: broker._injection_provider("empty"),
     "injection-not-supported", "provider empty does not support header injection", 403),
]
for call, reason, message, status in checks:
    try:
        call()
    except ProviderError as error:
        if (error.reason, error.message, error.status) != (reason, message, status):
            raise SystemExit(f"unsupported error changed: {(error.reason, error.message, error.status)!r}")
    else:
        raise SystemExit(f"missing unsupported error: {reason}")

full_provider.identity_for_grant = lambda repositories: {
    "name": "secret-response-canary\n",
    "email": "safe@example.test",
}
broker.providers = {"full": full}
try:
    broker.identity("request", {"provider": "full"}, "token")
except ProviderError as error:
    if (error.reason, error.message, error.status) != (
        "identity-invalid", "provider returned invalid commit identity metadata", 502
    ) or "secret-response-canary" in error.message:
        raise SystemExit(f"malformed identity error was not sanitized: {error.message!r}")
else:
    raise SystemExit("malformed provider identity was accepted")

print("OK")
`)
	if err != nil || !strings.Contains(out, "OK") {
		t.Fatalf("provider boundary test failed: err=%v out=%s", err, out)
	}
}
