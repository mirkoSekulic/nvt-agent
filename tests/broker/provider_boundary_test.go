package broker_test

import (
	"strings"
	"testing"
)

func TestProviderBoundary(t *testing.T) {
	out, err := runBrokerPython(t, `
import os

from broker.core.errors import ProviderError
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

full = InProcessProviderAdapter(FullProvider())
if not all(full.supports(capability) for capability in ("files", "placeholder-files", "injection")):
    raise SystemExit("adapter did not centralize supported capabilities")
if full.supports("unknown"):
    raise SystemExit("adapter reported an unknown capability")
if full.injection_hosts != ["example.test"] or not full.injection_git or full.bundle_ttl_seconds != 17:
    raise SystemExit("adapter did not preserve provider metadata")

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

broker = Broker.__new__(Broker)
broker.providers = {"empty": empty}
broker.agents = Agents()

def placeholder_files():
    broker.agents.materialization = "placeholder-file"
    return broker.placeholder_files("request", {"provider": "empty"}, "token")

checks = [
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

print("OK")
`)
	if err != nil || !strings.Contains(out, "OK") {
		t.Fatalf("provider boundary test failed: err=%v out=%s", err, out)
	}
}
