"""Hermetic operator/Helm -> real broker authorization bridge. No cloud calls."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from broker.core.server import Broker
from broker.core.errors import ProviderError


def verify(grants, provider=None):
    import yaml
    if provider is None:
        provider = yaml.safe_load((ROOT / "examples/http-authorization/broker.yaml").read_text())["providers"][0]
    provider = copy.deepcopy(provider)
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        secret = directory / "token"
        secret.write_text("fake-http-policy-pat")
        secret.chmod(0o600)
        provider["config"].pop("token-env", None)
        provider["config"]["token-file"] = str(secret)
        def identity(name, role, pair, selected):
            result = {"id": name, "role": role, "token-sha256": "sha256:" + hashlib.sha256((name + "-fixture").encode()).hexdigest(), "grants": selected}
            if pair:
                result["paired-agent"] = pair
            return result
        config, agents, audit = directory / "broker.json", directory / "agents.json", directory / "audit.jsonl"
        config.write_text(json.dumps({"providers": [provider]}))
        agents.write_text(json.dumps({"agents": [identity("agent", "agent", "", grants), identity("egress", "egress", "agent", []), identity("other", "agent", "", []), identity("other-egress", "egress", "other", [])]}))
        os.environ.update(NVT_BROKER_CONFIG=str(config), NVT_BROKER_AGENTS_CONFIG=str(agents), NVT_BROKER_AUDIT_LOG=str(audit))
        broker = Broker()
        try:
            for method, path, upgrade, token, permitted in [
                ("POST", "/graphql", False, "egress-fixture", True),
                ("DELETE", "/graphql", False, "egress-fixture", False),
                ("POST", "/designer/api/org/app/deployments/undeploy", False, "egress-fixture", False),
                ("POST", "/graphql?query=x", False, "egress-fixture", False),
                ("POST", "/%67raphql", False, "egress-fixture", False),
                ("POST", "/graphql", True, "egress-fixture", False),
                ("POST", "/graphql", False, "other-egress-fixture", False),
                ("POST", "/graphql", False, "agent-fixture", False),
            ]:
                try:
                    result = broker.injection_headers("fixture", {"capability": "api", "host": "api.example.test", "method": method, "path": path, "upgrade": upgrade}, "Bearer " + token)
                except ProviderError as error:
                    assert not permitted and error.status == 403
                    assert "fake-http-policy-pat" not in str(error)
                else:
                    assert permitted and result["headers"]["authorization"] == "Bearer fake-http-policy-pat"
        finally:
            broker.close()
        assert "fake-http-policy-pat" not in audit.read_text()
    print("Projected HTTP policy: allowed/denied broker decisions and isolation passed")


if __name__ == "__main__":
    verify(json.load(sys.stdin))
