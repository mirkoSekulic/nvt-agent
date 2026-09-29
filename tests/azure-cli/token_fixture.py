#!/usr/bin/env python3
"""Test-only token source. Production provider classification/protocol is unchanged."""
import importlib.util
from pathlib import Path
import time
import json

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("azure_provider", ROOT / "broker/providers/azure/provider.py")
provider = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provider)


class FixtureSource:
    def __init__(self, directory, tenant):
        self.directory = Path(directory)

    def acquire(self, audience):
        if (self.directory / "unavailable").exists():
            raise provider.Failure("azure-credentials-unavailable", 503)
        return "fixture-trusted-" + self.directory.name, int(time.time()) + 3600

    def discover(self):
        if (self.directory / "unavailable").exists():
            raise provider.Failure("azure-discovery-unavailable", 503)
        return json.loads((self.directory / "subscriptions.json").read_text())


provider.AzureCLITokenSource = FixtureSource
# Deterministic immediate refresh for executable-provider conformance only.
provider.DISCOVERY_TTL = 0
if __name__ == "__main__":
    provider.main()
