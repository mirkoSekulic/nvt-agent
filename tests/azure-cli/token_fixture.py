#!/usr/bin/env python3
"""Test-only token source. Production provider classification/protocol is unchanged."""
import importlib.util
from pathlib import Path
import time

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


provider.AzureCLITokenSource = FixtureSource
if __name__ == "__main__":
    provider.main()
