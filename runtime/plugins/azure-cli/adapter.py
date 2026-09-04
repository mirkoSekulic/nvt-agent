#!/usr/bin/env python3
"""Untrusted Azure CLI authentication adapter: only inert credentials exist here."""

import importlib.metadata
import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import sys
import tempfile

CLI_VERSION = "2.89.1"
PLACEHOLDER = "NVT-PLACEHOLDER-NOT-A-KEY"
SCOPES = {"https://management.core.windows.net//.default",
          "https://management.azure.com/.default",
          "https://management.azure.com//.default",
          "https://api.loganalytics.io/.default"}


class InertCredential:
    def acquire_token(self, scopes, **kwargs):
        if len(scopes) != 1 or scopes[0] not in SCOPES or kwargs.get("data"):
            raise ValueError("nvt-azure: unsupported token audience or credential operation")
        return {"access_token": PLACEHOLDER, "token_type": "Bearer", "expires_in": 3600}


def write_json(path, value):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(value, stream)
            stream.flush()
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def configure(metadata, directory):
    """Keep only non-secret account metadata, preserving a still-granted selection."""
    if importlib.metadata.version("azure-cli-core") != CLI_VERSION:
        raise ValueError("nvt-azure: unsupported Azure CLI version")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    profile = directory / "azureProfile.json"
    selected = None
    try:
        prior = json.loads(profile.read_text(encoding="utf-8-sig"))
        selected = next((s["id"] for s in prior["subscriptions"] if s.get("isDefault")), None)
    except (OSError, ValueError, KeyError, TypeError):
        pass
    subscriptions = metadata["subscriptions"]
    if not subscriptions or len(subscriptions) > 256:
        raise ValueError("nvt-azure: invalid account metadata")
    ids = [s["id"] for s in subscriptions]
    selected = selected if selected in ids else ids[0]
    accounts = [{"id": s["id"], "name": s.get("name", s["id"]),
                 "tenantId": metadata["tenant"], "state": "Enabled",
                 "environmentName": "AzureCloud", "isDefault": s["id"] == selected,
                 "user": {"name": "systemAssignedIdentity", "type": "servicePrincipal",
                          "assignedIdentityInfo": "MSI"}} for s in subscriptions]
    write_json(profile, {"subscriptions": accounts})
    # Avoid the CLI's automatic version-check network request on first use.
    write_json(directory / "versionCheck.json", {"versions": {
        "azure-cli": {"local": CLI_VERSION}, "core": {"local": CLI_VERSION}},
        "update_time": str(datetime.datetime.now())})
    os.environ["AZURE_CONFIG_DIR"] = str(directory)
    os.environ["AZURE_CORE_COLLECT_TELEMETRY"] = "false"
    os.environ["AZURE_LOGGING_ENABLE_LOG_FILE"] = "false"
    os.environ["AZURE_CORE_CHECK_VERSION"] = "false"
    os.environ["AZURE_EXTENSION_USE_DYNAMIC_INSTALL"] = "no"
    from azure.cli.core._profile import ManagedIdentityAuth
    ManagedIdentityAuth.credential_factory = staticmethod(lambda *_: InertCredential())


def main():
    import yaml
    provider = os.environ.get("NVT_AZURE_PROVIDER") or os.environ.get("NVT_PLUGIN_EGRESS_PROVIDER", "")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}", provider):
        raise ValueError("nvt-azure: select a mediated provider with plugin egress.provider")
    config = yaml.safe_load(Path(os.environ["NVT_PLUGIN_CONFIG"]).read_text())
    metadata = config["providers"][provider]
    proxy_key = "NVT_EGRESS_FORWARD_PROXY_URL_" + re.sub(r"[^a-zA-Z0-9]+", "_", provider).upper()
    proxy = os.environ[proxy_key]
    for key in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"):
        os.environ.pop(key, None)
    os.environ["HTTPS_PROXY"] = os.environ["https_proxy"] = proxy
    directory = Path.home() / ".nvt-azure" / provider
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Serialize local account selection and profile seeding across invocations.
    # This is local CLI state coordination, never an authorization boundary.
    with (directory / "adapter.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        configure(metadata, directory)
        # Login enrollment belongs to the trusted broker, never this adapter.
        if sys.argv[1:2] == ["login"]:
            raise ValueError("nvt-azure: enroll or reauthenticate this identity at the broker")
        from azure.cli.core import get_default_cli
        return get_default_cli().invoke(sys.argv[1:])


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError):
        print("nvt-azure: mediated configuration, CLI version, or authentication unavailable", file=sys.stderr)
        sys.exit(1)
