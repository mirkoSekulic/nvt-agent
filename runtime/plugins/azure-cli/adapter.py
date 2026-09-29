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
import ssl
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

CLI_VERSION = "2.89.1"
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
METADATA_LIMIT = 1024 * 1024
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


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("nvt-azure: catalog redirects are forbidden")


def account_metadata(provider, config):
    if "catalog" not in config:
        return config
    if config.get("catalog") is not True or set(config) != {"tenant", "catalog"}:
        raise ValueError("nvt-azure: invalid catalog configuration")
    base = os.environ["NVT_BROKER_URL"].rstrip("/")
    parsed = urlsplit(base)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path:
        raise ValueError("nvt-azure: invalid broker URL")
    context = ssl.create_default_context(cafile=os.environ.get("NVT_BROKER_CA_FILE") or None)
    # The existing agent-role broker capability is not an Azure credential.
    # Do not send it via the Azure proxy or follow a redirect to another host.
    request = Request(base + "/v1/catalog", data=json.dumps({"provider": provider}).encode(),
                      headers={"Content-Type": "application/json", "Authorization": "Bearer " + os.environ["NVT_BROKER_TOKEN"]})
    with build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=context)).open(request, timeout=40) as response:
        raw = response.read(METADATA_LIMIT + 1)
    if len(raw) > METADATA_LIMIT:
        raise ValueError("nvt-azure: catalog too large")
    result = json.loads(raw)
    files = result.get("files")
    if result.get("ok") is not True or result.get("routes") != [] or not isinstance(files, list) or len(files) != 1 or files[0].get("path") != "azure-account-metadata.json":
        raise ValueError("nvt-azure: invalid catalog")
    metadata = json.loads(files[0]["content"])
    validate_metadata(metadata)
    if metadata["tenant"] != config["tenant"]:
        raise ValueError("nvt-azure: catalog tenant mismatch")
    return metadata


def validate_metadata(metadata):
    if not isinstance(metadata, dict) or set(metadata) != {"tenant", "subscriptions"} or not isinstance(metadata["tenant"], str) or not re.fullmatch(UUID, metadata["tenant"]):
        raise ValueError("nvt-azure: invalid account metadata")
    subscriptions = metadata["subscriptions"]
    if not isinstance(subscriptions, list) or len(subscriptions) > 256:
        raise ValueError("nvt-azure: invalid account metadata")
    seen = set()
    for item in subscriptions:
        if (not isinstance(item, dict) or set(item) - {"id", "name"} or not isinstance(item.get("id"), str)
                or not re.fullmatch(UUID, item["id"]) or item["id"] in seen
                or not isinstance(item.get("name", item["id"]), str)
                or not 0 < len(item.get("name", item["id"]).encode()) <= 512
                or any(ord(c) < 32 or ord(c) == 127 for c in item.get("name", item["id"]))):
            raise ValueError("nvt-azure: invalid account metadata")
        seen.add(item["id"])


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
    validate_metadata(metadata)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    profile = directory / "azureProfile.json"
    selected = None
    try:
        prior = json.loads(profile.read_text(encoding="utf-8-sig"))
        selected = next((s["id"] for s in prior["subscriptions"] if s.get("isDefault")), None)
    except (OSError, ValueError, KeyError, TypeError):
        pass
    subscriptions = metadata["subscriptions"]
    ids = [s["id"] for s in subscriptions]
    selected = selected if selected in ids else (ids[0] if ids else None)
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
        configure(account_metadata(provider, metadata), directory)
        # Login enrollment belongs to the trusted broker, never this adapter.
        if sys.argv[1:2] == ["login"]:
            raise ValueError("nvt-azure: enroll or reauthenticate this identity at the broker")
        from azure.cli.core import get_default_cli
        return get_default_cli().invoke(sys.argv[1:])


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, TypeError, AttributeError):
        print("nvt-azure: mediated configuration, CLI version, or authentication unavailable", file=sys.stderr)
        sys.exit(1)
