#!/usr/bin/env python3
"""One-shot Claude OAuth refresh probe.

Loads the broker config, instantiates the named ``claude-oauth`` provider, and
performs a single refresh-token exchange against its configured ``token-url``.
On success the rotated credential is persisted (to ``credentials-file``) and
only redacted metadata is printed — status, credential field names, old/new
access/refresh expiry, and whether the refresh token rotated. Token values are
never printed.

This replaces ad-hoc Python run inside a live agent/broker container. It refuses
a ``credentials-env`` source, because a rotated credential cannot be written
back to an env var and would be silently lost.

Usage:
    NVT_BROKER_CONFIG=/path/to/broker.yaml \
        python3 scripts/claude-refresh-probe.py --provider claude-main

Exit status is 0 on a successful refresh, 1 on any failure. The JSON summary is
printed to stdout in both cases so it can be captured.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broker.core.config import BrokerConfigError, load_config, provider_entries
from broker.plugins.claude_oauth.provider import ClaudeOAuthProvider
from broker.plugins.github_app.provider import ProviderError


def build_provider(config_path, provider_name):
    config = load_config(config_path)
    for entry in provider_entries(config):
        if entry.get("name") == provider_name:
            if entry.get("plugin") != "claude-oauth":
                raise SystemExit(
                    f"provider {provider_name} is plugin {entry.get('plugin')!r}, not claude-oauth"
                )
            return ClaudeOAuthProvider(entry)
    raise SystemExit(f"no provider named {provider_name!r} in broker config")


def main(argv=None):
    parser = argparse.ArgumentParser(description="One-shot Claude OAuth refresh probe (redacted output only).")
    parser.add_argument("--provider", required=True, help="claude-oauth provider name in the broker config")
    parser.add_argument("--config", default=None, help="broker config path (defaults to $NVT_BROKER_CONFIG)")
    args = parser.parse_args(argv)

    try:
        provider = build_provider(args.config, args.provider)
    except BrokerConfigError as error:
        # Config errors are printed as-is; they never contain credential bytes.
        print(json.dumps({"status": "failed", "reason": "config-invalid", "message": str(error)}))
        return 1

    try:
        summary = provider.force_refresh()
    except ProviderError as error:
        # error.message carries only the upstream HTTP status and a safe OAuth
        # error class (see ClaudeOAuthProvider._refresh) — never token bytes.
        print(json.dumps({
            "status": "failed",
            "reason": error.reason,
            "message": error.message,
        }, indent=2))
        return 1

    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
