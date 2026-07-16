#!/usr/bin/env python3
"""Render only nvt's marker-owned local Compose egress block."""

import argparse
import json
import re
from pathlib import Path

import yaml


BEGIN = "# BEGIN nvt-managed egress (agent-init)"
END = "# END nvt-managed egress (agent-init)"


def scalar(value):
    value = str(value)
    if re.fullmatch(r"[A-Za-z0-9._:/-]+", value):
        return value
    return json.dumps(value)


def managed_block(agents_file, name):
    data = yaml.safe_load(agents_file.read_text(encoding="utf-8")) or {}
    agent = next(
        (item for item in data.get("agents", []) if isinstance(item, dict) and item.get("id") == name),
        None,
    )
    lines = [
        BEGIN,
        "egress:",
        "  mode: mediated",
        "  transport: transparent",
        "  placeholder: NVT-PLACEHOLDER-NOT-A-KEY",
        "  forward-proxy-url: http://127.0.0.1:15002",
        "  grants:",
    ]
    grants = (agent or {}).get("grants", []) or []
    for materialization in ("header-inject", "placeholder-file"):
        for grant in grants:
            if not isinstance(grant, dict) or (grant.get("materialization") or "file-bundle") != materialization:
                continue
            lines.append(f"    - provider: {scalar(grant.get('provider'))}")
            lines.append(f"      materialization: {materialization}")
            hosts = grant.get("egress-hosts") or grant.get("egressHosts") or []
            if hosts:
                lines.append("      egress-hosts:")
                for host in hosts:
                    lines.append(f"      - {scalar(host)}")
            if materialization == "header-inject" and grant.get("git"):
                lines.append("      git: true")
    lines.append(END)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent-config", required=True)
    parser.add_argument("--broker-agents", required=True)
    parser.add_argument("--agent-name", required=True)
    parser.add_argument("--mode", choices=("direct", "mediated"), required=True)
    parser.add_argument("--ensure", action="store_true")
    parser.add_argument("--egressd-config")
    args = parser.parse_args()

    config_file = Path(args.agent_config)
    agents_file = Path(args.broker_agents)
    original = config_file.read_text(encoding="utf-8")
    text = original
    owned = BEGIN in text
    if owned:
        before, _, rest = text.partition(BEGIN)
        if END not in rest:
            raise SystemExit("managed egress block is missing its end marker")
        _, _, after = rest.partition(END)
        text = before.rstrip("\n") + "\n" + after.lstrip("\n")
    elif not args.ensure:
        # agent-up migration never adopts or rewrites user-authored config.
        text = original

    if args.mode == "mediated" and (owned or args.ensure):
        text = text.rstrip("\n") + "\n\n" + managed_block(agents_file, args.agent_name) + "\n"

    if owned or args.ensure:
        parsed = yaml.safe_load(text)
        if not isinstance(parsed, dict):
            raise SystemExit("agent config is not a YAML object after managed egress rendering")
        egress = parsed.get("egress") or {}
        if args.mode == "mediated" and not egress.get("grants"):
            raise SystemExit("mediated agent config rendered no egress grants")
        if args.mode != "mediated" and egress.get("mode") == "mediated":
            raise SystemExit("direct mode but agent config still declares mediated egress")
    if (owned or args.ensure) and text != original:
        config_file.write_text(text, encoding="utf-8")
        print(f"rendered managed egress config into {config_file}")

    if args.mode == "mediated" and args.egressd_config:
        egressd_file = Path(args.egressd_config)
        if egressd_file.exists():
            egressd = json.loads(egressd_file.read_text(encoding="utf-8"))
            forward_proxy = egressd.get("forward_proxy")
            if isinstance(forward_proxy, dict):
                forward_proxy["transparent_mode"] = True
                if forward_proxy.get("allow_ports") in (None, [], [443]):
                    forward_proxy["allow_ports"] = [80, 443]
                data = yaml.safe_load(agents_file.read_text(encoding="utf-8")) or {}
                agent = next(
                    (item for item in data.get("agents", []) if isinstance(item, dict) and item.get("id") == args.agent_name),
                    None,
                )
                git_providers = {
                    grant.get("provider")
                    for grant in (agent or {}).get("grants", []) or []
                    if isinstance(grant, dict) and grant.get("git") and grant.get("provider")
                }
                for route in forward_proxy.get("inject_routes", []) or []:
                    if isinstance(route, dict) and route.get("capability") in git_providers:
                        route["require_capability_hint"] = True
                egressd_file.write_text(json.dumps(egressd, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
