#!/usr/bin/env python3
import argparse
import json
import os
import re
from pathlib import Path


NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")


def fail(message):
    raise SystemExit(f"render-agent-expose: {message}")


def scalar(value):
    value = value.strip()
    if value in ("", "[]", "{}"):
        return value
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def split_key_value(stripped):
    if ":" not in stripped:
        return None, None
    key, value = stripped.split(":", 1)
    return key.strip(), scalar(value)


def without_comment(line):
    in_single = False
    in_double = False
    for index, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            return line[:index]
    return line


def load_expose_http(path):
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        fail(f"missing agent config: {path}")

    expose_indent = None
    http_indent = None
    routes = []
    current = None

    for raw in lines:
        line = without_comment(raw).rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()

        if expose_indent is None:
            key, value = split_key_value(stripped)
            if indent == 0 and key == "expose":
                if value not in ("", "{}"):
                    fail("expose must be a YAML object")
                expose_indent = indent
            continue

        if indent <= expose_indent:
            break

        if http_indent is None:
            key, value = split_key_value(stripped)
            if key == "http":
                if value in ("[]", ""):
                    http_indent = indent
                    if value == "[]":
                        break
                else:
                    fail("expose.http must be a list")
            continue

        if indent <= http_indent:
            break

        if stripped.startswith("-"):
            if current is not None:
                routes.append(current)
            current = {}
            rest = stripped[1:].strip()
            if rest:
                key, value = split_key_value(rest)
                if key is None:
                    fail(f"expose.http[{len(routes)}] must be a YAML object")
                current[key] = value
            continue

        if current is None:
            fail("expose.http entries must be YAML objects")
        key, value = split_key_value(stripped)
        if key is None:
            fail(f"expose.http[{len(routes)}] must be a YAML object")
        current[key] = value

    if current is not None:
        routes.append(current)
    return normalize_routes(routes)


def normalize_routes(routes):
    seen = set()
    normalized = []
    for index, route in enumerate(routes):
        prefix = f"expose.http[{index}]"
        name = route.get("name")
        if not isinstance(name, str) or len(name) > 63 or not NAME_RE.fullmatch(name):
            fail(f"{prefix}.name must be a DNS label")
        if name in seen:
            fail(f"duplicate expose.http name: {name}")
        seen.add(name)

        source = route.get("source", "agent")
        if source != "agent":
            fail(f"{prefix}.source {source!r} is not supported yet")

        try:
            port = int(route.get("targetPort", ""))
        except ValueError:
            fail(f"{prefix}.targetPort must be an integer from 1 to 65535")
        if port < 1 or port > 65535:
            fail(f"{prefix}.targetPort must be an integer from 1 to 65535")

        normalized.append({"name": name, "targetPort": port, "source": source})
    return normalized


def router_id(agent_name, route_name):
    return f"{agent_name}-{route_name}"


def compose_override(agent_name, agent_host, routes):
    labels = {}
    host_suffix = f".{agent_host}"
    for route in routes:
        rid = router_id(agent_name, route["name"])
        host = f"{route['name']}{host_suffix}"
        labels[f"traefik.http.routers.{rid}.rule"] = f"Host(`{host}`)"
        labels[f"traefik.http.routers.{rid}.entrypoints"] = "web"
        labels[f"traefik.http.services.{rid}.loadbalancer.server.port"] = str(route["targetPort"])
    return labels


def yaml_quote(value):
    return "'" + value.replace("'", "''") + "'"


def write_compose_override(path, routes, labels):
    routes_json = json.dumps(routes, separators=(",", ":"))
    lines = [
        "services:",
        "  agent:",
        "    environment:",
        f"      NVT_EXPOSED_HTTP_ROUTES_JSON: {yaml_quote(routes_json)}",
    ]
    if labels:
        lines.extend(["  docker:", "    labels:"])
        for key, value in labels.items():
            lines.append(f"      {key}: {yaml_quote(value)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(prog="render-agent-expose.py")
    parser.add_argument("--agent-config", required=True)
    parser.add_argument("--agent-name", required=True)
    parser.add_argument("--agent-host", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--proxy-port", default=os.environ.get("NVT_PROXY_PORT", "4090"))
    parser.add_argument("--print-urls", action="store_true")
    args = parser.parse_args()

    routes = load_expose_http(Path(args.agent_config))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    labels = compose_override(args.agent_name, args.agent_host, routes)
    write_compose_override(output, routes, labels)

    if args.print_urls:
        for route in routes:
            print(f"expose {route['name']} http://{route['name']}.{args.agent_host}:{args.proxy_port} -> {route['targetPort']}")


if __name__ == "__main__":
    main()
