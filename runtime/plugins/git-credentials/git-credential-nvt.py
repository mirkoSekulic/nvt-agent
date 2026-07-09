#!/usr/bin/env python3
import os
import subprocess
import sys
from pathlib import Path

import yaml


CONFIG_FILE = Path.home() / ".nvt-agent" / "git-credentials" / "config.yaml"
PLACEHOLDER = "NVT-PLACEHOLDER-NOT-A-KEY"


def fail(message):
    print(f"git-credential-nvt: {message}", file=sys.stderr)
    sys.exit(1)


def output(command):
    result = subprocess.run(command, check=True, stdout=subprocess.PIPE, text=True)
    return result.stdout


def read_request():
    values = {}
    for line in sys.stdin:
        line = line.rstrip("\n")
        if not line:
            break
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    return values


def request_url(values):
    protocol = values.get("protocol")
    host = values.get("host")
    path = values.get("path", "")
    if not protocol or not host:
        return ""
    url = f"{protocol}://{host}/"
    if path:
        url += path.lstrip("/")
    return url


def request_target(values):
    host = values.get("host")
    path = values.get("path", "")
    if not host:
        return ""
    target = host
    if path:
        target += "/" + path.lstrip("/")
    return target.strip("/").removesuffix(".git")


def load_config():
    if not CONFIG_FILE.is_file():
        return []
    with CONFIG_FILE.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    credentials = data.get("credentials", [])
    if not isinstance(credentials, list):
        fail("credentials config must contain a credentials list")
    return credentials


def matching_rule(url, credentials):
    matches = [
        rule for rule in credentials
        if isinstance(rule, dict)
        and isinstance(rule.get("match"), str)
        and isinstance(rule.get("provider"), str)
        and url_matches(url, rule["match"])
    ]
    if not matches:
        return None
    return max(matches, key=lambda rule: len(rule["match"]))


def url_matches(url, match):
    prefix = match.rstrip("/")
    return url == prefix or url.startswith(prefix + "/") or url.startswith(prefix + ".git")


def provider_credentials(rule, target):
    provider = rule.get("provider")
    if not isinstance(provider, str) or not provider:
        fail("credential rule requires provider")
    username = rule.get("username") or "x-access-token"
    if not isinstance(username, str):
        fail("credential rule username must be a string")
    try:
        kind_command = ["git-host-credential", "credential-kind", "--provider", provider]
        if target:
            kind_command.extend(["--target", target])
        kind = output(kind_command).strip()
    except FileNotFoundError:
        fail("git-host-credential is not on PATH")
    except subprocess.CalledProcessError as error:
        fail(f"git-host-credential credential-kind failed with exit {error.returncode}")
    if kind == "mediated":
        return username, os.environ.get("NVT_EGRESS_PLACEHOLDER") or PLACEHOLDER
    try:
        command = ["git-host-credential", "token", "--provider", provider]
        if target:
            command.extend(["--target", target])
        token = output(command).strip()
    except FileNotFoundError:
        fail("git-host-credential is not on PATH")
    except subprocess.CalledProcessError as error:
        fail(f"git-host-credential token failed with exit {error.returncode}")
    if not token:
        fail("git-host-credential returned an empty token")
    return username, token


def main():
    operation = sys.argv[1] if len(sys.argv) > 1 else "get"
    if operation != "get":
        return

    request = read_request()
    url = request_url(request)
    if not url:
        return

    rule = matching_rule(url, load_config())
    if rule is None:
        return

    username, password = provider_credentials(rule, request_target(request))
    print(f"username={username}")
    print(f"password={password}")
    print()


if __name__ == "__main__":
    main()
