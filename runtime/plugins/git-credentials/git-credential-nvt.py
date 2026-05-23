#!/usr/bin/env python3
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

import yaml


CONFIG_FILE = Path.home() / ".nvt-agent" / "git-credentials" / "config.yaml"
CACHE_FILE = Path.home() / ".nvt-agent" / "git-credentials" / "cache.json"


def fail(message):
    print(f"git-credential-nvt: {message}", file=sys.stderr)
    sys.exit(1)


def output(command, **kwargs):
    result = subprocess.run(command, check=True, stdout=subprocess.PIPE, **kwargs)
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
        and url.startswith(rule["match"])
    ]
    if not matches:
        return None
    return max(matches, key=lambda rule: len(rule["match"]))


def env_value(name):
    value = os.environ.get(name)
    if value is None:
        fail(f"environment variable {name} is not set")
    return value


def token_env_credentials(rule):
    username = rule.get("username") or "x-access-token"
    token_env = rule.get("token_env")
    if not isinstance(token_env, str):
        fail("token_env credential requires token_env")
    return username, env_value(token_env)


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def private_key(rule):
    private_key_env = rule.get("private_key_env")
    private_key_b64_env = rule.get("private_key_b64_env")
    if private_key_env and private_key_b64_env:
        fail("github_app credential cannot set both private_key_env and private_key_b64_env")
    if isinstance(private_key_env, str):
        return env_value(private_key_env)
    if isinstance(private_key_b64_env, str):
        try:
            return base64.b64decode(env_value(private_key_b64_env)).decode("utf-8")
        except Exception as error:
            fail(f"could not decode {private_key_b64_env}: {error}")
    fail("github_app credential requires private_key_env or private_key_b64_env")


def github_app_value(rule, key):
    value = rule.get(key)
    if isinstance(value, str):
        return value
    env_key = f"{key}_env"
    env_name = rule.get(env_key)
    if isinstance(env_name, str):
        return env_value(env_name)
    fail(f"github_app credential requires {key} or {env_key}")


def github_app_jwt(rule):
    app_id = github_app_value(rule, "app_id")
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "iat": now - 60,
        "exp": now + 9 * 60,
        "iss": app_id,
    }
    signing_input = ".".join([
        b64url(json.dumps(header, separators=(",", ":")).encode("utf-8")),
        b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
    ])

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as key_file:
        key_file.write(private_key(rule))
        key_path = Path(key_file.name)

    try:
        signature = output(
            ["openssl", "dgst", "-sha256", "-sign", str(key_path)],
            input=signing_input.encode("utf-8"),
        )
    finally:
        key_path.unlink(missing_ok=True)

    return f"{signing_input}.{b64url(signature)}"


def read_cache():
    try:
        with CACHE_FILE.open("r", encoding="utf-8") as file:
            return json.load(file)
    except Exception:
        return {}


def write_cache(cache):
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CACHE_FILE.with_suffix(f".{os.getpid()}.tmp")
    with tmp.open("w", encoding="utf-8") as file:
        json.dump(cache, file)
        file.write("\n")
    tmp.replace(CACHE_FILE)
    CACHE_FILE.chmod(0o600)


def parse_time(value):
    if not isinstance(value, str):
        return 0
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0


def github_app_cache_key(rule):
    return "|".join([
        rule.get("api_url") or "https://api.github.com",
        github_app_value(rule, "app_id"),
        github_app_value(rule, "installation_id"),
    ])


def github_app_credentials(rule):
    cache_key = github_app_cache_key(rule)
    cache = read_cache()
    cached = cache.get(cache_key, {})
    if cached.get("token") and parse_time(cached.get("expires_at")) > time.time() + 300:
        return "x-access-token", cached["token"]

    installation_id = github_app_value(rule, "installation_id")
    api_url = rule.get("api_url") or "https://api.github.com"
    url = f"{api_url.rstrip('/')}/app/installations/{installation_id}/access_tokens"
    request = Request(
        url,
        method="POST",
        data=b"{}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {github_app_jwt(rule)}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urlopen(request, timeout=30) as response:
        data = json.loads(response.read().decode("utf-8"))

    token = data.get("token")
    if not isinstance(token, str) or not token:
        fail("GitHub App installation token response did not include token")

    cache[cache_key] = {
        "token": token,
        "expires_at": data.get("expires_at") or datetime.now(timezone.utc).isoformat(),
    }
    write_cache(cache)
    return "x-access-token", token


def credentials_for_rule(rule):
    kind = rule.get("type")
    if kind == "token_env":
        return token_env_credentials(rule)
    if kind == "github_app":
        return github_app_credentials(rule)
    if kind == "headers":
        return None
    fail(f"unsupported credential type: {kind}")


def main():
    operation = sys.argv[1] if len(sys.argv) > 1 else "get"
    if operation != "get":
        return

    url = request_url(read_request())
    if not url:
        return

    rule = matching_rule(url, load_config())
    if rule is None:
        return

    credentials = credentials_for_rule(rule)
    if credentials is None:
        return

    username, password = credentials
    print(f"username={username}")
    print(f"password={password}")
    print()


if __name__ == "__main__":
    main()
