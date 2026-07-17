import base64
import fnmatch
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from re import fullmatch
from urllib.parse import quote, urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
sys.path.insert(0, "/usr/local/lib/nvt-agent")
from shared.plugin_egress import PluginEgressError, environment as plugin_egress_environment


CACHE_FILE = Path.home() / ".nvt-agent" / "git-host-credentials" / "cache.json"


def fail(message):
    raise SystemExit(f"git-host-credential: {message}")


def env_value(name):
    value = os.environ.get(name)
    if value is None:
        fail(f"environment variable {name} is not set")
    return value


def load_config():
    path = Path(os.environ.get("NVT_PLUGIN_CONFIG", ""))
    if not path.is_file():
        fail("NVT_PLUGIN_CONFIG must point to a config file")
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    if not isinstance(data, dict):
        fail("config must be a YAML object")
    return data


def string_value(value, field, required=False):
    if value is None:
        if required:
            fail(f"{field} is required")
        return None
    if not isinstance(value, str):
        fail(f"{field} must be a string")
    if required and not value:
        fail(f"{field} must not be empty")
    return value


def list_value(value, field):
    if value is None:
        return []
    if not isinstance(value, list):
        fail(f"{field} must be a list")
    return value


def provider_name(provider):
    return provider.get("name") if isinstance(provider.get("name"), str) else "<unknown>"


def providers(config):
    items = list_value(config.get("providers"), "providers")
    seen = set()
    output = []
    for index, provider in enumerate(items):
        if not isinstance(provider, dict):
            fail(f"providers[{index}] must be a YAML object")
        name = string_value(provider.get("name"), f"providers[{index}].name", required=True)
        if name in seen:
            fail(f"duplicate provider name: {name}")
        seen.add(name)
        kind = string_value(provider.get("type"), f"providers[{index}].type", required=True)
        if kind not in {"github-app", "token-env", "headers", "broker"}:
            fail(f"unsupported providers[{index}].type: {kind}")
        output.append(provider)
    return output


def provider_by_name(config, name):
    for provider in providers(config):
        if provider["name"] == name:
            return provider
    fail(f"provider not found: {name}")


def provider_value(provider, key):
    value = provider.get(key)
    env_key = f"{key}-env"
    env_name = provider.get(env_key)
    if value is not None and env_name is not None:
        fail(f"provider {provider_name(provider)} cannot set both {key} and {env_key}")
    if value is not None:
        if isinstance(value, int):
            return str(value)
        if isinstance(value, str):
            return value
        fail(f"provider {provider_name(provider)} {key} must be a string or integer")
    if isinstance(env_name, str):
        return env_value(env_name)
    fail(f"provider {provider_name(provider)} requires {key} or {env_key}")


def token_env(provider):
    token_env_name = string_value(provider.get("token-env"), f"provider {provider_name(provider)} token-env", required=True)
    return env_value(token_env_name)


def private_key(provider):
    private_key_env = provider.get("private-key-env")
    private_key_base64_env = provider.get("private-key-base64-env") or provider.get("private-key-b64-env")
    if private_key_env and private_key_base64_env:
        fail(f"provider {provider_name(provider)} cannot set both private-key-env and private-key-base64-env")
    if isinstance(private_key_env, str):
        return env_value(private_key_env)
    if isinstance(private_key_base64_env, str):
        try:
            return base64.b64decode(env_value(private_key_base64_env)).decode("utf-8")
        except Exception as error:
            fail(f"could not decode {private_key_base64_env}: {error}")
    fail(f"provider {provider_name(provider)} requires private-key-env or private-key-base64-env")


def normalize_repo(value):
    if not value:
        return None
    repo = value.strip()
    scp_like = fullmatch(r"[^/@:]+@([^:]+):(.+)", repo)
    if scp_like:
        repo = f"{scp_like.group(1)}/{scp_like.group(2)}"
    elif "://" in repo:
        parsed = urlparse(repo)
        repo = f"{parsed.netloc}{parsed.path}".strip("/")
        repo = repo.removesuffix(".git")
    elif repo.count("/") == 1:
        repo = "github.com/" + repo
    return repo.strip("/").removesuffix(".git")


def provider_matches(provider, repo):
    normalized = normalize_repo(repo)
    if not normalized:
        return False
    for pattern in list_value(provider.get("match"), f"provider {provider_name(provider)} match"):
        if not isinstance(pattern, str):
            fail(f"provider {provider_name(provider)} match entries must be strings")
        normalized_pattern = normalize_repo(pattern) or pattern
        if fnmatch.fnmatchcase(normalized, normalized_pattern):
            return True
    return False


def resolve_provider(config, name=None, repo=None):
    if name:
        return provider_by_name(config, name)
    if repo:
        matches = [provider for provider in providers(config) if provider_matches(provider, repo)]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            names = ", ".join(provider["name"] for provider in matches)
            fail(f"multiple providers match {repo}: {names}; pass --provider")
    default_provider = string_value(config.get("default-provider"), "default-provider")
    if default_provider:
        return provider_by_name(config, default_provider)
    fail("provider is required; pass --provider, configure default-provider, or provide a matching repo")


def api_url(provider):
    value = string_value(provider.get("api-url") or "https://api.github.com", f"provider {provider_name(provider)} api-url", required=True)
    if not value.startswith("https://"):
        fail(f"provider {provider_name(provider)} api-url must start with https://")
    return value.rstrip("/")


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def openssl_sign(private_key_text, signing_input):
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as key_file:
        key_file.write(private_key_text)
        key_path = Path(key_file.name)
    try:
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(key_path)],
            check=True,
            input=signing_input.encode("utf-8"),
            stdout=subprocess.PIPE,
        )
        return result.stdout
    finally:
        key_path.unlink(missing_ok=True)


def github_app_jwt(provider):
    app_id = provider_value(provider, "app-id")
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"iat": now - 60, "exp": now + 9 * 60, "iss": app_id}
    signing_input = ".".join([
        b64url(json.dumps(header, separators=(",", ":")).encode("utf-8")),
        b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
    ])
    return f"{signing_input}.{b64url(openssl_sign(private_key(provider), signing_input))}"


def parse_time(value):
    if not isinstance(value, str):
        return 0
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0


def read_cache():
    try:
        with CACHE_FILE.open("r", encoding="utf-8") as file:
            return json.load(file)
    except Exception:
        return {}


def write_cache(cache):
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = CACHE_FILE.with_suffix(f".{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8") as file:
        json.dump(cache, file)
        file.write("\n")
    temporary.chmod(0o600)
    temporary.replace(CACHE_FILE)
    CACHE_FILE.chmod(0o600)


def cache_key(provider):
    return "|".join([
        api_url(provider),
        provider_value(provider, "app-id"),
        provider_value(provider, "installation-id"),
    ])


def installation_token(provider):
    key = cache_key(provider)
    cache = read_cache()
    cached = cache.get(key, {})
    if cached.get("token") and parse_time(cached.get("expires_at")) > time.time() + 300:
        return cached["token"]

    installation_id = provider_value(provider, "installation-id")
    request = Request(
        f"{api_url(provider)}/app/installations/{installation_id}/access_tokens",
        method="POST",
        data=b"{}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {github_app_jwt(provider)}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        fail(f"GitHub installation token request failed: {error.code} {error.reason}: {body}")
    except URLError as error:
        fail(f"GitHub installation token request failed: {error.reason}")
    token = data.get("token")
    if not isinstance(token, str) or not token:
        fail("GitHub App installation token response did not include token")
    cache[key] = {
        "token": token,
        "expires_at": data.get("expires_at") or datetime.now(timezone.utc).isoformat(),
    }
    write_cache(cache)
    return token


def github_json(provider, path):
    request = Request(
        f"{api_url(provider)}{path}",
        method="GET",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {github_app_jwt(provider)}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        fail(f"GitHub identity request failed: {error.code} {error.reason}: {body}")
    except URLError as error:
        fail(f"GitHub identity request failed: {error.reason}")


def github_app_identity(provider):
    app = github_json(provider, "/app")
    slug = app.get("slug")
    if not isinstance(slug, str) or not slug:
        fail(f"provider {provider_name(provider)} GitHub App response did not include slug")
    bot_login = f"{slug}[bot]"
    user = github_json(provider, f"/users/{quote(bot_login, safe='')}")
    bot_id = user.get("id")
    if not isinstance(bot_id, int):
        fail(f"provider {provider_name(provider)} GitHub bot user response did not include numeric id")
    return {
        "name": bot_login,
        "email": f"{bot_id}+{bot_login}@users.noreply.github.com",
    }


def broker_token(provider, target):
    broker_provider = broker_provider_name(provider)
    if not target:
        fail(f"provider {provider_name(provider)} broker token requires --target")
    command = ["brokerctl", "token", "--provider", broker_provider, "--target", target, "--raw"]
    purpose = string_value(provider.get("purpose"), f"provider {provider_name(provider)} purpose")
    if purpose:
        command.extend(["--purpose", purpose])
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        fail(f"broker token request failed: {stderr or stdout}")
    return result.stdout.strip()


def broker_identity(provider, target):
    broker_provider = broker_provider_name(provider)
    if not target:
        fail(f"provider {provider_name(provider)} broker identity requires --target")
    command = ["brokerctl", "identity", "--provider", broker_provider, "--target", target]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        fail(f"broker identity request failed: {stderr or stdout}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        fail(f"broker identity returned invalid JSON: {error}")
    if not payload.get("ok"):
        fail(f"broker identity request failed: {payload.get('message') or payload.get('error') or 'unknown error'}")
    name = payload.get("name")
    email = payload.get("email")
    if not isinstance(name, str) or not name or not isinstance(email, str) or not email:
        fail("broker identity response did not include name and email")
    return {"name": name, "email": email}


def broker_headers(provider, target):
    broker_provider = broker_provider_name(provider)
    if not target:
        fail(f"provider {provider_name(provider)} broker headers require --target")
    command = ["brokerctl", "headers", "--provider", broker_provider, "--target", target, "--raw"]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        fail(f"broker headers request failed: {stderr or stdout}")
    output = [line for line in result.stdout.splitlines() if line.strip()]
    if not output:
        fail("broker headers response did not include headers")
    return output


def credential_kind(provider):
    kind = provider.get("type")
    if kind == "broker":
        value = string_value(provider.get("credential-kind"), f"provider {provider_name(provider)} credential-kind") or "token"
        if value not in {"token", "headers", "mediated"}:
            fail(f"provider {provider_name(provider)} credential-kind must be token, headers, or mediated")
        return value
    if kind == "headers":
        return "headers"
    if kind in {"github-app", "token-env"}:
        return "token"
    fail(f"provider {provider_name(provider)} does not provide Git credentials")


def broker_provider_name(provider):
    return string_value(provider.get("broker-provider") or provider.get("provider"), f"provider {provider_name(provider)} broker-provider", required=True)


def mediated_proxy_url(provider):
    if credential_kind(provider) != "mediated":
        fail(f"provider {provider_name(provider)} is not mediated")
    try:
        env = plugin_egress_environment({"egress": {"provider": broker_provider_name(provider)}})
    except PluginEgressError as error:
        fail(str(error))
    proxy_url = env.get("HTTPS_PROXY")
    if not proxy_url:
        fail(f"provider {provider_name(provider)} is mediated but provider-scoped proxy is unavailable")
    return proxy_url


def token(provider, target=None):
    kind = provider.get("type")
    if credential_kind(provider) == "mediated":
        fail(f"provider {provider_name(provider)} is mediated; token credentials are not available in the agent")
    if kind == "github-app":
        return installation_token(provider)
    if kind == "token-env":
        return token_env(provider)
    if kind == "broker":
        return broker_token(provider, target)
    fail(f"provider {provider_name(provider)} does not provide token credentials")


def identity(provider, target=None):
    kind = provider.get("type")
    if kind == "github-app":
        return github_app_identity(provider)
    if kind == "broker":
        return broker_identity(provider, target)
    fail(f"provider {provider_name(provider)} does not support commit identity; use identity.mode=explicit")


def headers(provider, target=None):
    if credential_kind(provider) == "mediated":
        fail(f"provider {provider_name(provider)} is mediated; header credentials are injected by egressd")
    if provider.get("type") == "broker":
        return broker_headers(provider, target)
    if provider.get("type") != "headers":
        fail(f"provider {provider_name(provider)} does not provide header credentials")
    output = []
    for index, header in enumerate(list_value(provider.get("headers"), f"provider {provider_name(provider)} headers")):
        if not isinstance(header, dict):
            fail(f"provider {provider_name(provider)} headers[{index}] must be a YAML object")
        header_env = string_value(header.get("header-env"), f"provider {provider_name(provider)} headers[{index}].header-env", required=True)
        output.append(env_value(header_env))
    if not output:
        fail(f"provider {provider_name(provider)} headers must not be empty")
    return output


def validate_provider(provider):
    kind = provider.get("type")
    if kind == "github-app":
        if shutil.which("openssl") is None:
            fail("openssl not found on PATH")
        provider_value(provider, "app-id")
        provider_value(provider, "installation-id")
        private_key(provider)
        api_url(provider)
    elif kind == "token-env":
        token_env(provider)
    elif kind == "broker":
        if shutil.which("brokerctl") is None:
            fail("brokerctl not found on PATH")
        string_value(provider.get("broker-provider") or provider.get("provider"), f"provider {provider_name(provider)} broker-provider", required=True)
        credential_kind(provider)
    elif kind == "headers":
        headers(provider)
    else:
        fail(f"unsupported provider {provider_name(provider)} type: {kind}")
    list_value(provider.get("match"), f"provider {provider_name(provider)} match")
