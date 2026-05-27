#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml


CONFIG_DIR = Path.home() / ".nvt-agent" / "git-credentials"
CONFIG_FILE = CONFIG_DIR / "config.yaml"
MANAGED_HEADERS_FILE = CONFIG_DIR / "managed-headers.yaml"
HELPER_BINARY = "git-credential-nvt"
HELPER_CONFIG = "nvt"


def fail(message):
    raise SystemExit(f"git-credentials: {message}")


def run(command):
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True)


def output(command):
    result = subprocess.run(command, check=True, stdout=subprocess.PIPE, text=True)
    return result.stdout


def string_value(value, field, required=False):
    if value is None:
        if required:
            fail(f"{field} is required")
        return None
    if not isinstance(value, str):
        fail(f"{field} must be a string")
    return value


def list_value(value, field):
    if value is None:
        return []
    if not isinstance(value, list):
        fail(f"{field} must be a list")
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


def validate_rule(rule, index):
    if not isinstance(rule, dict):
        fail(f"credentials[{index}] must be a YAML object")

    match = string_value(rule.get("match"), f"credentials[{index}].match", required=True)
    if not match.startswith(("http://", "https://")):
        fail(f"credentials[{index}].match must start with http:// or https://")
    string_value(rule.get("provider"), f"credentials[{index}].provider", required=True)
    username = rule.get("username")
    if username is not None:
        string_value(username, f"credentials[{index}].username")
    validate_identity(rule.get("identity"), index)


def validate_identity(identity, index):
    if identity is None:
        return
    if not isinstance(identity, dict):
        fail(f"credentials[{index}].identity must be a YAML object")
    mode = string_value(identity.get("mode"), f"credentials[{index}].identity.mode", required=True)
    if mode == "explicit":
        string_value(identity.get("name"), f"credentials[{index}].identity.name", required=True)
        string_value(identity.get("email"), f"credentials[{index}].identity.email", required=True)
        return
    if mode == "provider":
        return
    fail(f"credentials[{index}].identity.mode must be explicit or provider")


def doctor_rule(rule, index):
    validate_rule(rule, index)
    if shutil.which("git-host-credential") is None:
        fail("git-host-credential is not on PATH")
    provider = string_value(rule.get("provider"), f"credentials[{index}].provider", required=True)
    subprocess.run(["git-host-credential", "doctor", "--provider", provider], check=True)
    check_identity_provider(rule, index)


def provider_type(rule):
    provider = string_value(rule.get("provider"), "provider", required=True)
    try:
        return output(["git-host-credential", "type", "--provider", provider]).strip()
    except FileNotFoundError:
        fail("git-host-credential is not on PATH")
    except subprocess.CalledProcessError as error:
        fail(f"git-host-credential type failed with exit {error.returncode}")


def provider_credential_kind(rule):
    provider = string_value(rule.get("provider"), "provider", required=True)
    try:
        return output(["git-host-credential", "credential-kind", "--provider", provider]).strip()
    except FileNotFoundError:
        fail("git-host-credential is not on PATH")
    except subprocess.CalledProcessError as error:
        fail(f"git-host-credential credential-kind failed with exit {error.returncode}")


def check_identity_provider(rule, index=None):
    identity = rule.get("identity")
    if not isinstance(identity, dict) or identity.get("mode") != "provider":
        return
    kind = provider_type(rule)
    if kind not in {"github-app", "broker"}:
        provider = string_value(rule.get("provider"), "provider", required=True)
        prefix = f"credentials[{index}]." if index is not None else ""
        fail(f"{prefix}identity.mode=provider requested, but provider {provider} does not support commit identity; use identity.mode=explicit")


def provider_headers(rule):
    provider = string_value(rule.get("provider"), "provider", required=True)
    try:
        headers = output(["git-host-credential", "headers", "--provider", provider, "--target", target_from_url(rule["match"])]).splitlines()
    except FileNotFoundError:
        fail("git-host-credential is not on PATH")
    except subprocess.CalledProcessError as error:
        fail(f"git-host-credential headers failed with exit {error.returncode}")
    if not headers:
        fail(f"provider {provider} returned no headers")
    return headers


def identity_for_rule(rule, target):
    identity = rule.get("identity")
    if identity is None:
        return None
    mode = identity.get("mode")
    if mode == "explicit":
        return {"name": identity["name"], "email": identity["email"]}
    if mode == "provider":
        provider = string_value(rule.get("provider"), "provider", required=True)
        try:
            output_text = output(["git-host-credential", "identity", "--provider", provider, "--target", target])
        except FileNotFoundError:
            fail("git-host-credential is not on PATH")
        except subprocess.CalledProcessError as error:
            fail(f"git-host-credential identity failed with exit {error.returncode}")
        try:
            value = json.loads(output_text)
        except json.JSONDecodeError as error:
            fail(f"git-host-credential identity returned invalid JSON: {error}")
        name = value.get("name")
        email = value.get("email")
        if not isinstance(name, str) or not name or not isinstance(email, str) or not email:
            fail("git-host-credential identity response did not include name and email")
        return {"name": name, "email": email}
    fail("identity.mode must be explicit or provider")


def repo_remote(repo_path):
    try:
        return output(["git", "-C", str(repo_path), "remote", "get-url", "origin"]).strip()
    except subprocess.CalledProcessError:
        return ""


def target_from_url(url):
    value = url.strip().removesuffix(".git").strip("/")
    if value.startswith(("https://", "http://")):
        from urllib.parse import urlparse

        parsed = urlparse(value)
        return f"{parsed.hostname or ''}{parsed.path}".strip("/").removesuffix(".git")
    if "@" in value and ":" in value and "://" not in value:
        _user_host, path = value.split(":", 1)
        host = _user_host.rsplit("@", 1)[-1]
        return f"{host}/{path}".strip("/").removesuffix(".git")
    return value


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


def configure_repo(path):
    repo_path = Path(path)
    if not (repo_path / ".git").exists():
        fail(f"{repo_path} is not a Git repository")
    credentials = list_value(load_config().get("credentials"), "credentials")
    remote = repo_remote(repo_path)
    if not remote:
        return False
    rule = matching_rule(remote, credentials)
    if rule is None:
        return False
    identity = identity_for_rule(rule, target_from_url(remote))
    if identity is None:
        return False
    run(["git", "-C", str(repo_path), "config", "user.name", identity["name"]])
    run(["git", "-C", str(repo_path), "config", "user.email", identity["email"]])
    print(f"git-credentials: configured commit identity for {repo_path}", flush=True)
    return True


def write_helper_config(credentials):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with CONFIG_FILE.open("w", encoding="utf-8") as file:
        yaml.safe_dump({"credentials": credentials}, file, sort_keys=False)
    CONFIG_FILE.chmod(0o600)


def read_managed_header_keys():
    if not MANAGED_HEADERS_FILE.is_file():
        return []
    with MANAGED_HEADERS_FILE.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    keys = data.get("keys", []) if isinstance(data, dict) else []
    return [key for key in keys if isinstance(key, str)]


def write_managed_header_keys(keys):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with MANAGED_HEADERS_FILE.open("w", encoding="utf-8") as file:
        yaml.safe_dump({"keys": sorted(set(keys))}, file, sort_keys=False)
    MANAGED_HEADERS_FILE.chmod(0o600)


def configure_git_helper():
    run(["git", "config", "--global", "credential.helper", HELPER_CONFIG])
    run(["git", "config", "--global", "credential.useHttpPath", "true"])


def clear_managed_headers():
    for key in read_managed_header_keys():
        subprocess.run(["git", "config", "--global", "--unset-all", key], check=False)


def configure_headers(credentials):
    clear_managed_headers()
    managed_keys = []
    for rule in credentials:
        match = rule["match"]
        key = f"http.{match}.extraHeader"
        for header in provider_headers(rule):
            run(["git", "config", "--global", "--add", key, header])
        managed_keys.append(key)
    write_managed_header_keys(managed_keys)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "doctor":
        doctor()
        return
    if len(sys.argv) > 1 and sys.argv[1] == "configure-repo":
        if len(sys.argv) != 3:
            fail("configure-repo requires a repository path")
        configure_repo(sys.argv[2])
        return

    config = load_config()
    credentials = list_value(config.get("credentials"), "credentials")
    if not credentials:
        write_helper_config([])
        configure_headers([])
        print("git-credentials: no credentials configured", flush=True)
        return

    for index, rule in enumerate(credentials):
        validate_rule(rule, index)
        check_identity_provider(rule, index)

    token_credentials = []
    header_credentials = []
    for rule in credentials:
        kind = provider_credential_kind(rule)
        if kind == "headers":
            header_credentials.append(rule)
        else:
            token_credentials.append(rule)

    write_helper_config(token_credentials)
    configure_headers(header_credentials)
    if token_credentials:
        configure_git_helper()


def doctor():
    if shutil.which("git") is None:
        fail("git not found on PATH")
    helper = shutil.which(HELPER_BINARY)
    if not helper:
        fail(f"{HELPER_BINARY} is not on PATH")

    config = load_config()
    credentials = list_value(config.get("credentials"), "credentials")
    if not credentials:
        print("git-credentials: no credentials configured")
        return

    for index, rule in enumerate(credentials):
        doctor_rule(rule, index)

    print(f"git-credentials: {len(credentials)} credential rule(s) look valid")


if __name__ == "__main__":
    main()
