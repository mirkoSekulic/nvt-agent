#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml


CONFIG_DIR = Path.home() / ".nvt-agent" / "git-credentials"
CONFIG_FILE = CONFIG_DIR / "config.yaml"
HELPER_BINARY = "git-credential-nvt"
HELPER_CONFIG = "nvt"


def fail(message):
    raise SystemExit(f"git-credentials: {message}")


def run(command):
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True)


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


def validate_header(header, field):
    if not isinstance(header, dict):
        fail(f"{field} must be a YAML object")
    string_value(header.get("header-env"), f"{field}.header-env", required=True)


def validate_rule(rule, index):
    if not isinstance(rule, dict):
        fail(f"credentials[{index}] must be a YAML object")

    string_value(rule.get("match"), f"credentials[{index}].match", required=True)
    kind = string_value(rule.get("type"), f"credentials[{index}].type", required=True)

    if kind == "token-env":
        string_value(rule.get("token-env"), f"credentials[{index}].token-env", required=True)
        return

    if kind == "github-app":
        if not rule.get("app-id") and not rule.get("app-id-env"):
            fail(f"credentials[{index}] requires app-id or app-id-env")
        if not rule.get("installation-id") and not rule.get("installation-id-env"):
            fail(f"credentials[{index}] requires installation-id or installation-id-env")
        if not rule.get("private-key-env") and not rule.get("private-key-b64-env"):
            fail(f"credentials[{index}] requires private-key-env or private-key-b64-env")
        return

    if kind == "headers":
        headers = list_value(rule.get("headers"), f"credentials[{index}].headers")
        if not headers:
            fail(f"credentials[{index}].headers must not be empty")
        for header_index, header in enumerate(headers):
            validate_header(header, f"credentials[{index}].headers[{header_index}]")
        return

    fail(f"unsupported credentials[{index}].type: {kind}")


def env_is_set(name, field):
    if not isinstance(name, str) or not name:
        fail(f"{field} must be a non-empty string")
    if os.environ.get(name) is None:
        fail(f"environment variable {name} is not set")


def validate_int_or_env(rule, index, key):
    value = rule.get(key)
    env_key = f"{key}-env"
    env_name = rule.get(env_key)
    if value and env_name:
        fail(f"credentials[{index}] cannot set both {key} and {env_key}")
    if value:
        if not isinstance(value, int) and not (isinstance(value, str) and value.strip().isdigit()):
            fail(f"credentials[{index}].{key} must be an integer or numeric string")
        return
    env_is_set(env_name, f"credentials[{index}].{env_key}")


def doctor_rule(rule, index):
    validate_rule(rule, index)
    kind = rule.get("type")
    match = string_value(rule.get("match"), f"credentials[{index}].match", required=True)
    if not match.startswith(("http://", "https://")):
        fail(f"credentials[{index}].match must start with http:// or https://")

    if kind == "token-env":
        env_is_set(rule.get("token-env"), f"credentials[{index}].token-env")
        username = rule.get("username")
        if username is not None:
            string_value(username, f"credentials[{index}].username")
        return

    if kind == "github-app":
        if shutil.which("openssl") is None:
            fail("openssl not found on PATH")
        validate_int_or_env(rule, index, "app-id")
        validate_int_or_env(rule, index, "installation-id")
        private_key_env = rule.get("private-key-env")
        private_key_b64_env = rule.get("private-key-b64-env")
        if private_key_env and private_key_b64_env:
            fail(f"credentials[{index}] cannot set both private-key-env and private-key-b64-env")
        env_is_set(private_key_env or private_key_b64_env, f"credentials[{index}].private-key-env")
        api_url = rule.get("api-url")
        if api_url is not None and not string_value(api_url, f"credentials[{index}].api-url").startswith("https://"):
            fail(f"credentials[{index}].api-url must start with https://")
        return

    if kind == "headers":
        for header_index, header in enumerate(list_value(rule.get("headers"), f"credentials[{index}].headers")):
            header_env = string_value(
                header.get("header-env"),
                f"credentials[{index}].headers[{header_index}].header-env",
                required=True,
            )
            env_is_set(header_env, f"credentials[{index}].headers[{header_index}].header-env")


def write_helper_config(credentials):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with CONFIG_FILE.open("w", encoding="utf-8") as file:
        yaml.safe_dump({"credentials": credentials}, file, sort_keys=False)
    CONFIG_FILE.chmod(0o600)


def configure_git_helper():
    run(["git", "config", "--global", "credential.helper", HELPER_CONFIG])
    run(["git", "config", "--global", "credential.useHttpPath", "true"])


def configure_headers(credentials):
    for rule in credentials:
        if rule.get("type") != "headers":
            continue
        match = string_value(rule.get("match"), "credentials.match", required=True)
        subprocess.run(["git", "config", "--global", "--unset-all", f"http.{match}.extraHeader"], check=False)
        for header in rule.get("headers", []):
            header_env = string_value(header.get("header-env"), "headers.header-env", required=True)
            value = os.environ.get(header_env)
            if value is None:
                fail(f"environment variable {header_env} is not set")
            run(["git", "config", "--global", "--add", f"http.{match}.extraHeader", value])


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "doctor":
        doctor()
        return

    config = load_config()
    credentials = list_value(config.get("credentials"), "credentials")
    if not credentials:
        print("git-credentials: no credentials configured", flush=True)
        return

    for index, rule in enumerate(credentials):
        validate_rule(rule, index)

    write_helper_config(credentials)
    configure_git_helper()
    configure_headers(credentials)


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
