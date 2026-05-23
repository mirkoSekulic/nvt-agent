#!/usr/bin/env python3
import os
import subprocess
from pathlib import Path

import yaml


CONFIG_DIR = Path.home() / ".nvt-agent" / "git-credentials"
CONFIG_FILE = CONFIG_DIR / "config.yaml"
HELPER = "/usr/local/lib/nvt-agent/plugins/git-credentials/git-credential-nvt.py"


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
    string_value(header.get("header_env"), f"{field}.header_env", required=True)


def validate_rule(rule, index):
    if not isinstance(rule, dict):
        fail(f"credentials[{index}] must be a YAML object")

    string_value(rule.get("match"), f"credentials[{index}].match", required=True)
    kind = string_value(rule.get("type"), f"credentials[{index}].type", required=True)

    if kind == "token_env":
        string_value(rule.get("token_env"), f"credentials[{index}].token_env", required=True)
        return

    if kind == "github_app":
        if not rule.get("app_id") and not rule.get("app_id_env"):
            fail(f"credentials[{index}] requires app_id or app_id_env")
        if not rule.get("installation_id") and not rule.get("installation_id_env"):
            fail(f"credentials[{index}] requires installation_id or installation_id_env")
        if not rule.get("private_key_env") and not rule.get("private_key_b64_env"):
            fail(f"credentials[{index}] requires private_key_env or private_key_b64_env")
        return

    if kind == "headers":
        headers = list_value(rule.get("headers"), f"credentials[{index}].headers")
        if not headers:
            fail(f"credentials[{index}].headers must not be empty")
        for header_index, header in enumerate(headers):
            validate_header(header, f"credentials[{index}].headers[{header_index}]")
        return

    fail(f"unsupported credentials[{index}].type: {kind}")


def write_helper_config(credentials):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with CONFIG_FILE.open("w", encoding="utf-8") as file:
        yaml.safe_dump({"credentials": credentials}, file, sort_keys=False)
    CONFIG_FILE.chmod(0o600)


def configure_git_helper():
    run(["git", "config", "--global", "credential.helper", HELPER])
    run(["git", "config", "--global", "credential.useHttpPath", "true"])


def configure_headers(credentials):
    for rule in credentials:
        if rule.get("type") != "headers":
            continue
        match = string_value(rule.get("match"), "credentials.match", required=True)
        subprocess.run(["git", "config", "--global", "--unset-all", f"http.{match}.extraHeader"], check=False)
        for header in rule.get("headers", []):
            header_env = string_value(header.get("header_env"), "headers.header_env", required=True)
            value = os.environ.get(header_env)
            if value is None:
                fail(f"environment variable {header_env} is not set")
            run(["git", "config", "--global", "--add", f"http.{match}.extraHeader", value])


def main():
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


if __name__ == "__main__":
    main()
