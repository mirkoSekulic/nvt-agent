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


def doctor_rule(rule, index):
    validate_rule(rule, index)
    if shutil.which("git-host-credential") is None:
        fail("git-host-credential is not on PATH")
    provider = string_value(rule.get("provider"), f"credentials[{index}].provider", required=True)
    subprocess.run(["git-host-credential", "doctor", "--provider", provider], check=True)


def provider_type(rule):
    provider = string_value(rule.get("provider"), "provider", required=True)
    try:
        return output(["git-host-credential", "type", "--provider", provider]).strip()
    except FileNotFoundError:
        fail("git-host-credential is not on PATH")
    except subprocess.CalledProcessError as error:
        fail(f"git-host-credential type failed with exit {error.returncode}")


def provider_headers(rule):
    provider = string_value(rule.get("provider"), "provider", required=True)
    try:
        headers = output(["git-host-credential", "headers", "--provider", provider]).splitlines()
    except FileNotFoundError:
        fail("git-host-credential is not on PATH")
    except subprocess.CalledProcessError as error:
        fail(f"git-host-credential headers failed with exit {error.returncode}")
    if not headers:
        fail(f"provider {provider} returned no headers")
    return headers


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
        match = rule["match"]
        key = f"http.{match}.extraHeader"
        subprocess.run(["git", "config", "--global", "--unset-all", key], check=False)
        for header in provider_headers(rule):
            run(["git", "config", "--global", "--add", key, header])


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

    token_credentials = []
    header_credentials = []
    for rule in credentials:
        kind = provider_type(rule)
        if kind == "headers":
            header_credentials.append(rule)
        else:
            token_credentials.append(rule)

    write_helper_config(token_credentials)
    if header_credentials:
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
