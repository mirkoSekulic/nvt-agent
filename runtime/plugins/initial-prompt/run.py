#!/usr/bin/env python3
import hashlib
import os
import subprocess
import time
from pathlib import Path

import yaml

DEFAULT_DELIVERY_ATTEMPTS = 30
DEFAULT_DELIVERY_RETRY_DELAY_SECONDS = 1.0


def fail(message):
    raise SystemExit(f"initial-prompt: {message}")


def state_dir():
    return Path(os.environ.get("NVT_STATE_DIR", str(Path.home() / ".nvt-agent")))


def config_path():
    value = os.environ.get("NVT_PLUGIN_CONFIG")
    if not value:
        fail("NVT_PLUGIN_CONFIG is not set")
    return Path(value)


def load_config():
    path = config_path()
    if not path.is_file():
        fail("NVT_PLUGIN_CONFIG must point to a config file")
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    if not isinstance(data, dict):
        fail("config must be a YAML object")
    text = data.get("text", "")
    if text is None:
        return ""
    if not isinstance(text, str):
        fail("text must be a string")
    return text


def prompt_hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_path():
    return state_dir() / "initial-prompt" / "last.sha256"


def read_last_hash(path):
    try:
        return path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return ""


def write_hash_atomically(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    temporary.write_text(value + "\n", encoding="utf-8")
    temporary.replace(path)


def int_env(name, default):
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError:
        fail(f"{name} must be an integer")
    if parsed < 1:
        fail(f"{name} must be greater than or equal to 1")
    return parsed


def float_env(name, default):
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        parsed = float(value)
    except ValueError:
        fail(f"{name} must be a number")
    if parsed < 0:
        fail(f"{name} must be greater than or equal to 0")
    return parsed


def delivery_attempts():
    return int_env("NVT_INITIAL_PROMPT_RETRY_ATTEMPTS", DEFAULT_DELIVERY_ATTEMPTS)


def delivery_retry_delay_seconds():
    return float_env("NVT_INITIAL_PROMPT_RETRY_DELAY_SECONDS", DEFAULT_DELIVERY_RETRY_DELAY_SECONDS)


def enqueue_prompt(text):
    command = ["agentdctl", "prompt", "--source", "plugin:initial-prompt", "--no-external"]
    try:
        result = subprocess.run(command, input=text, text=True, check=False)
    except FileNotFoundError:
        fail("agentdctl not found on PATH")
    return result.returncode


def deliver_prompt(text):
    attempts = delivery_attempts()
    delay_seconds = delivery_retry_delay_seconds()
    last_exit_code = 0
    for attempt in range(1, attempts + 1):
        last_exit_code = enqueue_prompt(text)
        if last_exit_code == 0:
            return
        if attempt < attempts:
            time.sleep(delay_seconds)
    fail(f"agentdctl prompt failed after {attempts} attempts; last exit {last_exit_code}")


def run():
    text = load_config()
    if text == "":
        return 0

    digest = prompt_hash(text)
    path = hash_path()
    if read_last_hash(path) == digest:
        return 0

    deliver_prompt(text)
    write_hash_atomically(path, digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
