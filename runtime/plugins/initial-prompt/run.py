#!/usr/bin/env python3
import hashlib
import os
import subprocess
from pathlib import Path

import yaml


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


def deliver_prompt(text):
    command = ["agentdctl", "prompt", "--source", "plugin:initial-prompt", "--no-external"]
    try:
        result = subprocess.run(command, input=text, text=True, check=False)
    except FileNotFoundError:
        fail("agentdctl not found on PATH")
    if result.returncode != 0:
        fail(f"agentdctl prompt failed with exit {result.returncode}")


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
