#!/usr/bin/env python3
import json
import os
import subprocess
import time
from pathlib import Path

import yaml

DEFAULT_DELAY_SECONDS = 5
DEFAULT_EVENT = "plugin.smoke.completed"
DEFAULT_PAYLOAD = {"ok": True}
DEFAULT_WAIT_FOR_PLUGIN = "event-webhook"
DEFAULT_WAIT_TIMEOUT_SECONDS = 30
WAIT_POLL_SECONDS = 0.1
SOURCE = "plugin:smoke-complete"


def fail(message):
    raise SystemExit(f"smoke-complete: {message}")


def config_path():
    value = os.environ.get("NVT_PLUGIN_CONFIG")
    if not value:
        fail("NVT_PLUGIN_CONFIG is not set")
    return Path(value)


def state_dir():
    return Path(os.environ.get("NVT_STATE_DIR", str(Path.home() / ".nvt-agent")))


def load_yaml(path):
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    if not isinstance(data, dict):
        fail("config must be a YAML object")
    return data


def int_seconds(value, field, default):
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool):
        fail(f"{field} must be an integer")
    if value < 0:
        fail(f"{field} must be greater than or equal to 0")
    return value


def event_name(value):
    if value is None:
        return DEFAULT_EVENT
    if not isinstance(value, str):
        fail("event must be a string")
    if not value.strip():
        fail("event must not be empty")
    if not value.startswith("plugin."):
        fail("event must start with plugin.")
    return value


def optional_plugin_name(value, field, default):
    if value is None:
        return default
    if value is False:
        return ""
    if not isinstance(value, str):
        fail(f"{field} must be a string or false")
    return value


def payload_object(value):
    if value is None:
        return dict(DEFAULT_PAYLOAD)
    if not isinstance(value, dict):
        fail("payload must be a YAML object")
    return value


def load_config():
    config = load_yaml(config_path())
    return {
        "delay_seconds": int_seconds(config.get("delaySeconds"), "delaySeconds", DEFAULT_DELAY_SECONDS),
        "event": event_name(config.get("event")),
        "payload": payload_object(config.get("payload")),
        "wait_for_plugin": optional_plugin_name(config.get("waitForPlugin"), "waitForPlugin", DEFAULT_WAIT_FOR_PLUGIN),
        "wait_timeout_seconds": int_seconds(
            config.get("waitTimeoutSeconds"),
            "waitTimeoutSeconds",
            DEFAULT_WAIT_TIMEOUT_SECONDS,
        ),
    }


def plugin_state_path(name):
    return state_dir() / "plugins" / name / "state.json"


def read_json(path):
    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    return data


def wait_for_plugin_ready(name, timeout_seconds):
    if not name:
        return

    deadline = time.monotonic() + timeout_seconds
    path = plugin_state_path(name)
    while True:
        state = read_json(path)
        if state is not None:
            if state.get("ready") is True:
                return
            if state.get("status") == "failed":
                fail(f"waitForPlugin {name} failed before smoke completion")
        if time.monotonic() >= deadline:
            fail(f"timed out waiting for waitForPlugin {name} to be ready")
        time.sleep(WAIT_POLL_SECONDS)


def publish(event, payload):
    try:
        payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    except TypeError as error:
        fail(f"payload must be JSON-serializable: {error}")

    command = [
        "agentdctl",
        "publish",
        event,
        "--source",
        SOURCE,
        "--payload",
        payload_json,
    ]
    try:
        result = subprocess.run(command, check=False)
    except FileNotFoundError:
        fail("agentdctl not found on PATH")
    if result.returncode != 0:
        fail(f"agentdctl publish failed with exit {result.returncode}")


def run():
    config = load_config()
    wait_for_plugin_ready(config["wait_for_plugin"], config["wait_timeout_seconds"])
    time.sleep(config["delay_seconds"])
    publish(config["event"], config["payload"])
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
