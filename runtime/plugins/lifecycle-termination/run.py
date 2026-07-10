#!/usr/bin/env python3
import json
import os
import signal
import subprocess
from pathlib import Path

import yaml


def fail(message):
    raise SystemExit(f"lifecycle-termination: {message}")


def string_list(value, field):
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        fail(f"{field} must be a list of non-empty strings")
    return value


def load_config():
    path = os.environ.get("NVT_PLUGIN_CONFIG")
    if not path:
        fail("NVT_PLUGIN_CONFIG is not set")
    with Path(path).open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        fail("config must be a YAML object")
    message_path = data.get("terminationMessagePath", "/dev/termination-log")
    if not isinstance(message_path, str) or not message_path.startswith("/"):
        fail("terminationMessagePath must be an absolute path")
    complete = string_list(data.get("completeOn"), "completeOn")
    failed = string_list(data.get("failOn"), "failOn")
    if not complete and not failed:
        fail("at least one completeOn or failOn event is required")
    return message_path, set(complete), set(failed)


def event_name(event):
    plugin_event = event.get("plugin_event")
    if isinstance(plugin_event, str) and plugin_event:
        return plugin_event
    name = event.get("event")
    if isinstance(name, str):
        return name
    return ""


def write_termination(path, name, outcome):
    payload = json.dumps(
        {"nvtLifecycleEvent": name, "outcome": outcome},
        separators=(",", ":"),
    )
    with Path(path).open("w", encoding="utf-8") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def run():
    message_path, complete, failed = load_config()
    process = subprocess.Popen(
        ["agentdctl", "subscribe", "--since", "end"],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        for line in process.stdout:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            name = event_name(event)
            outcome = "completed" if name in complete else "failed" if name in failed else ""
            if not outcome:
                continue
            write_termination(message_path, name, outcome)
            terminate_pid = int(os.environ.get("NVT_LIFECYCLE_TERMINATE_PID", "1"))
            if terminate_pid > 0:
                os.kill(terminate_pid, signal.SIGTERM)
            return 0
    finally:
        if process.stdout is not None:
            process.stdout.close()
        process.terminate()
    return process.wait()


if __name__ == "__main__":
    raise SystemExit(run())
