#!/usr/bin/env python3
import json
import os
import subprocess
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import yaml


def fail(message):
    raise SystemExit(f"event-webhook: {message}")


def state_dir():
    return Path(os.environ.get("NVT_STATE_DIR", str(Path.home() / ".nvt-agent")))


def plugin_state_dir():
    return state_dir() / "plugins" / "event-webhook"


def config_path():
    value = os.environ.get("NVT_PLUGIN_CONFIG")
    if not value:
        fail("NVT_PLUGIN_CONFIG is not set")
    return Path(value)


def load_yaml(path):
    if not path.is_file():
        return {}
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
    return value


def int_value(value, field, default):
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool):
        fail(f"{field} must be an integer")
    return value


def bool_value(value, field, default):
    if value is None:
        return default
    if not isinstance(value, bool):
        fail(f"{field} must be a boolean")
    return value


def object_value(value, field):
    if value is None:
        return {}
    if not isinstance(value, dict):
        fail(f"{field} must be a YAML object")
    return value


def string_list(value, field):
    if value is None:
        return []
    if not isinstance(value, list):
        fail(f"{field} must be a list")
    for item in value:
        if not isinstance(item, str):
            fail(f"{field} entries must be strings")
    return value


def load_config():
    config = load_yaml(config_path())
    url = string_value(config.get("url"), "url", required=True)
    since = string_value(config.get("since"), "since") or "end"
    if since not in {"end", "beginning"}:
        fail("since must be end or beginning")

    auth = object_value(config.get("auth"), "auth")
    auth_type = string_value(auth.get("type"), "auth.type") or "none"
    if auth_type not in {"none", "bearer-env"}:
        fail("auth.type must be none or bearer-env")
    token = None
    if auth_type == "bearer-env":
        env_name = string_value(auth.get("env"), "auth.env", required=True)
        token = os.environ.get(env_name, "").strip()
        if not token:
            fail(f"environment variable {env_name} is not set")

    delivery = object_value(config.get("delivery"), "delivery")
    retry = object_value(delivery.get("retry"), "delivery.retry")
    max_delivered_ids = int_value(delivery.get("max-delivered-ids"), "delivery.max-delivered-ids", 1000)
    max_attempts = int_value(retry.get("max-attempts"), "delivery.retry.max-attempts", 3)
    backoff_seconds = int_value(retry.get("backoff-seconds"), "delivery.retry.backoff-seconds", 5)
    if max_delivered_ids < 0:
        fail("delivery.max-delivered-ids must be greater than or equal to 0")
    if max_attempts < 1:
        fail("delivery.retry.max-attempts must be greater than or equal to 1")
    if backoff_seconds < 0:
        fail("delivery.retry.backoff-seconds must be greater than or equal to 0")

    return {
        "url": url,
        "since": since,
        "filters": string_list(config.get("filters"), "filters"),
        "auth_type": auth_type,
        "token": token,
        "dedupe": bool_value(delivery.get("dedupe"), "delivery.dedupe", True),
        "max_delivered_ids": max_delivered_ids,
        "max_attempts": max_attempts,
        "backoff_seconds": backoff_seconds,
    }


def delivery_state_path():
    return plugin_state_dir() / "delivery-state.json"


def read_delivery_state():
    path = delivery_state_path()
    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError:
        return {"delivered_ids": []}
    except json.JSONDecodeError:
        return {"delivered_ids": []}
    if not isinstance(data, dict) or not isinstance(data.get("delivered_ids"), list):
        return {"delivered_ids": []}
    return {"delivered_ids": [str(value) for value in data["delivered_ids"]]}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8") as file:
        json.dump(value, file, indent=2)
        file.write("\n")
    temporary.replace(path)


def remember_delivered(state, event_id, max_delivered_ids):
    if event_id is None:
        return
    delivered_ids = [value for value in state["delivered_ids"] if value != event_id]
    delivered_ids.append(event_id)
    if max_delivered_ids == 0:
        delivered_ids = []
    elif len(delivered_ids) > max_delivered_ids:
        delivered_ids = delivered_ids[-max_delivered_ids:]
    state["delivered_ids"] = delivered_ids
    write_json(delivery_state_path(), state)


def event_id(event):
    value = event.get("id")
    if value is None:
        return None
    return str(value)


def event_matches(event, filters):
    if not filters:
        return True
    values = []
    for key in ("event", "plugin_event"):
        value = event.get(key)
        if isinstance(value, str):
            values.append(value)
    return any(value.startswith(prefix) for value in values for prefix in filters)


def agent_name():
    return os.environ.get("NVT_AGENT_NAME") or os.environ.get("AGENT_NAME") or ""


def post_event(config, event):
    body = json.dumps({"agent": agent_name(), "event": event}, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if config["auth_type"] == "bearer-env":
        headers["Authorization"] = f"Bearer {config['token']}"
    request = Request(config["url"], data=body, headers=headers, method="POST")
    with urlopen(request, timeout=30) as response:
        status = response.getcode()
        if 200 <= status < 300:
            return
        raise RuntimeError(f"HTTP {status}")


def deliver_with_retry(config, event):
    last_error = None
    for attempt in range(1, config["max_attempts"] + 1):
        try:
            post_event(config, event)
            return True
        except HTTPError as error:
            last_error = f"HTTP {error.code}"
        except (URLError, OSError, RuntimeError) as error:
            last_error = str(error)
        if attempt < config["max_attempts"]:
            time.sleep(config["backoff_seconds"])
    print(f"event-webhook: failed to deliver event after {config['max_attempts']} attempts: {last_error}", flush=True)
    return False


def subscribe_process(config):
    command = ["agentdctl", "subscribe", "--since", config["since"]]
    try:
        return subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, text=True)
    except FileNotFoundError:
        fail("agentdctl not found on PATH")


def run():
    config = load_config()
    state = read_delivery_state()
    delivered = set(state["delivered_ids"])
    process = subscribe_process(config)
    try:
        for line in process.stdout:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict) or not event_matches(event, config["filters"]):
                continue
            eid = event_id(event)
            if config["dedupe"] and eid is not None and eid in delivered:
                continue
            if deliver_with_retry(config, event):
                if config["dedupe"] and eid is not None:
                    remember_delivered(state, eid, config["max_delivered_ids"])
                    delivered = set(state["delivered_ids"])
    finally:
        if process.stdout is not None:
            process.stdout.close()
    return process.wait()


if __name__ == "__main__":
    raise SystemExit(run())
