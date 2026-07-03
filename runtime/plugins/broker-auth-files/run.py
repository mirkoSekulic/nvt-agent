#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml


DEFAULT_DIR_MODE = "0700"
DEFAULT_FILE_MODE = "0600"
DEFAULT_REFRESH_SLACK_SECONDS = 900
DEFAULT_MIN_SLEEP_SECONDS = 60
DEFAULT_FALLBACK_SLEEP_SECONDS = 3600
DEFAULT_MAX_LOOPS = 0


def fail(message):
    raise SystemExit(f"broker-auth-files: {message}")


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
    if required and not value:
        fail(f"{field} must not be empty")
    return value


def list_value(value, field):
    if value is None:
        return []
    if not isinstance(value, list):
        fail(f"{field} must be a list")
    return value


def int_value(value, field, default):
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        fail(f"{field} must be a non-negative integer")
    return value


def mode_value(value, field, default):
    mode = string_value(value, field) or default
    if len(mode) != 4 or any(char not in "01234567" for char in mode):
        fail(f"{field} must be a four-digit octal string")
    return int(mode, 8), mode


def validate_file_name(name):
    if not isinstance(name, str) or not name or "/" in name or "\\" in name or name == "." or ".." in name:
        fail("bundle file names must be plain relative filenames")


def load_config():
    config = load_yaml(config_path())
    bundles = []
    for index, raw in enumerate(list_value(config.get("bundles"), "bundles")):
        if not isinstance(raw, dict):
            fail(f"bundles[{index}] must be a YAML object")
        provider = string_value(raw.get("provider"), f"bundles[{index}].provider", required=True)
        target = Path(string_value(raw.get("target"), f"bundles[{index}].target", required=True))
        dir_mode, _dir_mode_text = mode_value(raw.get("dir-mode"), f"bundles[{index}].dir-mode", DEFAULT_DIR_MODE)
        file_mode, _file_mode_text = mode_value(raw.get("file-mode"), f"bundles[{index}].file-mode", DEFAULT_FILE_MODE)
        bundles.append({
            "provider": provider,
            "target": target,
            "dir_mode": dir_mode,
            "file_mode": file_mode,
        })
    if not bundles:
        fail("bundles must not be empty")
    return {
        "bundles": bundles,
        "refresh_slack_seconds": int_value(config.get("refresh-slack-seconds"), "refresh-slack-seconds", DEFAULT_REFRESH_SLACK_SECONDS),
        "min_sleep_seconds": int_value(config.get("min-sleep-seconds"), "min-sleep-seconds", DEFAULT_MIN_SLEEP_SECONDS),
        "fallback_sleep_seconds": int_value(config.get("fallback-sleep-seconds"), "fallback-sleep-seconds", DEFAULT_FALLBACK_SLEEP_SECONDS),
        "max_loops": int_value(config.get("max-loops"), "max-loops", DEFAULT_MAX_LOOPS),
    }


def broker_files(provider):
    command = ["brokerctl", "files", "--provider", provider]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        fail("brokerctl not found on PATH")
    if result.returncode != 0:
        fail(f"broker files request failed: {result.stderr.strip() or result.stdout.strip()}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        fail(f"broker files response was not valid JSON: {error}")
    if not payload.get("ok"):
        fail(f"broker files request failed: {payload.get('message') or payload.get('error') or 'unknown error'}")
    files = payload.get("files")
    if not isinstance(files, list):
        fail("broker files response did not include files")
    return payload


def atomic_write(path, content, mode):
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as file:
            file.write(content)
        temporary.chmod(mode)
        os.replace(temporary, path)
        path.chmod(mode)
    finally:
        temporary.unlink(missing_ok=True)


def validated_files(files, bundle):
    output = []
    for index, item in enumerate(files):
        if not isinstance(item, dict):
            fail(f"files[{index}] must be an object")
        name = item.get("name")
        validate_file_name(name)
        content = item.get("content")
        if not isinstance(content, str):
            fail(f"files[{index}].content must be a string")
        mode, _mode_text = mode_value(item.get("mode"), f"files[{index}].mode", f"{bundle['file_mode']:04o}")
        output.append((bundle["target"] / name, content, mode))
    return output


def materialize_bundle(bundle):
    payload = broker_files(bundle["provider"])
    files = validated_files(payload["files"], bundle)
    bundle["target"].mkdir(parents=True, exist_ok=True)
    bundle["target"].chmod(bundle["dir_mode"])
    for path, content, mode in files:
        atomic_write(path, content, mode)
    return payload.get("expires_at")


def parse_expiry(value):
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        fail("broker files response expires_at must be a string or null")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        fail("broker files response expires_at must be RFC3339")


def materialize_all(config):
    expiries = []
    providers = []
    for bundle in config["bundles"]:
        providers.append(bundle["provider"])
        expiry = parse_expiry(materialize_bundle(bundle))
        if expiry is not None:
            expiries.append(expiry)
    earliest = min(expiries) if expiries else None
    return providers, earliest


def expiry_text(expiry):
    if expiry is None:
        return None
    return expiry.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sleep_seconds(config, earliest):
    if earliest is None:
        return config["fallback_sleep_seconds"]
    target = earliest.timestamp() - config["refresh_slack_seconds"]
    return max(config["min_sleep_seconds"], target - time.time())


def publish_rematerialized(providers, earliest):
    payload = json.dumps({"providers": providers, "expires_at": expiry_text(earliest)}, separators=(",", ":"))
    source = f"plugin:{os.environ.get('NVT_PLUGIN_NAME') or 'broker-auth-files'}"
    try:
        subprocess.run(
            ["agentdctl", "publish", "plugin.broker-auth-files.rematerialized", "--source", source, "--payload", payload],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return


def loop(config):
    attempts = 0
    backoff = max(config["min_sleep_seconds"], 1)
    while True:
        attempts += 1
        try:
            providers, earliest = materialize_all(config)
            publish_rematerialized(providers, earliest)
            backoff = max(config["min_sleep_seconds"], 1)
            if config["max_loops"] > 0 and attempts >= config["max_loops"]:
                return 0
            time.sleep(sleep_seconds(config, earliest))
        except (OSError, RuntimeError, SystemExit) as error:
            print(f"broker-auth-files: warning: re-materialization failed: {error}", flush=True)
            if config["max_loops"] > 0 and attempts >= config["max_loops"]:
                return 0
            time.sleep(min(backoff, config["fallback_sleep_seconds"]))
            backoff = min(backoff * 2, config["fallback_sleep_seconds"])


def doctor(config):
    try:
        subprocess.run(["brokerctl", "health"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    except FileNotFoundError:
        fail("brokerctl not found on PATH")
    except subprocess.CalledProcessError as error:
        fail(f"broker health failed: {error.stderr.strip() or error.stdout.strip()}")
    missing = []
    for bundle in config["bundles"]:
        target = bundle["target"]
        if not target.is_dir():
            missing.append(str(target))
            continue
        for path in target.iterdir():
            if path.is_file():
                break
        else:
            missing.append(str(target))
    if missing:
        fail("target files missing: " + ", ".join(missing))
    return 0


def ready(_config):
    return 0


def run():
    config = load_config()
    command = sys.argv[1] if len(sys.argv) > 1 else "run"
    if command == "doctor":
        return doctor(config)
    if command == "ready":
        return ready(config)
    if command == "loop":
        return loop(config)
    if command != "run":
        fail(f"unknown command: {command}")
    materialize_all(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
