#!/usr/bin/env python3
import os
import json
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml


BUILTIN_PLUGIN_DIR = Path("/usr/local/lib/nvt-agent/plugins")


def state_dir():
    return Path(os.environ.get("NVT_STATE_DIR", str(Path.home() / ".nvt-agent")))


def fail(message):
    raise SystemExit(f"run-plugins: {message}")


def load_yaml(path):
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    if not isinstance(data, dict):
        fail(f"{path} must be a YAML object")
    return data


def load_plugins(path):
    data = load_yaml(path)
    plugins = data.get("plugins", [])
    if plugins is None:
        return []
    if not isinstance(plugins, list):
        fail("plugins must be a list")
    return plugins


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
    if not isinstance(value, int):
        fail(f"{field} must be an integer")
    return value


def object_value(value, field):
    if value is None:
        return {}
    if not isinstance(value, dict):
        fail(f"{field} must be a YAML object")
    return value


def bool_value(value, field, default=False):
    if value is None:
        return default
    if not isinstance(value, bool):
        fail(f"{field} must be a boolean")
    return value


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def plugin_source(plugin):
    return string_value(plugin.get("source"), "plugin.source") or "builtin"


def plugin_health(plugin):
    health = object_value(plugin.get("health"), "plugin.health")
    return {
        "readiness": bool_value(health.get("readiness"), "plugin.health.readiness"),
        "command": string_value(health.get("command"), "plugin.health.command"),
    }


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8") as file:
        json.dump(value, file, indent=2)
        file.write("\n")
    temporary.replace(path)


def plugin_state_path(name):
    return state_dir() / "plugins" / name / "state.json"


def write_plugin_state(name, state):
    write_json(plugin_state_path(name), state)


def initial_plugin_state(plugin, when, restart):
    name = string_value(plugin.get("name"), "plugin.name", required=True)
    health = plugin_health(plugin)
    return {
        "name": name,
        "source": plugin_source(plugin),
        "when": when,
        "restart": restart,
        "health": {
            "readiness": health["readiness"],
            "command": health["command"],
        },
        "status": "pending",
        "ready": False,
        "pid": None,
        "attempt": 0,
        "started_at": None,
        "finished_at": None,
        "last_success_at": None,
        "last_exit_code": None,
        "last_error": None,
    }


def default_when(plugin_name):
    if plugin_name == "checkout-repos":
        return "before-agent"
    return "after-agent"


def plugin_when(plugin):
    name = string_value(plugin.get("name"), "plugin.name", required=True)
    when = string_value(plugin.get("when"), "plugin.when") or default_when(name)
    if when not in {"before-agent", "after-agent"}:
        fail("plugin.when must be before-agent or after-agent")
    return when


def builtin_command(name):
    manifest = load_yaml(BUILTIN_PLUGIN_DIR / name / "plugin.yaml")
    command = string_value(manifest.get("command"), f"builtin plugin {name} command")
    if command:
        return command
    run_py = BUILTIN_PLUGIN_DIR / name / "run.py"
    if run_py.is_file():
        return str(run_py)
    return None


def plugin_command(plugin):
    source = plugin_source(plugin)
    name = string_value(plugin.get("name"), "plugin.name", required=True)

    override = string_value(plugin.get("command"), "plugin.command")
    if override:
        return override

    if source == "builtin":
        return builtin_command(name)
    if source == "custom":
        return None

    fail(f"unsupported plugin.source: {source}")


def write_plugin_config(name, config):
    if not isinstance(config, dict):
        fail("plugin.config must be a YAML object")

    config_dir = state_dir() / "plugins" / name
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "config.yaml"
    with config_path.open("w", encoding="utf-8") as file:
        yaml.safe_dump(config, file, sort_keys=False)
    return config_path


def run_plugin(plugin, state, attempt):
    name = string_value(plugin.get("name"), "plugin.name", required=True)
    command = plugin_command(plugin)
    if not command:
        state.update(
            {
                "status": "skipped",
                "ready": True,
                "pid": None,
                "attempt": attempt,
                "started_at": None,
                "finished_at": utc_now(),
                "last_success_at": utc_now(),
                "last_exit_code": None,
                "last_error": None,
            }
        )
        write_plugin_state(name, state)
        print(f"run-plugins: {name} has no lifecycle command, skipping", flush=True)
        return
    config_path = write_plugin_config(name, object_value(plugin.get("config"), "plugin.config"))

    env = os.environ.copy()
    env["NVT_PLUGIN_NAME"] = name
    env["NVT_PLUGIN_CONFIG"] = str(config_path)

    print(f"run-plugins: {name} attempt {attempt} started", flush=True)
    process = subprocess.Popen(command, shell=True, env=env)
    state.update(
        {
            "status": "running",
            "ready": state["restart"] in {"always", "on-failure"},
            "pid": process.pid,
            "attempt": attempt,
            "started_at": utc_now(),
            "finished_at": None,
            "last_exit_code": None,
            "last_error": None,
        }
    )
    write_plugin_state(name, state)

    exit_code = process.wait()
    finished_at = utc_now()
    if exit_code == 0:
        state.update(
            {
                "status": "succeeded",
                "ready": True,
                "pid": None,
                "finished_at": finished_at,
                "last_success_at": finished_at,
                "last_exit_code": exit_code,
                "last_error": None,
            }
        )
        write_plugin_state(name, state)
        print(f"run-plugins: {name} attempt {attempt} exited with code 0", flush=True)
        return

    state.update(
        {
            "status": "failed",
            "ready": False,
            "pid": None,
            "finished_at": finished_at,
            "last_exit_code": exit_code,
            "last_error": f"plugin exited with code {exit_code}",
        }
    )
    write_plugin_state(name, state)
    print(f"run-plugins: {name} attempt {attempt} exited with code {exit_code}", flush=True)
    raise subprocess.CalledProcessError(exit_code, command)


def run_once_with_retries(plugin, state):
    name = string_value(plugin.get("name"), "plugin.name", required=True)
    retries = int_value(plugin.get("retries"), "plugin.retries", 0)
    delay = int_value(plugin.get("restart-delay-seconds"), "plugin.restart-delay-seconds", 5)

    for attempt in range(1, retries + 2):
        try:
            run_plugin(plugin, state, attempt)
            return
        except subprocess.CalledProcessError as error:
            if attempt > retries:
                raise
            state.update(
                {
                    "status": "restarting",
                    "ready": False,
                    "pid": None,
                    "last_error": f"plugin exited with code {error.returncode}",
                }
            )
            write_plugin_state(name, state)
            print(
                f"run-plugins: {name} failed with exit {error.returncode}; retrying in {delay}s",
                flush=True,
            )
            time.sleep(delay)


def run_with_lifecycle(plugin):
    name = string_value(plugin.get("name"), "plugin.name", required=True)
    when = plugin_when(plugin)
    restart = string_value(plugin.get("restart"), "plugin.restart") or "never"
    delay = int_value(plugin.get("restart-delay-seconds"), "plugin.restart-delay-seconds", 5)
    if restart not in {"never", "on-failure", "always"}:
        fail("plugin.restart must be never, on-failure, or always")

    state = initial_plugin_state(plugin, when, restart)
    write_plugin_state(name, state)

    while True:
        try:
            run_once_with_retries(plugin, state)
            if restart != "always":
                return
        except subprocess.CalledProcessError:
            if restart != "on-failure":
                raise

        state.update(
            {
                "status": "restarting",
                "ready": False,
                "pid": None,
            }
        )
        write_plugin_state(name, state)
        print(f"run-plugins: restarting {name} in {delay}s", flush=True)
        time.sleep(delay)


def run_lifecycle_thread_target(plugin, failures, failures_lock):
    name = string_value(plugin.get("name"), "plugin.name", required=True)
    try:
        run_with_lifecycle(plugin)
    except Exception as error:
        with failures_lock:
            failures.append((name, error))
        print(f"run-plugins: {name} lifecycle stopped: {error}", flush=True)


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in {"before-agent", "after-agent"}:
        fail("usage: run-plugins before-agent|after-agent [agent.yaml]")

    when = sys.argv[1]
    config_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("/nvt-agent/agent.yaml")

    if when == "before-agent":
        for plugin in load_plugins(config_path):
            if not isinstance(plugin, dict):
                fail("plugins entries must be YAML objects")
            if plugin_when(plugin) == when:
                run_with_lifecycle(plugin)
        return

    plugins_to_run = []
    for plugin in load_plugins(config_path):
        if not isinstance(plugin, dict):
            fail("plugins entries must be YAML objects")
        if plugin_when(plugin) == when:
            plugins_to_run.append(plugin)

    failures = []
    failures_lock = threading.Lock()
    threads = []
    for plugin in plugins_to_run:
        name = string_value(plugin.get("name"), "plugin.name", required=True)
        thread = threading.Thread(
            target=run_lifecycle_thread_target,
            args=(plugin, failures, failures_lock),
            name=f"plugin-{name}",
        )
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    if failures:
        fail(f"{len(failures)} after-agent plugin lifecycle failed")


if __name__ == "__main__":
    main()
