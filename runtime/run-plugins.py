#!/usr/bin/env python3
import os
import subprocess
import sys
import time
from pathlib import Path

import yaml


BUILTIN_PLUGIN_DIR = Path("/usr/local/lib/nvt-agent/plugins")


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


def default_when(plugin_name):
    if plugin_name == "checkout-repos":
        return "before_agent"
    return "after_agent"


def plugin_when(plugin):
    name = string_value(plugin.get("name"), "plugin.name", required=True)
    when = string_value(plugin.get("when"), "plugin.when") or default_when(name)
    if when not in {"before_agent", "after_agent"}:
        fail("plugin.when must be before_agent or after_agent")
    return when


def builtin_command(name):
    manifest = load_yaml(BUILTIN_PLUGIN_DIR / name / "plugin.yaml")
    command = string_value(manifest.get("command"), f"builtin plugin {name} command")
    if command:
        return command
    return str(BUILTIN_PLUGIN_DIR / name / "run.py")


def plugin_command(plugin):
    source = string_value(plugin.get("source"), "plugin.source") or "builtin"
    name = string_value(plugin.get("name"), "plugin.name", required=True)

    override = string_value(plugin.get("command"), "plugin.command")
    if override:
        return override

    if source == "builtin":
        return builtin_command(name)
    if source == "custom":
        fail("custom plugins require plugin.command")

    fail(f"unsupported plugin.source: {source}")


def write_plugin_config(name, config):
    if not isinstance(config, dict):
        fail("plugin.config must be a YAML object")

    config_dir = Path.home() / ".nvt-agent" / "plugins" / name
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "config.yaml"
    with config_path.open("w", encoding="utf-8") as file:
        yaml.safe_dump(config, file, sort_keys=False)
    return config_path


def run_plugin(plugin):
    name = string_value(plugin.get("name"), "plugin.name", required=True)
    command = plugin_command(plugin)
    config_path = write_plugin_config(name, object_value(plugin.get("config"), "plugin.config"))

    env = os.environ.copy()
    env["NVT_PLUGIN_NAME"] = name
    env["NVT_PLUGIN_CONFIG"] = str(config_path)

    subprocess.run(command, shell=True, check=True, env=env)


def run_once_with_retries(plugin):
    retries = int_value(plugin.get("retries"), "plugin.retries", 0)
    delay = int_value(plugin.get("restart_delay_seconds"), "plugin.restart_delay_seconds", 5)

    for attempt in range(1, retries + 2):
        try:
            run_plugin(plugin)
            return
        except subprocess.CalledProcessError as error:
            if attempt > retries:
                raise
            print(
                f"run-plugins: plugin failed with exit {error.returncode}; retrying in {delay}s",
                flush=True,
            )
            time.sleep(delay)


def run_with_lifecycle(plugin):
    restart = string_value(plugin.get("restart"), "plugin.restart") or "never"
    delay = int_value(plugin.get("restart_delay_seconds"), "plugin.restart_delay_seconds", 5)
    if restart not in {"never", "on-failure", "always"}:
        fail("plugin.restart must be never, on-failure, or always")

    while True:
        try:
            run_once_with_retries(plugin)
            if restart != "always":
                return
        except subprocess.CalledProcessError:
            if restart != "on-failure":
                raise

        print(f"run-plugins: restarting plugin in {delay}s", flush=True)
        time.sleep(delay)


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in {"before_agent", "after_agent"}:
        fail("usage: run-plugins before_agent|after_agent [agent.yaml]")

    when = sys.argv[1]
    config_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("/nvt-agent/agent.yaml")

    for plugin in load_plugins(config_path):
        if not isinstance(plugin, dict):
            fail("plugins entries must be YAML objects")
        if plugin_when(plugin) == when:
            run_with_lifecycle(plugin)


if __name__ == "__main__":
    main()
