#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml


BUILTIN_PLUGIN_DIR = Path("/usr/local/lib/nvt-agent/plugins")


def config_path():
    return Path(os.environ.get("NVT_AGENT_CONFIG_FILE", "/nvt-agent/agent.yaml"))


def state_dir():
    return Path(os.environ.get("NVT_STATE_DIR", str(Path.home() / ".nvt-agent")))


def workspace():
    return Path(os.environ.get("NVT_WORKSPACE", "/workspace"))


def check(status, name, message):
    return {
        "status": status,
        "name": name,
        "message": message,
    }


def ok(name, message):
    return check("ok", name, message)


def warn(name, message):
    return check("warn", name, message)


def fail(name, message):
    return check("fail", name, message)


def skip(name, message):
    return check("skip", name, message)


def load_yaml(path):
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} must be a YAML object")
    return data


def load_agent_config():
    path = config_path()
    data = load_yaml(path)
    return path, data


def command_exists(command):
    return shutil.which(command) is not None


def run_check(command, timeout=10):
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def directory_writable(path):
    path.mkdir(parents=True, exist_ok=True)
    probe = path / f".nvt-doctor-{os.getpid()}"
    probe.write_text("doctor\n", encoding="utf-8")
    probe.unlink()


def core_checks():
    checks = []
    path = config_path()
    try:
        _config_path, config = load_agent_config()
        checks.append(ok("core.agent-config", f"{path} is readable"))
    except (OSError, yaml.YAMLError, ValueError) as error:
        checks.append(fail("core.agent-config", str(error)))
        config = {}

    for name, path in [
        ("core.workspace", workspace()),
        ("core.state-dir", state_dir()),
    ]:
        try:
            directory_writable(path)
            checks.append(ok(name, f"{path} is writable"))
        except OSError as error:
            checks.append(fail(name, f"{path} is not writable: {error}"))

    for binary in ["code-server", "tmux", "git", "docker"]:
        found = shutil.which(binary)
        if found:
            checks.append(ok(f"core.{binary}", found))
        else:
            checks.append(fail(f"core.{binary}", f"{binary} not found on PATH"))

    runtime = config.get("runtime", {})
    command = runtime.get("command") if isinstance(runtime, dict) else None
    if isinstance(command, str) and command.strip():
        binary = command.split()[0]
        found = shutil.which(binary)
        if found:
            checks.append(ok("core.agent-command", f"{binary}: {found}"))
        else:
            checks.append(fail("core.agent-command", f"{binary} not found on PATH"))

    docker_host = os.environ.get("DOCKER_HOST")
    if docker_host:
        try:
            result = run_check(["docker", "info", "--format", "{{.ServerVersion}}"])
            if result.returncode == 0:
                checks.append(ok("core.docker-daemon", f"{docker_host} server {result.stdout.strip()}"))
            else:
                output = "\n".join(part for part in [result.stdout.strip(), result.stderr.strip()] if part)
                checks.append(fail("core.docker-daemon", output or "per-agent Docker daemon is not reachable"))
        except (OSError, subprocess.TimeoutExpired) as error:
            checks.append(fail("core.docker-daemon", f"per-agent Docker daemon is not reachable: {error}"))
    else:
        checks.append(warn("core.docker-daemon", "DOCKER_HOST is not set"))

    return checks


def plugin_entries(config):
    plugins = config.get("plugins", [])
    if plugins is None:
        return []
    if not isinstance(plugins, list):
        raise ValueError("plugins must be a list")
    for plugin in plugins:
        if not isinstance(plugin, dict):
            raise ValueError("plugin entries must be YAML objects")
    return plugins


def string_value(value, field, required=False):
    if value is None:
        if required:
            raise ValueError(f"{field} is required")
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    return value


def object_value(value, field):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be a YAML object")
    return value


def plugin_source(plugin):
    return string_value(plugin.get("source"), "plugin.source") or "builtin"


def plugin_name(plugin):
    return string_value(plugin.get("name"), "plugin.name", required=True)


def builtin_manifest(name):
    return load_yaml(BUILTIN_PLUGIN_DIR / name / "plugin.yaml")


def nested_command(value):
    data = object_value(value, "doctor")
    return string_value(data.get("command"), "doctor.command")


def plugin_doctor_command(plugin):
    override = nested_command(plugin.get("doctor"))
    if override:
        return override

    source = plugin_source(plugin)
    name = plugin_name(plugin)
    if source == "builtin":
        return nested_command(builtin_manifest(name).get("doctor"))
    if source == "custom":
        return None
    raise ValueError(f"unsupported plugin.source: {source}")


def write_plugin_config(name, config):
    config_dir = state_dir() / "plugins" / name
    config_dir.mkdir(parents=True, exist_ok=True)
    path = config_dir / "config.yaml"
    with path.open("w", encoding="utf-8") as file:
        yaml.safe_dump(config, file, sort_keys=False)
    return path


def run_plugin_doctor(plugin):
    name = plugin_name(plugin)
    try:
        command = plugin_doctor_command(plugin)
    except (OSError, yaml.YAMLError, ValueError) as error:
        return [fail(f"plugin.{name}", str(error))]

    if not command:
        return [skip(f"plugin.{name}", "no doctor command")]

    config = object_value(plugin.get("config"), "plugin.config")
    plugin_config = write_plugin_config(name, config)
    env = os.environ.copy()
    env["NVT_PLUGIN_NAME"] = name
    env["NVT_PLUGIN_CONFIG"] = str(plugin_config)

    result = subprocess.run(command, shell=True, env=env, text=True, capture_output=True, check=False)
    output = "\n".join(part for part in [result.stdout.strip(), result.stderr.strip()] if part)
    if result.returncode == 0:
        return [ok(f"plugin.{name}", output or "doctor command succeeded")]
    return [fail(f"plugin.{name}", output or f"doctor command exited with {result.returncode}")]


def plugin_checks(selected_plugin=None):
    try:
        _path, config = load_agent_config()
        plugins = plugin_entries(config)
    except (OSError, yaml.YAMLError, ValueError) as error:
        return [fail("plugins", str(error))]

    checks = []
    found = False
    for plugin in plugins:
        name = plugin_name(plugin)
        if selected_plugin and name != selected_plugin:
            continue
        found = True
        checks.extend(run_plugin_doctor(plugin))

    if selected_plugin and not found:
        checks.append(fail(f"plugin.{selected_plugin}", "plugin is not configured"))

    return checks


def print_text(checks):
    print("nvt-agent doctor")
    for item in checks:
        print(f"{item['status']:<5} {item['name']:<28} {item['message']}")


def has_failures(checks):
    return any(item["status"] == "fail" for item in checks)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", action="store_true", help="run only core diagnostics")
    parser.add_argument("--plugins", action="store_true", help="run only plugin diagnostics")
    parser.add_argument("--plugin", help="run diagnostics for one plugin")
    parser.add_argument("--json", action="store_true", help="print JSON")
    args = parser.parse_args()

    if args.core and (args.plugins or args.plugin):
        parser.error("--core cannot be combined with --plugins or --plugin")
    if args.plugins and args.plugin:
        parser.error("--plugins cannot be combined with --plugin")

    checks = []
    if args.core:
        checks.extend(core_checks())
    elif args.plugins:
        checks.extend(plugin_checks())
    elif args.plugin:
        checks.extend(plugin_checks(args.plugin))
    else:
        checks.extend(core_checks())
        checks.extend(plugin_checks())

    if args.json:
        print(json.dumps({"checks": checks, "ok": not has_failures(checks)}, indent=2))
    else:
        print_text(checks)

    return 1 if has_failures(checks) else 0


if __name__ == "__main__":
    raise SystemExit(main())
