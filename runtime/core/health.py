#!/usr/bin/env python3
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import yaml


def state_dir():
    return Path(os.environ.get("NVT_STATE_DIR", str(Path.home() / ".nvt-agent")))


def load_yaml(path):
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    if not isinstance(data, dict):
        raise SystemExit(f"health: {path} must be a YAML object")
    return data


def load_plugins(config_path):
    plugins = load_yaml(config_path).get("plugins", [])
    if plugins is None:
        return []
    if not isinstance(plugins, list):
        raise SystemExit("health: plugins must be a list")
    return plugins


def plugin_name(plugin):
    value = plugin.get("name")
    if not isinstance(value, str) or not value:
        raise SystemExit("health: plugin.name is required")
    return value


def plugin_health(plugin):
    health = plugin.get("health") or {}
    if not isinstance(health, dict):
        raise SystemExit(f"health: plugin {plugin_name(plugin)} health must be a YAML object")
    readiness = health.get("readiness", False)
    if not isinstance(readiness, bool):
        raise SystemExit(f"health: plugin {plugin_name(plugin)} health.readiness must be a boolean")
    command = health.get("command")
    if command is not None and not isinstance(command, str):
        raise SystemExit(f"health: plugin {plugin_name(plugin)} health.command must be a string")
    return readiness, command


def read_json(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def tmux_session_ready(session):
    result = subprocess.run(
        ["tmux", "has-session", "-t", session],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def tcp_ready(host, port):
    try:
        with socket.create_connection((host, port), timeout=0.25):
            return True
    except OSError:
        return False


def agentd_ready():
    socket_path = os.environ.get("NVT_AGENTD_SOCKET", "/run/nvt-agent/agentd.sock")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(0.25)
            client.connect(socket_path)
            client.sendall(b'{"type":"health"}\n')
            response = client.recv(4096)
        data = json.loads(response.decode("utf-8"))
        return bool(data.get("ok"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return False


def run_plugin_health_command(name, command):
    config_path = state_dir() / "plugins" / name / "config.yaml"
    env = os.environ.copy()
    env["NVT_PLUGIN_NAME"] = name
    env["NVT_PLUGIN_CONFIG"] = str(config_path)
    result = subprocess.run(
        command,
        shell=True,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def plugin_ready_from_state(state):
    return bool(state.get("ready", False))


def readiness_plugin_result(plugin):
    name = plugin_name(plugin)
    _readiness, command = plugin_health(plugin)
    state_path = state_dir() / "plugins" / name / "state.json"
    if not state_path.is_file():
        return {
            "ready": False,
            "status": "missing",
            "reason": f"missing plugin state: {state_path}",
        }

    try:
        state = read_json(state_path)
    except (OSError, json.JSONDecodeError) as error:
        return {
            "ready": False,
            "status": "unknown",
            "reason": f"failed to read plugin state: {error}",
        }

    if command:
        ready = run_plugin_health_command(name, command)
        return {
            "ready": ready,
            "status": state.get("status", "unknown"),
            "check": "command",
            "command": command,
            "reason": None if ready else "health command failed",
        }

    ready = plugin_ready_from_state(state)
    return {
        "ready": ready,
        "status": state.get("status", "unknown"),
        "check": "state",
        "reason": None if ready else state.get("last_error") or "plugin is not ready",
    }


def build_result(config_path):
    session = os.environ.get("AGENT_SESSION", "agent")
    code_server_port = int(os.environ.get("CODE_SERVER_PORT", "4090"))

    services = {
        "agent-session": {
            "ready": tmux_session_ready(session),
            "session": session,
        },
        "code-server": {
            "ready": tcp_ready("127.0.0.1", code_server_port),
            "port": code_server_port,
        },
        "agentd": {
            "ready": agentd_ready(),
            "socket": os.environ.get("NVT_AGENTD_SOCKET", "/run/nvt-agent/agentd.sock"),
        },
    }

    plugins = {}
    for plugin in load_plugins(config_path):
        if not isinstance(plugin, dict):
            raise SystemExit("health: plugin entries must be YAML objects")
        readiness, _command = plugin_health(plugin)
        if readiness:
            plugins[plugin_name(plugin)] = readiness_plugin_result(plugin)

    ready = all(service["ready"] for service in services.values()) and all(
        plugin["ready"] for plugin in plugins.values()
    )
    return {
        "ready": ready,
        "services": services,
        "plugins": plugins,
    }


def main():
    json_output = len(sys.argv) > 1 and sys.argv[1] == "--json"
    config_path = Path(os.environ.get("NVT_AGENT_CONFIG_FILE", "/nvt-agent/agent.yaml"))
    result = build_result(config_path)

    if json_output:
        print(json.dumps(result, indent=2))
    else:
        print("ready" if result["ready"] else "not-ready")

    return 0 if result["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
