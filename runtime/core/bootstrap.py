#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml


def run(command, **kwargs):
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True, **kwargs)


def as_string_list(value, field):
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SystemExit(f"tools.{field} must be a list of strings")
    return value


def optional_string(value, field):
    if value is None:
        return None
    if not isinstance(value, str):
        raise SystemExit(f"{field} must be a string")
    return value


def optional_bool(value, field, default=False):
    if value is None:
        return default
    if not isinstance(value, bool):
        raise SystemExit(f"{field} must be a boolean")
    return value


def optional_string_list(value, field):
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SystemExit(f"{field} must be a list of strings")
    return value


def load_bootstrap_config(path):
    if not path.is_file():
        print(f"bootstrap: no agent config at {path}", flush=True)
        return {}, {}, {}

    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    if not isinstance(data, dict):
        raise SystemExit("agent config must be a YAML object")

    runtime = data.get("runtime", {})
    if not isinstance(runtime, dict):
        raise SystemExit("runtime must be a YAML object")

    tools = data.get("tools", data)
    if not isinstance(tools, dict):
        raise SystemExit("tools must be a YAML object")

    code_server = data.get("code-server", {})
    if code_server is None:
        code_server = {}
    if not isinstance(code_server, dict):
        raise SystemExit("code-server must be a YAML object")

    return runtime, tools, code_server


def expand_path(value):
    home = os.environ.get("HOME", "")
    if value == "~":
        return home
    if value.startswith("~/"):
        return str(Path(home) / value[2:])
    return value.replace("${HOME}", home).replace("$HOME", home)


def prepend_path(path):
    current = os.environ.get("PATH", "")
    parts = [part for part in current.split(":") if part]
    if path in parts:
        return
    os.environ["PATH"] = ":".join([path, *parts])


def persist_env_var(name, value):
    env_path = Path.home() / ".nvt-agent" / "env"
    lines = []
    if env_path.is_file():
        lines = env_path.read_text(encoding="utf-8").splitlines()

    prefix = f"export {name}="
    replacement = f'export {name}="{value}"'
    replaced = False
    updated = []
    for line in lines:
        if line.startswith(prefix):
            if not replaced:
                updated.append(replacement)
                replaced = True
            continue
        updated.append(line)

    if not replaced:
        updated.append(replacement)

    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text("\n".join(updated) + "\n", encoding="utf-8")


def persist_agent_command(command, args):
    target = Path.home() / ".nvt-agent" / "agent-command.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"command": command, "args": args}, separators=(",", ":")) + "\n", encoding="utf-8")


def setup_tmux_config():
    target = Path.home() / ".tmux.conf"
    if target.exists():
        return
    target.write_text("set -g mouse on\n", encoding="utf-8")


def apply_additional_paths(paths):
    for path in reversed(paths):
        prepend_path(expand_path(path))
    persist_env_var("PATH", os.environ["PATH"])


def install_packages(packages):
    if not packages:
        return
    run(["apt-get", "update"])
    run(["apt-get", "install", "-y", "--no-install-recommends", *packages])


def configured_packages(tools):
    packages = tools.get("packages")
    apt_packages = tools.get("apt")

    if packages is not None and apt_packages is not None:
        raise SystemExit("use tools.packages instead of tools.apt, not both")
    if packages is not None:
        return as_string_list(packages, "packages")
    if apt_packages is not None:
        print("bootstrap: tools.apt is deprecated; use tools.packages", flush=True)
        return as_string_list(apt_packages, "apt")
    return []


def install_mise(packages):
    if not packages:
        return

    env = os.environ.copy()
    env["MISE_YES"] = "1"

    for package in packages:
        run(["mise", "use", "--global", package], env=env)


def run_shell(scripts):
    for index, script in enumerate(scripts, start=1):
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            prefix=f"nvt-bootstrap-{index}-",
            suffix=".sh",
            delete=False,
        ) as file:
            file.write("#!/usr/bin/env bash\n")
            file.write("set -e\n")
            file.write(script)
            file.write("\n")
            path = Path(file.name)

        try:
            run(["bash", str(path)])
        finally:
            path.unlink(missing_ok=True)


def workspace():
    return Path(os.environ.get("NVT_WORKSPACE", "/workspace"))


def resolve_workspace_path(path):
    value = expand_path(path)
    target = Path(value)
    if target.is_absolute():
        return target
    return workspace() / target


def install_code_server_extensions(extensions):
    for extension in extensions:
        run(["code-server", "--install-extension", extension])


def code_server_settings_target():
    return Path.home() / ".local" / "share" / "code-server" / "User" / "settings.json"


def copy_code_server_settings(settings_file):
    source = resolve_workspace_path(settings_file)
    if not source.is_file():
        return

    target = code_server_settings_target()
    if target.exists():
        print(f"bootstrap: code-server settings already exist, skipping {target}", flush=True)
        return

    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    print(f"bootstrap: copied code-server settings from {source}", flush=True)


def write_code_server_settings(values, overwrite):
    target = code_server_settings_target()
    if target.exists() and not overwrite:
        print(f"bootstrap: code-server settings already exist, skipping {target}", flush=True)
        return

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(values, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"bootstrap: wrote code-server settings to {target}", flush=True)


def apply_code_server_settings(config):
    settings_file = optional_string(config.get("settings-file"), "code-server.settings-file")
    settings = config.get("settings")

    if settings is None:
        if settings_file:
            print(
                "bootstrap: code-server.settings-file is deprecated; use code-server.settings.values",
                flush=True,
            )
            copy_code_server_settings(settings_file)
        return

    if not isinstance(settings, dict):
        raise SystemExit("code-server.settings must be a YAML object")

    has_values = "values" in settings
    if settings_file and has_values:
        raise SystemExit("code-server.settings-file is deprecated; use code-server.settings.values, not both")

    if not has_values:
        if settings_file:
            print(
                "bootstrap: code-server.settings-file is deprecated; use code-server.settings.values",
                flush=True,
            )
            copy_code_server_settings(settings_file)
        return

    values = settings.get("values")
    if not isinstance(values, dict):
        raise SystemExit("code-server.settings.values must be a YAML object")

    overwrite = optional_bool(settings.get("overwrite"), "code-server.settings.overwrite", False)
    write_code_server_settings(values, overwrite)


def setup_code_server(config):
    install_code_server_extensions(as_string_list(config.get("extensions"), "code-server.extensions"))
    apply_code_server_settings(config)


def main():
    config_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/nvt-agent/agent.yaml")
    runtime, tools, code_server = load_bootstrap_config(config_path)

    setup_tmux_config()
    command = optional_string(runtime.get("command"), "runtime.command")
    if command:
        # Kept for older helper scripts and diagnostics; start-agent-session uses
        # agent-command.json so runtime.args are passed without shell parsing.
        persist_env_var("AGENT_COMMAND", command)
        args = optional_string_list(runtime.get("args"), "runtime.args")
        persist_agent_command(command, args)
    setup_code_server(code_server)
    apply_additional_paths(as_string_list(tools.get("additional-paths"), "additional-paths"))
    install_packages(configured_packages(tools))
    install_mise(as_string_list(tools.get("mise"), "mise"))
    run_shell(as_string_list(tools.get("shell"), "shell"))


if __name__ == "__main__":
    main()
