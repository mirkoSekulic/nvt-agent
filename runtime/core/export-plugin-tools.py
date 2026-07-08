#!/usr/bin/env python3
import os
import json
import re
import shutil
import stat
import sys
from pathlib import Path

import yaml


BUILTIN_PLUGIN_DIR = Path("/usr/local/lib/nvt-agent/plugins")
MANAGED_MARKER = "# managed by nvt-agent export-plugin-tools"
TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
PROTECTED_NAMES = {
    "agent-capture",
    "agent-session",
    "agentd",
    "agentdctl",
    "bootstrap",
    "doctor",
    "entrypoint",
    "export-plugin-tools",
    "health",
    "prompt-agent",
    "run-plugins",
    "start-agent-session",
    "start-code-server",
    "write-agent-instructions",
}


def fail(message):
    raise SystemExit(f"export-plugin-tools: {message}")


def state_dir():
    return Path(os.environ.get("NVT_STATE_DIR", str(Path.home() / ".nvt-agent")))


def workspace():
    return Path(os.environ.get("NVT_WORKSPACE", "/workspace"))


def bin_dir():
    return Path.home() / ".local" / "bin"


def load_yaml(path):
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    if not isinstance(data, dict):
        fail(f"{path} must be a YAML object")
    return data


def load_plugins(path):
    plugins = load_yaml(path).get("plugins", [])
    if plugins is None:
        return []
    if not isinstance(plugins, list):
        fail("plugins must be a list")
    for plugin in plugins:
        if not isinstance(plugin, dict):
            fail("plugins entries must be YAML objects")
    return plugins


def string_value(value, field, required=False):
    if value is None:
        if required:
            fail(f"{field} is required")
        return None
    if not isinstance(value, str):
        fail(f"{field} must be a string")
    return value


def object_value(value, field):
    if value is None:
        return {}
    if not isinstance(value, dict):
        fail(f"{field} must be a YAML object")
    return value


def list_value(value, field):
    if value is None:
        return []
    if not isinstance(value, list):
        fail(f"{field} must be a list")
    return value


def plugin_name(plugin):
    return string_value(plugin.get("name"), "plugin.name", required=True)


def plugin_source(plugin):
    return string_value(plugin.get("source"), "plugin.source") or "builtin"


def builtin_manifest(name):
    return load_yaml(BUILTIN_PLUGIN_DIR / name / "plugin.yaml")


def plugin_manifest(plugin):
    source = plugin_source(plugin)
    name = plugin_name(plugin)
    if source == "builtin":
        return builtin_manifest(name)
    if source == "custom":
        return {}
    fail(f"unsupported plugin.source: {source}")


def plugin_exports(plugin):
    manifest = plugin_manifest(plugin)
    exports = object_value(manifest.get("exports"), f"plugin {plugin_name(plugin)} exports")
    override = object_value(plugin.get("exports"), "plugin.exports")
    tools = list_value(exports.get("tools"), f"plugin {plugin_name(plugin)} exports.tools")
    tools.extend(list_value(override.get("tools"), "plugin.exports.tools"))
    return tools


def plugin_config_path(name, config):
    config_dir = state_dir() / "plugins" / name
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "config.yaml"
    with config_path.open("w", encoding="utf-8") as file:
        yaml.safe_dump(config, file, sort_keys=False)
    return config_path


def validate_tool_name(name):
    if not name or not TOOL_NAME_RE.match(name):
        fail(f"exported tool name is invalid: {name!r}")
    if name in PROTECTED_NAMES:
        fail(f"exported tool name is protected: {name}")
    existing = shutil.which(name)
    if existing:
        fail(f"exported tool {name} would shadow existing command: {existing}")


def validate_command(command, tool_name):
    path = Path(command).expanduser()
    if not path.is_absolute():
        fail(f"exported tool {tool_name} command must be an absolute path")
    if not path.is_file():
        fail(f"exported tool {tool_name} command does not exist: {path}")
    if not os.access(path, os.X_OK):
        fail(f"exported tool {tool_name} command is not executable: {path}")
    return path


def managed_wrapper(path):
    try:
        with path.open("r", encoding="utf-8") as file:
            _shebang = file.readline()
            return file.readline().strip() == MANAGED_MARKER
    except OSError:
        return False


def clear_managed_wrappers():
    directory = bin_dir()
    directory.mkdir(parents=True, exist_ok=True)
    for path in directory.iterdir():
        if path.is_file() and managed_wrapper(path):
            path.unlink()


def shell_quote(value):
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def render_wrapper(tool_name, command, plugin_name_value, config_path):
    path = bin_dir() / tool_name
    content = "\n".join([
        "#!/usr/bin/env bash",
        MANAGED_MARKER,
        "set -euo pipefail",
        f"export NVT_PLUGIN_NAME={shell_quote(plugin_name_value)}",
        f"export NVT_PLUGIN_CONFIG={shell_quote(config_path)}",
        f"export NVT_WORKSPACE={shell_quote(workspace())}",
        f"exec {shell_quote(command)} \"$@\"",
        "",
    ])
    with path.open("w", encoding="utf-8") as file:
        file.write(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def export_tools(config_path):
    clear_managed_wrappers()
    seen = {}
    exported = []

    for plugin in load_plugins(config_path):
        name = plugin_name(plugin)
        config_path_for_plugin = plugin_config_path(name, object_value(plugin.get("config"), "plugin.config"))

        for index, tool in enumerate(plugin_exports(plugin)):
            if not isinstance(tool, dict):
                fail(f"plugin {name} exports.tools[{index}] must be a YAML object")
            tool_name = string_value(tool.get("name"), f"plugin {name} exports.tools[{index}].name", required=True)
            command = string_value(tool.get("command"), f"plugin {name} exports.tools[{index}].command", required=True)
            description = string_value(tool.get("description"), f"plugin {name} exports.tools[{index}].description")

            if tool_name in seen:
                fail(f"exported tool {tool_name} is defined by both {seen[tool_name]} and {name}")
            seen[tool_name] = name
            validate_tool_name(tool_name)
            command_path = validate_command(command, tool_name)
            render_wrapper(tool_name, command_path, name, config_path_for_plugin)
            exported.append({
                "name": tool_name,
                "plugin": name,
                "command": str(command_path),
                "description": description,
            })

    write_export_state(exported)
    if exported:
        print(f"export-plugin-tools: exported {len(exported)} tool(s)", flush=True)


def write_export_state(exported):
    path = state_dir() / "plugin-tools.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump({"tools": exported}, file, indent=2)
        file.write("\n")

    markdown_path = state_dir() / "plugin-tools.md"
    with markdown_path.open("w", encoding="utf-8") as file:
        if not exported:
            return
        file.write("\n## Exported Plugin Tools\n\n")
        file.write("These commands are exported by enabled plugins and are available on `PATH`.\n\n")
        for tool in exported:
            description = tool.get("description") or "No description provided."
            file.write(f"- `{tool['name']}` from plugin `{tool['plugin']}`: {description}\n")


def main():
    config_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/nvt-agent/agent.yaml")
    export_tools(config_path)


if __name__ == "__main__":
    main()
