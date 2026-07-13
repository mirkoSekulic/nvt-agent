import os
import re
from pathlib import Path

import yaml

from shared.git_source import GitSourceError, acquire, resolve_executable


class BrokerConfigError(Exception):
    pass


ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def fail(message):
    raise BrokerConfigError(message)


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


def injection_hosts(config, name):
    values = list_value(config.get("injection-hosts"), f"provider {name} config.injection-hosts")
    output = []
    for index, value in enumerate(values):
        if not isinstance(value, str) or not value:
            fail(f"provider {name} config.injection-hosts[{index}] must be a non-empty string")
        output.append(value)
    return output


def env_value(name):
    value = os.environ.get(name)
    if value is None:
        fail(f"environment variable {name} is not set")
    return value


def load_config(path=None):
    config_path = Path(path or os.environ.get("NVT_BROKER_CONFIG", ""))
    if not config_path.is_file():
        fail("NVT_BROKER_CONFIG must point to a broker config file")
    with config_path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    if not isinstance(data, dict):
        fail("broker config must be a YAML object")
    return data


def provider_entries(config, supported_plugins=None):
    entries = list_value(config.get("providers"), "providers")
    seen = set()
    output = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            fail(f"providers[{index}] must be a YAML object")
        name = string_value(entry.get("name"), f"providers[{index}].name", required=True)
        if name in seen:
            fail(f"duplicate provider name: {name}")
        seen.add(name)
        plugin = string_value(entry.get("plugin"), f"providers[{index}].plugin", required=True)
        if supported_plugins is not None and plugin not in supported_plugins:
            fail(f"unsupported providers[{index}].plugin: {plugin}")
        output.append(entry)
    return output


def provider_plugin_entries(config, builtin_plugins):
    entries = list_value(config.get("provider-plugins"), "provider-plugins")
    seen = set()
    output = {}
    for index, entry in enumerate(entries):
        field = f"provider-plugins[{index}]"
        if not isinstance(entry, dict):
            fail(f"{field} must be a YAML object")
        name = string_value(entry.get("name"), f"{field}.name", required=True)
        unknown = set(entry) - {"name", "source", "command", "pass-env", "initialize-timeout-seconds", "request-timeout-seconds"}
        if unknown:
            fail(f"{field} has unknown keys: {', '.join(sorted(unknown))}")
        if name in builtin_plugins:
            fail(f"external provider plugin name collides with built-in plugin: {name}")
        if name in seen:
            fail(f"duplicate provider plugin name: {name}")
        seen.add(name)

        command = list_value(entry.get("command"), f"{field}.command")
        if not command:
            fail(f"{field}.command must be a non-empty argument list")
        command = list(command)
        for argument_index, argument in enumerate(command):
            if not isinstance(argument, str) or not argument:
                fail(f"{field}.command[{argument_index}] must be a non-empty string")
        source = entry.get("source")
        try:
            if source is not None:
                root = acquire(source, os.environ.get("NVT_GIT_SOURCE_CACHE", "/state/git-sources"))
                executable = resolve_executable(root, command[0])
                command[0] = str(executable)
            else:
                executable = Path(command[0])
                if not executable.is_absolute():
                    fail(f"{field}.command[0] must be an absolute path")
                if not executable.is_file() or not os.access(executable, os.X_OK):
                    fail(f"{field}.command[0] must be an executable file")
        except GitSourceError as error:
            fail(f"{field}.source is invalid: {error}")

        pass_env = list_value(entry.get("pass-env"), f"{field}.pass-env")
        passed = []
        for env_index, env_name in enumerate(pass_env):
            if not isinstance(env_name, str) or not ENV_NAME_RE.fullmatch(env_name):
                fail(f"{field}.pass-env[{env_index}] must be an environment variable name")
            if env_name in passed:
                fail(f"{field}.pass-env contains duplicate name: {env_name}")
            if env_name not in os.environ:
                fail(f"environment variable {env_name} requested by {field}.pass-env is not set")
            passed.append(env_name)

        initialize_timeout = _positive_timeout(entry.get("initialize-timeout-seconds", 10), f"{field}.initialize-timeout-seconds")
        request_timeout = _positive_timeout(entry.get("request-timeout-seconds", 30), f"{field}.request-timeout-seconds")
        output[name] = {
            "name": name,
            "command": list(command),
            "pass_env": passed,
            "initialize_timeout": initialize_timeout,
            "request_timeout": request_timeout,
        }
    return output


def _positive_timeout(value, field):
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
        fail(f"{field} must be a positive number")
    return float(value)
