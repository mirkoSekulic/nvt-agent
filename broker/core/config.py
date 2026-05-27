import os
from pathlib import Path

import yaml


class BrokerConfigError(Exception):
    pass


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
