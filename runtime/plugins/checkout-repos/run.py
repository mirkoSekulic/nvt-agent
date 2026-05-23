#!/usr/bin/env python3
import os
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import yaml


def fail(message):
    raise SystemExit(f"checkout-repos: {message}")


def run(command):
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True)


def string_value(value, field, required=False):
    if value is None:
        if required:
            fail(f"{field} is required")
        return None
    if not isinstance(value, str):
        fail(f"{field} must be a string")
    return value


def list_value(value, field):
    if value is None:
        return []
    if not isinstance(value, list):
        fail(f"{field} must be a list")
    return value


def load_config():
    path = Path(os.environ.get("NVT_PLUGIN_CONFIG", ""))
    if not path.is_file():
        fail("NVT_PLUGIN_CONFIG must point to a config file")
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    if not isinstance(data, dict):
        fail("config must be a YAML object")
    return data


def default_repo_path(url):
    parsed = urlparse(url)
    name = Path(parsed.path).name
    if name.endswith(".git"):
        name = name[:-4]
    if not name:
        fail(f"cannot derive repo path from URL: {url}")
    return name


def workspace_path(repo):
    url = string_value(repo.get("url"), "repo.url", required=True)
    path = string_value(repo.get("path"), "repo.path") or default_repo_path(url)
    target = Path(path)
    if target.is_absolute():
        return target
    return Path(os.environ.get("NVT_WORKSPACE", "/workspace")) / target


def checkout_repo(repo):
    if not isinstance(repo, dict):
        fail("repos entries must be YAML objects")

    url = string_value(repo.get("url"), "repo.url", required=True)
    upstream = string_value(repo.get("upstream"), "repo.upstream")

    target = workspace_path(repo)
    target.parent.mkdir(parents=True, exist_ok=True)

    if target.exists():
        if not (target / ".git").is_dir():
            fail(f"{target} already exists and is not a Git repository")
        print(f"checkout-repos: exists, skipping {target}", flush=True)
        return

    run(["git", "clone", url, str(target)])
    if upstream:
        run(["git", "-C", str(target), "remote", "add", "upstream", upstream])


def main():
    config = load_config()
    repos = list_value(config.get("repos"), "repos")
    if not repos:
        print("checkout-repos: no repos configured", flush=True)
        return

    for repo in repos:
        checkout_repo(repo)


if __name__ == "__main__":
    main()
