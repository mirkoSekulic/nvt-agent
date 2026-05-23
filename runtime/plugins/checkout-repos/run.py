#!/usr/bin/env python3
import os
import subprocess
from pathlib import Path
from urllib.parse import quote, urlparse

import yaml


def fail(message):
    raise SystemExit(f"checkout-repos: {message}")


def run(command, **kwargs):
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True, **kwargs)


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


def merged_auth(repo, default_auth):
    if "auth" in repo:
        return object_value(repo.get("auth"), "repo.auth")
    return default_auth


def auth_type(auth):
    return string_value(auth.get("type"), "auth.type") or "none"


def token_auth(auth):
    token_env = string_value(auth.get("token_env"), "auth.token_env", required=True)
    token = os.environ.get(token_env)
    if token is None:
        fail(f"environment variable {token_env} is not set")
    username = string_value(auth.get("username"), "auth.username") or "x-access-token"
    return username, token


def credential_host_url(url):
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        fail(f"token_env auth requires an https URL: {url}")
    return f"{parsed.scheme}://{parsed.netloc}"


def credential_line(url, username, token):
    user = quote(username, safe="")
    password = quote(token, safe="")
    return f"{credential_host_url(url).replace('://', f'://{user}:{password}@')}\n"


def git_with_auth(args, url, auth):
    kind = auth_type(auth)
    if kind == "none":
        run(["git", *args])
        return

    if kind != "token_env":
        fail(f"unsupported auth.type: {kind}")

    username, token = token_auth(auth)
    env = os.environ.copy()
    env["NVT_GIT_USERNAME"] = username
    env["NVT_GIT_PASSWORD"] = token
    helper = "!f() { echo username=$NVT_GIT_USERNAME; echo password=$NVT_GIT_PASSWORD; }; f"
    run(["git", "-c", f"credential.helper={helper}", *args], env=env)


def configure_repo_credentials(target, url, auth):
    kind = auth_type(auth)
    if kind == "none":
        return

    if kind != "token_env":
        fail(f"unsupported auth.type: {kind}")

    username, token = token_auth(auth)
    credential_file = target / ".git" / "nvt-agent-credentials"
    credential_file.write_text(credential_line(url, username, token), encoding="utf-8")
    credential_file.chmod(0o600)
    run([
        "git",
        "-C",
        str(target),
        "config",
        "--local",
        "credential.helper",
        "store --file=.git/nvt-agent-credentials",
    ])


def configure_commit_identity(target, commit):
    name = string_value(commit.get("name"), "commit.name") or "nvt-agent[bot]"
    email = string_value(commit.get("email"), "commit.email") or "nvt-agent@localhost"
    run(["git", "-C", str(target), "config", "--local", "user.name", name])
    run(["git", "-C", str(target), "config", "--local", "user.email", email])


def checkout_repo(repo, default_auth, default_commit):
    if not isinstance(repo, dict):
        fail("repos entries must be YAML objects")

    url = string_value(repo.get("url"), "repo.url", required=True)
    auth = merged_auth(repo, default_auth)
    commit = object_value(repo.get("commit"), "repo.commit") or default_commit

    target = workspace_path(repo)
    target.parent.mkdir(parents=True, exist_ok=True)

    if target.exists():
        if not (target / ".git").is_dir():
            fail(f"{target} already exists and is not a Git repository")
        git_with_auth(["-C", str(target), "fetch", "--prune", "origin"], url, auth)
    else:
        git_with_auth(["clone", url, str(target)], url, auth)

    configure_repo_credentials(target, url, auth)
    configure_commit_identity(target, commit)


def main():
    config = load_config()
    default_auth = object_value(config.get("default_auth"), "default_auth")
    default_commit = object_value(config.get("commit"), "commit")
    repos = list_value(config.get("repos"), "repos")
    if not repos:
        print("checkout-repos: no repos configured", flush=True)
        return

    for repo in repos:
        checkout_repo(repo, default_auth, default_commit)


if __name__ == "__main__":
    main()
