#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
sys.path.insert(0, "/usr/local/lib/nvt-agent")
from shared.plugin_egress import PluginEgressError, environment as plugin_egress_environment

from git_host_credentials import (
    credential_kind,
    broker_provider_name,
    load_config,
    normalize_repo,
    resolve_provider,
    token,
)

PLACEHOLDER = "NVT-PLACEHOLDER-NOT-A-KEY"


def fail(message):
    raise SystemExit(f"gh-auth: {message}")


def split_args(argv):
    provider = None
    args = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--provider":
            if index + 1 >= len(argv):
                fail("--provider requires a value")
            provider = argv[index + 1]
            index += 2
            continue
        if arg.startswith("--provider="):
            provider = arg.split("=", 1)[1]
            index += 1
            continue
        args.append(arg)
        index += 1
    return provider, args


def repo_from_args(args):
    for index, arg in enumerate(args):
        if arg in {"--repo", "-R"} and index + 1 < len(args):
            return normalize_repo(args[index + 1])
        if arg.startswith("--repo="):
            return normalize_repo(arg.split("=", 1)[1])
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return normalize_repo(result.stdout.strip())
    except Exception:
        return None


def mediated_env(provider, repo):
    del repo
    try:
        env = plugin_egress_environment({"egress": {"provider": broker_provider_name(provider)}})
    except PluginEgressError as error:
        fail(str(error))
    placeholder = env.get("NVT_EGRESS_PLACEHOLDER") or PLACEHOLDER
    env["GH_TOKEN"] = placeholder
    for key in ("GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"):
        env.pop(key, None)
    return env


def main():
    provider_name, gh_args = split_args(sys.argv[1:])
    if not gh_args or gh_args in (["-h"], ["--help"]):
        print("usage: gh-auth [--provider NAME] <gh args...>")
        return

    if shutil.which("gh") is None:
        fail("gh not found on PATH")

    config = load_config()
    repo = repo_from_args(gh_args)
    provider = resolve_provider(config, provider_name, repo)

    if gh_args == ["auth", "status"]:
        print(f"gh-auth provider: {provider['name']}")
        print(f"provider type: {provider.get('type')}")
        if repo:
            print(f"matched repo: {repo}")
        if provider.get("type") == "github-app":
            installation_id = provider.get("installation-id")
            if not installation_id and isinstance(provider.get("installation-id-env"), str):
                installation_id = os.environ.get(provider["installation-id-env"], "")
            print(f"installation id: {installation_id}")
        return

    if credential_kind(provider) == "mediated":
        env = mediated_env(provider, repo)
    else:
        env = os.environ.copy()
        env["GH_TOKEN"] = token(provider, repo)
        env.pop("GITHUB_TOKEN", None)
    os.execvpe("gh", ["gh", *gh_args], env)


if __name__ == "__main__":
    main()
