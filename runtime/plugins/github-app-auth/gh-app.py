#!/usr/bin/env python3
import os
import subprocess
import sys

from github_app_auth import installation_token, load_config, normalize_repo, resolve_provider


def fail(message):
    raise SystemExit(f"gh-app: {message}")


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


def main():
    provider_name, gh_args = split_args(sys.argv[1:])
    if not gh_args or gh_args in (["-h"], ["--help"]):
        print("usage: gh-app [--provider NAME] <gh args...>")
        return

    config = load_config()
    repo = repo_from_args(gh_args)
    provider = resolve_provider(config, provider_name, repo)

    if gh_args == ["auth", "status"]:
        print(f"gh-app provider: {provider['name']}")
        if repo:
            print(f"matched repo: {repo}")
        installation_id = provider.get("installation-id")
        if not installation_id and isinstance(provider.get("installation-id-env"), str):
            installation_id = os.environ.get(provider["installation-id-env"], "")
        print(f"installation id: {installation_id}")
        return

    env = os.environ.copy()
    env["GH_TOKEN"] = installation_token(provider)
    env.pop("GITHUB_TOKEN", None)
    os.execvpe("gh", ["gh", *gh_args], env)


if __name__ == "__main__":
    main()
