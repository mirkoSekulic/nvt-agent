#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
from urllib.parse import quote, urlsplit, urlunsplit

from git_host_credentials import credential_kind, load_config, normalize_repo, resolve_provider, token

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


def remove_no_proxy_hosts(value, blocked):
    kept = []
    blocked = {item.lower() for item in blocked}
    for part in value.split(","):
        item = part.strip()
        if not item:
            continue
        lowered = item.lower()
        if lowered == "*":
            continue
        bare = lowered[1:] if lowered.startswith(".") else lowered
        if lowered in blocked or bare in blocked:
            continue
        kept.append(item)
    return ",".join(kept)


def proxy_url_for_provider(proxy_url, provider_name):
    parts = urlsplit(proxy_url)
    if not parts.scheme or not parts.hostname:
        fail(f"NVT_EGRESS_FORWARD_PROXY_URL is not a valid proxy URL: {proxy_url!r}")
    host = parts.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host
    if parts.port is not None:
        netloc = f"{netloc}:{parts.port}"
    # The username is a non-secret capability selector; the password is a fixed
    # dummy value so clients reliably send Proxy-Authorization on CONNECT.
    # egressd consumes it and never forwards it upstream. This lets one agent
    # use multiple GitHub App providers for the same github.com/api.github.com
    # hosts without host-based guessing.
    netloc = f"{quote(provider_name, safe='')}:x@{netloc}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def mediated_env(provider, repo):
    proxy_url = os.environ.get("NVT_EGRESS_FORWARD_PROXY_URL")
    if not proxy_url:
        fail(f"provider {provider['name']} is mediated but NVT_EGRESS_FORWARD_PROXY_URL is not set")
    proxy_url = proxy_url_for_provider(proxy_url, provider["broker-provider"])
    placeholder = os.environ.get("NVT_EGRESS_PLACEHOLDER") or PLACEHOLDER
    env = os.environ.copy()
    env["GH_TOKEN"] = placeholder
    for key in ("GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"):
        env.pop(key, None)
    env["HTTPS_PROXY"] = proxy_url
    env["HTTP_PROXY"] = proxy_url
    env["ALL_PROXY"] = proxy_url
    env["https_proxy"] = proxy_url
    env["http_proxy"] = proxy_url
    env["all_proxy"] = proxy_url
    # gh reaches both api.github.com and github.com. Remove those from broad
    # NO_PROXY lists so egressd can inject the credential instead of the CLI
    # bypassing mediation with the inert placeholder.
    host = None
    normalized = normalize_repo(repo) if repo else None
    if normalized and "/" in normalized:
        host = normalized.split("/", 1)[0]
    blocked = {"github.com", "api.github.com"}
    if host:
        blocked.add(host)
    for key in ("NO_PROXY", "no_proxy"):
        env[key] = remove_no_proxy_hosts(env.get(key, ""), blocked)
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
