#!/usr/bin/env python3
import argparse
import sys

from github_watcher_lib import (
    FileLock,
    fail,
    load_config,
    normalize_watch,
    read_json,
    registry_path,
    watch_key,
    write_json,
)


def ask(prompt, default=None):
    suffix = f" [{default}]" if default not in {None, ""} else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or default


def ask_bool(prompt, default):
    label = "Y/n" if default else "y/N"
    value = input(f"{prompt} [{label}]: ").strip().lower()
    if not value:
        return default
    return value in {"y", "yes", "true", "1"}


def config_from_args(args):
    config = load_config()
    default_provider = config.get("default-provider")
    if args.interactive:
        repo = ask("Repository owner/name", args.repo)
        number = int(ask("PR number", str(args.number or "")))
        provider = ask("Provider", args.provider or default_provider)
        labels = args.label or []
        while ask_bool("Add label?", False):
            labels.append(ask("Label"))
        comments = ask_bool("Watch comments?", args.comments)
        reviews = ask_bool("Watch reviews?", args.reviews)
        checks = ask_bool("Watch aggregate checks?", args.checks)
        prompt_comments = ask_bool("Prompt on comments?", args.prompt_comments)
        prompt_reviews = ask_bool("Prompt on reviews?", args.prompt_reviews)
        prompt_failed_checks = ask_bool("Prompt on failed checks?", args.prompt_failed_checks)
    else:
        repo = args.repo
        number = args.number
        provider = args.provider
        labels = args.label or []
        comments = args.comments
        reviews = args.reviews
        checks = args.checks
        prompt_comments = args.prompt_comments
        prompt_reviews = args.prompt_reviews
        prompt_failed_checks = args.prompt_failed_checks

    raw = {
        "repo": repo,
        "number": number,
        "provider": provider,
        "labels": labels,
        "publish": {"enabled": args.publish},
        "comments": {
            "enabled": comments,
            "author-associations": args.author_association,
            "prompt": {"enabled": prompt_comments},
        },
        "reviews": {
            "enabled": reviews,
            "author-associations": args.author_association,
            "prompt": {"enabled": prompt_reviews},
        },
        "checks": {
            "enabled": checks,
            "mode": "aggregate",
            "publish-failed-transition": args.publish_failed_checks,
            "publish-passed-transition": args.publish_passed_checks,
            "prompt": {
                "failed": prompt_failed_checks,
                "passed": args.prompt_passed_checks,
            },
        },
    }
    defaults = {
        "default-provider": default_provider,
        "broker": config.get("broker"),
    }
    normalized = normalize_watch(raw, defaults, "register")
    return normalized


def command_register(args):
    watch = config_from_args(args)
    with FileLock(registry_path().with_suffix(".lock")):
        data = read_json(registry_path(), {"prs": []})
        prs = data.get("prs", [])
        if not isinstance(prs, list):
            fail("registry pr list is invalid")
        key = watch_key(watch)
        prs = [item for item in prs if not isinstance(item, dict) or watch_key(normalize_watch(item, {"default-provider": watch["provider"]}, "registry")) != key]
        prs.append(watch)
        write_json(registry_path(), {"prs": prs})
    print(f"github-watch: registered {watch['repo']}#{watch['number']}")


def command_list(_args):
    data = read_json(registry_path(), {"prs": []})
    for raw in data.get("prs", []):
        try:
            watch = normalize_watch(raw, {"default-provider": raw.get("provider")}, "registry")
        except SystemExit as error:
            print(error, file=sys.stderr)
            continue
        labels = ",".join(watch.get("labels", [])) or "-"
        print(f"{watch['repo']}#{watch['number']} provider={watch['provider']} labels={labels}")


def command_remove(args):
    repo = args.repo.strip().removesuffix(".git")
    number = args.number
    with FileLock(registry_path().with_suffix(".lock")):
        data = read_json(registry_path(), {"prs": []})
        prs = []
        removed = False
        for raw in data.get("prs", []):
            watch = normalize_watch(raw, {"default-provider": raw.get("provider")}, "registry")
            if watch["repo"] == repo and watch["number"] == number:
                removed = True
                continue
            prs.append(raw)
        write_json(registry_path(), {"prs": prs})
    if removed:
        print(f"github-watch: removed {repo}#{number}")
    else:
        print(f"github-watch: {repo}#{number} was not registered")


def main():
    parser = argparse.ArgumentParser(prog="github-watch")
    subparsers = parser.add_subparsers(dest="command", required=True)

    register = subparsers.add_parser("register")
    register.add_argument("--repo")
    register.add_argument("--number", "--pr", type=int)
    register.add_argument("--provider")
    register.add_argument("--label", action="append", default=[])
    register.add_argument("--author-association", action="append", default=["OWNER", "MEMBER", "COLLABORATOR"])
    register.add_argument("--interactive", action="store_true")
    register.add_argument("--publish", action=argparse.BooleanOptionalAction, default=True)
    register.add_argument("--comments", action=argparse.BooleanOptionalAction, default=True)
    register.add_argument("--reviews", action=argparse.BooleanOptionalAction, default=True)
    register.add_argument("--checks", action=argparse.BooleanOptionalAction, default=True)
    register.add_argument("--prompt-comments", action=argparse.BooleanOptionalAction, default=True)
    register.add_argument("--prompt-reviews", action=argparse.BooleanOptionalAction, default=True)
    register.add_argument("--prompt-failed-checks", action=argparse.BooleanOptionalAction, default=True)
    register.add_argument("--prompt-passed-checks", action=argparse.BooleanOptionalAction, default=False)
    register.add_argument("--publish-failed-checks", action=argparse.BooleanOptionalAction, default=True)
    register.add_argument("--publish-passed-checks", action=argparse.BooleanOptionalAction, default=False)
    register.set_defaults(func=command_register)

    list_parser = subparsers.add_parser("list")
    list_parser.set_defaults(func=command_list)

    remove = subparsers.add_parser("remove")
    remove.add_argument("--repo", required=True)
    remove.add_argument("--number", "--pr", required=True, type=int)
    remove.set_defaults(func=command_remove)

    args = parser.parse_args()
    if args.command == "register" and not args.interactive:
        if not args.repo:
            parser.error("register requires --repo unless --interactive is used")
        if not args.number:
            parser.error("register requires --number unless --interactive is used")
    args.func(args)


if __name__ == "__main__":
    main()
