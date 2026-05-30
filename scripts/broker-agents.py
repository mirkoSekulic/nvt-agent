#!/usr/bin/env python3
import argparse
import copy
import fcntl
import hashlib
import os
from pathlib import Path

import yaml


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def load(path):
    try:
        with path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file)
    except FileNotFoundError:
        data = {"agents": []}
    except yaml.YAMLError as exc:
        raise SystemExit(f"{path} must be valid YAML: {exc}")
    if not isinstance(data, dict) or not isinstance(data.get("agents"), list):
        raise SystemExit(f"{path} must be YAML with an agents list")
    return data


def write_atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f".{os.getpid()}.tmp")
    with tmp.open("w", encoding="utf-8") as file:
        yaml.dump(data, file, Dumper=NoAliasDumper, sort_keys=False)
    tmp.replace(path)


def token_hash(token):
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


def update_agent(data, name, token):
    wanted_hash = token_hash(token)
    agents = [agent for agent in data["agents"] if isinstance(agent, dict) and agent.get("id") != name]
    current = next((agent for agent in data["agents"] if isinstance(agent, dict) and agent.get("id") == name), None)
    grants = current.get("grants", []) if isinstance(current, dict) and isinstance(current.get("grants"), list) else []
    agents.append({"id": name, "token-sha256": wanted_hash, "grants": grants})
    data["agents"] = sorted(agents, key=lambda agent: agent["id"])


def copy_register_agent(data, from_name, to_name, token, copy_grants):
    wanted_hash = token_hash(token)
    source = next((agent for agent in data["agents"] if isinstance(agent, dict) and agent.get("id") == from_name), None)
    if source is None:
        raise SystemExit(f"agent {from_name} is not registered; run agent-init first")
    if copy_grants:
        grants = source.get("grants", [])
    else:
        grants = []
    agents = [agent for agent in data["agents"] if isinstance(agent, dict) and agent.get("id") != to_name]
    agents.append({"id": to_name, "token-sha256": wanted_hash, "grants": copy.deepcopy(grants)})
    data["agents"] = sorted(agents, key=lambda agent: agent["id"])


def add_grant(data, name, provider, repo):
    for agent in data["agents"]:
        if isinstance(agent, dict) and agent.get("id") == name:
            grants = agent.setdefault("grants", [])
            for grant in grants:
                if isinstance(grant, dict) and grant.get("provider") == provider:
                    repositories = grant.setdefault("repositories", [])
                    if repo not in repositories:
                        repositories.append(repo)
                        repositories.sort()
                    return
            grants.append({"provider": provider, "repositories": [repo]})
            grants.sort(key=lambda grant: grant["provider"])
            return
    raise SystemExit(f"agent {name} is not registered; run agent-init first")


def unregister_agent(data, name):
    data["agents"] = [agent for agent in data["agents"] if not (isinstance(agent, dict) and agent.get("id") == name)]


def with_lock(path, func):
    lock_path = path.with_suffix(".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        data = load(path)
        func(data)
        write_atomic(path, data)


def main():
    parser = argparse.ArgumentParser(prog="broker-agents.py")
    parser.add_argument("--agents-file", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)

    register = subparsers.add_parser("register")
    register.add_argument("--name", required=True)
    register.add_argument("--token", required=True)

    copy_register = subparsers.add_parser("copy-register")
    copy_register.add_argument("--from-name", required=True)
    copy_register.add_argument("--name", required=True)
    copy_register.add_argument("--token", required=True)
    copy_register.add_argument("--copy-grants", action=argparse.BooleanOptionalAction, default=True)

    grant = subparsers.add_parser("grant")
    grant.add_argument("--name", required=True)
    grant.add_argument("--provider", required=True)
    grant.add_argument("--repo", required=True)

    unregister = subparsers.add_parser("unregister")
    unregister.add_argument("--name", required=True)

    args = parser.parse_args()
    path = Path(args.agents_file)
    if args.command == "register":
        with_lock(path, lambda data: update_agent(data, args.name, args.token))
    elif args.command == "copy-register":
        with_lock(path, lambda data: copy_register_agent(data, args.from_name, args.name, args.token, args.copy_grants))
    elif args.command == "grant":
        with_lock(path, lambda data: add_grant(data, args.name, args.provider, args.repo))
    elif args.command == "unregister":
        with_lock(path, lambda data: unregister_agent(data, args.name))


if __name__ == "__main__":
    main()
