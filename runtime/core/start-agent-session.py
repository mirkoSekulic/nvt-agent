#!/usr/bin/env python3
import json
import os
import re
import sys
from pathlib import Path


ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def fail(message):
    raise SystemExit(f"start-agent-session: {message}")


def load_command(path, launch_mode="fresh"):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing command file: {path}")
    except json.JSONDecodeError as error:
        fail(f"invalid command file: {error}")

    if not isinstance(data, dict):
        fail("command file must contain an object")
    has_environment = "env" in data
    environment = data.get("env")
    if has_environment:
        if not isinstance(environment, dict):
            fail("env must be an object")
        for name, value in environment.items():
            if not isinstance(name, str) or not ENV_NAME_RE.fullmatch(name):
                fail(f"env contains invalid environment variable name {name!r}")
            if not isinstance(value, str):
                fail(f"env.{name} must be a string")
    if launch_mode == "fresh":
        config = data
    elif launch_mode == "resume":
        config = data.get("resume")
        if not isinstance(config, dict):
            fail("resume command is not configured")
    else:
        fail(f"launch mode must be fresh or resume, got {launch_mode!r}")
    command = config.get("command")
    args = config.get("args", [])
    if not isinstance(command, str) or not command:
        fail("command must be a non-empty string")
    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        fail("args must be a list of strings")
    return command, args, environment


def main():
    if len(sys.argv) not in {2, 3}:
        fail("usage: start-agent-session <command-file> [fresh|resume]")
    launch_mode = sys.argv[2] if len(sys.argv) == 3 else "fresh"
    command, args, environment = load_command(Path(sys.argv[1]), launch_mode)
    if environment is None:
        os.execvp(command, [command, *args])
    child_environment = os.environ.copy()
    child_environment.update(environment)
    os.execvpe(command, [command, *args], child_environment)


if __name__ == "__main__":
    main()
