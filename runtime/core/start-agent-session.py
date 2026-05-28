#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path


def fail(message):
    raise SystemExit(f"start-agent-session: {message}")


def load_command(path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing command file: {path}")
    except json.JSONDecodeError as error:
        fail(f"invalid command file: {error}")

    if not isinstance(data, dict):
        fail("command file must contain an object")
    command = data.get("command")
    args = data.get("args", [])
    if not isinstance(command, str) or not command:
        fail("command must be a non-empty string")
    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        fail("args must be a list of strings")
    return command, args


def main():
    if len(sys.argv) != 2:
        fail("usage: start-agent-session <command-file>")
    command, args = load_command(Path(sys.argv[1]))
    os.execvp(command, [command, *args])


if __name__ == "__main__":
    main()
