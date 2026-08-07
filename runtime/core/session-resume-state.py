#!/usr/bin/env python3
import json
import os
import sys
import tempfile
from pathlib import Path


MARKER_VERSION = 1
RESUMABLE = "resumable"


def fail(message):
    raise SystemExit(f"session-resume-state: {message}")


def load_document(path, description):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing {description}: {path}")
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"invalid {description}: {error}")


def has_resume(command_path):
    document = load_document(command_path, "command file")
    if not isinstance(document, dict):
        fail("command file must contain an object")
    if "resume" not in document:
        return False
    resume = document.get("resume")
    if not isinstance(resume, dict):
        fail("resume command must contain an object")
    command = resume.get("command")
    args = resume.get("args", [])
    if not isinstance(command, str) or not command.strip():
        fail("resume command must be a non-empty string")
    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        fail("resume args must be a list of strings")
    return True


def load_marker(path):
    document = load_document(path, "resume marker")
    if not isinstance(document, dict) or set(document) != {"version", "state"}:
        fail("resume marker must contain exactly version and state")
    if document.get("version") != MARKER_VERSION:
        fail("unsupported resume marker version")
    state = document.get("state")
    if state != RESUMABLE:
        fail("unsupported resume marker state")
    return state


def durable_replace(path, state):
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {"version": MARKER_VERSION, "state": state},
        separators=(",", ":"),
        sort_keys=True,
    ) + "\n"
    fd, temporary = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_fd = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def prepare(command_path, marker_path):
    if not has_resume(command_path):
        print("legacy")
        return
    if not marker_path.exists():
        print("fresh")
        return
    load_marker(marker_path)
    print("resume")


def mark_established(command_path, marker_path, launch_mode):
    if not has_resume(command_path):
        if launch_mode != "legacy":
            fail(f"unexpected launch mode without runtime.resume: {launch_mode!r}")
        return
    if launch_mode == "fresh":
        if marker_path.exists():
            load_marker(marker_path)
            fail("fresh launch cannot establish resumable state over an existing marker")
        durable_replace(marker_path, RESUMABLE)
        return
    if launch_mode == "resume":
        load_marker(marker_path)
        return
    fail(f"unexpected launch mode with runtime.resume: {launch_mode!r}")


def main():
    if len(sys.argv) < 3:
        fail("usage: session-resume-state configured|prepare|established COMMAND_FILE [MARKER_FILE] [LAUNCH_MODE]")
    action = sys.argv[1]
    command_path = Path(sys.argv[2])
    if action == "configured" and len(sys.argv) == 3:
        raise SystemExit(0 if has_resume(command_path) else 1)
    if len(sys.argv) < 4:
        fail("usage: session-resume-state configured|prepare|established COMMAND_FILE [MARKER_FILE] [LAUNCH_MODE]")
    marker_path = Path(sys.argv[3])
    if action == "prepare" and len(sys.argv) == 4:
        # Missing is the only valid empty-state representation. Do not infer
        # resumability from any tool-specific file in NVT_STATE_DIR.
        prepare(command_path, marker_path)
        return
    if action == "established" and len(sys.argv) == 5:
        mark_established(command_path, marker_path, sys.argv[4])
        return
    fail("usage: session-resume-state configured|prepare|established COMMAND_FILE [MARKER_FILE] [LAUNCH_MODE]")


if __name__ == "__main__":
    main()
