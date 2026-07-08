#!/usr/bin/env python3
"""agent-session: session-driver adapter.

A small abstraction over the terminal multiplexer that hosts the agent's
interactive runtime command. The selected driver (``zellij`` by default,
``tmux`` when explicitly configured) is resolved once here so session startup,
prompt delivery, and capture all agree on the same driver.

All zellij/tmux specifics live in this file. Nothing else in the runtime shells
out to a multiplexer directly; startup, prompt delivery, and capture go through
these subcommands instead. Keep the contract small:

    agent-session driver                        print the resolved driver
    agent-session exists   [--session S]        exit 0 if the session is live
    agent-session start    [--session S] --command-file F [--workdir D]
    agent-session send     [--session S] [--buffer B] [--file P]
    agent-session capture  [--session S] [--lines N]

The resolved driver comes, in order, from the ``NVT_SESSION_DRIVER`` environment
override, then the persisted ``session.json`` state, then the ``zellij``
default. Any invalid value fails loudly.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

VALID_DRIVERS = ("zellij", "tmux")
DEFAULT_DRIVER = "zellij"

# Kept in one place so agentd, capture, and startup all build the same wrapper.
# Overridable via NVT_START_EXEC_HELPER so tests can point it at a stub.
EXEC_HELPER = os.environ.get(
    "NVT_START_EXEC_HELPER", "/usr/local/bin/start-agent-session-exec"
)


def fail(message):
    raise SystemExit(f"agent-session: {message}")


def state_dir():
    value = os.environ.get("NVT_STATE_DIR")
    if value:
        return Path(value)
    return Path.home() / ".nvt-agent"


def session_state_path():
    return state_dir() / "session.json"


def validate_driver(driver, origin):
    if driver not in VALID_DRIVERS:
        fail(
            f"invalid session driver {driver!r} from {origin}; "
            f"expected one of {', '.join(VALID_DRIVERS)}"
        )
    return driver


def resolve_driver():
    override = os.environ.get("NVT_SESSION_DRIVER")
    if override:
        return validate_driver(override, "NVT_SESSION_DRIVER")

    path = session_state_path()
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            fail(f"invalid session state {path}: {error}")
        if not isinstance(data, dict):
            fail(f"session state {path} must contain an object")
        driver = data.get("driver", DEFAULT_DRIVER)
        if not isinstance(driver, str) or not driver:
            fail(f"session state {path} driver must be a non-empty string")
        return validate_driver(driver, str(path))

    return DEFAULT_DRIVER


def session_name(explicit):
    if explicit:
        return explicit
    return os.environ.get("AGENT_SESSION") or "agent"


def default_workdir(explicit):
    if explicit:
        return explicit
    return os.environ.get("NVT_WORKSPACE") or os.getcwd()


def run(argv, **kwargs):
    return subprocess.run(argv, **kwargs)


def kdl_quote(value):
    # KDL string literals are double-quoted with backslash escapes.
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def start_wrapper(command_file):
    # Structured args are preserved by start-agent-session-exec, which reads the
    # command file and execs the runtime command with its argv intact instead of
    # shell-joining. The wrapper only sources the runtime env first.
    quoted = command_file.replace("'", "'\\''")
    return (
        'source "$HOME/.nvt-agent/env"; '
        f"exec {EXEC_HELPER} '{quoted}'"
    )


# --- tmux driver -----------------------------------------------------------


def tmux_exists(session):
    result = run(
        ["tmux", "has-session", "-t", session],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def tmux_start(session, command_file, workdir):
    command = "bash -lc " + shell_single_quote(start_wrapper(command_file))
    run(
        ["tmux", "new-session", "-d", "-s", session, "-c", workdir, command],
        check=True,
    )


def tmux_send(session, buffer_name, path):
    run(["tmux", "load-buffer", "-b", buffer_name, str(path)], check=True)
    run(
        ["tmux", "paste-buffer", "-b", buffer_name, "-t", session, "-p", "-r"],
        check=True,
    )
    run(["tmux", "send-keys", "-t", session, "Enter"], check=True)


def tmux_capture(session, lines):
    run(
        ["tmux", "capture-pane", "-p", "-S", f"-{lines}", "-t", session],
        check=True,
    )


# --- zellij driver ---------------------------------------------------------


def zellij_exists(session):
    result = run(
        ["zellij", "list-sessions", "--no-formatting"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return False
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # A dead session is still listed as "<name> (EXITED - ...)"; treat it as
        # gone so startup relaunches it.
        if "EXITED" in stripped:
            continue
        if stripped.split()[0] == session:
            return True
    return False


def zellij_client_argv(session, layout_path):
    # A single client both creates and attaches the session.
    # --new-session-with-layout always starts a fresh session; the client is
    # kept alive headlessly by spawn_detached_pty so the session stays
    # renderable and injectable with no human attached.
    return [
        "zellij",
        "--session",
        session,
        "--new-session-with-layout",
        str(layout_path),
    ]


def spawn_detached_pty(argv):
    """Run ``argv`` in a fully detached daemon that owns a pseudo-terminal.

    Unlike tmux, zellij only renders panes and accepts injected keystrokes
    while a client is attached; ``attach --create-background`` leaves no client,
    so ``write-chars`` and ``dump-screen`` silently do nothing. Startup instead
    leaves a headless client attached for the session's lifetime: a daemon holds
    the PTY master (draining it so the client never blocks on a full buffer)
    while the client runs on the slave. The daemon is double-forked and
    ``setsid``-detached so it can never reacquire a controlling terminal and
    survives the caller exiting.
    """
    pid = os.fork()
    if pid > 0:
        os.waitpid(pid, 0)  # reap the intermediate child
        return
    try:
        os.setsid()
        if os.fork() > 0:
            os._exit(0)
        # Daemon: release the caller's stdio, then supervise the PTY client.
        devnull = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(devnull, fd)
        if devnull > 2:
            os.close(devnull)
        master, slave = os.openpty()
        client = os.fork()
        if client == 0:
            os.setsid()  # take the slave as the controlling terminal
            for fd in (0, 1, 2):
                os.dup2(slave, fd)
            if slave > 2:
                os.close(slave)
            os.close(master)
            try:
                os.execvp(argv[0], argv)
            finally:
                os._exit(127)
        os.close(slave)
        # Drain forever so the client never stalls on a full PTY buffer; EOF
        # (client/session gone) ends the daemon.
        while True:
            try:
                if not os.read(master, 65536):
                    break
            except OSError:
                break
    finally:
        os._exit(0)


def zellij_start(session, command_file, workdir):
    layout_path = state_dir() / f"session-{session}.kdl"
    layout_path.parent.mkdir(parents=True, exist_ok=True)
    wrapper = start_wrapper(command_file)
    layout = (
        "layout {\n"
        f'    cwd {kdl_quote(workdir)}\n'
        '    pane command="bash" {\n'
        f'        args "-lc" {kdl_quote(wrapper)}\n'
        "    }\n"
        "}\n"
    )
    layout_path.write_text(layout, encoding="utf-8")
    spawn_detached_pty(zellij_client_argv(session, layout_path))


def zellij_send(session, path):
    text = Path(path).read_text(encoding="utf-8")
    run(
        ["zellij", "--session", session, "action", "write-chars", "--", text],
        check=True,
    )
    # 13 = carriage return, i.e. submit the prompt.
    run(["zellij", "--session", session, "action", "write", "13"], check=True)


def zellij_capture(session, lines):
    with tempfile.NamedTemporaryFile("w", suffix=".dump", delete=False) as handle:
        dump_path = Path(handle.name)
    try:
        # zellij >= 0.44 takes the target as --path (the pre-0.44 positional
        # PATH form is rejected); without it the dump goes to stdout.
        run(
            ["zellij", "--session", session, "action", "dump-screen", "--full", "--path", str(dump_path)],
            check=True,
        )
        content = dump_path.read_text(encoding="utf-8").splitlines()
    finally:
        dump_path.unlink(missing_ok=True)
    tail = content[-lines:] if lines > 0 else content
    if tail:
        sys.stdout.write("\n".join(tail) + "\n")


# --- helpers ---------------------------------------------------------------


def shell_single_quote(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def driver_exists(driver, session):
    if driver == "tmux":
        return tmux_exists(session)
    return zellij_exists(session)


# --- subcommands -----------------------------------------------------------


def cmd_driver(_args):
    print(resolve_driver())
    return 0


def cmd_exists(args):
    driver = resolve_driver()
    return 0 if driver_exists(driver, session_name(args.session)) else 1


def cmd_start(args):
    driver = resolve_driver()
    session = session_name(args.session)
    workdir = default_workdir(args.workdir)
    command_file = args.command_file
    if not command_file:
        fail("start requires --command-file")
    if driver == "tmux":
        tmux_start(session, command_file, workdir)
    else:
        zellij_start(session, command_file, workdir)
    return 0


def cmd_send(args):
    driver = resolve_driver()
    session = session_name(args.session)
    if not driver_exists(driver, session):
        fail(f"{driver} session not found: {session}")

    cleanup = None
    if args.file:
        path = Path(args.file)
    else:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write(sys.stdin.read())
            path = Path(handle.name)
        cleanup = path

    try:
        if driver == "tmux":
            tmux_send(session, args.buffer, path)
        else:
            zellij_send(session, path)
    finally:
        if cleanup is not None:
            cleanup.unlink(missing_ok=True)
    return 0


def cmd_capture(args):
    driver = resolve_driver()
    session = session_name(args.session)
    lines = args.lines
    if lines < 1:
        fail("--lines must be a positive integer")
    if driver == "tmux":
        tmux_capture(session, lines)
    else:
        zellij_capture(session, lines)
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="agent-session")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("driver", help="print the resolved session driver")

    exists = sub.add_parser("exists", help="exit 0 if the session is live")
    exists.add_argument("-t", "--session")

    start = sub.add_parser("start", help="start the session running the runtime command")
    start.add_argument("-t", "--session")
    start.add_argument("--command-file", required=True)
    start.add_argument("--workdir")

    send = sub.add_parser("send", help="deliver a prompt to the session")
    send.add_argument("-t", "--session")
    send.add_argument("--buffer", default=os.environ.get("AGENT_PROMPT_BUFFER", "agent-prompt"))
    send.add_argument("--file")

    capture = sub.add_parser("capture", help="print recent session output")
    capture.add_argument("-t", "--session")
    capture.add_argument("-n", "--lines", type=int, default=100)

    return parser


HANDLERS = {
    "driver": cmd_driver,
    "exists": cmd_exists,
    "start": cmd_start,
    "send": cmd_send,
    "capture": cmd_capture,
}


def main(argv=None):
    args = build_parser().parse_args(argv)
    return HANDLERS[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
