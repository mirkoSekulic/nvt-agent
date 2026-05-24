#!/usr/bin/env python3
import argparse
import json
import os
import socket
import sys
import time
from pathlib import Path


def socket_path():
    return os.environ.get("NVT_AGENTD_SOCKET", "/run/nvt-agent/agentd.sock")


def state_dir():
    return Path(os.environ.get("NVT_STATE_DIR", str(Path.home() / ".nvt-agent")))


def events_path():
    return state_dir() / "agentd" / "events.jsonl"


def request(payload):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(socket_path())
            client.sendall(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
            response = b""
            while not response.endswith(b"\n"):
                chunk = client.recv(65536)
                if not chunk:
                    break
                response += chunk
    except OSError as error:
        print(json.dumps({"ok": False, "error": f"could not connect to agentd: {error}"}, separators=(",", ":")))
        return 1
    if not response:
        raise SystemExit("agentdctl: empty response from agentd")
    data = json.loads(response.decode("utf-8"))
    print(json.dumps(data, separators=(",", ":")))
    return 0 if data.get("ok") else 1


def read_message(args):
    if args.message:
        return " ".join(args.message)
    if sys.stdin.isatty():
        raise SystemExit("agentdctl: expected prompt argument or stdin")
    return sys.stdin.read()


def load_payload(value):
    if value.startswith("@"):
        with open(value[1:], "r", encoding="utf-8") as file:
            return json.load(file)
    return json.loads(value)


def effective_event_name(event):
    if event.get("event") == "plugin.event":
        value = event.get("plugin_event")
        if isinstance(value, str):
            return value
    value = event.get("event")
    if isinstance(value, str):
        return value
    return ""


def event_matches(event, filters):
    if not filters:
        return True
    name = effective_event_name(event)
    return any(name.startswith(prefix) for prefix in filters)


def subscribe(args):
    path = events_path()
    position = None

    try:
        while True:
            if position is None:
                try:
                    file = path.open("r", encoding="utf-8")
                except FileNotFoundError:
                    time.sleep(0.05)
                    continue
                with file:
                    if args.since == "end":
                        file.seek(0, os.SEEK_END)
                    while True:
                        line = file.readline()
                        if not line:
                            position = file.tell()
                            break
                        emit_event_line(line, args.filter)
                continue

            try:
                with path.open("r", encoding="utf-8") as file:
                    file.seek(position)
                    while True:
                        line = file.readline()
                        if not line:
                            position = file.tell()
                            break
                        emit_event_line(line, args.filter)
            except FileNotFoundError:
                position = None

            time.sleep(0.05)
    except (KeyboardInterrupt, BrokenPipeError):
        return 0


def emit_event_line(line, filters):
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return
    if not isinstance(event, dict) or not event_matches(event, filters):
        return
    print(json.dumps(event, separators=(",", ":")), flush=True)


def main():
    parser = argparse.ArgumentParser(prog="agentdctl")
    subparsers = parser.add_subparsers(dest="command", required=True)

    prompt = subparsers.add_parser("prompt")
    prompt.add_argument("--source", default=os.environ.get("NVT_PROMPT_SOURCE", "host"))
    prompt.add_argument("--external", action=argparse.BooleanOptionalAction, default=True)
    prompt.add_argument("message", nargs="*")

    publish = subparsers.add_parser("publish")
    publish.add_argument("event")
    publish.add_argument("--source", required=True)
    publish.add_argument("--payload", default="{}")

    signal_parser = subparsers.add_parser("signal")
    signal_parser.add_argument("name")
    signal_parser.add_argument("--source", default="agent")
    signal_parser.add_argument("--message")
    signal_parser.add_argument("--payload", default="{}")

    subscribe_parser = subparsers.add_parser("subscribe")
    subscribe_parser.add_argument("--since", choices=["end", "beginning"], default="end")
    subscribe_parser.add_argument("--filter", action="append", default=[])

    subparsers.add_parser("status")
    subparsers.add_parser("health")

    args = parser.parse_args()

    if args.command == "prompt":
        return request({
            "type": "prompt",
            "source": args.source,
            "external": args.external,
            "message": read_message(args),
        })

    if args.command == "publish":
        payload = load_payload(args.payload)
        return request({
            "type": "event.publish",
            "source": args.source,
            "event": args.event,
            "payload": payload,
        })

    if args.command == "signal":
        if not args.name.strip():
            parser.error("signal name must not be empty")
        payload = load_payload(args.payload)
        if args.message is not None:
            payload["message"] = args.message
        return request({
            "type": "event.publish",
            "source": args.source,
            "event": f"plugin.agent.signal.{args.name}",
            "payload": payload,
        })

    if args.command == "subscribe":
        return subscribe(args)

    if args.command == "status":
        return request({"type": "status"})

    if args.command == "health":
        return request({"type": "health"})

    parser.error(f"unsupported command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
