#!/usr/bin/env python3
import argparse
import json
import os
import socket
import sys


def socket_path():
    return os.environ.get("NVT_AGENTD_SOCKET", "/run/nvt-agent/agentd.sock")


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
        if args.payload.startswith("@"):
            with open(args.payload[1:], "r", encoding="utf-8") as file:
                payload = json.load(file)
        else:
            payload = json.loads(args.payload)
        return request({
            "type": "event.publish",
            "source": args.source,
            "event": args.event,
            "payload": payload,
        })

    if args.command == "status":
        return request({"type": "status"})

    if args.command == "health":
        return request({"type": "health"})

    parser.error(f"unsupported command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
