#!/usr/bin/env python3
import argparse
import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def broker_url():
    return os.environ.get("NVT_BROKER_URL", "http://127.0.0.1:7347").rstrip("/")


def request_json(path, payload=None, method="POST"):
    url = broker_url() + path
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if path != "/health":
        token = os.environ.get("NVT_BROKER_TOKEN", "").strip()
        if not token:
            print("brokerctl: NVT_BROKER_TOKEN is not set", file=sys.stderr)
            raise SystemExit(2)
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, data=data, method=method, headers=headers)
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8")), response.status
    except HTTPError as error:
        try:
            return json.loads(error.read().decode("utf-8")), error.code
        except Exception:
            return {"ok": False, "error": "broker-http-error", "message": str(error)}, error.code
    except URLError as error:
        return {"ok": False, "error": "broker-unreachable", "message": str(error.reason)}, 1


def print_json(payload):
    print(json.dumps(payload, separators=(",", ":")))


def command_health(_args):
    payload, status = request_json("/health", method="GET")
    print_json(payload)
    return 0 if status == 200 and payload.get("ok") else 1


def parse_header(values):
    output = {}
    for value in values or []:
        if ":" not in value:
            raise SystemExit(f"brokerctl: invalid --header {value!r}; expected name:value")
        key, header_value = value.split(":", 1)
        output[key.strip()] = header_value.strip()
    return output


def command_http_request(args):
    payload = {
        "provider": args.provider,
        "method": args.method,
        "url": args.url,
        "headers": parse_header(args.header),
        "paginate": args.paginate,
    }
    response, _status = request_json("/v1/http/request", payload)
    print_json(response)
    return 0 if response.get("ok") else 1


def command_token(args):
    payload = {"provider": args.provider, "target": args.target, "purpose": args.purpose}
    response, _status = request_json("/v1/token", payload)
    if args.raw and response.get("ok"):
        print(response["token"])
    else:
        print_json(response)
    return 0 if response.get("ok") else 1


def command_identity(args):
    payload = {"provider": args.provider, "target": args.target}
    response, _status = request_json("/v1/identity", payload)
    print_json(response)
    return 0 if response.get("ok") else 1


def command_headers(args):
    payload = {"provider": args.provider, "target": args.target}
    response, _status = request_json("/v1/headers", payload)
    if args.raw and response.get("ok"):
        for header in response["headers"]:
            print(header)
    else:
        print_json(response)
    return 0 if response.get("ok") else 1


def main():
    parser = argparse.ArgumentParser(prog="brokerctl")
    subparsers = parser.add_subparsers(dest="command", required=True)

    health = subparsers.add_parser("health")
    health.set_defaults(func=command_health)

    http = subparsers.add_parser("http")
    http_sub = http.add_subparsers(dest="http_command", required=True)
    request = http_sub.add_parser("request")
    request.add_argument("--provider", required=True)
    request.add_argument("--method", required=True)
    request.add_argument("--url", required=True)
    request.add_argument("--header", action="append", default=[])
    request.add_argument("--paginate", action="store_true")
    request.set_defaults(func=command_http_request)

    token = subparsers.add_parser("token")
    token.add_argument("--provider", required=True)
    token.add_argument("--target", required=True)
    token.add_argument("--purpose")
    token.add_argument("--raw", action="store_true")
    token.set_defaults(func=command_token)

    identity = subparsers.add_parser("identity")
    identity.add_argument("--provider", required=True)
    identity.add_argument("--target", required=True)
    identity.set_defaults(func=command_identity)

    headers = subparsers.add_parser("headers")
    headers.add_argument("--provider", required=True)
    headers.add_argument("--target", required=True)
    headers.add_argument("--raw", action="store_true")
    headers.set_defaults(func=command_headers)

    args = parser.parse_args()
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
