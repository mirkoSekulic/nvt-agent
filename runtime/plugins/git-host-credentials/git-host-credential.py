#!/usr/bin/env python3
import argparse
import json

from git_host_credentials import headers, identity, load_config, providers, resolve_provider, token, validate_provider


def command_token(args):
    provider = resolve_provider(load_config(), args.provider, args.target)
    print(token(provider, args.target))


def command_headers(args):
    provider = resolve_provider(load_config(), args.provider, args.target)
    for header in headers(provider):
        print(header)


def command_identity(args):
    provider = resolve_provider(load_config(), args.provider, args.target)
    print(json.dumps(identity(provider, args.target), separators=(",", ":")))


def command_resolve(args):
    provider = resolve_provider(load_config(), args.provider, args.target)
    print(provider["name"])


def command_type(args):
    provider = resolve_provider(load_config(), args.provider, args.target)
    print(provider["type"])


def command_doctor(args):
    config = load_config()
    selected = [resolve_provider(config, args.provider, args.target)] if args.provider or args.target else providers(config)
    if not selected:
        raise SystemExit("git-host-credential: no providers configured")
    for provider in selected:
        validate_provider(provider)
    print(f"git-host-credential: {len(selected)} provider(s) look valid")


def main():
    parser = argparse.ArgumentParser(prog="git-host-credential")
    subparsers = parser.add_subparsers(dest="command", required=True)

    token_parser = subparsers.add_parser("token")
    token_parser.add_argument("--provider")
    token_parser.add_argument("--target")
    token_parser.set_defaults(func=command_token)

    headers_parser = subparsers.add_parser("headers")
    headers_parser.add_argument("--provider")
    headers_parser.add_argument("--target")
    headers_parser.set_defaults(func=command_headers)

    identity_parser = subparsers.add_parser("identity")
    identity_parser.add_argument("--provider")
    identity_parser.add_argument("--target")
    identity_parser.set_defaults(func=command_identity)

    resolve = subparsers.add_parser("resolve")
    resolve.add_argument("--provider")
    resolve.add_argument("--target")
    resolve.set_defaults(func=command_resolve)

    type_parser = subparsers.add_parser("type")
    type_parser.add_argument("--provider")
    type_parser.add_argument("--target")
    type_parser.set_defaults(func=command_type)

    doctor = subparsers.add_parser("doctor")
    doctor.add_argument("--provider")
    doctor.add_argument("--target")
    doctor.set_defaults(func=command_doctor)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
