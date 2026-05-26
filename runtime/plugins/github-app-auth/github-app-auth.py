#!/usr/bin/env python3
import argparse

from github_app_auth import installation_token, load_config, providers, resolve_provider, validate_provider


def command_token(args):
    provider = resolve_provider(load_config(), args.provider, args.repo)
    print(installation_token(provider))


def command_resolve(args):
    provider = resolve_provider(load_config(), args.provider, args.repo)
    print(provider["name"])


def command_doctor(args):
    config = load_config()
    selected = [resolve_provider(config, args.provider, args.repo)] if args.provider or args.repo else providers(config)
    if not selected:
        raise SystemExit("github-app-auth: no providers configured")
    for provider in selected:
        validate_provider(provider)
    print(f"github-app-auth: {len(selected)} provider(s) look valid")


def main():
    parser = argparse.ArgumentParser(prog="github-app-auth")
    subparsers = parser.add_subparsers(dest="command", required=True)

    token = subparsers.add_parser("token")
    token.add_argument("--provider")
    token.add_argument("--repo")
    token.set_defaults(func=command_token)

    resolve = subparsers.add_parser("resolve")
    resolve.add_argument("--provider")
    resolve.add_argument("--repo")
    resolve.set_defaults(func=command_resolve)

    doctor = subparsers.add_parser("doctor")
    doctor.add_argument("--provider")
    doctor.add_argument("--repo")
    doctor.set_defaults(func=command_doctor)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
