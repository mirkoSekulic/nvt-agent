#!/usr/bin/env python3
import argparse
import json
import sys


def positive_int(value):
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be greater than or equal to 0")
    return parsed


def parse_args():
    parser = argparse.ArgumentParser(description="Render a no-GitHub smoke AgentSchedule admission payload.")
    parser.add_argument("--run-name", required=True)
    parser.add_argument("--work-id", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--active-deadline-seconds", type=positive_int, required=True)
    parser.add_argument("--completed-ttl-seconds", type=positive_int, required=True)
    parser.add_argument("--smoke-delay-seconds", type=positive_int, required=True)
    return parser.parse_args()


def payload(args):
    return {
        "work": {
            "id": args.work_id,
            "title": args.run_name,
        },
        "agentRun": {
            "apiVersion": "nvt.dev/v1alpha1",
            "kind": "AgentRun",
            "metadata": {
                "name": args.run_name,
            },
            "spec": {
                "runtime": {
                    "type": "codex",
                    "autonomy": "trusted-local",
                },
                "image": "nvt-agent-runtime:latest",
                "workspace": {
                    "mode": "Ephemeral",
                },
                "broker": {
                    "grants": [],
                },
                "agent": {
                    "config": {
                        "plugins": [
                            {
                                "name": "event-webhook",
                                "source": "builtin",
                                "when": "after-agent",
                                "restart": "always",
                                "config": {
                                    "url": (
                                        "http://nvt-operator:8082/v1/agentruns/"
                                        f"{args.namespace}/{args.run_name}/events"
                                    ),
                                    "auth": {
                                        "type": "bearer-env",
                                        "env": "NVT_OPERATOR_CALLBACK_TOKEN",
                                    },
                                    "filters": ["plugin.smoke."],
                                    "delivery": {
                                        "retry": {
                                            "backoff-seconds": 1,
                                        },
                                    },
                                },
                            },
                            {
                                "name": "smoke-complete",
                                "source": "builtin",
                                "when": "after-agent",
                                "restart": "never",
                                "config": {
                                    "delaySeconds": args.smoke_delay_seconds,
                                    "event": "plugin.smoke.completed",
                                    "payload": {
                                        "ok": True,
                                    },
                                },
                            },
                        ],
                    },
                },
                "lifecycle": {
                    "completeOn": ["plugin.smoke.completed"],
                    "failOn": [],
                },
                "ttl": {
                    "activeDeadlineSeconds": args.active_deadline_seconds,
                    "completedTTLSeconds": args.completed_ttl_seconds,
                },
            },
        },
    }


def main():
    rendered = payload(parse_args())
    json.dump(rendered, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
