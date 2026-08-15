#!/usr/bin/env python3
import subprocess
import sys

SOURCE = "plugin:work-control"
EVENTS = {
    "complete": "plugin.work.completed",
    "fail": "plugin.work.failed",
}


def main(argv):
    if len(argv) != 1 or argv[0] not in EVENTS:
        print("usage: nvt-work {complete|fail}", file=sys.stderr)
        return 2
    try:
        result = subprocess.run(
            ["agentdctl", "publish", EVENTS[argv[0]], "--source", SOURCE],
            check=False,
        )
    except FileNotFoundError:
        print("nvt-work: agentdctl not found on PATH", file=sys.stderr)
        return 1
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
