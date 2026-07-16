#!/usr/bin/env python3
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, "/usr/local/lib/nvt-agent")

from shared.plugin_egress import PluginEgressError, environment


def main():
    if len(sys.argv) < 3 or sys.argv[1] != "--provider":
        raise SystemExit("plugin-egress-exec: usage: plugin-egress-exec --provider NAME COMMAND [ARG ...]")
    plugin = {"egress": {"provider": sys.argv[2]}}
    try:
        env = environment(plugin)
    except PluginEgressError as error:
        raise SystemExit(f"plugin-egress-exec: {error}")
    if len(sys.argv) < 4:
        raise SystemExit("plugin-egress-exec: command is required")
    os.execvpe(sys.argv[3], sys.argv[3:], env)


if __name__ == "__main__":
    main()
