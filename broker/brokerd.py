#!/usr/bin/env python3
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broker.core.config import BrokerConfigError
from broker.core.server import serve


def main():
    bind = os.environ.get("NVT_BROKER_BIND", "127.0.0.1:7347")
    try:
        serve(bind)
    except BrokerConfigError as error:
        print(f"brokerd: {error}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
