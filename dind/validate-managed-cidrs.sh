#!/bin/sh
set -eu

exec python3 - "${1:-}" ${NVT_DIND_PROTECTED_CIDRS:-} <<'PY'
import ipaddress
import sys

try:
    managed = ipaddress.ip_network(sys.argv[1], strict=False)
except (ValueError, IndexError):
    raise SystemExit("invalid managed Docker CIDR")
if managed.version != 4:
    raise SystemExit("managed Docker CIDR must be IPv4")

for raw in sys.argv[2:]:
    try:
        protected = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        raise SystemExit("invalid protected CIDR")
    if protected.version == 4 and managed.overlaps(protected):
        raise SystemExit("managed Docker CIDR overlaps a protected CIDR")
PY
