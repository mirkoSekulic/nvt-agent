#!/bin/sh
set -eu

managed="${1:-}"
shift || true

range() {
  output="$(ipcalc -n -b "$1" 2>/dev/null)" || return 1
  network="$(printf '%s\n' "$output" | awk -F= '$1 == "NETWORK" {print $2}')"
  broadcast="$(printf '%s\n' "$output" | awk -F= '$1 == "BROADCAST" {print $2}')"
  [ -n "$network" ] && [ -n "$broadcast" ] || return 1
  printf '%s %s\n' "$network" "$broadcast"
}

ipnum() {
  awk -F. '{ if (NF != 4) exit 1; print ($1 * 16777216) + ($2 * 65536) + ($3 * 256) + $4 }' <<EOF
$1
EOF
}

managed_range="$(range "$managed")" || { echo "invalid managed Docker CIDR" >&2; exit 1; }
set -- $managed_range
managed_first="$(ipnum "$1")" || { echo "invalid managed Docker CIDR" >&2; exit 1; }
managed_last="$(ipnum "$2")" || { echo "invalid managed Docker CIDR" >&2; exit 1; }

for protected in ${NVT_DIND_PROTECTED_CIDRS:-}; do
  protected_range="$(range "$protected")" || { echo "invalid protected CIDR" >&2; exit 1; }
  set -- $protected_range
  protected_first="$(ipnum "$1")" || { echo "invalid protected CIDR" >&2; exit 1; }
  protected_last="$(ipnum "$2")" || { echo "invalid protected CIDR" >&2; exit 1; }
  if [ "$managed_first" -le "$protected_last" ] && [ "$protected_first" -le "$managed_last" ]; then
    echo "managed Docker CIDR overlaps a protected CIDR" >&2
    exit 1
  fi
done
