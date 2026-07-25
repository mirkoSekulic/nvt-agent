#!/bin/sh
set -eu

sysctl_root="${NVT_BRIDGE_SYSCTL_ROOT:-/proc/sys/net/bridge}"

disable_bridge_hook() {
  name="$1"
  path="${sysctl_root}/${name}"
  [ -e "${path}" ] || return 0

  if ! value="$(cat "${path}")"; then
    echo "nvt-dind-netfilter: could not read ${name}" >&2
    exit 1
  fi
  [ "${value}" = "0" ] && return 0

  if ! printf '0\n' >"${path}"; then
    echo "nvt-dind-netfilter: could not disable ${name}" >&2
    exit 1
  fi
  if ! value="$(cat "${path}")"; then
    echo "nvt-dind-netfilter: could not read back ${name}" >&2
    exit 1
  fi
  if [ "${value}" != "0" ]; then
    echo "nvt-dind-netfilter: ${name} read back as ${value}, expected 0" >&2
    exit 1
  fi
}

disable_bridge_hook bridge-nf-call-iptables
disable_bridge_hook bridge-nf-call-ip6tables
