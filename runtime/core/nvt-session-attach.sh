#!/usr/bin/env bash
set -euo pipefail

session="${AGENT_SESSION:-agent}"
wait_seconds="${NVT_SESSION_ATTACH_WAIT_SECONDS:-60}"
state_dir="${NVT_STATE_DIR:-${HOME}/.nvt-agent}"
lease_dir="${state_dir}/session-attachment-lease"
lease_lock="${state_dir}/session-attachment-lease.lock"
claim_seconds="${NVT_SESSION_ATTACH_CLAIM_SECONDS:-10}"
boot_id="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || printf 'unknown')"

if ! [[ "${claim_seconds}" =~ ^[0-9]+$ ]] || [ "${claim_seconds}" -lt 1 ] || [ "${claim_seconds}" -gt 60 ]; then
  echo "nvt-session-attach: NVT_SESSION_ATTACH_CLAIM_SECONDS must be an integer from 1 to 60" >&2
  exit 2
fi

mkdir -p "${state_dir}"

process_start() {
  [ -r "/proc/$1/stat" ] || return 1
  awk '{print $22}' "/proc/$1/stat" 2>/dev/null
}

lease_is_live() {
  [ -f "${lease_dir}/state" ] || return 1
  lease_state="$(cat "${lease_dir}/state" 2>/dev/null || true)"
  if [ "${lease_state}" = claimed ]; then
    expires="$(cat "${lease_dir}/expires" 2>/dev/null || true)"
    [ "${expires}" -gt "$(date +%s)" ] 2>/dev/null
    return
  fi
  [ "${lease_state}" = attached ] || return 1
  owner_pid="$(cat "${lease_dir}/pid" 2>/dev/null || true)"
  owner_start="$(cat "${lease_dir}/start" 2>/dev/null || true)"
  owner_boot="$(cat "${lease_dir}/boot" 2>/dev/null || true)"
  [ "${owner_boot}" = "${boot_id}" ] && [ -n "${owner_pid}" ] && [ "$(process_start "${owner_pid}" || true)" = "${owner_start}" ]
}

claim() {
  exec 9>"${lease_lock}"
  flock 9
  if lease_is_live; then
    exit 3
  fi
  rm -rf "${lease_dir}"
  mkdir -m 0700 "${lease_dir}"
  token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  printf '%s\n' "${token}" > "${lease_dir}/token"
  printf '%s\n' claimed > "${lease_dir}/state"
  printf '%s\n' "$(( $(date +%s) + claim_seconds ))" > "${lease_dir}/expires"
  printf '%s\n' "${token}"
}

adopt() {
  token="$1"
  exec 9>"${lease_lock}"
  flock 9
  [ "$(cat "${lease_dir}/token" 2>/dev/null || true)" = "${token}" ] || {
    echo "nvt-session-attach: attachment claim is missing or stale" >&2
    exit 3
  }
  printf '%s\n' "$$" > "${lease_dir}/pid"
  process_start "$$" > "${lease_dir}/start"
  printf '%s\n' "${boot_id}" > "${lease_dir}/boot"
  printf '%s\n' attached > "${lease_dir}/state"
  flock -u 9
  trap 'if [ "$(cat "${lease_dir}/token" 2>/dev/null || true)" = "${token}" ]; then rm -rf "${lease_dir}"; fi' EXIT
}

case "${1:-}" in
  --claim)
    claim
    exit 0
    ;;
  --attach)
    [ "$#" -eq 2 ] || { echo "usage: nvt-session-attach --attach CLAIM" >&2; exit 2; }
    adopt "$2"
    ;;
  "")
    token="$("$0" --claim)" || exit $?
    adopt "${token}"
    ;;
  *)
    echo "usage: nvt-session-attach [--claim | --attach CLAIM]" >&2
    exit 2
    ;;
esac

if ! command -v tmux >/dev/null 2>&1; then
  echo "nvt-session-attach: tmux session backend is not installed" >&2
  exit 127
fi

if ! [[ "${wait_seconds}" =~ ^[0-9]+$ ]] || [ "${wait_seconds}" -lt 1 ] || [ "${wait_seconds}" -gt 300 ]; then
  echo "nvt-session-attach: NVT_SESSION_ATTACH_WAIT_SECONDS must be an integer from 1 to 300" >&2
  exit 2
fi

deadline=$((SECONDS + wait_seconds))
while ! tmux has-session -t "${session}" 2>/dev/null; do
  if [ "${SECONDS}" -ge "${deadline}" ]; then
    echo "nvt-session-attach: agent session ${session} was not available within ${wait_seconds}s" >&2
    exit 1
  fi
  sleep 1
done

tmux attach-session -t "${session}"
