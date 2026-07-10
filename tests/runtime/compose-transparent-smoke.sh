#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROJECT="nvt-transparent-smoke-${RANDOM}"
export COMPOSE_PROVIDER_CANARY="fixture-${RANDOM}-${RANDOM}"
cleanup() {
  docker compose -p "${PROJECT}" -f "${ROOT}/tests/runtime/transparent-compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

make -C "${ROOT}" egressd-build captured-build
docker compose -p "${PROJECT}" -f "${ROOT}/tests/runtime/transparent-compose.yaml" up -d
tester_id="$(docker compose -p "${PROJECT}" -f "${ROOT}/tests/runtime/transparent-compose.yaml" ps -q tester)"

# Scan the untrusted tester's configured env/args and live filesystem/process
# view without placing the runtime canary in an exec argument or log.
inspect="$(docker inspect "${tester_id}")"
case "${inspect}" in *"${COMPOSE_PROVIDER_CANARY}"*) echo "compose canary found in tester config" >&2; exit 1 ;; esac
printf '%s\n' "${COMPOSE_PROVIDER_CANARY}" | docker exec -i "${tester_id}" sh -ec '
  IFS= read -r canary
  case "$(env)" in *"$canary"*) exit 1 ;; esac
  for file in /proc/[0-9]*/cmdline /proc/[0-9]*/environ; do
    [ -r "$file" ] || continue
    value="$(tr "\000" "\n" <"$file" 2>/dev/null || true)"
    case "$value" in *"$canary"*) exit 1 ;; esac
  done
  for file in $(find / -xdev -maxdepth 5 -type f -readable 2>/dev/null); do
    value="$(cat "$file" 2>/dev/null || true)"
    case "$value" in *"$canary"*) exit 1 ;; esac
  done
'
docker exec "${tester_id}" touch /tmp/scan-complete
status="$(docker wait "${tester_id}")"
docker logs "${tester_id}"
[[ "${status}" == "0" ]]

echo "Compose proves functional/best-effort transparent routing and provider-secret non-possession; it is not a CNI enforcement proof."
