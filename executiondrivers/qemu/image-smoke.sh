#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${NVT_QEMU_DRIVER_IMAGE:-nvt-qemu-execution-driver:test}"
WORKDIR="$(mktemp -d "${ROOT}/.qemu-image-smoke.XXXXXX")"
cleanup() {
  docker run --rm --user 0:0 --entrypoint sh \
    -v "${WORKDIR}:/var/lib/nvt-execution-driver" "${IMAGE}" \
    -c 'rm -rf /var/lib/nvt-execution-driver/executions' >/dev/null 2>&1 || true
  chmod -R u+rwX "${WORKDIR}" >/dev/null 2>&1 || true
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT
chmod 0777 "${WORKDIR}"

[[ "$(docker image inspect "${IMAGE}" --format '{{.Config.User}}')" == "65532:65532" ]] || {
  echo "QEMU image does not run as its fixed non-root identity" >&2
  exit 1
}
[[ "$(docker image inspect "${IMAGE}" --format '{{json .Config.Entrypoint}}')" == '["/usr/local/bin/nvt-qemu-driver"]' ]] || {
  echo "QEMU image entrypoint is invalid" >&2
  exit 1
}

guest_digest="$(docker run --rm --entrypoint cat "${IMAGE}" /opt/nvt-qemu/guest/digest | tr -d '\n')"
[[ "${guest_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
  echo "QEMU image guest digest is invalid" >&2
  exit 1
}
actual_digest="$({
  docker run --rm --entrypoint sh "${IMAGE}" -c '
    for artifact in /opt/nvt-qemu/guest/vmlinuz /opt/nvt-qemu/guest/initramfs /opt/nvt-qemu/guest/root.qcow2; do
      printf "%s:" "$(stat -c %s "${artifact}")"
      cat "${artifact}"
    done
  '
} | python3 -c 'import hashlib,sys; print("sha256:" + hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')"
[[ "${actual_digest}" == "${guest_digest}" ]] || {
  echo "QEMU image guest artifacts do not match their checksum" >&2
  exit 1
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj /CN=qemu-image-smoke \
  -keyout "${WORKDIR}/ca.key" -out "${WORKDIR}/ca.crt" >/dev/null 2>&1

python3 - "${guest_digest}" "${WORKDIR}/ca.crt" >"${WORKDIR}/requests.jsonl" <<'PY'
import json
import sys

ca = open(sys.argv[2], encoding="utf-8").read()
configuration = {
    "contract_version": "nvt.qemu-driver/v1",
    "guest_image": {"digest": sys.argv[1]},
    "host_bundle": {
        "repository": "https://registry.example/nvt/host-bundle",
        "digest": "sha256:" + "b" * 64,
    },
    "enrollment_ca_pem": ca,
    "native_session_endpoint": "tls://gateway.example:7443",
    "native_session_ca_pem": ca,
    "cpus": 1,
    "memory_mib": 512,
    "acceleration": "tcg",
    "boot_timeout_seconds": 30,
}
desired = {
    "execution_id": "nvt-agentrun-" + "a" * 64,
    "generation": 1,
    "desired_fingerprint": "sha256:" + "c" * 64,
    "workload_kind": "vm",
    "class_name": "qemu-smoke",
    "configuration": configuration,
}
requests = [
    {"jsonrpc": "2.0", "id": "initialize", "method": "initialize", "params": {"protocol_version": "nvt.execution-driver/v1", "driver_instance_name": "qemu-reference"}},
    {"jsonrpc": "2.0", "id": "reconcile", "method": "reconcile", "params": {"desired": desired}},
    {"jsonrpc": "2.0", "id": "shutdown", "method": "shutdown", "params": {}},
]
for request in requests:
    print(json.dumps(request, separators=(",", ":")))
PY

docker run --rm -i \
  -e NVT_EXECUTION_DRIVER_STATE_DIR=/var/lib/nvt-execution-driver \
  -v "${WORKDIR}:/var/lib/nvt-execution-driver" \
  "${IMAGE}" <"${WORKDIR}/requests.jsonl" >"${WORKDIR}/responses.jsonl"

# The production state tree is intentionally private to UID 65532. Inspect it
# through an explicit root test container instead of weakening its modes for
# the unrelated host runner identity.
state_count="$(docker run --rm --user 0:0 --entrypoint sh \
  -v "${WORKDIR}:/var/lib/nvt-execution-driver" "${IMAGE}" \
  -c 'find /var/lib/nvt-execution-driver/executions -mindepth 2 -maxdepth 2 -name state.json -type f | wc -l')"
[[ "${state_count}" == "1" ]] || {
  echo "QEMU built-image smoke produced an unexpected durable-state count" >&2
  exit 1
}
docker run --rm --user 0:0 --entrypoint sh \
  -v "${WORKDIR}:/var/lib/nvt-execution-driver" "${IMAGE}" \
  -c 'state="$(find /var/lib/nvt-execution-driver/executions -mindepth 2 -maxdepth 2 -name state.json -type f)"; cat "${state}"; test -f "$(dirname "${state}")/guest.qcow2"; test ! -e "$(dirname "${state}")/control.sock"' \
  >"${WORKDIR}/inspected-state.json"

python3 - "${WORKDIR}" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
responses = [json.loads(line) for line in (root / "responses.jsonl").read_text().splitlines() if line]
assert len(responses) == 3
assert responses[0]["result"]["protocol_version"] == "nvt.execution-driver/v1"
assert responses[1]["result"]["phase"] == "provisioning"
assert responses[1]["result"]["ready"] is False
assert responses[2]["result"] == {}

state = json.loads((root / "inspected-state.json").read_text())
assert set(state) == {
    "version", "execution_id", "generation", "desired_fingerprint",
    "class_name", "configuration", "attempt", "guest_instance_id",
    "enrollment_accepted", "host_port",
}
encoded = json.dumps(state, sort_keys=True).lower()
for forbidden in ("runtime_identity", "enrollment_token", "bootstrap_envelope", '"token"', '"opaque"'):
    assert forbidden not in encoded
PY

echo "QEMU built-image TCG guest smoke passed"
