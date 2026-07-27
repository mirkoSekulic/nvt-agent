#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HOST_IMAGE="${NVT_EXECUTION_DRIVER_HOST_IMAGE:-nvt-execution-driver-host:test}"
DRIVER_IMAGE="${NVT_EXECUTION_DRIVER_FIXTURE_IMAGE:-nvt-execution-driver-fixture:test}"
# The agent and its DinD sidecar share repository paths, while /tmp is local to
# the agent container. Keep bind sources below the checkout for both CI and the
# nvt development runtime.
WORKDIR="$(mktemp -d "${ROOT}/.execution-driver-host-smoke.XXXXXX")"
CONTAINER="nvt-driver-fixture-$$"

cleanup() {
  docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

docker build -f "${ROOT}/tests/fixtures/execution-driver/Dockerfile" -t "${DRIVER_IMAGE}" "${ROOT}" >/dev/null
mkdir -p "${WORKDIR}/host"
chmod 0777 "${WORKDIR}/host"
docker run --rm \
  -v "${WORKDIR}/host:/nvt-host" \
  "${HOST_IMAGE}" install --destination=/nvt-host/nvt-execution-driver-host

mkdir -p "${WORKDIR}/auth" "${WORKDIR}/state"
chmod 0777 "${WORKDIR}/state"
printf '%064d' 0 >"${WORKDIR}/auth/auth-token"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=nvt-driver.test \
  -addext subjectAltName=DNS:nvt-driver.test \
  -keyout "${WORKDIR}/auth/tls.key" \
  -out "${WORKDIR}/auth/tls.crt" >/dev/null 2>&1
chmod 0444 "${WORKDIR}/auth/"*

port="$(python3 - <<'PY'
import socket
with socket.socket() as value:
    value.bind(("127.0.0.1", 0))
    print(value.getsockname()[1])
PY
)"

docker run -d --name "${CONTAINER}" \
  --network host \
  -v "${WORKDIR}/host:/nvt-host:ro" \
  -v "${WORKDIR}/auth:/auth:ro" \
  -v "${WORKDIR}/state:/state" \
  -e NVT_FAKE_DRIVER_STATE_DIR=/state \
  -e NVT_FAKE_DRIVER_MODE=slow-initialize \
  --entrypoint /nvt-host/nvt-execution-driver-host \
  "${DRIVER_IMAGE}" \
  serve \
  --listen="127.0.0.1:${port}" \
  --driver-instance=fake-oci \
  --driver-command=/fake-driver \
  --pass-env=NVT_FAKE_DRIVER_STATE_DIR \
  --pass-env=NVT_FAKE_DRIVER_MODE \
  --tls-cert=/auth/tls.crt \
  --tls-key=/auth/tls.key \
  --auth-token=/auth/auth-token \
  --initialize-timeout=5s \
  --operation-timeout=5s >/dev/null

[[ "${port}" =~ ^[0-9]+$ ]]
if curl --silent --fail --noproxy '*' --connect-timeout 1 --max-time 1 \
  --cacert "${WORKDIR}/auth/tls.crt" \
  --resolve "nvt-driver.test:${port}:127.0.0.1" \
  "https://nvt-driver.test:${port}/readyz" >/dev/null 2>&1; then
  echo "execution driver host became ready before the slow initialization completed" >&2
  exit 1
fi
ready=0
for _ in $(seq 1 50); do
  if curl --silent --fail --noproxy '*' --cacert "${WORKDIR}/auth/tls.crt" \
    --resolve "nvt-driver.test:${port}:127.0.0.1" \
    "https://nvt-driver.test:${port}/readyz" >/dev/null; then
    ready=1
    break
  fi
  sleep 0.1
done
if [[ "${ready}" != "1" ]]; then
  docker inspect --format 'state={{.State.Status}} exit={{.State.ExitCode}} error={{.State.Error}}' "${CONTAINER}" >&2 || true
  docker logs "${CONTAINER}" >&2 || true
  curl --verbose --noproxy '*' --cacert "${WORKDIR}/auth/tls.crt" \
    --resolve "nvt-driver.test:${port}:127.0.0.1" \
    "https://nvt-driver.test:${port}/readyz" >/dev/null || true
  echo "execution driver host did not become ready" >&2
  exit 1
fi

fingerprint="sha256:$(printf '0%.0s' $(seq 1 64))"
payload="$(printf '{\"execution_id\":\"oci-smoke\",\"generation\":1,\"desired_fingerprint\":\"%s\",\"workload_kind\":\"vm\",\"class_name\":\"fake-small\",\"configuration\":{\"ready\":true}}' "${fingerprint}")"
status_code="$(curl --silent --noproxy '*' --output "${WORKDIR}/response.json" --write-out '%{http_code}' --cacert "${WORKDIR}/auth/tls.crt" \
  --resolve "nvt-driver.test:${port}:127.0.0.1" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $(cat "${WORKDIR}/auth/auth-token")" \
  --data "${payload}" \
  "https://nvt-driver.test:${port}/v1/reconcile")"
if [[ "${status_code}" != "200" ]]; then
  cat "${WORKDIR}/response.json" >&2
  docker logs "${CONTAINER}" >&2 || true
  echo "execution driver host reconcile returned HTTP ${status_code}" >&2
  exit 1
fi
response="$(cat "${WORKDIR}/response.json")"
python3 - "${response}" <<'PY'
import json
import sys
value = json.loads(sys.argv[1])
assert value["protocol_version"] == "nvt.execution-driver-host/v1"
assert value["status"]["phase"] == "running"
assert value["status"]["ready"] is True
assert value["status"]["external_resource_id"]
PY

unauthorized="$(curl --silent --noproxy '*' --output /dev/null --write-out '%{http_code}' \
  --cacert "${WORKDIR}/auth/tls.crt" \
  --resolve "nvt-driver.test:${port}:127.0.0.1" \
  -H 'Content-Type: application/json' \
  --data '{"execution_id":"oci-smoke"}' \
  "https://nvt-driver.test:${port}/v1/observe")"
[[ "${unauthorized}" == "401" ]]

echo "execution driver host image smoke passed"
