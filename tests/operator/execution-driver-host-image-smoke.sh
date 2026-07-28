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
  --enrollment-socket=/tmp/nvt-guest-enrollment.sock \
  --enrollment-timeout=5s \
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

prepare_payload='{"contract_version":"nvt.guest-enrollment-handoff/v1","execution_scope":{"agent_run_uid":"00000000-0000-0000-0000-000000000001","execution_id":"oci-smoke","driver_registration":"fake-oci"},"desired_generation":1}'
prepare_code="$(curl --silent --noproxy '*' --output "${WORKDIR}/prepare.json" --write-out '%{http_code}' --cacert "${WORKDIR}/auth/tls.crt" \
  --resolve "nvt-driver.test:${port}:127.0.0.1" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $(cat "${WORKDIR}/auth/auth-token")" \
  --data "${prepare_payload}" \
  "https://nvt-driver.test:${port}/v1/guest-enrollment/prepare")"
[[ "${prepare_code}" == "200" ]]
python3 - "${WORKDIR}/prepare.json" "${WORKDIR}/deliver.json" <<'PY'
import json
import sys
prepare = json.load(open(sys.argv[1]))
assert prepare["contract_version"] == "nvt.guest-enrollment-handoff/v1"
assert prepare["state"] == "prepared" and prepare["newly_prepared"] is True
binding = {
    "agent_run_uid": "00000000-0000-0000-0000-000000000001",
    "execution_id": "oci-smoke",
    "driver_registration": "fake-oci",
    "desired_generation": 1,
    "guest_instance_id": prepare["guest_instance_id"],
}
value = {
    "contract_version": "nvt.guest-enrollment-handoff/v1",
    "envelope": {
        "contract_version": "nvt.guest-enrollment/v1",
        "binding": binding,
        "exchange_url": "https://broker.example/v1/guest-enrollment/exchange",
        "token": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "issued_at": "2026-07-27T12:00:00Z",
        "expires_at": "2026-07-27T12:05:00Z",
    },
}
with open(sys.argv[2], "w") as output:
    json.dump(value, output, separators=(",", ":"))
PY
deliver_code="$(curl --silent --noproxy '*' --output "${WORKDIR}/deliver-response.json" --write-out '%{http_code}' --cacert "${WORKDIR}/auth/tls.crt" \
  --resolve "nvt-driver.test:${port}:127.0.0.1" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $(cat "${WORKDIR}/auth/auth-token")" \
  --data-binary "@${WORKDIR}/deliver.json" \
  "https://nvt-driver.test:${port}/v1/guest-enrollment/deliver")"
[[ "${deliver_code}" == "200" ]]
curl --silent --fail --noproxy '*' --cacert "${WORKDIR}/auth/tls.crt" \
  --resolve "nvt-driver.test:${port}:127.0.0.1" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $(cat "${WORKDIR}/auth/auth-token")" \
  --data "${prepare_payload}" \
  "https://nvt-driver.test:${port}/v1/guest-enrollment/prepare" >"${WORKDIR}/accepted.json"
python3 - "${WORKDIR}/accepted.json" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1]))
assert value["state"] == "accepted" and value["newly_prepared"] is False
PY
if grep -R -Fq 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' "${WORKDIR}/state"; then
  echo "fake driver persisted plaintext enrollment material" >&2
  exit 1
fi

unauthorized="$(curl --silent --noproxy '*' --output /dev/null --write-out '%{http_code}' \
  --cacert "${WORKDIR}/auth/tls.crt" \
  --resolve "nvt-driver.test:${port}:127.0.0.1" \
  -H 'Content-Type: application/json' \
  --data '{"execution_id":"oci-smoke"}' \
  "https://nvt-driver.test:${port}/v1/observe")"
[[ "${unauthorized}" == "401" ]]

echo "execution driver host image smoke passed"
