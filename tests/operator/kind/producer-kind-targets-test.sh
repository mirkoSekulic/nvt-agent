#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORKDIR="$(mktemp -d)"
WORKDIR_CREATED=1

cleanup() {
  if [[ "${WORKDIR_CREATED}" == "1" && -n "${WORKDIR}" ]]; then
    rm -rf "${WORKDIR}"
  fi
}
trap cleanup EXIT

BIN_DIR="${WORKDIR}/bin"
mkdir -p "${BIN_DIR}"

cat >"${BIN_DIR}/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'docker %s\n' "$*" >>"${TOOL_LOG}"
SH

cat >"${BIN_DIR}/kind" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'kind %s\n' "$*" >>"${TOOL_LOG}"
if [[ "$*" == "get clusters" ]]; then
  printf '%s\n' "${EXPECTED_CLUSTER}"
fi
SH

cat >"${BIN_DIR}/helm" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'helm %s\n' "$*" >>"${TOOL_LOG}"
SH

chmod +x "${BIN_DIR}/docker" "${BIN_DIR}/kind" "${BIN_DIR}/helm"

TOOL_LOG="${WORKDIR}/tools.log"
EXPECTED_CLUSTER="poc-cluster"
export TOOL_LOG EXPECTED_CLUSTER

VALUES_FILE="${WORKDIR}/values.github-comments.yaml"
printf 'producer:\n  repositories: []\n' >"${VALUES_FILE}"

PATH="${BIN_DIR}:${PATH}" make -C "${ROOT}" producer-build PRODUCER_IMAGE=custom-producer:test >"${WORKDIR}/build.out"
grep -q -- 'docker build -f producers/github-comments/Dockerfile -t custom-producer:test .' "${TOOL_LOG}"

: >"${TOOL_LOG}"
PATH="${BIN_DIR}:${PATH}" make -C "${ROOT}" gateway-build GATEWAY_IMAGE=custom-gateway:test >"${WORKDIR}/gateway-build.out"
grep -q -- 'docker build -f gateway/Dockerfile -t custom-gateway:test .' "${TOOL_LOG}"

: >"${TOOL_LOG}"
PATH="${BIN_DIR}:${PATH}" make -C "${ROOT}" producer-kind-load \
  PRODUCER_IMAGE=custom-producer:test \
  CLUSTER="${EXPECTED_CLUSTER}" \
  CREATE_CLUSTER=0 >"${WORKDIR}/load.out"
grep -q -- 'kind get clusters' "${TOOL_LOG}"
grep -q -- 'docker build -f producers/github-comments/Dockerfile -t custom-producer:test .' "${TOOL_LOG}"
grep -q -- 'kind load docker-image custom-producer:test --name poc-cluster' "${TOOL_LOG}"

: >"${TOOL_LOG}"
PATH="${BIN_DIR}:${PATH}" make -C "${ROOT}" gateway-kind-load \
  GATEWAY_IMAGE=custom-gateway:test \
  CLUSTER="${EXPECTED_CLUSTER}" \
  CREATE_CLUSTER=0 >"${WORKDIR}/gateway-load.out"
grep -q -- 'kind get clusters' "${TOOL_LOG}"
grep -q -- 'docker build -f gateway/Dockerfile -t custom-gateway:test .' "${TOOL_LOG}"
grep -q -- 'kind load docker-image custom-gateway:test --name poc-cluster' "${TOOL_LOG}"

: >"${TOOL_LOG}"
PATH="${BIN_DIR}:${PATH}" make -C "${ROOT}" producer-kind-install \
  PRODUCER_RELEASE=producer-test \
  PRODUCER_CHART=charts/nvt \
  PRODUCER_VALUES="${VALUES_FILE}" \
  NAMESPACE=producer-ns \
  KUBECTL_CONTEXT=kind-poc-cluster \
  ROLLOUT_TIMEOUT=12s >"${WORKDIR}/install.out"
grep -q -- 'helm upgrade --install producer-test charts/nvt --kube-context kind-poc-cluster -n producer-ns --create-namespace --reuse-values --set producer.enabled=true -f '"${VALUES_FILE}"' --wait --timeout 12s' "${TOOL_LOG}"

if PATH="${BIN_DIR}:${PATH}" make -C "${ROOT}" producer-kind-install \
  PRODUCER_VALUES="${WORKDIR}/missing.yaml" >"${WORKDIR}/missing.out" 2>"${WORKDIR}/missing.err"; then
  printf 'expected missing producer values file to fail\n' >&2
  exit 1
fi
grep -q 'PRODUCER_VALUES file does not exist' "${WORKDIR}/missing.err"

: >"${TOOL_LOG}"
PATH="${BIN_DIR}:${PATH}" make -C "${ROOT}" -n producer-build \
  PRODUCER_IMAGE=dry-run:test >"${WORKDIR}/dry-build.out"
grep -q -- 'docker build -f producers/github-comments/Dockerfile -t "dry-run:test" .' "${WORKDIR}/dry-build.out"

PATH="${BIN_DIR}:${PATH}" make -C "${ROOT}" -n producer-kind-load \
  PRODUCER_IMAGE=dry-run:test \
  CLUSTER=dry-cluster >"${WORKDIR}/dry-load.out"
grep -q -- 'kind load docker-image "dry-run:test" --name "dry-cluster"' "${WORKDIR}/dry-load.out"

PATH="${BIN_DIR}:${PATH}" make -C "${ROOT}" -n gateway-kind-load \
  GATEWAY_IMAGE=dry-gateway:test \
  CLUSTER=dry-cluster >"${WORKDIR}/dry-gateway-load.out"
grep -q -- 'kind load docker-image "dry-gateway:test" --name "dry-cluster"' "${WORKDIR}/dry-gateway-load.out"

PATH="${BIN_DIR}:${PATH}" make -C "${ROOT}" -n operator-kind-install \
  OPERATOR_KIND_GATEWAY=1 \
  GATEWAY_IMAGE=dry-gateway:test >"${WORKDIR}/dry-operator-gateway-install.out"
grep -q -- 'docker build -f gateway/Dockerfile -t "dry-gateway:test" .' "${WORKDIR}/dry-operator-gateway-install.out"
grep -q -- 'kind load docker-image "dry-gateway:test" --name "nvt-smoke"' "${WORKDIR}/dry-operator-gateway-install.out"
grep -q -- '--set gateway.enabled=true --set gateway.image.repository=dry-gateway --set gateway.image.tag=test' "${WORKDIR}/dry-operator-gateway-install.out"
grep -q 'rollout status deployment/nvt-agent-gateway' "${WORKDIR}/dry-operator-gateway-install.out"

echo "producer kind Make targets test passed"
