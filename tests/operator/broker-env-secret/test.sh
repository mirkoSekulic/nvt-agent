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

ENV_FILE="${WORKDIR}/broker.env"
SECRET_VALUE="fake-broker-secret-value"
printf 'GITHUB_APP_ID=123\nGITHUB_APP_PRIVATE_KEY_BASE64=%s\n' "${SECRET_VALUE}" >"${ENV_FILE}"

FAKE_KUBECTL="${WORKDIR}/kubectl"
cat >"${FAKE_KUBECTL}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"${KUBECTL_ARGS_LOG}"

if [[ "$*" == *" create secret generic "* ]]; then
  from_env_file=""
  for arg in "$@"; do
    case "${arg}" in
      --from-env-file=*)
        from_env_file="${arg#--from-env-file=}"
        ;;
    esac
  done
  printf '%s\n' "${from_env_file}" >"${KUBECTL_FROM_ENV_FILE_LOG}"
  printf 'apiVersion: v1\nkind: Secret\nmetadata:\n  name: test-broker-env\n'
  exit 0
fi

if [[ "$*" == *" apply -f -"* ]]; then
  cat >"${KUBECTL_APPLY_LOG}"
  exit 0
fi

printf 'unexpected kubectl invocation: %s\n' "$*" >&2
exit 1
SH
chmod +x "${FAKE_KUBECTL}"

KUBECTL_ARGS_LOG="${WORKDIR}/kubectl-args.log"
KUBECTL_FROM_ENV_FILE_LOG="${WORKDIR}/kubectl-from-env-file.log"
KUBECTL_APPLY_LOG="${WORKDIR}/kubectl-apply.yaml"
export KUBECTL_ARGS_LOG KUBECTL_FROM_ENV_FILE_LOG KUBECTL_APPLY_LOG

KUBECTL="${FAKE_KUBECTL}" \
  BROKER_ENV_FILE="${ENV_FILE}" \
  BROKER_ENV_SECRET="test-broker-env" \
  NAMESPACE="test-ns" \
  KUBECTL_CONTEXT="test-context" \
  bash "${ROOT}/scripts/broker-env-secret.sh" \
  >"${WORKDIR}/script.out" 2>"${WORKDIR}/script.err"

grep -q -- '--context test-context -n test-ns create secret generic test-broker-env' "${KUBECTL_ARGS_LOG}"
grep -q -- '--from-env-file='"${ENV_FILE}" "${KUBECTL_ARGS_LOG}"
grep -q -- '--dry-run=client -o yaml' "${KUBECTL_ARGS_LOG}"
grep -q -- '--context test-context apply -f -' "${KUBECTL_ARGS_LOG}"
grep -Fxq "${ENV_FILE}" "${KUBECTL_FROM_ENV_FILE_LOG}"
grep -q 'kind: Secret' "${KUBECTL_APPLY_LOG}"

if grep -R "${SECRET_VALUE}" "${WORKDIR}/script.out" "${WORKDIR}/script.err" "${KUBECTL_ARGS_LOG}" "${KUBECTL_APPLY_LOG}"; then
  printf 'broker env helper output leaked env file content\n' >&2
  exit 1
fi

if KUBECTL="${FAKE_KUBECTL}" BROKER_ENV_FILE="${WORKDIR}/missing.env" \
  bash "${ROOT}/scripts/broker-env-secret.sh" >"${WORKDIR}/missing.out" 2>"${WORKDIR}/missing.err"; then
  printf 'expected missing env file to fail\n' >&2
  exit 1
fi
grep -q 'BROKER_ENV_FILE must be an existing regular file' "${WORKDIR}/missing.err"

if KUBECTL="${FAKE_KUBECTL}" BROKER_ENV_FILE="" \
  bash "${ROOT}/scripts/broker-env-secret.sh" >"${WORKDIR}/empty.out" 2>"${WORKDIR}/empty.err"; then
  printf 'expected empty env file value to fail\n' >&2
  exit 1
fi
grep -q 'BROKER_ENV_FILE is required' "${WORKDIR}/empty.err"

echo "broker env Secret helper test passed"
