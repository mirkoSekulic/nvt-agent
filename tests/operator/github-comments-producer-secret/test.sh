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

KEY_FILE="${WORKDIR}/private-key.pem"
SECRET_CONTENT="fake-private-key-content"
printf '%s\n' "${SECRET_CONTENT}" >"${KEY_FILE}"

FAKE_KUBECTL="${WORKDIR}/kubectl"
cat >"${FAKE_KUBECTL}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"${KUBECTL_ARGS_LOG}"

if [[ "$*" == *" create secret generic "* ]]; then
  from_file=""
  for arg in "$@"; do
    case "${arg}" in
      --from-file=*)
        from_file="${arg#--from-file=}"
        ;;
    esac
  done
  printf '%s\n' "${from_file}" >"${KUBECTL_FROM_FILE_LOG}"
  printf 'apiVersion: v1\nkind: Secret\nmetadata:\n  name: test-github-app\n'
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
KUBECTL_FROM_FILE_LOG="${WORKDIR}/kubectl-from-file.log"
KUBECTL_APPLY_LOG="${WORKDIR}/kubectl-apply.yaml"
export KUBECTL_ARGS_LOG KUBECTL_FROM_FILE_LOG KUBECTL_APPLY_LOG

KUBECTL="${FAKE_KUBECTL}" \
  GITHUB_APP_PRIVATE_KEY_FILE="${KEY_FILE}" \
  PRODUCER_GITHUB_APP_SECRET="test-github-app" \
  PRODUCER_GITHUB_APP_KEY="app.pem" \
  NAMESPACE="test-ns" \
  KUBECTL_CONTEXT="test-context" \
  bash "${ROOT}/scripts/github-comments-producer-secret.sh" \
  >"${WORKDIR}/script.out" 2>"${WORKDIR}/script.err"

grep -q -- '--context test-context -n test-ns create secret generic test-github-app' "${KUBECTL_ARGS_LOG}"
grep -q -- '--from-file=app.pem='"${KEY_FILE}" "${KUBECTL_ARGS_LOG}"
grep -q -- '--dry-run=client -o yaml' "${KUBECTL_ARGS_LOG}"
grep -q -- '--context test-context apply -f -' "${KUBECTL_ARGS_LOG}"
grep -Fxq "app.pem=${KEY_FILE}" "${KUBECTL_FROM_FILE_LOG}"
grep -q 'kind: Secret' "${KUBECTL_APPLY_LOG}"

if grep -R "${SECRET_CONTENT}" "${WORKDIR}/script.out" "${WORKDIR}/script.err" "${KUBECTL_ARGS_LOG}" "${KUBECTL_APPLY_LOG}"; then
  printf 'secret helper output leaked private key content\n' >&2
  exit 1
fi

if KUBECTL="${FAKE_KUBECTL}" GITHUB_APP_PRIVATE_KEY_FILE="${WORKDIR}/missing.pem" \
  bash "${ROOT}/scripts/github-comments-producer-secret.sh" >"${WORKDIR}/missing.out" 2>"${WORKDIR}/missing.err"; then
  printf 'expected missing private key file to fail\n' >&2
  exit 1
fi
grep -q 'GITHUB_APP_PRIVATE_KEY_FILE must be an existing regular file' "${WORKDIR}/missing.err"

if KUBECTL="${FAKE_KUBECTL}" GITHUB_APP_PRIVATE_KEY_FILE="" \
  bash "${ROOT}/scripts/github-comments-producer-secret.sh" >"${WORKDIR}/empty.out" 2>"${WORKDIR}/empty.err"; then
  printf 'expected empty private key file value to fail\n' >&2
  exit 1
fi
grep -q 'GITHUB_APP_PRIVATE_KEY_FILE is required' "${WORKDIR}/empty.err"

echo "github comments producer Secret helper test passed"
