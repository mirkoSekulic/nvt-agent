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

SOURCE_DIR="${WORKDIR}/codex"
mkdir -p "${SOURCE_DIR}/logs" "${SOURCE_DIR}/sessions" "${SOURCE_DIR}/cache" "${SOURCE_DIR}/skills"
printf '{"tokens":true}\n' >"${SOURCE_DIR}/auth.json"
printf 'model = "gpt-5"\n' >"${SOURCE_DIR}/config.toml"
printf 'install-test\n' >"${SOURCE_DIR}/installation_id"
printf 'large log\n' >"${SOURCE_DIR}/logs/codex.log"
printf 'session\n' >"${SOURCE_DIR}/sessions/session.jsonl"
printf 'cache\n' >"${SOURCE_DIR}/cache/blob"
printf 'state\n' >"${SOURCE_DIR}/state.sqlite"
printf 'history\n' >"${SOURCE_DIR}/history.jsonl"

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
  if [[ -z "${from_file}" ]]; then
    printf 'missing --from-file\n' >&2
    exit 1
  fi
  find "${from_file}" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort >"${KUBECTL_FILES_LOG}"
  printf 'apiVersion: v1\nkind: Secret\nmetadata:\n  name: test-secret\n'
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
KUBECTL_FILES_LOG="${WORKDIR}/kubectl-files.log"
KUBECTL_APPLY_LOG="${WORKDIR}/kubectl-apply.yaml"
export KUBECTL_ARGS_LOG KUBECTL_FILES_LOG KUBECTL_APPLY_LOG

KUBECTL="${FAKE_KUBECTL}" \
  CODEX_AUTH_SOURCE="${SOURCE_DIR}" \
  CODEX_AUTH_SECRET="test-secret" \
  NAMESPACE="test-ns" \
  KUBECTL_CONTEXT="test-context" \
  bash "${ROOT}/scripts/operator-codex-auth-secret.sh"

EXPECTED_FILES="${WORKDIR}/expected-files.txt"
printf 'auth.json\nconfig.toml\ninstallation_id\n' >"${EXPECTED_FILES}"
cmp -s "${EXPECTED_FILES}" "${KUBECTL_FILES_LOG}" || {
  printf 'unexpected filtered Secret files:\n' >&2
  cat "${KUBECTL_FILES_LOG}" >&2
  exit 1
}

grep -q -- '--context test-context create secret generic test-secret' "${KUBECTL_ARGS_LOG}"
grep -q -- '--context test-context -n test-ns apply -f -' "${KUBECTL_ARGS_LOG}"

KUBECTL_ARGS_LOG="${WORKDIR}/kubectl-legacy-args.log"
KUBECTL_FILES_LOG="${WORKDIR}/kubectl-legacy-files.log"
KUBECTL_APPLY_LOG="${WORKDIR}/kubectl-legacy-apply.yaml"
export KUBECTL_ARGS_LOG KUBECTL_FILES_LOG KUBECTL_APPLY_LOG

KUBECTL="${FAKE_KUBECTL}" \
  SOURCE="${SOURCE_DIR}" \
  SECRET="legacy-secret" \
  NAMESPACE="legacy-ns" \
  KUBECTL_CONTEXT="legacy-context" \
  bash "${ROOT}/scripts/operator-codex-auth-secret.sh"
cmp -s "${EXPECTED_FILES}" "${KUBECTL_FILES_LOG}"
grep -q -- '--context legacy-context create secret generic legacy-secret' "${KUBECTL_ARGS_LOG}"
grep -q -- '--context legacy-context -n legacy-ns apply -f -' "${KUBECTL_ARGS_LOG}"

MISSING_SOURCE="${WORKDIR}/missing"
mkdir -p "${MISSING_SOURCE}"
printf '{}\n' >"${MISSING_SOURCE}/auth.json"
printf 'install-test\n' >"${MISSING_SOURCE}/installation_id"

if KUBECTL="${FAKE_KUBECTL}" CODEX_AUTH_SOURCE="${MISSING_SOURCE}" bash "${ROOT}/scripts/operator-codex-auth-secret.sh" \
  >"${WORKDIR}/missing.out" 2>"${WORKDIR}/missing.err"; then
  printf 'expected missing config.toml to fail\n' >&2
  exit 1
fi
grep -q 'required Codex auth file is missing: .*/config.toml' "${WORKDIR}/missing.err"

echo "operator codex auth Secret helper test passed"
