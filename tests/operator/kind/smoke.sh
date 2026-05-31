#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# shellcheck source=tests/operator/kind/lib.sh
source "${SCRIPT_DIR}/lib.sh"

trap diagnostics ERR
trap cleanup EXIT

load_case() {
  local case_file="${SCRIPT_DIR}/cases/${KIND_SMOKE_CASE}.sh"
  [[ -f "${case_file}" ]] || die "unknown KIND_SMOKE_CASE ${KIND_SMOKE_CASE}"
  # shellcheck source=/dev/null
  source "${case_file}"
}

run_render_mode() {
  require_render_tools
  validate_common_config
  case_validate_config
  case_render
  log "render smoke passed"
}

run_kind_mode() {
  require_kind_tools
  validate_common_config
  case_validate_config
  case_kind_setup
  start_operator_port_forward
  case_run
  log "kind operator smoke passed"
}

main() {
  load_config
  load_case

  case "${KIND_SMOKE_MODE}" in
    render)
      run_render_mode
      ;;
    kind)
      run_kind_mode
      ;;
    *)
      die "KIND_SMOKE_MODE must be render or kind"
      ;;
  esac
}

main "$@"
