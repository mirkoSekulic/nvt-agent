#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Azure deployment and selection are intentionally not branches in the core
# chart or operator. Provider-owned deployment/profile integration belongs to
# the separately reviewed follow-up.
MATCHES="$({
  grep -Rni -i 'azure' "${ROOT}/charts/nvt" "${ROOT}/tests/operator/helm" || true
  find "${ROOT}/operator" -type f ! -name '*_test.go' ! -name 'go.sum' \
    -exec grep -Hni -i 'azure' {} + || true
})"
if [[ -n "${MATCHES}" ]]; then
	printf '%s\n' "${MATCHES}" >&2
  echo "generic chart/operator surfaces contain Azure-specific wiring" >&2
  exit 1
fi

grep -Fq 'separate `nvt-execution-driver-azure` chart' "${ROOT}/executiondrivers/azure/README.md"
grep -Fq 'which an untrusted producer request can select Azure' "${ROOT}/executiondrivers/azure/README.md"

echo "Azure provider boundary test passed"
