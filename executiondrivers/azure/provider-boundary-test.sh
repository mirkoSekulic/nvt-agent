#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Azure deployment and selection are intentionally not branches in the core
# chart or operator. Provider-owned deployment/profile integration belongs to
# the separately reviewed follow-up.
mapfile -d '' OPERATOR_FILES < <(find "${ROOT}/operator" -type f ! -name '*_test.go' ! -name 'go.sum' -print0)
if grep -Rni -i 'azure' "${ROOT}/charts/nvt" "${ROOT}/tests/operator/helm" ||
  grep -ni -i 'azure' "${OPERATOR_FILES[@]}"; then
  echo "generic chart/operator surfaces contain Azure-specific wiring" >&2
  exit 1
fi

grep -Fq 'separate `nvt-execution-driver-azure` chart' "${ROOT}/executiondrivers/azure/README.md"
grep -Fq 'which an untrusted producer request can select Azure' "${ROOT}/executiondrivers/azure/README.md"

echo "Azure provider boundary test passed"
