#!/usr/bin/env bash
set -euo pipefail
AZURE_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
helm lint "${AZURE_REPO_ROOT}/charts/nvt" -f "${AZURE_REPO_ROOT}/examples/azure/helm-values.yaml"
helm template nvt "${AZURE_REPO_ROOT}/charts/nvt" -n nvt --include-crds \
  -f "${AZURE_REPO_ROOT}/examples/azure/helm-values.yaml" |
  python3 "${AZURE_REPO_ROOT}/tests/azure-cli/check_helm.py"
