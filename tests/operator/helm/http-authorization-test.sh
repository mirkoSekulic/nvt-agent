#!/usr/bin/env bash
set -euo pipefail
HTTP_POLICY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
helm lint "${HTTP_POLICY_ROOT}/charts/nvt" -f "${HTTP_POLICY_ROOT}/examples/http-authorization/helm-values.yaml"
helm template nvt "${HTTP_POLICY_ROOT}/charts/nvt" -n nvt --include-crds \
  -f "${HTTP_POLICY_ROOT}/examples/http-authorization/helm-values.yaml" |
  python3 "${HTTP_POLICY_ROOT}/tests/http-authorization/check_helm.py"
