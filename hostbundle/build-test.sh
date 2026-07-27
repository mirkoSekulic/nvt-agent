#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
revision=0123456789abcdef0123456789abcdef01234567
relative=".host-bundle-relative-$$"
relative_output="${ROOT}/${relative}"
absolute_output="$(mktemp -d)"
trap 'rm -rf -- "${relative_output}" "${absolute_output}"' EXIT

cd "${ROOT}"
bash hostbundle/build.sh 0.8.33-ci "${revision}" "${relative}/../${relative}"
[[ -f "${relative_output}/nvt-host-bundle-linux-amd64.tar.gz" ]]
[[ -f "${relative_output}/oci/index.json" ]]
[[ "$(tr -d '\n' <"${relative_output}/digest.txt")" =~ ^sha256:[0-9a-f]{64}$ ]]
[[ ! -e "${ROOT}/hostbundle/${relative}" ]]
if grep -aFq 'NVT_HOST_BUNDLE_TEST_' "${relative_output}/bin/nvt-host-bootstrap"; then
  echo "test-only bootstrap transport entered the production binary" >&2
  exit 1
fi

bash hostbundle/build.sh 0.8.33-ci "${revision}" "${absolute_output}"
cmp "${relative_output}/nvt-host-bundle-linux-amd64.tar.gz" "${absolute_output}/nvt-host-bundle-linux-amd64.tar.gz"
diff -ru "${relative_output}/oci" "${absolute_output}/oci"

if bash hostbundle/build.sh 0.8.33-ci "${revision}" "${relative}" >/dev/null 2>&1; then
  echo "non-empty host-bundle output directory was accepted" >&2
  exit 1
fi
cmp "${relative_output}/nvt-host-bundle-linux-amd64.tar.gz" "${absolute_output}/nvt-host-bundle-linux-amd64.tar.gz"

if bash hostbundle/build.sh 0.8.33-ci "${revision}" / >/dev/null 2>&1; then
  echo "root host-bundle output directory was accepted" >&2
  exit 1
fi

echo "host-bundle relative/absolute deterministic build test passed"
