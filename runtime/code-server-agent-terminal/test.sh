#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

code_server_root="${WORKDIR}/code-server-9.9.9"
mkdir -p "${WORKDIR}/bin" "${code_server_root}/bin" "${code_server_root}/lib/vscode/extensions"
printf '#!/bin/sh\nexit 0\n' >"${code_server_root}/bin/code-server"
chmod 0755 "${code_server_root}/bin/code-server"
ln -s "${code_server_root}/bin/code-server" "${WORKDIR}/bin/code-server"

PATH="${WORKDIR}/bin:${PATH}" \
  sh "${ROOT}/runtime/code-server-agent-terminal/install.sh" \
  "${ROOT}/runtime/code-server-agent-terminal"

target="${code_server_root}/lib/vscode/extensions/nvt-agent-terminal"
cmp "${ROOT}/runtime/code-server-agent-terminal/package.json" "${target}/package.json"
cmp "${ROOT}/runtime/code-server-agent-terminal/extension.js" "${target}/extension.js"
node "${ROOT}/runtime/code-server-agent-terminal/test.js"

echo "code-server agent terminal installer test passed"
