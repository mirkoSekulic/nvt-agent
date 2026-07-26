#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER="${ROOT}/runtime/branding/install-code-server-branding.sh"
ASSETS="${ROOT}/assets/branding"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

code_server_root="${WORKDIR}/code-server-9.9.9"
media_dir="${code_server_root}/src/browser/media"
mkdir -p "${WORKDIR}/bin" "${code_server_root}/bin" "${media_dir}"
printf '#!/bin/sh\nexit 0\n' >"${code_server_root}/bin/code-server"
chmod 0755 "${code_server_root}/bin/code-server"
ln -s "${code_server_root}/bin/code-server" "${WORKDIR}/bin/code-server"
for expected in \
  favicon.svg favicon-dark-support.svg favicon.ico \
  pwa-icon-192.png pwa-icon-512.png \
  pwa-icon-maskable-192.png pwa-icon-maskable-512.png; do
  : >"${media_dir}/${expected}"
done

PATH="${WORKDIR}/bin:${PATH}" "${INSTALLER}" "${ASSETS}"
cmp "${ASSETS}/nvt-agent-mark.svg" "${media_dir}/favicon.svg"
cmp "${ASSETS}/nvt-agent-mark.svg" "${media_dir}/favicon-dark-support.svg"
cmp "${ASSETS}/favicon.ico" "${media_dir}/favicon.ico"
cmp "${ASSETS}/nvt-agent-mark-192.png" "${media_dir}/pwa-icon-192.png"
cmp "${ASSETS}/nvt-agent-mark-512.png" "${media_dir}/pwa-icon-512.png"
cmp "${ASSETS}/nvt-agent-mark-192.png" "${media_dir}/pwa-icon-maskable-192.png"
cmp "${ASSETS}/nvt-agent-mark-512.png" "${media_dir}/pwa-icon-maskable-512.png"
for installed in favicon.svg favicon-dark-support.svg favicon.ico \
  pwa-icon-192.png pwa-icon-512.png pwa-icon-maskable-192.png pwa-icon-maskable-512.png; do
  test -L "${media_dir}/${installed}" || {
    echo "branding test: ${installed} is not linked to the overridable asset directory" >&2
    exit 1
  }
done

rm "${media_dir}/favicon.svg"
if PATH="${WORKDIR}/bin:${PATH}" "${INSTALLER}" "${ASSETS}" >"${WORKDIR}/missing.log" 2>&1; then
  echo "branding test: installer accepted a missing expected code-server asset" >&2
  exit 1
fi
grep -F "expected installed asset is missing: ${media_dir}/favicon.svg" "${WORKDIR}/missing.log" >/dev/null

echo "code-server branding installer test passed"
