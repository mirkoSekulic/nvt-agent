#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${NVT_RUNTIME_BRANDING_IMAGE:-nvt-agent-runtime:branding-test}"
# Keep the bind source under the shared workspace so both a local host daemon
# and the nvt DinD sidecar resolve the same path.
OVERRIDE_DIR="$(mktemp -d "${ROOT}/.branding-override.XXXXXX")"
trap 'rm -rf "${OVERRIDE_DIR}"' EXIT
cp "${ROOT}/assets/branding/nvt-agent-mark.svg" "${OVERRIDE_DIR}/nvt-agent-mark.svg"
cp "${ROOT}/assets/branding/nvt-agent-mark-64.png" "${OVERRIDE_DIR}/nvt-agent-mark-64.png"
cp "${ROOT}/assets/branding/nvt-agent-mark-192.png" "${OVERRIDE_DIR}/nvt-agent-mark-192.png"
cp "${ROOT}/assets/branding/nvt-agent-mark-512.png" "${OVERRIDE_DIR}/nvt-agent-mark-512.png"
cp "${ROOT}/assets/branding/favicon.ico" "${OVERRIDE_DIR}/favicon.ico"
printf 'override-favicon-canary' >>"${OVERRIDE_DIR}/favicon.ico"

docker run --rm \
  -v "${ROOT}/assets/branding:/expected:ro" \
  -v "${ROOT}/runtime/code-server-agent-terminal:/expected-agent-terminal:ro" \
  --entrypoint sh \
  "${IMAGE}" -ec '
    code_server_binary="$(readlink -f "$(command -v code-server)")"
    code_server_root="$(dirname "$(dirname "${code_server_binary}")")"
    media_dir="${code_server_root}/src/browser/media"
    cmp /expected/nvt-agent-mark.svg "${media_dir}/favicon.svg"
    cmp /expected/nvt-agent-mark.svg "${media_dir}/favicon-dark-support.svg"
    cmp /expected/favicon.ico "${media_dir}/favicon.ico"
    cmp /expected/nvt-agent-mark-192.png "${media_dir}/pwa-icon-192.png"
    cmp /expected/nvt-agent-mark-512.png "${media_dir}/pwa-icon-512.png"
    cmp /expected/nvt-agent-mark-192.png "${media_dir}/pwa-icon-maskable-192.png"
    cmp /expected/nvt-agent-mark-512.png "${media_dir}/pwa-icon-maskable-512.png"
    for installed in favicon.svg favicon-dark-support.svg favicon.ico \
      pwa-icon-192.png pwa-icon-512.png pwa-icon-maskable-192.png pwa-icon-maskable-512.png; do
      test -L "${media_dir}/${installed}"
    done
    grep -F -- "--app-name \"NVT Agent\"" /usr/local/bin/start-code-server >/dev/null
    extension_dir="${code_server_root}/lib/vscode/extensions/nvt-agent-terminal"
    cmp /expected-agent-terminal/package.json "${extension_dir}/package.json"
    cmp /expected-agent-terminal/extension.js "${extension_dir}/extension.js"
    node /expected-agent-terminal/test.js
    code-server --help | grep -F -- "--app-name" >/dev/null
    code-server --bind-addr 127.0.0.1:4199 --auth none --app-name "NVT Agent" /tmp >/tmp/nvt-code-server-branding.log 2>&1 &
    server_pid=$!
    trap "kill ${server_pid} >/dev/null 2>&1 || true" EXIT
    for attempt in $(seq 1 30); do
      if curl -fsS http://127.0.0.1:4199/manifest.json >/tmp/nvt-manifest.json 2>/dev/null; then
        break
      fi
      sleep 1
    done
    curl -fsS http://127.0.0.1:4199/manifest.json >/tmp/nvt-manifest.json
    grep -F "\"name\": \"NVT Agent\"" /tmp/nvt-manifest.json >/dev/null
    grep -F "pwa-icon-maskable-192.png" /tmp/nvt-manifest.json >/dev/null
  '

# The image's code-server assets are links to the fixed directory, so a
# read-only ConfigMap-style mount changes the served asset without rebuilding.
docker run --rm \
  -v "${OVERRIDE_DIR}:/usr/local/share/nvt-agent/branding:ro" \
  --entrypoint sh \
  "${IMAGE}" -ec '
    media_dir="$(dirname "$(dirname "$(readlink -f "$(command -v code-server)")")")/src/browser/media"
    test -L "${media_dir}/favicon.ico"
    grep -F "override-favicon-canary" "${media_dir}/favicon.ico" >/dev/null
  '

echo "code-server branding image smoke passed"
