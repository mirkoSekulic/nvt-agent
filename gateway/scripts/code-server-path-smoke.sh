#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${NVT_CODE_SERVER_SMOKE_IMAGE:-nvt-agent:code-server-path-smoke}"
CONTAINER="nvt-code-server-path-smoke-$$"
PORT="${NVT_CODE_SERVER_SMOKE_PORT:-14090}"

cleanup() {
  docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker build -f "${ROOT}/runtime/Dockerfile" -t "${IMAGE}" "${ROOT}"
docker run -d --rm \
  --name "${CONTAINER}" \
  --network host \
  --entrypoint code-server \
  "${IMAGE}" \
  --bind-addr "0.0.0.0:${PORT}" \
  --auth none \
  /workspace >/dev/null

for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${PORT}/" >/dev/null; then
    break
  fi
  sleep 1
done
curl -fsS "http://127.0.0.1:${PORT}/" >/dev/null
docker exec "${CONTAINER}" code-server --version

cd "${ROOT}/gateway"
NVT_GATEWAY_CODE_SERVER_SMOKE_URL="http://127.0.0.1:${PORT}" \
  go test -count=1 -run '^TestRealCodeServerPathMode$' ./internal/gateway
