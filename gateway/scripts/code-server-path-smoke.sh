#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${NVT_CODE_SERVER_SMOKE_IMAGE:-nvt-agent:code-server-path-smoke}"
CONTAINER="nvt-code-server-path-smoke-$$"
CONTAINER_PORT=4090

cleanup() {
  docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker build -f "${ROOT}/runtime/Dockerfile" -t "${IMAGE}" "${ROOT}"
docker run -d --rm \
  --name "${CONTAINER}" \
  --publish "127.0.0.1::${CONTAINER_PORT}" \
  --entrypoint code-server \
  "${IMAGE}" \
  --bind-addr "0.0.0.0:${CONTAINER_PORT}" \
  --auth none \
  /workspace >/dev/null

for _ in $(seq 1 60); do
  if docker exec "${CONTAINER}" curl -fsS "http://127.0.0.1:${CONTAINER_PORT}/" >/dev/null; then
    break
  fi
  sleep 1
done
docker exec "${CONTAINER}" curl -fsS "http://127.0.0.1:${CONTAINER_PORT}/" >/dev/null
docker exec "${CONTAINER}" code-server --version

PUBLISHED="$(docker port "${CONTAINER}" "${CONTAINER_PORT}/tcp" | head -1)"
HOST_PORT="${PUBLISHED##*:}"
if curl -fsS "http://127.0.0.1:${HOST_PORT}/" >/dev/null 2>&1; then
  cd "${ROOT}/gateway"
  NVT_GATEWAY_CODE_SERVER_SMOKE_URL="http://127.0.0.1:${HOST_PORT}" \
    go test -count=1 -run '^TestRealCodeServerPathMode$' ./internal/gateway
else
  # Some containerized Docker daemons do not expose their published loopback
  # into the calling container. Run the proof in the code-server network while
  # retaining the same portable loopback publication used by Docker Desktop.
  docker run --rm \
    --network "container:${CONTAINER}" \
    --volume "${ROOT}:/src" \
    --workdir /src/gateway \
    --env "NVT_GATEWAY_CODE_SERVER_SMOKE_URL=http://127.0.0.1:${CONTAINER_PORT}" \
    golang:1.25 \
    go test -count=1 -run '^TestRealCodeServerPathMode$' ./internal/gateway
fi
