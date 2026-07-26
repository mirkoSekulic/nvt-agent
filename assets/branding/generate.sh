#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BRANDING_DIR="${ROOT}/assets/branding"
SOURCE="${BRANDING_DIR}/source/nvt-logo-source.png"
EXPECTED_SOURCE_SHA256="ecc3b84860236edc1b2550a1e89ffb38c5a145639cff26d8b05e3c0aff754212"

command -v convert >/dev/null || {
  echo "branding: ImageMagick convert is required" >&2
  exit 1
}
actual_source_sha256="$(sha256sum "${SOURCE}" | awk '{print $1}')"
if [[ "${actual_source_sha256}" != "${EXPECTED_SOURCE_SHA256}" ]]; then
  echo "branding: source SHA-256 is ${actual_source_sha256}, expected ${EXPECTED_SOURCE_SHA256}" >&2
  exit 1
fi

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

# Every product asset is a direct, aspect-preserving resize of the supplied
# artwork. Do not trace, simplify, recolor, crop, remove its background, or
# otherwise reinterpret the logo here.
for size in 512 192 64 32 16; do
  convert "${SOURCE}" -filter Lanczos -resize "${size}x${size}" -strip -depth 8 \
    -define png:compression-level=9 PNG24:"${BRANDING_DIR}/nvt-agent-mark-${size}.png"
done

# code-server references SVG favicon filenames. This is deliberately and
# transparently a raster wrapper around the faithful 512 px derivative; it is
# not presented as a native vector logo. Embedding the high-resolution product
# asset lets browsers downsample cleanly while keeping the fixed ConfigMap
# branding bundle within Kubernetes' size limit.
{
  printf '%s' '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" role="img" aria-label="NVT Agent"><image width="512" height="512" href="data:image/png;base64,'
  base64 "${BRANDING_DIR}/nvt-agent-mark-512.png" | tr -d '\n'
  printf '%s\n' '"/></svg>'
} >"${workdir}/nvt-agent-mark.svg"
install -m 0644 "${workdir}/nvt-agent-mark.svg" "${BRANDING_DIR}/nvt-agent-mark.svg"

convert \
  "${BRANDING_DIR}/nvt-agent-mark-16.png" \
  "${BRANDING_DIR}/nvt-agent-mark-32.png" \
  \( "${SOURCE}" -filter Lanczos -resize 48x48 -strip -depth 8 \) \
  "${BRANDING_DIR}/nvt-agent-mark-64.png" \
  "${BRANDING_DIR}/favicon.ico"

# Go embed cannot reach outside its package tree. These two copies are the only
# package-local assets; regeneration keeps them byte-identical to canonical.
install -m 0644 "${BRANDING_DIR}/nvt-agent-mark-64.png" \
  "${ROOT}/gateway/internal/gateway/branding/nvt-agent-mark-64.png"
install -m 0644 "${BRANDING_DIR}/nvt-agent-mark-192.png" \
  "${ROOT}/gateway/internal/gateway/branding/nvt-agent-mark-192.png"
install -m 0644 "${BRANDING_DIR}/favicon.ico" \
  "${ROOT}/gateway/internal/gateway/branding/favicon.ico"

echo "branding assets generated"
