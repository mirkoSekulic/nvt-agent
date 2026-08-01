#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE="${ROOT}/executiondrivers/azure/internal/template/deployment.bicep"
EXPECTED="${ROOT}/executiondrivers/azure/internal/template/deployment.json"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

BICEP="${BICEP:-${WORKDIR}/bicep}"
if [[ ! -x "${BICEP}" ]]; then
  case "$(uname -s):$(uname -m)" in
    Linux:x86_64)
      asset=bicep-linux-x64
      digest=ff5b194b042c220df4a50d6768ed1d6c39a32894bfdc4ff83d62b115d966a7ce
      ;;
    Linux:aarch64|Linux:arm64)
      asset=bicep-linux-arm64
      digest=204684133b8e64027385e358d31aceda57b3ec00d028df769d9767a54d4dd154
      ;;
    *)
      echo "unsupported host for pinned Bicep verification" >&2
      exit 1
      ;;
  esac
  curl --fail --silent --show-error --location \
    "https://github.com/Azure/bicep/releases/download/v0.45.15/${asset}" \
    --output "${BICEP}"
  printf '%s  %s\n' "${digest}" "${BICEP}" | sha256sum --check --status
  chmod 0755 "${BICEP}"
fi
"${BICEP}" build "${SOURCE}" --outfile "${WORKDIR}/deployment.json"
cmp "${EXPECTED}" "${WORKDIR}/deployment.json"
