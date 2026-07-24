#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SMOKE="${ROOT}/tests/operator/kata/dind-overlay2-smoke.sh"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

KATA_DIND_RENDER_ONLY=1 \
KATA_DIND_RUNTIME_IMAGE=registry.example/nvt-agent-runtime:test \
KATA_DIND_STORAGE_CLASS=managed-csi \
KATA_DIND_DOCKER_SIZE=40Gi \
KATA_DIND_TOLERATIONS_JSON='[{"key":"purpose","operator":"Equal","value":"nvt-agent","effect":"NoSchedule"}]' \
  bash "${SMOKE}" >"${WORKDIR}/configured.yaml"

grep -q '^  runtimeClassName: kata-vm-isolation$' "${WORKDIR}/configured.yaml"
grep -q '^    dockerSize: 40Gi$' "${WORKDIR}/configured.yaml"
grep -q '^  tolerations: \[{"key":"purpose","operator":"Equal","value":"nvt-agent","effect":"NoSchedule"}\]$' "${WORKDIR}/configured.yaml"
grep -q '^  storageClassName: managed-csi$' "${WORKDIR}/configured.yaml"

KATA_DIND_RENDER_ONLY=1 \
KATA_DIND_RUNTIME_IMAGE=registry.example/nvt-agent-runtime:test \
  bash "${SMOKE}" >"${WORKDIR}/default.yaml"
grep -q '^  tolerations: \[\]$' "${WORKDIR}/default.yaml"
if grep -q '^  storageClassName:' "${WORKDIR}/default.yaml"; then
  echo "default Kata smoke unexpectedly selected a StorageClass" >&2
  exit 1
fi

if KATA_DIND_RENDER_ONLY=1 \
  KATA_DIND_RUNTIME_IMAGE=registry.example/nvt-agent-runtime:test \
  KATA_DIND_TOLERATIONS_JSON='[{"key":"purpose","unexpected":true}]' \
  bash "${SMOKE}" >"${WORKDIR}/invalid.stdout" 2>"${WORKDIR}/invalid.stderr"; then
  echo "unsafe Kata toleration configuration rendered successfully" >&2
  exit 1
fi
grep -q 'must be a valid bounded Kubernetes toleration array' "${WORKDIR}/invalid.stderr"

echo "Kata DinD smoke render test passed"
