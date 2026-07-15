#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" != "2" ]]; then
  echo "usage: $0 <chart-directory> <release-commit-sha>" >&2
  exit 2
fi

chart="$1"
revision="${2,,}"
version="$(awk -F ': *' '/^version:/ { gsub(/"/, "", $2); print $2; exit }' "${chart}/Chart.yaml")"

# OCI/Docker tags cannot preserve SemVer build metadata verbatim, so release
# chart versions intentionally use core SemVer with an optional prerelease.
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*)|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.((0|[1-9][0-9]*)|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?$'
if [[ ! "${version}" =~ ${semver} ]]; then
  echo "chart version must be valid SemVer without build metadata" >&2
  exit 2
fi
if [[ ! "${revision}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "release commit must be a full 40-character Git object ID" >&2
  exit 2
fi

short_sha="${revision:0:7}"
printf 'VERSION=%s\n' "${version}"
printf 'REVISION=%s\n' "${revision}"
printf 'SHORT_SHA=%s\n' "${short_sha}"
printf 'RELEASE_TAG=%s-%s\n' "${version}" "${short_sha}"
