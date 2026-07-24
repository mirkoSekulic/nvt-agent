#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" != "4" ]]; then
  echo "usage: $0 <registry-owner> <release-tag> <revision> <source-url>" >&2
  exit 2
fi

owner="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
release_tag="$2"
revision="$(printf '%s' "$3" | tr '[:upper:]' '[:lower:]')"
source_url="$4"
parallelism="${NVT_RELEASE_IMAGE_PARALLELISM:-4}"

if [[ ! "${owner}" =~ ^[a-z0-9][a-z0-9-]*$ ]] ||
   [[ ! "${release_tag}" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] ||
   [[ ! "${revision}" =~ ^[0-9a-f]{40}$ ]] ||
   [[ ! "${source_url}" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
   [[ ! "${parallelism}" =~ ^[1-8]$ ]]; then
  echo "invalid coordinated release metadata" >&2
  exit 2
fi

images=(
  "nvt-agent-runtime|runtime/Dockerfile"
  "nvt-dind|dind/Dockerfile"
  "nvt-broker|broker/Dockerfile"
  "nvt-egressd|egressd/Dockerfile"
  "nvt-captured|captured/Dockerfile"
  "nvt-operator|operator/Dockerfile"
  "nvt-agent-gateway|gateway/Dockerfile"
  "nvt-github-comments-producer|producers/github-comments/Dockerfile"
)

verify_release_metadata() {
  local image="$1"
  local error_file found_revision found_source found_version status
  error_file="$(mktemp)"
  set +e
  docker manifest inspect "${image}" >/dev/null 2>"${error_file}"
  status=$?
  set -e
  if [[ "${status}" != "0" ]]; then
    if grep -Eqi 'manifest unknown|not found' "${error_file}"; then
      rm -f "${error_file}"
      return 1
    fi
    rm -f "${error_file}"
    echo "could not determine immutable image state: ${image}" >&2
    exit 2
  fi
  rm -f "${error_file}"
  docker pull --quiet "${image}" >/dev/null
  found_revision="$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "${image}")"
  found_source="$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.source" }}' "${image}")"
  found_version="$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.version" }}' "${image}")"
  if [[ "${found_revision}" != "${revision}" || "${found_source}" != "${source_url}" || "${found_version}" != "${release_tag}" ]]; then
    echo "conflicting immutable image tag: ${image}" >&2
    exit 2
  fi
  echo "Verified coordinated release metadata for existing ${image}."
}

publish_image() {
  local entry="$1"
  local name dockerfile image
  IFS='|' read -r name dockerfile <<<"${entry}"
  image="ghcr.io/${owner}/${name}:${release_tag}"
  if verify_release_metadata "${image}"; then
    return
  fi
  echo "Publishing ${name}."
  docker build \
    --label "org.opencontainers.image.source=${source_url}" \
    --label "org.opencontainers.image.revision=${revision}" \
    --label "org.opencontainers.image.version=${release_tag}" \
    --tag "${image}" \
    --file "${dockerfile}" \
    .
  # Recheck after the build. Version-scoped workflow concurrency prevents
  # duplicate releases from racing; this catches an externally-created tag.
  if verify_release_metadata "${image}"; then
    return
  fi
  docker push "${image}"
}

verify_published_image() {
  local entry="$1"
  local name image verified
  IFS='|' read -r name _ <<<"${entry}"
  image="ghcr.io/${owner}/${name}:${release_tag}"
  verified=0
  for _ in $(seq 1 10); do
    if verify_release_metadata "${image}" >/dev/null; then
      verified=1
      break
    fi
    sleep 2
  done
  [[ "${verified}" == "1" ]] || {
    echo "required image manifest is missing after publication: ${image}" >&2
    return 2
  }
}

wait_for_batch() {
  local failed=0 pid
  for pid in "${batch_pids[@]}"; do
    if ! wait "${pid}"; then
      failed=1
    fi
  done
  batch_pids=()
  if [[ "${failed}" != "0" ]]; then
    echo "coordinated image worker failed" >&2
    return 2
  fi
}

batch_pids=()
for entry in "${images[@]}"; do
  publish_image "${entry}" &
  batch_pids+=("$!")
  if [[ "${#batch_pids[@]}" == "${parallelism}" ]]; then
    wait_for_batch
  fi
done
if [[ "${#batch_pids[@]}" != "0" ]]; then
  wait_for_batch
fi

batch_pids=()
for entry in "${images[@]}"; do
  verify_published_image "${entry}" &
  batch_pids+=("$!")
  if [[ "${#batch_pids[@]}" == "${parallelism}" ]]; then
    wait_for_batch
  fi
done
if [[ "${#batch_pids[@]}" != "0" ]]; then
  wait_for_batch
fi

echo "Verified all eight image manifests and coordinated release metadata labels."
