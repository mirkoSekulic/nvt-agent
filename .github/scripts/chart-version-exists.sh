#!/usr/bin/env bash

# Exit 0 when the chart version exists, 1 when it is absent, and 2 when the
# registry state cannot be determined safely.
set -euo pipefail

if [[ "$#" != "3" ]]; then
  echo "usage: $0 <github-owner> <chart-name> <chart-version>" >&2
  exit 2
fi

owner="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
chart_name="$2"
version="$3"

if ! owner_type="$(gh api "/users/${owner}" --jq .type)"; then
  echo "could not determine GitHub owner type for ${owner}" >&2
  exit 2
fi
if [[ "${owner_type}" == "Organization" ]]; then
  package_owner_kind="orgs"
else
  package_owner_kind="users"
fi

endpoint="/${package_owner_kind}/${owner}/packages/container/helm%2F${chart_name}/versions?per_page=100"
error_file="$(mktemp)"
trap 'rm -f "${error_file}"' EXIT

set +e
output="$(gh api --paginate --slurp "${endpoint}" 2>"${error_file}")"
status=$?
set -e
if [[ "${status}" != "0" ]]; then
  if grep -q 'HTTP 404' "${error_file}"; then
    exit 1
  fi
  echo "could not query GHCR versions for helm/${chart_name}" >&2
  cat "${error_file}" >&2
  exit 2
fi

if ! exists="$(jq -r --arg version "${version}" \
  '[.[][] | .metadata.container.tags[]?] | index($version) != null' \
  <<<"${output}")"; then
  echo "could not parse GHCR versions for helm/${chart_name}" >&2
  exit 2
fi

if [[ "${exists}" == "true" ]]; then
  exit 0
fi
exit 1
