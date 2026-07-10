#!/usr/bin/env bash
set -euo pipefail

# Kind copies proxy variables into the node container. A localhost proxy from
# the surrounding mediated agent is unreachable inside that node and prevents
# CNI/image bootstrap. Remove only loopback proxy values; preserve any real
# deployment/corporate proxy configuration.
for name in HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy; do
  value="${!name-}"
  case "${value}" in
    *://127.0.0.1:*|*://localhost:*|*://\[::1\]:*) unset "${name}" ;;
  esac
done

exec "$@"
