#!/bin/sh
set -u

real_docker="${NVT_DOCKER_REAL_BIN:-/usr/bin/docker}"
ensure_networks="${NVT_DOCKER_ENSURE_BIN:-/usr/local/bin/ensure-docker-networks}"
if [ -z "${NVT_DOCKER_REQUIRED_NETWORKS+x}" ]; then
  exec "${real_docker}" "$@"
fi

"${ensure_networks}" || exit $?
if [ "${1:-}" != system ] || [ "${2:-}" != prune ]; then
  exec "${real_docker}" "$@"
fi

"${real_docker}" "$@"
status=$?
# Restore an unused required network synchronously after `docker system prune`
# returns. Other invocations use exec so Docker retains native signal handling;
# their preflight still repairs a network removed through another API path.
"${ensure_networks}" || exit $?
exit "${status}"
