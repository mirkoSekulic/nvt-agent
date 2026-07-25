#!/bin/sh
set -u

real_docker="${NVT_DOCKER_REAL_BIN:-/usr/bin/docker}"
ensure_networks="${NVT_DOCKER_ENSURE_BIN:-/usr/local/bin/ensure-docker-networks}"
if [ -z "${NVT_DOCKER_REQUIRED_NETWORKS+x}" ]; then
  exec "${real_docker}" "$@"
fi

post_prune=false
classify_command() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --context|--host|-H|-c|--config|--tlscacert|--tlscert|--tlskey)
        echo "docker: daemon-selection overrides are not supported with required networks; configure the daemon in the process environment" >&2
        return 64
        ;;
      --context=*|--host=*|-H?*|-c?*|--config=*|--tlscacert=*|--tlscert=*|--tlskey=*|--tls|--tlsverify)
        echo "docker: daemon-selection overrides are not supported with required networks; configure the daemon in the process environment" >&2
        return 64
        ;;
      --debug|-D|--help|--version|-v)
        shift
        ;;
      --log-level|-l)
        if [ "$#" -lt 2 ]; then
          echo "docker: global option is missing its value" >&2
          return 64
        fi
        shift 2
        ;;
      --log-level=*)
        shift
        ;;
      --)
        shift
        break
        ;;
      -*)
        echo "docker: unsupported global option with required networks" >&2
        return 64
        ;;
      *)
        break
        ;;
    esac
  done
  if [ "${1:-}" = system ] && [ "${2:-}" = prune ]; then
    post_prune=true
  fi
}

classify_command "$@" || exit $?
"${ensure_networks}" || exit $?
if [ "${post_prune}" != true ]; then
  exec "${real_docker}" "$@"
fi

"${real_docker}" "$@"
status=$?
# Restore an unused required network synchronously after `docker system prune`
# returns. Other invocations use exec so Docker retains native signal handling;
# their preflight still repairs a network removed through another API path.
"${ensure_networks}" || exit $?
exit "${status}"
