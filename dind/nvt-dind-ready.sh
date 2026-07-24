#!/bin/sh
set -eu

run_dir="${NVT_DIND_RUN_DIR:-/run/nvt-dind}"
required_driver_file="${run_dir}/required-storage-driver"
driver="$(docker info --format '{{.Driver}}')" || exit 1

if [ -f "${required_driver_file}" ]; then
  required="$(cat "${required_driver_file}")"
  if [ "${driver}" != "${required}" ]; then
    printf 'nvt-dind: Docker storage driver is not the required driver\n' >&2
    exit 1
  fi
fi
