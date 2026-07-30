#!/usr/bin/env bash
set -euo pipefail

image="${1:-${NVT_NATIVE_EGRESS_RELAY_IMAGE:-nvt-native-egress-relay:test}}"
workdir="$(mktemp -d)"
trap 'docker rm -f nvt-native-egress-relay-image-test >/dev/null 2>&1 || true; rm -rf "${workdir}"' EXIT

[[ "$(docker image inspect --format '{{.Config.User}}' "${image}")" == "65532:65532" ]]
[[ "$(docker image inspect --format '{{json .Config.Entrypoint}}' "${image}")" == '["/nvt-native-egress-relay"]' ]]

container="$(docker create --name nvt-native-egress-relay-image-test "${image}")"
docker export "${container}" >"${workdir}/rootfs.tar"
listing="${workdir}/rootfs.list"
tar -tf "${workdir}/rootfs.tar" >"${listing}"
grep -qx 'nvt-native-egress-relay' "${listing}"
for forbidden in 'bin/sh' 'bin/bash' 'usr/bin/git' 'usr/bin/go' 'usr/bin/apt' 'usr/bin/apt-get' 'usr/bin/dpkg'; do
  if grep -qx "${forbidden}" "${listing}"; then
    echo "forbidden build/runtime tool in relay image: ${forbidden}" >&2
    exit 1
  fi
done

output="$(docker run --rm "${image}" --credential=forbidden 2>&1 || true)"
[[ "${output}" == *'nvt-native-egress-relay: unavailable' ]]
[[ "${output}" != *forbidden* ]]

echo "native egress relay image contract passed"
