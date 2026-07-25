#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENTRYPOINT="${ROOT}/dind/nvt-dind-entrypoint.sh"
READY="${ROOT}/dind/nvt-dind-ready.sh"
CIDR_VALIDATOR="${ROOT}/dind/validate-managed-cidrs.sh"
BRIDGE_NETFILTER="${ROOT}/dind/disable-bridge-netfilter.sh"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT
BIN="${WORKDIR}/bin"
mkdir -p "${BIN}"

cat >"${BIN}/findmnt" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf 'findmnt %s\n' "$*" >>"${FAKE_LOG}"
[[ "${FAKE_FINDMNT_FAIL:-0}" != 1 ]] || exit 1
if [[ -f "${FAKE_MOUNT_MARKER}" ]]; then
  if [[ " $* " == *" SOURCE,FSTYPE "* ]]; then
    # Model a Kubernetes/Docker volume overmounted by the ext4 loop device.
    printf '/dev/pvc ext4\n/dev/loop0 ext4\n'
  else
    printf 'ext4\n'
  fi
else
  printf '%s\n' "${FAKE_FS_TYPE:-ext4}"
fi
FAKE

cat >"${BIN}/truncate" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf 'truncate %s\n' "$*" >>"${FAKE_LOG}"
: >"${@: -1}"
FAKE

cat >"${BIN}/mkfs.ext4" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf 'mkfs.ext4 %s\n' "$*" >>"${FAKE_LOG}"
[[ "${FAKE_MKFS_FAIL:-0}" != 1 ]]
FAKE

cat >"${BIN}/losetup" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf 'losetup %s\n' "$*" >>"${FAKE_LOG}"
for arg in "$@"; do
  [[ "${arg}" != "--autoclear" ]] || exit 2
done
case "${1:-}" in
  -f)
    if [[ "${FAKE_NEED_LOOP_NODES:-0}" == 1 && ! -f "${FAKE_DEVICE_DIR}/loop-control" ]]; then
      exit 1
    fi
    if [[ "${FAKE_REPORT_LOST_LOOP:-0}" == 1 ]]; then
      printf '/dev/loop0 (lost)\n'
    else
      printf '/dev/loop0\n'
    fi
    ;;
  -j)
    if [[ -f "${FAKE_ASSOCIATED_MARKER}" ]]; then
      printf '/dev/loop0: []: (%s)\n' "$2"
    fi
    ;;
  --find)
    if [[ "${FAKE_REQUIRE_DISCOVERED_LOOP_NODE:-0}" == 1 && ! -f "${FAKE_DEVICE_DIR}/loop0" ]]; then
      exit 1
    fi
    : >"${FAKE_ASSOCIATED_MARKER}"
    printf '/dev/loop0\n'
    ;;
  -d)
    [[ "${FAKE_LOOP_DETACH_FAIL:-0}" != 1 ]] || exit 1
    rm -f "${FAKE_ASSOCIATED_MARKER}"
    ;;
  *) exit 2 ;;
esac
FAKE

cat >"${BIN}/mknod" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf 'mknod %s\n' "$*" >>"${FAKE_LOG}"
: >"$1"
FAKE

cat >"${BIN}/stat" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${*: -1}" == */kmsg ]]; then
  printf '%s\n' "${FAKE_KMSG_STAT:-21b6:1:b}"
  exit 0
fi
exec /usr/bin/stat "$@"
FAKE

cat >"${BIN}/e2fsck" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf 'e2fsck %s\n' "$*" >>"${FAKE_LOG}"
sleep "${FAKE_FSCK_DELAY:-0}"
exit "${FAKE_FSCK_STATUS:-0}"
FAKE

cat >"${BIN}/mount" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf 'mount %s\n' "$*" >>"${FAKE_LOG}"
if [[ "${FAKE_MOUNT_FAIL:-0}" == 1 ]]; then
  exit 1
fi
: >"${FAKE_MOUNT_MARKER}"
FAKE

cat >"${BIN}/umount" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf 'umount %s\n' "$*" >>"${FAKE_LOG}"
rm -f "${FAKE_MOUNT_MARKER}"
FAKE

cat >"${BIN}/dockerd" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf 'dockerd %s\n' "$*" >>"${FAKE_LOG}"
FAKE

# Stands in for the base image's Docker entrypoint, which runs the upstream
# cgroup-v2 nesting setup before executing the requested command.
cat >"${BIN}/dockerd-entrypoint.sh" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf 'dockerd-entrypoint.sh %s\n' "$*" >>"${FAKE_LOG}"
exec "$@"
FAKE

cat >"${BIN}/docker" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf 'docker %s\n' "$*" >>"${FAKE_LOG}"
if [[ "$*" == "info --format {{.Driver}}" ]]; then
  printf '%s\n' "${FAKE_DOCKER_DRIVER:-overlay2}"
else
  exit 2
fi
FAKE
chmod +x "${BIN}"/*

bridge_sysctls="${WORKDIR}/bridge-sysctls"
mkdir -p "${bridge_sysctls}"
printf '1\n' >"${bridge_sysctls}/bridge-nf-call-iptables"
printf '1\n' >"${bridge_sysctls}/bridge-nf-call-ip6tables"
NVT_BRIDGE_SYSCTL_ROOT="${bridge_sysctls}" "${BRIDGE_NETFILTER}"
grep -qx 0 "${bridge_sysctls}/bridge-nf-call-iptables"
grep -qx 0 "${bridge_sysctls}/bridge-nf-call-ip6tables"

rm "${bridge_sysctls}/bridge-nf-call-ip6tables"
printf '1\n' >"${bridge_sysctls}/bridge-nf-call-iptables"
NVT_BRIDGE_SYSCTL_ROOT="${bridge_sysctls}" "${BRIDGE_NETFILTER}"
grep -qx 0 "${bridge_sysctls}/bridge-nf-call-iptables"

rm "${bridge_sysctls}/bridge-nf-call-iptables"
ln -s /proc/uptime "${bridge_sysctls}/bridge-nf-call-iptables"
if NVT_BRIDGE_SYSCTL_ROOT="${bridge_sysctls}" "${BRIDGE_NETFILTER}" >"${WORKDIR}/bridge-stdout" 2>"${WORKDIR}/bridge-stderr"; then
  echo "bridge netfilter helper accepted an unwritable sysctl" >&2
  exit 1
fi
grep -q 'could not disable bridge-nf-call-iptables' "${WORKDIR}/bridge-stderr"

rm "${bridge_sysctls}/bridge-nf-call-iptables"
ln -s /dev/null "${bridge_sysctls}/bridge-nf-call-iptables"
if NVT_BRIDGE_SYSCTL_ROOT="${bridge_sysctls}" "${BRIDGE_NETFILTER}" >"${WORKDIR}/bridge-stdout" 2>"${WORKDIR}/bridge-stderr"; then
  echo "bridge netfilter helper accepted a failed readback" >&2
  exit 1
fi
grep -q 'read back as .* expected 0' "${WORKDIR}/bridge-stderr"

new_fixture() {
  local name="$1"
  FIXTURE="${WORKDIR}/${name}"
  rm -rf "${FIXTURE}"
  mkdir -p "${FIXTURE}/data" "${FIXTURE}/backing" "${FIXTURE}/run" "${FIXTURE}/dev"
  export FAKE_LOG="${FIXTURE}/commands.log"
  export FAKE_MOUNT_MARKER="${FIXTURE}/mounted"
  export FAKE_ASSOCIATED_MARKER="${FIXTURE}/associated"
  export FAKE_DEVICE_DIR="${FIXTURE}/dev"
  : >"${FAKE_LOG}"
  unset FAKE_FINDMNT_FAIL FAKE_MKFS_FAIL FAKE_MOUNT_FAIL FAKE_FSCK_STATUS FAKE_FSCK_DELAY FAKE_NEED_LOOP_NODES FAKE_DOCKER_DRIVER
  unset FAKE_REQUIRE_DISCOVERED_LOOP_NODE
  unset FAKE_REPORT_LOST_LOOP
  unset FAKE_LOOP_DETACH_FAIL
  unset FAKE_PERSISTENT_STORAGE
  unset FAKE_KERNEL_LOG_DEVICE FAKE_KMSG_STAT
}

run_entrypoint() {
  PATH="${BIN}:${PATH}" \
    NVT_DIND_DATA_ROOT="${FIXTURE}/data" \
    NVT_DIND_BACKING_DIR="${FIXTURE}/backing" \
    NVT_DIND_RUN_DIR="${FIXTURE}/run" \
    NVT_DIND_DEVICE_DIR="${FIXTURE}/dev" \
    NVT_DIND_IMAGE_SIZE_BYTES=1073741824 \
    NVT_DIND_PERSISTENT_STORAGE="${FAKE_PERSISTENT_STORAGE:-false}" \
    NVT_DIND_TRANSPARENT="${FAKE_DIND_TRANSPARENT:-false}" \
    NVT_DIND_BRIDGE_NETFILTER_HELPER="${BRIDGE_NETFILTER}" \
    NVT_BRIDGE_SYSCTL_ROOT="${FIXTURE}/bridge-sysctls" \
    NVT_DIND_KERNEL_LOG_DEVICE="${FAKE_KERNEL_LOG_DEVICE:-false}" \
    "${ENTRYPOINT}" --host=tcp://127.0.0.1:2375 --tls=false
}

# Docker must always start through the base image's entrypoint so the upstream
# cgroup-v2 nesting setup runs, and the prepared dockerd arguments must survive
# that handoff unchanged.
assert_vendor_handoff() {
  local expected_args="$1"
  local handoff_line dockerd_line
  if ! grep -qx "dockerd-entrypoint.sh dockerd ${expected_args}" "${FAKE_LOG}"; then
    echo "Docker did not start through the base image entrypoint with: dockerd ${expected_args}" >&2
    exit 1
  fi
  grep -qx "dockerd ${expected_args}" "${FAKE_LOG}"
  handoff_line="$(grep -nx "dockerd-entrypoint.sh dockerd ${expected_args}" "${FAKE_LOG}" | head -n 1 | cut -d: -f1)"
  dockerd_line="$(grep -nx "dockerd ${expected_args}" "${FAKE_LOG}" | head -n 1 | cut -d: -f1)"
  [[ "${handoff_line}" -lt "${dockerd_line}" ]]
}

assert_docker_not_started() {
  if grep -Eq '^dockerd(-entrypoint\.sh)? ' "${FAKE_LOG}"; then
    echo "Docker startup continued after a fatal storage error" >&2
    exit 1
  fi
}

new_fixture kernel-log-device-off
export FAKE_FS_TYPE=ext4
mkdir -p "${FIXTURE}/bridge-sysctls"
printf '1\n' >"${FIXTURE}/bridge-sysctls/bridge-nf-call-iptables"
printf '1\n' >"${FIXTURE}/bridge-sysctls/bridge-nf-call-ip6tables"
printf 'leave-untouched' >"${FIXTURE}/dev/kmsg"
run_entrypoint
grep -qx 1 "${FIXTURE}/bridge-sysctls/bridge-nf-call-iptables"
grep -qx 1 "${FIXTURE}/bridge-sysctls/bridge-nf-call-ip6tables"
grep -qx 'leave-untouched' "${FIXTURE}/dev/kmsg"
if grep -q '^mknod .*/kmsg ' "${FAKE_LOG}"; then
  echo "disabled kernel-log device changed the device filesystem" >&2
  exit 1
fi

new_fixture kernel-log-device-create
export FAKE_FS_TYPE=ext4
export FAKE_KERNEL_LOG_DEVICE=true
run_entrypoint
grep -q '^mknod .*/dev/kmsg c 1 11$' "${FAKE_LOG}"
[[ "$(/usr/bin/stat -c '%a' "${FIXTURE}/dev/kmsg")" == 600 ]]
assert_vendor_handoff '--host=tcp://127.0.0.1:2375 --tls=false'

new_fixture kernel-log-device-existing
export FAKE_FS_TYPE=ext4
export FAKE_KERNEL_LOG_DEVICE=true
printf 'existing-device' >"${FIXTURE}/dev/kmsg"
export FAKE_KMSG_STAT=21b6:1:b
run_entrypoint
grep -qx 'existing-device' "${FIXTURE}/dev/kmsg"
if grep -q '^mknod .*/kmsg ' "${FAKE_LOG}"; then
  echo "existing valid kernel-log device was replaced" >&2
  exit 1
fi

for invalid in regular directory wrong-device symlink; do
  new_fixture "kernel-log-device-${invalid}"
  export FAKE_FS_TYPE=ext4
  export FAKE_KERNEL_LOG_DEVICE=true
  case "${invalid}" in
    regular)
      : >"${FIXTURE}/dev/kmsg"
      export FAKE_KMSG_STAT=81a4:0:0
      ;;
    directory)
      mkdir "${FIXTURE}/dev/kmsg"
      export FAKE_KMSG_STAT=41ed:0:0
      ;;
    wrong-device)
      : >"${FIXTURE}/dev/kmsg"
      export FAKE_KMSG_STAT=21b6:1:a
      ;;
    symlink)
      ln -s "${FIXTURE}/outside" "${FIXTURE}/dev/kmsg"
      ;;
  esac
  if run_entrypoint >"${FIXTURE}/stdout" 2>"${FIXTURE}/stderr"; then
    echo "invalid ${invalid} kernel-log path was accepted" >&2
    exit 1
  fi
  grep -q 'kernel-log device' "${FIXTURE}/stderr"
  assert_docker_not_started
done

new_fixture invalid-kernel-log-intent
export FAKE_FS_TYPE=ext4
export FAKE_KERNEL_LOG_DEVICE=maybe
if run_entrypoint >"${FIXTURE}/stdout" 2>"${FIXTURE}/stderr"; then
  echo "invalid kernel-log device intent was accepted" >&2
  exit 1
fi
grep -q 'kernel-log device intent must be true or false' "${FIXTURE}/stderr"
assert_docker_not_started

new_fixture non-virtiofs
export FAKE_FS_TYPE=ext4
run_entrypoint
assert_vendor_handoff '--host=tcp://127.0.0.1:2375 --tls=false'
if grep -Eq '^(truncate|mkfs\.ext4|losetup|e2fsck|mount) ' "${FAKE_LOG}"; then
  echo "non-virtiofs startup changed Docker storage" >&2
  exit 1
fi

new_fixture non-virtiofs-persistent-reuse
export FAKE_FS_TYPE=ext4
export FAKE_PERSISTENT_STORAGE=true
run_entrypoint
grep -q '^mkfs.ext4 -q -F .*\.creating$' "${FAKE_LOG}"
grep -q '^mount -t ext4 -o noatime /dev/loop0 .*/data$' "${FAKE_LOG}"
assert_vendor_handoff '--host=tcp://127.0.0.1:2375 --tls=false --storage-driver=overlay2'
printf 'persistent-docker-state' >"${FIXTURE}/backing/docker-data.ext4"
rm -f "${FAKE_MOUNT_MARKER}" "${FAKE_ASSOCIATED_MARKER}"
: >"${FAKE_LOG}"
run_entrypoint
grep -q '^e2fsck -p /dev/loop0$' "${FAKE_LOG}"
if grep -Eq '^(truncate|mkfs\.ext4) ' "${FAKE_LOG}"; then
  echo "persistent non-virtiofs Docker storage was reformatted on restart" >&2
  exit 1
fi
grep -qx persistent-docker-state "${FIXTURE}/backing/docker-data.ext4"
assert_vendor_handoff '--host=tcp://127.0.0.1:2375 --tls=false --storage-driver=overlay2'

new_fixture invalid-persistence-intent
export FAKE_FS_TYPE=ext4
export FAKE_PERSISTENT_STORAGE=maybe
if run_entrypoint >"${FIXTURE}/stdout" 2>"${FIXTURE}/stderr"; then
  echo "invalid persistent storage intent was accepted" >&2
  exit 1
fi
grep -q 'persistent storage intent must be true or false' "${FIXTURE}/stderr"
assert_docker_not_started

new_fixture detection-failure
export FAKE_FINDMNT_FAIL=1
if run_entrypoint >"${FIXTURE}/stdout" 2>"${FIXTURE}/stderr"; then
  echo "Docker startup continued without detecting its backing filesystem" >&2
  exit 1
fi
grep -q 'could not detect the filesystem backing the Docker data root' "${FIXTURE}/stderr"
assert_docker_not_started

new_fixture new-image
export FAKE_FS_TYPE=virtiofs
export FAKE_DIND_TRANSPARENT=true
export FAKE_NEED_LOOP_NODES=1
mkdir -p "${FIXTURE}/bridge-sysctls"
printf '1\n' >"${FIXTURE}/bridge-sysctls/bridge-nf-call-iptables"
printf '1\n' >"${FIXTURE}/bridge-sysctls/bridge-nf-call-ip6tables"
run_entrypoint
grep -qx 0 "${FIXTURE}/bridge-sysctls/bridge-nf-call-iptables"
grep -qx 0 "${FIXTURE}/bridge-sysctls/bridge-nf-call-ip6tables"
[[ -f "${FIXTURE}/backing/docker-data.ext4" ]]
[[ ! -e "${FIXTURE}/backing/.docker-data.ext4.creating" ]]
grep -q '^truncate -s 1073741824 .*\.creating$' "${FAKE_LOG}"
grep -q '^mkfs.ext4 -q -F .*\.creating$' "${FAKE_LOG}"
grep -q '^mknod .*/loop-control c 10 237$' "${FAKE_LOG}"
grep -q '^losetup --find --show .*/docker-data\.ext4$' "${FAKE_LOG}"
grep -q '^mount -t ext4 -o noatime /dev/loop0 .*/data$' "${FAKE_LOG}"
grep -q '^losetup -d /dev/loop0$' "${FAKE_LOG}"
mount_line="$(grep -n '^mount -t ext4 -o noatime /dev/loop0 ' "${FAKE_LOG}" | cut -d: -f1)"
detach_line="$(grep -n '^losetup -d /dev/loop0$' "${FAKE_LOG}" | cut -d: -f1)"
[[ "${mount_line}" -lt "${detach_line}" ]]
assert_vendor_handoff '--bip=172.30.0.1/24 --default-address-pool base=172.31.0.0/16,size=24 --host=tcp://127.0.0.1:2375 --tls=false --storage-driver=overlay2'
grep -qx overlay2 "${FIXTURE}/run/required-storage-driver"

new_fixture missing-discovered-loop-node
export FAKE_FS_TYPE=virtiofs
export FAKE_REQUIRE_DISCOVERED_LOOP_NODE=1
export FAKE_REPORT_LOST_LOOP=1
run_entrypoint
grep -q '^mknod .*/loop0 b 7 0$' "${FAKE_LOG}"
grep -q '^losetup --find --show .*/docker-data\.ext4$' "${FAKE_LOG}"
grep -q '^dockerd .*--storage-driver=overlay2$' "${FAKE_LOG}"

new_fixture existing-image
export FAKE_FS_TYPE=virtiofs
printf 'existing-canonical-image' >"${FIXTURE}/backing/docker-data.ext4"
run_entrypoint
grep -q '^e2fsck -p /dev/loop0$' "${FAKE_LOG}"
if grep -Eq '^(truncate|mkfs\.ext4) ' "${FAKE_LOG}"; then
  echo "existing Docker backing image was reformatted" >&2
  exit 1
fi
grep -qx 'existing-canonical-image' "${FIXTURE}/backing/docker-data.ext4"

new_fixture delayed-recovery
export FAKE_FS_TYPE=virtiofs
export FAKE_FSCK_DELAY=1
printf 'existing-canonical-image' >"${FIXTURE}/backing/docker-data.ext4"
run_entrypoint >"${FIXTURE}/stdout" 2>"${FIXTURE}/stderr" &
recovery_pid=$!
sleep 0.2
if grep -Eq '^dockerd(-entrypoint\.sh)? ' "${FAKE_LOG}"; then
  echo "dockerd started before delayed filesystem recovery completed" >&2
  exit 1
fi
wait "${recovery_pid}"
grep -q '^dockerd .*--storage-driver=overlay2$' "${FAKE_LOG}"

new_fixture partial-image
export FAKE_FS_TYPE=virtiofs
: >"${FIXTURE}/backing/.docker-data.ext4.creating"
if run_entrypoint >"${FIXTURE}/stdout" 2>"${FIXTURE}/stderr"; then
  echo "partial Docker backing image was accepted" >&2
  exit 1
fi
grep -q 'partial Docker backing image exists' "${FIXTURE}/stderr"
assert_docker_not_started

new_fixture symlink-image
export FAKE_FS_TYPE=virtiofs
printf 'outside' >"${FIXTURE}/outside"
ln -s "${FIXTURE}/outside" "${FIXTURE}/backing/docker-data.ext4"
if run_entrypoint >"${FIXTURE}/stdout" 2>"${FIXTURE}/stderr"; then
  echo "symlink Docker backing image was accepted" >&2
  exit 1
fi
grep -q 'backing image is not a regular file' "${FIXTURE}/stderr"
grep -qx outside "${FIXTURE}/outside"
assert_docker_not_started

new_fixture format-failure
export FAKE_FS_TYPE=virtiofs
export FAKE_MKFS_FAIL=1
if run_entrypoint >"${FIXTURE}/stdout" 2>"${FIXTURE}/stderr"; then
  echo "Docker startup continued after format failure" >&2
  exit 1
fi
grep -q 'could not format the new Docker backing image' "${FIXTURE}/stderr"
[[ -f "${FIXTURE}/backing/.docker-data.ext4.creating" ]]
[[ ! -e "${FIXTURE}/backing/docker-data.ext4" ]]
assert_docker_not_started

new_fixture corrupt-image
export FAKE_FS_TYPE=virtiofs
printf 'do-not-destroy' >"${FIXTURE}/backing/docker-data.ext4"
export FAKE_FSCK_STATUS=4
if run_entrypoint >"${FIXTURE}/stdout" 2>"${FIXTURE}/stderr"; then
  echo "corrupt Docker backing image was accepted" >&2
  exit 1
fi
grep -q 'backing filesystem check failed' "${FIXTURE}/stderr"
grep -qx 'do-not-destroy' "${FIXTURE}/backing/docker-data.ext4"
! grep -q '^mkfs.ext4 ' "${FAKE_LOG}"
assert_docker_not_started

new_fixture mount-failure
export FAKE_FS_TYPE=virtiofs
printf 'do-not-destroy' >"${FIXTURE}/backing/docker-data.ext4"
export FAKE_MOUNT_FAIL=1
if run_entrypoint >"${FIXTURE}/stdout" 2>"${FIXTURE}/stderr"; then
  echo "Docker startup continued after mount failure" >&2
  exit 1
fi
grep -q 'could not mount the Docker backing filesystem' "${FIXTURE}/stderr"
grep -qx 'do-not-destroy' "${FIXTURE}/backing/docker-data.ext4"
assert_docker_not_started

new_fixture detach-failure
export FAKE_FS_TYPE=virtiofs
printf 'do-not-destroy' >"${FIXTURE}/backing/docker-data.ext4"
export FAKE_LOOP_DETACH_FAIL=1
if run_entrypoint >"${FIXTURE}/stdout" 2>"${FIXTURE}/stderr"; then
  echo "Docker startup continued without loop-device cleanup" >&2
  exit 1
fi
grep -q 'could not mark the Docker loop device for automatic cleanup' "${FIXTURE}/stderr"
grep -qx 'do-not-destroy' "${FIXTURE}/backing/docker-data.ext4"
grep -q '^umount .*/data$' "${FAKE_LOG}"
assert_docker_not_started

new_fixture driver-check
printf 'overlay2\n' >"${FIXTURE}/run/required-storage-driver"
export FAKE_DOCKER_DRIVER=vfs
if PATH="${BIN}:${PATH}" NVT_DIND_RUN_DIR="${FIXTURE}/run" "${READY}" >"${FIXTURE}/stdout" 2>"${FIXTURE}/stderr"; then
  echo "vfs satisfied the overlay2 readiness gate" >&2
  exit 1
fi
grep -q 'storage driver is not the required driver' "${FIXTURE}/stderr"
export FAKE_DOCKER_DRIVER=overlay2
PATH="${BIN}:${PATH}" NVT_DIND_RUN_DIR="${FIXTURE}/run" "${READY}"
rm -f "${FIXTURE}/run/required-storage-driver"
export FAKE_DOCKER_DRIVER=vfs
PATH="${BIN}:${PATH}" NVT_DIND_RUN_DIR="${FIXTURE}/run" "${READY}"

bash "${ROOT}/tests/operator/kata/test.sh"

validate_cidrs() {
  docker run --rm -e NVT_DIND_PROTECTED_CIDRS="$1" -v "${CIDR_VALIDATOR}:/validator:ro" python:3.13-alpine /validator 172.30.0.0/15
}
validate_cidrs '10.0.0.0/8 169.254.0.0/16 fd00:1234::/48'
for protected in 172.30.0.0/15 172.16.0.0/12 172.30.1.0/24 172.28.0.0/14 172.31.255.0/24; do
  if validate_cidrs "${protected}" >/dev/null 2>&1; then
    echo "overlapping protected CIDR ${protected} was accepted" >&2
    exit 1
  fi
done
if validate_cidrs 'not-a-cidr' >/dev/null 2>&1; then
  echo "malformed protected CIDR was accepted" >&2
  exit 1
fi
if validate_cidrs 'fd00:1234::/129' >/dev/null 2>&1; then
  echo "malformed IPv6 protected CIDR was accepted" >&2
  exit 1
fi
echo "nvt-dind CIDR validation test passed"

echo "nvt-dind storage setup test passed"
