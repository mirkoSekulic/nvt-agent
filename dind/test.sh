#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENTRYPOINT="${ROOT}/dind/nvt-dind-entrypoint.sh"
READY="${ROOT}/dind/nvt-dind-ready.sh"
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
    printf '/dev/loop0\n'
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
  unset FAKE_LOOP_DETACH_FAIL
  unset FAKE_PERSISTENT_STORAGE
}

run_entrypoint() {
  PATH="${BIN}:${PATH}" \
    NVT_DIND_DATA_ROOT="${FIXTURE}/data" \
    NVT_DIND_BACKING_DIR="${FIXTURE}/backing" \
    NVT_DIND_RUN_DIR="${FIXTURE}/run" \
    NVT_DIND_DEVICE_DIR="${FIXTURE}/dev" \
    NVT_DIND_IMAGE_SIZE_BYTES=1073741824 \
    NVT_DIND_PERSISTENT_STORAGE="${FAKE_PERSISTENT_STORAGE:-false}" \
    "${ENTRYPOINT}" --host=tcp://127.0.0.1:2375 --tls=false
}

new_fixture non-virtiofs
export FAKE_FS_TYPE=ext4
run_entrypoint
grep -q '^dockerd --host=tcp://127.0.0.1:2375 --tls=false$' "${FAKE_LOG}"
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
grep -q '^dockerd .*--storage-driver=overlay2$' "${FAKE_LOG}"
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
grep -q '^dockerd .*--storage-driver=overlay2$' "${FAKE_LOG}"

new_fixture invalid-persistence-intent
export FAKE_FS_TYPE=ext4
export FAKE_PERSISTENT_STORAGE=maybe
if run_entrypoint >"${FIXTURE}/stdout" 2>"${FIXTURE}/stderr"; then
  echo "invalid persistent storage intent was accepted" >&2
  exit 1
fi
grep -q 'persistent storage intent must be true or false' "${FIXTURE}/stderr"
! grep -q '^dockerd ' "${FAKE_LOG}"

new_fixture detection-failure
export FAKE_FINDMNT_FAIL=1
if run_entrypoint >"${FIXTURE}/stdout" 2>"${FIXTURE}/stderr"; then
  echo "Docker startup continued without detecting its backing filesystem" >&2
  exit 1
fi
grep -q 'could not detect the filesystem backing the Docker data root' "${FIXTURE}/stderr"
! grep -q '^dockerd ' "${FAKE_LOG}"

new_fixture new-image
export FAKE_FS_TYPE=virtiofs
export FAKE_NEED_LOOP_NODES=1
run_entrypoint
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
grep -q '^dockerd --host=tcp://127.0.0.1:2375 --tls=false --storage-driver=overlay2$' "${FAKE_LOG}"
grep -qx overlay2 "${FIXTURE}/run/required-storage-driver"

new_fixture missing-discovered-loop-node
export FAKE_FS_TYPE=virtiofs
export FAKE_REQUIRE_DISCOVERED_LOOP_NODE=1
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
if grep -q '^dockerd ' "${FAKE_LOG}"; then
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
! grep -q '^dockerd ' "${FAKE_LOG}"

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
! grep -q '^dockerd ' "${FAKE_LOG}"

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
! grep -q '^dockerd ' "${FAKE_LOG}"

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
! grep -q '^dockerd ' "${FAKE_LOG}"

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
! grep -q '^dockerd ' "${FAKE_LOG}"

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
! grep -q '^dockerd ' "${FAKE_LOG}"

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

echo "nvt-dind storage setup test passed"
