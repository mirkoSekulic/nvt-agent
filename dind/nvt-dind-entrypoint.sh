#!/bin/sh
set -eu

data_root="${NVT_DIND_DATA_ROOT:-/var/lib/docker}"
backing_dir="${NVT_DIND_BACKING_DIR:-/var/lib/nvt-dind}"
run_dir="${NVT_DIND_RUN_DIR:-/run/nvt-dind}"
device_dir="${NVT_DIND_DEVICE_DIR:-/dev}"
image_size_bytes="${NVT_DIND_IMAGE_SIZE_BYTES:-21474836480}"
persistent_storage="${NVT_DIND_PERSISTENT_STORAGE:-false}"
image="${backing_dir}/docker-data.ext4"
creating="${backing_dir}/.docker-data.ext4.creating"
required_driver_file="${run_dir}/required-storage-driver"

fail() {
  printf 'nvt-dind: %s\n' "$1" >&2
  exit 1
}

mkdir -p "${data_root}" "${run_dir}"
rm -f "${required_driver_file}"

if ! filesystem_type="$(findmnt -n -o FSTYPE --target "${data_root}" 2>/dev/null)" || [ -z "${filesystem_type}" ]; then
  fail "could not detect the filesystem backing the Docker data root"
fi
case "${persistent_storage}" in
  true|false) ;;
  *) fail "persistent storage intent must be true or false" ;;
esac

# Persistent AgentRuns always keep Docker state in the dedicated durable
# backing mount, independent of the filesystem used by the container runtime.
# Ephemeral non-virtiofs runs retain Docker's native data-root behavior; only
# ephemeral virtiofs needs the xattr-capable loopback workaround.
if [ "${persistent_storage}" = false ] && [ "${filesystem_type}" != "virtiofs" ]; then
  exec dockerd "$@"
fi

case "${image_size_bytes}" in
  ''|*[!0-9]*) fail "image size must be a positive byte count" ;;
esac
if [ "${image_size_bytes}" -lt 67108864 ] || [ "${image_size_bytes}" -gt 1099511627776 ]; then
  fail "image size must be between 64 MiB and 1 TiB"
fi

mkdir -p "${backing_dir}"
if [ -L "${image}" ] || { [ -e "${image}" ] && [ ! -f "${image}" ]; }; then
  fail "existing Docker backing image is not a regular file"
fi
if [ -e "${creating}" ]; then
  fail "partial Docker backing image exists; refusing to overwrite it"
fi

if [ ! -e "${image}" ]; then
  umask 077
  (set -C; : >"${creating}") 2>/dev/null || fail "could not reserve a new Docker backing image"
  truncate -s "${image_size_bytes}" "${creating}" || fail "could not size the new Docker backing image"
  mkfs.ext4 -q -F "${creating}" || fail "could not format the new Docker backing image"
  chmod 0600 "${creating}"
  mv "${creating}" "${image}"
fi
chmod 0600 "${image}"

ensure_loop_devices() {
  if free_loop_device="$(losetup -f 2>/dev/null)"; then
    case "${free_loop_device}" in
      *' (lost)') free_loop_device="${free_loop_device% (lost)}" ;;
    esac
    loop_name="${free_loop_device##*/}"
    loop_index="${loop_name#loop}"
    case "${loop_name}" in
      loop*) ;;
      *) fail "invalid free loop device reported by the kernel" ;;
    esac
    case "${loop_index}" in
      ''|*[!0-9]*) fail "invalid free loop device reported by the kernel" ;;
    esac
    if [ ! -e "${device_dir}/${loop_name}" ]; then
      mkdir -p "${device_dir}"
      mknod "${device_dir}/${loop_name}" b 7 "${loop_index}" ||
        fail "could not recreate the discovered loop device inside the guest"
    fi
    losetup -f >/dev/null 2>&1 || fail "the discovered loop device is unusable inside the guest"
    return
  fi
  mkdir -p "${device_dir}"
  [ -e "${device_dir}/loop-control" ] ||
    mknod "${device_dir}/loop-control" c 10 237 || fail "could not create loop-control inside the guest"
  index=0
  while [ "${index}" -lt 8 ]; do
    [ -e "${device_dir}/loop${index}" ] ||
      mknod "${device_dir}/loop${index}" b 7 "${index}" || fail "could not create loop devices inside the guest"
    index=$((index + 1))
  done
  losetup -f >/dev/null 2>&1 || fail "no loop device is available inside the guest"
}

ensure_loop_devices
associated="$(losetup -j "${image}" | cut -d: -f1)"
case "${associated}" in
  *"
"*) fail "Docker backing image has multiple loop-device associations" ;;
esac
new_loop=0
if [ -n "${associated}" ]; then
  loop_device="${associated}"
else
  loop_device="$(losetup --find --show "${image}")" || fail "could not attach the Docker backing image"
  new_loop=1
fi

set +e
e2fsck -p "${loop_device}"
fsck_status=$?
set -e
case "${fsck_status}" in
  0|1) ;;
  *)
    [ "${new_loop}" = 0 ] || losetup -d "${loop_device}" >/dev/null 2>&1 || true
    fail "Docker backing filesystem check failed"
    ;;
esac

if ! mount -t ext4 -o noatime "${loop_device}" "${data_root}"; then
  [ "${new_loop}" = 0 ] || losetup -d "${loop_device}" >/dev/null 2>&1 || true
  fail "could not mount the Docker backing filesystem"
fi
mounted_source_type="$(findmnt -rn -o SOURCE,FSTYPE --mountpoint "${data_root}" 2>/dev/null | tail -n 1 || true)"
if [ "${mounted_source_type}" != "${loop_device} ext4" ]; then
  umount "${data_root}" >/dev/null 2>&1 || true
  [ "${new_loop}" = 0 ] || losetup -d "${loop_device}" >/dev/null 2>&1 || true
  fail "Docker data root is not backed by the expected ext4 loop device after mount"
fi

# util-linux losetup has no --autoclear attach option. Detaching a busy loop
# device marks it for lazy destruction: the mounted filesystem remains usable,
# and the kernel releases the device when the container mount disappears.
if ! losetup -d "${loop_device}"; then
  umount "${data_root}" >/dev/null 2>&1 || true
  losetup -d "${loop_device}" >/dev/null 2>&1 || true
  fail "could not mark the Docker loop device for automatic cleanup"
fi

printf '%s\n' overlay2 >"${required_driver_file}"
exec dockerd "$@" --storage-driver=overlay2
