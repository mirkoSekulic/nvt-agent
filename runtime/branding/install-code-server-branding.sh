#!/bin/sh
set -eu

assets_dir="${1:-/usr/local/share/nvt-agent/branding}"
code_server_binary="$(command -v code-server)" || {
  echo "code-server branding: code-server is not installed" >&2
  exit 1
}
code_server_binary="$(readlink -f "${code_server_binary}")"
code_server_root="$(dirname "$(dirname "${code_server_binary}")")"
media_dir="${code_server_root}/src/browser/media"

for expected in \
  favicon.svg \
  favicon-dark-support.svg \
  favicon.ico \
  pwa-icon-192.png \
  pwa-icon-512.png \
  pwa-icon-maskable-192.png \
  pwa-icon-maskable-512.png; do
  if [ ! -f "${media_dir}/${expected}" ]; then
    echo "code-server branding: expected installed asset is missing: ${media_dir}/${expected}" >&2
    exit 1
  fi
done

for required in \
  nvt-agent-mark.svg \
  favicon.ico \
  nvt-agent-mark-192.png \
  nvt-agent-mark-512.png; do
  if [ ! -f "${assets_dir}/${required}" ]; then
    echo "code-server branding: generated asset is missing: ${assets_dir}/${required}" >&2
    exit 1
  fi
done

# Keep code-server's stable filenames as symlinks to the fixed branding
# contract. A read-only ConfigMap mounted over assets_dir can therefore replace
# the public artwork without rebuilding the runtime image.
ln -sfn "${assets_dir}/nvt-agent-mark.svg" "${media_dir}/favicon.svg"
ln -sfn "${assets_dir}/nvt-agent-mark.svg" "${media_dir}/favicon-dark-support.svg"
ln -sfn "${assets_dir}/favicon.ico" "${media_dir}/favicon.ico"
ln -sfn "${assets_dir}/nvt-agent-mark-192.png" "${media_dir}/pwa-icon-192.png"
ln -sfn "${assets_dir}/nvt-agent-mark-512.png" "${media_dir}/pwa-icon-512.png"
ln -sfn "${assets_dir}/nvt-agent-mark-192.png" "${media_dir}/pwa-icon-maskable-192.png"
ln -sfn "${assets_dir}/nvt-agent-mark-512.png" "${media_dir}/pwa-icon-maskable-512.png"

echo "code-server branding installed in ${code_server_root}"
