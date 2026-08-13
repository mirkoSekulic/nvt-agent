#!/bin/sh
set -eu

source_dir="${1:-$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)}"
code_server_binary="$(command -v code-server)" || {
  echo "code-server agent terminal: code-server is not installed" >&2
  exit 1
}
code_server_binary="$(readlink -f "${code_server_binary}")"
code_server_root="$(dirname "$(dirname "${code_server_binary}")")"
extensions_dir="${code_server_root}/lib/vscode/extensions"
target="${extensions_dir}/nvt-agent-terminal"

for required in package.json extension.js; do
  if [ ! -f "${source_dir}/${required}" ]; then
    echo "code-server agent terminal: extension source is missing ${required}" >&2
    exit 1
  fi
done
if [ ! -d "${extensions_dir}" ]; then
  echo "code-server agent terminal: built-in extension directory is missing" >&2
  exit 1
fi

install -d -m 0755 "${target}"
install -m 0644 "${source_dir}/package.json" "${target}/package.json"
install -m 0644 "${source_dir}/extension.js" "${target}/extension.js"

echo "code-server agent terminal extension installed in ${target}"
