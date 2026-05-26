#!/usr/bin/env bash
set -euo pipefail

image="${1:-nvt-agent:exports-test}"

docker run --rm --entrypoint bash "$image" -lc '
set -euo pipefail

mkdir -p /nvt-agent /workspace
cat > /nvt-agent/agent.yaml <<YAML
plugins:
  - name: git-host-credentials
    source: builtin
    config:
      default-provider: example-token
      providers:
        - name: example-token
          type: token-env
          token-env: GIT_TOKEN
          match:
            - github.com/example/*
  - name: git-credentials
    source: builtin
    when: before-agent
    config:
      credentials:
        - match: https://github.com/example/repo
          provider: example-token
          username: test-user
YAML

export GIT_TOKEN=dummy-token
export NVT_AGENT_CONFIG_FILE=/nvt-agent/agent.yaml
export NVT_WORKSPACE=/workspace
export NVT_STATE_DIR=/root/.nvt-agent
export PATH=/root/.local/bin:/root/bin:/root/.local/share/mise/shims:$PATH

export-plugin-tools /nvt-agent/agent.yaml
git-host-credential resolve --target github.com/example/repo
git-host-credential doctor --provider example-token
run-plugins before-agent /nvt-agent/agent.yaml

test "$(git config --global --get credential.helper)" = nvt

output="$(printf "protocol=https\nhost=github.com\npath=example/repo\n\n" | git credential fill)"
printf "%s\n" "$output"
printf "%s\n" "$output" | grep -qx "username=test-user"
printf "%s\n" "$output" | grep -qx "password=dummy-token"
'
