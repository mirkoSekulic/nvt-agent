ARG BASE_IMAGE=ghcr.io/catthehacker/ubuntu:act-24.04
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive
ENV NVT_WORKSPACE=/workspace
ENV NVT_STATE_DIR=/root/.nvt-agent
ENV CODE_SERVER_PORT=4090
ENV PATH=/root/.local/bin:/root/bin:/root/.local/share/mise/shims:$PATH

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    python3-yaml \
    ca-certificates \
    openssl \
    gh \
    ripgrep \
    tmux \
    sudo \
  && rm -rf /var/lib/apt/lists/*

# Opt-in non-root runtime user. The base image already ships a uid/gid 1000
# user (`ubuntu`); rename it to `agent` with home /home/agent and give it
# passwordless sudo. The image default user stays root (no `USER agent`
# directive) — non-root mode is selected at runtime by the operator/compose, so
# existing root/Codex behavior is unchanged.
RUN groupmod -n agent ubuntu \
  && usermod -l agent -d /home/agent -m ubuntu \
  && printf 'agent ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/nvt-agent \
  && chmod 0440 /etc/sudoers.d/nvt-agent \
  && mkdir -p /home/agent/.nvt-agent /home/agent/.local/bin \
  && chown -R 1000:1000 /home/agent

RUN docker --version \
  && docker compose version

# zellij is the default session driver; tmux (installed above) stays available
# via runtime.session.driver: tmux.
ARG ZELLIJ_VERSION=v0.44.3
RUN set -eux; \
  arch="$(uname -m)"; \
  case "$arch" in \
    x86_64) zj_arch=x86_64 ;; \
    aarch64|arm64) zj_arch=aarch64 ;; \
    *) echo "unsupported arch for zellij: $arch" >&2; exit 1 ;; \
  esac; \
  curl -fsSL "https://github.com/zellij-org/zellij/releases/download/${ZELLIJ_VERSION}/zellij-${zj_arch}-unknown-linux-musl.tar.gz" \
    | tar -xz -C /usr/local/bin zellij; \
  chmod +x /usr/local/bin/zellij; \
  zellij --version

RUN curl -fsSL https://mise.run \
  | MISE_INSTALL_PATH=/usr/local/bin/mise sh

RUN curl -fsSL https://code-server.dev/install.sh \
  | sh -s -- --method=standalone --prefix=/usr/local

RUN npm install -g @openai/codex @anthropic-ai/claude-code

COPY runtime/core/entrypoint.sh /usr/local/bin/entrypoint
COPY runtime/core/nvt-as-root /usr/local/bin/nvt-as-root
COPY runtime/core/bootstrap.py /usr/local/bin/bootstrap
COPY runtime/core/run-plugins.py /usr/local/bin/run-plugins
COPY runtime/core/export-plugin-tools.py /usr/local/bin/export-plugin-tools
COPY runtime/core/health.py /usr/local/bin/health
COPY runtime/core/doctor.py /usr/local/bin/doctor
COPY runtime/core/agent-capture.sh /usr/local/bin/agent-capture
COPY runtime/core/prompt-agent.sh /usr/local/bin/prompt-agent
COPY runtime/core/brokerctl.py /usr/local/bin/brokerctl
COPY runtime/core/write-agent-instructions.sh /usr/local/bin/write-agent-instructions
COPY runtime/core/start-code-server.sh /usr/local/bin/start-code-server
COPY runtime/core/start-agent-session.sh /usr/local/bin/start-agent-session
COPY runtime/core/start-agent-session.py /usr/local/bin/start-agent-session-exec
COPY runtime/core/agent-session.py /usr/local/bin/agent-session
COPY runtime/agentd/agentd.py /usr/local/bin/agentd
COPY runtime/agentd/agentdctl.py /usr/local/bin/agentdctl
COPY runtime/plugins /usr/local/lib/nvt-agent/plugins

RUN chmod +x \
  /usr/local/bin/entrypoint \
  /usr/local/bin/nvt-as-root \
  /usr/local/bin/bootstrap \
  /usr/local/bin/run-plugins \
  /usr/local/bin/export-plugin-tools \
  /usr/local/bin/health \
  /usr/local/bin/doctor \
  /usr/local/bin/agent-capture \
  /usr/local/bin/prompt-agent \
  /usr/local/bin/brokerctl \
  /usr/local/bin/write-agent-instructions \
  /usr/local/bin/start-code-server \
  /usr/local/bin/start-agent-session \
  /usr/local/bin/start-agent-session-exec \
  /usr/local/bin/agent-session \
  /usr/local/bin/agentd \
  /usr/local/bin/agentdctl \
  /usr/local/lib/nvt-agent/plugins/checkout-repos/run.py \
  /usr/local/lib/nvt-agent/plugins/git-credentials/run.py \
  /usr/local/lib/nvt-agent/plugins/git-credentials/git-credential-nvt.py \
  /usr/local/lib/nvt-agent/plugins/git-host-credentials/git-host-credential.py \
  /usr/local/lib/nvt-agent/plugins/git-host-credentials/gh-auth.py \
  /usr/local/lib/nvt-agent/plugins/event-webhook/run.py \
  /usr/local/lib/nvt-agent/plugins/initial-prompt/run.py \
  /usr/local/lib/nvt-agent/plugins/smoke-complete/run.py \
  /usr/local/lib/nvt-agent/plugins/github-watcher/run.py \
  /usr/local/lib/nvt-agent/plugins/github-watcher/github-watch.py \
  && mkdir -p /workspace /root/.nvt-agent

WORKDIR /workspace
HEALTHCHECK --interval=10s --timeout=2s --start-period=30s --retries=3 CMD health
ENTRYPOINT ["/usr/local/bin/entrypoint"]
