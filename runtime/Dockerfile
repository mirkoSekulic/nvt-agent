ARG BASE_IMAGE=ghcr.io/catthehacker/ubuntu:act-24.04
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive
ENV NVT_WORKSPACE=/workspace
ENV CODE_SERVER_PORT=4090

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    python3-yaml \
    ripgrep \
    tmux \
  && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://mise.run \
  | MISE_INSTALL_PATH=/usr/local/bin/mise sh

RUN curl -fsSL https://code-server.dev/install.sh \
  | sh -s -- --method=standalone --prefix=/usr/local

RUN npm install -g @openai/codex @anthropic-ai/claude-code

COPY runtime/core/entrypoint.sh /usr/local/bin/entrypoint
COPY runtime/core/bootstrap.py /usr/local/bin/bootstrap
COPY runtime/core/run-plugins.py /usr/local/bin/run-plugins
COPY runtime/core/prompt-agent.sh /usr/local/bin/prompt-agent
COPY runtime/core/write-agent-instructions.sh /usr/local/bin/write-agent-instructions
COPY runtime/core/start-code-server.sh /usr/local/bin/start-code-server
COPY runtime/core/start-agent-session.sh /usr/local/bin/start-agent-session
COPY runtime/plugins /usr/local/lib/nvt-agent/plugins

RUN chmod +x \
  /usr/local/bin/entrypoint \
  /usr/local/bin/bootstrap \
  /usr/local/bin/run-plugins \
  /usr/local/bin/prompt-agent \
  /usr/local/bin/write-agent-instructions \
  /usr/local/bin/start-code-server \
  /usr/local/bin/start-agent-session \
  /usr/local/lib/nvt-agent/plugins/checkout-repos/run.py \
  /usr/local/lib/nvt-agent/plugins/git-credentials/run.py \
  /usr/local/lib/nvt-agent/plugins/git-credentials/git-credential-nvt.py \
  && mkdir -p /workspace /root/.nvt-agent

WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/entrypoint"]
