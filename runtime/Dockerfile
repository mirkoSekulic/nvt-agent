ARG BASE_IMAGE=ghcr.io/catthehacker/ubuntu:act-24.04
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive
ENV NVT_WORKSPACE=/workspace
ENV CODE_SERVER_PORT=4090

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ripgrep \
    tmux \
  && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://code-server.dev/install.sh \
  | sh -s -- --method=standalone --prefix=/usr/local

RUN npm install -g @openai/codex @anthropic-ai/claude-code

COPY runtime/entrypoint.sh /usr/local/bin/nvt-agent-entrypoint
COPY runtime/start-code-server.sh /usr/local/bin/nvt-start-code-server
COPY runtime/start-agent-session.sh /usr/local/bin/nvt-start-agent-session

RUN chmod +x \
  /usr/local/bin/nvt-agent-entrypoint \
  /usr/local/bin/nvt-start-code-server \
  /usr/local/bin/nvt-start-agent-session \
  && mkdir -p /workspace /root/.nvt-agent

WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/nvt-agent-entrypoint"]
