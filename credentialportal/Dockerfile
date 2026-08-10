FROM golang:1.25 AS build

WORKDIR /src
COPY credentialportal ./credentialportal
WORKDIR /src/credentialportal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/nvt-credential-portal ./cmd/nvt-credential-portal

FROM node:24-bookworm-slim AS cli

# Keep these independent build arguments so enrollment and AgentRun CLI
# versions can later be driven by one coordinated source of truth.
ARG CODEX_CLI_VERSION=0.147.0
ARG CLAUDE_CODE_VERSION=2.1.226
RUN npm install -g --allow-scripts=@anthropic-ai/claude-code \
  "@openai/codex@${CODEX_CLI_VERSION}" \
  "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}"

FROM node:24-bookworm-slim
COPY --from=cli /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN ln -s ../lib/node_modules/@openai/codex/bin/codex.js /usr/local/bin/codex \
  && ln -s ../lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe /usr/local/bin/claude
COPY --from=build /out/nvt-credential-portal /nvt-credential-portal
USER node:node
EXPOSE 8080
ENTRYPOINT ["/nvt-credential-portal"]
