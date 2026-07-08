# nvt broker

`brokerd` is the trusted authority service for nvt-agent. It is deployed
separately from the agent runtime and owns root secrets, derived token caches,
broker-executed API requests, and audit logs.

The agent image contains only `brokerctl`.

## Local Run

```sh
export NVT_BROKER_CONFIG=/path/to/broker.yaml
export NVT_BROKER_AGENTS_CONFIG=/path/to/agents.yaml
export NVT_BROKER_AUDIT_LOG=/tmp/nvt-broker-audit.jsonl
export NVT_BROKER_BIND=127.0.0.1:7347
python3 broker/brokerd.py
```

Example agents config:

```yaml
agents:
  - id: frontend
    token-sha256: sha256:<hash>
    grants:
      - provider: fork-app
        repositories:
          - my-user/my-repo
```

`agents.yaml` is live-reloaded. Provider config is loaded at startup.

Example config:

```yaml
providers:
  - name: fork-app
    plugin: github-app
    config:
      app-id-env: GITHUB_APP_ID
      installation-id-env: GITHUB_APP_INSTALLATION_ID
      private-key-base64-env: GITHUB_APP_PRIVATE_KEY_BASE64
      api-url: https://api.github.com
    allow:
      repositories:
        - my-user/my-repo
      permissions:
        contents: read
        pull_requests: read
        checks: read
      methods:
        - GET
```

Codex OAuth file-bundle provider example:

```yaml
providers:
  - name: codex-main
    plugin: codex-oauth
    config:
      auth-file: /broker-secrets/codex/auth.json
      token-url: https://auth.openai.com/oauth/token
      client-id: app_EMoamEEZ73f0CkXaXp7hrann
      refresh-margin-seconds: 600
      bundle-ttl-seconds: 1200
      stub-refresh-token: nvt-broker-stub
      extra-files:
        - name: config.toml
          path: /broker-secrets/codex/config.toml
        - name: installation_id
          path: /broker-secrets/codex/installation_id
```

Claude Code OAuth provider example. Direct/file-bundle mode (dev/fallback,
agent receives the real credential):

```yaml
providers:
  - name: claude-main
    plugin: claude-oauth
    config:
      credentials-file: /broker-secrets/claude/.credentials.json
      token-url: https://platform.claude.com/v1/oauth/token
      client-id: <claude-code-oauth-client-id>
      refresh-margin-seconds: 600
```

Mediated mode (zero-possession; the agent gets an inert placeholder file and
the real Bearer token is injected at the edge for the paired egress identity):

```yaml
providers:
  - name: claude-main
    plugin: claude-oauth
    config:
      credentials-file: /broker-secrets/claude/.credentials.json
      token-url: https://platform.claude.com/v1/oauth/token
      client-id: <claude-code-oauth-client-id>
      refresh-margin-seconds: 600
      injection-hosts:
        - api.anthropic.com
      injection-extra-headers:
        anthropic-beta: oauth-2025-04-20
      placeholder-file:
        path: .claude/.credentials.json
        hosts:
          - api.anthropic.com
```

Grant file-bundle providers by provider name; repositories are not used:

```yaml
agents:
  - id: frontend
    token-sha256: sha256:<hash>
    grants:
      - provider: codex-main
```

For mediated Claude, the agent holds a `placeholder-file` grant and its paired
egress identity injects the real token (see `docs/claude-auth.md`). Because the
agent receives only placeholder credentials, the broker refreshes the
broker-owned Claude OAuth token before vending files or injection headers:

```yaml
agents:
  - id: frontend
    token-sha256: sha256:<hash>
    grants:
      - provider: claude-main
        materialization: placeholder-file
  - id: frontend-egress
    token-sha256: sha256:<hash>
    role: egress
    paired-agent: frontend
```

## Client

`brokerctl health` does not require a token. Other commands require
`NVT_BROKER_TOKEN` and are normally run from inside an initialized agent
container.

```sh
brokerctl health

export NVT_BROKER_TOKEN=<agent-token>

brokerctl http request \
  --provider fork-app \
  --method GET \
  --url https://api.github.com/repos/my-user/my-repo/pulls/123

brokerctl token \
  --provider fork-app \
  --target github.com/my-user/my-repo \
  --purpose git-push

brokerctl identity \
  --provider fork-app \
  --target github.com/my-user/my-repo

brokerctl headers \
  --provider company-headers \
  --target github.com/my-user/my-repo \
  --raw

brokerctl files \
  --provider codex-main
```

`http request` keeps the derived GitHub token inside the broker. `token` is a
compatibility mode for tools that need a token, mainly Git credential helpers.
`identity` returns provider commit identity metadata after the same agent grant
check; GitHub App providers return the App bot name and noreply email.
`headers` is a compatibility mode for static Git headers. Returned headers are
visible to the agent and may be written into Git config.
`files` returns a UTF-8 file bundle for generic runtime materialization.
For `codex-oauth`, the bundle contains the real OpenAI access token and an
inert refresh-token stub, never the real broker-owned refresh token.
For `claude-oauth`, mediated placeholder bundles contain no real Claude tokens;
the broker owns and refreshes the canonical `claudeAiOauth` access/refresh
tokens when `credentials-file` is used. `credentials-env` is read-only and
fails loudly if a refresh would be required. The refresh path is implemented
and conformance-tested against the broker's fake OAuth endpoint; real Claude
endpoint/client-id proof is still required before treating mediated Claude
refresh as production-ready.
The broker applies file-bundle TTL caps to returned `expires_at` metadata so
runtime refreshers can re-materialize bundles on a bounded cadence. For
`codex-oauth`, this does not reduce the lifetime of an already-issued OpenAI
access token. Codex file bundles remain the insecure/compatibility fallback
until credential-less Codex ships. The canonical contract and cadence guard are
in `protocol/broker.md`.

Grant repository patterns must match the provider target mode: GitHub-mode
providers use `owner/repo`, while literal-mode providers use the full
`host/path/repo` form.
