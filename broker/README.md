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

Grant file-bundle providers by provider name; repositories are not used:

```yaml
agents:
  - id: frontend
    token-sha256: sha256:<hash>
    grants:
      - provider: codex-main
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
For `codex-oauth`, the bundle contains derived access-token material and an
inert refresh-token stub, never the real broker-owned refresh token.
`bundle-ttl-seconds` caps the returned `expires_at` metadata so the runtime
refresher replaces the file bundle frequently. OpenAI controls the issued JWT
lifetime, so this remains the file-bundle fallback rather than full
credential-less Codex.

Grant repository patterns must match the provider target mode: GitHub-mode
providers use `owner/repo`, while literal-mode providers use the full
`host/path/repo` form.
