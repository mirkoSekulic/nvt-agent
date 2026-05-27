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
```

`http request` keeps the derived GitHub token inside the broker. `token` is a
compatibility mode for tools that need a token, mainly Git credential helpers.
`identity` returns provider commit identity metadata after the same agent grant
check; GitHub App providers return the App bot name and noreply email.
`headers` is a compatibility mode for static Git headers. Returned headers are
visible to the agent and may be written into Git config.
