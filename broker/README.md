# nvt broker

`brokerd` is the trusted authority service for nvt-agent. It is deployed
separately from the agent runtime and owns root secrets, derived token caches,
broker-executed API requests, and audit logs.

The agent image contains only `brokerctl`.

## Local Run

```sh
export NVT_BROKER_CONFIG=/path/to/broker.yaml
export NVT_BROKER_AUDIT_LOG=/tmp/nvt-broker-audit.jsonl
export NVT_BROKER_BIND=127.0.0.1:7347
python3 broker/brokerd.py
```

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

```sh
brokerctl health

brokerctl http request \
  --provider fork-app \
  --method GET \
  --url https://api.github.com/repos/my-user/my-repo/pulls/123

brokerctl token \
  --provider fork-app \
  --target github.com/my-user/my-repo \
  --purpose git-push
```

`http request` keeps the derived GitHub token inside the broker. `token` is a
compatibility mode for tools that need a token, mainly Git credential helpers.
