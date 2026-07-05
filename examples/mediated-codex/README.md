# Mediated Codex (codex-oauth via egressd)

Non-secret example configs for running Codex ChatGPT-plan auth in **mediated
mode**: the broker owns the real `auth.json`, egressd injects the access token
(and any claim-derived header) at the network edge, and the agent container
holds no real credential. See `docs/mediated-egress-plan.md` and
`protocol/injection.md`.

All tokens/hashes below are placeholders — generate your own.

## Broker provider (`.broker/broker.yaml`)

```yaml
providers:
  - name: codex-main
    plugin: codex-oauth
    config:
      auth-file: /state/codex/auth.json
      refresh-margin-seconds: 3600
      # Hosts egressd may inject this credential for:
      injection-hosts:
        - chatgpt.com
        - auth.openai.com
      # Backend requires an account-id header derived from the token claims.
      # The claim key is a URL (contains dots) → list form, exact segments.
      injection-claim-headers:
        - header: chatgpt-account-id
          claim-path:
            - https://api.openai.com/auth
            - chatgpt_account_id
```

## Identities (`.broker/agents.yaml`)

An agent with a `header-inject` grant and its paired egress identity. The
egress identity is the only one that can fetch the credential; the agent
identity cannot.

```yaml
agents:
  - id: my-agent
    token-sha256: sha256:<hash of the agent broker token>
    role: agent
    grants:
      - provider: codex-main
        materialization: header-inject
  - id: my-agent-egress
    token-sha256: sha256:<hash of the egress broker token>
    role: egress
    paired-agent: my-agent
```

## egressd (`egressd.json`)

```json
{
  "broker_url": "https://broker:7347",
  "broker_ca_file": "/tls/broker-ca.pem",
  "routes": [
    {
      "listen": "127.0.0.1:8471",
      "capability": "codex-main",
      "upstream": "chatgpt.com",
      "listen_tls_cert": "/tls/egressd-cert.pem",
      "listen_tls_key": "/tls/egressd-key.pem"
    }
  ]
}
```

- `broker_url` is **https** in production; `broker_ca_file` pins its CA. The
  egressd→broker leg is the one path carrying real credentials.
- `listen_tls_*` make the agent-facing listener serve HTTPS; the agent must
  trust the serving cert's CA. Omit them only if the client accepts a
  plaintext base URL.

## Agent-side Codex config (`~/.codex/config.toml`)

```toml
check_for_update_on_startup = false
chatgpt_base_url = "https://127.0.0.1:8471"
```

## Agent-side placeholder `~/.codex/auth.json`

The agent gets a zero-entropy placeholder — never the real file. It satisfies
Codex's startup parser; the real token is injected by egressd and the
placeholder is stripped before reaching the upstream.

```json
{
  "tokens": {
    "access_token": "<placeholder JWT: header.payload.NVT-PLACEHOLDER-NOT-A-KEY>",
    "refresh_token": "nvt-broker-stub",
    "id_token": "NVT-PLACEHOLDER-NOT-A-KEY"
  },
  "last_refresh": "2020-01-01T00:00:00Z"
}
```

The placeholder JWT payload carries a far-future `exp` (so Codex does not try
to refresh locally) and a placeholder `chatgpt_account_id` (egressd strips it;
the broker injects the real one from the real token's claims).
