# Claude Code auth through the broker

This document explains how to drive Claude Code from broker-managed credentials,
the Claude analogue of the Codex broker auth direction. It covers the two
authentication mechanisms Claude Code uses and the two materialization modes for
each.

The design keeps runtime core, `agentd`, and `egressd` generic: no
Claude-specific logic lives in bootstrap or the sidecar. The Claude file shape
lives entirely in the `claude-oauth` broker provider
(`broker/plugins/claude_oauth/`); bootstrap materializes the placeholder file by
the returned relative `path`, and `egressd` injects the returned headers with no
provider-specific code. The contract is pinned in `protocol/broker.md`
("Claude OAuth Provider Rules") and `protocol/injection.md`.

## Which mechanism do you have?

Claude Code authenticates one of two ways:

1. **API key** — an Anthropic API key sent as the `x-api-key` header. This is
   the simplest path and needs **no new provider**: a generic `token` provider
   already injects it (see [API key](#api-key-mechanism) below).
2. **Subscription OAuth** (Claude Pro/Max) — an OAuth access/refresh token pair
   stored in `~/.claude/.credentials.json` under a `claudeAiOauth` object, sent
   as `authorization: Bearer <access token>` to `api.anthropic.com`. This is
   what the `claude-oauth` provider is for.

## API key mechanism

No `claude-oauth` provider is needed. Configure a `token` provider that injects
the key as `x-api-key` (no `Bearer` scheme) with the required version header:

```yaml
providers:
  - name: anthropic-key
    plugin: token
    config:
      token-env: ANTHROPIC_API_KEY          # real key, broker-side only
      injection-hosts:
        - api.anthropic.com
      injection-header: x-api-key
      injection-scheme: ""                   # inject the raw key, no scheme
      injection-extra-headers:
        anthropic-version: "2023-06-01"
    allow:
      repositories:
        - my-user/my-repo
```

Grant it `materialization: header-inject` to the agent and pair an `egress`
identity (see `protocol/injection.md`). The agent runs with the documented
placeholder `NVT-PLACEHOLDER-NOT-A-KEY` in `ANTHROPIC_API_KEY`; `egressd` strips
it and injects the real key on allowed `api.anthropic.com` requests. This path
is proven by `TestAnthropicProviderAgnosticismProof` in `tests/broker`.

## Subscription OAuth mechanism (`claude-oauth`)

The broker holds the real `~/.claude/.credentials.json` and materializes either
a usable copy (direct) or an inert placeholder (mediated) into the agent.

### Broker-side credential source

Point the provider at the credential with exactly one of:

- `credentials-file`: an absolute host path to `.credentials.json`. This is the
  durable, refreshable source — required for broker-side token refresh (see
  [Broker-side token refresh](#broker-side-token-refresh)).
- `credentials-env`: the name of an env var holding the JSON (broker sidecar /
  Kubernetes secret). No host path required. Read-only: it is never
  network-refreshed (a rotation cannot be persisted back to an env var), so use
  it only when an out-of-band process keeps the credential fresh.

`claude-oauth` defaults to the refresh request shape observed from Claude Code
CLI 2.1.205. This is empirical compatibility, not a documented stable contract:

- `token-url`: `https://platform.claude.com/v1/oauth/token`
- `client-id`: `9d1c250a-e61b-44d9-88ed-5944d1962f5e`
- `refresh-scope`: `user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload`
- `user-agent`: `axios/1.15.2`

The refresh request does not send `anthropic-beta`. API beta headers are a
separate concern and must be configured explicitly under
`injection-extra-headers`.

The client id identifies the Claude Code OAuth application, not your
subscription. It is not a secret, and the Claude `.credentials.json` file does
not carry it. Anthropic does not document these observed values as a stability
contract, so production deployments can override them with `token-url`,
`client-id` / `client-id-env`, `refresh-scope` / `refresh-scope-env`, and
`user-agent` / `user-agent-env` if Claude Code changes.

To seed a local dev credential, log in with Claude Code once on a trusted host
and copy the resulting `~/.claude/.credentials.json` to the broker-side path.
The file is broker-owned; it never needs to exist inside the agent container.

### Direct / local fallback mode

Vends a usable `.credentials.json` into the agent. This is the insecure
dev/fallback path — the agent holds the real access and refresh token.

Broker provider:

```yaml
providers:
  - name: claude-main
    plugin: claude-oauth
    config:
      credentials-file: /broker-secrets/claude/.credentials.json
      refresh-margin-seconds: 600
```

Agent grant (file-bundle is the default materialization):

```yaml
agents:
  - id: frontend
    token-sha256: sha256:<hash>
    grants:
      - provider: claude-main
```

Runtime `broker-auth-files` bundle to place the file under the agent's `.claude`
directory (use the agent home, e.g. `/root/.claude` or `/home/agent/.claude`):

```yaml
bundles:
  - provider: claude-main
    target: /root/.claude
```

The provider vends a single file named `.credentials.json`; the plugin writes it
to `<target>/.credentials.json` (mode `0600`). `target` is an absolute path (the
plugin does not expand `~`).

### Mediated mode (zero-possession)

The agent receives only an inert placeholder `.credentials.json`
(`accessToken`/`refreshToken` = `NVT-PLACEHOLDER-NOT-A-KEY`, far-future
`expiresAt`, real non-secret subscription metadata copied through). `egressd`
injects the real Bearer token on allowed Anthropic hosts such as
`api.anthropic.com` and `mcp-proxy.anthropic.com`. No real Claude credential is
ever present in the agent filesystem, env, or process args.

Broker provider:

```yaml
providers:
  - name: claude-main
    plugin: claude-oauth
    config:
      credentials-file: /broker-secrets/claude/.credentials.json
      refresh-margin-seconds: 600
      injection-hosts:
        - api.anthropic.com
        - mcp-proxy.anthropic.com
      injection-extra-headers:
        anthropic-beta: oauth-2025-04-20
      placeholder-file:
        path: .claude/.credentials.json
        hosts:
          - api.anthropic.com
          - mcp-proxy.anthropic.com
```

Agent + paired egress identity:

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

A single `placeholder-file` grant does double duty: it authorizes the agent to
fetch the placeholder file **and** authorizes the paired egress identity to
fetch the real Bearer token from `/v1/injection/headers`. No separate
`header-inject` grant is required. The placeholder file is materialized by
runtime bootstrap (`apply_placeholder_files`), which is fully generic.

Mediated mode is opt-in: it activates only when a grant carries
`materialization: placeholder-file` (or `header-inject`) and the provider
declares `injection-hosts`. Without those, `claude-oauth` behaves as a
direct/file-bundle provider only.

## Security properties

- The real `accessToken`/`refreshToken` are never emitted by
  `/v1/placeholder-files`, on any path including errors.
- A `placeholder-file` grant is denied on every secret-bearing endpoint
  (`/v1/files`, `/v1/token`, `/v1/headers`) with `materialization-mismatch`.
- Injection is authorized only for the `egress` role and only for the
  capability granted to its paired agent; the agent itself cannot fetch the
  Bearer token, and an egress paired to a different agent is denied.
- Injected header values never appear in the audit log, on allow or deny paths.

These are pinned by `tests/broker/claude_auth_conformance_test.go` and
`tests/broker/placeholder_config_validation_test.go`.

## Broker-side token refresh

The broker refreshes the broker-owned Claude OAuth access token before
file-bundle vending and edge injection when `claudeAiOauth.expiresAt` is within
`refresh-margin-seconds` (default 900). Claude credentials expose only the
access-token `expiresAt` (refresh-token expiry is unknown), so refresh is
proactive — ahead of expiry — rather than reactive to a 401. Successful refresh
uses the configured or default `token-url`, `client-id`, `refresh-scope`,
`user-agent`, and broker-owned `refreshToken`, then persists the
new `accessToken`, rotated `refreshToken` when returned, and recomputed
`expiresAt`.

Refresh is **single-flight**: concurrent callers collapse to at most one
upstream refresh. Serialization is both in-process (a thread lock) and
cross-process (an advisory `flock` on a lock file beside `credentials-file`,
shared with the manual probe), so a second broker instance or the probe cannot
run a competing refresh-token exchange that invalidates the rotation. A queued
caller re-reads the just-refreshed credential instead of calling upstream. After
a transient failure (HTTP 429/5xx/network) the sanitized failure is cached for
`refresh-cooldown-seconds` (default 90, jittered, exponential backoff up to
`refresh-cooldown-max-seconds`) so Claude Code retries cannot storm the OAuth
endpoint. A request served from the cooldown makes no upstream call and emits no
refresh audit event; a genuine upstream-refresh failure is audited once (a
sanitized `<operation>.refresh` event with `allowed: false` and the reason, no
token material) even when a still-valid token is then served.

Placeholder-file vending does **not** trigger a refresh: the placeholder carries
only inert tokens with a far-future expiry, so a placeholder fetch stays a pure
custody proof and adds no upstream load.

This is required for **mediated** mode: the agent receives only placeholder
credentials, so it cannot self-refresh. If refresh fails while the current
access token is still valid, the broker serves the current token and logs the
fallback without exposing token bytes. If the token is expired, the mediated
injection request fails closed with a sanitized reason —
`token-refresh-rate-limited` (429),
`token-refresh-login-required` (`invalid_grant`/`unauthorized_client`, 400/401/403),
or `token-refresh-failed` (5xx/network). Only the upstream HTTP status and a safe
OAuth error class ever reach error messages or audit; token bytes, `Authorization`
headers, request bodies, and raw response bodies never do.

The **direct** `/v1/files` path is different: it is a possession path where the
agent holds the refresh token, so even when the access token is expired and a
broker refresh fails, the broker still vends the well-formed (expired) real
credential and lets Claude Code self-refresh. Only the mediated injection path
fails closed on an expired token.

Use `credentials-file` for durable refresh. A `credentials-env` source is
**never network-refreshed**: a rotated credential cannot be written back to an
env var, so refreshing it only in memory would be lost on restart — after which
the broker would reload the now-stale (possibly already-rotated-away) env
refresh token, a production/Kubernetes time bomb. A `credentials-env` source
therefore serves a still-valid token and fails closed on the mediated path once
expired, and the manual probe below refuses it outright.

### Manual refresh proof

`scripts/claude-refresh-probe.py` runs a one-shot broker-side refresh against a
configured provider. On success it persists the rotated credential to the
broker-owned `credentials-file` and prints only redacted metadata (status,
credential field names, old/new `expiresAt`, rotation flag) — never token bytes.
It refuses a `credentials-env` source (which cannot persist a rotation).

The probe is **safe to run against a live broker**: it takes the same
cross-process refresh `flock` (beside `credentials-file`) that the broker's own
refresh takes, so the probe and an in-broker refresh serialize on the shared
lock rather than spending the same refresh token twice and invalidating each
other's rotation. (It is still a manual/operator tool; routine refresh is
automatic.)

The refresh path is also conformance-tested against the broker's fake OAuth
endpoint: exact request shape (JSON body including `scope`, safe headers, and
no `anthropic-beta` header),
refresh-token rotation, single-flight collapse, cross-process probe/broker
serialization, 429 cooldown/back-off, refresh-failure audit, valid-token
fallback, mediated expired-token fail-closed vs. direct expired-credential
self-refresh, `credentials-env` never-refresh, `invalid_grant` re-login
classification, and no-token-leak in responses/logs/audit are all covered.

Before treating mediated Claude refresh as production-ready, run the probe
against a copied Claude credential in the target environment and verify that
`expiresAt` and token material change only in the broker-owned credentials file
without appearing in agent placeholder files, audit logs, or responses. If
Anthropic changes the Claude Code OAuth app, set `client-id`/`client-id-env`,
`token-url`, `refresh-scope`/`refresh-scope-env`, or
`user-agent`/`user-agent-env` explicitly.

For a native-vs-broker release gate, use two independently obtained disposable
credentials in isolated trusted containers (refresh-token rotation means one
credential must not be shared between the two arms). Pin and record the Claude
Code version, run one normal non-interactive Claude request in the native arm,
and run the command below in the broker arm:

```sh
python3 scripts/claude-refresh-probe.py \
  --config /trusted/redacted-proof/broker.yaml \
  --provider claude-main >broker-refresh-summary.json
```

The gate passes only when both requests succeed, both credential files rotate,
the probe output contains metadata only, and a reviewer confirms that broker
audit/log output and the captured endpoint-facing request contain no token
values. If capturing TLS in the trusted environment, retain only the method,
URL, safe header names/values, and JSON key names; delete bodies and raw capture
files. Never commit either disposable credential or a raw capture. This manual
gate intentionally does not run in CI and must not use a production credential.
