# Claude Code Authentication

nvt supports Claude Code API keys and subscription OAuth credentials. Both can
run in direct mode or behind mediated egress.

Claude-specific file shape and refresh behavior live in the `claude-oauth`
broker provider. Runtime core, `agentd`, `captured`, and `egressd` remain
provider-agnostic.

## API Key

A generic token provider can inject an Anthropic API key; no Claude-specific
provider is required:

```yaml
providers:
  - name: anthropic-key
    plugin: token
    config:
      token-env: ANTHROPIC_API_KEY
      injection-hosts: [api.anthropic.com]
      injection-header: x-api-key
      injection-scheme: ""
      injection-extra-headers:
        anthropic-version: "2023-06-01"
    allow:
      repositories: [my-user/my-repo]
```

Grant the provider with `materialization: header-inject`. The agent receives an
inert placeholder while egressd injects the real key at the approved host.

## Subscription OAuth

Claude Code stores subscription credentials in
`~/.claude/.credentials.json` under `claudeAiOauth`. Configure a
`claude-oauth` provider with a durable broker-owned credential file:

```yaml
providers:
  - name: claude-main
    plugin: claude-oauth
    config:
      credentials-file: /broker-secrets/claude/.credentials.json
      refresh-margin-seconds: 600
      refresh-expiry-warning-seconds: 432000
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

Seed this file by logging in with Claude Code in a trusted environment. The
credential is import material for the broker; mediated agents never receive a
usable copy.

`credentials-env` is also supported, but it cannot persist refresh-token
rotation. Use it only when another system continuously replaces the credential.
Production OAuth refresh should use `credentials-file`.

### OAuth Client Compatibility

The provider defaults to the Claude Code OAuth request shape verified by the
test suite:

- token URL: `https://platform.claude.com/v1/oauth/token`
- client ID: `9d1c250a-e61b-44d9-88ed-5944d1962f5e`
- scopes: `user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload`
- user agent: `axios/1.15.2`

The client ID identifies the Claude Code OAuth application, not an individual
subscription, and is not secret. Anthropic does not publish these values as a
stable external contract. Override `token-url`, `client-id`, `refresh-scope`,
or `user-agent` if a future Claude Code release changes them.

## Direct Mode

Direct mode grants `file-bundle` and writes a usable credential into the agent:

```yaml
agents:
  - id: frontend
    token-sha256: sha256:<hash>
    grants:
      - provider: claude-main
        materialization: file-bundle
```

The `broker-auth-files` plugin writes `.credentials.json` under its configured
absolute target. This is a compatibility path, not credential non-possession.

## Mediated Mode

Mediated mode grants `placeholder-file` and pairs a separate egress identity:

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

The agent receives a valid-looking file whose access and refresh fields contain
`NVT-PLACEHOLDER-NOT-A-KEY`. The same grant authorizes the paired egress
identity to obtain the real Bearer header. No additional header-inject grant is
needed.

For enforced Kubernetes workloads, combine mediated mode with transparent
transport. This prevents tools from bypassing egressd while allowing ordinary
non-injection traffic as policy-approved blind tunnels.

## First-Run State

A credentials file alone does not start a session: Claude Code first runs an
interactive first-run wizard (onboarding, login method, workspace trust) that a
headless session can never answer. When `runtime.command` is `claude`,
bootstrap seeds `~/.claude.json` with onboarding completed and the workspace
trusted so the session starts directly. An existing `~/.claude.json` is left
untouched; this seeding is independent of egress mode and of the credentials
file.

## Refresh

Before injection or direct file vending, the broker refreshes when `expiresAt`
enters `refresh-margin-seconds` (default 900). A successful exchange durably
persists the new access token, any rotated refresh token, access expiry,
returned refresh-token expiry, granted scopes, and OAuth client ID. Older
credentials or responses may omit refresh-token expiry; in that case the
existing value is preserved.

Rotation and lifetime extension are separate: a new refresh token can retain
the old token's absolute expiry. Monitor the persisted
`refreshTokenExpiresAt` and replace the broker credential from a trusted login
before it lapses; once it expires, interactive login is required. The provider
logs one sanitized warning when the authorization enters
`refresh-expiry-warning-seconds` (default five days).

Refresh is single-flight in-process and protected across processes by a lock
beside the credential file. Transient failures use bounded cooldown and
backoff. If refresh fails:

- a still-valid access token may continue until its real expiry;
- an expired token fails closed in mediated mode;
- errors expose only a sanitized class such as rate-limited, login-required,
  or refresh-failed;
- token values and response bodies never enter logs or audit events.

Credential replacement is written and `fsync`ed before atomic rename. The
canonical file is intentionally forced to mode `0600`; deployments must not
depend on group-readable broker credentials. The parent directory is then
`fsync`ed when the filesystem supports it; a post-rename directory-`fsync`
failure is logged as reduced crash durability without misreporting the completed
replacement as a content failure. If rename itself fails after Anthropic has
rotated the token, a uniquely named mode-`0600` temporary file is retained
beside the canonical credential as the recovery copy. A still-valid canonical
access token may continue during cooldown; expired use fails closed with
`token-refresh-persist-failed`.

Placeholder-file vending does not itself refresh because the file contains no
usable token.

### Manual Refresh Proof

Run the broker-side probe against a copied credential before production use:

```sh
python3 scripts/claude-refresh-probe.py \
  --config /trusted/proof/broker.yaml \
  --provider claude-main
```

The probe uses the same cross-process lock as the broker, persists rotation,
and prints only metadata such as old/new access and refresh expiry and whether
the refresh token rotated.
It refuses `credentials-env` because rotation cannot be persisted there.

Never run competing native and broker refreshes against the same refresh token.
Use disposable credentials when comparing Claude Code and broker behavior.

## Verification

The broker suites cover placeholder non-possession, identity pairing, request
shape, refresh rotation, concurrency, cooldown, expired-token failure,
`credentials-env` behavior, and sanitized errors. See
`tests/broker/claude_auth_conformance_test.go` and
`tests/broker/placeholder_config_validation_test.go`.

The normative provider and injection rules are in the
[broker protocol](../protocol/broker.md) and
[injection protocol](../protocol/injection.md).
