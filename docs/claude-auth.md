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

- `credentials-file`: an absolute host path to `.credentials.json` (local dev).
- `credentials-env`: the name of an env var holding the JSON (broker sidecar /
  Kubernetes secret). No host path required.

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
injects the real Bearer token on allowed `api.anthropic.com` requests. No real
Claude credential is ever present in the agent filesystem, env, or process args.

Broker provider:

```yaml
providers:
  - name: claude-main
    plugin: claude-oauth
    config:
      credentials-file: /broker-secrets/claude/.credentials.json
      injection-hosts:
        - api.anthropic.com
      injection-extra-headers:
        anthropic-beta: oauth-2025-04-20
      placeholder-file:
        path: .claude/.credentials.json
        hosts:
          - api.anthropic.com
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

## Known limitation: broker-side token refresh

This revision does not refresh the broker-side Claude OAuth token over the
network. It serves the current access token and surfaces the real `expiresAt` as
the injection/bundle expiry ceiling. Automatic refresh (an OAuth `refresh_token`
exchange analogous to the Codex `token-url` / `client-id` flow) is intentionally
left for a follow-up so this change does not ship an unverified live-refresh path
against Anthropic's token endpoint.

The impact differs by mode:

- **Mediated mode** is the one affected. The agent holds no refresh token, so it
  cannot self-heal. Once the broker-side access token expires, its `expiresAt`
  ceiling is in the past and `egressd` fails closed (it must not serve material
  past `expires_at`), so mediated Claude stops working until the broker-side
  `.credentials.json` is refreshed out of band — for example by re-copying it
  from a host where Claude Code refreshes it, or by scripting a refresh into the
  broker sidecar. Note the broker itself does not reject a merely-expired token;
  the fail-closed behavior is enforced at the egress edge.
- **Direct / file-bundle mode** is not affected in the same way: the agent
  receives the real `refreshToken`, so Claude Code refreshes on its own. The
  broker vends the current `.credentials.json` as-is (it does not reject an
  expired-but-well-formed credential); `credentials-invalid` /
  `credentials-not-found` fire only for a missing or malformed file.
