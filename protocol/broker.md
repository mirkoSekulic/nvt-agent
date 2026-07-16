# broker Protocol

`brokerd` is the trusted authority API for nvt-agent. It is the trusted-side
counterpart to `agentd`:

```text
agentd   session and event API in the untrusted agent runtime
brokerd  secret, credential, and broker-executed request boundary
```

The agent image contains only `brokerctl`, a thin client. `brokerd`, provider
implementations, root secrets, token caches, and audit logs live in a separate
broker image/service.

Administrators can also register trusted, language-agnostic executable provider
implementations. Their configuration, JSON-RPC transport, supervision, and
security contract are specified in [broker-provider.md](broker-provider.md).

## Transport

V1 uses HTTP JSON. `brokerctl` hides the transport so later deployments can use
a Unix socket, sidecar, mTLS service, or service mesh without changing plugin
commands.

Default local bind:

```text
127.0.0.1:7347
```

Docker Compose and Kubernetes must override this with an internal-only service
interface. V1 local mode has bearer-token agent identity for broker grants, but
not production-grade workload identity. Reachability still matters: do not
publish the broker to untrusted networks.

Local multi-agent Compose mode uses bearer-token agent identity. Agents send:

```text
Authorization: Bearer <NVT_BROKER_TOKEN>
```

The broker stores only `sha256:<hash>` values in its live-reloaded agents
config. `/health` is token-free; capability endpoints require a valid token.

## Endpoints

### GET /health

Returns:

```json
{"ok":true,"status":"ready"}
```

### POST /v1/http/request

Broker-executed HTTP request. This is the v1 zero-token path for GitHub API
reads.

Request:

```json
{
  "provider": "fork-app",
  "method": "GET",
  "url": "https://api.github.com/repos/my-user/my-repo/pulls/123",
  "headers": {
    "accept": "application/vnd.github+json",
    "if-none-match": "\"etag\""
  },
  "paginate": false
}
```

Requires `Authorization: Bearer ...`.

Response:

```json
{
  "ok": true,
  "status": 200,
  "headers": {
    "x-ratelimit-remaining": "4999"
  },
  "body": "{\"number\":123}"
}
```

Non-2xx upstream status codes are still successful broker transport responses
with `ok: true`; callers inspect `status`.

### POST /v1/token

Compatibility endpoint for tools that require a token, mainly Git credential
helpers.

Request:

```json
{
  "provider": "fork-app",
  "target": "github.com/my-user/my-repo",
  "purpose": "git-push"
}
```

Requires `Authorization: Bearer ...`.

Response:

```json
{"ok":true,"token":"...","expires_at":"..."}
```

Token mode is not full zero-trust because the agent receives a derived token.
For GitHub App providers this derived token is short-lived and repo-scoped. For
static token providers, the agent receives the static token itself; this is a
compatibility path, not a zero-trust path. The root secret still stays out of
agent env/config.

### POST /v1/headers

Compatibility endpoint for tools that require static HTTP headers, mainly Git
`http.<url>.extraHeader` configuration.

Request:

```json
{
  "provider": "company-headers",
  "target": "github.com/my-user/my-repo"
}
```

Requires `Authorization: Bearer ...`.

Response:

```json
{"ok":true,"headers":["X-API-Key: ..."]}
```

Header mode is not zero-trust for Git. The returned headers are written into
the agent's Git config by `git-credentials`, so the agent can read them. The
benefit over in-agent env secrets is central broker grants, audit, and keeping
the original secret env vars out of the agent container.

### POST /v1/files

Returns a provider-vended UTF-8 file bundle.

Request:

```json
{
  "provider": "codex-main"
}
```

Requires `Authorization: Bearer ...`.

Response:

```json
{
  "ok": true,
  "files": [
    {"name": "auth.json", "content": "{\"tokens\":{}}\n", "mode": "0600"}
  ],
  "expires_at": "2026-07-03T12:00:00Z"
}
```

Rules:

- `name` must be a plain relative filename: non-empty, no `/`, no `\`, and no
  `..`.
- `content` is a UTF-8 string. V1 does not use base64.
- `mode` is optional per file, a four-digit octal string, and defaults to
  `"0600"` when omitted.
- `expires_at` is the UTC RFC3339 time when the bundle should be considered
  stale. `null` means the bundle does not expire.
- Authorization uses the same bearer-token agent identity as other capability
  endpoints. File providers are default-deny: the authenticated agent must have
  an explicit grant entry for the provider.
- Repository grants do not apply to file providers. The minimal grant is a
  grant object naming the provider with no repositories:

```yaml
agents:
  - id: frontend
    token-sha256: sha256:<hash>
    grants:
      - provider: codex-main
```

Unknown providers, missing grants, and provider failures use the same
`{"ok":false,"error":"...","message":"..."}` error shape and status
conventions as `/v1/token`.

### POST /v1/placeholder-files

Returns a provider-materialized **placeholder** file: a syntactically valid
auth/config file whose secret fields carry only inert placeholders. This is
the `placeholder-file` materialization mode — **distinct from `file-bundle`**.
`file-bundle` writes usable credential material into the agent (the
dev/fallback path); `placeholder-file` never does. The real secret values stay
in broker/provider custody and are injected at the network edge,
so a file-based tool can start against a local auth file it accepts while the
agent holds no real credential.

Request: `{"provider": "codex-main"}`. Requires an `agent`-role bearer token
whose identity holds a `placeholder-file` grant for the provider.

Response:

```json
{
  "ok": true,
  "files": [
    {"path": ".codex/auth.json", "content": "{ ... placeholders ... }\n", "mode": "0600"}
  ],
  "hosts": ["chatgpt.com", "api.openai.com", "auth.openai.com"],
  "expires_at": null
}
```

Rules:

- `path` is a **relative** path under the agent home (subdirectories allowed);
  absolute paths and `.`/`..`/empty segments are refused. `content` is a UTF-8
  string; `mode` is a four-digit octal string (default `"0600"`).
- Secret fields are placeholders only, on every path including errors. The two
  placeholder shapes: `plain` (the zero-entropy `NVT-PLACEHOLDER-NOT-A-KEY`)
  and `jwt` (a syntactically valid JWT carrying only non-secret identity claims
  plus a far-future `exp`, with a placeholder signature — for tools that parse
  local token claims before any network call). Non-secret literal fields are
  emitted verbatim.
- `hosts` are the upstream hosts the placeholder's real credential is valid
  for; consumed by the forward-proxy route/injection map. Not a
  secret.
- Scoped exactly like every other grant: the agent fetches only its own
  bindings, and a `placeholder-file` grant is denied on `/v1/token`,
  `/v1/headers`, and `/v1/files` (`materialization-mismatch`) — the real
  secret is unreachable everywhere.
- **Injection-eligible**: `/v1/injection/headers` accepts a `placeholder-file`
  grant, so the same grant both materializes the placeholder file and lets the
  edge inject the real credential (no second `header-inject` grant for the
  provider is needed). This functions only for providers that also implement
  injection (an `injection_headers` method plus `injection-hosts`), such as the
  Codex preset; the generic `placeholder` provider is materialization-only and
  returns `injection-not-supported`.
- `egress`-role identities are refused; the placeholder file is inert and
  agent-owned.
- Error shape and status conventions match `/v1/token`.

### POST /v1/identity

Returns commit identity metadata for a broker provider after applying the same
agent grant check as token/http requests.

Request:

```json
{
  "provider": "fork-app",
  "target": "github.com/my-user/my-repo"
}
```

Requires `Authorization: Bearer ...`.

Response:

```json
{
  "ok": true,
  "name": "my-agent-app[bot]",
  "email": "123456789+my-agent-app[bot]@users.noreply.github.com"
}
```

For GitHub App providers, the broker fetches app metadata with the App JWT,
then fetches the bot user account. The email prefix is the bot user's numeric
id, not the App id and not the installation id. The target is used for
authorization; the identity itself is provider/app-level and cached by the
provider process.

## GitHub App Provider Rules

The GitHub App provider validates before injecting auth:

- request method must be allowed, and v1 should use `GET` for HTTP execution
- request scheme and host must exactly match configured `api-url`
- no URL userinfo
- path must match `/repos/{owner}/{repo}/...`
- extracted repo must match configured `allow.repositories`
- redirects are disabled
- caller `authorization`, `cookie`, `host`, and proxy headers are never
  forwarded

The configured upstream is the only allowed host. Production uses
`https://api.github.com`; tests may configure `http://127.0.0.1:<port>` as the
upstream. Internal/metadata/localhost blocking applies to anything that is not
the configured upstream.

Provider `allow.repositories` is a ceiling. In local multi-agent mode, broker
core intersects that ceiling with the authenticated agent grant and passes the
effective repository scope into the provider per request. Empty grants and empty
intersections deny.

## Durable Broker Seed Reconciliation

Production deployments may mount a generic read-only seed directory beside
broker-owned writable state. Each source filename has an independent durable
imported-source digest on the broker PVC. An unchanged source never overwrites
provider-rotated canonical state; a changed source is imported once; source
deletion never deletes canonical state. Existing canonical files with no marker
are preserved while the current source digest is adopted.

Seed replacement is outside the HTTP protocol but inside the trusted broker
lifecycle boundary. The sole broker writer is stopped and reaped before any
canonical replacement, readiness is false during the transition, canonical
files and markers are atomically written, and the broker resumes automatically.
A bounded mode-`0600` recovery record protects the previous canonical value
until the restarted broker accepts the replacement. The mechanism is filename-
and provider-agnostic and has no Kubernetes API or external secret-manager
contract.

## Codex OAuth Provider Rules

The `codex-oauth` provider is a file-bundle provider. It keeps the canonical
Codex OAuth `auth.json` in the broker and vends a read-only working copy to
agents:

- the broker is the only writer for the real `tokens.refresh_token`
- the vended `auth.json` always replaces `tokens.refresh_token` with a
  configured stub value
- the provider decodes the `access_token` JWT payload without signature
  verification only to read `exp`
- when the access token is within `refresh-margin-seconds` of expiry, the
  provider refreshes with `grant_type=refresh_token`, the configured
  `client-id`, and the current canonical refresh token
- file-bundle vending refreshes early enough to satisfy both
  `refresh-margin-seconds` and `bundle-ttl-seconds`
- successful refresh updates `access_token`, rotated `refresh_token`,
  optional `id_token`, and `last_refresh`, then atomically replaces the
  canonical file
- if refresh fails while the current access token is still valid, the provider
  serves the current token and records metadata-only audit; if the token is
  expired, the request fails
- broker core caps file-bundle `expires_at` metadata with
  `bundle-ttl-seconds`; if the provider expiry is sooner, `expires_at` is the
  provider expiry instead
- `bundle-ttl-seconds` does not reduce the lifetime of an already-issued
  OpenAI access token; the vended `auth.json` still contains the real
  `access_token`, which remains valid until its actual JWT expiry
- short-lived bundle metadata drives frequent broker re-materialization by the
  runtime refresher; this remains the insecure/compatibility file-bundle
  fallback until credential-less Codex ships
- `files.vend` audit `expires_at` and `bundle_expires_at` are capped bundle
  metadata; provider-specific fields such as `access_token_expires_at` may
  record the true credential expiry
- `files.refresh`, injection, and token-path audit expiry metadata use the true
  access-token expiry
- audit entries record provider, agent, operation, and expiry metadata only;
  token values and file contents must never be logged

Codex fallback refresh cadence depends on both broker and runtime settings:

- broker `bundle-ttl-seconds` sets the generic maximum bundle metadata lifetime
- runtime `broker-auth-files` `refresh-slack-seconds` is subtracted from the
  earliest returned `expires_at`
- runtime `broker-auth-files` `min-sleep-seconds` is the lower bound for loop
  sleeps

With the defaults, `1200 - 900 = 300s`, so each agent refresher wakes roughly
every five minutes. If `bundle-ttl-seconds <= refresh-slack-seconds`, the next
wake target is already due and the runtime clamps to `min-sleep-seconds`; with
the default `min-sleep-seconds: 60`, that can create a 60-second loop per agent.

The Codex plan-auth fallback remains file-bundle based. The broker owns and
writes the root refresh token; agent bundles receive the real OpenAI access
token plus inert stub fields. Full credential-less Codex is intentionally left
for later CA/TLS termination and WebSocket injection work.

Default Codex OAuth settings match the Codex CLI refresh flow:

```yaml
token-url: https://auth.openai.com/oauth/token
client-id: app_EMoamEEZ73f0CkXaXp7hrann
refresh-margin-seconds: 600
bundle-ttl-seconds: 1200
stub-refresh-token: nvt-broker-stub
```

## Claude OAuth Provider Rules

The `claude-oauth` provider is the Claude Code analogue of `codex-oauth`. It
holds the Claude Code subscription OAuth credential
(`~/.claude/.credentials.json`, a `{"claudeAiOauth": {...}}` object with
`accessToken`/`refreshToken` secrets and non-secret `scopes`,
`subscriptionType`, `rateLimitTier`, and a millisecond `expiresAt`) in broker
custody and exposes the same three materialization surfaces:

- **direct / file-bundle** (`/v1/files`): vends a usable `.credentials.json`
  into the agent, including the real access and refresh token. This is the
  insecure dev/fallback path (the `file-bundle` contract writes usable
  credential material into the container). The vended filename defaults to
  `.credentials.json`; place it under `~/.claude` with a runtime
  `broker-auth-files` bundle whose `target` is `~/.claude`.
- **mediated / placeholder-file** (`/v1/placeholder-files`): vends a
  syntactically valid `.credentials.json` whose `accessToken` and
  `refreshToken` are the zero-entropy `NVT-PLACEHOLDER-NOT-A-KEY` and whose
  `expiresAt` is far-future, so Claude Code starts without ever holding real
  credential bytes. Non-secret subscription metadata is copied through verbatim,
  guarded so a copied value that is too long or JWT-shaped is refused
  (`placeholder-claim-unsafe`) rather than smuggled into the placeholder.
- **mediated / edge injection** (`/v1/injection/headers`): returns
  `authorization: Bearer <access token>` plus any configured
  `injection-extra-headers`, with all injected names listed in
  `strip_request_headers`. Only the paired `egress` identity may fetch it.

Rules:

- Exactly one broker-side credential source: `credentials-file` (an absolute
  host path) or `credentials-env` (an env var holding the JSON). Neither is a
  runtime contract requirement — the agent never learns the source.
- The real `accessToken`/`refreshToken` are broker-owned. They are read on every
  request (so external rotation is picked up) and refreshed proactively when
  `expiresAt` is within `refresh-margin-seconds` (see **Refresh** below), but are
  **never** emitted by `/v1/placeholder-files`, on any path including errors. A
  missing or malformed broker-side credential fails loudly
  (`credentials-not-found` / `credentials-invalid`).
- `placeholder-file.hosts` must be a subset of `injection-hosts`, so the
  materialized host bindings can never drift from what the edge can inject for.
- `injection-extra-headers` may not override `authorization` and may not
  contain the injection placeholder.
- The API-key authentication path (`x-api-key`) does **not** need this provider:
  a generic `token` provider with `injection-header: x-api-key` and an
  `injection-extra-headers` `anthropic-version` already injects an Anthropic API
  key with zero egressd changes (see "Injection Support" below and
  `protocol/injection.md`). `claude-oauth` exists for the subscription OAuth
  credential, whose material lives in `.credentials.json` rather than an env var.

Example (mediated, subscription OAuth):

```yaml
providers:
  - name: claude-main
    plugin: claude-oauth
    config:
      credentials-file: /state/claude/.credentials.json
      injection-hosts:
        - api.anthropic.com
      injection-extra-headers:
        anthropic-beta: oauth-2025-04-20
      placeholder-file:
        path: .claude/.credentials.json
        hosts:
          - api.anthropic.com
```

**Refresh.** The broker keeps the broker-side Claude access token fresh over the
network with an OAuth `refresh_token` exchange (`token-url`/`client-id`,
analogous to the Codex flow; both default to Claude Code's public values and are
overridable). Claude credentials expose `expiresAt` for the access token and
newer versions may also expose `refreshTokenExpiresAt`. The latter is useful
status metadata, but the broker cannot wait until it lapses because an expired
refresh token cannot renew itself. Instead it
refreshes **proactively**: on any `/v1/files` or `/v1/injection/headers` request
where the access token is within `refresh-margin-seconds` (default 900) of
`expiresAt`, it exchanges the refresh token, persists the rotated credential
(new `accessToken`, any rotated `refreshToken`, recomputed `expiresAt`, returned
`refreshTokenExpiresAt`, granted scopes, and client ID) back to
`credentials-file`, and serves the fresh token. If the response omits refresh
expiry or scope metadata, the existing value is preserved. This front-runs Claude Code's
own 401-driven retries, which would otherwise storm the OAuth endpoint.

Anthropic's returned `refresh_token_expires_in` is authoritative and is
persisted as `refreshTokenExpiresAt`; rotation alone does not imply lifetime
extension. Operators must replace the broker credential from a trusted login
before that absolute expiry. The provider emits one sanitized warning when the
credential enters `refresh-expiry-warning-seconds` (default 432000, five days).

Refresh is hardened against retry storms:

- **Single-flight.** At most one upstream refresh call is in flight at a time.
  Concurrent callers serialize on a refresh lock — both *in-process* (a thread
  lock) and *cross-process* (an advisory `flock` on a lock file beside
  `credentials-file`), so a second broker instance or the manual probe cannot
  run a competing refresh-token exchange that invalidates the rotation. A queued
  caller re-reads the just-refreshed credential and skips its own upstream call.
  The common still-valid path takes no lock and makes no upstream call.
- **Cooldown / backoff.** A transient failure (HTTP 429, 5xx, network) caches
  the sanitized failure for `refresh-cooldown-seconds` (default 90, with light
  jitter and exponential backoff up to `refresh-cooldown-max-seconds`). During
  the cooldown no upstream call is made: a still-valid token is served, a
  mediated request for an expired one fails closed. This is what prevents Claude
  CLI retries from hammering the OAuth endpoint after a 429.
- **Serve-valid vs. fail-closed.** If refresh fails while the access token is
  still comfortably valid, the current token is served (the request succeeds).
  If the access token is already expired and refresh fails, the *mediated
  injection* request fails closed with the sanitized reason — never a stale
  token — while the *direct `/v1/files`* path still vends the expired real
  credential (see below).
- **Refresh audit.** A genuine upstream-refresh attempt that fails is audited
  once as a sanitized `<operation>.refresh` event (`allowed: false`, the
  classified reason, no token material) — even when a still-valid token is then
  served, so the failure is visible before the token actually expires. A request
  served from the cooldown makes no upstream call and emits no refresh audit
  event, so cooldowns cannot manufacture noisy or misleading duplicate
  upstream-refresh events. A successful refresh audits `allowed: true` with the
  new expiry.
- **Durable rotation.** The refreshed credential is created as mode `0600`,
  file-`fsync`ed, and atomically replaces the canonical file (also intentionally
  mode `0600`; group-readable sharing is unsupported). Directory `fsync` is
  attempted after replacement; an unsupported/failed directory `fsync` logs
  reduced crash durability but does not misreport the completed replacement as
  a content failure. If replacement itself fails after upstream rotation, the
  uniquely named completed temporary credential is retained beside the
  canonical file as a recovery copy and the failure is audited as
  `token-refresh-persist-failed`. A still-valid canonical access token may be
  served during cooldown; expired use fails closed.

**Sanitized diagnostics.** A refresh failure surfaces only the upstream HTTP
status and a safe OAuth error class (e.g. `HTTP 429 (rate_limit_error)`) in the
`ProviderError` message and audit. Access tokens, refresh tokens, `Authorization`
headers, the request body, and raw response bodies never appear in logs, errors,
audit, or PR text. Likely re-login cases (`invalid_grant`/`unauthorized_client`,
HTTP 400/401/403) are classified distinctly as `token-refresh-login-required`;
transient cases (429/5xx/network) are `token-refresh-rate-limited` /
`token-refresh-failed` and remain retryable after the cooldown.

The broker still does not reject a merely-expired-but-well-formed credential on
the direct path — `/v1/files` refreshes if it can and otherwise vends what it
has (direct mode is possession, and the agent's own `refreshToken` lets Claude
Code self-refresh) — and `credentials-invalid`/`credentials-not-found` fire only
for a missing or malformed file.

A `credentials-env` source is **never network-refreshed**: a rotated credential
cannot be written back to an env var, so refreshing it only in memory would be
lost on restart, after which the broker would reload the now-stale (possibly
already-rotated-away) env refresh token. So an env source serves a still-valid
token and fails closed on the mediated path once expired (durable refresh
requires `credentials-file`). This is the supported, fail-closed contract; do
not reintroduce in-memory env refresh without a genuinely durable sink.

**Manual probe.** `scripts/claude-refresh-probe.py --provider <name>` runs a
single one-shot refresh against the configured `token-url`, persists the rotated
credential on success, and prints only redacted metadata (status, credential
field names, old/new access and refresh expiry, whether the refresh token rotated). It refuses
a `credentials-env` source (rotation cannot be persisted there). It is safe to
run against a live broker: it takes the same cross-process refresh `flock` as
the broker's own refresh, so the two serialize instead of racing two rotating
exchanges against one canonical credential. This replaces ad-hoc Python run
inside a live container.

**Defaults.** The Claude OAuth request shape defaults to the values observed in
Claude Code CLI 2.1.205; all are overridable because Anthropic does not document
them as a stability contract:

```yaml
token-url: https://platform.claude.com/v1/oauth/token
client-id: 9d1c250a-e61b-44d9-88ed-5944d1962f5e
refresh-scope: "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
user-agent: axios/1.15.2
refresh-margin-seconds: 900
refresh-cooldown-seconds: 90
refresh-cooldown-max-seconds: 900
bundle-ttl-seconds: 1200
```

The default client id is the public Claude Code OAuth application id, not a
user/subscription secret; it is not carried in the Claude `.credentials.json`.
Override it with `client-id`/`client-id-env` if the CLI OAuth app changes.

## Static Token And Header Providers

Static providers use the same `allow.repositories` ceiling and authenticated
agent grant intersection as GitHub App providers. By default they use the same
GitHub target mode as `github-app`: host-prefixed targets such as
`github.com/owner/repo` are accepted at the endpoint boundary and normalized to
`owner/repo`.

For self-hosted Git providers, set `config.target-mode: literal`. Literal mode
normalizes URL, SSH, and plain targets to their full host/path repository id:

```text
https://altinn.studio/repos/digdir/oed.git -> altinn.studio/repos/digdir/oed
git@altinn.studio:repos/digdir/oed.git     -> altinn.studio/repos/digdir/oed
altinn.studio/repos/digdir/oed             -> altinn.studio/repos/digdir/oed
```

Grant patterns must use the provider's target mode. GitHub mode grants use
`owner/repo` patterns. Literal mode grants use full `host/path/repo` patterns,
for example `altinn.studio/repos/digdir/oed`.

Static token provider:

```yaml
providers:
  - name: github-pat
    plugin: token
    config:
      token-env: GITHUB_PAT
    allow:
      repositories:
        - my-user/my-repo
```

Static headers provider:

```yaml
providers:
  - name: company-headers
    plugin: headers
    config:
      target-mode: literal
      headers:
        - header-env: COMPANY_GIT_API_KEY_HEADER
    allow:
      repositories:
        - altinn.studio/repos/digdir/oed
```

These providers are compatibility providers. They remove raw secret env vars
from the agent container, but token/header capability calls still return
credentials to the agent.

## Injection Support (Mediated Egress)

Providers opt into header injection (`protocol/injection.md`) with an
`injection-hosts` config list naming the upstream hosts the credential may be
injected for. A provider without `injection-hosts` does not support
injection and `/v1/injection/*` denies with `injection-not-supported`.

```yaml
providers:
  - name: codex-main
    plugin: codex-oauth
    config:
      auth-file: /state/codex/auth.json
      injection-hosts:
        - chatgpt.com
        - auth.openai.com
```

The `token`, `codex-oauth`, and `claude-oauth` plugins support injection. For
`codex-oauth` and `claude-oauth`, injected material is
`authorization: Bearer <access token>` using the same broker-side refresh flow
as file vending. `claude-oauth` also returns any configured
`injection-extra-headers` (e.g. `anthropic-beta`). Audit entries use the
`injection.*` operation prefix. Grants must carry `materialization:
header-inject` **or** `materialization:
placeholder-file` (both are zero-possession; see `protocol/injection.md` for the
identity role/pairing model and endpoint shapes).

Some backends (Codex ChatGPT-plan) require an auxiliary header derived from
the access-token claims (e.g. an account id). `codex-oauth` computes these
from the **real** token via `injection-claim-headers`; the derived headers are
returned alongside `authorization` and added to `strip_request_headers` so the
agent's placeholder versions never reach the upstream. `claim-path` is a dotted
string or a YAML list of exact segments (use the list form when a claim key
itself contains dots, as the OpenAI account claim key does):

```yaml
providers:
  - name: codex-main
    plugin: codex-oauth
    config:
      injection-hosts:
        - chatgpt.com
      injection-claim-headers:
        - header: chatgpt-account-id
          claim-path:
            - https://api.openai.com/auth
            - chatgpt_account_id
```

## Headers

Allowed caller request headers:

- `accept`
- `if-none-match`
- `x-github-api-version`
- `content-type`

Response headers are lowercased.

## Pagination

`paginate: true` is provider-owned. The agent does not follow arbitrary GitHub
`Link` URLs.

The provider validates the original `/repos/{owner}/{repo}/...` URL, then
controls `per_page` and `page` query parameters internally. It returns an
aggregated JSON array and fails cleanly if page or response-size caps are
exceeded.

## Audit

Every broker request appends one JSONL audit entry with request id, provider,
operation, authenticated agent id when available, target, allow/deny result,
denial reason, upstream status, and response size when available.

## Stability

The stable contract is the `brokerctl` command behavior and the JSON shapes
documented here. The Python implementation may be replaced by Go as long as the
black-box broker tests keep passing.
