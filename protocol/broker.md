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
a Unix socket, mTLS service, or service mesh without changing plugin commands.

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
config. `/health` and `/ready` are token-free; capability endpoints require a
valid token.

## Endpoints

### GET /health

Returns:

```json
{"ok":true,"status":"ready"}
```

### GET /ready

Returns HTTP 200 only when every configured provider has accepted its local
configured state. Embedded providers own format validation and must not contact
upstreams or refresh credentials from this probe; executable providers must
have a successfully initialized live generation. Failures return a generic
HTTP 503 without provider names, configuration, or credential diagnostics.
Seed replacement uses this stricter endpoint before discarding recovery state.
When the optional guest-enrollment issuer is enabled, `/ready` also requires a
readable v1 durable store; it performs no issuance and exposes no state.

### Guest enrollment endpoints

The optional production issuer implements the exact payloads and lifecycle in
[guest-enrollment.md](guest-enrollment.md):

| Endpoint | Maximum request | Authorization |
| --- | ---: | --- |
| `POST /v1/guest-enrollment/issue` | 4 KiB | Dedicated orchestrator bearer |
| `POST /v1/guest-enrollment/exchange` | 16 KiB | One-time token plus exact binding in the body |
| `POST /v1/guest-enrollment/revoke-binding` | 4 KiB | Dedicated orchestrator bearer |
| `POST /v1/guest-enrollment/revoke-execution` | 4 KiB | Dedicated orchestrator bearer |
| `POST /v1/guest-enrollment/complete-execution-cleanup` | 4 KiB | Dedicated orchestrator bearer |
| `POST /v1/guest-runtime-identity/status` | 4 KiB | Current runtime identity plus exact binding |
| `POST /v1/guest-runtime-identity/rotate` | 16 KiB | Current runtime identity plus exact binding and successor |
| `POST /v1/guest-session-identity/issue` | 8 KiB | Current runtime identity plus exact binding and fixed audience |
| `POST /v1/guest-session-identity/authenticate` | 4 KiB | Session credential plus exact binding and fixed audience |
| `POST /v1/native-egress-identity/issue` | 8 KiB | Current runtime identity plus exact binding and fixed audience |
| `POST /v1/native-egress-identity/authenticate` | 8 KiB | Native-egress credential plus exact binding and fixed audience |
| `POST /v1/native-egress-identity/revoke-binding` | 8 KiB | Dedicated orchestrator bearer |
| `POST /v1/native-egress-identity/revoke-execution` | 8 KiB | Dedicated orchestrator bearer |

Issue returns the frozen `BootstrapEnvelope`; exchange returns the frozen
`ExchangeResult`; both revoke operations and cleanup completion return
`{"ok":true}`. The issue
caller cannot supply `exchange_url`: every envelope carries the issuer-owned
canonical HTTPS endpoint loaded at broker startup. Unknown fields, duplicate
keys at any depth, invalid UTF-8, trailing JSON, and over-limit requests fail
as `invalid-request`.

The runtime identity endpoints implement
[`nvt.guest-runtime-identity/v1`](guest-runtime-identity.md). Status returns
only the exact non-secret binding and broker-owned issuance/expiry window.
Rotation atomically replaces the authenticating digest with a client-generated
successor digest and never echoes the successor. Lost-response recovery probes
the already-known successor before retrying that same value; it never blindly
creates another identity.

The session endpoints implement
[`nvt.guest-session-identity/v1`](guest-session-identity.md). Issue authenticates
the indexed active runtime identity before body admission, accepts only the
fixed `nvt.native-guest-control/v1` audience, and returns one short-lived
broker-generated credential. Authenticate accepts that credential and returns
only its exact non-secret binding, audience, and broker-owned time window. It
does not establish a gateway route or transport in this phase.

The operator client exposes only issue, the two revoke operations, and cleanup
completion; it has no guest exchange method. It holds the dedicated bearer in
a projected Secret and never passes it to a driver host. For external AgentRun
cleanup it repeats execution-scope revocation until acknowledged, invokes the
exact driver delete operation until `deleted`, repeats cleanup completion until
acknowledged, and only then clears the lifecycle finalizer. Response loss at
any step is recovered by repeating that exact idempotent operation.
The separately authenticated driver-host handoff is specified in
[guest-enrollment.md](guest-enrollment.md); its ordinary reconcile payload
remains credential-free.

The orchestrator bearer is a separate Secret-mounted authority. Ordinary
agent and egress identities cannot issue or revoke enrollments. The broker
authenticates issue and revoke authorization before reading their request
bodies. Exchange is intentionally available before the guest has a runtime
identity, but its SQLite transaction accepts only one canonical 256-bit token
with the complete exact binding. The broker admits at most 128 accepted
connections before TLS handshake or HTTP parsing and gives both TLS handshake
and request-line/header parsing a 10-second monotonic absolute deadline; byte
progress does not extend either deadline. Saturation at this
pre-header boundary closes the connection because no HTTP request exists yet;
the JSON `capacity-exceeded` response is available only after a request has
been parsed. Enrollment bodies have a separate 10-second monotonic absolute
deadline that is likewise not extended by partial reads. Public
exchange bodies have a 64-request bound; authenticated issue/revoke bodies use
an independent 16-request control-plane bound so public exchange saturation
cannot block authoritative revocation. Decoded exchange transactions have a
32-operation bound and a global 128 requests/second token bucket with a burst
of 256. Enrollment admission saturation after parsing returns
`capacity-exceeded`; there is no alternate identity or driver fallback.
Valid-shaped absent tokens are rejected through indexed read-only lookups and
never acquire the SQLite writer lock. A token that selects durable state must
enter the transactional writer path, which validates the complete bounded
store before consuming the token or issuing an identity.
Runtime status/rotation bodies have an independent 64-request HTTP bound, a
32-operation issuer bound, and per-enrollment body-concurrency and token-bucket
bounds. They do not consume the control-plane revocation body slots. An indexed
digest lookup authenticates an active identity before body admission, so an
unknown identity consumes neither a body slot nor another identity's quota.
A noisy valid identity can exhaust only its own quota. Normal status and
rotation validate the selected record, transactionally maintained counters,
and indexed digest membership; they never enumerate predecessor history.
Complete-store validation is a streaming startup/recovery operation. Steady
readiness and maintenance validate bounded metadata rather than deserializing
fleet history. A known integrity failure latches the issuer unhealthy and all
runtime operations fail closed until maintenance successfully validates the
complete store; readiness alone never clears the latch.
Runtime identity timestamps use the later of the issuer's current wall clock
and the enrollment's durable `issued_at`, so a backward clock adjustment cannot
commit a record that the same issuer subsequently rejects as malformed.

Guest session authentication has its own 64-request HTTP and 32-operation
issuer bounds plus independent per-credential concurrency and rate admission;
session issuance and authentication also use separate 32-operation issuer
bounds.
Unknown bearers are rejected by indexed digest lookup before slow-body
admission. A session credential cannot consume the runtime-identity or
orchestrator control quotas. Issuance permits exactly two simultaneously live
credentials per exact binding: this is the bounded response-loss recovery
window. A third issue fails until expiry, and maintenance removes expired rows.
Both exact-binding and execution-scope revocation delete every matching session
digest in the same transaction as the runtime identity.

The native-egress identity endpoints implement the authority portion of
[`nvt.native-egress-identity/v1`](native-egress.md). Issue authenticates the
indexed current, active, unexpired runtime identity before body admission and
requires exact equality on all five binding fields plus the fixed
`nvt.native-egress/v1` audience. The broker returns a purpose-prefixed,
sequence-bearing credential once and persists only its domain-separated
SHA-256 digest. Authenticate returns only non-secret binding, sequence,
audience, and broker-owned time metadata. At most two unexpired credentials
exist per lifecycle; a committed response loss may consume the first slot and
one bounded retry may consume the second. Both native-egress revoke paths use
the existing orchestrator authority and the same enrollment/tombstone
transactions, so existing guest-enrollment revocation also removes every
native-egress credential atomically.

Native-egress authority requests have one issuer-owned shared 64-operation cap
and a 30-second monotonic absolute deadline. Guest-authenticated issue and
authenticate traffic acquire the shared lease and one of only 48 guest leases
before any bearer-backed SQLite lookup, retaining sixteen shared slots for
orchestrator revocation. Bearers are authenticated before request bodies are
read. Unknown egress bearers are rejected by indexed digest lookup and use
per-credential rate/concurrency isolation after authentication. The same
deadline bounds SQLite busy waits and is checked after lock acquisition and at
the final pre-commit authorization point; expiry before that point rolls back
and releases admission. A synchronous SQLite commit already begun after the
final check is the sole uninterruptible OS boundary, may retain its lease only
until that system call returns, and retains the documented
committed-response-loss semantics. Requests are at most 8 KiB and responses at
most 16 KiB. Maintenance removes only expired credential rows; it never evicts
live credentials or lifecycle/tombstone authority.

Errors are bounded stable classes from the guest-enrollment contract. Responses,
audit entries, readiness, and process logs never contain a request body,
plaintext or digest token, plaintext runtime identity, plaintext or digest
session credential, plaintext or digest native-egress credential, or SQLite
diagnostic.
The broker uses one durable SQLite database with full synchronous commits. It
must run as the chart's single `Recreate` replica; sharing that file among
broker processes is unsupported. This issuer is disabled unless durable state,
TLS/canonical URL, and the dedicated authorization Secret are all configured.
Background maintenance records token and runtime-identity expiry at their
original deadlines. Each tombstone durably records its transition time and a
retention deadline no more than 24 hours later, independent of later wall-clock
movement. Maintenance does not infer AgentRun cleanup from elapsed time.
Tombstones and terminal records are reclaimed only after the authenticated
cleanup-complete operation durably marks the exact revoked scope and the
retention deadline has passed. Until then the 10,000-entry hard bound fails
closed rather than evicting live or revocation state. Runtime identity history
uses an administrator-configured aggregate capacity (2,000,000 by default,
bounded from 20,000 through 10,000,000). Issue atomically reserves one complete
20,000-entry allowance or fails before returning an enrollment envelope.
Rotation records the retired digest and increments the reserved lifecycle's
used count atomically, rejecting any successor digest already current or
historical. Expiry before the one-time exchange releases the unused reservation
atomically but retains the expired record for replay and binding enforcement.
After identity issuance, exact-binding and execution cleanup release the
reservation and delete all matching history. At the recommended 30-minute
planning interval the allowance covers more than 365 days, but the interval is
a client `SHOULD`, not broker enforcement. The orchestrator must
replace/re-enroll the guest binding before exhaustion rather than evicting
replay history.

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

Trusted control-plane preparation may omit `target`:

```json
{"provider":"fork-app"}
```

The target-less form still requires the exact AgentRun bearer identity and an
effective grant for that provider. It asks the provider for provider-bound,
non-secret commit metadata under the complete granted repository ceiling. It
does not vend a token, headers, files, or any credential-fetching capability,
and it is intended for the operator to snapshot through the versioned
[prepared provider metadata](prepared-provider-metadata.md) contract. Providers with target-dependent identity fail
explicitly; broker core never guesses a repository, provider, or fallback.

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
id, not the App id and not the installation id. When present, the target is
used for repository authorization. The target-less preparation form authorizes
the provider against the complete effective grant. The identity itself is
provider/app-level and cached by the provider process.

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

Seed replacement is outside the credential API but inside the trusted broker
lifecycle boundary. The broker process group, including executable providers,
is stopped and reaped before any canonical replacement, readiness is false
during the transition, canonical
files and markers are atomically written, and the broker resumes automatically.
A bounded mode-`0600` recovery record protects the previous canonical value
until every configured provider accepts the replacement through `/ready`.
Projected volumes are read from one pinned `..data` generation; a generation
movement during scanning is retried without stopping the healthy broker. The
mechanism is filename- and provider-agnostic and has no Kubernetes API or
external secret-manager contract.

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
  `authorization: Bearer <access token>` as a replacement header. Configured
  `injection-extra-headers` are returned as non-secret append-only feature
  headers, allowing Claude Code's version-specific `anthropic-beta` values to
  survive. Only the paired `egress` identity may fetch it.

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
  contain the injection placeholder. For `claude-oauth`, these values must be
  comma-separated feature-negotiation tokens, not credentials; egressd
  preserves client values and appends/deduplicates the configured values.
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
`codex-oauth` and `claude-oauth`, replacement material is
`authorization: Bearer <access token>` using the same broker-side refresh flow
as file vending. `claude-oauth` returns configured
`injection-extra-headers` (e.g. `anthropic-beta`) as append-only non-secret
feature tokens so client-selected values remain intact. Audit entries use the
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
