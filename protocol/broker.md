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
- `bundle-ttl-seconds` caps the vended bundle `expires_at`; if the OpenAI
  access token expires sooner, `expires_at` is the access token expiry instead
- OpenAI controls the actual JWT lifetime. The broker cannot shorten an issued
  OpenAI access token, but it can keep agent-side materialization lifetime and
  refresh cadence short and explicit.
- audit entries record provider, agent, operation, and expiry metadata only;
  token values and file contents must never be logged

The Codex plan-auth fallback remains file-bundle based. The broker owns and
writes the root refresh token; agent bundles receive derived access-token
material plus inert stub fields. Full credential-less Codex is intentionally
left for later CA/TLS termination and WebSocket injection work.

Default Codex OAuth settings match the Codex CLI refresh flow:

```yaml
token-url: https://auth.openai.com/oauth/token
client-id: app_EMoamEEZ73f0CkXaXp7hrann
refresh-margin-seconds: 600
bundle-ttl-seconds: 1200
stub-refresh-token: nvt-broker-stub
```

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

The `token` and `codex-oauth` plugins support injection. For `codex-oauth`,
injected material is `authorization: Bearer <access token>` using the same
refresh flow as file vending; audit entries use the `injection.*` operation
prefix. Grants must carry `materialization: header-inject` (see
`protocol/injection.md` for the identity role/pairing model and endpoint
shapes).

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
