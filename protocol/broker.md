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
