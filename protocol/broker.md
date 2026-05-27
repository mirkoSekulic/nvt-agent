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
interface. V1 has no strong caller authentication, so reachability is the
boundary.

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
The root secret still stays in the broker.

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
