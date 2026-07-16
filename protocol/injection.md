# Injection Protocol (Mediated Credential Egress)

Status: implemented and pinned by the conformance suites referenced below.

This protocol delivers credential **non-possession**: for mediated grants, no
provider credential — API key, OAuth access/refresh token, installation token —
is ever available to the agent container. Credentials are injected into
outbound requests by `egressd`, a trusted reverse proxy that fetches injectable
material from `brokerd` under an identity the agent does not hold. The protocol
uses only the configured egress endpoint; deployment placement is outside this
contract.

```text
agent    holds no credentials; sends ordinary or placeholder-bearing requests
         toward egressd
egressd  trusted service; fetches injectable headers, injects, re-originates TLS
brokerd  policy, refresh, audit; releases injectable material to egress
         identities only
```

## Relationship To Existing Broker Endpoints

`/v1/token`, `/v1/headers`, and `/v1/files` (see `protocol/broker.md`) are
compatibility endpoints: they return secret-bearing material **to the
caller**. This protocol inverts that access model — the workload identity can
never obtain the secret. `/v1/headers` is explicitly *not* the semantic anchor
for injection; it remains unchanged for direct-mode compatibility.

## Identity Model: Roles And Pairing

Broker identities gain a `role`. Reusing plain agent identities for the
egress service would produce two bearer tokens with the same powers, which loses the
non-possession property.

```yaml
agents:
  - id: frontend
    token-sha256: sha256:<hash>
    role: agent            # default when omitted (backwards compatible)
    grants:
      - provider: codex-main
        materialization: header-inject
  - id: frontend-egress
    token-sha256: sha256:<hash>
    role: egress
    paired-agent: frontend
```

Rules, all enforced broker-side:

- `role` omitted means `agent`. Existing configs remain valid.
- `egress` identities hold no grants. A config listing grants on an `egress`
  identity is a validation error, not an ignored field.
- Each `egress` identity is paired to exactly one agent identity via
  `paired-agent`. Missing or unknown `paired-agent` is a validation error.
- `egress` identities may call only `/health` and `/v1/injection/*`.
  Secret-bearing endpoints (`/v1/token`, `/v1/headers`, `/v1/files`,
  `/v1/http/request`) deny `egress` callers.
- `agent` identities may not call `/v1/injection/headers`.
- An injection request is authorized only when the caller's role is `egress`
  **and** the requested capability is granted to the caller's paired agent.
  Agent A's egress identity cannot fetch material for agent B's grants.
- Kubernetes deployments replace bearer tokens with projected ServiceAccount
  tokens validated via TokenReview; the role and pairing semantics are
  unchanged.

## Materialization Modes

Each grant carries a materialization mode:

- `file-bundle` (default) — current behavior; the agent identity may call the
  compatibility endpoints per `protocol/broker.md`. Writes usable credential
  material into the container (the dev/fallback path).
- `header-inject` — zero-possession; only the paired egress identity may
  obtain the credential, via `/v1/injection/headers`.
- `placeholder-file` — zero-possession for file-based tools; the agent
  identity fetches a syntactically valid auth file containing only inert
  placeholders, via `/v1/placeholder-files` (see `protocol/broker.md`). The
  real credential stays broker-side and is injected at the edge.
  Distinct from `file-bundle`: no path in this mode writes usable credentials.
  The response's `hosts` bindings feed the forward-proxy route/injection map.
  A `placeholder-file` grant is **injection-eligible**: `/v1/injection/headers`
  accepts it, so the same grant that materializes the file can also authorize
  edge injection without a second grant. This only functions for providers
  that also implement injection (an `injection_headers` method and
  `injection-hosts`) — e.g. the Codex preset. The generic `placeholder`
  provider is materialization-only and returns `injection-not-supported`.

Modes are mutually exclusive per grant, enforced broker-side:

- A `header-inject` or `placeholder-file` grant denies `/v1/token`,
  `/v1/headers`, and `/v1/files` for that provider and agent.
- A `placeholder-file` grant is the only mode that may call
  `/v1/placeholder-files`; `file-bundle`/`header-inject` grants are denied
  there.
- `/v1/injection/headers` accepts `header-inject` and `placeholder-file`
  grants (both zero-possession); a `file-bundle` grant is denied there.

Run-level admission is enforced by the operator's AgentSchedule admission and
by Compose `agent-init`:

- run `egress: direct` with any `header-inject` or `placeholder-file` grant
  fails admission (both are zero-possession mediated modes).
- run `egress: mediated` with any `file-bundle` grant fails admission.
- There is no downgrade path in either direction. The error names the
  offending grant.

`placeholder-file` grants are accepted in mediated mode and their host bindings
feed the egress route map. A provider must implement injection and declare its
injection hosts for those placeholders to become usable at the edge; otherwise
the run fails closed rather than falling back to a usable file.

## Endpoints

### POST /v1/injection/headers

Egress role only.

Request:

```json
{
  "capability": "codex-main",
  "host": "chatgpt.com",
  "method": "POST",
  "path": "/backend-api/responses"
}
```

Requires `Authorization: Bearer ...` (an `egress`-role identity).

Response:

```json
{
  "ok": true,
  "headers": {
    "authorization": "Bearer ..."
  },
  "expires_at": "2026-07-05T12:00:00Z",
  "strip_request_headers": ["authorization"]
}
```

Rules:

- The endpoint is provider-agnostic. The broker maps `capability` to a
  provider; the provider computes injectable headers for
  `(host, method, path)`. `egressd` contains no provider-specific logic —
  new providers are broker plugins with zero egressd changes.
- `host` is the pinned upstream **hostname without a port**. Provider
  `injection-hosts` entries are bare hostnames, and `egressd` strips any
  `:port` from its pinned upstream before asking; the port applies only to
  the dial target.
- Response header names are lowercased.
- `expires_at` is the cache ceiling. `egressd` must not serve cached material
  past it and must not fall back to stale material when a refetch fails
  (fail closed).
- `strip_request_headers` lists caller-supplied request headers `egressd`
  must remove before injection (placeholder scrub, see below).
- Denials use the same `{"ok":false,"error":"...","message":"..."}` shape and
  status conventions as `protocol/broker.md`. Denial reasons include
  role mismatch, missing pairing, capability not granted to the paired agent,
  host not allowed for the capability, and materialization mode mismatch.

### POST /v1/injection/routing

Agent or egress role. Returns non-secret routing metadata for a capability.
This is the only injection surface an `agent` identity may call, and its
response never contains secret material — pinned by conformance test.

Authorization mirrors the scoping of `/v1/injection/headers`:

- An `agent` caller must itself hold a `header-inject` grant for the
  requested capability.
- An `egress` caller is authorized against its paired agent's grants; an
  egress identity whose paired agent does not hold the grant is denied.
- Capabilities not granted (including unknown capabilities) deny with the
  standard error shape.
- `file-bundle` grants deny. Routing is a mediated-mode surface; a
  direct-mode grant has no mediated egress path to route to, and answering would let
  routing act as a probe across materialization modes.

Request:

```json
{"capability": "codex-main"}
```

Response:

```json
{
  "ok": true,
  "hosts": ["chatgpt.com", "auth.openai.com"],
  "placeholder": "NVT-PLACEHOLDER-NOT-A-KEY"
}
```

A git-capable capability (a `github-app` provider with `injection-hosts`)
additionally reports `"git": true`. The flag is a non-secret routing hint:
runtime bootstrap installs the git redirect wiring (managed `insteadOf`
rewrite, `http.sslCAInfo` trust for the per-agent CA, `GIT_TERMINAL_PROMPT=0`)
for grants whose routing carries it. Non-git capabilities omit the field.

The local base URL the agent's tooling points at (the `egressd` listen
address) is composed by runtime bootstrap, not returned by the broker.

### Explicit forward-proxy capability selection

Runtime configuration selects this behavior with `egress.transport: forward-proxy`
(or `transparent` for captured traffic). The removed
`egress.forward-proxy` boolean is rejected on presence; it is not a fallback
selector. `egress.forward-proxy-url` remains the endpoint contract.

Forward-proxy MITM may have several mediated providers for the same upstream
host, for example multiple GitHub Apps on `api.github.com`, or multiple Codex
or Claude sessions on their shared service hosts. Host-only selection is
ambiguous and must not guess.

When more than one inject route is configured for a CONNECT host, `egressd`
requires an explicit non-secret capability selector on the CONNECT request.
The supported selector is HTTP proxy Basic auth where the username is the
broker provider name, e.g. a proxy URL shaped like:

```text
http://github-altinn-app@egressd:8473
```

The password is ignored. The selector is consumed by `egressd` and never
forwarded upstream. It is not authority by itself: `egressd` still calls
`/v1/injection/headers` with the selected capability, and the broker enforces
the paired agent grant, materialization mode, host, method, path, and
provider-specific scope. If the selector names a capability that is not
configured for that host, or no selector is present for an ambiguous host, the
CONNECT fails closed.

Runtime bootstrap exports both the plain forward proxy URL and provider-scoped
variants:

```text
NVT_EGRESS_FORWARD_PROXY_URL=http://egressd:8473
NVT_EGRESS_FORWARD_PROXY_URL_CODEX_MAIN=http://codex-main@egressd:8473
```

Tool wrappers or preseeded runtime profiles that explicitly reference a broker
provider should use the provider-scoped URL. The plain URL remains valid when a
CONNECT host maps to a single inject route.

Runtime plugins declare the same selector at the generic plugin boundary:

```yaml
plugins:
  - name: example-http-plugin
    egress:
      provider: github-main-app
```

For mediated proxy transports, the generic lifecycle launcher and exported-tool
wrapper resolve the corresponding provider-scoped URL and set `HTTPS_PROXY`
and its lowercase variant before the plugin code runs. `HTTP_PROXY` and
`ALL_PROXY` are removed at that scoped boundary because egressd's explicit
injection listener is CONNECT-only; provider injection is an authenticated
HTTPS contract. The launcher also exposes the selected non-secret name as
`NVT_PLUGIN_EGRESS_PROVIDER`; controlled plugin clients may use its presence to
avoid legacy direct credential materialization during migration, but it conveys
no topology or authority. The declaration must name an exact provider
capability backed by one or more grants with the same injection-eligible
materialization (`header-inject` or `placeholder-file`). Repeated grants may
aggregate repository scope; zero matches, conflicting modes, or any ineligible
entry fail before launch. The declaration contains no credential and
does not authorize the provider by itself. Direct mode and plugins without the
declaration retain their existing environment.

Provider-scoped proxy environment names normalize non-alphanumeric runs to `_`
and uppercase the result. All configured mediated provider names must therefore
have distinct normalized forms: names such as `github-main`, `github.main`, and
`github_main` cannot coexist in one agent configuration. Bootstrap rejects a
collision before exporting provider-scoped endpoints; it never overwrites or
selects one implicitly.

Controlled HTTP clients make ordinary requests without an Authorization
placeholder. The selector on the CONNECT identifies the configured route and
egressd obtains the headers from the broker. Placeholder headers and files
remain for unmodifiable clients that require credential-shaped local input;
there is no request-body, query-string, or arbitrary-value substitution.

When `runtime.command` is used with mediated forward-proxy egress, runtime
bootstrap requires:

```yaml
runtime:
  proxy:
    provider: codex-main
```

Bootstrap binds `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, and their lowercase
variants to that provider-scoped URL. This keeps the runtime's primary agent
CLI explicit without teaching bootstrap about Codex, Claude, GitHub, or any
other provider type.

### POST /v1/injection/report

Egress role only. Reports proxied requests so the broker's audit log covers
individual requests, not just per-fetch injection. This endpoint is
**observability, not a security control**: reporting is asynchronous,
bounded, and best-effort on the `egressd` side — a report failure is logged
and dropped, never blocking or failing proxied traffic. Authorization and
enforcement live in `/v1/injection/headers` and the network layer, not here.

Request (batched):

```json
{"entries": [
  {"capability": "git-app", "host": "github.com", "method": "POST",
   "path_class": "git-upload-pack", "status": 200},
  {"capability": "codex-main", "host": "chatgpt.com", "method": "POST",
   "path_class": "backend-api", "status": 429}
]}
```

Forward-proxy CONNECT entries use `{capability, host, port, decision}` where
`decision` is `allow` or `deny`:

```json
{"entries": [
  {"capability": "tunnel-main", "host": "example.com", "port": 443,
   "decision": "allow"}
]}
```

Response: `{"ok": true, "reported": <n>}`.

Rules:

- Egress role only; the paired agent is resolved as for
  `/v1/injection/headers`. An `agent` identity is denied.
- Authorization is role + pairing only. Entries are **not** re-checked
  against grants: a report for a just-revoked capability is still
  audit-worthy, and a compromised `egressd` can spam granted capabilities
  regardless — re-checking buys nothing and would drop legitimate audit.
- `path_class` is a **sanitized** class, never a raw path (see below).
  `egressd` computes it at the source so raw paths never leave the trusted edge.
- At most 100 entries per report; combined with the request size limit this
  bounds a report. Oversized reports are denied with the standard error
  shape, not truncated silently. A malformed entry rejects the whole batch;
  nothing is partially audited.
- One audit line per entry, `operation: "injection.request"` (HTTP) with
  `{host, method, path_class, status}` or the CONNECT shape with
  `{host, port, decision}`. Header values and token material never appear,
  on any path including errors.

**`path_class` definition.** git smart-HTTP paths reduce to
`git-upload-pack` | `git-receive-pack` | `info-refs`; every other path
reduces to its first path segment (`/repos/o/r/pulls/1` → `repos`, `/` →
`root`). This keeps the audit useful without spraying repo or file names
into it. The broker **enforces the shape** — `path_class` must match
`^[a-z0-9._-]{1,64}$` — so a buggy or compromised `egressd` cannot write a
raw path or arbitrary string into the audit log; a non-conforming entry
rejects the batch.

## Placeholder Convention

Some CLIs refuse to start without a syntactically present key. Mediated mode
may satisfy them with the fixed constant:

```text
NVT-PLACEHOLDER-NOT-A-KEY
```

Rules:

- The constant is documented here, carries zero secret entropy, and is
  allowlisted by the non-possession smoke test.
- A conformance test proves the placeholder is inert: a direct
  (egress-bypassing) upstream request presenting it is rejected.
- `egressd` strips or replaces the placeholder header on injection
  (`strip_request_headers`); it is never forwarded alongside the real
  credential.

## Transport Requirements

The `egressd -> brokerd` leg carries real credentials in flight. In mediated
deployments it must use TLS or a transport unreachable from the agent. Serving
`/v1/injection/headers` over plaintext HTTP on an agent-reachable network is a
conformance failure. The agent-to-egress path carries only inert placeholders
and non-secret routing metadata; the agent has no real credential to send.

## Audit

Every injection request appends one JSONL audit entry: request id,
capability, egress identity id, paired agent id, host, method, path class,
allow/deny result, denial reason, and expiry metadata. Header values and
token material are never logged, on any path including errors.

`/v1/injection/headers` audits one entry per *fetch*, which `egressd` caches
for a TTL window — so it does not capture individual proxied requests.
`/v1/injection/report` (above) closes that gap: `egressd` reports each
proxied request and forward-proxy CONNECT, appending one
`operation: "injection.request"` line per entry to the same log. Because
that reporting is best-effort observability, audit completeness is not a
security guarantee — the security guarantees are non-possession and
enforcement, neither of which depends on the report path.

## Stability

The stable contract is the JSON shapes and authorization rules documented
here, pinned by `tests/broker/injection_conformance_test.go` and the mediated
smoke tests in `tests/runtime/`. Broker and egress implementations may be
replaced as long as the black-box suites keep passing.
