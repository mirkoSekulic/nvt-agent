# Injection Protocol (Mediated Credential Egress)

Status: draft contract (Phase 0 of `docs/mediated-egress-plan.md`).
Implementation begins in Phase 1. The conformance tests referenced at the
bottom pin this contract before any implementation exists.

This protocol delivers credential **non-possession**: for mediated grants, no
provider credential — API key, OAuth access/refresh token, installation token —
is ever available to the agent container. Credentials are injected into
outbound requests by `egressd`, a trusted reverse proxy running alongside the
agent, which fetches injectable material from `brokerd` under an identity the
agent does not hold.

```text
agent    holds no credentials; sends requests to egressd over localhost
egressd  trusted sidecar; fetches injectable headers, injects, re-originates TLS
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
sidecar would produce two bearer tokens with the same powers, which loses the
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
  Agent A's sidecar cannot fetch material for agent B's grants.
- Kubernetes deployments replace bearer tokens with projected ServiceAccount
  tokens validated via TokenReview; the role and pairing semantics are
  unchanged.

## Materialization Modes

Each grant carries a materialization mode:

- `file-bundle` (default) — current behavior; the agent identity may call the
  compatibility endpoints per `protocol/broker.md`.
- `header-inject` — zero-possession; only the paired egress identity may
  obtain the credential, via `/v1/injection/headers`.

Modes are mutually exclusive per grant, enforced broker-side:

- A `header-inject` grant denies `/v1/token`, `/v1/headers`, and `/v1/files`
  for that provider and agent.
- A `file-bundle` grant denies `/v1/injection/headers` for that provider and
  the paired egress identity.

Run-level admission (normative here, enforced by the operator's
AgentSchedule admission and by compose `agent-init` from plan Phase 3):

- run `egress: direct` with any `header-inject` grant fails admission.
- run `egress: mediated` with any `file-bundle` grant fails admission.
- There is no downgrade path in either direction. The error names the
  offending grant.

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
  new providers are broker plugins with zero sidecar changes.
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

The local base URL the agent's tooling points at (the `egressd` listen
address) is composed by runtime bootstrap, not returned by the broker.

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
  (sidecar-bypassing) upstream request presenting it is rejected.
- `egressd` strips or replaces the placeholder header on injection
  (`strip_request_headers`); it is never forwarded alongside the real
  credential.

## Transport Requirements

The `egressd -> brokerd` leg is the one network path that carries real
credentials in flight, and `egressd` shares the agent's network namespace. In
mediated deployments this leg must use TLS or a transport unreachable from
the agent's network namespace. Serving `/v1/injection/headers` over plaintext
HTTP on a network reachable from the agent netns is a conformance failure for
mediated mode. The `agent -> egressd` localhost hop needs no such protection:
it carries no credentials, because the agent has none.

## Audit

Every injection request appends one JSONL audit entry: request id,
capability, egress identity id, paired agent id, host, method, path class,
allow/deny result, denial reason, and expiry metadata. Header values and
token material are never logged, on any path including errors.

## Stability

The stable contract is the JSON shapes and authorization rules documented
here, pinned by `tests/broker/injection_conformance_test.go` and the mediated
smoke tests in `tests/runtime/`. Broker and sidecar implementations may be
replaced as long as the black-box suites keep passing.
