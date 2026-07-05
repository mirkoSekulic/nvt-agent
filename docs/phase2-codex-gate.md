# Phase 2 Gate — Codex Plan-Auth Mediation: Findings & Decision

Status: **NO-GO for redirect-only Codex plan-auth mediation**
Parent: `docs/mediated-egress-plan.md` (Phase 2), spec:
`docs/phase2-codex-gate-plan.md`

This document records the empirical answer to:

> Can real Codex ChatGPT-plan auth be fully mediated through egressd via
> base-URL redirection, with the agent container holding **no** real
> credential?

## How to Run

```sh
make phase2-codex-gate
# useful variants:
#   PHASE2_SCHEME=http make phase2-codex-gate
#   PHASE2_SCHEME=http PHASE2_UPSTREAM=api.openai.com \
#     PHASE2_MODEL_PROVIDER_BASE=http://egressd:8471/v1 make phase2-codex-gate
```

Evidence lands in `.phase2-out/evidence/`:
`summary.txt`, `codex-stdout.txt`, `codex-stderr.txt`, `egressd.log`,
`broker-audit.jsonl`, `injection-audit.jsonl`.

## Runs

Run date: 2026-07-05.

All runs used a placeholder `auth.json` inside the agent container and the real
Codex `auth.json` only in broker-owned harness state.

### HTTPS `chatgpt_base_url`

Command:

```sh
make phase2-codex-gate
```

Result:

- egressd started with an agent-facing HTTPS listener.
- Codex accepted the placeholder `access_token` and `id_token` once both were
  JWT-shaped.
- Codex attempted redirected MCP calls to `https://egressd:8471/api/codex/ps/mcp`,
  but the agent-facing TLS path failed during handshake.
- Codex then attempted the main turn through a hardcoded WebSocket endpoint:
  `wss://chatgpt.com/backend-api/codex/responses`.
- Because the agent network is internal-only, that hardcoded direct host lookup
  failed before any broker injection request.

### HTTP `chatgpt_base_url`

Command:

```sh
PHASE2_SCHEME=http make phase2-codex-gate
```

Result:

- egressd started with an agent-facing HTTP listener.
- Codex still attempted the main turn through a hardcoded WebSocket endpoint:
  `wss://api.openai.com/v1/responses`.
- No request reached egressd/broker injection.

### HTTP API-style provider base URL

Command:

```sh
PHASE2_SCHEME=http PHASE2_UPSTREAM=api.openai.com \
  PHASE2_MODEL_PROVIDER_BASE=http://egressd:8471/v1 make phase2-codex-gate
```

Result:

- egressd started with upstream `api.openai.com`.
- `model_providers.openai.base_url` was written as
  `http://egressd:8471/v1`.
- Codex still attempted the main turn through the hardcoded WebSocket endpoint:
  `wss://api.openai.com/v1/responses`.
- No request reached egressd/broker injection.

## Findings

### Required Hosts

Observed hardcoded direct endpoints:

- `wss://chatgpt.com/backend-api/codex/responses`
- `wss://api.openai.com/v1/responses`

These were not redirected by `chatgpt_base_url` or by the tested
`model_providers.openai.base_url` setting in Codex `0.142.4`.

### Minimal Placeholder Shape

Codex requires both `access_token` and `id_token` to be JWT-shaped. A literal
placeholder `id_token` fails before network traffic:

```text
invalid ID token format at line 6 column 3
```

The harness now writes the same inert, zero-secret placeholder JWT shape for
both fields, with a stub refresh token.

### Claim-Derived Headers

Not reached. No injection requests were made.

### TLS / Cert Pinning

Not fully proven. The fixed harness starts egressd with TLS certificates
mounted correctly, but Codex's redirected MCP calls to the HTTPS listener fail
during TLS handshake before a normal HTTP request reaches egressd:

```text
http: TLS handshake error ... remote error: tls: error decrypting message
```

This is secondary to the main result: the model turn's Responses WebSocket is
not redirected by the tested base URL settings.

### Bypass Attempts

Confirmed. On the internal-only agent network, Codex repeatedly failed DNS
lookup for hardcoded WebSocket endpoints:

```text
failed to lookup address information: Try again, url: wss://chatgpt.com/backend-api/codex/responses
failed to lookup address information: Try again, url: wss://api.openai.com/v1/responses
```

### Refresh

Not reached. The harness computed a forced refresh margin, but no injection
request reached the broker:

```text
injection_requests=0
refresh_seen=0
```

### Non-Possession

Passed in every run. The harness reported:

```text
no credential leakage detected (agent fs/env/args + evidence)
```

The scan covered real token values and stable fragments across the agent
placeholder auth file, captured agent env, sampled process args, Codex home,
egressd logs, broker audit, and Codex stdio evidence.

## Decision

**NO-GO for redirect-only Codex plan-auth mediation.**

Redirected base URLs are not enough for current Codex plan-auth because the
Responses WebSocket endpoint is hardcoded outside the tested redirect settings.
The correct next step is not more Phase 3 wiring for Codex plan-auth; it is one
of:

- keep Codex plan-auth on the existing file-bundle/broker-auth path for now;
- mediate providers/tools whose HTTP base URL is actually redirectable;
- bring Phase 6-style forward-proxy/transparent mediation earlier for Codex
  plan-auth, because that can catch hardcoded endpoints.

This is a successful Phase 2 result: the gate answered the question before
operator/compose production wiring was built around a false assumption.

## Evidence References

- `.phase2-out/evidence/summary.txt`
- `.phase2-out/evidence/codex-stderr.txt`
- `.phase2-out/evidence/egressd.log`
- `.phase2-out/evidence/agent-container-scan.txt`
- `.phase2-out/evidence/agent-ps-during.txt`
- `.phase2-out/evidence/injection-audit.jsonl`
