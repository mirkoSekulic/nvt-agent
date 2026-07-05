# Phase 2 Implementation Spec — Codex Plan-Auth Mediation Gate

Status: implementation spec for the executing agent
Parent plan: `docs/mediated-egress-plan.md` (Phase 2)
Contract: `protocol/injection.md`; broker injection support: `protocol/broker.md`
Builds on: Phase 1 (`egressd/`, broker `/v1/injection/*`, merged in #54)

## What this phase is

An **empirical gate**, not an architecture phase. The single deliverable is a
documented, evidence-backed answer to one question:

> Can a real Codex CLI running ChatGPT-plan auth be fully mediated through
> egressd via base-URL redirection — with the agent container holding **no**
> real credential — or does Codex use fixed endpoints / certificate pinning
> that defeat localhost TLS re-origination?

The PR produces a **harness** to answer it, **config examples** for mediated
`codex-oauth`, and a **committed gate document** recording the answer and the
go/no-go decision. It does **not** wire operator or compose production paths.
That wiring (Phase 3) is gated on this phase returning "go".

Hard rule: **do not implement operator/compose production wiring in this PR.**
If the gate passes, Phase 3 is a separate PR. If it fails, Phase 3 changes
shape entirely (mediate only redirectable/API-key providers).

## Success criteria (definition of done)

1. A `make` target brings up broker + egressd + an agent container on an
   internal-only network, with the broker owning the real `auth.json` and the
   agent holding no real credential.
2. A real Codex turn (e.g. "print pong") completes **through egressd**.
3. Evidence captured: the set of hosts Codex required, whether any Codex
   traffic tried to bypass the configured base URLs, and whether TLS
   re-origination worked (no cert pinning failure).
4. The real refresh flow is exercised through egressd at least once.
5. `docs/phase2-codex-gate.md` is written with the host list, the minimal
   placeholder shape, any claim-derived headers required, cert-pinning
   observations, and the **go/no-go decision with rationale**.
6. Config examples for mediated `codex-oauth` are committed.
7. No real credential (token, JWT, refresh token) appears in the repo, in
   logs, or in the agent container filesystem/env/process args.

## Background the agent needs

### How Codex selects plan-auth and talks to the backend

- Codex reads `~/.codex/auth.json`. Presence of OAuth `tokens` (vs an API
  key) selects ChatGPT-plan mode. Codex decodes the access-token JWT locally
  (the broker's `codex-oauth` provider does the same to read `exp`).
- Base URL redirection points: `chatgpt_base_url` in `~/.codex/config.toml`
  is the primary lever for the plan-auth backend; `model_providers.*.base_url`
  covers the API-style path. **Both must be set to the egressd route** and the
  exact key names/coverage verified empirically — this is part of the gate.
- Plan-auth requests may carry **auxiliary headers derived from token
  claims** (notably an account-id header). See "Claim-derived headers" below.

### Phase 1 pieces this builds on (already merged)

- Broker `POST /v1/injection/headers` — egress-role only, authorized against
  the paired agent's `header-inject` grant, host checked against the
  provider's `injection-hosts`. Returns `{headers, expires_at,
  strip_request_headers}`.
- Broker `POST /v1/injection/routing` — non-secret hosts + placeholder.
- `codex-oauth` provider `injection_headers(host, method, path, agent_id,
  audit, request_id)` — reuses the real refresh flow, returns
  `authorization: Bearer <access token>`. Currently returns only the
  authorization header (see task 3 — may need claim-derived headers).
- egressd — per-route reverse proxy: fetches injectable headers under its
  egress identity, caches per `(method, path)`, injects, re-originates TLS to
  the pinned upstream, fails closed, strips placeholder-bearing headers, SSE
  passthrough. Config: `broker_url`, `broker_ca_file`, `routes[]` with
  `listen`, `capability`, `upstream`.
- Identity model in `.broker/agents.yaml`: `role: agent|egress`,
  `paired-agent`, per-grant `materialization: file-bundle|header-inject`.

## Tasks

### Task 1 — Mediated broker config for real codex-oauth

Add `injection-hosts` to the `codex-main` provider and create the mediated
identity pair. This is done in a **harness-local config**, not by mutating the
user's live `.broker/`.

The harness must use a **copy** of the real `auth.json` into a throwaway
broker state dir, or mount the real one read-only into a broker started with a
harness-specific config. Never write tokens into the repo.

Provider addition (harness broker.yaml):

```yaml
providers:
  - name: codex-main
    plugin: codex-oauth
    config:
      auth-file: /state/codex/auth.json
      injection-hosts:
        - chatgpt.com          # verify exact host(s) during the gate
        - auth.openai.com      # token refresh host
      refresh-margin-seconds: 3600
```

Identities (harness agents.yaml) — an agent with a header-inject grant and its
paired egress identity:

```yaml
agents:
  - id: codex-probe
    token-sha256: sha256:<hash of agent token>
    role: agent
    grants:
      - provider: codex-main
        materialization: header-inject
  - id: codex-probe-egress
    token-sha256: sha256:<hash of egress token>
    role: egress
    paired-agent: codex-probe
```

### Task 2 — egressd config wiring + Codex config

egressd config for the harness:

```json
{
  "broker_url": "http://broker:7347",
  "allow_insecure_broker": true,
  "routes": [
    { "listen": "127.0.0.1:8471", "capability": "codex-main", "upstream": "chatgpt.com" }
  ]
}
```

Notes:
- `allow_insecure_broker: true` is acceptable **only** because the harness
  runs broker and egressd on an isolated internal network the agent cannot
  reach (see task 4). Production uses broker TLS (`NVT_BROKER_TLS_CERT/KEY`).
  Document this explicitly so nobody copies the insecure setting to prod.
- One route per upstream host Codex needs. Start with `chatgpt.com`; add
  routes as the gate reveals required hosts. If Codex needs multiple hosts on
  one base URL, egressd may need host-based routing on a single listener —
  record that as a finding if it comes up.

Codex config the agent container gets (`~/.codex/config.toml`):

```toml
chatgpt_base_url = "http://127.0.0.1:8471"
# also test model_providers.*.base_url coverage:
# [model_providers.openai]
# base_url = "http://127.0.0.1:8471/v1"
```

The agent's `~/.codex/auth.json` gets the **placeholder** shape (task 3), not
the real file.

### Task 3 — Placeholder shape + claim-derived headers (empirical)

The plan's open question: what minimal placeholder does Codex accept at
startup, and does it send headers derived from token claims?

Steps:
1. Determine the minimal placeholder `auth.json` Codex accepts to enter
   plan-auth mode without a real token. Likely a syntactically valid,
   zero-entropy placeholder JWT (fake `header.payload.signature` with harmless
   claims) plus the stub refresh token. Record the exact minimal shape.
2. Observe whether the upstream receives (or rejects for lack of) auxiliary
   headers beyond `Authorization` — specifically any account-id header derived
   from the JWT claims.
3. **If claim-derived headers are required:** extend the `codex-oauth`
   provider's `injection_headers` to compute those headers from the **real**
   token's claims and return them in the injection response, and add the
   placeholder header names to `strip_request_headers`. The contract already
   supports this (injection returns a header *map*, and a strip list). Add a
   broker conformance test pinning that these headers are present and derived
   from the real token, never the placeholder.
4. **If no extra headers are needed:** record that as a finding; no provider
   change.

The placeholder JWT constant and `auth.json` shape, once determined, are the
Phase 3 bootstrap spec — capture them precisely in the gate document.

### Task 4 — Isolation topology (compose, harness-only)

macOS has no netns for host-level deny-all, so run the gate **inside
containers** on an internal-only network. This proves "does Codex try fixed
direct hosts" loudly: any non-redirected call fails with connection errors
enumerable from Codex's own output.

Topology (a dedicated `compose.phase2.yaml`, not the production compose files):

- `broker` — on `phase2-internal` only. Mounts the throwaway state dir with
  the copied `auth.json`. Not reachable by the agent.
- `egressd` — on **both** `phase2-internal` (to reach broker) and
  `phase2-egress` (a network with outbound internet). This is the only path
  out.
- `agent` — on `phase2-internal` only, `internal: true` (no internet).
  Runs the Codex CLI, config pointing at egressd, placeholder auth.json.

```yaml
networks:
  phase2-internal:
    internal: true      # no outbound internet for anything only on this net
  phase2-egress: {}     # egressd's outbound path
```

Because the agent is only on the `internal: true` network, its **only**
reachable outbound endpoint is egressd. A Codex attempt to reach a fixed host
directly fails at connect — exactly the signal the gate needs.

egressd needs an image: add a minimal `egressd/Dockerfile` (build the Go
binary, distroless/static base). This is legitimate Phase 2 scope (the harness
needs it) and reusable by Phase 3.

### Task 5 — Make target + evidence capture

Add a `make` target, e.g. `phase2-codex-gate`, that:

1. Builds broker, egressd, runtime images (or reuses `:latest`).
2. Creates a throwaway broker state dir; copies the real `auth.json` in;
   writes the harness broker.yaml/agents.yaml with generated tokens.
3. Brings up `compose.phase2.yaml`.
4. Runs a real Codex turn non-interactively in the agent container (e.g.
   `codex exec "print pong"` or the equivalent one-shot invocation — verify
   the correct non-interactive command).
5. Captures evidence into a gitignored `./.phase2-out/` dir:
   - egressd request log: which `(method, path, upstream)` tuples were
     fetched (metadata only — **never header values**).
   - broker audit tail (`injection.*` entries; metadata only).
   - Codex stdout/stderr (scan for connection failures to non-egressd hosts).
   - the effective host list Codex required.
6. Tears down.

Evidence-capture hygiene:
- egressd already never logs header values — keep the harness to that
  standard. Add a request-metadata log line to egressd only if it logs
  `(method, path, upstream, status)` and nothing credential-bearing.
- The script must fail loudly if any token-shaped string lands in
  `./.phase2-out/` (grep the output dir for the real token prefix and for
  `eyJ` JWT markers before declaring success).
- `.phase2-out/` and any throwaway state dir go in `.gitignore`.

### Task 6 — Real refresh proof

You cannot mint short-lived tokens against real `auth.openai.com`, and you do
not need to: set `refresh-margin-seconds` in the harness broker config
**larger than the current access token's remaining lifetime**. Then the first
injection forces the real refresh flow (real refresh token, real token URL)
before vending. Confirm from broker audit that an `injection.refresh` entry
appears and the turn still succeeds.

The mechanical cache-expiry / in-flight-stream behavior is already pinned
deterministically by egressd and broker tests with fakes — this task only
proves the **real** refresh works through the same path once.

### Task 7 — The gate document (the actual deliverable)

Write `docs/phase2-codex-gate.md` capturing:

- **Required hosts**: the exact host list Codex needed (and which base-URL key
  routed each).
- **Minimal placeholder shape**: the `auth.json` / JWT structure Codex accepts
  at startup with no real credential.
- **Claim-derived headers**: whether any were required, and if so which and
  how the provider derives them.
- **Cert pinning / TLS**: did localhost TLS re-origination work, or did Codex
  reject the egressd-terminated connection?
- **Bypass attempts**: did any Codex traffic try to reach a fixed host
  directly (observed as connect failures on the internal network)?
- **Decision**:
  - **GO** if `chatgpt_base_url` (+ any needed `model_providers.*.base_url`)
    covers all required traffic and TLS re-origination works → Phase 3 wires
    operator/compose for mediated codex-oauth.
  - **NO-GO** if Codex has non-redirectable fixed endpoints or cert pinning →
    keep Codex plan-auth on file bundles for now; mediate only redirectable /
    API-key providers. Phase 3 scope changes accordingly.
- **Evidence**: reference the captured logs (sanitized) that back each claim.

### Task 8 — Config examples

Add committed, non-secret examples for mediated `codex-oauth`:
- a broker provider block with `injection-hosts`,
- an agent + paired egress identity with `materialization: header-inject`,
- an egressd `config.json` route,
- the Codex `config.toml` redirection snippet.

Place under `docs/` or an `examples/` dir consistent with the repo. Use
placeholder hashes/tokens only.

## Deliverables checklist (for the PR)

- [ ] `compose.phase2.yaml` (harness only; internal-network topology)
- [ ] `egressd/Dockerfile`
- [ ] `make phase2-codex-gate` target + supporting script
- [ ] Placeholder `auth.json`/JWT shape determined and documented
- [ ] `codex-oauth` claim-derived header support **iff** the gate shows it's
      needed (+ conformance test)
- [ ] `docs/phase2-codex-gate.md` with host list, placeholder shape, headers,
      cert-pinning finding, and go/no-go decision
- [ ] Config examples for mediated codex-oauth
- [ ] `.gitignore` entries for `.phase2-out/` and throwaway state
- [ ] No operator/compose production wiring
- [ ] No credential material in repo, logs, or agent container (asserted by
      the harness before it reports success)

## Guardrails

- **Empirical gate, not architecture.** Resist scope creep into Phase 3.
- **The user does not have a Codex API key.** This phase uses the real
  ChatGPT-plan `auth.json` the broker already owns; it must never require an
  API key, and the agent container must never receive the real auth file.
- **Trusted-core review still applies** to any `codex-oauth` provider change
  (claim-derived headers): compute from the real token, strip placeholders,
  never log values.
- **Fail closed and fail loud**: if the harness cannot prove non-possession
  (no token in the agent container) it must report failure, not a soft pass.
- The gate can legitimately return **NO-GO**. That is a successful phase
  outcome — a documented answer — not a failure of the work.
```
