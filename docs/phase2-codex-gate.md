# Phase 2 Gate — Codex Plan-Auth Mediation: Findings & Decision

Status: **TEMPLATE — fill from a `make phase2-codex-gate` run**
Parent: `docs/mediated-egress-plan.md` (Phase 2), spec:
`docs/phase2-codex-gate-plan.md`

This document is the deliverable of Phase 2. It records the empirical answer to:

> Can real Codex ChatGPT-plan auth be fully mediated through egressd via
> base-URL redirection, with the agent container holding **no** real
> credential?

Fill each section from `.phase2-out/evidence/` after running the harness. Do
not paste raw tokens — reference sanitized evidence only.

## How to run

```
make phase2-codex-gate
# variables:
#   PHASE2_AUTH_SOURCE           real auth.json (default .broker/codex/auth.json)
#   PHASE2_SCHEME                https (default, egressd serves TLS) | http
#   PHASE2_UPSTREAM              upstream host (default chatgpt.com)
#   PHASE2_CODEX_CMD             the turn (default: codex exec "print pong")
#   PHASE2_MODEL_PROVIDER_BASE   optional: also set model_providers.openai.base_url
#                                to test the API-style path (recorded as a finding)
```

Evidence lands in `.phase2-out/evidence/`:
`summary.txt`, `codex-stdout.txt`, `codex-stderr.txt`, `egressd.log`,
`broker-audit.jsonl`, `injection-audit.jsonl`.

## The three possible outcomes (decision guide)

Run `PHASE2_SCHEME=https` first (Codex almost certainly requires https). Then:

| Observation | Meaning | Decision |
|---|---|---|
| Turn completes over `https` with the per-agent CA | Codex requires https but does **not** pin certs; TLS re-origination works | **GO** |
| Turn fails over `https` with a cert/pinning error, even with the CA trusted | Codex **pins certs** on the plan-auth host | **NO-GO** for plan-auth (keep on file bundles); mediate redirectable/API-key providers only |
| Turn fails because Codex called a host **not** covered by `chatgpt_base_url` | fixed/hardcoded endpoint outside the base URL | **NO-GO or partial** — record the host; may need multi-route or transparent mode (Phase 6) |
| Turn completes over `http` (if you also test `PHASE2_SCHEME=http`) | base URL fully covers traffic, no TLS requirement | **GO** (simplest) |

A NO-GO is a **successful phase outcome** — a documented answer — not a
failure of the work.

## Findings (fill in)

### Required hosts
_The set of hosts Codex needed, and which base-URL key routed each. From
`egressd.log` (routed) and `codex-stderr.txt` (connect failures to
un-routed hosts on the internal network)._

- `chatgpt.com` — routed via `chatgpt_base_url`? (yes/no)
- `auth.openai.com` — needed for refresh? routed how?
- others: …

### Minimal placeholder shape
_What `auth.json` shape Codex accepted at startup with no real credential.
The harness uses a placeholder JWT (`header.payload.NVT-PLACEHOLDER-NOT-A-KEY`)
with far-future `exp` and a placeholder account claim. Record whether that was
sufficient, or what minimum Codex actually needs._

### Claim-derived headers
_Did the upstream require headers beyond `Authorization`? The harness injects
`chatgpt-account-id` from the real token's `https://api.openai.com/auth →
chatgpt_account_id` claim and strips the placeholder. Record whether it was
required, and the exact header name / claim path if different._

### TLS / cert pinning
_Did localhost TLS re-origination work with the per-agent CA, or did Codex
reject the egressd-terminated connection? Distinguish "requires https"
(CA works) from "pins certs" (CA cannot help)._

### Bypass attempts
_Did any Codex traffic try to reach a fixed host directly? On the internal
network these appear as connect failures in `codex-stderr.txt`. List them._

### Refresh
_Refresh is **forced**: the harness computes the margin from the source token's
`exp`, so the first injection always triggers the real refresh flow. Confirm
`summary.txt: refresh_seen` ≥ 1 and `injection.refresh` entries in
`broker-audit.jsonl`, and that the turn still succeeded._

### model_providers coverage (optional)
_Only if run with `PHASE2_MODEL_PROVIDER_BASE`. Record whether the API-style
path also routed through egressd or hit a fixed host. Default runs gate
`chatgpt_base_url` plan-auth traffic only._

### Non-possession
_The harness fails loudly if any real token value **or fragment** appears in:
the agent's `auth.json`, the agent container's env, its process args
(sampled during the run), its codex home, or any captured evidence
(egressd log, broker audit, codex stdio). Confirm "no credential leakage
detected (agent fs/env/args + evidence)" in the run output._

## Decision

**GO / NO-GO / PARTIAL:** _____

**Rationale:** _____

**Consequence for Phase 3:**
- GO → wire operator/compose for mediated `codex-oauth` (Phase 3 as planned).
- NO-GO (cert pinning) → keep Codex plan-auth on `file-bundle`; ship mediation
  for redirectable/API-key providers; revisit with transparent mode (Phase 6).
- PARTIAL (extra hosts) → enumerate hosts; decide multi-route now vs. Phase 6.

## Evidence references
_Link the sanitized files under `.phase2-out/evidence/` that back each claim._
