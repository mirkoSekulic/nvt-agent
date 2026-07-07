# PR 6.1 Plan: Generic placeholder-file materialization

Status: landed — generic placeholder-file materialization, Codex preset, and
runtime materialization implemented with fixture-level tests (no real secrets).
The real tool-behind-a-placeholder-file win is demonstrated after 6.2 merges
(the honest dependency noted below).
Parent: [mediated-egress-plan.md](mediated-egress-plan.md) §"Phase 6", sequence
row 7. This is the broker/provider half of Phase 6, split out from
[phase6.2-forward-proxy-pr-plan.md](phase6.2-forward-proxy-pr-plan.md) (row 8)
so each trusted-core surface is reviewed on a phase-sized diff.

## Why this is its own PR

The forward-proxy work (6.2) and this materialization contract compose at
runtime, but they are two independent trusted-core surfaces — a broker/provider
credential contract here, egressd CA-leaf-widening + CONNECT-MITM there.
Bundling them doubles the review surface, against the parent plan's whole
sequencing discipline. So this lands first, reviewed alone as a
broker/provider/runtime change with **fake Codex-shaped fixtures and no real
secrets**, and 6.2 consumes it.

**Honest dependency**: a placeholder file is inert on its own — it only becomes
useful once something at the network edge swaps the placeholder for the real
credential (6.2's MITM injection). This PR therefore ships the *contract and
its tests*, provable end-to-end at the fixture level, but the real
tool-behind-a-placeholder-file win is only demonstrated after 6.2 merges. That
is an accepted, stated ordering, not a hidden gap.

## Goal

Give providers a generic, broker-owned way to materialize **syntactically
valid auth/config files containing only placeholders** into the agent, while
the real secret material stays in broker/provider custody. This is the missing
primitive for file-based tools (Codex's `~/.codex/auth.json`, Claude-style
`.credentials.json`, any JSON auth file) that neither `redirect-env` nor
base-url wiring can reach: the tool reads a local auth *file*, so mediation
needs a file it will accept that carries no real secret.

This is the mechanism that moves such tools **off the `file-bundle` fallback**
(usable credentials written into the container — the exact thing the
zero-secrets invariant exists to eliminate) toward true non-possession. Codex
is the first proof, as a provider preset, not a core special case.

## The load-bearing decision (read first)

`placeholder-file` is **not** `file-bundle`. `file-bundle` writes usable
credential material into the agent (the dev/fallback path). `placeholder-file`
writes only inert placeholders; the real values never leave broker/provider
state. Keeping these distinct — separate materialization mode, separate
admission, separate tests — is what preserves the zero-secrets invariant while
still satisfying a tool that demands a local file.

Corollary, **host files are import-only**: production placeholder files are
generated from broker/provider state, never copied from the developer host at
runtime. A local dev helper may *import* an existing `~/.codex/auth.json` into
broker state for convenience, but the runtime path never reads a host auth
file as the source of truth and never copies real values into the agent.

## Decisions settled here (don't relitigate in the PR)

1. **Broker owns the secret; the agent gets placeholders.** The agent receives
   file contents, path, mode, and public metadata only. Real secret fields
   remain in broker/provider state (this PR does not change where refresh
   happens; `codex_oauth` remains the single refresh-token writer).
2. **Generic contract, provider presets.** The core shape is generic —
   placeholder files/env entries, secret-field selectors, allowed hosts,
   optional placeholder shapes. Codex-specific rules live in a
   provider/preset, never in `agentd`, bootstrap core, or egressd. `agentd`
   owns only session I/O; this is a provider contract with a simple config
   surface (per AGENTS.md).
3. **Secret vs identity fields are distinguished, not blanket-placeholdered.**
   In a token file, secret fields (`access_token`, `refresh_token`, and for
   Codex the `id_token`'s signature) become placeholders; **non-secret
   identity metadata a tool reads locally may be real or realistic**. Codex's
   `id_token` in particular carries claims the CLI parses before any network
   call (subject/account id, plan/subscription-ish fields, `exp`); a
   syntactically-valid-but-empty JWT is not enough. See decision 4.
4. **`jwt` placeholder shape carries plausible claims + far-future `exp`.** The
   `jwt` shape emits a syntactically valid JWT whose *claims* are populated
   from the provider's known non-secret identity (account id / subject, an
   email that may be a placeholder-safe value, any plan fields the CLI reads)
   and a far-future `exp` so a tool that checks local token expiry starts
   without attempting a refresh. The signature is a placeholder — it is never
   verified locally, and the real bearer token is injected at the edge (6.2).
   The broker already extracts these claims today (the Phase 4
   `injection-claim-headers` path), so the provider can emit them without new
   secret exposure.

## Work items

### 1. Broker/provider: `placeholder-file` materialization

Where: the broker files/materialization path (`broker/core/server.py` +
provider interface), `broker/plugins/codex_oauth/`, `protocol/broker.md`,
`protocol/injection.md`, `tests/broker`.

- New provider-owned materialization mode `placeholder-file`, distinct from
  `file-bundle`. Response gives the agent: file path, mode, and rendered
  content containing placeholders only, plus public metadata (allowed hosts).
- Generic contract supports:
  - file path and mode (e.g. `.codex/auth.json`, `0600`);
  - a JSON template or provider-generated JSON object;
  - secret-field selectors by key/path (e.g. `access_token`, `refresh_token`,
    keys matching `*_token`);
  - per-placeholder allowed-hosts bindings (which upstream hosts the
    placeholder is valid for — consumed by 6.2's route/injection map);
  - optional placeholder shapes: `plain` (opaque placeholder string) and
    `jwt` (decision 4 — claims + far-future exp, placeholder signature).
- Identity model unchanged: only the paired egress identity / the agent's own
  grant fetches its bindings; an agent identity cannot fetch another agent's.
  Materialization returns no real secret on any path.

### 2. Codex provider preset

Where: `broker/plugins/codex_oauth/` (or a preset alongside it), tests.

- Broker-owned Codex OAuth state emits `.codex/auth.json` with: placeholder
  `access_token` and `refresh_token`; a `jwt`-shaped `id_token` carrying the
  real non-secret account claims + far-future exp; host bindings for
  `chatgpt.com`, `api.openai.com`, and `auth.openai.com` (the refresh
  endpoint — load-bearing for 6.2's refresh mediation).
- Local-import helper (dev only) to seed broker/provider state from an
  existing `~/.codex/auth.json`, clearly outside the runtime path.

### 3. Runtime: materialize placeholder files

Where: `runtime/core/bootstrap.py` (or the existing broker-auth-files path),
`tests/runtime`.

- Materialize provider-owned placeholder files into the agent home/workspace
  exactly as the broker/provider response instructs (path, mode, content).
- Bootstrap must **never** read host auth files as the runtime source of truth
  and **never** write real provider tokens in this mode. Host-file import is a
  separate dev helper, not the agent runtime path.

## Tests

- A broker/provider fixture whose state contains real token strings
  materializes a placeholder file with **no real token bytes** (secret scan
  over the materialized file/env is clean, with the real strings as needles).
- `id_token` is JWT-shaped when requested and carries the expected non-secret
  claims (account id, far-future exp); its signature is a placeholder.
- Placeholders are stable across repeated materialization of the same grant
  (idempotent), and each placeholder is bound to the expected hosts.
- Agent identities cannot fetch real placeholder bindings directly; only the
  granted path returns them, and it returns placeholders.
- Runtime: a `placeholder-file` run writes the expected auth file containing
  placeholders and no real material; the non-possession smoke needle list
  gains the real provider token strings.

## Commit order (reviewable, tests-first per commit)

1. Generic `placeholder-file` materialization contract + protocol doc +
   broker tests (fixtures only, no real secrets)
2. Codex provider preset (`.codex/auth.json` template, `jwt` id_token,
   host bindings incl. `auth.openai.com`) + preset tests
3. Runtime materialization + runtime test
4. Docs (protocol/broker.md, protocol/injection.md)

## Review checklist (trusted-core items)

- Real tokens stay broker-owned; the agent-facing materialization writes
  placeholders only, on every path including errors.
- `placeholder-file` is a distinct mode from `file-bundle`; no path writes
  usable credentials in `placeholder-file` mode.
- Host files are import-only; nothing in the runtime path reads a host auth
  file as the source of truth.
- `jwt` id_token carries only non-secret identity claims + a placeholder
  signature; no real secret leaks through a claim.
- Agent identity cannot obtain another agent's bindings; materialization is
  scoped like every other grant.
- Codex specifics live in the provider/preset and tests — not in `agentd`,
  bootstrap core, or egressd.

## Explicitly out of scope

- **egressd CA-leaf-widening, CONNECT-MITM, `HTTPS_PROXY`/`NO_PROXY`** — all
  of that is PR 6.2. This PR ships no egressd change.
- **The real Codex end-to-end proof** — needs 6.2's MITM to swap the
  placeholder for the real token; it is 6.2's go/no-go spike. This PR proves
  the materialization mechanics at the fixture level only.
- **Body/query placeholder substitution** — deferred (see 6.2).
- Host-auth-file runtime sourcing — a dev import helper at most, never the
  runtime architecture.
