# Phase 4 Plan: git-over-HTTPS Mediation

Status: plan — implementation not started
Parent: [mediated-egress-plan.md](mediated-egress-plan.md) §5, Phase 4 (PR 5 in the sequence table)

## Goal

Non-possession for GitHub tokens. The agent runs `git clone/fetch/push` over
HTTPS while the repo-scoped installation token exists only in the broker and
egressd. Inspect the agent container — filesystem, env, process args — and find
zero git credential material. This closes the last large credential class in
the zero-secrets invariant.

## Non-goals (each is its own phase)

- Egress enforcement, NetworkPolicy, iptables — Phase 5. Interim honesty per
  parent §5: the agent can still *reach* github.com directly at Phase-4 time;
  it just gets nothing from doing so (401 without a token).
- CONNECT-MITM, transparent proxying, proxy-env wiring — Phase 6 (reuses the
  CA built here).
- git-SSH — disallowed in mediated mode, permanently.
- Production Anthropic/Codex redirect wiring — focused provider PRs.

## Starting position (what already exists)

Less greenfield than it sounds. Three primitives are already in the tree;
Phase 4 connects them with a CA in the middle:

- **egressd TLS serving**: per-route `listen_tls_cert`/`listen_tls_key` and
  `Route.TLSEnabled()` (`egressd/internal/egress/config.go`), served via
  `ListenAndServeTLS` in `cmd/egressd/main.go`. Static files only today; no
  on-the-fly leaf signing.
- **Repo-scoped GitHub App minting**: `broker/plugins/github_app/provider.py`
  — `_mint_token(repo)` scopes each installation token to a single repo;
  `_ensure_repo_allowed()` intersects the provider allowlist with the agent
  grant's `repositories`; `github_repo_from_target()` and `_repo_from_path()`
  already parse repo identity out of targets/paths.
- **Injection contract carries `path`**: `POST /v1/injection/headers` takes
  `{capability, host, method, path}` (`protocol/injection.md`), but the only
  injection providers so far (`static_token`, `codex_oauth`) ignore
  method/path. `github_app` becomes the first real consumer. **The protocol
  doc needs no shape change** — repo scoping is provider-internal, behind the
  unchanged contract.

## Design decisions

### 1. Routing model: redirect, not MITM

Consistent with the redirectable phases: do not intercept `github.com`.
Bootstrap installs a managed rewrite after `scrub_git_state()` runs (scrub
removes *pre-existing* rewrites, then we install our own):

```
url."https://127.0.0.1:<git-port>/".insteadOf = "https://github.com/"
```

egressd serves HTTPS on that port with a leaf cert the agent trusts via the
per-agent CA. No SNI interception in this phase; Phase 6 CONNECT-MITM reuses
the same CA machinery later.

### 2. CA custody: generated inside egressd at boot, never in etcd

The CA private key is subject to the same zero-secrets invariant as every
other credential: it exists only in the trusted sidecar. Two options
considered:

- *Operator-generated Secret* — reuses the `reconcileTokenSecret` pattern, but
  puts the CA key in etcd and operator memory. Wider custody surface than
  necessary. Rejected.
- *egressd-generated at boot* — **chosen**. egressd generates the CA keypair
  on startup, keeps the key in its own private volume/memory, and publishes
  **only `ca.crt`** to a small shared `emptyDir` mounted read-only in the
  agent container. Compose gets the identical shape via a shared volume.
  Bootstrap waits for `ca.crt` with a fail-closed timeout.

Hardening in the same stroke:

- Leaf certs minted on demand via `tls.Config.GetCertificate` (SAN =
  `127.0.0.1` / route hostname, hours-scale TTL, cached).
- **Name constraints on the CA** so even a leaked key cannot sign for
  arbitrary hosts.
- Agent-side deletion of `ca.crt` or `GIT_SSL_NO_VERIFY` is self-DoS, not a
  bypass (parent §5): it breaks the agent's own git and still yields no token.

### 3. Broker: `github_app` becomes an injection provider

Add `injection_headers(host, method, path)` and `injection-hosts:
[github.com]` to the provider:

- **Repo extraction** — handle git-HTTP shapes
  (`/{owner}/{repo}.git/info/refs`, `/{owner}/{repo}.git/git-upload-pack`,
  `git-receive-pack`) alongside the existing API shape, reusing
  `github_repo_from_target()` / `_repo_from_path()`.
- **Authorization** — extracted repo runs through the existing two-layer
  `_ensure_repo_allowed()` check; minting stays single-repo-scoped via
  `_mint_token(repo)`.
- **Header dialect** — git paths get `authorization: Basic
  base64(x-access-token:<token>)`; API paths get `Bearer`. `expires_at` from
  token expiry minus the existing 300s buffer. `strip_request_headers:
  [authorization]`.
- **Write-path scoping** — `git-receive-pack` (push) requires the grant to
  carry write permission; `upload-pack` (fetch) needs read only. This is the
  first method/path-based authorization decision in the injection path —
  pinned by conformance tests.

### 4. egressd: generalize TLS serving + a git-aware route

Extend `Route` with a `listen_tls: ca` mode backed by the boot-generated CA;
static cert/key files remain supported. The existing `Proxy` (placeholder
stripping, fail-closed cache, pinned upstream, `validateUpstream` SSRF guard)
is reused as-is — git traffic is just another capability route to
`github.com:443`.

**Spike item**: verify git smart-HTTP POST bodies (chunked pack uploads,
`Expect: 100-continue`, large clones) stream through `buildOutbound` without
buffering. The SSE path suggests it works; it needs a test, not an assumption.

### 5. Lift the exactly-one-grant limit (Phase 4 forces multi-route)

A realistic mediated run needs an LLM grant *and* a git grant. Route plumbing
already allocates `127.0.0.1:8471+i` per route
(`RenderEgressdConfigJSON`); the limit lives only in admission and
`agent-init`. Extend both to N header-inject grants, each with its own
route/port and per-grant `redirect-env`/`base-url`. This resolves the parent
plan's "until multi-route agent config is fully designed" deferral.

### 6. Runtime bootstrap wiring

For a git-typed grant, `apply_mediated_egress()` additionally:

- waits for `ca.crt` (fail-closed timeout),
- `git config --global http.sslCAInfo <ca.crt>` (config, not env, so it
  survives shells),
- installs the managed `insteadOf` rewrite,
- sets `GIT_TERMINAL_PROMPT=0`,
- exports trust-related env only via the existing `redirect-env` mechanism
  (sources remain `base-url` | `placeholder` — nothing here can carry a
  secret by construction).

Optional convenience: also rewrite `git@github.com:` → mediated HTTPS; SSH
otherwise stays hard-disallowed.

## Work breakdown (tests-first)

| # | Work item | Where | Test that pins it |
|---|---|---|---|
| 1 | `github_app.injection_headers` + git-path repo extraction + read/write permission mapping | `broker/plugins/github_app/` | `tests/broker/injection_conformance_test.go`: repo allow/deny, path shapes, push-needs-write, egress-role-only, token never vended to agent identity, audit entries |
| 2 | CA generation at boot, cert publication, `GetCertificate` leaf signing, name constraints | `egressd/internal/egress/`, `cmd/egressd/main.go` | First real TLS e2e in `proxy_test.go`: client with CA pool → HTTPS route → fake git upstream sees injected Basic auth; client-supplied auth stripped; CA key never readable via the shared volume |
| 3 | git smart-HTTP streaming proof | egressd tests | `git ls-remote`/`clone` against a fake `info/refs` + `upload-pack` upstream through egressd — CI-able, no GitHub dependency |
| 4 | Bootstrap git wiring (sslCAInfo, insteadOf, cert wait) | `runtime/core/bootstrap.py` | `mediated_smoke_test.go`: scrub still holds, rewrite + CA config present, secret scan gains needles for the installation token **and the CA private key PEM** |
| 5 | Multi-grant admission + operator CA/TLS rendering (shared emptyDir, TLS fields in `RenderEgressdConfigJSON`) | `operator/internal/controller/` | Controller tests: N grants → N routes; volume shape (key not mounted in agent); admission failures stay loud |
| 6 | Kind smoke: git grant variant | `tests/operator/kind/cases/mediated-egress.sh` | Pod shape incl. CA volumes/mounts; agent sees cert only |
| 7 | Docs: parent plan §5 update to v3.6; provider doc for git path shapes | `docs/`, `protocol/` | — |

Build order: 1 → 2/3 (parallel once contract tests exist) → 4 → 5/6 → 7. One
PR per the parent plan's sequencing constraint (PR 5, deliberately alone),
structured as reviewable commits in that order.

## Trusted-core review checklist

TLS termination is the highest-risk surface in the design; this is why the
phase ships alone. Review must specifically cover:

- request smuggling through the proxy hop,
- upstream-host confusion / SSRF (upstream stays pinned per-route),
- CA key custody and volume permissions,
- leaf cert scope: SAN minimalism, short TTL, name constraints,
- token/header non-logging on every error path,
- placeholder-strip guarantee extended to `Basic` credentials git clients may
  volunteer.

## Open questions (settled in the PR, not before)

- Grant schema for "this is a git grant" — likely implied by provider type
  (`github-app` + `header-inject`), no new field.
- Compose `agent-init`: CA generated host-side vs. egressd entrypoint —
  recommend entrypoint, for parity with k8s.
- Leaf cert for `127.0.0.1` IP SAN vs. a synthetic hostname — git/curl both
  accept IP SANs; test decides.
