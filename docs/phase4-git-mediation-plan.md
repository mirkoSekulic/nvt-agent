# Phase 4 Plan: git-over-HTTPS Mediation

Status: implemented — see the Phase 4 PR for the delivered work breakdown
Parent: [mediated-egress-plan.md](mediated-egress-plan.md) §5, Phase 4 (PR 5 in the sequence table)

## Goal

Non-possession for GitHub tokens. The agent runs `git clone/fetch/push` over
HTTPS while the repo-scoped installation token exists only in the broker and
egressd. Inspect the agent container — filesystem, env, process args — and find
zero git credential material. This closes the last large credential class in
the zero-secrets invariant.

## Non-goals (each is its own phase)

- Egress enforcement, NetworkPolicy, iptables — Phase 5. Interim honesty per
  parent §5: the agent can still *reach* github.com directly at Phase-4 time.
  Direct access gets no mediated credential — private-repo and write-scoped
  operations fail — but public unauthenticated operations still work until
  Phase-5 enforcement lands. Do not read Phase 4 as blocking direct GitHub
  reach.
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

- Leaf certs minted on demand via `tls.Config.GetCertificate` (hours-scale
  TTL, cached). **Leafs are minted only for local redirect names** — IP SAN
  `127.0.0.1` or a synthetic local hostname — never for real upstream names
  such as `github.com`. Minting upstream-name SANs is exactly the line
  Phase 6 crosses deliberately; Phase 4 must not cross it.
- **Name constraints on the CA** so even a leaked key cannot sign for
  arbitrary hosts. Defense-in-depth, not the boundary: the primary invariant
  remains CA key only in egressd, CA cert only in the agent trust store,
  leafs only for local redirect names.
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
- **Permission shape (defined here, not improvised in the PR)** — grants gain
  `permissions: { contents: read | write }`, mirroring GitHub App permission
  keys. Default is `read`. The grant-level map intersects with the existing
  provider-level `permissions` config (already passed into the mint body by
  `_mint_token`); the broker maps `git-receive-pack` → requires
  `contents: write` and mints the token with the narrower of the two.

### 4. egressd: generalize TLS serving + a git-aware route

Extend `Route` with a `listen_tls: ca` mode backed by the boot-generated CA;
static cert/key files remain supported. The existing `Proxy` (placeholder
stripping, fail-closed cache, pinned upstream, `validateUpstream` SSRF guard)
is reused as-is — git traffic is just another capability route to
`github.com:443`.

**Explicit upstream identity requirement**: the client-facing host is
`127.0.0.1` (via the `insteadOf` rewrite), but the outbound URL, `Host`
header, and TLS SNI must all be forced to the pinned route upstream — never
derived from the client request's Host. `buildOutbound` already forces
URL/Host to `Route.Upstream`; Phase 4 states this as a requirement, extends
it explicitly to SNI on the re-originated TLS connection, and pins it with a
test on the git route (the first route where client-facing and upstream
identities diverge).

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
| 2 | CA generation at boot, cert publication, `GetCertificate` leaf signing, name constraints | `egressd/internal/egress/`, `cmd/egressd/main.go` | First real TLS e2e in `proxy_test.go`: client with CA pool → HTTPS route → fake git upstream sees injected Basic auth; **agent-supplied `Authorization: Basic <garbage>` is stripped — upstream sees only the broker-injected Basic header, exactly once**; outbound Host + SNI = pinned upstream, never client Host; leaf SANs are local-only (no upstream names); CA key never readable via the shared volume |
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

## Open questions (settled in the PR)

- Grant schema for "this is a git grant" — split by trust domain. Broker-side
  there is no flag: git capability is implied by the provider type
  (`github-app` with `injection-hosts`), and `/v1/injection/routing` reports
  it as a non-secret `git: true` hint that drives bootstrap wiring. The run
  spec (AgentRun grant / compose `agents.yaml` grant) carries an explicit
  `git: true`, because the operator and `agent-init` cannot see broker
  provider plugin types but must render the TLS route, CA volume, and https
  base-url.
- Compose `agent-init`: CA generated by egressd at boot from its config
  (`ca.publish_dir`), never host-side — identical shape to k8s, key never
  exists outside the egressd process.
- Leaf cert: `127.0.0.1`/`::1` IP SANs plus a `localhost` DNS SAN; the git
  smart-HTTP e2e test clones over `https://127.0.0.1:<port>` with only
  `http.sslCAInfo` set, so no synthetic hostname is needed.
