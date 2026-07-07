# PR 6.2 Plan: TLS-terminating forward-proxy mode (+ Codex proof)

Status: plan — implement after PR 6.1 merges
Parent: [mediated-egress-plan.md](mediated-egress-plan.md) §"Phase 6", sequence
row 8. Prerequisite:
[phase6.1-placeholder-file-materialization-pr-plan.md](phase6.1-placeholder-file-materialization-pr-plan.md)
(row 7 — the placeholder-file contract this PR consumes). Step 2 (transparent
iptables REDIRECT/TPROXY, row 9) is a **separate** plan after this.

## Goal

Close the main coverage gap: arbitrary/unmodifiable tools with hardcoded
endpoints that honor proxy env vars. Set `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`
in the agent container and make egressd terminate `CONNECT` under the Phase 4
per-agent CA, inject the credential, and re-originate TLS to the real
upstream — so most CLIs, language HTTP clients, and SDKs get mediated with
**zero per-tool config** and **zero header-injection-contract changes**.

Combined with the PR 6.1 placeholder-file contract, this is what lets a
file-based tool run in true non-possession: 6.1 gives it a placeholder auth
file, the tool emits the placeholder in its request, and this PR's MITM strips
the placeholder and injects the real broker-owned credential at the edge.
**Codex is the integration proof** (work item 4b) — and a real go/no-go, not
an assumed win (see below).

This reuses machinery that already exists: the per-agent CA (Phase 4), the
CONNECT-only forward-proxy listener (Phase 2b), the injection path + material
cache + fail-closed (Phase 1), the quota + audit + enforcement layer (Phase 5),
and the placeholder-file contract (6.1). The genuinely new, highest-risk
element is that egressd now mints leaf certs for **real upstream names** — the
line Phase 4 deliberately refused to cross — so the entire design is gated on a
per-grant host allowlist, in two independent layers.

## The load-bearing security decision (read first)

Phase 4/5 minted leafs **only for local/synthetic names** (localhost, per-run
Service DNS names) and put critical name constraints on the CA forbidding
upstream names, precisely so a leaked CA key could not impersonate
`api.anthropic.com` to the agent. Forward-proxy MITM **requires** egressd to
present a valid-looking cert for the real upstream SNI. This PR relaxes that,
but bounds it hard:

- egressd mints an upstream-name leaf **only** for a host that appears in some
  granted capability's `injection-hosts` (the mediated allowlist). Any other
  SNI is refused at `GetCertificate` — no leaf, handshake fails.
- The CA name constraints are widened to exactly `localhost` + local names +
  the union of allowlisted `injection-hosts`, and nothing else. A leaked key
  still cannot sign for an arbitrary host.
- Two independent gates, both fail-closed: (1) the CONNECT allowlist refuses a
  non-allowlisted `host:port` before any handshake; (2) `GetCertificate`
  refuses to mint a leaf for a non-allowlisted SNI even if CONNECT were
  bypassed. Neither alone is the boundary; both are pinned by test.
- The private CA key custody is unchanged (per-agent, in egressd only, durable
  Secret per 6a). Widening *which names it may sign* does not widen *who holds
  it*.

This section is the trusted-core review's primary focus. Everything else is
plumbing around it.

## Decisions settled here (don't relitigate in the PR)

1. **Header injection only.** egressd MITMs the CONNECT, injects the
   broker-provided headers into the decrypted request, and re-originates TLS —
   exactly the Phase 4 `Proxy` injection logic, now reached via CONNECT+SNI
   instead of a base-url rewrite. **Body/query placeholder substitution is out
   of scope** unless the Codex proof (4b) empirically requires it, in which
   case: stop and revise the plan first, do not quietly add broad body
   substitution.
2. **Route selection by SNI/CONNECT host, mapped to a capability.** The CONNECT
   target host is matched against each header-inject grant's
   `injection-hosts`. A host that maps to a capability is MITM'd + injected. A
   host that is not mapped is **denied** (fail-closed) — no allow-but-
   passthrough tier (that is a policy knob for later; keep the first version
   deny-by-default with no unmediated escape).
3. **Opt-in, and only under enforcement.** Forward-proxy mode is enabled per
   run via a new field (naming TBD, e.g. `spec.egressForwardProxy: true`) and
   **requires `spec.egressEnforcement`**: without the CNI fence the agent can
   ignore the proxy env and reach hosts directly, so proxy mode without
   enforcement is coverage theater. Admission rejects the combination loudly.
4. **`NO_PROXY` is operator-rendered.** The agent points `HTTP(S)_PROXY` at
   egressd, but broker, operator callback, kube-dns, localhost, and the egressd
   Service itself must go direct. `NO_PROXY` is computed by the operator (it
   knows those endpoints), not hand-authored, so a missed entry can't silently
   route infra through the MITM.
5. **Consumes the 6.1 placeholder-file contract; no new materialization here.**
   The placeholder auth file the Codex proof relies on comes from the merged
   6.1 contract. This PR adds no materialization mode.
6. **No change to the header-injection endpoint.** `/v1/injection/headers`
   already takes `(capability, host, method, path)`. Forward-proxy requests
   call it exactly as redirect routes do; changing its shape is a regression.

## Work items

### 1. egressd: TLS-terminating CONNECT handler

Where: `egressd/internal/egress/forward_proxy.go`, `ca.go`, `config.go`,
`cmd/egressd/main.go`, new `forward_proxy_mitm_test.go`.

- Extend `ForwardProxyConfig` with a TLS-terminating mode: a per-host →
  capability map (or a list of `{host, capability, upstream}` route entries)
  and a `terminate_tls: true` flag. The existing blind-tunnel path stays for
  diagnostics/future policy; injectable hosts use the TLS-terminating path.
- On CONNECT to an allowlisted, injectable host: respond `200 Connection
  Established`, then TLS-handshake with the client using `ca.ServerTLSConfig()`
  whose `GetCertificate` mints a leaf for the SNI — **only if the SNI is an
  allowlisted host** (extend the Phase 4 `allowedLeafName` set with the
  configured upstream hosts; refuse otherwise). Then serve the decrypted
  request through the existing `Proxy` injection logic (material fetch, header
  inject, placeholder strip, re-originate TLS to the pinned upstream, stream).
- CA changes (`ca.go`): `GetCertificate` allowlist and the CA
  `PermittedDNSDomains` gain the configured upstream hosts. Add IP-SAN refusal
  for upstreams. Keep local/synthetic names working.
- Reuse, do not fork: the per-request injection is the same `Proxy.material` +
  `buildOutbound` path; quota (`quotaExceeded`) and audit (`report`) apply to
  each proxied request exactly as on redirect routes. CONNECT allow/deny audit
  (`writeDecision`) stays.
- Tests (egressd, `-race`): client → proxy CONNECT → egressd terminates → fake
  upstream sees the broker-injected header and never the placeholder; a leaf is
  minted for the allowlisted SNI and **refused** for a non-allowlisted SNI
  (both gates pinned independently); outbound Host + SNI pinned to the upstream
  (SSRF guard); broker-down fails the proxied request closed (no plaintext, no
  bypass); quota N+1 fails closed on the proxied path; streaming passes
  through.

### 2. Operator: render forward-proxy config, env, NO_PROXY, admission

Where: `operator/api/v1alpha1/agentrun_types.go` + both CRD copies,
`ValidateAgentRunEgressMode`, `RenderEgressdConfigJSON`, `DesiredAgentPod`,
controller tests.

- New spec field (e.g. `EgressForwardProxy bool`). Admission: requires
  `egress: mediated` **and** `egressEnforcement: true`; the combination error
  names the field.
- `RenderEgressdConfigJSON`: emit the forward-proxy TLS-terminating block with
  the per-host→capability map derived from the header-inject grants'
  `egressHosts`/`injection-hosts` (for Codex: `chatgpt.com`, `api.openai.com`,
  and `auth.openai.com` — the refresh endpoint), plus the CA leaf-name
  extension for those hosts. The forward-proxy listener binds a fixed local
  port (e.g. `0.0.0.0:8473`).
- `DesiredAgentPod`: set `HTTP_PROXY`/`HTTPS_PROXY=http://<egressd>:<port>`
  (own-Pod Service in enforcement mode) and a computed `NO_PROXY` covering the
  broker Service, operator callback, kube-dns, `localhost`/`127.0.0.1`, the
  cluster domain, and the egressd Service host. The CA is already installed
  into the agent trust store by the 6b bootstrap — verify it covers proxy-env
  HTTPS clients.
- NetworkPolicy: add the forward-proxy port to the agent→egressd egress rule
  and the egressd ingress rule; egressd → upstream :443 is already allowed. No
  new internet reachability for the agent.
- Controller tests: field admission (enforcement required); rendered config has
  the TLS-terminating block with the right host→capability map (incl.
  `auth.openai.com`) and CA leaf names; agent Pod has `HTTP(S)_PROXY` + a
  `NO_PROXY` including broker/callback/DNS/localhost; non-forward-proxy runs
  render none of it.

### 3. Bootstrap: proxy env + trust verification

Where: `runtime/core/bootstrap.py`, `tests/runtime/mediated_smoke_test.go`.

- The proxy env vars are non-secret (they point at egressd). Confirm the CA
  trust-store install (6b) runs whenever forward-proxy mode is on. Confirm
  `NO_PROXY` from the operator reaches the agent unchanged (bootstrap does not
  compute it).
- Runtime test: with forward-proxy egress config the agent env carries
  `HTTP(S)_PROXY` and a `NO_PROXY` including the infra hosts; the CA is
  trusted; secret scan stays clean.

### 4. kind smoke: arbitrary-tool coverage

Where: new `tests/operator/kind/cases/forward-proxy-egress.sh`, reuse the
hermetic echo fixture and Calico cluster from 6a/6b.

- A run with forward-proxy + enforcement, an allowlisted echo-fixture host, and
  **no base-url override**. From the agent container: a plain `curl
  https://<allowlisted-echo-host>/...` (only `HTTPS_PROXY` set, tool unaware of
  egressd) reaches the fixture and the fixture sees the injected credential;
  the agent never holds the token. A `curl https://<non-allowlisted-host>`
  **fails** (CONNECT denied / handshake refused, not a 401). Broker / callback
  / DNS still work (run reaches Completed).
- Assert the two-layer gate: the non-allowlisted host is denied, and (if
  practical) an attempt to force the SNI to a non-allowlisted name is refused
  at cert minting.

### 4b. Codex proof — a go/no-go spike (not an assumed win)

This revisits the **Phase 2 Codex NO-GO**, which was killed by the ChatGPT-plan
**refresh** lifecycle. The placeholder-file + MITM mechanism is a new attempt
at exactly that problem, so it carries the same go/no-go gate. The whole design
works only if Codex's refresh flow can also be mediated — treat refresh as the
explicit kill switch.

Where: a focused kind/phase harness using real Codex auth available to the
broker/provider in the test environment (the merged 6.1 preset materializes the
placeholder `.codex/auth.json`).

Run Codex in forward-proxy mediated mode with **no real Codex token** in the
agent filesystem, env, process args, or generated config, and exercise all four
paths:

1. **Normal `codex exec` turn** completes end to end.
2. **Streaming / WebSocket path** works through the MITM (SSE/WS frames pass
   through, as the Phase 2/4 streaming tests require).
3. **Forced / short-token refresh path**: drive Codex to a state where it
   attempts a token refresh (short/expiring local token, or a broker-side
   expiry mid-session surfacing as a 401).
4. **`auth.openai.com/oauth/token` mediation**: the refresh call itself is
   mediated — egressd injects the real refresh material (or the `codex_oauth`
   provider handles the refresh) so the placeholder refresh_token never has to
   work directly.

- **Pass condition**: Codex survives all four, including refresh, with no real
  tokens in the agent.
- **Fail condition**: Codex needs an unmediated local refresh token, or sends a
  secret only inside a request body/query that header injection cannot replace,
  or has unsupported refresh behavior. On fail: **stop and update the plan**
  (body substitution, or a different Codex strategy) before implementing — do
  not quietly widen scope in this PR.
- CI may run this manual/optional if real Codex auth is unavailable, but the PR
  must include an automated fixture-level test proving the placeholder-file +
  proxy injection mechanics with fake Codex-shaped auth (incl. a simulated
  refresh against a fake `auth.openai.com`).

### 5. Docs

- Parent plan → v3.8; Phase 6 forward-proxy marked landed, the leaf-name
  widening and its allowlist bound documented in §"Phase 6" and the
  review-checklist; the Codex NO-GO note updated with the go/no-go outcome.
- Chart README: forward-proxy mode, its enforcement requirement, the `NO_PROXY`
  scope, and the "arbitrary tools that honor proxy env" coverage statement (the
  residue — tools that ignore proxy env — deferred to step 2).

## Commit order (reviewable, tests-first per commit)

1. egressd CA leaf-name widening (allowlisted upstream SNIs) + refusal tests —
   the security-critical change, reviewed alone
2. egressd TLS-terminating CONNECT handler + injection reuse + `-race` tests
3. Operator render + admission (enforcement-required) + NO_PROXY + policy
4. Bootstrap trust/env verification + runtime test
5. kind forward-proxy smoke on Calico
6. Codex go/no-go proof (4b) + fixture-level automated test
7. Docs (parent → v3.8, chart README)

## Review checklist (trusted-core items)

- Leaf minting: an upstream-name leaf is minted **only** for a configured
  allowlisted host; every other SNI is refused at `GetCertificate`, and the
  CONNECT allowlist independently refuses a non-allowlisted `host:port`. Both
  gates pinned; neither presented as the sole boundary.
- CA name constraints widen to exactly local names + allowlisted hosts; a
  leaked key still cannot sign an arbitrary host (canary-host test).
- Upstream identity: outbound Host + SNI pinned to the route upstream, never
  derived from the client's CONNECT/SNI (SSRF).
- Fail-closed: broker down / revoked grant / quota exceeded fails the proxied
  request; no plaintext fallthrough, no blind-tunnel bypass for an injectable
  host.
- `NO_PROXY` covers broker, callback, DNS, localhost, egressd itself —
  operator-rendered, pinned by test.
- Enforcement required: forward-proxy without `egressEnforcement` is rejected
  at admission.
- Header-injection endpoint shape unchanged — the transport-agnostic contract
  holds.
- Audit/quota apply to proxied requests identically to redirect routes; no
  header/token values in any report or log on the MITM path.
- Codex proof does not add Codex logic to egressd or `agentd`; Codex specifics
  live in the 6.1 provider/preset and tests. Refresh is mediated or the proof
  is a documented NO-GO.

## Explicitly out of scope

- **Transparent iptables `REDIRECT`/`TPROXY` mode** (parent sequence row 9) —
  its own plan, strictly after this; for tools that ignore proxy env.
- **Body/query placeholder substitution** — deferred unless the Codex proof
  proves it required and the plan is explicitly revised first.
- Allow-but-passthrough host tier — deny-by-default in this PR.
- Placeholder-file materialization — that is PR 6.1; this PR consumes it.
- Compose forward-proxy (operator-mode focus; compose stays the documented
  non-enforcement gap).
- The global mediated-by-default flip (independent, wait-on-soak).
