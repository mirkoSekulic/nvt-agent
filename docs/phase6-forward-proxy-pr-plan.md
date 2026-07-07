# Phase 6 (step 1) Plan: TLS-terminating forward-proxy mode

Status: plan — ready to implement (Phase 5 complete: #63 6a, #64 6b)
Parent: [mediated-egress-plan.md](mediated-egress-plan.md) §"Phase 6", sequence
row 7 ("TLS-terminating forward-proxy mode"). Step 2 (transparent iptables
REDIRECT, row 8) is a **separate** plan after this.

## Goal

Close the main coverage gap: arbitrary/unmodifiable tools with hardcoded
endpoints that honor proxy env vars, and auth-file based tools whose local
credential file can be represented with placeholders. Today mediation covers
only *redirectable* tools (base-url / `redirect-env` configurable) and
hard-disallows the rest. Phase 6 step 1 sets `HTTP_PROXY`/`HTTPS_PROXY`/
`NO_PROXY` in the agent container and makes egressd terminate `CONNECT` under
the Phase 4 per-agent CA, inject the credential, and re-originate TLS to the
real upstream — so most CLIs, language HTTP clients, and SDKs get mediated
without per-tool base-url wiring. In the same PR, providers gain a generic
broker-owned **placeholder file** materialization path: the agent can receive
syntactically valid auth/config files containing placeholders, while the
broker/provider remains the source of truth for the real secret material.

This reuses machinery that already exists: the per-agent CA (Phase 4), the
CONNECT-only forward-proxy listener (Phase 2b), the injection path + material
cache + fail-closed (Phase 1), and the quota + audit + enforcement layer
(Phase 5). The genuinely new and highest-risk element is that egressd now
mints leaf certs for **real upstream names** — the line Phase 4 deliberately
refused to cross — so the entire design is gated on a per-grant host
allowlist, in two independent layers. The other new element is deliberately
not tool-specific: placeholder file materialization is a broker/provider
contract that Codex proves first, but Claude-style `.credentials.json` or
other JSON auth files can use later without adding tool logic to core.

## The load-bearing security decision (read first)

Phase 4/5 minted leafs **only for local/synthetic names** (localhost, per-run
Service DNS names) and put critical name constraints on the CA forbidding
upstream names, precisely so a leaked CA key could not impersonate
`api.anthropic.com` to the agent. Forward-proxy MITM **requires** egressd to
present a valid-looking cert for the real upstream SNI. Step 1 relaxes that,
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

1. **Header injection only in step 1.** egressd MITMs the CONNECT, injects the
   broker-provided headers into the decrypted request, and re-originates TLS —
   exactly the Phase 4 `Proxy` injection logic, now reached via CONNECT+SNI
   instead of a base-url rewrite. **Body/query placeholder substitution is
   out of scope** (parent plan lists it as optional-within-phase); defer to a
   follow-up so step 1 stays a bounded TLS-termination change.
2. **Route selection by SNI/CONNECT host, mapped to a capability.** The
   CONNECT target host is matched against each header-inject grant's
   `injection-hosts`. A host that maps to a capability is MITM'd + injected. A
   host that is not mapped is **denied** (fail-closed) in step 1 — there is no
   allow-but-passthrough tier yet (that is a policy knob for later; keep the
   first version deny-by-default with no unmediated escape).
3. **Opt-in, and only under enforcement.** Forward-proxy mode is enabled per
   run via a new field (naming TBD in the PR, e.g. `spec.egressForwardProxy:
   true`) and **requires `spec.egressEnforcement`**: without the CNI fence the
   agent can ignore the proxy env and reach hosts directly, so proxy mode
   without enforcement is coverage theater. Admission rejects the combination
   loudly. Same-Pod and non-enforced mediated runs are unchanged.
4. **`NO_PROXY` is fail-open for infra, fail-closed for upstreams.** The agent
   points `HTTP(S)_PROXY` at egressd, but broker, operator callback, kube-dns,
   localhost, and the egressd Service itself must go direct — they are the
   allowlist, not mediated upstreams. `NO_PROXY` is rendered by the operator
   (it knows those endpoints), not hand-authored, so a missed entry can't
   silently route infra through the MITM.
5. **Broker owns placeholder files; host files are import-only.** Production
   placeholder auth/config files are generated from broker/provider state, not
   copied from the developer host. A provider may expose a file template such
   as `.codex/auth.json` or `.claude/.credentials.json`; secret fields are
   replaced with placeholders, and the real values stay in broker/provider
   custody. A local helper may import an existing host auth file into broker
   state for dev/bootstrap convenience, but runtime materialization never
   treats the host file as the source of truth and never copies real values
   into the agent.
6. **Generic placeholder materialization, provider presets.** The core shape is
   generic: placeholder files/env entries, secret-field selectors, allowed
   hosts, and optional placeholder shapes (for example `jwt`). Codex is the
   first proof because it needs a token-shaped local auth file, but Codex
   rules must live in a provider/preset, not in `agentd`, bootstrap core, or
   egressd. egressd remains transport/injection machinery; it should not know
   what a Codex auth file is.
7. **No change to the injection endpoint for proxy transport.**
   `/v1/injection/headers` already takes `(capability, host, method, path)`.
   Forward-proxy requests call it exactly as redirect routes do. Broker changes
   in this PR are allowed only for the generic placeholder materialization
   surface and its provider tests; changing the header-injection endpoint shape
   is a regression.

## Work items

### 0. Broker/provider: generic placeholder file materialization

Where: `broker/core/server.py` or the existing files/materialization path,
provider interfaces, `protocol/broker.md`, `protocol/injection.md`,
`tests/broker`, runtime non-possession tests.

- Add a provider-owned materialization shape for **placeholder files**. The
  agent receives file contents, path, mode, and public metadata only; real
  secret values remain in broker/provider state. This is distinct from
  `file-bundle`: `file-bundle` writes usable credential material into the
  agent, while `placeholder-file` writes only inert placeholders.
- The generic contract must support:
  - file path and mode (for example `.codex/auth.json`);
  - a JSON template or provider-generated JSON object;
  - secret field selectors by key/path (for example `access_token`,
    `refresh_token`, `id_token`, keys ending in `_token`);
  - allowed hosts per placeholder binding;
  - optional shape rules, initially `plain` and `jwt`. `jwt` emits a
    syntactically valid placeholder JWT with a far-future `exp`, so tools that
    parse local token expiry can start without seeing the real token.
- Codex is implemented as a provider preset/proof, not a core special case:
  broker-owned Codex OAuth state emits `.codex/auth.json` with placeholders
  for token fields and host bindings for `chatgpt.com` / `api.openai.com`.
  If a local dev flow needs existing `~/.codex/auth.json`, it is imported into
  broker/provider state first; the runtime path still materializes only
  placeholders.
- The provider also exposes the header-injection behavior needed by egressd
  for those hosts. The normal request path should be header injection
  (`Authorization`, account headers, etc.) rather than body substitution. Body
  or query placeholder replacement remains out of scope unless the Codex proof
  empirically requires it.
- Tests: broker/provider fixture containing real token strings materializes a
  placeholder file with no real token bytes; `id_token` placeholder is
  JWT-shaped when requested; placeholders are stable enough for repeated
  materialization of the same grant; each placeholder is bound to the expected
  hosts; agent identities cannot fetch real placeholder bindings directly;
  secret scan over the materialized file/env finds no real provider secret.

### 1. egressd: TLS-terminating CONNECT handler

Where: `egressd/internal/egress/forward_proxy.go`, `ca.go`, `config.go`,
`cmd/egressd/main.go`, new `forward_proxy_mitm_test.go`.

- Extend `ForwardProxyConfig` with a TLS-terminating mode: a per-host →
  capability map (or a list of `{host, capability, upstream}` route entries)
  and a `terminate_tls: true` flag. The existing blind-tunnel path stays for
  diagnostics/future policy, but injectable hosts in this mode use the
  TLS-terminating path.
- On CONNECT to an allowlisted, injectable host: respond `200 Connection
  Established`, then TLS-handshake with the client using
  `ca.ServerTLSConfig()` whose `GetCertificate` mints a leaf for the SNI —
  **only if the SNI is an allowlisted host** (extend the Phase 4
  `allowedLeafName` set with the configured upstream hosts; refuse otherwise).
  Then serve the decrypted request through the existing `Proxy` injection
  logic (material fetch, header inject, placeholder strip, re-originate TLS to
  the pinned upstream, stream response).
- CA changes (`ca.go`): `GetCertificate` allowlist and the CA
  `PermittedDNSDomains` gain the configured upstream hosts. Add IP-SAN refusal
  for upstreams (upstreams are DNS names; a leaf for an IP upstream is
  refused). Keep local/synthetic names working.
- Reuse, do not fork: the per-request injection is the same `Proxy.material` +
  `buildOutbound` path; quota (`quotaExceeded`) and audit (`report`) apply to
  each proxied request exactly as on redirect routes. The CONNECT
  allow/deny audit (`writeDecision`) stays.
- Tests (egressd, `-race`): client → proxy CONNECT → egressd terminates →
  fake upstream sees the broker-injected header and never the placeholder;
  a leaf is minted for the allowlisted SNI and **refused** for a
  non-allowlisted SNI (both the CONNECT gate and the `GetCertificate` gate
  pinned independently); outbound Host + SNI pinned to the upstream, never the
  client's; broker-down fails the proxied request closed (no plaintext, no
  bypass); quota N+1 fails closed on the proxied path; streaming passes
  through.

### 2. Operator: render forward-proxy config, env, NO_PROXY, admission

Where: `operator/api/v1alpha1/agentrun_types.go` + both CRD copies,
`ValidateAgentRunEgressMode`, `RenderEgressdConfigJSON`, `DesiredAgentPod`,
controller tests.

- New spec field (e.g. `EgressForwardProxy bool`). Admission: requires
  `egress: mediated` **and** `egressEnforcement: true`; the combination error
  names the field. Reject forward-proxy without enforcement loudly.
- `RenderEgressdConfigJSON`: emit the forward-proxy TLS-terminating block with
  the per-host→capability map derived from the header-inject grants'
  `egressHosts`/`injection-hosts`, plus the CA leaf-name extension for those
  hosts. The forward-proxy listener binds a fixed local port (e.g.
  `0.0.0.0:8473`) on the agent-reachable network.
- `DesiredAgentPod`: set `HTTP_PROXY`/`HTTPS_PROXY=http://<egressd>:<port>`
  (own-Pod Service in enforcement mode) and a computed `NO_PROXY` covering
  the broker Service, operator callback, kube-dns, `localhost`/`127.0.0.1`,
  the cluster domain for in-cluster infra, and the egressd Service host
  itself. The CA is already installed into the agent trust store by the 6b
  bootstrap (system trust store) — verify it covers proxy-env HTTPS clients.
- NetworkPolicy: the agent egress fence already allows only broker / paired
  egressd / callback / DNS. Forward-proxy traffic goes agent → egressd
  (already allowed on the route ports; add the forward-proxy port to the
  agent→egressd rule and the egressd ingress rule). egressd → upstream :443
  is already allowed. No new internet reachability for the agent.
- Controller tests: field admission (enforcement required); rendered config
  has the TLS-terminating forward-proxy block with the right host→capability
  map and CA leaf names; agent Pod has `HTTP(S)_PROXY` + a `NO_PROXY` that
  includes broker/callback/DNS/localhost; non-forward-proxy runs render none
  of it.

### 3. Bootstrap: proxy env is config, not secret

Where: `runtime/core/bootstrap.py`, `tests/runtime/mediated_smoke_test.go`.

- The proxy env vars are non-secret (they point at egressd), so they ride the
  existing env mechanism. Confirm the CA trust-store install (6b) runs
  whenever forward-proxy mode is on (every mediated-enforced-proxy run has an
  https path). Confirm `NO_PROXY` from the operator reaches the agent
  unchanged (bootstrap does not need to compute it).
- Materialize provider-owned placeholder files into the agent home/workspace
  exactly as instructed by the broker/provider response. Bootstrap must never
  read host auth files as the runtime source of truth and must never write real
  provider tokens in forward-proxy mediated mode. Host-file import belongs to
  a separate dev/bootstrap helper outside the agent runtime path.
- Runtime test: with forward-proxy egress config, the agent env carries
  `HTTP(S)_PROXY` and a `NO_PROXY` including the infra hosts; the CA is
  trusted; the secret scan stays clean (proxy URLs and the CA cert are
  public; the needle list keeps real provider secrets and the CA key). A
  placeholder-file run writes the expected auth file containing placeholders
  and no real token material.

### 4. kind smoke: arbitrary-tool coverage

Where: new `tests/operator/kind/cases/forward-proxy-egress.sh`, reuse the
hermetic echo fixture and Calico cluster from 6a/6b.

- A run with forward-proxy + enforcement, an allowlisted echo-fixture host,
  and **no base-url override** on the tool. From the agent container: a plain
  `curl https://<allowlisted-echo-host>/...` (only `HTTPS_PROXY` set, tool
  unaware of egressd) reaches the fixture and the fixture sees the injected
  credential; the agent never holds the token (secret scan / token grep as in
  6b). A `curl https://<non-allowlisted-host>` **fails** (CONNECT denied /
  handshake refused, not a 401). Broker / callback / DNS still work (run
  reaches Completed).
- Assert the two-layer gate at the smoke level: the non-allowlisted host is
  denied, and (if practical) an attempt to force the SNI to a non-allowlisted
  name through the proxy is refused at cert minting.

### 4b. Codex placeholder-auth proof

Where: a new focused kind or phase harness, using real Codex auth available to
the broker/provider in the test environment.

- Run Codex in forward-proxy mediated mode with no real Codex token in the
  agent filesystem, env, process args, or generated config. The agent-side
  `.codex/auth.json` exists and is syntactically valid but contains only
  placeholders (including JWT-shaped placeholders where Codex parses local
  token shape/expiry).
- Force Codex traffic through egressd via `HTTPS_PROXY` and the installed
  per-run CA. egressd injects broker-owned auth on the allowed
  `chatgpt.com` / `api.openai.com` traffic. A real `codex exec` turn must
  complete.
- This proof is allowed to be optional/manual in CI if real Codex auth is not
  available, but the PR must include an automated fixture-level test proving
  the placeholder file and proxy substitution/injection mechanics with fake
  Codex-shaped auth.
- If the real Codex proof shows Codex sends a secret only inside a request
  body/query that cannot be replaced by header injection, stop and update the
  plan before adding body substitution. Do not quietly add broad body
  substitution in this PR.

### 5. Docs

- Parent plan → v3.8; Phase 6 step-1 marked landed, the leaf-name widening and
  its allowlist bound documented in §"Phase 6" and the review-checklist.
- Chart README: forward-proxy mode, its enforcement requirement, the
  `NO_PROXY` scope, and the "arbitrary tools that honor proxy env" coverage
  statement (and the residue — tools that ignore proxy env — deferred to
  step 2).

## Commit order (reviewable, tests-first per commit)

1. Broker/provider placeholder-file materialization contract + Codex preset
   fixture tests (no real secrets materialized)
2. egressd CA leaf-name widening (allowlisted upstream SNIs) + refusal tests —
   land the security-critical change first, reviewed alone
3. egressd TLS-terminating CONNECT handler + injection reuse + `-race` tests
4. Operator render + admission (enforcement-required) + NO_PROXY + policy
5. Bootstrap trust/env verification + placeholder-file runtime test
6. kind forward-proxy smoke on Calico
7. Codex placeholder-auth proof or documented manual gate
8. Docs (parent → v3.8, chart README)

## Review checklist (trusted-core items)

- Leaf minting: an upstream-name leaf is minted **only** for a configured
  allowlisted host; every other SNI is refused at `GetCertificate`, and the
  CONNECT allowlist independently refuses a non-allowlisted `host:port`. Both
  gates pinned; neither presented as the sole boundary.
- CA name constraints widen to exactly local names + allowlisted hosts;
  a leaked key still cannot sign an arbitrary host (test with a canary host).
- Upstream identity: outbound Host + SNI pinned to the route upstream, never
  the client's CONNECT/SNI value used to pick a different upstream (SSRF).
- Fail-closed: broker down / revoked grant / quota exceeded fails the proxied
  request; no plaintext fallthrough, no blind-tunnel bypass for an injectable
  host.
- `NO_PROXY` covers broker, callback, DNS, localhost, egressd itself —
  operator-rendered, so infra never transits the MITM; pinned by test.
- Enforcement is required: forward-proxy without `egressEnforcement` is
  rejected at admission (without the CNI fence the proxy env is advisory).
- Broker/provider placeholder files: real tokens stay broker-owned; agent
  materialization writes placeholders only; host auth files are import-only and
  never the runtime source of truth.
- Header-injection endpoint shape remains unchanged — the transport-agnostic
  contract holds.
- Audit/quota apply to proxied requests identically to redirect routes; no
  header/token values in any report or log on the MITM path.
- Codex proof does not add Codex logic to egressd or `agentd`; Codex-specific
  defaults live in the provider/preset and tests.

## Explicitly out of scope

- **Transparent iptables `REDIRECT`/`TPROXY` mode** (parent sequence row 8) —
  its own plan, strictly after this; for tools that ignore proxy env.
- **Body/query placeholder substitution** — optional-within-phase; a follow-up
  once header-injection MITM has soaked, unless the Codex proof proves it is
  required and the plan is explicitly revised before implementation.
- Host-auth-file runtime sourcing. Importing a host auth file into broker state
  may be a dev helper, but the runtime architecture is broker/provider-owned
  placeholder materialization, not copying host auth into agents.
- Compose forward-proxy (operator-mode focus, consistent with prior phases;
  compose stays the documented non-enforcement gap).
- Allow-but-passthrough host tier (unmediated allowlisted hosts) — deny-by-
  default in step 1; a policy knob for later if a real tool needs it.
- The global mediated-by-default flip (independent, wait-on-soak).
