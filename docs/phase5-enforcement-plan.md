# Phase 5 Plan: Egress Enforcement + Audit + Quotas + Revocation

Status: fixes (#61) and prerequisite broker-TLS PR (#62) merged; 6a implemented ([phase5-6a-enforcement-pr-plan.md](phase5-6a-enforcement-pr-plan.md) — decisions: `spec.egressEnforcement` opt-in, Calico on kind, plain-HTTP `/ca.crt` endpoint since the certificate is the trust anchor being bootstrapped); 6b not started
Parent: [mediated-egress-plan.md](mediated-egress-plan.md) §6, §7, Phase 5 (PRs 6a/6b in the sequence table)

## Goal

Turn mediation from non-possession into an actual egress control, then add the
choke-point payoff: per-request audit, per-grant quotas, mid-run revocation,
the Anthropic provider-agnosticism proof, and flipping the operator default to
`mediated`. Split into two PRs per the parent plan:

- **PR 6a — enforcement**: the agent Pod cannot reach arbitrary hosts;
  egress-denied smoke lands in CI.
- **PR 6b — observability/control**: audit, quotas, revocation, Anthropic
  proof. (The default flip is **deferred past Phase 5** — see below.)

Plus one prerequisite, **as its own PR** (not folded into 6a): **broker TLS in
the chart** — production mediated mode must not require
`egressAllowInsecureBroker`. It touches chart, operator, broker URL, CA
distribution, and kind tests; keeping it separate keeps the 6a review about
enforcement and nothing else.

## Non-goals

- Transparent/CONNECT-MITM mediation, proxy-env wiring — Phase 6.
- Spend quotas (need provider-response parsing) — deferred, per parent plan.
- Compose enforcement — stays the documented gap (§7, resolved decision):
  non-possession holds locally; enforcement is real in operator mode.
  Deprivileging/relocating dind remains an independent workstream.
- Broker mutation API (revoke endpoint/CLI) — revocation rides the existing
  ConfigMap/hot-reload path this phase; an API is future work.

## Starting position (what already exists)

- **Revocation mostly works today.** `AgentRegistry.reload_if_changed()`
  hot-reloads `agents.yaml` on mtime change on *every* `authenticate()`
  (`broker/core/agents.py:29-54`), and `/v1/injection/headers` re-checks the
  grant on every fetch (`broker/core/server.py:200-212`). Removing a grant
  from the ConfigMap makes egressd's next fetch fail closed. Phase 5's work is
  bounding and testing the propagation, not building the mechanism.
- **Audit exists per injection *fetch*, not per request.**
  `injection.headers` audits with host/method/path (`server.py:213-224`), but
  egressd serves from cache (`proxy.go:69-94`) so one entry covers a whole TTL
  window. egressd never reports individual proxied requests to the broker.
- **The k8s Pod runs privileged dind in-Pod** (`agentrun_controller.go:844-870`,
  `Privileged: true`), sharing the Pod netns with agent and egressd — the k8s
  analogue of compose's `network_mode: service:docker`. Consequence: in-netns
  iptables is bypassable in k8s too (agent → dind → `--privileged --net
  container:` → NET_ADMIN). Only CNI-level NetworkPolicy sits outside the
  agent's privilege domain.
- **No NetworkPolicy or egressd Service templates exist**; the kind harness
  creates clusters with default kindnet, which does **not** enforce
  NetworkPolicy (`Makefile:61-70`, no kind config file in the repo).
- **Broker TLS is implemented but unwired**: `serve()` honors
  `NVT_BROKER_TLS_CERT/KEY` (`server.py:393-405`); egressd supports
  `broker_ca_file` (`config.go:70`, `main.go:101-115`); nothing in the chart
  or operator sets either.
- **The egress-denied smoke skeleton is staged and skipped**:
  `TestMediatedEgressDenied` (`tests/runtime/mediated_smoke_test.go:428`).

## Bugs found while planning (fixed — shipped as the Phase 5 fix PR)

1. **`static_token.injection_headers` signature mismatch.** `server.py:212`
   calls providers with 7 args (now including `grant`), but
   `static_token/provider.py:71` accepts 6 — a live `TypeError` on any
   injection fetch against a `token` provider. `codex_oauth` and `github_app`
   were updated; `static_token` was missed. Add a conformance test that
   exercises injection for **every** provider type declaring
   `injection-hosts`.
2. **Revocation latency is unbounded by credential lifetime.** egressd caches
   material until `ExpiresAt − 30s` (`proxy.go:96-102`). GitHub installation
   tokens live ~1h, so a revoked git grant keeps working from cache for up to
   ~1h — far beyond "one cache TTL" as the parent plan intends. Fix: clamp
   the cache TTL in egressd (`maxCacheTTL`, e.g. 60–120s) independent of
   credential expiry. Refetch is cheap — the broker already caches minted
   tokens per `(provider, repo, permissions)` with its own buffer. This
   separates *credential validity* from *authorization cache lifetime*, which
   revocation depends on.

## Prerequisite PR — broker TLS in the chart

1. Cert issuance without new dependencies: the chart (or operator) generates a
   self-signed broker CA + serving cert into a Secret (`nvt-broker-tls`).
   cert-manager stays optional/pluggable via values; not required.
2. `broker-deployment.yaml`: mount the Secret, set `NVT_BROKER_TLS_CERT/KEY`.
3. Operator: `brokerURL` → `https://nvt-broker:7347`
   (`agentrun_controller.go:52`); render `broker_ca_file` in
   `RenderEgressdConfigJSON` (currently omitted) and mount the CA cert into
   the egressd container.
4. Admission consequence: mediated runs no longer need
   `egressAllowInsecureBroker` in-cluster. The flag stays for local/kind
   plaintext setups; the kind smoke switches to the TLS path to prove it.
5. The agent's own `NVT_BROKER_URL` leg moves to TLS too (bootstrap/brokerctl
   need the CA — distribute via the agent-config ConfigMap; the cert is
   public material).

## PR 6a — enforcement

### Placement decision: own-Pod egressd (recommended)

Per parent §6/§7, evaluate own-Pod egressd + NetworkPolicy vs.
deprivileged-dind. The exploration hardens the case for **own-Pod as the k8s
control**:

- Same-Pod NetworkPolicy must allow the union of agent+egressd destinations
  (one Pod = one policy endpoint), so the agent can always reach upstreams
  directly. Ruled out for enforcement.
- In-netns iptables (owner-match + FORWARD deny) does not hold in k8s today:
  dind is `Privileged: true` inside the Pod, so the agent can obtain
  NET_ADMIN in its own netns and flush rules. iptables becomes defense-in-
  depth **gated on the deprivileged-dind workstream**, not this phase's
  control. State the NET_ADMIN precondition explicitly in code comments and
  docs.
- Own-Pod egressd + CNI-enforced NetworkPolicy is enforced host-side, beyond
  the agent's reach even with full in-netns privileges — including traffic
  from dind-spawned containers, which still exits the Pod and hits the CNI.

**Same-Pod remains the compose and default-k8s shape; own-Pod is opt-in with
enforcement** (`spec.egress: mediated` + `enforcement: true`, naming TBD in
the PR). The injection contract is placement-agnostic by design (§2); the
pieces that are *not* yet placement-agnostic and need rework:

1. **Route addressing**: `base-url` is `127.0.0.1:8471+i`
   (`agentrun_controller.go:719`). Own-Pod needs a per-run egressd Service
   (`<run>-egressd`) and base-URLs of `https://<run>-egressd:<port>`.
2. **Agent→egressd leg gains TLS**: the hop leaves localhost, and git routes
   already terminate TLS. Leaf SANs move from `127.0.0.1` to the Service DNS
   name (the Phase 4 leaf-SAN discipline — local/synthetic redirect names
   only — extends naturally; a per-run Service name is still not an upstream
   name). Non-git API routes should also serve TLS in own-Pod mode.
3. **CA cert distribution — operator-distributed (primary design)**: the
   Phase 4 shared-`emptyDir` publication is same-Pod-only. In own-Pod mode,
   the operator creates a durable per-run CA Secret
   (`<run>-egress-ca-keypair`) mounted only into egressd and publishes only
   `ca.crt` into a per-run ConfigMap (`<run>-egress-ca`) mounted read-only
   into the agent Pod. The **agent never network-fetches its own trust
   anchor**. Bootstrap reads trust from the mount, exactly like Phase 4.

   **Implementation constraint**: this sequencing (egressd Pod ready → CA
   keypair validated → ConfigMap published → agent Pod created) is more controller
   choreography than the existing reconcile does anywhere. Implement it as an
   explicit state machine surfaced through AgentRun status conditions (e.g.
   `EgressdReady`, `EgressCAPublished`) with each reconcile pass advancing
   one observable step — not as hidden ordering inside a single reconcile
   path. Controller tests assert the condition progression, including the
   stuck states (egressd never ready, CA publication fails).
4. **Pairing at the network layer**: per-run Pod labels so NetworkPolicies
   select exactly the paired Pods (`nvt.dev/agentrun: <name>`,
   `nvt.dev/role: agent|egressd`).

### NetworkPolicy templates (greenfield chart work)

- **Agent Pod egress** (default-deny +): kube-dns :53 (UDP/TCP), broker
  Service :7347, paired egressd Pod (label selector), operator callback
  Service :8082. Nothing else — no direct internet.
- **egressd Pod**: egress to broker + upstream :443; ingress only from the
  paired agent Pod.
- **CNI limitation, stated plainly**: vanilla NetworkPolicy selects by
  CIDR/port, not hostname, so "upstream :443" concretely means
  `0.0.0.0/0:443` on the egressd Pod. Excluding cluster/Service CIDRs via
  `except` blocks is a worthwhile second-pass hardening if the chosen CNI
  handles it cleanly — do not let it complicate the first pass.
  That is acceptable **only because egressd enforces the semantic per-host
  allowlist** (pinned route upstreams, capability `injection-hosts`,
  fail-closed CONNECT allowlist). Hostname-level control lives in egressd;
  the CNI provides the coarse fence around the *agent*, which gets no
  internet CIDR at all. Do not present the egressd policy as host-scoped.
- Rendered by the operator per-run (paired selectors), not static chart
  templates; chart carries any cluster-scoped baseline. Direct mode renders
  exactly today's Pod — no policies (parent config-surface table).
- **Lifecycle/GC**: every per-run object in enforcement mode — egressd Pod,
  Service, both NetworkPolicies, CA ConfigMap, egressd config ConfigMap,
  egress token Secret — carries the AgentRun ownerReference and is covered by
  the existing finalizer flow. A controller test deletes an enforcement-mode
  AgentRun and asserts zero orphaned objects; otherwise enforcement mode
  leaks resources on every run.

### kind harness: enforcement-capable CNI

- New kind cluster config with `disableDefaultCNI: true` + a Calico install
  step (make target; Cilium works too — pick in the PR, Calico is the lighter
  lift on kind). Keep the kindnet path for the non-enforcement smokes so
  existing CI stays fast; the egress-denied case requires the Calico cluster.
- **Egress-denied smoke case** (un-skips the staged skeleton): from the agent
  container, direct HTTPS to a non-allowlisted host **fails**; the same
  request via egressd **succeeds**; a dind-spawned container's direct egress
  **also fails** (this is the §7 FORWARD-path case — under own-Pod it's
  covered by the CNI, which is the point). Callback/broker/DNS still work.

## PR 6b — observability + control

### Per-request audit

egressd reports each proxied request to the broker: new endpoint
`POST /v1/injection/report` (egress-role only), appending to the same
`audit.jsonl` with `{agent (paired), capability, host, method, path_class,
status}`. Design constraints:

- **Asynchronous, bounded, best-effort**: a small in-memory queue + batch
  flush. Audit must not add per-request latency or take down traffic —
  enforcement and authorization live elsewhere; a report failure logs loudly
  (sanitized) and drops. This choice is deliberate and documented: audit here
  is observability, not a security control.
- **`path_class`, not raw path**: git paths reduce to
  `git-upload-pack|git-receive-pack|info-refs`; API paths to the first path
  segment. Avoids spraying repo/file names into the audit log while keeping
  it useful. Never header values (existing egressd invariant).
- Forward-proxy CONNECTs report `{host, port, decision}` the same way.
- Protocol addition goes in `protocol/injection.md` + conformance tests
  (egress-role-only, agent identity rejected, shape pinned).

### Per-grant request-count quotas

- Grant schema: `quota: { requests: N }` (AgentRun grant + `agents.yaml`),
  absent = unlimited. Flows into egressd route config as `max_requests`.
- Enforced **at the sidecar**, counted per route for the run's lifetime;
  breach → fail closed with 429-shaped error via the existing `writeError`
  path, logged sanitized, reported via the audit path. Counter lives beside
  the material cache on the `Proxy` struct; `ForwardProxy` reuses its
  `tunnelSlots` accounting pattern for tunnel counts.
- Explicitly request-count only; spend quotas deferred (parent plan).

### Revocation (bound it, test it, document it)

With the TTL clamp from the bug-fix list, the end-to-end bound becomes:
**ConfigMap projection lag (kubelet sync, ~1min worst case) + egressd cache
TTL (≤ clamp)**. Work items:

- The TTL clamp in egressd (see bugs above) — the load-bearing piece.
- **The test must cover the whole chain, not just the broker step**:
  ConfigMap update → kubelet projection → broker mtime hot-reload → egressd
  cache expiry → request denied. Conformance level: revoke grant in fixtures
  → next fetch fails closed, no Pod restart. Smoke level (kind mediated
  case): edit the ConfigMap, observe denial through egressd within the bound.
- **Mount-mode constraint, pinned**: hot-reload is mtime-based
  (`agents.py:40`) and works today because the chart mounts the agents
  ConfigMap as a directory volume (`/config`, items — verified, no
  `subPath`). A `subPath` mount would freeze the file forever and silently
  kill revocation in k8s. Add a chart/render test asserting the agents
  volume is not `subPath`-mounted.
- Document the propagation bound in the parent plan §7 and the chart README.

### Anthropic as the provider-agnosticism proof

The bar (parent plan): adding `ANTHROPIC_BASE_URL` + a grant is config-only
**for egressd** — zero sidecar changes, or it's a contract regression. The
exploration confirms egressd needs nothing; two broker-side items are needed
and are legitimate provider-plugin work (call this out honestly in the PR):

- `static_token` currently hardcodes `authorization: Bearer`; Anthropic wants
  `x-api-key` (+ `anthropic-version`). Generalize `static_token` with
  `header-name`/`extra-headers` config (or give `static_headers` injection
  support — pick one, don't do both).
- The signature bug from the fix-first list.

Then the proof is: provider entry with `injection-hosts: [api.anthropic.com]`,
grant with `redirect-env: { ANTHROPIC_BASE_URL: base-url }`, fake-upstream
conformance test asserting the key is injected and the placeholder/agent env
never carries it. A real-key manual test stays optional/local.

### Default egress mode: make it configurable, do NOT flip yet

The parent plan's "then flip the operator default to `mediated`" is **revised:
the flip is product behavior, not just security hardening, and it leaves
Phase 5's scope.** A default flip breaks every existing file-bundle consumer
that doesn't say `egress: direct` explicitly. Instead:

- 6b adds a chart value `defaultEgressMode: direct | mediated` (operator env
  → the empty-mode fallback in `AgentRunEgressMode()`,
  `agentrun_controller.go:1032`), **defaulting to `direct`**.
- Operators opt clusters into mediated-by-default when *their* consumers have
  migrated; the smoke suites run against both defaults in CI.
- The global flip happens in a later, trivial PR — after both smoke tests are
  green in CI **and** real-cluster usage has soaked — and consists of
  changing one default value plus CRD `default:` markers and producer specs
  (`producers/github-comments`). Admission errors already name the offending
  grant, so the failure mode for stragglers is loud.
- 6b still bumps the parent plan (v3.7) and chart README to document the
  knob and the revised flip criteria.

## Work breakdown

| # | PR | Work item | Test that pins it |
|---|----|-----------|-------------------|
| 0 | fix | `static_token` injection signature + egressd `maxCacheTTL` clamp | conformance: injection fetch per provider type; unit: cache expiry ≤ clamp regardless of `expires_at` |
| 1 | pre | Chart broker TLS + operator `https://` brokerURL + `broker_ca_file` rendering | kind smoke runs mediated without `egressAllowInsecureBroker`; egressd rejects plaintext broker without the flag |
| 2 | 6a | Own-Pod egressd: per-run Service, TLS on agent→egressd leg, egressd-Pod-first sequencing + operator-published CA ConfigMap, run/role Pod labels | controller tests: two-Pod rendering + creation order, Service, labels, CA ConfigMap contents; bootstrap fail-closed when CA mount absent |
| 3 | 6a | Operator-rendered NetworkPolicies (agent + egressd, paired selectors) + ownership/GC of all enforcement-mode objects | controller tests: policy shape; direct mode renders zero policies; delete-run-assert-no-orphans |
| 4 | 6a | kind Calico cluster config + egress-denied smoke (direct fails, via-egressd succeeds, dind-spawned fails) | the un-skipped egress-denied case in CI |
| 5 | 6b | `POST /v1/injection/report` + egressd async batched reporting, `path_class` sanitization | conformance: role gating, entry shape; egressd test: reports emitted, traffic unaffected when broker report path fails |
| 6 | 6b | Per-grant `quota.requests` end-to-end (CRD → agents.yaml → egressd enforcement) | egressd unit: N+1th request fails closed + audited; admission/controller schema tests |
| 7 | 6b | Revocation bound: full-chain conformance + kind smoke (ConfigMap edit → broker reload → cache expiry → denial within bound) | the revocation tests; chart render test: agents volume never `subPath`-mounted; docs updated with the bound |
| 8 | 6b | Anthropic proof: `static_token` header generalization + provider/grant config | conformance fake-upstream proof; explicit assertion of zero egressd diffs (review gate, noted in PR description) |
| 9 | 6b | `defaultEgressMode` chart value (default `direct`) + docs (parent → v3.7); **global flip deferred** to a later PR after real-cluster soak | smoke suites pass under both default settings |

Build order: 0 → 1 → 2/3 (together) → 4 → 5..8 (parallelizable) → 9. The
global default flip is intentionally **not** in this sequence.

## Review checklist (trusted-core items)

- NetworkPolicy pairing selectors: no cross-run reachability (agent A ↛
  egressd B); default-deny actually default-denies (test with a canary host).
- CA distribution: `GET /ca.crt` serves cert only, never key material; the
  operator publishes only `ca.crt` from the validated per-run Secret
  (ConfigMap content matches the Secret cert); agent bootstrap fails closed
  when the CA mount is absent.
- Audit reporting: no header/token values in any report or error path;
  bounded queue cannot OOM egressd; report failures cannot block or fail
  proxied traffic.
- Quota counter: no TOCTOU between check and increment under concurrency.
- TTL clamp: revocation bound holds for long-lived credentials (git's 1h
  token is the regression case).
- `defaultEgressMode` knob: admission errors under a mediated default are
  loud and name the grant; no silent downgrade path in either default; the
  knob changes only the empty-mode fallback, never overrides an explicit
  `spec.egress`.

## Open questions (settled in the PRs, not before)

- Own-Pod opt-in field name and scope (`enforcement: true` on AgentRun vs.
  chart-level) — 6a decides; contract stays placement-agnostic either way.
- Calico vs. Cilium for the kind enforcement cluster — whichever installs
  faster/leaner in CI wins.
- Same-node affinity for the agent↔egressd hop in own-Pod mode (parent §6
  mitigation) — measure first, add if the hop cost shows.
- Whether `quota.requests` counts forward-proxy CONNECT tunnels in the same
  bucket or a separate `quota.tunnels` — decide when wiring the config.
