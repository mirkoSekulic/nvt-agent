# PR 6b Plan: Observability + Control (audit, quotas, revocation, Anthropic proof)

Status: implemented — broker `POST /v1/injection/report` + async egressd reporter, per-grant `quota.requests`, revocation chain tests + subPath guard, Anthropic `static_token` generalization (zero egressd diffs), `egress.defaultMode` knob (default `direct`), hermetic kind echo fixture. Global mediated-by-default flip still deferred.
Parent: [phase5-enforcement-plan.md](phase5-enforcement-plan.md) PR 6b (work
items 5–9); prerequisites merged (#61 fixes, #62 broker TLS, #63 PR 6a)

## Goal

The choke-point payoff: every proxied request is audited, grants carry
request-count quotas enforced at the sidecar, the revocation bound is proven
end-to-end and documented, Anthropic lands as the provider-agnosticism proof
with **zero egressd changes**, and clusters gain a `defaultEgressMode` knob —
defaulting to `direct`, with the global flip explicitly deferred past this
phase. One PR, commits in the order below; work items are independent enough
to review commit-by-commit but ship together per the parent sequencing.

## Decisions settled here (don't relitigate in the PR)

1. **Audit is observability, not a security control.** Reporting is
   asynchronous, bounded, and best-effort by design: a report failure logs
   loudly (sanitized) and drops — it never adds per-request latency and never
   blocks or fails proxied traffic. Enforcement and authorization live
   elsewhere. State this in code comments and the protocol doc.
2. **`path_class`, never raw paths.** git smart-HTTP paths reduce to
   `git-upload-pack` | `git-receive-pack` | `info-refs`; API paths to the
   first path segment (`/repos/o/r/pulls/1` → `repos`). Forward-proxy
   CONNECTs report `{host, port, decision}`. Header values never appear in
   any report, on any path including errors (existing egressd invariant).
3. **Quotas are request-count only, HTTP routes only, per egressd process.**
   `quota.requests` counts proxied requests per route in an in-egressd
   counter, so its lifetime is the **egressd process, not the run** — an
   egressd restart (in-place container restart, or the 6a level-triggered
   Pod recreation after eviction) resets the counter to zero. This is an
   accepted limitation of the first version: the quota is a soft resource
   guard, not a security boundary (the security boundaries are
   non-possession and enforcement, which do not depend on it). Durable
   run-lifetime quotas — counter state persisted broker-side or in a per-run
   object — are explicit future work. Document the per-process semantics in
   the CRD field doc, the chart README, and the code. Forward-proxy CONNECT
   tunnel quotas (`quota.tunnels`) are **out of scope**: no mediated grant
   drives the forward proxy today, so there is nothing to meter — noted as
   future work, not half-wired.
4. **Anthropic support generalizes `static_token`**, not `static_headers`
   (the plan says pick one). New provider config: `injection-header`
   (default `authorization`), `injection-scheme` (default `Bearer`; empty
   string means the raw token, which is what `x-api-key` wants), and
   `injection-extra-headers` (static name→value map, e.g.
   `anthropic-version`). All injected header names are appended to
   `strip_request_headers`.
5. **`defaultEgressMode` is resolved at AgentRun creation, and scoped to the
   nvt schedule/admission path.** The #62/#63 lesson: env-driven behavior
   read on every reconcile retroactively reclassifies running runs when the
   knob flips — so the default must be applied exactly once, at creation.
   The nvt admission/schedule endpoint fills `spec.egress` from
   `NVT_DEFAULT_EGRESS_MODE` **before** it creates the AgentRun, so every run
   it produces is explicit and a knob change can never alter an existing run.
   **Important CRD interaction, stated so it isn't discovered in
   implementation**: the AgentRun CRD carries `spec.egress` with an OpenAPI
   `default: direct` (`operator/config/crd/bases/nvt.dev_agentruns.yaml`), so
   a **direct `kubectl apply`** of an AgentRun with empty egress is defaulted
   to `direct` by the API server — the operator never sees empty and the knob
   does not apply on that path. That is the documented, accepted behavior for
   this PR: an operator running mediated-by-default drives runs through the
   nvt path (producers/schedules), not raw kubectl. The knob never overrides
   an explicit `spec.egress` on any path. Fully operator-owned defaulting for
   the raw-kubectl path (removing the CRD `default` and adding a mutating
   admission webhook, or resolving empty at read time — which reintroduces
   the retroactive-reclassification hazard and is therefore rejected) is
   explicit future work, not this PR.

## Work items

### 1. Broker: `POST /v1/injection/report`

Where: `broker/core/server.py`, `protocol/injection.md`,
`tests/broker/injection_conformance_test.go` (or a new report conformance
file).

- Egress-role only, paired-agent resolution identical to
  `/v1/injection/headers`. Agent identities are rejected — pinned by test.
- Request shape (batched):

  ```json
  {"entries": [
    {"capability": "git-app", "host": "github.com", "method": "POST",
     "path_class": "git-upload-pack", "status": 200},
    {"capability": "codex-main", "host": "chatgpt.com", "method": "POST",
     "path_class": "backend-api", "status": 429}
  ]}
  ```

  CONNECT entries use `{"capability", "host", "port", "decision"}`.
- One audit line per entry in the same `audit.jsonl`:
  `{request_id, agent (egress id), paired_agent, provider, host, method,
  path_class, status, operation: "injection.request", allowed: true}`.
- Bounds: cap entries per report (e.g. 100) and rely on the existing
  `MAX_REQUEST_BYTES`; oversized reports are denied with the standard error
  shape, not truncated silently.
- Authorization is role + pairing only. Entries are not re-checked against
  grants: reports for a just-revoked capability are still audit-worthy, and
  a compromised egressd can spam audit with granted capabilities anyway.
- Protocol doc: endpoint shape, role gating, `path_class` definition, and
  the best-effort semantics (decision 1) — pinned by conformance tests
  (agent identity rejected, shape, audit entries present, no header values).

### 2. egressd: async batched reporting

Where: new `egressd/internal/egress/reporter.go`, wiring in `proxy.go`,
`forward_proxy.go`, `cmd/egressd/main.go`.

- One `Reporter` per process, sharing the existing `BrokerClient`: bounded
  in-memory queue (e.g. 1024 entries), one background goroutine, batch flush
  on ~2s tick or 100 entries. Queue full ⇒ increment a drop counter and log
  a sanitized line — never block the request path.
- `Proxy.ServeHTTP` enqueues after the upstream response (status known);
  quota breaches and fail-closed errors are reported too (status 429/502).
  `ForwardProxy` enqueues CONNECT `{host, port, decision}` on allow and
  deny.
- `path_class` is computed in egressd — sanitization at the source, so raw
  paths never leave the process: git shapes map to the three git classes,
  everything else to the first path segment.
- Tests: reports arrive at a fake broker with correct `path_class` and no
  header/token values anywhere in the payload; proxied traffic latency and
  success are unaffected when the report endpoint 500s, hangs, or is
  unreachable; a flood beyond queue capacity drops (bounded memory, no
  goroutine growth); reporter drains on flush tick, not per request.

### 3. Per-grant request quotas

Where: `operator/api/v1alpha1/agentrun_types.go` + both CRD copies,
`ValidateAgentRunEgressMode`, `RenderEgressdConfigJSON`,
`broker/core/agents.py` (schema parse), `scripts/agent-init.sh` +
`scripts/broker-agents.py` (compose parity),
`egressd/internal/egress/config.go` + `proxy.go`.

- Grant schema: `quota: { requests: N }` (positive integer; absent =
  unlimited) on the AgentRun grant and in `agents.yaml` (parsed and
  validated broker-side for schema strictness; the broker does not enforce
  it). Operator renders it into the route as `max_requests`; `agent-init`
  renders the same for compose.
- egressd enforcement, per route, **per egressd process** (see decision 3 —
  not durable across egressd restart; document this in the CRD field doc and
  chart README): a single atomic counter beside the material cache. **No
  TOCTOU**: `atomic.AddInt64` first, then compare the result to the limit —
  the N+1th increment fails closed with a 429-shaped `egress-quota-exceeded`
  via the existing `writeError` path, logged sanitized and reported through
  the audit path. Concurrency test: hammer with M > N parallel requests,
  assert exactly N reach the upstream.
- Admission/controller tests: schema round-trip, invalid quota rejected
  loudly naming the grant.

### 4. Revocation: prove the chain, pin the mount, document the bound

The egressd TTL clamp (the load-bearing piece) shipped in #61; this item is
tests and docs, not mechanism.

- **Conformance** (`tests/broker`): grant removed from the agents fixture ⇒
  the next `/v1/injection/headers` fetch fails closed, no broker restart.
- **Kind smoke** (extend the mediated case): revoke through the supported
  path — patch the AgentRun spec to drop a grant, let the operator reconcile
  the broker agents ConfigMap — then observe denial through egressd within
  the bound. Do **not** edit the ConfigMap directly: the operator's policy
  reconcile would re-add the grant and the test would race itself.
- **Mount-mode guard**: chart render test (helm suite) asserting the broker
  agents ConfigMap volume is never `subPath`-mounted — a subPath freezes the
  projected file and silently kills mtime-based hot-reload, i.e. revocation.
- **Document the bound** in parent plan §7 and the chart README:
  operator reconcile + kubelet ConfigMap sync (~1min worst case) + egressd
  cache clamp (≤60s).

### 5. Anthropic provider-agnosticism proof

Where: `broker/plugins/static_token/provider.py`, `tests/broker`,
`tests/runtime` (redirect-env), PR description.

- Generalize `static_token` per decision 4: `injection-header`,
  `injection-scheme`, `injection-extra-headers`; validate at config load
  (header names lowercase, no placeholder collisions); everything injected
  is stripped from the incoming request.
- The proof, conformance level: a provider entry with
  `injection-hosts: [api.anthropic.com]`, `injection-header: x-api-key`,
  empty scheme, `anthropic-version` extra header; a grant with
  `redirect-env: { ANTHROPIC_BASE_URL: base-url }`. Tests assert the key is
  injected as `x-api-key` (no `Bearer`), `anthropic-version` rides along,
  both are stripped, and the agent env carries only the placeholder.
- **Review gate, stated in the PR description**: `git diff --stat` for
  `egressd/` under this work item is empty. Anything else is a contract
  regression — the whole point of the proof.
- A real-key manual test stays optional/local; CI uses fixtures.

### 6. `defaultEgressMode` knob (default `direct`; global flip deferred)

Where: `charts/nvt/values.yaml` + `operator-deployment.yaml`, the nvt
schedule/admission path (where AgentRuns are created — this is the only
creation path the knob affects, per decision 5),
`operator/internal/controller`, helm + controller tests, docs.

- Chart value `defaultEgressMode: direct | mediated` (default `direct`) →
  operator env `NVT_DEFAULT_EGRESS_MODE`, validated at operator startup
  (fail fast on anything else — the #62 lesson).
- Per decision 5, the default is applied **at AgentRun creation, on the nvt
  admission/schedule path only**: that endpoint sets `spec.egress` from the
  knob when the incoming request leaves it empty, *before* creating the
  AgentRun, so the stored object is always explicit. **Do not** change
  `AgentRunEgressMode()` to read the env: resolving empty at reconcile time
  would retroactively reclassify runs when the knob flips (the #62/#63
  hazard). Leave the CRD `default: direct` and the `AgentRunEgressMode()`
  empty→direct fallback exactly as they are — together they mean a raw
  `kubectl apply` with empty egress stays `direct` regardless of the knob,
  which is the documented, accepted scope for this PR.
- Tests: knob never overrides explicit `spec.egress`; the nvt admission path
  stamps the knob's mode into `spec.egress` at creation (assert the created
  object is explicit, not empty); under a mediated default, a file-bundle
  grant fails admission loudly naming the grant (no silent downgrade in
  either direction); **flipping the knob mid-run does not reclassify or fail
  an existing run** (pinned controller test — the retroactive-failure
  regression class from #62/#63); a raw-kubectl AgentRun with empty egress
  is `direct` under a mediated knob (the CRD-default scope boundary is
  pinned, not just documented); smoke suites pass under both defaults.
- Docs: parent plan → v3.7; chart README documents the knob, its
  nvt-path-only scope and the raw-kubectl CRD-default caveat, and the revised
  flip criteria (both smokes green in CI + real-cluster soak, then a trivial
  later PR changes the default value, CRD `default:` markers, and producer
  specs).

### 7. Carry-overs from the #63 review

- **Hermetic in-cluster fixture upstream for the kind smokes — a required 6b
  work item, not conditional.** 6a made the enforced smoke prove real
  traversal, but against the external `httpbin.org` (outbound-network
  dependency, CI flakiness). The quota and revocation smoke steps in this PR
  each need real traffic through egressd anyway, so this PR replaces
  `httpbin.org` with a kind-loaded echo image that reflects the request
  (method, path, injected auth header) — hermetic and reusable by all three
  smokes (enforced-egress, quota, revocation). Do this before the quota and
  revocation smokes so they build on the hermetic fixture rather than adding
  more external-network reliance.
- `runtime/core/write-agent-instructions.sh` alignment was already handled in
  6a (the fenced-egress guidance note). Verify it still describes the runtime
  behavior after this PR's changes; no new work expected unless the trust or
  quota behavior changes what the agent sees.

## Commit order (reviewable, tests-first per commit)

1. Hermetic kind fixture upstream (item 7) — lands first so the quota and
   revocation smokes build on it, not on `httpbin.org`
2. Broker `/v1/injection/report` + protocol doc + conformance
3. egressd reporter + proxy/CONNECT wiring
4. Quotas end-to-end (CRD → agents.yaml → egressd) + quota smoke on the fixture
5. Revocation chain tests + subPath render guard + bound docs
6. `static_token` generalization + Anthropic proof
7. `defaultEgressMode` knob + both-defaults tests
8. Docs (parent → v3.7, chart README)

## Review checklist (trusted-core items)

- No header or token values in any report, audit entry, or error path —
  grep-level review of the reporter and the broker handler.
- The reporter's queue is bounded and cannot OOM egressd; report failures
  cannot block, slow, or fail proxied traffic (test proves latency parity
  with the broker report endpoint down).
- Quota counter has no TOCTOU under concurrency; exactly N requests reach
  the upstream; the per-egressd-process (non-durable) semantics are
  documented, not silently implied to be run-lifetime.
- Revocation bound holds for long-lived credentials (git's ~1h installation
  token is the regression case) and the agents ConfigMap is never
  subPath-mounted.
- `defaultEgressMode`: admission errors under a mediated default are loud
  and name the grant; no silent downgrade in either direction; the knob
  changes only the creation-time default on the nvt admission path, never an
  existing run and never an explicit `spec.egress`; `AgentRunEgressMode()` is
  not made env-reading (no read-time resolution); the raw-kubectl CRD-default
  scope boundary is pinned by test.
- Anthropic work item: zero egressd diffs.

## Explicitly out of scope

The global mediated-by-default flip (later PR, after CI + soak),
durable run-lifetime quotas (this PR is per-egressd-process; persisting
counter state broker-side or in a per-run object is future work), spend
quotas (need provider-response parsing), CONNECT tunnel quotas
(`quota.tunnels` — no consumer yet), operator-owned defaulting for the
raw-kubectl path (removing the CRD `default` + a mutating admission webhook),
a broker revoke API/CLI (revocation rides ConfigMap hot-reload this phase),
Phase 6 CONNECT-MITM, compose enforcement (documented gap).
