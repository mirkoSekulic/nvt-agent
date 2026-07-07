# PR 6a Plan: Egress Enforcement (own-Pod egressd + NetworkPolicy)

Status: plan — ready to implement
Parent: [phase5-enforcement-plan.md](phase5-enforcement-plan.md) PR 6a; prerequisites merged (#61 fixes, #62 broker TLS)

## Goal

A mediated run with enforcement on cannot reach arbitrary hosts: egressd moves
to its own Pod, CNI-enforced NetworkPolicies fence the agent Pod, and the
egress-denied smoke lands in CI. Non-possession is untouched; this adds the
second, independent guarantee. This is the trusted-core-review PR of Phase 5;
it ships alone — **one PR**, with the commit order below followed strictly so
review stays possible. Do not split it without asking first.

## Decisions settled here (don't relitigate in the PR)

1. **Opt-in field**: `spec.egressEnforcement: true` on AgentRun (bool, default
   false). Admission: requires `egress: mediated`; `direct` + enforcement
   fails loudly naming the field. Same-Pod remains the default mediated shape
   and the compose shape — zero behavior change for existing runs.
2. **CNI**: Calico on kind (lighter install than Cilium; the parent plan
   already leans this way). The kindnet path stays for all existing smokes.
3. **CA public endpoint**: egressd serves `GET /ca.crt` on a dedicated
   plain-HTTP listener (the cert is public material and *is* the trust anchor
   being bootstrapped — TLS on this endpoint would be circular). The listener
   also serves `/healthz` for the readiness probe. Key material is never
   served; pin with a test that walks every listener response.
4. **Egress-denied smoke placement**: the assertions live in a new kind case
   (enforcement is a k8s control). `TestMediatedEgressDenied` in
   `tests/runtime` gets its skip reason updated to point at the kind case and
   to document the compose gap (parent §7 resolved decision) — it must never
   pass silently.

## Work items

### 1. CRD + admission

Where: `operator/api/v1alpha1/agentrun_types.go`, both CRD yaml copies
(`operator/config/crd/bases/` **and** `charts/nvt/crds/` — they are
`cmp`-checked by the helm test), `ValidateAgentRunEgressMode`.

- `EgressEnforcement bool json:"egressEnforcement,omitempty"` + DeepCopy +
  CRD schema.
- Validation: enforcement ⇒ mediated. Error names the field.
- **Carry-over hardening from the #62 review (this PR touches exactly this
  path):**
  - The operator fails fast at startup (`cmd/manager/main.go`) when
    `NVT_BROKER_URL` is `https://` and `NVT_BROKER_CA_SECRET` is empty —
    misconfiguration becomes a deploy-time error, not a per-run 180s hang.
  - `ValidateAgentRunEgressMode` must not retroactively fail *running* runs
    when operator env changes: skip (or downgrade to event/condition) once the
    run's Pod exists. Controller test: admit under `https`, flip env to
    `http`, reconcile → run stays Running.

### 2. egressd: Service-name leafs + CA endpoint

Where: `egressd/internal/egress/ca.go`, `config.go`, `cmd/egressd/main.go`.

- `CAConfig` gains `LeafDNSNames []string` (rendered by the operator as
  `<run>-egressd`, `<run>-egressd.<ns>`, `<run>-egressd.<ns>.svc`).
  `GetCertificate` allowlist = localhost + these names; CA name constraints
  (`PermittedDNSDomains`) extended to match. **Upstream names remain
  refused** — a per-run Service name is a synthetic redirect name; assert in
  the existing SAN tests that `github.com`-style hellos still fail.
- `CAConfig` gains `ServeAddr string` (e.g. `0.0.0.0:8470`): plain-HTTP
  listener serving only `GET /ca.crt` (the PEM) and `GET /healthz`. Tests:
  cert-only (no `PRIVATE KEY` bytes on any path, 404 elsewhere).
- Own-Pod routes listen on `0.0.0.0:8471+i` with `listen_tls: ca` for
  **every** route — the hop leaves localhost, so non-git API routes serve TLS
  too.

### 3. Operator: two-Pod rendering + explicit state machine

Where: `operator/internal/controller/agentrun_controller.go` — the heart of
the PR.

Per-run objects in enforcement mode, all owner-referenced: egressd Pod
`<run>-egressd`, Service `<run>-egressd` (route ports + CA port), ConfigMap
`<run>-egress-ca`, a durable Secret `<run>-egress-ca-keypair` with the egress
CA keypair mounted only into egressd, and two NetworkPolicies. Labels on both
Pods:
`nvt.dev/agentrun: <name>`, `nvt.dev/role: agent|egressd`.

Reconcile as a **status-condition state machine**, one observable step per
pass (per the parent plan — not hidden ordering inside a single reconcile).
Condition order:

```text
BrokerPolicyReady → EgressdCreated → EgressdReady → EgressCAPublished
                                                  → agent Pod created
```

1. Reconcile the broker agents policy (agent identity, paired egress
   identity, grants/materialization/permissions — the existing
   `reconcileBrokerAgentsPolicy` flow) → condition `BrokerPolicyReady`.
   **Scope note**: this condition gates the *agent Pod*, not egressd.
   egressd is broker-independent at startup — it fetches injectable material
   lazily and fail-closed on the first proxied request, and CA
   generation/publication needs no broker at all — so egressd creation may
   proceed in parallel with policy reconciliation; do not serialize it behind
   the broker and manufacture a deadlock when the broker is slow. The
   condition exists for observability and to make the agent-Pod gate
   explicit. (The #62 bootstrap retry still absorbs the ConfigMap projection
   lag on the agent side.)
2. Render egressd config/Pod/Service → condition `EgressdCreated`.
3. Wait for egressd Pod Ready (readiness probe = CA listener `/healthz`) →
   `EgressdReady`.
4. The operator validates the Secret-backed CA material, publishes only
   `ca.crt` into `<run>-egress-ca` → `EgressCAPublished`. The private key
   remains mounted only into egressd; the agent never network-fetches its own
   trust anchor.
5. Create the agent Pod — **never before `EgressCAPublished` and
   `BrokerPolicyReady` both hold**: `<run>-egress-ca` ConfigMap mounted
   read-only at `/nvt-egress-ca` (same path as Phase 4 — **bootstrap is
   unchanged**), grants' base-urls rendered as
   `https://<run>-egressd:<8471+i>`.

Stuck states: conditions carry reasons, requeue with backoff,
`activeDeadlineSeconds` still bounds the whole run. Controller tests: full
condition progression; egressd-never-ready; CA Secret validation fails (bad
or mismatched keypair ⇒ no publish, loud condition); no reconcile path creates
the agent Pod with `EgressCAPublished` unset; same-Pod mediated and direct
modes render exactly as today.

**Agent-side trust for non-git tools**: base-urls are now `https://` for
every grant, but generic CLIs use the system trust store. Bootstrap
(`runtime/core/bootstrap.py`): when any grant's base-url is `https`, wait for
the egress CA file (the existing Phase 4 fail-closed wait), install it into
the container trust store (`/usr/local/share/ca-certificates/` +
`update-ca-certificates`; the agent is root) and persist
`SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE` via the existing env mechanism; git
keeps its explicit `http.sslCAInfo`. **Fail closed, no fallback**: a missing
or invalid `ca.crt`, or a non-zero `update-ca-certificates`, aborts bootstrap
— never continue without trust, never downgrade to plain HTTP or direct
mode. Runtime tests: env + trust-store file present on success; bootstrap
exits non-zero on missing/invalid CA and on a failing trust-store install.

**CA scan rules, stated explicitly for the smoke/secret-scan needles**: the
CA *certificate* is public material and allowed anywhere in the agent
container (trust store, env, git config). The CA *private key* PEM is a
forbidden needle in `scanTreeForSecretMaterial` and the kind smoke — it must
never appear in the agent container, the published ConfigMap, or any listener
response.

### 4. NetworkPolicies

Operator-rendered per run; nothing static in the chart beyond any
cluster-scoped baseline.

- **Agent Pod, egress default-deny +**: kube-dns :53 UDP/TCP
  (namespaceSelector for `kube-system`), broker Service :7347, paired egressd
  (`nvt.dev/agentrun: <name>` + `role: egressd`), operator callback :8082. No
  internet CIDR at all. Ingress is left unrestricted this PR (gateway /
  code-server unaffected) — state this explicitly in the PR.
- **egressd Pod**: ingress only from the paired agent; egress to broker +
  `0.0.0.0/0:443`. Comment in code and PR text, verbatim from the parent
  plan: this is a coarse fence — **the semantic per-host allowlist lives in
  egressd** (pinned upstreams, injection-hosts); do not present the policy as
  host-scoped. `except` blocks for cluster CIDRs are a second-pass hardening,
  not this PR.
- Direct mode and non-enforcement mediated render **zero** policies (test).
- **GC test**: create enforcement run → delete → assert zero orphaned
  Pods/Services/ConfigMaps/Secrets/NetworkPolicies (extends the existing
  finalizer flow).

### 5. kind harness: Calico cluster + egress-denied smoke

- `tests/operator/kind/kind-calico.yaml` (`disableDefaultCNI: true`,
  podSubnet matching Calico), Make target `operator-kind-cluster-enforced`
  (create cluster + apply pinned Calico manifest + wait for calico-node).
  Existing kindnet targets untouched.
- New case `tests/operator/kind/cases/enforced-egress.sh` (reuse the mediated
  case's payloads with `egressEnforcement: true` and the fixture providers
  from #62):
  - direct HTTPS from the agent container to a non-allowlisted host **fails
    as connection timeout/refused, not 401** (the 401-vs-refused distinction
    is what separates enforcement from non-possession);
  - **agent → paired egressd through the Service** succeeds: an explicit
    request from the agent container to `https://<run>-egressd:<port>`
    (verified against the published CA) reaches the fixture upstream. This
    must be a real request driven from inside the agent container — "run
    reaches Completed" alone does not prove the agent→egressd path, because
    bootstrap's brokerctl calls go to the broker, not egressd. Implementation
    note: under Calico the policy decision applies to the post-DNAT Pod
    endpoint, so the distinct thing the Service path proves on top of
    Pod-selector reachability is that kube-dns egress and Service resolution
    work under the default-deny policy — assert the DNS+connect path, not
    just label matching;
  - **cross-run isolation**: run a second enforcement AgentRun and assert
    agent A cannot reach egressd B — by Pod IP (the stronger proof, policy
    without kube-proxy in the way) and via B's Service name where practical.
    This is the one assertion that actually validates the pairing selectors;
  - a **dind-spawned container's** direct egress also fails (the parent §7
    FORWARD-path case — the CNI covers it because traffic still exits the
    Pod);
  - DNS, broker, and the operator callback still work (run reaches
    `Completed`);
  - pod shape: labels, two Pods, Service, CA ConfigMap, both policies.

### 6. Docs

- `docs/phase5-enforcement-plan.md`: 6a marked landed; decisions recorded
  (field name, Calico, plain-HTTP CA endpoint rationale).
- Parent plan §6/§7: own-Pod is the k8s enforcement shape; in-netns iptables
  stays gated on the deprivileged-dind workstream (state the NET_ADMIN
  precondition).
- Chart README: enforcement requires a NetworkPolicy-enforcing CNI; on
  kindnet the policies are inert (documented, and the smoke only runs on the
  Calico cluster).

## Commit order (reviewable, tests-first per commit)

1. CRD/admission + operator startup env validation
2. egressd CA leaf names + `/ca.crt` endpoint
3. Operator state machine + two-Pod rendering
4. NetworkPolicies + GC
5. kind Calico + egress-denied smoke
6. Docs

## Trusted-core review checklist

- Pairing selectors: agent A cannot reach egressd B — required smoke
  assertion (see the enforced-egress case), not just a policy-shape review.
- Default-deny actually denies: canary host check in the smoke, not just
  "allowed things work".
- Agent→egressd reachability is proven through the Service DNS path from
  inside the agent container, under the default-deny policy.
- `GET /ca.crt` serves cert only, on every path including errors; the
  operator publishes only the public cert from the validated CA Secret
  (ConfigMap bytes == Secret `ca.crt`); the CA private key PEM is a forbidden
  needle everywhere.
- Bootstrap fails closed when the CA mount is absent or the trust-store
  install fails (Phase 4 wait re-run against the ConfigMap-mount shape; no
  insecure/direct fallback).
- Leaf SAN scope: Service names yes, upstream names still refused; name
  constraints updated in lockstep.
- The condition state machine has no path that creates the agent Pod before
  both `BrokerPolicyReady` and `EgressCAPublished` hold — and egressd
  creation is not serialized behind the broker.

## Explicitly out of scope

Audit/quotas/revocation/Anthropic/default-mode knob (PR 6b), CONNECT-MITM
(Phase 6), compose enforcement (documented gap), cluster-CIDR `except`
hardening, same-node affinity (measure first, per the parent plan's open
question).
