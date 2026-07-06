# PR 6a Plan: Egress Enforcement (own-Pod egressd + NetworkPolicy)

Status: plan — ready to implement
Parent: [phase5-enforcement-plan.md](phase5-enforcement-plan.md) PR 6a; prerequisites merged (#61 fixes, #62 broker TLS)

## Goal

A mediated run with enforcement on cannot reach arbitrary hosts: egressd moves
to its own Pod, CNI-enforced NetworkPolicies fence the agent Pod, and the
egress-denied smoke lands in CI. Non-possession is untouched; this adds the
second, independent guarantee. This is the trusted-core-review PR of Phase 5;
it ships alone.

## Decisions settled here (don't relitigate in the PR)

1. **Opt-in field**: `spec.egressEnforcement: true` on AgentRun (bool, default
   false). Admission: requires `egress: mediated`; `direct` + enforcement
   fails loudly naming the field. Same-Pod remains the default mediated shape
   and the compose shape — zero behavior change for existing runs.
2. **CNI**: Calico on kind (lighter install than Cilium; the parent plan
   already leans this way). The kindnet path stays for all existing smokes.
3. **CA fetch transport**: egressd serves `GET /ca.crt` on a dedicated
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
`<run>-egress-ca`, two NetworkPolicies. Labels on both Pods:
`nvt.dev/run: <name>`, `nvt.dev/role: agent|egressd`.

Reconcile as a **status-condition state machine**, one observable step per
pass (per the parent plan — not hidden ordering inside a single reconcile):

1. Render egressd config/Pod/Service → condition `EgressdCreated`.
2. Wait for egressd Pod Ready (readiness probe = CA listener `/healthz`) →
   `EgressdReady`.
3. The operator fetches `http://<svc>:<ca-port>/ca.crt` **once**, validates it
   parses as a certificate (and only a certificate), publishes it into
   `<run>-egress-ca` → `EgressCAPublished`. The agent never network-fetches
   its own trust anchor.
4. Create the agent Pod: `<run>-egress-ca` ConfigMap mounted read-only at
   `/nvt-egress-ca` (same path as Phase 4 — **bootstrap is unchanged**),
   grants' base-urls rendered as `https://<run>-egressd:<8471+i>`.

Stuck states: conditions carry reasons, requeue with backoff,
`activeDeadlineSeconds` still bounds the whole run. Controller tests: full
condition progression; egressd-never-ready; CA fetch fails (non-cert body ⇒
no publish, loud condition); same-Pod mediated and direct modes render
exactly as today.

**Agent-side trust for non-git tools**: base-urls are now `https://` for
every grant, but generic CLIs use the system trust store. Bootstrap
(`runtime/core/bootstrap.py`): when mediated and the egress CA file is
present, install it into the container trust store
(`/usr/local/share/ca-certificates/` + `update-ca-certificates`; the agent is
root) and persist `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE` via the existing env
mechanism; git keeps its explicit `http.sslCAInfo`. Runtime test: env +
trust-store file present, secret scan still clean (the CA cert is public; the
needle list keeps the key PEM).

### 4. NetworkPolicies

Operator-rendered per run; nothing static in the chart beyond any
cluster-scoped baseline.

- **Agent Pod, egress default-deny +**: kube-dns :53 UDP/TCP
  (namespaceSelector for `kube-system`), broker Service :7347, paired egressd
  (`nvt.dev/run: <name>` + `role: egressd`), operator callback :8082. No
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
  - the same request via the egressd base-url **succeeds** against the
    fixture upstream;
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

- Pairing selectors: agent A cannot reach egressd B (second run in the smoke,
  or a canary policy test).
- Default-deny actually denies: canary host check in the smoke, not just
  "allowed things work".
- `GET /ca.crt` serves cert only, on every path including errors; the
  operator publishes exactly what it fetched (ConfigMap bytes == served
  bytes).
- Bootstrap fails closed when the CA mount is absent (already pinned in
  Phase 4 — re-run against the ConfigMap-mount shape).
- Leaf SAN scope: Service names yes, upstream names still refused; name
  constraints updated in lockstep.
- The condition state machine has no path that creates the agent Pod before
  `EgressCAPublished`.

## Explicitly out of scope

Audit/quotas/revocation/Anthropic/default-mode knob (PR 6b), CONNECT-MITM
(Phase 6), compose enforcement (documented gap), cluster-CIDR `except`
hardening, same-node affinity (measure first, per the parent plan's open
question).
