# nvt Helm Chart

## Broker TLS

The broker serves TLS by default. The egressd→broker leg carries real
credentials through the agent Pod's network namespace, so mediated runs in a
cluster must not depend on `spec.egressAllowInsecureBroker`:

```yaml
broker:
  tls:
    enabled: true
    secretName: nvt-broker-tls
    existingSecret: ""
```

When `existingSecret` is empty, the chart generates a self-signed CA and a
serving cert for `nvt-broker.<namespace>.svc` into `secretName` at install
time and preserves it across upgrades (`helm lookup`), so the trust anchor
does not rotate on every `helm upgrade`. The broker Deployment carries a
`checksum/broker-tls` pod annotation derived from the same material, so the
broker restarts exactly when the Secret changes. `helm template | kubectl
apply` bypasses `lookup` and regenerates the cert on every render; the
checksum tracks the regenerated material, so the broker restarts onto the
newly applied cert — but every apply rotates the trust anchor and breaks
in-flight mediated runs, so prefer `helm upgrade --install` (or
`existingSecret`) for stable trust. Rotating an `existingSecret` out of band
requires a manual `kubectl rollout restart deployment/nvt-broker`.

Set `existingSecret` to bring your own cert (for example from cert-manager);
it must be a `kubernetes.io/tls` Secret that also carries `ca.crt`. The chart
points the operator at the Secret (`NVT_BROKER_CA_SECRET`) and switches the
operator-rendered broker URL to `https://nvt-broker:7347`; the operator then
projects only the `ca.crt` item into agent Pods (agent and egressd
containers) — the serving key never leaves the broker.

With `tls.enabled=false` the broker stays plaintext and mediated AgentRuns
must set `spec.egressAllowInsecureBroker: true` explicitly (local/dev only).

## Gateway OIDC Authorization

The optional access gateway supports generic OIDC login plus a separate
authorization policy. Authentication alone is not enough in shared IdPs:
when `gateway.auth.mode=oidc`, the default authorization decision is deny
unless an allow rule matches. To allow any authenticated user, configure an
explicit `authenticated: true` rule.

Authorization rules evaluate claims from `gateway.auth.authorization.claimSource`.
The default is `id_token`. Use `userinfo` when the IdP exposes entitlement
claims there. `access_token` is accepted only for JWT access tokens that verify
against the issuer JWKS; opaque access tokens fail closed.

Do not use SSN, pid, or fødselsnummer claims as authorization keys. Prefer
organization, group, resource, or entitlement claims. Gateway authorization
policy validation rejects those sensitive claim paths, and logs intentionally
include only the decision, rule id, agent access key, and a short hash of the
subject.

Example with provider-neutral OIDC fields and Ansattporten-style authorize
parameters. The rule below assumes the configured claim source exposes
`authorization_details`; choose `userinfo` or `access_token` to match the
provider's actual claim placement:

```yaml
gateway:
  enabled: true
  auth:
    mode: oidc
    session:
      existingSecret: nvt-gateway-session
    oidc:
      issuerURL: https://ansattporten.no
      clientID: nvt-gateway
      clientSecret:
        existingSecret: nvt-gateway-oidc
      scopes: ["openid", "profile"]
      extraAuthParams:
        authorization_details: |
          [
            {
              "type": "ansattporten:altinn:resource",
              "resource": "urn:altinn:resource:digdir-selvbetjening-klienter",
              "organizationform": "enterprise",
              "representation_is_required": false
            }
          ]
    authorization:
      default: deny
      # id_token (default), userinfo, or access_token for JWT access tokens
      claimSource: userinfo
      rules:
        - id: allowed-altinn-org
          effect: allow
          where:
            array: authorization_details[].authorized_parties[]
            all:
              - claimPath: orgno.ID
                values: ["0192:991825827"]
              - claimPath: resource
                values: ["digdir-selvbetjening-klienter"]
        - id: break-glass-admins
          effect: allow
          claimPath: groups[]
          values: ["nvt-agent-admins"]
```

For `where.array`, all conditions are evaluated against the same selected array
element. This prevents combining an organization match from one
`authorized_parties[]` entry with a resource match from another entry.

## Broker State Persistence

By default the broker keeps `/state` on an `emptyDir`, preserving existing
kind/smoke behavior:

```yaml
broker:
  persistence:
    enabled: false
```

## Agent Egress

Agent egress mode is selected per `AgentRun` with `spec.egress`; direct mode
remains the API default. The chart exposes the egressd image and a
creation-time default egress mode:

```yaml
egress:
  egressdImage: nvt-egressd:latest
  defaultMode: direct   # direct | mediated
  allowInsecureUpstreams: false
```

`egress.allowInsecureUpstreams` is a **test/dev opt-in** (operator env
`NVT_ALLOW_INSECURE_UPSTREAMS`) for the per-grant `allowInsecureUpstream`
escape hatch, which lets egressd reach an upstream over plain HTTP — used only
so hermetic in-cluster smoke fixtures (which cannot present a publicly-trusted
cert) are reachable. Leave it `false` in any real deployment: a plaintext
upstream leg carries the injected credential in the clear. With it off,
admission **rejects** any grant that sets `allowInsecureUpstream`, and it is
**always** rejected for `git` grants.

`egress.defaultMode` (operator env `NVT_DEFAULT_EGRESS_MODE`, validated at
startup) is applied **once, at AgentRun creation on the nvt admission/schedule
path** (producers and schedules): when an incoming run leaves `spec.egress`
empty, the admission endpoint stamps this mode before creating the object, so
the stored run is always explicit. Flipping the knob therefore never
reclassifies an existing run. It never overrides an explicit `spec.egress`.

Scope caveat: a **raw `kubectl apply`** of an AgentRun with empty egress is
defaulted to `direct` by the CRD schema (the API server, not the operator),
regardless of this knob — the operator never sees empty on that path and does
not resolve the default at read time (that would reintroduce the
reclassification hazard). An operator running mediated-by-default drives runs
through the nvt path, not raw kubectl. The global mediated-by-default flip
(changing this default value, the CRD `default:` markers, and producer specs)
stays deferred until both egress smokes are green in CI and real-cluster
usage has soaked.

### Forward-proxy mode (arbitrary tools that honor proxy env)

`spec.egressForwardProxy: true` (which **requires** `spec.egressEnforcement`)
mediates unmodified tools with hardcoded endpoints that honor `HTTP(S)_PROXY`.
The operator points the agent's `HTTP_PROXY`/`HTTPS_PROXY` at egressd; egressd
terminates the `CONNECT` under the per-agent CA (already trusted by the agent),
injects the broker credential, strips the placeholder, and re-originates TLS to
the pinned upstream. A tool sends a plain `https://<upstream>/...` with no
base-url override and gets mediated with **zero per-tool config**.

Two independent fail-closed gates bound the MITM: the CONNECT host must be a
configured inject route, and egressd refuses to mint a leaf for any other SNI.
The per-agent CA's critical name constraints widen to exactly `localhost` +
local Service names + the allowlisted upstream hosts, so a leaked CA key still
cannot impersonate an arbitrary host. Hosts that are **not** a configured
inject route are denied (no unmediated passthrough).

`NO_PROXY` is **operator-computed** — localhost, the cluster domains, the
broker, the operator callback, and kube-dns go direct — so infra legs never
route through the MITM. Routing is deny-by-default; a non-allowlisted host
fails at CONNECT (not a 401).

Residue: tools that ignore proxy env entirely (a transparent `iptables`
`REDIRECT`/`TPROXY` mode) are a separate, later step; forward-proxy covers the
large majority of CLIs, language HTTP clients, and SDKs.

### Per-grant request quotas

A mediated grant may cap its proxied requests:

```yaml
broker:
  grants:
    - provider: anthropic-main
      materialization: header-inject
      egressHosts: [api.anthropic.com:443]
      quota:
        requests: 1000
```

The operator renders this into the egressd route as `max_requests`; the
(N+1)th request fails closed with a 429. **The count is per egressd process,
not per run** — an egressd restart (in-place container restart, or the
enforcement-mode Pod recreation after eviction) resets it. It is a soft
resource guard, not a security boundary; durable run-lifetime quotas are
future work. Absent = unlimited.

### Revocation

Removing a grant from an `AgentRun` (patch `spec.broker.grants`) makes the
operator reconcile it out of the broker agents ConfigMap; the broker
hot-reloads on the file's mtime change and the next `egressd` fetch for that
grant fails closed — no broker restart. The end-to-end bound is **operator
reconcile + kubelet ConfigMap projection (~1 min worst case) + egressd cache
clamp (≤60s)**. Revoke through the AgentRun spec, never by editing the broker
agents ConfigMap directly (the operator's policy reconcile would re-add the
grant). The broker agents ConfigMap must be mounted as a directory volume,
never with `subPath` — a subPath freezes the projected file and silently
disables hot-reload; the helm render test guards this.

A mediated run can additionally set `spec.egressEnforcement: true`: egressd
moves to its own Pod and the operator renders per-run NetworkPolicies that
fence the agent Pod (egress only to kube-dns, the broker, the paired egressd,
and the operator callback). **Enforcement requires a NetworkPolicy-enforcing
CNI** (Calico, Cilium, ...): on kindnet — kind's default — the policies are
accepted but inert, and the enforcement smoke only runs on the Calico cluster
(`make operator-kind-cluster-enforced`).
The rendered policies assume the chart-managed broker/operator Pods run in the
same namespace as the `AgentRun` and keep the chart labels/ports used by the
controller selectors.

For providers that maintain broker-owned state, enable a PVC:

```yaml
broker:
  persistence:
    enabled: true
    size: 1Gi
    storageClassName: ""
    existingClaim: ""
```

When `existingClaim` is empty, the chart renders `PersistentVolumeClaim`
`nvt-broker-state` with `ReadWriteOnce`. Set `storageClassName` to choose a
class; leave it empty to use the cluster default. When `existingClaim` is set,
the broker mounts that pre-created claim and the chart does not render a PVC.

Optional one-time seed:

```yaml
broker:
  persistence:
    enabled: true
    seedSecretName: codex-auth
    seedTargetDir: codex
```

When `seedSecretName` is set, an init container using the broker image copies
the Secret files into `/state/<seedTargetDir>/` only when that directory is
absent or empty. It never overwrites existing state. This matters for stateful
providers: after a provider rotates credentials, old seed Secret contents may
be stale and must not be re-applied over live broker state.

`seedSecretName` requires `persistence.enabled=true`; rendering fails if a seed
Secret is configured with ephemeral broker state.
