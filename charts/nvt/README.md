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

## Broker State Persistence

By default the broker keeps `/state` on an `emptyDir`, preserving existing
kind/smoke behavior:

```yaml
broker:
  persistence:
    enabled: false
```

## Agent Egress

Agent egress mode is selected per `AgentRun` with `spec.egress`; the chart does
not set a cluster-wide mode default. Direct mode remains the API default. The
chart exposes only the egressd image used when an individual `AgentRun` opts
into mediated mode:

```yaml
egress:
  egressdImage: nvt-egressd:latest
```

A mediated run can additionally set `spec.egressEnforcement: true`: egressd
moves to its own Pod and the operator renders per-run NetworkPolicies that
fence the agent Pod (egress only to kube-dns, the broker, the paired egressd,
and the operator callback). **Enforcement requires a NetworkPolicy-enforcing
CNI** (Calico, Cilium, ...): on kindnet — kind's default — the policies are
accepted but inert, and the enforcement smoke only runs on the Calico cluster
(`make operator-kind-cluster-enforced`).

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
