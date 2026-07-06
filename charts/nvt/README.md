# nvt Helm Chart

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
