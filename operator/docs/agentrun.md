# AgentRun v1alpha1

`AgentRun` is one disposable nvt agent execution. Producers and schedulers may
create it, but producer-specific behavior does not belong in the resource.

## Example

```yaml
apiVersion: nvt.dev/v1alpha1
kind: AgentRun
metadata:
  name: issue-123
  namespace: nvt
spec:
  runtime:
    type: codex
    autonomy: trusted-local
    user: non-root
  image: nvt-agent-runtime:latest
  runtimeClassName: kata-vm-isolation
  resources:
    requests: {cpu: "2", memory: 8Gi}
    limits: {cpu: "2", memory: 8Gi}
  tolerations:
    - key: purpose
      operator: Equal
      value: nvt-agent
      effect: NoSchedule
  egress: mediated
  egressEnforcement: true
  egressTransport: transparent
  workspace:
    mode: Ephemeral
  broker:
    grants:
      - provider: github-main-app
        materialization: header-inject
        repositories: [mirkoSekulic/nvt-agent]
        preparations:
          - operation: identity
        egressHosts: [github.com:443, api.github.com:443]
        git: true
        permissions:
          contents: write
          pull_requests: write
  prompt:
    text: Implement the issue and create a pull request.
  agent:
    workspaceInstructions: |
      Follow the repository contribution guide.
    workflowInstructions: |
      Review the pull request and report findings first.
    config:
      runtime:
        command: codex
      plugins: []
  lifecycle:
    completeOn:
      - plugin.github.pr.merged
      - plugin.github.pr.closed
  ttl:
    activeDeadlineSeconds: 14400
    completedTTLSeconds: 300
    failedTTLSeconds: 3600
    runRetentionSeconds: 2592000
```

`preparations` is an explicit provider-metadata request. Version 1 supports
only the non-secret `identity` operation. The operator resolves it before Pod
creation and mounts the generic, read-only document described in
[`protocol/prepared-provider-metadata.md`](../../protocol/prepared-provider-metadata.md).
It does not inspect or modify runtime plugin configuration. Omit preparations
to preserve the existing behavior and receive no metadata file or path variable.

`agent.workspaceInstructions` is optional administrator-provided guidance. The
operator projects it through the read-only agent configuration volume and the
runtime appends it to generated `AGENTS.md` before any local
`AGENTS.local.md`. It cannot replace platform guidance and is not a security
boundary. Do not put credentials or sensitive values in it: the agent can read
the content. Profiled schedules snapshot this field from the selected execution
profile; producers cannot submit an override.

`agent.workflowInstructions` is the distinct snapshot of an independently
authorized workflow profile. When present, the operator projects a separate
fixed read-only file. Runtime composition order is generated platform guidance,
execution-profile guidance, workflow guidance, then local workspace guidance.
The same 64 KiB, non-secret, agent-readable constraints apply. The selected
workflow name is recorded separately in immutable `profileProvenance`.

## Runtime

```yaml
runtime:
  type: codex          # codex | claude
  autonomy: trusted-local
  user: root           # root | non-root
```

`non-root` runs as uid/gid 1000 with `HOME=/home/agent` and passwordless sudo.
Root remains the compatibility default.

The operator translates the typed runtime selection into the generic command
contract consumed by runtime bootstrap. `trusted-local` adds
`--sandbox danger-full-access --ask-for-approval never` for Codex and
`--dangerously-skip-permissions` for Claude; `interactive` adds no autonomy
arguments. An explicitly configured `agent.config.runtime.args` list is a
complete override and is preserved exactly, so the operator never appends
potentially contradictory defaults. An explicit non-empty
`agent.config.runtime.command` is likewise preserved.

Optional `runtimeAuth` copies files from a same-namespace Secret into a
writable runtime home:

```yaml
runtimeAuth:
  secretName: codex-auth
  mountPath: /root/.codex
```

Known defaults are `/root/.codex` and `/root/.claude`. Runtime auth is a direct
compatibility path and is not mounted into DinD. Mediated providers use broker
custody and placeholders instead.

`image` selects the runtime image. `runtimeClassName` requests a runtime handler;
the cluster's RuntimeClass scheduling configuration may select the node/runtime
environment. `resources` is applied to the agent container; VM-backed runtimes
can use its limits to size the Pod VM. `tolerations` optionally permits only the generated agent Pod to
schedule onto matching tainted nodes, but a toleration does not select a node or
remove the taint. The separate egress service Pod and platform Deployments do
not inherit AgentRun tolerations.

`runtime.container.capabilities.add` optionally adds valid Linux capabilities
to the untrusted Kubernetes/OCI `agent` container only:

```yaml
runtime:
  type: codex
  autonomy: trusted-local
  user: root
  container:
    capabilities:
      add: [SYS_PTRACE]
```

Names use the Linux UAPI form without the `CAP_` prefix. Duplicate, malformed,
and unknown names are rejected before Pod creation. This is deliberately not a
generic VM contract: a future backend that cannot honor the container control
must reject it explicitly rather than silently ignore it. Kubernetes admission
policy and the selected runtime decide whether a valid capability is permitted.

Capabilities expand the authority of untrusted agent code. Powerful values
such as `NET_ADMIN` or `SYS_ADMIN` can weaken isolation and mediated-egress
guarantees even though they are administrator-owned and opt-in. No capability
is added by default, and the setting never applies to egressd, captured,
net-init, DinD, or platform containers.

## Egress

`egress` is `direct` or `mediated`; omitted means direct.

```yaml
egress: mediated
egressEnforcement: true
egressTransport: transparent
```

- `egressEnforcement` requests a CNI-enforced guarantee that workload egress
  traverses the paired egress service. It requires mediated mode and a
  policy-enforcing CNI; deployment placement is operator-owned.
- `egressTransport` is `redirect`, `forward-proxy`, or `transparent`.
  Forward-proxy and transparent require enforcement.
- `egressAllowInsecureBroker` permits local plaintext broker traffic only.

Pre-1.0 migration: replace `egressForwardProxy: true` with
`egressTransport: forward-proxy`. Remove `egressForwardProxy: false` or use
`egressTransport: redirect` explicitly. A deprecated pointer tombstone remains
temporarily in the CRD only so either legacy value is rejected with migration
guidance instead of being pruned. It has no behavior and may be removed in a
later pre-1.0 release; migrate stored manifests before installing this CRD.

See [Transparent mediated egress](../../docs/transparent-egress-architecture.md).

## Workspace

Ephemeral storage remains the default (including when `mode` is omitted):

```yaml
workspace:
  mode: Ephemeral
```

The operator uses `emptyDir`. Data survives container restart in the same Pod
but not Pod deletion or replacement.

Persistent storage is opt-in:

```yaml
workspace:
  mode: Persistent
  size: 20Gi
  dockerSize: 30Gi # optional; dedicated Docker claim, defaults to 20Gi
  storageClassName: managed-csi # optional; cluster default when omitted
```

The operator creates two `ReadWriteOnce` filesystem PVCs owned by the
`AgentRun`: the requested workspace claim and a dedicated sidecar-only Docker
claim. The workspace claim provides separate `workspace` and `home`
subdirectories. The agent sees `/workspace` and its complete home (`/root`, or
`/home/agent` for non-root runs), but it cannot mount or directly access the
Docker claim or backing image. An init container creates the workspace/home
directories and applies ownership for uid/gid 0 or 1000 before the agent starts.

The privileged Docker sidecar detects the filesystem under `/var/lib/docker`.
When Kata exposes it through `virtiofs`, the sidecar creates or reuses a sparse
ext4 image in its private backing directory, checks it, mounts it with a loop
device and `noatime`, and requires Docker's `overlay2` driver before the agent
starts. Filesystem and loop tools are baked into the coordinated `nvt-dind`
image; startup never installs them from the network. A malformed, partial, or
unmountable existing image fails closed and is never reformatted.

Ephemeral runs keep the backing image in a sidecar-only `emptyDir` with a 20
GiB size limit, so Pod replacement discards Docker data. Persistent runs keep
it in the dedicated Docker PVC, so Pod or sidecar replacement reuses the same
ext4 image without `mkfs`. `workspace.dockerSize` requests that claim between 1
GiB and 1 TiB and defaults to 20 GiB when omitted. The inner ext4 image uses
90% of its outer allocation, leaving enforced outer-filesystem
allocation/metadata headroom instead of advertising the full outer quota. The
Docker claim uses the same optional `storageClassName` as the workspace claim.
On non-virtiofs filesystems, the entrypoint leaves the existing Docker storage
behavior unchanged.

Both claims are reused across agent Pod deletion/replacement and controller
restarts while the run is active. The operator creates the consuming Pod while
valid claims are Pending, so both `Immediate` and `WaitForFirstConsumer`
StorageClasses are supported. `WorkspaceReady` remains false until both claims
become `Bound`. Workspace mode, size, Docker size, and storage class are
immutable for an existing run; expansion and shrink are not supported in v1,
and the controller never deletes/recreates a drifted live claim.

Both PVC lifetimes end when terminal operational cleanup becomes due, not when
an active Pod crashes or is replaced. The operator requests claim deletion at
that point; Kubernetes PVC protection may keep them terminating until the Pod
has unmounted them. Deleting the `AgentRun` sooner also makes garbage collection
delete both owned PVCs. Physical volume cleanup still follows the StorageClass
reclaim policy; use `reclaimPolicy: Delete` for lifecycle-scoped storage.

Loop-device, filesystem, mount, and Docker daemon privileges remain confined
to the Docker sidecar. The agent receives no privilege, Linux capability, raw
backing-image mount, or node Docker socket from this feature.

Persistent storage is not a security-material store. Broker/callback/egress
tokens, runtime-auth projections, generated configuration, and egress CA
material remain separate ephemeral, Secret, or ConfigMap mounts and are
refreshed for each Pod. Persistent runs reject `file-bundle` broker grants
because those materialize usable credentials inside the container; use
mediated zero-possession grants instead. The image-backed root filesystem
outside the selected home remains disposable.

## Broker Grants

```yaml
broker:
  grants:
    - provider: github-main-app
      materialization: header-inject
      repositories: [owner/repo]
      preparations:
        - operation: identity
      egressHosts: [github.com:443]
      git: true
      permissions:
        contents: write
      quota:
        requests: 1000
```

- `provider` names a statically configured broker provider.
- `repositories` narrows its repository scope.
- `preparations` explicitly requests bounded non-secret provider metadata;
  version 1 permits only `operation: identity`.
- `materialization` is `file-bundle` for direct mode or `header-inject` /
  `placeholder-file` for mediated mode. Admission rejects mixed modes.
- `egressHosts` binds valid upstream host:port destinations.
- `git` enables mediated git smart-HTTP behavior.
- `permissions` narrows the provider's permission ceiling.
- `allowInsecureUpstream` enables a plain-HTTP test fixture and is rejected
  unless the operator explicitly allows it. It is always invalid for git.
- `quota.requests` is a soft per-egressd-process limit; restart resets it.

The controller reconciles each run's agent and paired egress identities into
broker policy. Removing a grant revokes it after policy projection and egressd
cache expiry.

## Prompt And Agent Config

`prompt.text` is an optional convenience for disposable runs. The operator
renders it through the generic `runtime.initial-prompt` launch contract with
`delivery: argument`. Bootstrap appends the text after `runtime.args`, so
autonomy flags remain unchanged. The default Codex and Claude commands start a
long-lived interactive session with that first prompt; an explicit command or
wrapper retains its own lifecycle and must accept the final prompt argument. If
the embedded config already declares `runtime.initial-prompt`, rendering fails
to avoid ambiguity.

`agent.config` is the normal agent YAML object. Unknown fields are preserved so
plugin configuration can remain implementation-swappable. Runtime tools,
code-server, exposed ports, repositories, and plugins live there.

Runs created through profiled `AgentSchedule` admission also carry
`spec.profileProvenance`. It snapshots the authenticated Kubernetes producer,
schedule identity and generation, selected profile, and the immutable
principal issuer/subject plus optional display name. The fully resolved
runtime, agent runtime config, egress, and broker grants are stored directly in
the same `AgentRun`; later schedule edits do not re-resolve existing runs.

## Lifecycle

```yaml
lifecycle:
  completeOn: [plugin.github.pr.merged]
  failOn: [plugin.agent.signal.failed]
```

Direct and non-enforced mediated runs may report events through the
authenticated callback endpoint. Enforced runs avoid callback credentials in
the Agent Pod: the operator observes a termination message and validates it
against the same lifecycle lists.

Terminal phases are `Completed`, `Failed`, and `DeadlineExceeded`.

## TTL

```yaml
ttl:
  activeDeadlineSeconds: 14400
  completedTTLSeconds: 300
  failedTTLSeconds: 3600
  runRetentionSeconds: 2592000
```

- Active deadline marks a running workload `DeadlineExceeded` and immediately
  performs terminal operational cleanup.
- Completed and failed TTLs control when terminal operational cleanup occurs.
  Until that deadline, run-scoped resources are retained. Cleanup removes the
  agent and enforced egressd Pods, persistent workspace PVC, per-run Service,
  NetworkPolicies, ConfigMaps, and Secrets, and revokes both run identities
  from the broker agents policy. Broker access is revoked and both Pod
  deletions are requested first; the NetworkPolicies and all remaining
  resources stay in place until both Pods are confirmed gone, preserving the
  egress fence throughout asynchronous Kubernetes termination.
- Run retention controls deletion of only the lightweight terminal `AgentRun`
  metadata after operational cleanup. `runRetentionSeconds: 0` retains that
  metadata indefinitely without retaining workloads, credentials, policy, or
  storage after their completed/failed cleanup deadline.

## Status

```yaml
status:
  phase: Running
  podName: issue-123-agent
  startedAt: "..."
  finishedAt: null
  reason: ""
  conditions: []
```

Phases are `Pending`, `Running`, `Completed`, `Failed`, and
`DeadlineExceeded`. Persistent runs expose `WorkspaceReady`. Enforced runs
expose provisioning conditions including `BrokerPolicyReady`,
`EgressdCreated`, `EgressdReady`, and `EgressCAPublished`; the agent Pod is not
created before its storage, trust, and policy prerequisites are ready.

The CRD schema under `operator/config/crd/bases/` is authoritative for exact
validation and defaults.
