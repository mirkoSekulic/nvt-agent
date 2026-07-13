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
        egressHosts: [github.com:443, api.github.com:443]
        git: true
        permissions:
          contents: write
          pull_requests: write
  prompt:
    text: Implement the issue and create a pull request.
  agent:
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

## Runtime

```yaml
runtime:
  type: codex          # codex | claude
  autonomy: trusted-local
  user: root           # root | non-root
```

`non-root` runs as uid/gid 1000 with `HOME=/home/agent` and passwordless sudo.
Root remains the compatibility default.

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

`image` selects the runtime image. `runtimeClassName` optionally selects a
hardened runtime such as Kata Containers.

## Egress

`egress` is `direct` or `mediated`; omitted means direct.

```yaml
egress: mediated
egressEnforcement: true
egressTransport: transparent
```

- `egressEnforcement` creates a separate egressd Pod and per-run
  NetworkPolicies. It requires mediated mode and a policy-enforcing CNI.
- `egressTransport` is `redirect`, `forward-proxy`, or `transparent`.
  Forward-proxy and transparent require enforcement.
- `egressForwardProxy` remains a compatibility alias for forward-proxy.
- `egressAllowInsecureBroker` permits local plaintext broker traffic only.

See [Transparent mediated egress](../../docs/transparent-egress-architecture.md).

## Workspace

v1 supports only:

```yaml
workspace:
  mode: Ephemeral
```

The operator uses `emptyDir`. Data survives container restart in the same Pod
but not Pod deletion or replacement.

## Broker Grants

```yaml
broker:
  grants:
    - provider: github-main-app
      materialization: header-inject
      repositories: [owner/repo]
      egressHosts: [github.com:443]
      git: true
      permissions:
        contents: write
      quota:
        requests: 1000
```

- `provider` names a statically configured broker provider.
- `repositories` narrows its repository scope.
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
renders it as the builtin `initial-prompt` plugin. If the embedded config
already declares that plugin, rendering fails to avoid ambiguity.

`agent.config` is the normal agent YAML object. Unknown fields are preserved so
plugin configuration can remain implementation-swappable. Runtime tools,
code-server, exposed ports, repositories, and plugins live there.

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

- Active deadline marks a running workload `DeadlineExceeded` and removes its
  Pod.
- Completed and failed TTLs control terminal Pod cleanup.
- Run retention controls deletion of the terminal AgentRun object.

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
`DeadlineExceeded`. Enforced runs expose provisioning conditions including
`BrokerPolicyReady`, `EgressdCreated`, `EgressdReady`, and
`EgressCAPublished`; the agent Pod is not created before its trust and policy
prerequisites are ready.

The CRD schema under `operator/config/crd/bases/` is authoritative for exact
validation and defaults.
