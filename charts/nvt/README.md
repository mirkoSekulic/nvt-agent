# nvt Helm Chart

The chart installs the AgentRun and AgentSchedule CRDs, operator, broker, and
optional browser gateway and GitHub comments producer.

For deployments, install the published OCI chart shown in
[`charts/README.md`](../README.md). A source checkout cannot know the release
commit used to publish images. If source rendering is required, supply one
exact published tag explicitly:

```sh
helm template nvt ./charts/nvt \
  --set-string global.imageTag=0.2.0-943d5ba
```

Do not install the source chart without `global.imageTag` or component-specific
tags: its development `Chart.AppVersion` is not a published image identity.

Provider credentials are supplied through existing Secrets, never literal
chart values.

## Upgrading CRDs

Helm installs files from a chart's `crds/` directory on first install but does
not upgrade them during a normal `helm upgrade`. Existing installations must
therefore update both the AgentRun and AgentSchedule CRDs before, or as part
of, upgrading to chart `0.8.41`; otherwise the API server will prune or reject
new AgentRun and schedule fields such as container capabilities, required
Docker networks, the Docker kernel-log device control, dedicated Docker
storage size, broker grant preparations, profile workspace instructions, or
workflow producer policies.

For Flux, configure the `HelmRelease` to create or replace CRDs consistently on
install and upgrade:

```yaml
spec:
  install:
    crds: CreateReplace
  upgrade:
    crds: CreateReplace
```

For the Helm CLI, apply the CRDs from the same immutable chart version before
upgrading the release:

```sh
helm show crds oci://ghcr.io/mirkosekulic/helm/nvt --version 0.8.41 \
  | kubectl apply --server-side -f -

helm upgrade --install nvt oci://ghcr.io/mirkosekulic/helm/nvt \
  --version 0.8.41 --namespace nvt --create-namespace
```

Do not apply CRDs from a different chart version than the release being
installed.

For transparent AgentRuns, configure `dind.protectedCIDRs` with every cluster
Pod, Service, control-plane, broker, and deployment-denied IPv4 range. Startup
fails closed if any configured range overlaps the managed Docker pool
`172.30.0.0/15`; malformed CIDRs are also rejected. The defaults protect
loopback and link-local/metadata ranges but cannot infer cluster-specific CIDRs.

## Coordinated images

The published chart's `appVersion` is the immutable image tag for its tested
platform bundle. Chart `0.2.0` published from commit `943d5ba...`, for example,
uses `0.2.0-943d5ba` for runtime, DinD, broker, egressd, captured, operator,
gateway, producer, and execution-driver-host images. Empty component tags
default to `Chart.AppVersion`; repository, tag, and pull policy remain
independently overridable. The QEMU reference driver is a test implementation,
not a coordinated product image.

`dind.image` is the coordinated Docker sidecar image. It contains the ext4 and
loop-device tools used only when an AgentRun's Docker data root is backed by
Kata virtiofs; it performs no per-run package installation.

All default repositories are under `ghcr.io/mirkosekulic`. The chart is
published only after all nine image manifests and the native host-bundle OCI
artifact exist and can be fetched anonymously with isolated credential-free
clients. The release reuses an
existing image tag only when its OCI source, full revision, and version labels
match. GHCR package writers are trusted: matching labels establish coordinated
release metadata, not byte-for-byte content identity against copied labels.

### Custom branding

The coordinated images include the NVT Agent logo. An open-source deployment
can replace the public gateway and code-server artwork with one
administrator-owned ConfigMap in the release namespace:

```sh
kubectl create configmap company-agent-branding -n nvt \
  --from-file=nvt-agent-mark.svg=./nvt-agent-mark.svg \
  --from-file=favicon.ico=./favicon.ico \
  --from-file=nvt-agent-mark-64.png=./nvt-agent-mark-64.png \
  --from-file=nvt-agent-mark-192.png=./nvt-agent-mark-192.png \
  --from-file=nvt-agent-mark-512.png=./nvt-agent-mark-512.png
```

```yaml
branding:
  existingConfigMap: company-agent-branding
```

The key names are fixed: the chart does not accept arbitrary paths, external
URLs, or encoded image values. The ConfigMap is public presentation data, not
a place for credentials. It is mounted read-only into the gateway and only the
untrusted agent container; DinD, captured, egressd, broker, and the operator do
not receive it. Missing keys prevent the affected Pod from starting, and the
gateway validates the 64/192 PNG dimensions plus ICO header before serving.

Changing the ConfigMap name rolls the gateway Deployment and applies to newly
created or normally replaced AgentRun Pods. Existing create-once AgentRun Pods
keep their current mount until replacement. Updating data in the same ConfigMap
is projected by Kubernetes for code-server, while the gateway must be restarted
to reload its in-memory validated assets. Leave `existingConfigMap` empty to
use the built-in branding.

## Upgrading image values from 0.1

Version 0.2 replaces scalar image values with repository/tag/pullPolicy maps.
Migrate saved values before upgrading:

```yaml
# 0.1 (no longer accepted)
operator:
  image: nvt-operator:latest

# 0.2
operator:
  image:
    repository: ghcr.io/mirkosekulic/nvt-operator
    tag: 0.2.0-943d5ba
    pullPolicy: IfNotPresent
```

The same shape applies to runtime, broker, gateway, producer, egressd, and
captured. A legacy scalar fails rendering with an explicit migration error.
Do not use `--reuse-values` across this boundary; migrate the values file or
reset stored values before the 0.2 upgrade. `make producer-kind-install` uses
`--reset-values` and treats `PRODUCER_VALUES` as a complete consolidated-chart
values file for this reason.

## GitHub comments producer

The producer is integrated under `producer` and disabled by default. It keeps
the former chart's configuration surface, including direct and schedule
admission, legacy/profiled admission, projected TokenReview credentials,
persistence, ServiceAccount/RBAC, GitHub App Secret references, AgentRun
settings, TTL, grants, runtime auth, and arbitrary agent configuration.

```yaml
producer:
  enabled: true
  repositories:
    - owner: example
      name: repository
  githubApp:
    appID: 123456
    installationID: 12345678
    existingSecret: nvt-github-app
  submission:
    mode: scheduleAdmission
    admissionMode: profiled
    scheduleName: default
    workflow: implement-pr # optional static workflow profile name
  persistence:
    enabled: true
    size: 1Gi
```

Create `nvt-github-app` out of band with the configured private-key key; the
chart never accepts or renders private-key material. In profiled mode without
workflows, list the rendered producer ServiceAccount username in the
compatibility `agentSchedule.allowedProducers` list. With workflow profiles,
use the typed `agentSchedule.producerPolicies` field shown below.
The chart projects only a rotating `nvt-operator` audience token. The default
producer AgentRun runtime image is the coordinated `runtime.image`; set
`producer.agentRun.runtimeImage` only for an intentional override.

Legacy/direct producer payloads can opt into AgentRun-scoped persistence:

```yaml
producer:
  agentRun:
    workspaceMode: Persistent
    workspaceSize: 20Gi
    workspaceDockerSize: 30Gi # optional dedicated Docker PVC; defaults to 20Gi
    workspaceStorageClassName: managed-csi # optional
```

Ephemeral remains the default. Persistent mode requires a positive Kubernetes
quantity and cannot be combined with the legacy producer's file-bundle broker
grants. Its optional Docker size must be between 1 GiB and 1 TiB; the operator
creates a separate sidecar-only Docker claim so workspace/home use cannot
consume the Docker quota. Profiled admission does not send these fields;
configure `size`, optional `dockerSize`, and `storageClassName` in the
operator-owned `AgentSchedule.spec.template.workspace` instead.

Persistent AgentRuns use the dedicated Docker claim on every container
runtime, not only Kata/virtiofs. During an upgrade, an already-running
pre-0.8.15 persistent Pod is preserved until its next normal replacement; the
operator does not create an unreferenced `WaitForFirstConsumer` Docker claim.
That replacement creates and consumes the claim, and Docker persistence begins
from then on.

## Broker TLS

Broker TLS is enabled by default:

```yaml
broker:
  tls:
    enabled: true
    secretName: nvt-broker-tls
    existingSecret: ""
```

Without `existingSecret`, Helm creates and preserves a self-signed CA and
serving certificate across normal upgrades. The broker Deployment checksum
rolls the Pod when the material changes.

For production, prefer an existing `kubernetes.io/tls` Secret containing
`tls.crt`, `tls.key`, and `ca.crt`:

```yaml
broker:
  tls:
    enabled: true
    existingSecret: nvt-broker-tls
```

The operator projects only `ca.crt` into workloads. The serving key remains in
the broker Pod. Rotating an externally managed Secret requires restarting the
broker Deployment unless the external controller performs that rollout.

Plain HTTP requires `broker.tls.enabled=false` plus explicit
`spec.egressAllowInsecureBroker: true` on mediated runs. This is for local tests
only.

## Broker State

Broker state uses `emptyDir` by default. Stateful OAuth providers should use a
PVC:

```yaml
broker:
  persistence:
    enabled: true
    size: 1Gi
    storageClassName: ""
    existingClaim: ""
```

Optionally reconcile credential seeds from an existing Kubernetes Secret:

```yaml
broker:
  persistence:
    enabled: true
    seedSecretName: codex-auth
    seedTargetDir: codex
```

The Secret is a generic read-only source directory; NVT has no dependency on
the system that materializes it. Every top-level Secret key maps to the same
filename under `/state/<seedTargetDir>` and is tracked independently by a
durable source digest on the PVC. Provider configuration still selects the
canonical file explicitly; filenames are never inferred by provider type.

The first source value is imported as mode `0600`. Broker-side rotation may
then change that canonical file without the unchanged source overwriting it.
When Kubernetes atomically projects changed Secret keys, the broker lifecycle
supervisor pins and validates one complete projected generation, makes readiness
false, terminates and reaps the broker and its provider process group,
atomically imports the new value and marker, and starts the broker again in the
same Pod. No Helm change, rollout, `kubectl exec`, PVC edit, or Kubernetes API
permission is required. Removing a Secret key never deletes canonical state.

On migration from the old one-shot seed behavior, an existing canonical file
without a marker is preserved and the current source digest is adopted. This
prevents a stale seed from overwriting a credential already rotated by the
broker. Invalid, escaping, non-regular, symlinked, or oversized source entries
hold the broker unready without replacing its last usable canonical file; fix
the source Secret to recover automatically. Kubernetes' projected `..data`
symlinks are the only accepted source-file symlink form.

Replacement retains at most one mode-`0600` recovery record per changed file
until every configured provider accepts its local state through the
provider-owned readiness contract, then removes it. The chart keeps a single
broker replica and `Recreate` strategy so there is still exactly one writer for
provider state.

### Native guest enrollment issuer

The provider-neutral VM guest enrollment issuer is disabled by default. It is
enabled only with persistent broker state, TLS, a canonical broker-owned
exchange URL, and a dedicated control-plane bearer token from an existing
Secret:

```yaml
broker:
  persistence:
    enabled: true
    size: 1Gi
  tls:
    enabled: true
  guestEnrollment:
    enabled: true
    exchangeURL: https://nvt-broker.nvt.svc:7347/v1/guest-enrollment/exchange
    runtimeIdentityHistoryCapacity: 2000000
    orchestratorAuth:
      existingSecret: nvt-guest-enrollment-orchestrator
      tokenKey: token
```

The referenced Secret key must contain one 32–4096 byte opaque token using
letters, digits, `.`, `_`, `~`, or `-`, with no newline. The chart never
creates or copies that value into a ConfigMap, environment value, AgentRun, or
agent Pod. The broker and operator each read the projected bearer once at
startup. Rotation is therefore one coordinated maintenance operation: update
the shared Secret, then restart both the broker and operator Deployments.
Restarting only one side creates a temporary authorization mismatch that fails
closed and can block enrollment cleanup until the other Deployment restarts.

The issuer stores only token/runtime-identity digests and bounded lifecycle
metadata in `/state/guest-enrollment.sqlite3`. It uses SQLite transactions and
therefore shares the broker's existing one-replica, `Recreate`, single-writer
contract. Do not scale the broker or mount the same database through multiple
broker Pods. Enrolled guests can authenticate and atomically rotate the current
opaque identity through the same TLS broker; no plaintext credential storage
is introduced. The canonical URL must resolve to
this issuer over authenticated HTTPS. Enabling this issuer alone does not route
AgentRuns to VMs.

`runtimeIdentityHistoryCapacity` is the practical aggregate predecessor-digest
storage bound. Each accepted enrollment reserves 20,000 entries atomically, so
the default `2000000` admits 100 complete lifecycles and cannot be consumed
first-come by rotations from another lifecycle. Values from 20,000 through
10,000,000 are accepted; size the broker PVC for the selected maximum. New
enrollment fails before an envelope is returned if a complete reservation is
unavailable. Expiry before exchange atomically releases the unused reservation;
an issued runtime identity retains its allowance until exact revocation. The
recommended 30-minute rotation interval provides a one-year
planning horizon only when clients follow it; the broker does not enforce that
interval. Replace/re-enroll guests before their reservation is exhausted.

The operator bridge is a separate opt-in and uses explicit broker trust plus
the same dedicated orchestrator Secret:

```yaml
executionDrivers:
  guestEnrollment:
    enabled: true
    registrations: [qemu-lab]
    brokerURL: https://nvt-broker.nvt.svc:7347
    serverName: nvt-broker.nvt.svc
    ca:
      existingSecret: nvt-broker-tls
      key: ca.crt
    orchestratorAuth:
      existingSecret: nvt-guest-enrollment-orchestrator
      tokenKey: token
    requestTimeoutSeconds: 30
    handoffTimeoutSeconds: 30
    ttlSeconds: 300
```

The operator receives the orchestrator bearer; driver hosts receive only their
existing per-registration authentication and the one-time envelope addressed
to that exact registration. The bearer is never passed to a driver. Only exact
names in `guestEnrollment.registrations` receive the sensitive handoff socket;
other external registrations retain the ordinary execution-driver protocol.
The controller activates enrollment only for external `kind: vm` runs. Keep
this configuration and registration available while any AgentRun retains the
`nvt.dev/agentrun-guest-enrollment` finalizer: cleanup must acknowledge broker
execution-scope revocation, exact-driver deletion, and broker cleanup completion
before finalizer removal. Expiry maintenance is automatic, but elapsed time
alone never erases an uncompleted revocation.

## Agent Egress

Direct mode remains the default:

```yaml
egress:
  egressd:
    image:
      repository: ghcr.io/mirkosekulic/nvt-egressd
      tag: "" # Chart.AppVersion
  captured:
    image:
      repository: ghcr.io/mirkosekulic/nvt-captured
      tag: "" # Chart.AppVersion
  defaultMode: direct
  networkPolicyCapable: false
  allowedTCPPorts: [80, 443]
  denyCIDRs: []
  allowInsecureUpstreams: false
```

`defaultMode` is applied once when an AgentRun enters through schedule
admission. It never reclassifies an existing object and does not override an
explicit `spec.egress`. Raw `kubectl apply` with an omitted field follows the
CRD default, which is direct.

## Execution profiles

`agentSchedule.template`, optional `executionClasses`, `profiles`,
`profileSelection`, and either the legacy
`allowedProducers` list or typed workflow `producerPolicies` configure profiled
admission. Empty values
preserve legacy full-`AgentRun` admission. Profiled admission requires a
projected ServiceAccount token with audience `nvt-operator`; see the
[AgentSchedule contract](../../operator/docs/agentschedule.md).

Omitted profile execution keeps the existing Kubernetes Pod path. Operators
may spell that selection explicitly as `execution: {kind: pod, driver:
kubernetes}`. Future external drivers select one exact entry from
`agentSchedule.executionClasses` by `kind`, logical `driver`, and `classRef`;
the class's bounded opaque configuration is snapshotted into the AgentRun.
Unknown/mismatched selections fail without Pod fallback. Chart `0.8.41`
reconciles external AgentRuns only through the exact matching registered host.
Defaults remain Kubernetes-only and need no source access, cloud SDK, cloud
credentials, or extra workload.

```yaml
agentSchedule:
  executionClasses:
    - name: vm-standard
      kind: vm
      driver: example-vm
      configuration: {cpu: 4}
  profiles:
    - name: codex-vm
      execution: {kind: vm, driver: example-vm, classRef: vm-standard}
      # remaining profile-owned fields omitted
```

The matching installation-owned registration uses a complete provider image
pinned by digest. One workload is created per registration, so two logical
registrations may reuse the same implementation image without sharing a
ServiceAccount, infrastructure credential, authentication token, or process:

```yaml
executionDrivers:
  registrations:
    - name: example-vm
      image: registry.example.test/nvt/example-vm@sha256:<64-lowercase-hex>
      command: [/usr/local/bin/example-vm-driver]
      resources:
        requests: {cpu: 100m, memory: 128Mi}
        limits: {cpu: "1", memory: 512Mi}
      serviceAccount:
        create: true
        annotations: {} # workload-identity annotations belong here
        podLabels: {}   # generic identity-webhook opt-in labels, if required
      # Optional provider-neutral durable convergence/resource storage. A
      # driver that owns local disks must request a bounded claim or select one
      # existing claim; omission preserves the previous stateless Pod shape.
      storage:
        size: 20Gi
        storageClassName: ""
      # Names injected by an approved workload-identity webhook. Every listed
      # name is required at process start; values are never stored here.
      passEnv: [PROVIDER_FEDERATED_TOKEN_FILE]
      secretEnvironment:
        - name: PROVIDER_CLIENT_SECRET
          secretName: example-vm-infrastructure
          key: client-secret
      secretFiles:
        - name: provider
          secretName: example-vm-infrastructure
          items:
            - {key: config, path: config.json}
```

The provider image owns its language runtime and dependencies. A coordinated
static host binary is copied into the Pod and starts only the explicit command;
there is no clone, build, package installation, hook, or source acquisition at
startup. `passEnv` is the exact allowlist for environment added by an approved
workload-identity webhook; a missing listed name fails process startup.
Secret-backed environment entries are automatically included in the same
allowlist. Secret files have fixed mounts below
`/var/run/secrets/nvt-execution-driver/<name>`; no unlisted host environment
enters the driver's clean child environment.
The per-registration HTTPS Service requires its own bearer token and trusts its
own chart-managed CA; NetworkPolicy admits only the operator Pod. These drivers
are trusted control-plane extensions, not sandboxes. Infrastructure credentials
must be scoped to the matching registration. The operator receives only host
transport CA/token material, never provider credentials.

Registrations are an operational lifecycle commitment. Do not remove or rename
a registration while an AgentRun still references it: deletion keeps the
operator finalizer and reports the driver unavailable until the same logical
registration is restored. Restoring that registration lets level-triggered
provider cleanup resume; the operator never falls back to Kubernetes or a
different driver. A driver's ready response is portable execution state only
and does not publish an external endpoint through the gateway.

The repository's QEMU implementation is a provider-isolated, test-only
reference driver. CI builds it locally to prove persistent registration
storage, native linux/amd64 provisioning, one-time guest enrollment, real
agentd/session readiness, restart recovery, and cleanup. It is not published
as a coordinated image or supported as a production execution provider. See
the [QEMU reference-driver contract](../../executiondrivers/qemu/README.md).
Gateway routing and mediated VM egress remain intentionally outside this
reference proof.

`activeDeadlineSeconds`, `completedTTLSeconds`, and `failedTTLSeconds` remain
operator-owned for external runs. When cleanup becomes due, the operator calls
only that run's exact driver until it reports `deleted`; the external cleanup
finalizer is not removed on an error. `runRetentionSeconds` independently
controls how long the terminal AgentRun remains after operational cleanup.

### Native VM host bundle

The coordinated release also publishes
`ghcr.io/mirkosekulic/nvt-host-bundle:<appVersion>` as a generic OCI artifact,
not a runnable container image. Tags are discovery only. A VM execution class
must snapshot the complete repository and `sha256` OCI index digest in its
existing opaque, administrator-owned configuration:

```yaml
executionClasses:
  - name: native-vm-small
    kind: vm
    driver: example-vm
    configuration:
      hostBundle:
        repository: https://ghcr.io/mirkosekulic/nvt-host-bundle
        digest: sha256:<64-hex>
```

The value contains no enrollment credential and is not a producer surface.
See the [native host-bundle contract](../../protocol/host-bundle.md) for bundle
contents, native prerequisites, atomic activation, and current limitations.

Helm validates the same load-bearing registration bounds as the host contract:
the command is capped at 128 arguments and 16 KiB aggregate text, and CPU and
memory requests/limits must be positive Kubernetes quantities with each request
no greater than its limit. Kubernetes admission remains authoritative for the
full syntax of arbitrary annotations, labels, extended resources, and Secret
object existence; those API-owned checks are not duplicated as a second chart
policy.

Scheduling fields in the shared template are passed to the generated agent Pod:

```yaml
agentSchedule:
  template:
    runtimeClassName: kata-vm-isolation
    resources:
      requests: {cpu: "2", memory: 8Gi}
      limits: {cpu: "2", memory: 8Gi}
    workspace:
      mode: Persistent
      size: 20Gi
      dockerSize: 30Gi
      storageClassName: managed-csi
    tolerations:
      - key: purpose
        operator: Equal
        value: nvt-agent
        effect: NoSchedule
```

RuntimeClass scheduling may select the runtime/node environment. A toleration
permits the agent Pod to schedule onto a matching tainted pool, but does not
select a node or remove the taint. These are generic Kubernetes values. They do
not move the separate egress service Pod or any nvt platform Deployment.
`resources` is applied to the agent container. On AKS Pod Sandboxing, the CPU
and memory limits determine the Kata Pod VM allocation; set requests equal to
limits when predictable VM capacity is required.

When `agentSchedule.template` is non-empty, an absent or empty `image` defaults
to the coordinated runtime image (`runtime.image` with the published chart's
immutable `appVersion`). Set `agentSchedule.template.image` explicitly to
preserve an intentional override. An empty template remains omitted for legacy
schedule admission.

Execution profiles can declare generic required IPv4 Docker networks under
`runtime.docker.requiredNetworks`. For example, a nested-cluster profile may
reserve `kind` on `172.31.250.0/24`. The name and explicit `/24` subnet are
profile-owned, snapshotted into each AgentRun, and reconciled before Docker CLI
operations and after `docker system prune`, so pruning cannot permanently
remove the contract. Subnets must be unique and inside the managed
`172.31.0.0/16` pool;
IPv6, dual-stack, malformed, and incompatible existing networks fail closed.
Omitting the field preserves existing Docker behavior.

The same profile block can opt into a kernel-log device for nested privileged
system workloads:

```yaml
agentSchedule:
  profiles:
    - name: nested-system-codex
      runtime:
        type: codex
        autonomy: trusted-local
        docker:
          kernelLogDevice: true
      # agentRuntimeConfig, egress, and broker fields omitted
```

Only the privileged DinD sidecar prepares the real `/dev/kmsg` character
device (major 1, minor 11); the untrusted agent container receives neither the
setting nor the device. Omission remains false.

**Security boundary:** outside a microVM-backed RuntimeClass, exposing
`/dev/kmsg` can expose the Kubernetes node kernel log to nested privileged
workloads. Enable it only in an administrator-approved microVM execution
profile. Invalid existing paths or device numbers fail DinD startup rather
than being replaced.

Execution profiles may append reusable administrator-owned workspace guidance:

```yaml
agentSchedule:
  profiles:
    - name: codex-default
      workspaceInstructions: |
        Follow the repository contribution guide.
        Run the project checks before opening a pull request.
```

The selected text is snapshotted into the AgentRun and appended to generated
platform guidance before local `AGENTS.local.md`; it never replaces either
layer. Producers cannot submit or override it. This is configuration, not a
security boundary, and it must not contain credentials or sensitive values
because the untrusted agent can read it. The value is bounded to 64 KiB.

The same profile-owned runtime block can request Linux capabilities for only
the untrusted Kubernetes/OCI agent container:

```yaml
agentSchedule:
  profiles:
    - name: debug-codex
      runtime:
        type: codex
        autonomy: trusted-local
        container:
          capabilities:
            add: [SYS_PTRACE]
      # agentRuntimeConfig, egress, and broker fields omitted
```

This is an opt-in container process control, not a generic VM abstraction or a
raw Kubernetes security-context escape hatch. A future backend that cannot
honor it must reject it. Kubernetes policy and the runtime remain authoritative.
Capabilities such as `NET_ADMIN` and `SYS_ADMIN` can weaken mediated-egress and
other isolation guarantees when an administrator explicitly grants them.

Workflow profiles decouple reusable guidance from execution/auth profiles and
authorize selection by the TokenReview-authenticated producer identity:

```yaml
agentSchedule:
  workflowProfiles:
    - name: implement-pr
      workspaceInstructions: |
        Implement the change and create a pull request.
    - name: review-pr
      workspaceInstructions: |
        Review the pull request and report findings first.
  producerPolicies:
    - identity: system:serviceaccount:nvt:nvt-github-comments-producer
      workflows: [implement-pr, review-pr]
      defaultWorkflow: implement-pr
```

The original string `allowedProducers` list remains supported for schedules
without workflow configuration. Enabling workflows requires replacing it with
`producerPolicies`; the chart and operator reject mixing the two forms. The
optional producer `submission.workflow` sends only a static workflow name, not
instruction text or execution-profile/provider selection. AgentRun snapshots
keep execution-profile and workflow instructions distinct, and the runtime
orders platform, profile, workflow, then local guidance.

### Enforced Transparent Mode

```yaml
egress:
  networkPolicyCapable: true
```

```yaml
spec:
  egress: mediated
  egressEnforcement: true
  egressTransport: transparent
  # Optional; omitted uses egressd's package-manager-oriented default of 256.
  egressMaxConcurrentTunnels: 512
```

The operator creates a paired egress endpoint, per-run NetworkPolicies, a
credential-less capture relay, and one-shot NET_ADMIN routing initialization.
Normal outbound TCP, including DinD traffic, is redirected through captured and
egressd. The untrusted workload has no direct internet egress rule. Deployment
placement is an operator implementation detail, not an AgentRun contract.
Locally published DinD services remain reachable from the agent through Docker
bridge interfaces, including Compose bridges created after Pod initialization;
connections originating in DinD containers still enter PREROUTING capture.

`egressMaxConcurrentTunnels` is an optional profile-owned bound for simultaneous
CONNECT tunnels in forward-proxy and transparent transports (1–4096). egressd
queues at most the same number of additional requests for a bounded five-second
burst window, then rejects sustained overload explicitly. Omit the field to use
the default 256-tunnel active bound.

`networkPolicyCapable=true` is an operator assertion, not CNI installation.
Set it only when the cluster CNI enforces NetworkPolicy. The enforced kind
smoke uses Calico because default kind networking does not prove the boundary.

Forward-proxy transport remains available for clients that honor
`HTTP(S)_PROXY`. For the pre-1.0 migration, replace
`spec.egressForwardProxy: true` with `spec.egressTransport: forward-proxy`;
remove a false legacy field or select `redirect` explicitly. The consolidated
CRD retains a deprecated rejection-only tombstone so either legacy value fails
loudly instead of being pruned. The tombstone has no behavior and may be removed
in a later pre-1.0 release; migrate stored manifests before upgrading the chart.

`allowInsecureUpstreams` permits explicitly marked plain-HTTP fixtures for
hermetic tests. Leave it false in real deployments; plaintext would expose an
injected credential on the upstream leg.

### Quotas And Revocation

A grant may set a soft per-egressd-process request limit:

```yaml
spec:
  broker:
    grants:
      - provider: anthropic-main
        materialization: header-inject
        egressHosts: [api.anthropic.com:443]
        quota:
          requests: 1000
```

An execution profile that needs provider-owned commit identity in an enforced
mediated run declares it on the exact grant, independently of plugin config:

```yaml
broker:
  grants:
    - provider: fork-app
      materialization: header-inject
      repositories: [owner/repo]
      egressHosts: [github.com:443]
      preparations:
        - operation: identity
```

The operator mounts only the resulting bounded name/email metadata. It does not
mount the control-plane broker token or rewrite a runtime plugin configuration.

The next request after the limit receives 429. An egressd restart resets the
counter, so this is a resource guard rather than durable accounting.

To revoke access, remove the grant from `AgentRun.spec.broker.grants`. The
operator updates broker policy; the broker hot-reloads it; egressd stops
receiving material after policy projection and cache expiry. Do not edit the
broker ConfigMap directly or mount its policy file with `subPath`.

See [Transparent mediated egress](../../docs/transparent-egress-architecture.md)
for trust boundaries and traffic behavior.

## Gateway

Enable the optional gateway to list and route browser sessions:

```yaml
gateway:
  enabled: true
  baseDomain: agents.example.com
  publicURL: https://agents.example.com
```

The chart creates a ClusterIP Service, not an external Ingress. Configure the
cluster's ingress layer separately.

### Native VM guest session listener

The provider-neutral native guest listener is separately opt-in and remains
unrelated to browser ingress. Supply an existing TLS Secret whose certificate
covers the in-cluster gateway DNS name and an explicit CA Secret for the
broker. The chart never generates or embeds private key material:

```yaml
gateway:
  enabled: true
  replicas: 1
  nativeSession:
    enabled: true
    port: 7443
    tls:
      existingSecret: nvt-gateway-native-session-tls
      certificateKey: tls.crt
      privateKeyKey: tls.key
    brokerURL: https://nvt-broker.nvt.svc.cluster.local:7347
    serverName: nvt-broker.nvt.svc.cluster.local
    ca:
      existingSecret: nvt-broker-tls
      key: ca.crt
    authenticationTimeoutSeconds: 5
    revalidationIntervalSeconds: 30
```

The Service exposes `native-session` as TLS. The gateway validates each hello
through the broker, discards the session bearer, and closes the connection at
the bounded revalidation interval so reconnect must authenticate again. The
registry is process-local, so Helm requires exactly one gateway replica while
this feature is enabled. The native listener port must also differ from both
the HTTP container port and HTTP Service port. Temporary broker or bounded
capacity failures close without a definitive rejection so the guest retries
the same credential; only an authenticated denial or exact status mismatch is
terminal. Missing Secrets or keys fail at Kubernetes volume
setup; invalid TLS or CA material fails gateway startup. This phase exposes
only the bounded agentd relay used by the native control contract. It does not
publish a browser/code-server route or implement an HTTP/WebSocket reverse
tunnel. The gateway loads both TLS identity and broker trust once at startup;
restart its Deployment after rotating either referenced Secret.

### OIDC

External deployments should use generic OIDC authorization code flow with
PKCE:

```yaml
gateway:
  enabled: true
  replicas: 1
  auth:
    mode: oidc
    session:
      existingSecret: nvt-gateway-session
      cookieDomain: .agents.example.com
    oidc:
      issuerURL: https://issuer.example.com
      clientID: nvt-gateway
      clientSecret:
        existingSecret: nvt-gateway-oidc
    authorization:
      default: deny
      claimSource: id_token
      rules:
        - id: platform-team
          effect: allow
          claimPath: groups[]
          values: [nvt-agent-users]
```

Authentication does not imply authorization. OIDC defaults to deny until a
rule allows the user. Session state is process-local, so OIDC mode currently
requires one gateway replica.

Optional `gateway.auth.admission` is a separate default-deny login gate applied
after authentication and before session creation. `gateway.auth.authorization`
remains the per-AgentRun gate. Resource allow rules are ORed, so a broad group
or organization rule must not be combined with `owner: true` as a substitute
for admission: use the organization rule in admission and keep owner matching
in authorization.

Both OAuth-backed modes can populate selected admission claims through generic
bounded HTTPS sources:

```yaml
gateway:
  auth:
    mode: oauth2
    session:
      # Membership is a login-time snapshot; bound the revocation window.
      maxAgeSeconds: 3600
    oauth2:
      credentials:
        existingSecret: nvt-gateway-github
      issuer: https://github.com
      authorizationURL: https://github.com/login/oauth/authorize
      tokenURL: https://github.com/login/oauth/access_token
      scopes: []
      clientAuthMethod: client_secret_post
      identity:
        endpoint: https://api.github.com/user
        allowedHosts: [api.github.com]
        subjectPath: id
        displayNamePath: login
    claimEnrichment:
      allowedHosts: [api.github.com]
      sources:
        - endpoint: https://api.github.com/user/memberships/orgs/Altinn
          outputClaim: organization_membership
          valuePath: state
    admission:
      default: deny
      rules:
        - id: allowed-organization
          effect: allow
          claimPath: organization_membership
          values: [active]
    authorization:
      default: deny
      rules:
        - id: agent-owner
          effect: allow
          owner: true
```

This is a generic claim-source example, not GitHub-specific gateway policy.
Each configured endpoint receives the temporary OAuth bearer token, must use
HTTPS, and must be on `allowedHosts`; redirects and failures deny login. Only
the selected non-sensitive value is retained. Required OAuth permissions and
organization approval belong to provider/client configuration. For the GitHub
example, the GitHub App needs organization **Members: read**, must be installed
and approved for the Altinn organization by an organization owner, and must be
authorized by each user. It needs no repository permissions. Active membership
returns `state: active`; pending, unaffiliated, blocked, or unapproved access
fails admission closed.

Claim enrichment runs only during OAuth login. The selected claims are kept in
the server-side session and are not refreshed on every request; OAuth tokens
are discarded. Organization removal affects new logins immediately, but an
existing session remains valid until `gateway.auth.session.maxAgeSeconds`
expires or session state is invalidated, including by a gateway restart. Use an
explicit shorter lifetime such as `3600` (one hour) for security-sensitive
production deployments rather than the 24-hour default.

Authorization may read verified claims from `id_token`, `userinfo`, or a JWT
`access_token`. Sensitive identity claims such as SSN or pid are rejected as
authorization keys.

For Ansattporten-style authorization details:

```yaml
gateway:
  auth:
    oidc:
      authorizationDetails: |
        [{"type":"ansattporten:altinn:resource","resource":"urn:altinn:resource:example"}]
    authorization:
      claimSource: userinfo
      rules:
        - id: authorized-organization
          effect: allow
          where:
            array: authorization_details[].authorized_parties[]
            all:
              - claimPath: orgno.ID
                values: ["0192:991825827"]
              - claimPath: resource
                values: [example]
```

All `where.all` conditions must match the same array element. See the
[gateway README](../../gateway/README.md) for callback and session behavior.

### Generic OAuth2 owner login

The generic OAuth2 adapter supports providers without OIDC. GitHub is one
configuration example; no provider or organization behavior is built into the
gateway. Put the client ID and secret in one existing Secret. The chart never
renders credential values into a ConfigMap or Pod environment literal:

```yaml
gateway:
  enabled: true
  replicas: 1
  baseDomain: agents.example.com
  publicURL: https://agents.example.com
  auth:
    mode: oauth2
    session:
      existingSecret: nvt-gateway-session
      cookieDomain: .agents.example.com
    oauth2:
      credentials:
        existingSecret: nvt-gateway-github
        clientIDKey: client-id
        clientSecretKey: client-secret
      issuer: https://github.com
      authorizationURL: https://github.com/login/oauth/authorize
      tokenURL: https://github.com/login/oauth/access_token
      scopes: []
      clientAuthMethod: client_secret_post
      identity:
        endpoint: https://api.github.com/user
        allowedHosts: [api.github.com]
        subjectPath: id
        displayNamePath: login
    authorization:
      default: deny
      rules:
        - id: agent-owner
          effect: allow
          owner: true
```

Register `https://agents.example.com/oauth2/callback` as the GitHub App
callback. No repository permission or scope is needed for the current-user
identity lookup. Owner matching uses only exact normalized issuer and immutable
subject from `AgentRun.spec.profileProvenance.principal`; login/display name and
requested-by annotations are ignored. See the [gateway
README](../../gateway/README.md) for the OAuth2 trust boundary and the exact
0.3 `github.*` to 0.4 `oauth2.*` migration.

OAuth2 does not provide OIDC's cryptographically verified issuer/ID-token
identity contract. Trusted operator configuration defines the issuer namespace
and identity endpoint; prefer OIDC when available.

Chart 0.4 removes the provider-specific 0.3 surface. Change
`gateway.auth.mode: github` to `oauth2`, move `gateway.auth.github.credentials`,
`callbackPath`, `issuer`, `authorizationURL`, and `tokenURL` beneath
`gateway.auth.oauth2`, and replace `github.userURL` with
`oauth2.identity.endpoint`. Add the endpoint's exact `allowedHosts` entry plus
`subjectPath` and optional `displayNamePath`. Existing Secret names and key
names may be retained. Old values fail validation; there is no automatic
fallback.

### Path routing

Subdomain routing remains the default. Path mode can route the complete gateway
at an HTTPS origin root or below one canonical base path:

```yaml
gateway:
  enabled: true
  routing:
    mode: path
  publicURL: https://staging.altinn.studio/agents
  # baseDomain is not used for request routing in path mode.
  baseDomain: ""
  auth:
    mode: oauth2
    session:
      existingSecret: nvt-gateway-session
      cookieDomain: "" # host-only; do not use .altinn.studio
      secure: true
    oauth2:
      credentials:
        existingSecret: nvt-gateway-github
      issuer: https://github.com
      authorizationURL: https://github.com/login/oauth/authorize
      tokenURL: https://github.com/login/oauth/access_token
      clientAuthMethod: client_secret_post
      identity:
        endpoint: https://api.github.com/user
        allowedHosts: [api.github.com]
        subjectPath: id
        displayNamePath: login
    authorization:
      default: deny
      rules:
        - id: agent-owner
          effect: allow
          owner: true
```

This renders the dashboard at `https://staging.altinn.studio/agents/`, sessions
at `https://staging.altinn.studio/agents/<access-key>/`, and the default OAuth
callback at `https://staging.altinn.studio/agents/oauth2/callback`.
`callbackPath` remains gateway-relative (`/oauth2/callback`); do not repeat the
base path there. A root `publicURL` remains supported. The Service stays
`ClusterIP`; DNS, certificates, and external routing are deployment-owned. The
load balancer must preserve the `/agents` prefix and WebSocket upgrades rather
than stripping or rewriting the prefix.

The access key is a routing identifier derived from the AgentRun name today,
not a secret or authorization mechanism. Path-routed agents share browser
storage and same-origin request reachability, so owner authorization does not
provide browser-origin isolation. Prefer subdomain mode for stronger per-agent
origin isolation. A dedicated origin is preferred, but a shared-origin base
path is supported when deployment constraints require it; owner authorization
does not isolate browser storage or same-origin requests from other
applications on that origin. Path mode requires an empty `cookieDomain`,
Secure gateway cookies, and gateway-relative OIDC/OAuth2 callbacks below the
reserved `/oauth2/` namespace.

## Validation

```sh
make operator-helm-test
```

The render suite checks TLS, Secrets, policy mounts, gateway authorization,
and egress configuration.
