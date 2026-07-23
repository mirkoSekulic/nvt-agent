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
of, upgrading to chart `0.8.5`; otherwise the API server will prune or reject
the new scheduling fields.

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
helm show crds oci://ghcr.io/mirkosekulic/helm/nvt --version 0.8.5 \
  | kubectl apply --server-side -f -

helm upgrade --install nvt oci://ghcr.io/mirkosekulic/helm/nvt \
  --version 0.8.5 --namespace nvt --create-namespace
```

Do not apply CRDs from a different chart version than the release being
installed.

## Coordinated images

The published chart's `appVersion` is the immutable image tag for its tested
platform bundle. Chart `0.2.0` published from commit `943d5ba...`, for example,
uses `0.2.0-943d5ba` for runtime, broker, egressd, captured, operator, gateway,
and producer images. Empty component tags default to `Chart.AppVersion`;
repository, tag, and pull policy remain independently overridable.

All default repositories are under `ghcr.io/mirkosekulic`. The chart is
published only after all seven manifests exist and can be fetched anonymously
with an isolated credential-free Docker configuration. The release reuses an
existing image tag only when its OCI source, full revision, and version labels
match. GHCR package writers are trusted: matching labels establish coordinated
release metadata, not byte-for-byte content identity against copied labels.

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
  persistence:
    enabled: true
    size: 1Gi
```

Create `nvt-github-app` out of band with the configured private-key key; the
chart never accepts or renders private-key material. In profiled mode, list the
rendered producer ServiceAccount username in `agentSchedule.allowedProducers`.
The chart projects only a rotating `nvt-operator` audience token. The default
producer AgentRun runtime image is the coordinated `runtime.image`; set
`producer.agentRun.runtimeImage` only for an intentional override.

Legacy/direct producer payloads can opt into AgentRun-scoped persistence:

```yaml
producer:
  agentRun:
    workspaceMode: Persistent
    workspaceSize: 20Gi
    workspaceStorageClassName: managed-csi # optional
```

Ephemeral remains the default. Persistent mode requires a positive Kubernetes
quantity and cannot be combined with the legacy producer's file-bundle broker
grants. Profiled admission does not send these fields; configure persistence in
the operator-owned `AgentSchedule.spec.template.workspace` instead.

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

`agentSchedule.template`, `profiles`, `profileSelection`, and
`allowedProducers` configure operator-owned execution profiles. Empty values
preserve legacy full-`AgentRun` admission. Profiled admission requires a
projected ServiceAccount token with audience `nvt-operator`; see the
[AgentSchedule contract](../../operator/docs/agentschedule.md).

Scheduling fields in the shared template are passed to the generated agent Pod:

```yaml
agentSchedule:
  template:
    runtimeClassName: kata-vm-isolation
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

When `agentSchedule.template` is non-empty, an absent or empty `image` defaults
to the coordinated runtime image (`runtime.image` with the published chart's
immutable `appVersion`). Set `agentSchedule.template.image` explicitly to
preserve an intentional override. An empty template remains omitted for legacy
schedule admission.

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
```

The operator creates a paired egress endpoint, per-run NetworkPolicies, a
credential-less capture relay, and one-shot NET_ADMIN routing initialization.
Normal outbound TCP, including DinD traffic, is redirected through captured and
egressd. The untrusted workload has no direct internet egress rule. Deployment
placement is an operator implementation detail, not an AgentRun contract.

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
