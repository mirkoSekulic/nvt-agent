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

Optionally seed an empty state directory once from an existing Secret:

```yaml
broker:
  persistence:
    enabled: true
    seedSecretName: codex-auth
    seedTargetDir: codex
```

Seeding never overwrites existing broker state. This protects refreshed and
rotated credentials from stale Secret contents.

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

The operator creates a separate paired egressd Pod, per-run NetworkPolicies, a
credential-less captured sidecar, and a one-shot NET_ADMIN routing init
container. Normal outbound TCP, including DinD traffic, is redirected through
captured and egressd. The Agent Pod has no direct internet egress rule.

`networkPolicyCapable=true` is an operator assertion, not CNI installation.
Set it only when the cluster CNI enforces NetworkPolicy. The enforced kind
smoke uses Calico because default kind networking does not prove the boundary.

Forward-proxy transport remains available for clients that honor
`HTTP(S)_PROXY`. `spec.egressForwardProxy` is a compatibility input; new
resources use `spec.egressTransport: forward-proxy`.

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

### GitHub owner login

Direct GitHub OAuth2 login uses a dedicated GitHub App and the same generic
authorization engine. Put its client ID and secret in one existing Secret; the
chart never renders credential values into a ConfigMap or Pod environment
literal:

```yaml
gateway:
  enabled: true
  replicas: 1
  baseDomain: agents.example.com
  publicURL: https://agents.example.com
  auth:
    mode: github
    session:
      existingSecret: nvt-gateway-session
      cookieDomain: .agents.example.com
    github:
      credentials:
        existingSecret: nvt-gateway-github
        clientIDKey: client-id
        clientSecretKey: client-secret
    authorization:
      default: deny
      rules:
        - id: agent-owner
          effect: allow
          owner: true
```

Register `https://agents.example.com/oauth2/github/callback` as the GitHub App
callback. No repository permission or scope is needed for the current-user
identity lookup. Owner matching uses only exact normalized issuer and immutable
subject from `AgentRun.spec.profileProvenance.principal`; login/display name and
requested-by annotations are ignored. See the [gateway
README](../../gateway/README.md) for GitHub Enterprise endpoint overrides and
trust details.

### Path routing

Subdomain routing remains the default. A dedicated origin covered by an
existing certificate can instead route sessions below access-key routing
identifier paths:

```yaml
gateway:
  enabled: true
  routing:
    mode: path
  publicURL: https://agents.altinn.studio
  # baseDomain is not used for request routing in path mode.
  baseDomain: ""
  auth:
    mode: github
    session:
      existingSecret: nvt-gateway-session
      cookieDomain: "" # host-only; do not use .altinn.studio
      secure: true
    github:
      credentials:
        existingSecret: nvt-gateway-github
    authorization:
      default: deny
      rules:
        - id: agent-owner
          effect: allow
          owner: true
```

This renders the dashboard at `https://agents.altinn.studio/` and sessions at
`https://agents.altinn.studio/<access-key>/`. `publicURL` must be an HTTPS root
origin. The Service remains `ClusterIP`; DNS, certificates, and external load
balancer routing are deployment-owned and are not created by this chart.

The access key is a routing identifier derived from the AgentRun name today,
not a secret or authorization mechanism. Path-routed agents share browser
storage and same-origin request reachability, so owner authorization does not
provide browser-origin isolation. Prefer subdomain mode for stronger per-agent
origin isolation. If path mode is required, dedicate a complete origin such as
`agents.altinn.studio`; never configure a path such as
`dev.altinn.studio/agents`. Path mode requires an empty `cookieDomain`, Secure
gateway cookies, and OIDC/GitHub callbacks below the reserved `/oauth2/`
namespace.

## Validation

```sh
make operator-helm-test
```

The render suite checks TLS, Secrets, policy mounts, gateway authorization,
and egress configuration.
