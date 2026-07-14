# nvt Helm Chart

The chart installs the AgentRun and AgentSchedule CRDs, operator, broker, and
optional browser gateway.

```sh
helm upgrade --install nvt ./charts/nvt \
  --namespace nvt \
  --create-namespace
```

Provider credentials are supplied through existing Secrets, never literal
chart values.

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
  egressdImage: nvt-egressd:latest
  capturedImage: nvt-captured:latest
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
existing certificate can instead route sessions below opaque access-key paths:

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

## Validation

```sh
make operator-helm-test
```

The render suite checks TLS, Secrets, policy mounts, gateway authorization,
and egress configuration.
