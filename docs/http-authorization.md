# Broker HTTP endpoint allowlisting

The builtin `token` provider optionally authorizes actual HTTP requests before
releasing injection headers to trusted egress. This is endpoint authorization,
**not** read-only/observe policy, body inspection, or a token-scoping mechanism.
Credentials remain broker/egress-side. Agent clients use existing non-secret
provider selectors and public trust settings; no new runtime/agentd API is needed.
An HTTP-policy token provider also refuses raw token export, even if a mistakenly
configured file-bundle grant would otherwise permit it.

## Portable contract

Use existing provider `allow.authorization` and agent grant `authorization`:

```yaml
authorization:
  defaultAction: deny
  rules:
    - {operation: http.POST, resource: http/api.example.test/graphql}
    - {operation: http.POST, resource: http/api.example.test/designer/api/*/*/deployments/undeploy}
```

- Both policies must permit the request. If either supplies HTTP policy, a missing
  policy on the other side denies everything. `defaultAction` defaults to `deny`;
  `allow` and presets are rejected. Empty policies deny everything. Rules are ORed
  within each policy; policies intersect with each other and the injection-host ceiling.
- Operations are exactly `http.GET`, `http.HEAD`, `http.POST`, `http.PUT`,
  `http.PATCH`, `http.DELETE`, or `http.OPTIONS`. No method wildcards, CONNECT,
  TRACE, or case folding. Broker injection rejects non-uppercase HTTP methods
  instead of authorizing a spelling different from the actual upstream request.
- Resources are `http/<exact-lowercase-host>/<path>`. Hosts use DNS-label syntax;
  wildcard hosts, port suffixes, trailing DNS dots, and upstream URLs are invalid.
  Existing HTTPS routes and exact host ceilings remain mandatory.
- A whole-segment `*` matches exactly one nonempty segment, never a slash, zero
  segments, or a recursive tree. No `**`, substring globs, regex, or implicit
  prefix matching. Different path lengths require separate rules.
- Paths contain case-sensitive ASCII unreserved segments (`A-Z a-z 0-9 . _ ~ -`)
  separated by single `/`. Root `/` is allowed. Empty/dot segments, non-root
  trailing slashes, backslashes, semicolons, non-ASCII, fragments, and **all percent
  encoding** are denied, not decoded/normalized into an allowed path.
- **All query strings, even a bare `?`, are denied in HTTP-policy mode.** This
  initial contract does not authorize query parameter semantics. HTTP/WebSocket
  upgrades are also denied. Bodies and ordinary end-to-end headers are not inspected.
- Bounds: 128 unique rules per policy, 253-character hosts, 2048-character paths,
  and 64 path segments. Unknown fields/malformed rules fail closed. Invalid provider
  policy prevents startup; invalid grant HTTP semantics deny materialization.
  Token-provider `allow` accepts only `repositories` and `authorization`; misspelled
  or previously ignored fields such as `permissions` are rejected, not treated as
  a credential restriction.

**GraphQL security boundary:** permitting `POST /graphql` permits every request
body at that endpoint. With a broad PAT, all token-authorized GraphQL capabilities
may be accessible, including mutations and other repositories/resources. Neither
`allow.repositories` nor a boolean downscopes an arbitrary PAT's GraphQL body.
Use upstream repository-scoped credentials or a separate service-aware authorizer
for that stronger guarantee. The same warning applies to resource IDs in JSON
bodies and server-side routing headers.

## Local YAML

```yaml
brokerProviders:
  api:
    plugin: token
    config: {injection-hosts: [api.example.test], injection-git: false}
    secrets: {token-file: api-token}
    mediation: {hosts: [api.example.test], materialization: header-inject, git: false}
    allow:
      authorization:
        defaultAction: deny
        rules:
          - {operation: http.POST, resource: http/api.example.test/graphql}
profiles:
  api-client:
    # Keep existing runtime and other settings.
    httpCredentials:
      - provider: api
        authorization:
          defaultAction: deny
          rules:
            - {operation: http.POST, resource: http/api.example.test/graphql}
```

The [complete example](../examples/http-authorization/manifest.example.yaml)
includes the broker-only secret binding and a narrower grant. No repository,
checkout, workflow, or generated-config edit is necessary. Local validation requires
both policies; compilation preserves them in the existing native contracts. Profiles
without the binding receive no grant. Names-only `httpCredentials: [api]` retains
legacy host-wide behavior and canonical output for providers without HTTP policy;
it cannot opt into a provider with an explicit HTTP ceiling.

## Git and API access using one secret

Keep repository-scoped Git providers/grants unchanged. Add a separate non-Git
provider for APIs, referencing the **same** broker-held secret and declaring both
HTTP policies. Distinct instances also allow different Basic/Bearer wire auth.
Keep the Git instance in `injection-git: true` mode with header-inject grants.
Do not also grant an unrestricted host-wide instance of the same credential:
an agent can select any granted capability, so that would bypass the API binding's
restrictions. In particular, legacy host-scoped manual-Git bindings with
`injection-git: false` also authorize arbitrary API paths on their allowed host.
Use names such as `forge-git` and `forge-api`, with explicit non-secret proxy
selection, especially when capabilities share a host:

```sh
curl --proxy "$NVT_EGRESS_FORWARD_PROXY_URL_FORGE_API" \
  --request POST --header 'Content-Type: application/json' \
  --data '{"query":"..."}' https://api.example.test/graphql
```

Use generated public trust settings. See [HTTP credentials](http-credentials.md)
for Git proxy selection. Clients must honor proxy selection; a CLI requiring a
token merely to start still needs its existing non-secret placeholder/bootstrap
mechanism. This feature adds no CLI authentication adapter.

There is **no** fallback from failed Git/repository checks into API authorization.
A direct broker Git-mode provider may additionally have HTTP policy, but both it
and all repository checks apply; it cannot thereby enable `/graphql`. Local HTTP
policy authoring uses separate non-Git instances. Legacy Git checks remain intact;
their denials now yield 403 instead of a misleading egress 502.

## Standalone, Kubernetes, and Helm

- [broker.yaml](../examples/http-authorization/broker.yaml): provider ceiling and
  broker-private token-file reference.
- [agents.yaml](../examples/http-authorization/agents.yaml): header-inject grant
  and paired egress identity. Hashes are illustrative; privately provision actual
  identities, never giving broker credentials to enforced workloads.
- [AgentRun](../examples/http-authorization/agentrun.yaml): the same concrete
  `spec.broker.grants[].authorization`. Use a coordinated pinned runtime image
  instead of the example tag when deploying.
- [Helm overlay](../examples/http-authorization/helm-values.yaml): ceiling under
  `broker.config.providers`, grant under `agentSchedule.profiles[].broker.grants`.
  Provision the Secret referenced by `broker.envSecretName` separately; only the
  broker receives it. Existing TLS/network-policy prerequisites still apply.

No CRD or provider-protocol extension is required. The operator snapshots profile
policy into an AgentRun and projects it to the broker. Every deployment path uses
the same provider matcher, not a local-only policy engine.

## Denials and caching

Broker HTTP 403 becomes caller 403 (`egress-injection-forbidden`) before upstream
forwarding. Egress never reflects broker response bodies or credential diagnostics.
Broker/upstream failures remain 502; upstream HTTP statuses otherwise pass through.

The existing cache keys method, escaped request URI (including query), and upgrade
intent. Instances belong to one route/provider/host and paired egress identity,
not shared across agents or capabilities. Denied variants cannot reuse allowed
material. TTL remains at most 60 seconds, further limited by credential expiry.
Tightening policy/revoking a grant may leave an already-authorized exact request
usable until its cache entry expires, plus in-flight work. Failed refreshes do not
reuse expired material; this is **not instantaneous revocation**. Apply changes
through the trusted configuration lifecycle, not edits to generated files.

Tests use fake tokens and loopback services: actual broker + egress CONNECT/TLS,
Helm rendering, and raw AgentRun/profiled admission -> actual broker integration.
They do not claim a live Kubernetes or cloud smoke test.
