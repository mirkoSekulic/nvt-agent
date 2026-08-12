# Generic OAuth2/OIDC login eligibility

The gateway and credential portal use the same provider-neutral eligibility
contract. The gateway exposes it as `gateway.auth.admission`; the portal exposes
it as `credentialPortal.auth.eligibility`. Both are default-deny allow-rule
policies evaluated only after OAuth2/OIDC authentication and optional bounded
claim enrichment.

Principal identity is always the exact verified issuer plus immutable subject.
Eligibility claims and display names never replace either identity field.

For OIDC portal authentication, `auth.oidc.eligibilityClaimSource` explicitly
selects `id_token` (the compatibility default), `access_token`, or `userinfo`.
An access-token source must be a JWT whose signature, configured issuer, and
audience are verified through OIDC discovery before any claims are evaluated;
`accessTokenAudience` defaults to the portal client ID. UserInfo must return the
same immutable subject as the verified ID token. Plain OAuth2 identity behavior
is unchanged.

## Policy contract

Rules are ORed. A scalar predicate matches any selected scalar value. A
`where` predicate selects JSON objects from an array path and requires every
condition in `all` to match the same object:

```yaml
default: deny
rules:
  - id: approved-party
    effect: allow
    where:
      array: memberships[]
      all:
        - claimPath: organization.ID
          values: ["0192:123456789"]
        - claimPath: resource
          values: [approved-resource]
```

Dotted paths select object members and `[]` explicitly flattens an array. Path,
rule, condition, value, and selection cardinality are bounded. Missing members,
wrong shapes, excessive arrays, split matches across different objects, and
unsupported scalar values do not match.

`authenticated: true` remains available for deployments that only need an
explicit authenticated-principal rule. `owner` is not an eligibility predicate;
gateway AgentRun owner authorization and portal slot ownership remain separate
exact issuer/subject checks.

## Bounded claim enrichment

Each configured source is an HTTPS GET with the transient OAuth access token.
The endpoint host must appear in `allowedHosts`. Redirects, non-success status,
timeouts, malformed or duplicate-key JSON, excessive responses, output-name
collisions, missing or ambiguous selections, and reflected access-token values
fail login closed. Tokens and raw responses are never logged or stored in a
session.

The special `valuePath: $` selects the complete response, including a bounded
top-level JSON array. Before retention, the complete selected structure is
walked recursively and rejected if any field name can carry a personal
identifier, token, secret, password, or credential. Legitimate declarative
`authorization_details` and `authorized_parties` structures remain available.
Other paths select exactly one non-sensitive value. For example:

```yaml
claimEnrichment:
  allowedHosts: [claims.identity.example]
  timeoutSeconds: 5
  limits:
    maxResponseBytes: 65536
    maxDepth: 8
    maxArrayItems: 64
    maxObjectProperties: 64
    maxTotalNodes: 1024
    maxStringBytes: 1024
  sources:
    - endpoint: https://claims.identity.example/v1/memberships
      outputClaim: memberships
      valuePath: $
```

A source may opt into bounded RFC 8288 Link pagination:

```yaml
    - endpoint: https://claims.identity.example/v1/teams
      outputClaim: teams
      valuePath: $
      pagination:
        mode: link
        maxPages: 5
```

Pagination is disabled when the object is absent. Paginated pages must each be
a top-level JSON array and `valuePath` must be `$`; arrays are combined before
policy evaluation. Only one unambiguous `rel=next` is accepted. Before the
bearer is sent, the next URL must retain HTTPS, exact original origin/effective
port, and exact original path, with no userinfo or fragment; only its query may
change. Redirects remain rejected. One timeout covers the complete source
operation. Page count, response bytes, combined array items, and decoded nodes
are cumulative; the existing depth, object-property, and string bounds apply to
every page. Loops,
malformed links, non-array pages, partial results, and all limit overflow fail
closed. Each response body is closed before the next request; raw pages and the
OAuth bearer are never logged or retained.

For example, a GitHub OAuth App can use the same contract in either gateway
admission or credential-portal eligibility:

```yaml
oauth2:
  scopes: [read:org]
claimEnrichment:
  allowedHosts: [api.github.com]
  limits:
    maxArrayItems: 256
  sources:
    - endpoint: https://api.github.com/user/teams
      outputClaim: teams
      valuePath: $
      pagination: {mode: link, maxPages: 10}
eligibility: # use admission at the gateway
  default: deny
  rules:
    - id: allowed-team
      effect: allow
      where:
        array: teams[]
        all:
          - claimPath: organization.login
            values: [Altinn]
          - claimPath: slug
            values: [allowed-team]
```

The application contains no provider branch for this shape. GitHub OAuth App
organization approval and SSO authorization may still be required by the
organization's policy. At the gateway, keep AgentRun authorization separate
with an `owner: true` rule; team eligibility must not broaden resource access.

The limits shown are the defaults. `pagination.maxPages` is explicit and may be
2 through 10. Administrators may configure smaller values
or bounded larger values up to the compiled safety ceilings. Hosts, endpoints,
paths, expected values, predicates, timeout, and response limits are deployment
configuration; shared code contains no identity-provider-specific decisions.

## Compatibility and consumer boundaries

When gateway admission is absent, authenticated gateway login behaves as it did
before. Existing scalar admission and static authorization rules retain their
meaning. In particular, bounded printable rule IDs and JSON claim keys are not
restricted to programming-language identifier syntax, duplicate IDs retain
ordered first-match behavior, and duplicate expected values remain valid. The
gateway parser also accepts the former authorization-shaped `owner: false`
field as a no-op; `owner: true` is still invalid for login admission. This
compatibility shim is gateway-only: portal eligibility rejects either value and
the shared evaluator has no owner predicate. The new resource ceilings (64
rules, 16 conditions and path segments, 64 values,
and the documented byte/selection limits) fail startup closed; deployments
exceeding them must reduce the policy before upgrading. When portal eligibility
is absent, portal login still requires an exact configured static slot owner.
When it is present, an eligible principal
may receive a portal session without a per-principal slot, but can still view or
address only slots whose configured owner exactly matches that principal.

This contract does not create broker accounts, enrollment slots, provider
instances, execution profiles, or AgentRuns. Dynamic credential ownership and
operator resolution are separate follow-on features.
