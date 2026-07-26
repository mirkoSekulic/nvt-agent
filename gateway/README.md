# nvt-agent gateway

The gateway routes browser access to running agent sessions and can protect the
dashboard and session routes with OIDC or a generic OAuth2 identity adapter. Authentication
adapters produce the same normalized principal (`issuer`, immutable `subject`,
optional display name, sanitized claims). Authorization is separate and
defaults to deny whenever authentication is enabled.

`auth.mode=none` remains the default and preserves unrestricted access to all
routable AgentRuns, including legacy runs.

The gateway embeds its default public logo assets. Deployments may set
`NVT_GATEWAY_BRANDING_DIR` (or `--branding-dir`) to an absolute directory
containing the documented fixed branding files; assets are validated and
loaded once at startup. The Helm chart's `branding.existingConfigMap` mounts
this contract without allowing arbitrary gateway asset paths. See the chart
README for the complete key list and rollout behavior.

## Routing modes

`routing.mode=subdomain` is the default and preserves the original routing
contract: the dashboard is served at `https://<baseDomain>/` and an AgentRun at
`https://<access-key>.<baseDomain>/`. `baseDomain` remains required in this
mode.

`routing.mode=path` serves either a configured origin root or a native base
path below an existing origin:

- `https://agents.altinn.studio/` is the dashboard;
- `https://agents.altinn.studio/<access-key>/` is an AgentRun session;
- `https://staging.altinn.studio/agents/` is a prefixed dashboard;
- `https://staging.altinn.studio/agents/<access-key>/` is a prefixed session;
- `/healthz` remains the internal Service probe, while OAuth paths are reserved
  below the configured base path.

The access key is a routing identifier, not a secret or authorization factor;
the operator currently derives it from the AgentRun name. Authorization must
always come from the configured gateway policy.

Path mode requires `publicURL` to be HTTPS with no query, fragment, embedded
credentials, escaping, dot segments, or duplicate slashes. Configure non-root
base paths without a trailing slash; a root-origin trailing slash remains
accepted and is normalized for backward compatibility.
Configure either an origin such as `https://agents.example.com` or one
canonical base path such as `https://staging.altinn.studio/agents`. Requests
must carry that configured origin's Host header. Forwarded host/proto/prefix
headers do not influence routing, links, callbacks, or return URLs. OAuth
return URLs are restricted to the same origin and a valid dashboard or
AgentRun route below the base path.
OIDC and OAuth2 callback paths must be unambiguous children of `/oauth2/` in
path mode so they cannot collide with routing identifiers. Callback paths are
gateway-relative: with `publicURL: https://staging.altinn.studio/agents` and
`callbackPath: /oauth2/callback`, register
`https://staging.altinn.studio/agents/oauth2/callback` at the identity provider.
The external load balancer must forward the whole configured prefix unchanged
and preserve WebSocket upgrades; no prefix-stripping rewrite is required or
supported by the gateway contract.

The gateway removes exactly `<base-path>/<access-key>` before proxying while
preserving the remainder path, query string, and WebSocket upgrade. This behavior was
verified with the runtime image's code-server 4.129.0: code-server rejects an
unmodified arbitrary prefix, while its root HTML emits relative asset,
service-worker, callback, proxy, and WebSocket paths. Re-run the real binary
proof with:

```sh
gateway/scripts/code-server-path-smoke.sh
```

The proof loads the initial redirect and workbench HTML, fetches a referenced
versioned JavaScript asset, and completes a WebSocket upgrade through the
access-key route. The runtime currently resolves code-server at image build
time, so record the resolved version when repeating this proof.

The dashboard defaults to the `Active` view: authorized AgentRuns that have a
Ready, Running agent Pod with a Pod IP and are therefore routable. AgentRun
phase is display-only because it can lag the Pod state. The `All` view also
shows authorized Pending, Failed, and otherwise unroutable runs for diagnosis.
Authorization is applied before either view is rendered. These
views are selected only by `?view=active` and `?view=all`; they add no chart or
gateway configuration.

Authenticated sessions are stored only in gateway memory; the signed browser
cookie contains an opaque session identifier, not principal claims. After a
gateway restart, a browser presenting an otherwise valid orphaned cookie is
sent through the normal login flow, while API requests receive `401`; both
responses clear the orphaned cookie. Dashboard logout uses
`POST /oauth2/logout`, removes the server-side session, clears gateway cookies,
and redirects to a public signed-out confirmation page. Reauthentication
requires the explicit Sign in link on that page. Logout does not perform
provider- or IdP-specific sign-out.

Path-routed agents share one browser origin, including when the gateway is
mounted below a broader application origin. Consequently they also share the
origin's browser storage boundary and can make same-origin requests to other
paths on that origin. Owner authorization controls gateway requests but is not
browser-origin isolation. Subdomain mode provides stronger per-agent origin
isolation and remains preferred where the certificate and external router can
support it. A dedicated origin remains safer; mounting below a shared origin
is supported when deployment constraints require it, but owner authorization
does not provide browser-origin isolation from other applications on that
origin.

Do not use SSN, `pid`, or fødselsnummer claims for authorization. Prefer
organization, group, resource, or entitlement claims. The gateway rejects
sensitive claim paths and logs only the decision, rule id, agent access key, and
a short hash of issuer plus subject.

## Sign-in and sign-out

The gateway never starts an OAuth/OIDC flow on its own. When an unauthenticated
browser navigates to the dashboard or to any AgentRun session URL, the gateway
renders a provider-generic sign-in page with a `Sign in` control and returns
`200`. Authorization begins only when the user activates that control.

The sign-in control targets the mounted `/oauth2/login` endpoint and carries a
`return_url` that preserves the originally requested path and query, so a
successful login lands on the page the user asked for.

The control's own origin is never taken from the request. When `publicURL` is
configured it is used, which keeps central login on one stable origin in
subdomain mode and carries the mounted base path in path mode. Without it the
control is a mounted relative URL, so a forwarded host header cannot point the
control at another origin.

The candidate return URL is validated exactly like a return URL supplied to the
login endpoint: in path mode it must resolve to the configured public origin and
a routable path below the mounted base path, and in subdomain mode it must stay
on the base domain or one of its AgentRun subdomains. Anything else falls back
to the dashboard root, so no request can turn the sign-in control into an open
redirect.

Rendering the page resolves nothing about the requested AgentRun, so the same
page is returned whether or not a session with that access key exists. It also
issues no session or login-state cookie; only a completed login does that. A
`HEAD` request returns the same status and headers with no body.

Only an HTML document navigation receives the page. The gateway requires an
`Accept` header that explicitly lists `text/html` with a non-zero quality, which
is what browsers send for document navigation. Everything else stays
fail-closed with `401`, no HTML body, and no provider redirect:

- an absent `Accept` header, as sent by many command-line and library clients;
- a bare `*/*`, which expresses no preference for a document;
- API media types such as `application/json`;
- `text/html;q=0`, or any unparsable quality;
- protocol upgrades, including WebSocket, which are never navigation.

Protected non-`GET`/`HEAD` requests also remain fail-closed, and `auth.mode=none`
serves the dashboard without any sign-in page.

### Local sign-out and persistent identity-provider sessions

`POST /oauth2/logout` deletes the server-side session and clears every
gateway-owned cookie, then shows the signed-out page. **This is a local gateway
sign-out only.** The gateway does not attempt single-logout, back-channel
logout, or any other sign-out at the identity provider, and it cannot end an SSO
session held by the provider or by an upstream federated login.

That distinction is the reason sign-in is explicit. While the provider session
is still valid, the next authorization request can complete without prompting
for credentials. If the gateway redirected automatically, revisiting the
dashboard after signing out would silently re-authenticate and reappear as
though sign-out had failed. Requiring the `Sign in` control makes the local
session state visible: after signing out the visitor stays on the signed-out
page until they choose to sign in again.

To end the provider session as well, users sign out with the identity provider
directly. Operators who need enforced re-authentication should configure that at
the provider, for example with a shorter session lifetime or a prompt/`acr`
requirement through `auth.oidc.extraAuthParams` or `auth.oidc.acrValues`.

## AgentRun owner authorization

An owner rule compares the authenticated principal to immutable profiled
admission provenance using exact issuer plus subject:

```yaml
authorization:
  default: deny
  rules:
    - id: agent-owner
      effect: allow
      owner: true
```

Display names, GitHub logins, and `nvt.dev/requested-by` annotations never
participate. Legacy or malformed AgentRuns without
`spec.profileProvenance.principal` do not match an owner rule. Dashboard results
are filtered with the same policy; inaccessible run metadata is not rendered.
Each rule must contain exactly one of `authenticated`, `owner`,
`claimPath`+`values`, or `where`.

## Login admission and OAuth claim enrichment

Authentication, login admission, and AgentRun authorization are independent
gates:

1. the configured adapter authenticates a principal;
2. optional `auth.admission` decides whether that principal may receive a
   gateway session;
3. `auth.authorization` still decides which AgentRuns that session may see or
   open.

When admission is absent, successful authentication creates a session exactly
as before. When it is configured, its default is deny and a principal must
match one allow rule before any session is stored or session cookie is issued.
Admission supports `authenticated`, `claimPath`+`values`, and `where`; `owner`
is invalid because no AgentRun exists at login time.

Resource authorization rules retain allow/OR semantics. Do not add a broad
organization claim rule beside `owner: true` to simulate login admission: that
would authorize every matching organization member to every AgentRun. Put the
organization requirement in `admission` and keep `owner` in `authorization`.

OAuth adapters can enrich their normalized principal through declarative claim
sources before admission. Every source is a bounded HTTPS GET carrying the
temporary OAuth bearer token. Its host must be explicitly allowed, redirects
are rejected, and only the selected non-sensitive JSON value is retained under
a new safe top-level claim. Source failures, missing/ambiguous values, output
collisions, malformed or oversized responses, and timeouts fail login closed.
Access tokens and raw responses are never stored in sessions or cookies.

This provider-neutral configuration expresses GitHub organization membership
entirely as operator configuration:

```yaml
gateway:
  auth:
    mode: oauth2
    session:
      # Membership is checked at login, so use a bounded revocation window.
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
      allowedHosts:
        - api.github.com
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

For this GitHub example, configure the GitHub App with organization
**Members: read** permission and have an Altinn organization owner install and
approve the app for that organization. Each user must also authorize the app.
GitHub then returns `state: active` only for an active member; pending membership
does not match, while an unaffiliated user or blocked/unapproved app produces a
failed source request and login is denied. No repository permission is needed.
Other providers have their own permission/approval requirements. Claim sources
cannot add arbitrary headers, disable TLS verification, follow redirects, or
derive their endpoint from a browser request.

Enriched admission claims are a login-time snapshot. They are stored in the
server-side session and are not re-fetched on each dashboard or AgentRun
request; the temporary OAuth token is discarded. Removing a user from an
organization therefore blocks new logins immediately, while an existing
session remains valid until `auth.session.maxAgeSeconds` expires or the session
is otherwise invalidated (including a gateway restart). For security-sensitive
production deployments, configure a shorter explicit lifetime such as the
one-hour (`3600`) value above instead of relying on the 24-hour default.

## Generic OAuth2 login

Use `auth.mode=oauth2` when a provider offers authorization-code OAuth2 but not
OIDC. The trusted gateway configuration defines the issuer namespace and the
identity endpoint used to obtain one immutable subject; unlike OIDC, OAuth2
alone does not cryptographically establish an issuer/ID-token identity
contract. Prefer OIDC when the provider supports it.

For GitHub, create a dedicated GitHub App for human login. Configure its
callback URL as `https://<gateway-host>/oauth2/callback`; it needs no repository
permissions, repository scopes, or webhook subscriptions for profile identity
lookup. A membership claim source does require the organization permission and
installation/approval described above. Store both credentials in a Kubernetes
Secret:

```sh
kubectl -n nvt create secret generic nvt-gateway-github \
  --from-literal=client-id='<github-app-client-id>' \
  --from-literal=client-secret='<github-app-client-secret>'
```

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

The generic flow uses state and PKCE, supports `client_secret_post` and
`client_secret_basic`, performs one bounded redirect-free HTTPS identity GET,
and retains only the configured issuer, canonical string/integer subject, and
optional display name. Access and refresh tokens and the raw identity response
are discarded before session creation. The identity endpoint host must be
explicitly allowlisted. Principals from different issuers are never guessed or
linked; any account correlation requires an external explicit mapping.

### Migration from chart 0.3

Chart 0.4 removes `auth.mode=github` and `auth.github.*`. Migrate saved values
to `auth.mode=oauth2` and the explicit `auth.oauth2.*` fields shown above. The
old GitHub defaults are intentionally configuration now: issuer,
authorization/token URLs, identity endpoint, host allowlist, and JSON paths
must all be declared. Rename the credentials block but the referenced Secret
and its `client-id`/`client-secret` keys may remain unchanged. There is no
automatic compatibility fallback.

| Chart 0.3 | Chart 0.4 |
| --- | --- |
| `auth.mode: github` | `auth.mode: oauth2` |
| `auth.github.credentials` | `auth.oauth2.credentials` |
| `auth.github.callbackPath` | `auth.oauth2.callbackPath` |
| `auth.github.issuer` | `auth.oauth2.issuer` |
| `auth.github.authorizationURL` | `auth.oauth2.authorizationURL` |
| `auth.github.tokenURL` | `auth.oauth2.tokenURL` |
| `auth.github.userURL` | `auth.oauth2.identity.endpoint` |

Also set `auth.oauth2.clientAuthMethod`,
`auth.oauth2.identity.allowedHosts`, `subjectPath`, and optional
`displayNamePath`; these replace the removed adapter's implicit behavior.

In path mode, `session.cookieDomain` must be empty so the gateway cookie is
host-only, and its Path is scoped to the configured gateway base path. Secure
session cookies are mandatory; do not broaden the cookie to `.altinn.studio`.
Gateway cookies are removed before proxying to an AgentRun and agent responses
cannot set or overwrite them. Remaining agent cookies are forced to the
selected base-path/access-key path.

## Ansattporten example

This example asks Ansattporten for an Altinn resource authorization and allows
access only when one `authorized_parties[]` entry contains both the expected
organization number and resource.

```yaml
gateway:
  enabled: true
  replicas: 1
  baseDomain: agents.altinn.studio
  publicURL: https://agents.altinn.studio

  auth:
    mode: oidc

    session:
      existingSecret: nvt-gateway-session
      secretKey: session-secret
      cookieName: nvt_agent_gateway
      cookieDomain: .agents.altinn.studio
      secure: true
      maxAgeSeconds: 86400

    oidc:
      issuerURL: https://ansattporten.no
      clientID: nvt-agent-gateway
      clientSecret:
        existingSecret: nvt-gateway-oidc
        secretKey: client-secret
      scopes:
        - openid
        - profile
      callbackPath: /oauth2/callback

      # Sent as the authorization_details query parameter on /authorize.
      authorizationDetails: |
        [
          {
            "type": "ansattporten:altinn:resource",
            "resource": "urn:altinn:resource:digdir-selvbetjening-klienter",
            "organizationform": "enterprise",
            "representation_is_required": false
          }
        ]

    authorization:
      default: deny

      # Use access_token if Ansattporten returns authorization_details in a JWT
      # access token. Use userinfo if your IdP exposes it from userinfo instead.
      claimSource: access_token

      rules:
        - id: allowed-altinn-org
          effect: allow
          where:
            array: authorization_details[].authorized_parties[]
            all:
              - claimPath: orgno.ID
                values:
                  - "0192:991825827"
              - claimPath: resource
                values:
                  - digdir-selvbetjening-klienter
```

Create the referenced secrets before installing the chart:

```bash
kubectl -n nvt create secret generic nvt-gateway-session \
  --from-literal=session-secret="$(openssl rand -base64 48)"

kubectl -n nvt create secret generic nvt-gateway-oidc \
  --from-literal=client-secret="<ansattporten-client-secret>"
```

Register this redirect URI in the OIDC client:

```text
https://agents.altinn.studio/oauth2/callback
```

For `where.array`, all conditions are evaluated against the same selected array
element. This prevents combining an organization match from one
`authorized_parties[]` entry with a resource match from another entry.
