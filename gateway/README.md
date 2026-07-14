# nvt-agent gateway

The gateway routes browser access to running agent sessions and can protect the
dashboard and session routes with OIDC or direct GitHub OAuth2. Authentication
adapters produce the same normalized principal (`issuer`, immutable `subject`,
optional display name, sanitized claims). Authorization is separate and
defaults to deny whenever authentication is enabled.

`auth.mode=none` remains the default and preserves unrestricted access to all
routable AgentRuns, including legacy runs.

## Routing modes

`routing.mode=subdomain` is the default and preserves the original routing
contract: the dashboard is served at `https://<baseDomain>/` and an AgentRun at
`https://<access-key>.<baseDomain>/`. `baseDomain` remains required in this
mode.

`routing.mode=path` serves a dedicated configured origin instead:

- `https://agents.altinn.studio/` is the dashboard;
- `https://agents.altinn.studio/<access-key>/` is an AgentRun session;
- `/healthz` and all `/oauth2/*` paths are reserved for the gateway.

Path mode requires `publicURL` to be an HTTPS origin with no non-root path,
query, fragment, or embedded credentials. Requests must carry that configured
origin's Host header. Forwarded host/proto headers do not influence routing,
links, callbacks, or return URLs. OAuth return URLs are restricted to the same
origin and a valid dashboard or AgentRun route.

The gateway removes exactly `/<access-key>` before proxying while preserving
the remainder path, query string, and WebSocket upgrade. This behavior was
verified with the runtime image's code-server 4.128.0: code-server rejects an
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

Do not use SSN, `pid`, or fødselsnummer claims for authorization. Prefer
organization, group, resource, or entitlement claims. The gateway rejects
sensitive claim paths and logs only the decision, rule id, agent access key, and
a short hash of issuer plus subject.

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

## GitHub login

Create a dedicated GitHub App for human gateway login. Configure its callback
URL as `https://<gateway-host>/oauth2/github/callback`; it needs no repository
permissions, repository scopes, webhook subscriptions, or installation access
for this profile-only identity lookup. Store both OAuth credentials in a
Kubernetes Secret:

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
    mode: github
    session:
      existingSecret: nvt-gateway-session
      cookieDomain: .agents.example.com
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

The flow uses state and PKCE, calls GitHub's current-user endpoint, and retains
only issuer `https://github.com`, decimal numeric user ID as subject, and login
as display data. The access token is discarded after lookup. GitHub Enterprise
Server deployments can configure the issuer, authorization, token, and user
URLs explicitly. GitHub and OIDC principals are never guessed or linked across
issuers; any future account correlation requires an external explicit mapping.

In path mode, leave `session.cookieDomain` empty for a host-only cookie on the
dedicated gateway origin. Secure session cookies are mandatory in path mode;
do not broaden the cookie to `.altinn.studio`.

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
