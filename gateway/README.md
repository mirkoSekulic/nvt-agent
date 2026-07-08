# nvt-agent gateway

The gateway routes browser access to running agent sessions and can protect the
dashboard and session routes with OIDC. Authentication and authorization are
separate: with `auth.mode=oidc`, the default authorization decision is deny
unless an allow rule matches.

Do not use SSN, `pid`, or fødselsnummer claims for authorization. Prefer
organization, group, resource, or entitlement claims. The gateway rejects
sensitive claim paths and logs only the decision, rule id, agent access key, and
a short subject hash.

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
