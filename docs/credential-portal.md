# Self-service credential-file enrollment

`nvt-credential-portal` is an optional, standalone enrollment service. It is
disabled by default. Its complete data path is:

```text
browser -> credential portal -> pre-created Kubernetes seed Secret
        -> existing broker seed supervisor -> broker PVC canonical file
        -> existing broker provider refresh and injection
```

The portal is not a second credential runtime. It never reads the current
Secret, the broker PVC, provider health, AgentRuns, or Key Vault. It neither
refreshes nor injects credentials. Removing the Deployment later does not
remove the pre-created Secret or the broker PVC and does not interrupt running
agents or broker refresh.

## Security boundary

Authentication is generic OIDC or OAuth2. The portal uses its own encrypted,
HTTP-only, Secure session cookie, short-lived signed login state, PKCE, and a
separate callback path. Admission is default-deny: a successfully authenticated
issuer/subject pair receives a session only when it owns at least one configured
slot. Display names are never authorization input.

Each slot binds a stable name and exact owner `(issuer, subject)` to one explicit
adapter, broker provider name, pre-created Secret, and data key. The request
cannot supply or override the adapter, provider, Secret, or key. The Service
Account has only `patch` on the configured Secret name; it has no `get`, `list`,
`create`, or `delete`. The application sends one JSON Patch `add` operation
(which creates or replaces that member) for the configured `/data` key and
never observes any other key. The pre-created Secret must contain a `data: {}`
object, but its configured slot keys may initially be absent.
The portal requests a metadata-only PATCH response and streams/discards the
response rather than decoding a Secret object.

Uploads are raw `application/json`, bounded to at most 1 MiB, protected by
same-origin CSRF and explicit replacement confirmation, and parsed entirely in
memory. Multipart input, duplicate JSON keys, cross-provider shapes, and
documents below the current broker provider's minimum usable shape are rejected
before a Secret patch. Accepted documents are otherwise preserved. Audit output
contains only timestamp, issuer, subject, slot, adapter, broker provider,
outcome, and a fixed reason code. Credential content, token hashes,
authorization codes, and raw provider errors are never returned or logged.

The configured seed Secret still contains credentials. Back it up and protect
it accordingly. Session and OAuth client secrets must come from existing
Kubernetes Secrets. Slot configuration, issuer/subject identifiers, and public
OAuth endpoints are deployment configuration; they are not credentials. Do not
place real long-lived credentials in Helm values, ConfigMaps, annotations,
events, or command arguments.

Liveness/readiness probes report only that the portal process was configured
and started. They do not claim that a credential exists, is usable, was imported
by the broker, or is healthy upstream.

## Enrollment adapters

The adapter is selected by the administrator, never inferred from the file.

- `codex-oauth-file` accepts a top-level object with non-empty
  `tokens.access_token` and `tokens.refresh_token`; the access token must be a
  JWT with an integer `exp`, as required by the existing broker provider.
- `claude-oauth-file` accepts a top-level object with non-empty
  `claudeAiOauth.accessToken` and `claudeAiOauth.refreshToken`, matching the
  existing broker provider's minimum source shape.

Direct browser Codex or Claude OAuth is not included. Future official OAuth
enrollment can be added behind another explicit adapter without changing the
portal/core/broker boundary.

## Enabling the chart

First create the seed, session, and OAuth client Secrets out of band. The chart
does not create credential-bearing Secrets. Then configure the persistent
broker seed and portal. A minimal OIDC example is in
`tests/operator/helm/credential-portal-values.yaml`; production deployments
must replace its illustrative issuer, subjects, and Secret names.

Expose the portal Service through an HTTPS ingress at exactly
`credentialPortal.publicURL`. NetworkPolicy permits the portal's HTTP listener
and outbound DNS/HTTPS for Kubernetes and the identity provider; cluster policy
may narrow peers while preserving those dependencies.

An optional gateway dashboard link is independent:

```yaml
gateway:
  credentialPortal:
    url: /agents/credentials
    label: Manage credentials
```

The gateway does not proxy portal APIs, share its session, inspect credential
state, or require the portal to be available. An empty URL preserves the prior
dashboard.

## Migrating an existing seed without exposing it

Preserve the broker PVC throughout. To copy an existing seed Secret to a new,
portal-owned Secret without printing decoded values, pipe the Kubernetes JSON
object directly into a server-side apply after replacing only metadata:

```sh
kubectl get secret old-broker-seed -n nvt -o json \
  | jq '.metadata={"name":"nvt-portal-seed","namespace":"nvt"} | del(.immutable)' \
  | kubectl apply --server-side --field-manager=nvt-credential-portal-migration -f -
kubectl get secret nvt-portal-seed -n nvt -o name
```

Do not use `-o yaml` interactively, decode the data, or enable shell tracing.
Only after the second command verifies existence, change
`broker.persistence.seedSecretName` and configure portal slots for its keys.

The seed supervisor tracks the digest imported from the seed independently of
the canonical file. An identical copied seed records/adopts the same generation
and does not overwrite a newer credential already rotated on the PVC. A later,
intentional portal replacement changes the seed digest and follows the existing
atomic import, provider acceptance/readiness, and rollback contract. A rejected
replacement preserves the last usable canonical credential.

After a verified portal enrollment/import, obsolete ExternalSecret or Key Vault
seed entries may be removed. Those systems remain optional seed producers and
are not known to the portal. Removing the portal does not remove the Secret or
broker state. Deleting the namespace loses Kubernetes Secrets and namespace
PVCs unless they are separately retained or backed up.
