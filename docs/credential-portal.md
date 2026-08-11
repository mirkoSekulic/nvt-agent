# Self-service provider credential enrollment

`nvt-credential-portal` is an optional, standalone enrollment service. It is
disabled by default. Its complete data path is:

```text
browser -> credential portal -> tokenless credential runner -> credential portal
        -> pre-created Kubernetes seed Secret -> existing broker seed supervisor
        -> broker PVC canonical file -> existing provider refresh and injection
```

The portal is not a second credential runtime. It never reads the current
Secret, the broker PVC, provider health, AgentRuns, or Key Vault. It neither
refreshes nor injects credentials. Removing the Deployment later does not
remove the pre-created Secret or the broker PVC and does not interrupt running
agents or broker refresh.

The normal user flow is Connect/Reconnect. After portal authentication establishes
the stable owner, the portal asks a separate credential-runner sidecar to run the
selected trusted adapter in an isolated, private, memory-backed temporary home. Codex uses
`codex login --device-auth`; Claude uses `claude auth login --claudeai`. The
browser receives only the provider-hosted authorization URL and, where the
official flow requires it, a short-lived device or paste-back code. Provider
tokens and the generated `auth.json` or `.credentials.json` stay server-side.

## Security boundary

Authentication is generic OIDC or OAuth2. The portal uses its own encrypted,
HTTP-only, Secure session cookie, short-lived signed login state, PKCE, and a
separate callback path. By default, a successfully authenticated issuer/subject
pair receives a session only when it owns at least one configured slot. Optional
`auth.eligibility` and `auth.claimEnrichment` use the same provider-neutral,
bounded default-deny contract as gateway login admission. With that policy set,
an eligible principal may receive a session without a static slot, but exact
issuer/subject ownership still protects every slot operation. This is admission
groundwork only and does not dynamically create enrollment slots or broker
accounts. See [generic OAuth2/OIDC eligibility](oauth-eligibility.md).
Display names are never authorization input. OAuth2 identity subjects may
be JSON strings or integers; integer subjects are converted to their exact
canonical decimal form, so quote that value in slot configuration (for example,
`subject: "424242"`). Fractional numbers and identity values containing the
transient access token are rejected.

Each slot binds a stable name and exact owner `(issuer, subject)` to one explicit
adapter, broker provider name, pre-created Secret, and data key. The request
cannot supply or override the adapter, provider, Secret, or key. The Service
Account has only `patch` on the configured Secret name; it has no `get`, `list`,
`create`, or `delete`. The application sends one JSON Patch `add` operation
(which creates or replaces that member) for the configured `/data` key and
never observes any other key. The pre-created Secret must contain a `data: {}`
object, but its configured slot keys may initially be absent.
The portal container requests a metadata-only PATCH response and streams/discards the
response rather than decoding a Secret object.

The CLI runner is a separate container boundary. Pod ServiceAccount automounting
and Kubernetes service-link environment injection are disabled. A short-lived
projected Kubernetes API token is mounted only into the small portal container;
the runner receives no Kubernetes token, portal configuration, session/OAuth
client Secret environment, or Kubernetes/workload credential. The containers
communicate only on pod localhost using a per-pod random key generated into
memory-backed storage. Every bounded protocol request has an HMAC, timestamp,
and unique replay-rejected nonce; enrollment identifiers are opaque and
single-use. The runner can invoke only compiled-in adapters. It cannot select or
see a Secret destination or patch Kubernetes. A completed document remains
retrievable over the authenticated protocol until the portal validates it,
successfully patches the exact slot-bound Secret key, and sends an explicit
idempotent acknowledgment. A reset response can therefore be fetched again
without starting another provider login.

Portal login and provider authorization are separate sessions and callback
paths. Each in-memory enrollment session binds the authenticated principal,
exact configured slot and adapter, an opaque one-time identifier, expiry, and
single-use code handoff. Request parameters cannot override the provider,
adapter, Secret, or key. Reconnect never relies on reported credential health
or expiry and can be started at any time.

Enrollment processes are capped and time-bounded in both components. CLI output
is bounded and never logged. Each process receives a small allowlisted
environment and a fresh private `HOME`; portal session/OAuth client secrets are
not mounted into the runner container and cannot be inherited. Generated
files are accepted only at the adapter's fixed path, must be regular bounded
files, and are validated before patch. The temporary home is removed before the
Secret is changed, and in-memory credential bytes are cleared as practical.
Logout, timeout, cancellation, and shutdown terminate unfinished enrollment
processes. Cancellation removes the runner session after subprocess cleanup and
immediately reclaims capacity. Every session has the same bounded enrollment
expiry even after CLI success; an unacknowledged or abandoned result is wiped
and removed at expiry. Validation or Secret-patch failure triggers best-effort
remote cancellation and wiping instead of acknowledgment. The portal
ServiceAccount still has only the configured Secret `patch` permission and has
no workload-creation permission.

The optional administrator recovery upload is disabled by default. When enabled,
uploads are raw `application/json`, bounded to at most 1 MiB, protected by
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

Liveness reports only that the portal process is running. Readiness additionally
performs a bounded, authenticated localhost check of the credential runner, so
a missing or wedged runner removes the portal Pod from service. Neither probe
claims that a credential exists, is usable, was imported by the broker, or is
healthy upstream.

## Enrollment adapters and proof status

The adapter is selected by the administrator, never inferred from provider
output or a recovery file.

- `codex-oauth-file` invokes the **experimental** `codex login --device-auth`
  flow, discovers
  `$HOME/.codex/auth.json`, and accepts a top-level object with non-empty
  `tokens.access_token` and `tokens.refresh_token`; the access token must be a
  JWT with an integer `exp`, as required by the existing broker provider.
- `claude-oauth-file` invokes `claude auth login --claudeai`, discovers
  `$HOME/.claude/.credentials.json`, and accepts a top-level object with non-empty
  `claudeAiOauth.accessToken` and `claudeAiOauth.refreshToken`, matching the
  existing broker provider's minimum source shape.

On 2026-08-10, sanitized lifecycle probes against installed Codex CLI 0.147.0
and Claude Code 2.1.224 confirmed the official remote-safe handoffs: Codex
emitted an `auth.openai.com` device URL and one-time code while polling, and
Claude emitted a `claude.com` authorization URL and waited for paste-back code.
The Codex device flow can require an account security setting and has failed in
deployments where that setting was unavailable. It therefore requires explicit
`credentialPortal.enrollment.experimentalCodexDeviceAuth: true` opt-in. The
probes used empty temporary homes, did not complete authorization, and
created no credential file. End-to-end real-account completion and generated
file validation therefore remain **unverified** and these adapters must not be
described as production-ready until an authorized operator records that
sanitized proof. The fake-CLI conformance suite covers the complete handoff,
file discovery, validation, Secret patch, failure, and cleanup contracts without
real credentials. The image pins Codex CLI `0.147.0` and Claude Code `2.1.226`
so rebuilding a commit cannot silently change command parsing or credential-file
behavior. CLI version parity with AgentRun images is deferred; separate image
build arguments make later coordinated sourcing explicit.

## Enabling the chart

First create the seed, session, and OAuth client Secrets out of band. The chart
does not create credential-bearing Secrets. Then configure the persistent
broker seed and portal. A minimal OIDC example is in
`tests/operator/helm/credential-portal-values.yaml`; production deployments
must replace its illustrative issuer, subjects, and Secret names.

Expose the portal Service through an HTTPS ingress at exactly
`credentialPortal.publicURL`. NetworkPolicy permits the portal's HTTP listener
and outbound DNS/HTTPS for Kubernetes, identity, and provider authorization;
cluster policy may narrow peers while preserving those dependencies.

Claude Connect/Reconnect is available when the portal and a Claude slot are
enabled. A Codex slot additionally requires explicit acknowledgement of its
unproven device flow:

```yaml
credentialPortal:
  enrollment:
    experimentalCodexDeviceAuth: true
```

To expose the secondary recovery upload explicitly:

```yaml
credentialPortal:
  recoveryUpload:
    enabled: true
```

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
