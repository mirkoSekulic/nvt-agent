# Local credential management

Local credential management reuses the credential portal, enrollment runner,
gateway link, and broker seed supervisor. It is disabled by default. Enable it
only on a developer workstation:

```sh
NVT_CREDENTIAL_PORTAL_ENABLED=true make infra-up
```

Open `http://localhost:4090/agents`, choose **Manage credentials**, and select a
configured Codex or Claude slot. Recovery upload is the explicitly enabled
secondary path. The local auth mode creates a session only for the configured
single local principal and is accepted only at an HTTP `localhost` public URL;
session cookies, CSRF checks, same-origin checks, bounded uploads, and slot
ownership still apply. Kubernetes OIDC/OAuth, eligibility, and Secret patching
are unchanged.

The first enabled start copies the non-secret template to
`.broker/credential-portal-local.json`. Edit labels, provider names, and slots
there; provider-specific commands remain portal configuration. Do not add
credentials to this file.

Portal replacements are atomically written with mode `0600` to the private
`local-credential-seeds` named volume. The broker mounts that volume read-only.
Its existing seed supervisor stops the broker, imports the new generation into
the broker-owned `local-broker-private` volume, starts and checks the broker,
then commits the import marker. This prevents a portal write from racing a
broker-written canonical file. Broker provider configuration should reference
the corresponding canonical files, for example `/private/portal/codex` and
`/private/portal/claude`.

Existing `.broker` configuration and credentials remain mounted at `/state`
and continue to work when the feature is disabled or before a provider is
migrated. To migrate without exposing material, copy the existing credential
inside a one-shot trusted management container into the matching seed-volume
slot, verify broker readiness, then change that provider's `credentials-file`
to `/private/portal/<slot>`. Never print or pass the credential through shell
arguments. Named volumes survive portal, controller, broker, and `infra-down`
restarts; delete them only as an explicit credential-destruction operation.
