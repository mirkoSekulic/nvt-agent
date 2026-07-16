# Codex Authentication

nvt supports Codex with direct auth for local compatibility and mediated auth
for workloads where the agent must not possess provider credentials.

## Direct Mode

Direct mode copies a usable Codex `auth.json` into the agent. It is convenient
for local development, but the agent can read and exfiltrate the access token.
Do not treat this mode as credential non-possession.

The `codex-oauth` broker provider owns OAuth refresh and can vend the file
through the `broker-auth-files` runtime plugin. See the provider contract in
the [broker protocol](../protocol/broker.md).

## Mediated Mode

Mediated Codex uses three generic mechanisms:

1. The broker owns the real access and refresh tokens.
2. The agent receives a syntactically valid `auth.json` containing inert
   placeholders.
3. Transparent or forward-proxy egress sends Codex traffic through `egressd`,
   which obtains the approved credential from the broker and injects it into
   the outbound request.

No Codex-specific secret handling lives in runtime core, `agentd`, `captured`,
or `egressd`. Codex-specific file shape and OAuth refresh behavior belong to
the `codex-oauth` broker provider.

```text
Codex -> placeholder Authorization -> captured/egressd
      -> broker authorization and refresh
      -> real Authorization to the pinned upstream
```

Use a `placeholder-file` grant and explicitly select the provider used by the
runtime proxy. This is important when multiple Codex accounts share the same
upstream hostname: provider selection is never inferred from the host.

## What Has Been Proven

The real Codex proof validates:

- a real Codex turn through TLS-terminating egress;
- WebSocket upgrade and bidirectional relay;
- placeholder removal and broker credential injection;
- absence of real Codex credentials in agent filesystem, environment, and
  process arguments;
- broker-owned refresh and refresh-token rotation;
- fail-closed behavior when broker authorization is unavailable.

Run the manual proof from a trusted host that has a valid Codex login:

```sh
make phase6-real-codex-proof
```

The proof is manual because it consumes a real subscription credential and
calls external services. Hermetic protocol, proxy, refresh, and non-possession
tests run in CI; see [CI coverage](ci-coverage.md).

## Security Boundary

Mediation protects credentials only when direct egress is also fenced. In
Kubernetes, use mediated mode with enforcement and transparent transport. The
workload NetworkPolicy then allows external traffic only through its paired
`egressd` service. Local Compose demonstrates mediation and non-possession but is
not an equivalent hostile-workload boundary because privileged local
containers share and can modify the network namespace.

See [Transparent mediated egress](transparent-egress-architecture.md) for the
full traffic and enforcement model.
