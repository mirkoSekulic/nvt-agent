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

## What the Manual Proof Shows

Run the manual proof from a trusted host that has a valid Codex login:

```sh
make codex-mediated-proof
```

It runs one real `codex exec` turn inside a mediated + enforced +
forward-proxy `AgentRun` whose `codex-main` grant uses `placeholder-file`
materialization, and writes evidence to `.proof-out/codex/`.

The run fails unless both of these hold:

- **Real turn under mediation.** Codex completes a turn through the
  TLS-terminating forward proxy and echoes a per-run nonce back in
  `/tmp/last-message`. Because the agent holds only a placeholder `auth.json`,
  a successful turn means `egressd` stripped the placeholder and injected the
  broker-held credential.
- **Non-possession in the collected evidence.** The host access, refresh, and
  id tokens appear in none of: the agent's copied `~/.codex` directory, the
  agent's proxy environment, Codex stdout/stderr, the agent's last message, the
  `egressd` and broker logs, or the broker audit log.

The summary file also records, without gating the run:

- **WebSocket upgrade**, reported as passing only when the broker audit shows a
  `101 Switching Protocols` for the run; a WSS-to-HTTPS fallback or a run with
  no upgrade is reported as unproven.
- **Refresh**, always reported as `unproven`. This harness does not force a
  token refresh, so it says nothing about real-Codex refresh or refresh-token
  rotation. Do not read a passing run as refresh evidence.

Broker-owned refresh and rotated-refresh-token persistence for the
`codex-oauth` provider are covered hermetically, against a fake OAuth server,
by `TestCodexOAuthRefreshPersistsRotatedTokenAndAudits` and
`TestCodexOAuthPersistsRotatedRefreshTokenBeforeNewAccessValidation` in
`tests/broker/broker_conformance_test.go`. Fail-closed behavior when broker
authorization is unavailable or denied is covered by
`TestForwardProxyMITMFailsClosedOnBrokerDown` in
`egressd/internal/egress/forward_proxy_mitm_test.go` and
`TestFailsClosedWhenBrokerDenies` in `egressd/internal/egress/proxy_test.go`.

The proof stays manual because it consumes a real subscription credential and
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
