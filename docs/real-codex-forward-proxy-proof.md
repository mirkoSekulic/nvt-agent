# Real Codex Forward-Proxy Proof Findings

Status: manual proof run completed on `2026-07-07` after PR 66 (`spec.egressForwardProxy`) merged.

This document records the real Codex proof result and the remaining work needed before relying on mediated Codex auth in a real environment.

## Goal

Prove that a real Codex CLI can run in an `AgentRun` with:

- `egress: mediated`
- `egressEnforcement: true`
- `egressForwardProxy: true`
- `codex-main` grant using `materialization: placeholder-file`
- no real Codex token in the agent filesystem, environment, or process args
- real Codex credentials held by the broker and injected only at egressd

## Test Setup

Cluster:

- kind cluster: `nvt-codex-proof`
- namespace: `nvt`
- Calico enabled, because forward-proxy enforcement depends on NetworkPolicy

Broker seed:

- host Codex auth was copied into Kubernetes Secret `codex-auth` with `make operator-codex-auth-secret`
- broker persistence was enabled
- broker init copied the Secret into `/state/codex`
- `codex-oauth` provider read `/state/codex/auth.json`

Provider shape:

```yaml
broker:
  persistence:
    enabled: true
    seedSecretName: codex-auth
    seedTargetDir: codex
  config:
    providers:
      - name: codex-main
        plugin: codex-oauth
        config:
          auth-file: /state/codex/auth.json
          injection-hosts:
            - chatgpt.com
            - api.openai.com
            - auth.openai.com
          placeholder-file:
            path: .codex/auth.json
            hosts:
              - chatgpt.com
              - api.openai.com
              - auth.openai.com
            id-token-claims:
              - claim: chatgpt_account_id
                claim-path:
                  - https://api.openai.com/auth
                  - chatgpt_account_id
          injection-claim-headers:
            - header: ChatGPT-Account-ID
              claim-path:
                - https://api.openai.com/auth
                - chatgpt_account_id
```

AgentRun shape:

- `runtimeAuth` was not set
- grant:
  - provider `codex-main`
  - materialization `placeholder-file`
  - egress hosts `chatgpt.com:443`, `api.openai.com:443`, `auth.openai.com:443`
- runtime command ran `codex exec --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check --output-last-message ...`

## Result

The second run succeeded after restarting the broker to pick up corrected provider config.

Evidence:

- Codex returned the exact nonce:
  - prompt nonce: `NVT_CODEX_PROOF_1783430893`
  - last message: `NVT_CODEX_PROOF_1783430893`
- Codex reported token usage: `2,505`
- agent had proxy env:
  - `HTTPS_PROXY=http://real-codex-proof-egressd:8473`
  - `HTTP_PROXY=http://real-codex-proof-egressd:8473`
  - `NO_PROXY` included broker, operator callback, Kubernetes service domains, localhost, and egressd itself
- agent `.codex/auth.json` was placeholder-only for token-bearing fields:
  - `access_token placeholder True`
  - `refresh_token placeholder True`
  - `id_token` was JWT-shaped synthetic placeholder content
- local scan of copied agent Codex/proof files found no host Codex token material:
  - `secret_hits []`
  - files scanned: `76`

## What This Proves

Proven:

- Real Codex can complete a normal `codex exec` turn in a mediated, enforced, forward-proxy AgentRun.
- The agent does not need a usable local Codex access token or refresh token.
- Placeholder-file materialization plus forward-proxy MITM composes correctly for the HTTPS fallback path.
- egressd can inject the broker-owned real Codex credential at the network edge.
- No real host Codex token was found in the copied agent auth/proof files.

Not proven:

- Codex WebSocket path.
- Codex refresh path through `auth.openai.com/oauth/token`.
- Long-running multi-hour Codex sessions crossing an access-token expiry boundary.

## Observed Failures

### 1. Broker ConfigMap Changes Do Not Restart Broker

First run failed with:

```text
egressd codex-main: injection material unavailable: broker denied injection: injection-claim-missing
```

Root cause:

- Helm updated `nvt-broker-config` with the corrected nested claim path.
- `nvt-broker` did not restart.
- The running broker still used the old provider config (`claim-path: account_id`).

After `kubectl rollout restart deployment/nvt-broker -n nvt`, the same AgentRun shape succeeded.

Required fix:

- Add checksum annotations to the broker Deployment for config inputs that require process restart:
  - `nvt-broker-config`
  - likely `nvt-broker-agents` if the broker does not dynamically reload it
  - TLS Secret was already discussed separately; preserve existing TLS checksum behavior if present

Acceptance:

- Helm upgrade that changes `broker.config.providers` rolls `deployment/nvt-broker`.
- A test or helm render assertion pins the checksum annotation.

**Fixed (PR A landed):** the broker Deployment now carries a
`checksum/broker-config` pod annotation (`nvt.brokerConfigChecksum`) that hashes
`broker.config`, so a Helm upgrade changing `broker.config.providers` rolls
`deployment/nvt-broker`. The `nvt-broker-agents` ConfigMap is **not** checksummed
on purpose — the broker hot-reloads it by mtime (revocation depends on that), so
a restart there would be counterproductive. A helm-render assertion pins that the
annotation is present and changes when `broker.config.providers` changes.

### 2. Codex WebSocket Path Failed, HTTPS Fallback Worked

Codex stderr showed repeated WebSocket failures:

```text
failed to connect to websocket: HTTP error: 405 Method Not Allowed,
url: wss://chatgpt.com/backend-api/codex/responses
warning: Falling back from WebSockets to HTTPS transport
```

After fallback, Codex succeeded over HTTPS.

Interpretation:

- The normal `codex exec` proof passed because HTTPS fallback works through egressd.
- The WebSocket path is not proven.
- This may be an upstream behavior, missing upgrade handling in `Proxy.ServeHTTP`, or method/header mismatch introduced by the MITM path.

Required investigation:

- Add a focused egressd test for HTTP Upgrade/WebSocket through `serveDecrypted` and `Proxy.ServeHTTP`.
- Verify whether Go's current handler path preserves `Connection: Upgrade`, `Upgrade: websocket`, and bidirectional streaming when the request comes through the single-connection MITM server.
- Capture sanitized request metadata for the failed WSS handshake:
  - method
  - path class
  - upgrade yes/no
  - upstream response status
  - no header values, no bodies, no frame payloads

Acceptance:

- Either Codex WebSocket succeeds through egressd, or docs explicitly state that real Codex currently relies on HTTPS fallback and WebSocket remains unproven.

### 3. Refresh Path Is Still Unproven

The proof did not force token expiry or refresh.

Risk:

- Long-running agents may hit access-token expiry.
- If Codex attempts local refresh with placeholder `refresh_token`, it will fail unless the refresh request is mediated in a way Codex accepts.
- The broker provider can refresh its own real auth, but we have not proven the full runtime behavior when Codex receives a 401 mid-session.

Required investigation:

- Add an opt-in/manual proof mode that forces refresh behavior.
- Possible approaches:
  - seed broker with an access token close to expiry, preserving the real refresh token
  - add a broker/provider test-only knob to treat the access token as expired for injection fetch
  - run a long-lived Codex turn across token expiry if feasible

Acceptance:

- A real Codex run survives token refresh without any real refresh token in the agent.
- Or the docs explicitly mark refresh as the remaining blocker for long-lived Codex sessions.

## Recommended PRs

### PR A: Broker Config Rollout Checksum — LANDED

Scope:

- Helm chart only, plus tests.
- Add checksum annotations to `nvt-broker` Deployment for broker config.
- Add helm test coverage.

Why first:

- This caused a real false failure during the proof.
- It is small and production-relevant beyond Codex.

Landed as the `checksum/broker-config` pod annotation on the broker Deployment,
pinned by `tests/operator/helm/test.sh`.

### PR B: Manual Real Codex Proof Harness — LANDED

Scope:

- Add a script and make target, manual/opt-in.
- Do not run in CI by default.
- Should write evidence under an ignored output directory, for example `.phase6-out/real-codex-proof/`.

Target (landed):

```sh
make phase6-real-codex-proof            # uses ~/.codex
CODEX_AUTH_SOURCE=/path/to/.codex make phase6-real-codex-proof
```

Implemented in `scripts/phase6-real-codex-proof.sh`; writes evidence and a
summary (normal turn / WebSocket / refresh / secret-scan) under
`.phase6-out/real-codex-proof/` (git-ignored). Refresh is not forced yet (PR D)
and the WebSocket path is recorded as fallback-only (PR C).

Suggested behavior:

1. Create/use Calico kind cluster.
2. Create namespace.
3. Create filtered `codex-auth` Secret from `CODEX_AUTH_SOURCE` / `~/.codex`.
4. Install nvt with broker persistence and `codex-main` provider config.
5. Submit a forward-proxy `placeholder-file` AgentRun.
6. Wait for proof completion.
7. Collect:
   - Codex stdout/stderr/last message
   - agent auth shape
   - proxy env
   - egressd logs
   - broker audit/logs
8. Scan copied agent files for host token needles without printing token values.
9. Emit a summary with:
   - normal turn pass/fail
   - WebSocket pass/fail
   - refresh pass/fail/unproven
   - secret scan pass/fail

### PR C: WebSocket / Upgrade Investigation

Scope:

- egressd tests first.
- If needed, implementation changes in `Proxy.ServeHTTP` to correctly support WebSocket upgrade over MITM.

Do not add provider-specific Codex logic to egressd.

### PR D: Refresh Proof

Scope:

- broker/provider test knob or proof harness changes.
- Real Codex proof mode that exercises refresh.

Do not widen to body/query substitution unless the proof shows Codex sends required secrets in body/query and header injection cannot satisfy it.

## Operational Recommendation

For a real environment today:

- Forward-proxy mediated Codex is promising and has passed the normal HTTPS turn proof.
- Do not yet claim full long-lived Codex support until refresh is proven.
- Do not claim WebSocket support until the `405` is understood or fixed.
- Broker config rollout checksum should be fixed before staging deployment.

