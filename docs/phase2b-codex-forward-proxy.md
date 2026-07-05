# Phase 2b — Codex CONNECT-Only Forward Proxy

Status: implemented as low-risk plumbing after the Phase 2 redirect-only
NO-GO.

This phase adds a forward-proxy mode to `egressd` that supports only HTTP
`CONNECT` blind tunnels. It is intentionally not credential-less Codex
mediation yet.

## Boundary

What this phase does:

- accepts HTTP `CONNECT host:port` requests;
- allows only configured hosts, default deny;
- defaults allowed ports to `443`;
- tunnels bytes blindly after `200 Connection Established`;
- logs only sanitized CONNECT decisions:
  `event=connect`, `target_host`, `target_port`, `decision`, and optional
  `error_class`.

Those CONNECT decisions are sanitized `egressd` stdout logs only in this PR.
They are not broker `audit.jsonl` entries; per-request broker audit remains a
later egress enforcement/audit phase.

What this phase does not do:

- no plain HTTP proxying for `GET`/`POST` proxy requests;
- no TLS termination or per-agent CA;
- no WebSocket handshake inspection or injection;
- no credential injection;
- no broker API changes;
- no `agentd` changes.

Codex still uses its existing `auth.json` in the Phase 2b harness. The harness
proves that current Codex honors proxy environment variables for the hardcoded
WebSocket endpoints; it does not prove credential non-possession.

## Harness

Run:

```sh
make phase2b-codex-forward-proxy
```

Useful override:

```sh
PHASE2B_AUTH_SOURCE=/path/to/auth.json make phase2b-codex-forward-proxy
```

The harness starts an isolated agent container and `egressd` on an internal
agent network. `egressd` also has an outbound network and listens as a
CONNECT-only proxy at `http://egressd:8471`.

The Codex run sets:

```text
HTTPS_PROXY=http://egressd:8471
HTTP_PROXY=http://egressd:8471
ALL_PROXY=http://egressd:8471
NO_PROXY=localhost,127.0.0.1,::1,broker,egressd
```

It runs:

```sh
codex exec --skip-git-repo-check "print pong"
```

Evidence lands in `.phase2b-out/evidence/`:

- `codex-stdout.txt`
- `codex-stderr.txt`
- `egressd.log`
- `summary.txt`

Acceptance:

- Codex prints `pong`.
- `egressd.log` contains allowed CONNECT decisions for allowlisted hosts.
- `egressd.log` contains no credential/header-shaped text.

Denied-host behavior is covered by focused `egressd` Go tests, not by the real
Codex harness.

## Initial Allowlist

The harness allowlist is:

- `chatgpt.com`
- `ab.chatgpt.com`
- `github.com`
- `api.openai.com`
- `auth.openai.com`

Only port `443` is allowed by default.

## Next PR

The next PR should harden Codex fallback behavior and short-TTL vended bundles.
Credential-less Codex waits for later CA/TLS termination plus WebSocket
handshake injection.
