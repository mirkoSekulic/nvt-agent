# Executable broker provider protocol

`nvt.broker-provider/v1` lets a broker administrator register a trusted local
executable as a provider implementation. The executable may be written in any
language. It runs with broker-side access and can receive credentials in config,
environment, requests, and results: this is a code-extension mechanism, **not a
sandbox or subprocess security boundary**. Administrators must trust and secure
the executable exactly as they trust `brokerd` and embedded Python providers.

Embedded providers remain the default. Executable implementations are registered
separately from provider instances:

```yaml
provider-plugins:
  - name: company-oauth
    command:
      - /opt/nvt/providers/company-oauth
    pass-env:
      - COMPANY_CLIENT_ID
      - COMPANY_CREDENTIAL
    initialize-timeout-seconds: 10
    request-timeout-seconds: 30

providers:
  - name: company-main
    plugin: company-oauth
    config:
      credentials-file: /broker-secrets/company/credentials.json
    allow:
      repositories:
        - example/*
```

External names may not collide with built-in plugin names. `command` is a
non-empty argument list. It is executed directly, never through a shell, and
`command[0]` must be an absolute executable file for a local registration.
`pass-env` is the explicit
list of additional environment-variable names; a missing requested variable is
a startup error. The child does not inherit the broker environment. Its fixed,
non-secret baseline is only `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`,
`LANG=C.UTF-8`, `LC_ALL=C.UTF-8`, and `TZ=UTC`, plus `pass-env` values.

There is one long-lived child per configured provider instance. Two instances
using the same registered implementation therefore have separate process state
and caches.

An implementation may instead come from an immutable public Git source:

```yaml
provider-plugins:
  - name: company-oauth
    source:
      git:
        url: https://github.com/example/nvt-plugins.git
        revision: 0123456789abcdef0123456789abcdef01234567
        subdir: providers/company-oauth
    command: [company-oauth]

providers:
  - name: claude-mirko
    plugin: company-oauth
    config: {credentials-file: /broker-secrets/mirko.json}
  - name: claude-john
    plugin: company-oauth
    config: {credentials-file: /broker-secrets/john.json}
```

For a Git source, `command[0]` is a safe relative path beneath the selected
subdirectory and is resolved to a verified absolute executable before startup;
remaining arguments stay explicit. Each provider instance still receives its
own long-lived child, config, credentials, refresh lineage, and cache. Provider
selection remains the explicit instance name and is never inferred from a host.

Only public HTTPS repositories at full immutable commit IDs are supported.
`NVT_GIT_SOURCE_ALLOWED_HOSTS` is an exact-host allowlist that defaults to
`github.com`. Authentication, credential helpers, redirects, submodules, Git
LFS, hooks, builds, installs, and floating revisions are disabled. Checkouts are
cached and atomically published by canonical URL plus revision; cache hits,
commit identity, subdirectories, and symlink containment are revalidated. A
repository is never scanned and a declaration is never automatically updated.
Fetched executable providers are trusted broker code, exactly like local
executable providers; the subprocess is not a sandbox.

## Transport and framing

The protocol is JSON-RPC 2.0 over the child's stdin and stdout. Both are UTF-8,
newline-delimited streams with exactly one compact JSON object per line. stdout
is protocol-only; diagnostics go to stderr. Requests carry unique string IDs,
and responses may arrive out of order.

An input or output line, including its newline, is limited to 1 MiB, matching
the broker HTTP request limit. The broker rejects oversized, malformed,
non-object, duplicate-ID, and unknown-ID responses and terminates that process.
The broker never logs raw protocol lines: results can contain credentials.
stderr is continuously drained to prevent deadlock, but is discarded by the
broker; it is never copied into HTTP errors, audit records, or normal logs.

The first valid response for an ID may complete its caller. A later response
with that same ID is a protocol violation: it invalidates the process
generation and fails every request still pending in that generation. It cannot
retroactively fail a caller that already returned. Recovery is complete only
after that generation has become unavailable, a new child has initialized, and
a fresh request succeeds.

Request:

```json
{"jsonrpc":"2.0","id":"unique-string","method":"token","params":{}}
```

Success and error responses:

```json
{"jsonrpc":"2.0","id":"unique-string","result":{}}
{"jsonrpc":"2.0","id":"unique-string","error":{"code":-32000,"message":"provider error","data":{"reason":"repo-not-allowed","status":403,"message":"repository is not allowed"}}}
```

`error.data` has exactly `reason` (a non-empty stable string of at most 128
characters), `status` (400 through 599), and optional non-empty sanitized
`message` (at most 4096 characters). Those fields map to core `ProviderError`.
They must not contain stderr, protocol text, traces, response bodies, tokens,
headers, config, or other credential material. The outer JSON-RPC error message
is not surfaced.

## Initialization and metadata

The first request is `initialize`:

```json
{"protocol_version":"nvt.broker-provider/v1","provider_instance_name":"company-main","plugin_name":"company-oauth","config":{},"allow":{}}
```

`allow` is the configured provider ceiling; broker core still computes agent
grants and passes the effective repository scope on individual operations. A
successful result contains:

```json
{"protocol_version":"nvt.broker-provider/v1","capabilities":["token"],"injection_hosts":[],"injection_git":false,"bundle_ttl_seconds":null}
```

The only capability strings are `http.request`, `token`, `identity`, `headers`,
`files`, `placeholder-files`, and `injection.headers`. Unknown or duplicate
values fail initialization. Metadata defaults are an empty `injection_hosts`
list, false `injection_git`, and null `bundle_ttl_seconds`; a non-null TTL is a
positive integer. Injection metadata requires `injection.headers`. Providers
declaring `token`, `identity`, or `headers` must implement `target.normalize`.
Each injection host must be a unique normalized lowercase DNS hostname: labels
contain only `a-z`, `0-9`, and interior hyphens, with no scheme, path, wildcard,
port, trailing dot, uppercase characters, or IPv4/IPv6 literals.
`injection.headers` with an empty host list is valid metadata but is not exposed
as an injection-capable provider.

## Operations

Every params object contains only provider context already available to embedded
providers. Python objects and `AuditLog` are never serialized. Broker core is
the sole audit writer; provider-generated audit records are not supported.

- `target.normalize`: `{target}` → `{target, audit_target}`. The returned
  normalized target is a non-empty JSON string; `audit_target` is a non-empty,
  sanitized string suitable for audit. Each is at most 8192 UTF-8 bytes.
  `audit_target` must not contain credentials or control characters.
- `http.request`: `{method,url,headers,paginate,effective_repositories}` →
  `{status,headers,body,audit_target}`. `audit_target` is the sanitized target
  core records for this request.
- `token`: `{target,effective_repositories}` → `{token,expires_at}`.
- `identity`: `{target,effective_repositories}` → `{name,email}`.
- `headers`: `{target,effective_repositories}` → `{headers}`.
- `files`: `{agent_id,request_id}` → `{files,expires_at}`.
- `placeholder-files`: `{agent_id,request_id,grant}` →
  `{files,hosts,expires_at}`.
- `injection.headers`: `{host,method,path,agent_id,request_id,grant}` →
  `{headers,expires_at,strip_request_headers}`.
- `shutdown`: `{}` → any JSON result. The broker bounds this request, then
  terminates and reaps the child if it does not exit.

Field shapes match the corresponding HTTP endpoints in [broker.md](broker.md).
The provider must enforce its configured ceiling. Broker core continues to
enforce agent identity, grant/materialization rules, effective repositories,
injection host routing, expiry capping, and all audit semantics.

## Failure, restart, and health

Initialize and ordinary requests use their configured timeouts. EOF, timeout,
crash, malformed or oversized output, or response correlation violations fail
the triggering and all pending requests closed. No other provider is tried and
no cached secret result is returned. The bad child is terminated and reaped.
Timeout callers return at their absolute request deadline; lifecycle-owned
cleanup retires and reaps the failed generation before any replacement starts.

After an initial successful startup, a failed instance becomes unavailable and
is restarted with bounded exponential backoff. Calls during backoff return a
sanitized provider-unavailable error. A successful reinitialize makes that
instance ready again. Backoff is not reset by initialization alone; it resets
only after the generation has remained live for at least five seconds and
successfully completed a request. Other providers remain live. Health reports
only aggregate configured, ready, and unavailable counts—never provider names,
config, or credential state—and does not call providers or upstream services.
