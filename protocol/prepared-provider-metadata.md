# Prepared Provider Metadata v1

Prepared provider metadata is a small, language-neutral contract between the
trusted operator and runtime plugins. It carries only explicitly requested,
non-secret provider metadata. It is not a credential materialization channel.

An `AgentRun` requests preparation on an exact broker grant:

```yaml
broker:
  grants:
    - provider: fork-app
      preparations:
        - operation: identity
```

Version 1 allows only `identity`. Before creating the agent Pod, the operator
uses that AgentRun's control-plane broker identity and the target-less
`POST /v1/identity` operation. Unsupported, unauthorized, or malformed results
fail closed. The operator does not infer a provider from a repository or from
plugin configuration.

The operator writes a read-only ConfigMap item at
`/nvt-agent/prepared-provider-metadata.json` and sets
`NVT_PREPARED_PROVIDER_METADATA_FILE` to that path:

```json
{
  "version": 1,
  "providers": {
    "fork-app": {
      "identity": {
        "name": "Example App Bot",
        "email": "12345+example[bot]@users.noreply.github.com"
      }
    }
  }
}
```

`providers` is keyed by the exact broker grant provider name, and the next key
is the requested operation. Consumers must require version `1`, select the
exact provider and operation they were configured to use, validate the bounded
name/email strings, and fail closed when an entry is absent or malformed.

The document never contains broker tokens, provider credentials, request
headers, placeholder files, or upstream response bodies. The environment
variable exposes only its path. Runs with no preparations receive neither the
document nor the environment variable. Presence of the variable explicitly
selects prepared consumption: consumers must fail closed on a missing or
malformed exact entry and must not fall back. Its absence leaves local/direct
target-bearing broker identity behavior unchanged; enforced agents still have
no broker token with which to use that path. Cache validity is tied to the exact
prepared grant configuration, so a changed provider, repository ceiling,
materialization, permission, or preparation is resolved again before startup.

This contract is independent of plugin implementation language and provider
implementation source. Embedded and executable providers use the same broker
identity operation.
