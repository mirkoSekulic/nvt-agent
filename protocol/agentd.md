# agentd Protocol

`agentd` is the container-local session API. It runs inside the agent
container and listens on a Unix socket.

Default socket:

```text
/run/nvt-agent/agentd.sock
```

The protocol is newline-delimited JSON. Each request receives one JSON response.

## Requests

### prompt

Enqueue text for injection into the running agent session.

```json
{"type":"prompt","source":"plugin:example","external":true,"message":"Run the tests"}
```

Fields:

- `source`: caller identity. Examples: `host`, `plugin:github-watcher`.
- `external`: when true, `agentd` wraps the prompt with an untrusted-input warning.
- `message`: prompt text.

### status

Return daemon/session state.

```json
{"type":"status"}
```

### health

Return whether `agentd` is accepting requests.

```json
{"type":"health"}
```

### event.publish

Publish a plugin event for logging and future subscribers.

```json
{"type":"event.publish","source":"plugin:test-runner","event":"plugin.test-runner.failed","payload":{"summary":"3 failed"}}
```

Plugin events are advisory. Core session events are reserved for `agentd`.

