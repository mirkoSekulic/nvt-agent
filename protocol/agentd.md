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

Before acknowledging the request as queued, `agentd` waits for the configured
tmux session and a launcher-owned generation marker. The launcher publishes the
marker only after its fast-exit stability check completes; `agentd` then starts
a separate bounded, continuous-session startup grace. This generic gate
prevents prompt events and injection while the session target is still in its
initial startup window; it does not inspect provider-specific terminal output.
The request wait includes scheduling/poll margin beyond the maximum configured
grace. If readiness is not reached within that bounded wait, the request fails
without a prompt ID or queued/injected event, allowing an idempotent caller to
retry.

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

## Client Commands

`agentdctl subscribe` tails the append-only event log. It is implemented as a
client-side log follower, not as a long-lived socket request to `agentd`.

Default behavior is live-only:

```sh
agentdctl subscribe --filter plugin.tests.
```

Replay from the beginning is explicit:

```sh
agentdctl subscribe --since beginning --filter plugin.tests.
```

Filters are prefix matches against the effective event name. For plugin events,
that is `plugin_event`; for core events, that is `event`. Multiple filters are
ORed.

Delivery semantics:

- `--since end`: at-most-once for future events; downtime events can be missed
- `--since beginning`: replay from the log; reactions must be idempotent

`agentdctl signal` is publish sugar for advisory agent-reported signals:

```sh
agentdctl signal done --message "Finished the task"
```

This publishes:

```text
plugin.agent.signal.done
```

`plugin.agent.signal.*` events are permanent advisory events. Future verified
session events, if added, should use a distinct `session.*` namespace.
