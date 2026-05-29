# event-webhook

`event-webhook` forwards selected `agentd` event envelopes to an HTTP endpoint.
It does not interpret event payloads and has no domain-specific logic.

The plugin is intended to run as a long-running `after-agent` plugin:

```yaml
plugins:
  - name: event-webhook
    source: builtin
    when: after-agent
    restart: always
    config:
      url: http://example.test/events
      filters:
        - plugin.github.pr.
        - agent.signal.done
```

## Local or Test Webhooks

Use `auth.type: none` when the endpoint is local, private, or otherwise does not
need an authorization header:

```yaml
plugins:
  - name: event-webhook
    source: builtin
    when: after-agent
    restart: always
    config:
      url: http://127.0.0.1:9000/events
      auth:
        type: none
```

`auth.type` defaults to `none`.

## Bearer Token Webhooks

Use `auth.type: bearer-env` to read a bearer token from an environment variable:

```yaml
plugins:
  - name: event-webhook
    source: builtin
    when: after-agent
    restart: always
    config:
      url: https://webhook.example.test/events
      auth:
        type: bearer-env
        env: NVT_EVENT_WEBHOOK_TOKEN
```

If the configured environment variable is missing or empty, the plugin fails
before subscribing.

## Filters

`filters` is a list of string prefixes. Empty or omitted `filters` forwards all
events. Prefixes are checked against both `event` and `plugin_event`, so an
envelope like this matches `plugin.github.pr.`:

```json
{"event":"plugin.event","plugin_event":"plugin.github.pr.merged"}
```

The HTTP request body is:

```json
{
  "agent": "<NVT_AGENT_NAME or AGENT_NAME>",
  "event": { "...original event object...": true }
}
```

Requests use `Content-Type: application/json`. Bearer auth adds
`Authorization: Bearer <token>`.

## Replay and Dedupe

The plugin subscribes with `since: end` by default. Set `since: beginning` to
replay existing events:

```yaml
config:
  url: http://127.0.0.1:9000/events
  since: beginning
  delivery:
    dedupe: true
    max-delivered-ids: 1000
```

With dedupe enabled, successfully delivered event ids are stored under:

```text
$NVT_STATE_DIR/plugins/event-webhook/delivery-state.json
```

`max-delivered-ids` bounds the state file so replay-safe delivery does not grow
without limit. Events without an `id` are delivered whenever they are observed.

## Delivery Options

```yaml
delivery:
  dedupe: true
  max-delivered-ids: 1000
  retry:
    max-attempts: 3
    backoff-seconds: 5
```

Any 2xx response is treated as success. Non-2xx responses and transport errors
are retried. After retries are exhausted, the failure is logged and the plugin
continues with future events.
