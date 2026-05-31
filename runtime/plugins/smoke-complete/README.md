# smoke-complete

`smoke-complete` is a tiny builtin runtime plugin for local and operator smoke
tests. It sleeps for a configured delay and publishes a deterministic `agentd`
event. It is smoke/test support only; it is not a scheduler plugin and does not
talk to GitHub or any external service.

Normal operator-smoke example:

```yaml
plugins:
  - name: event-webhook
    source: builtin
    when: after-agent
    restart: always
    config:
      url: http://nvt-operator:8082/v1/agentruns/<namespace>/<name>/events
      auth:
        type: bearer-env
        env: NVT_OPERATOR_CALLBACK_TOKEN
      filters:
        - plugin.smoke.

  - name: smoke-complete
    source: builtin
    when: after-agent
    restart: never
    config:
      delaySeconds: 5
      event: plugin.smoke.completed
      payload:
        ok: true
```

Configuration:

- `delaySeconds`: optional integer, default `5`
- `event`: optional plugin event name, default `plugin.smoke.completed`
- `payload`: optional object, default `{ok: true}`
- `waitForPlugin`: optional plugin state to wait for before sleeping and
  publishing, default `event-webhook`; set to `false` to disable
- `waitTimeoutSeconds`: optional integer, default `30`

The default `waitForPlugin` makes the plugin wait until `event-webhook` is
running and ready before it publishes the smoke completion event. This keeps the
future operator smoke lifecycle deterministic when both plugins run
`after-agent`.

The plugin publishes through:

```sh
agentdctl publish "$event" --source plugin:smoke-complete --payload "$payload"
```
