# broker-auth-files

`broker-auth-files` is a generic plugin that materializes broker-vended file
bundles into a target directory. It does not know what the files are for;
provider-specific behavior belongs in the broker provider.

Example:

```yaml
plugins:
  - name: broker-auth-files
    source: builtin
    when: before-agent
    restart: never
    config:
      bundles:
        - provider: codex-main
          target: /root/.codex
          dir-mode: "0700"
          file-mode: "0600"
```

For each bundle the plugin runs:

```sh
brokerctl files --provider <provider>
```

It creates the target directory, validates each returned file name as a plain
relative filename, and writes files atomically with the returned per-file mode
or the bundle `file-mode` default. Any broker, validation, or write failure
exits non-zero, which stops the agent when used as a `before-agent` plugin.

`run.py doctor` checks broker reachability and that target files exist.

## Loop Mode

`run.py loop` keeps bundles fresh for long-lived agents. It uses the same
`bundles` config as one-shot mode plus optional loop controls:

```yaml
refresh-slack-seconds: 900
min-sleep-seconds: 60
fallback-sleep-seconds: 3600
max-loops: 0
```

Loop behavior:

- materialize every configured bundle
- use the earliest broker `expires_at` as the bundle expiry
- sleep until `expires_at - refresh-slack-seconds`, clamped to at least
  `min-sleep-seconds`
- use `fallback-sleep-seconds` when no bundle has an expiry
- repeat forever when `max-loops: 0`; tests may set a positive limit

Failed cycles log a warning and retry with exponential backoff capped at
`fallback-sleep-seconds`. A failed cycle does not remove, truncate, or
partially overwrite existing target files: the plugin validates every returned
file before writing any file, then uses atomic rename per file. `restart:
always` is only a backstop for unexpected process termination.

After each successful cycle, the plugin publishes an advisory event:

```sh
agentdctl publish plugin.broker-auth-files.rematerialized \
  --source plugin:<instance-name> \
  --payload '{"providers":["..."],"expires_at":"..."}'
```

Missing or failing `agentdctl` is non-fatal.

Use the builtin refresher instance to run loop mode beside the one-shot seed:

```yaml
plugins:
  - name: broker-auth-files
    source: builtin
    when: before-agent
    config:
      bundles:
        - provider: codex-main
          target: /root/.codex
  - name: broker-auth-files-refresher
    source: builtin
    when: after-agent
    restart: always
    config:
      bundles:
        - provider: codex-main
          target: /root/.codex
      refresh-slack-seconds: 900
```

## Long-Lived Sessions

For Codex ChatGPT-plan auth bundles, keeping the on-disk bundle fresh is enough
for long-lived sessions. This was verified on `codex-cli 0.142.5`: a live
session caches its access token in memory and does not re-read `auth.json` per
turn. On a real 401, Codex's UnauthorizedRecovery path reloads `auth.json` from
disk before attempting OAuth refresh, guarded by matching the account id in the
file to the running process account id. The source path is
`codex-rs/login/src/auth/manager.rs` at tag `rust-v0.142.5` in
`openai/codex`. Broker-vended bundles preserve `account_id`, so the reload
guard is satisfied; the stub refresh token is only used if the refresher itself
is broken.
