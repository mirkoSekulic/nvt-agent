# broker-auth-files

`broker-auth-files` is a generic before-agent plugin that materializes
broker-vended file bundles into a target directory. It does not know what the
files are for; provider-specific behavior belongs in the broker provider.

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
Periodic re-materialization before token expiry is out of scope for this
plugin version.
