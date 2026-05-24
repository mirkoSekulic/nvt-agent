# {{PLUGIN_NAME}}

nvt-agent plugin scaffold.

## Commands

```sh
./run.sh
./run.sh doctor
./run.sh ready
```

The generated plugin manifest points at:

```text
{{PLUGIN_COMMAND}}
```

The plugin receives:

```text
NVT_PLUGIN_NAME
NVT_PLUGIN_CONFIG
NVT_WORKSPACE
NVT_STATE_DIR
```

Read `NVT_PLUGIN_CONFIG` for plugin-specific configuration.
