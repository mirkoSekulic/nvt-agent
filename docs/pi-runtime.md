# Pi runtime

NVT's `pi` preset runs the interactive terminal from
`@earendil-works/pi-coding-agent@0.85.1` (Node >=22.19). The runtime image installs
this exact version; changing `PI_VERSION` requires rerunning the compatibility
proof. There is no host Pi dependency, RPC bridge, or producer-specific adapter.

## Configuration and credentials

See the complete [local manifest](../examples/pi/manifest.example.yaml),
[AgentRun](../examples/pi/agentrun.example.yaml), and
[Helm values](../examples/pi/values.example.yaml). Endpoint and model names are
fictional. Configure a compatible HTTPS service before running these examples.

The local runtime selection is:

```yaml
runtime:
  preset: pi
  autonomy: trusted-local
  credentialProvider: model-api
  model: custom/example-model
  effort: "off"
  pi:
    provider: custom
    baseUrl: https://models.example.test/v1
    api: openai-completions
    models:
      - id: example-model
        contextWindow: 128000
        maxTokens: 8192
    compat:
      supportsDeveloperRole: false
      supportsReasoningEffort: false
```

Kubernetes uses the same fields under `spec.runtime`, with `type: pi` instead
of `preset: pi`. AgentSchedule profiles use that same typed runtime plus
`agentRuntimeConfig: {command: pi}`. Producers select the profile/workflow and
supply the task through the existing run request contract. Repository account
and credential-provider selections stay separate from `runtime.credentialProvider`.

For local runs, declare the existing static-token provider (`plugin: token`):

```yaml
secrets:
  model-key: {file: ./.nvt-local/secrets/model-api-key}
brokerProviders:
  model-api:
    plugin: token
    config:
      injection-hosts: [models.example.test]
    secrets:
      token-file: model-key
    mediation:
      hosts: [models.example.test]
      materialization: header-inject
```

Store the key in that private file with mode `0600`. Compilation does not read
it; the existing private-input mechanism mounts it only in the broker. Do not
put a real key in the manifest, runtime environment, arguments, Pi configuration,
or extension source. The generated model grant permits only `injection.headers`;
it gives the agent neither raw-token nor file-bundle access.

The Helm example reuses `broker.persistence.seedSecretName` to import a
Kubernetes Secret into the broker's private `/state/model-api/key`. The seed is
mounted read-only at mode `0400`; the broker's existing seed supervisor handles
updates. The [Secret example](../examples/pi/secret.example.yaml) contains a
fake value. In a deployment, provision the Secret through the administrator's
secret manager. No real key belongs in Helm values or a generated ConfigMap.

Kubernetes runs need this explicit grant:

```yaml
broker:
  grants:
    - provider: model-api
      repositories: []
      materialization: header-inject
      egressHosts: [models.example.test:443]
```

The existing broker configuration must define that provider and its destination
ceiling. Missing bindings, unsupported materialization, direct/redirect egress,
and endpoint/grant mismatches fail validation. Broker authorization also checks
provider existence and destination permission at request time.

Pi receives only `NVT-PLACEHOLDER-NOT-A-KEY`. Its HTTPS proxy URL explicitly
selects the provider; egressd strips the placeholder and injects the bearer key.
Pi 0.85.1's Undici fetch dispatcher honors the proxy and `NODE_EXTRA_CA_CERTS`
installed by NVT's existing CA bootstrap. NVT clears Pi's `NO_PROXY` bypass
list. TLS verification stays enabled on both legs. There is no retry to a direct
endpoint after proxy or TLS failure. API authentication errors and rate limits
surface through Pi's normal error/retry behavior.

Host grants authorize mediated credential use. A model selector or host ceiling
does **not** enforce per-model, billing, or inference-only authorization.
Local Compose provides credential non-possession but has no Kubernetes CNI
fence; use enforced egress and an enforcing CNI for network isolation. The
example AgentRun requests enforcement. RuntimeClass selection is unchanged.

## Managed public configuration

`runtime.pi` is a small public schema, not an import of Pi's `models.json`:

- One named provider, one HTTPS endpoint on port 443, and 1–128 models.
- `api`: `openai-completions` or `openai-responses`. The automated terminal/tool
  compatibility fixture exercises `openai-completions`.
- Each model accepts `id`, `name`, `reasoning`, `contextWindow`, and `maxTokens`.
  `model` must identify a catalog entry as `provider/id`.
- `effort`: `off`, `minimal`, `low`, `medium`, `high`, or `xhigh`; omission uses
  `off`. Both fresh and resumed launches receive the typed selection.
- Boolean `compat` entries: `supportsStore`, `supportsDeveloperRole`,
  `supportsReasoningEffort`, `supportsUsageInStreaming`, `requiresToolResultName`,
  `requiresAssistantAfterToolResult`, `requiresThinkingAsText`, `supportsStrictMode`.
- Boolean `settings`: `hideThinkingBlock`, `collapseChangelog`, `showHardwareCursor`.
- Optional `extensions`: up to 32 `{name, content}` assets; names must be simple
  `.ts`, `.js`, or `.mjs` filenames, and each source is limited to 64 KiB.

Credential fields (`apiKey`, `oauth`, auth files), arbitrary headers, shell/env
credential resolution, URL userinfo/query/fragment/interpolation, unknown settings,
and raw launch/resume/environment overrides are rejected. No credential-resolution
command runs during compilation. All supplied text must be public; validation
cannot identify a secret disguised as an ordinary model name or executable source.

An explicit client extension can modify only the selected Pi instance:

```yaml
pi:
  # provider, baseUrl, api and models as above
  extensions:
    - name: compatibility.ts
      content: |
        export default function(pi) {
          pi.on("before_agent_start", async (event) => ({
            systemPrompt: event.systemPrompt + "\nFollow the configured client conventions."
          }));
        }
```

Extensions execute as workload code. They are not a security boundary and must
contain no credentials. They must be self-contained or use dependencies already
in the image; startup does not fetch extension packages.

Each bootstrap rewrites the NVT-owned `pi/agent/models.json`, `settings.json`,
and empty `auth.json` beneath `NVT_STATE_DIR`. It replaces extension assets and
removes deselected ones. An existing user Pi home is never copied or mounted.
Declarative updates take effect at the next normal workstation reconciliation/
restart, preserving `pi/session.jsonl`; stale preseeded settings cannot override
new intent. Interactive edits to managed settings/auth files are not durable
configuration and are replaced at bootstrap.

## Autonomy, guidance, and lifecycle

Pi has no built-in sandbox or tool-approval mode. NVT supports it only with
`trusted-local`; `approval-required` locally and `interactive` in Kubernetes
are errors. Isolation comes from NVT's runtime/container and enforced egress.
Pi's `--approve` concerns project resource trust, not tool approvals.

NVT uses `--no-approve` to ignore project-local Pi settings and executable
resources without an interactive trust dialog. Automatic extension, skill,
prompt-template, and theme discovery is disabled. Explicit managed extensions
still load. NVT explicitly appends the generated workspace `AGENTS.md`, including
`AGENTS.local.md` and profile/workflow guidance. Exported plugin tools remain on
PATH. Quiet startup and `PI_SKIP_VERSION_CHECK=1` avoid startup update checks;
managed settings contain no package-install declarations.

The terminal attaches through the existing gateway/code-server NVT terminal
extension. Initial tasks are arguments only on fresh launches. Later agentd
prompts use tmux bracketed paste plus Enter, including multiline input. Pi queues
steering input received while busy; Escape interrupts generation. The same
explicit `NVT_STATE_DIR/pi/session.jsonl` is opened on resume, so no global
last-session search can select another workstation's conversation. State dirs
must remain scoped to their existing run/workstation persistence boundary.
Watcher and `nvt-work complete`/`fail` workflows keep their existing contracts.

## Verification

Run the standard localplatform, protocol/resolvedrun, operator, tests/runtime,
tests/agentd, tests/broker and egressd Go suites, plus
`bash tests/operator/helm/test.sh`. The actual Pi proof is deliberately explicit
so a missing binary cannot be mistaken for integration coverage:

```sh
npm install --prefix /tmp/nvt-pi-test --no-audit --no-fund \
  @earendil-works/pi-coding-agent@0.85.1
(cd egressd && go build -o /tmp/nvt-pi-test/egressd ./cmd/egressd)
NVT_PI_TEST_BINARY=/tmp/nvt-pi-test/node_modules/.bin/pi \
NVT_PI_TEST_EGRESSD=/tmp/nvt-pi-test/egressd \
  python3 tests/pi/compatibility.py

docker build -f runtime/Dockerfile -t nvt-agent-runtime:pi-test .
bash tests/pi/container-smoke.sh
```

The first proof uses real Pi, isolated tmux, agentd, broker and egressd processes
with a mock TLS API and fake keys. It checks streaming/tool completion, multiline
paste, busy followups, interruption, restart without task replay, public config
updates, explicit extensions, credential denial/non-possession, upstream 401/429,
wrong CA, denied destinations, missing keys, and a failed proxy. The second boots
the full runtime image and exercises the existing gateway workbench/WebSocket
proof. Neither uses a live backend or changes an existing workstation.

Upstream contracts: [models](https://github.com/earendil-works/pi/blob/v0.85.1/packages/coding-agent/docs/models.md),
[security](https://github.com/earendil-works/pi/blob/v0.85.1/packages/coding-agent/docs/security.md),
[sessions](https://github.com/earendil-works/pi/blob/v0.85.1/packages/coding-agent/docs/sessions.md).
