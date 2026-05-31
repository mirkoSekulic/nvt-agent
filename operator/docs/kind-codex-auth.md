# Local kind Codex Auth

This is POC/local-dev support for running a real Codex `AgentRun` in kind. It
copies the current local Codex auth directory into a Kubernetes Secret. It is not
a production auth model; production may use API keys or another Secret
provisioning path later.

Create or refresh the Secret:

```sh
make operator-codex-auth-secret
```

Defaults:

```text
SOURCE=$HOME/.codex
NAMESPACE=nvt
SECRET=codex-auth
CLUSTER=nvt-smoke
KUBECTL_CONTEXT=kind-$(CLUSTER)
```

Override any value as needed:

```sh
make operator-codex-auth-secret \
  SOURCE=$HOME/.nvt/k8s-auth/codex \
  SECRET=codex-auth \
  NAMESPACE=nvt \
  CLUSTER=nvt-smoke
```

The helper fails if `SOURCE` is not an existing directory. It applies the Secret
with:

```sh
kubectl create secret generic "$SECRET" --from-file="$SOURCE" --dry-run=client -o yaml |
  kubectl --context "$KUBECTL_CONTEXT" -n "$NAMESPACE" apply -f -
```

If local Codex auth changes later, re-run the helper. Kubernetes will not track
future changes to `$HOME/.codex` automatically.

Reference the Secret from an `AgentRun`:

```yaml
spec:
  runtime:
    type: codex
    autonomy: trusted-local
  runtimeAuth:
    secretName: codex-auth
```

For `codex`, the operator defaults the mount path to `/root/.codex`. You can
override it explicitly:

```yaml
spec:
  runtimeAuth:
    secretName: codex-auth
    mountPath: /root/.codex
```

The Secret is mounted read-only into a copy init container, copied into a
writable `emptyDir`, and the writable home is mounted into the agent container
at `/root/.codex`. This lets Codex update state, history, caches, and SQLite
sidecar files under `~/.codex`. Runtime auth is not mounted into the
Docker-in-Docker sidecar and is separate from broker Secrets.

See `operator/examples/agentrun-codex-kind.yaml` for a minimal local kind
example.
