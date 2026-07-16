# Local kind Codex Auth

This is POC/local-dev support for running a real Codex `AgentRun` in kind. The
helper filters the current local Codex auth directory into a small Kubernetes
Secret. It is not a production auth model; production may use API keys or
another Secret provisioning path later.

Create or refresh the Secret:

```sh
make operator-codex-auth-secret
```

Defaults:

```text
SOURCE=$HOME/.codex
CODEX_AUTH_SOURCE=$SOURCE
NAMESPACE=nvt
SECRET=codex-auth
CODEX_AUTH_SECRET=$SECRET
CLUSTER=nvt-smoke
KUBECTL_CONTEXT=kind-$(CLUSTER)
```

Override any value as needed:

```sh
make operator-codex-auth-secret \
  CODEX_AUTH_SOURCE=$HOME/.nvt/k8s-auth/codex \
  CODEX_AUTH_SECRET=codex-auth \
  NAMESPACE=nvt \
  CLUSTER=nvt-smoke
```

The older `SOURCE` and `SECRET` variables are still accepted for compatibility,
but `CODEX_AUTH_SOURCE` and `CODEX_AUTH_SECRET` are preferred.

The helper fails if `CODEX_AUTH_SOURCE` is not an existing directory. It copies
only these required files into a script-owned temporary directory:

```text
auth.json
config.toml
installation_id
```

`installation_id` is required because the tested real Codex kind flow used it
with `auth.json` and `config.toml` as the minimal auth/config set. The helper
does not include logs, SQLite state, sessions, cache, skills, shell snapshots,
history, tmp files, or other mutable runtime data.

The helper applies the Secret with the filtered directory:

```sh
kubectl create secret generic "$CODEX_AUTH_SECRET" --from-file="$filtered_dir" --dry-run=client -o yaml |
  kubectl --context "$KUBECTL_CONTEXT" -n "$NAMESPACE" apply -f -
```

Do not manually create the Secret from the whole `$HOME/.codex` directory. It
can contain large mutable logs, SQLite files, caches, sessions, and other state
that can exceed Kubernetes Secret limits and should not be copied into the
cluster.

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
auxiliary files under `~/.codex`. Runtime auth is not mounted into the
Docker-in-Docker daemon service and is separate from broker Secrets.

See `operator/examples/agentrun-codex-kind.yaml` for a minimal local kind
example.
