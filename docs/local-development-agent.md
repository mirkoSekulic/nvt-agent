# Native local workstations

The local backend is reproduced from one non-secret `nvt.local.yaml`, optional
files beneath `.nvt-local/`, and broker-managed OAuth enrollment. Generated
configuration, identities, admission credentials, databases, workspaces,
runtime homes, Docker data, and sessions live in exactly labeled Docker
volumes. There is no generated host Compose file or local `.env` file.

## Configure and start

```sh
cp nvt.local.example.yaml nvt.local.yaml
make local-images
make local-init
make local-up
make local-status
```

Open `http://localhost:4090/agents`. A workstation keeps its `/workspace`,
runtime home, nested Docker data, and agent session across controller, Docker,
Docker Desktop, and laptop restarts. The runtime resumes through its existing
generic resume command.

The complete schema and example are in
[`protocol/local-manifest.md`](../protocol/local-manifest.md) and
[`localplatform/manifest/testdata/valid.yaml`](../localplatform/manifest/testdata/valid.yaml).
Instruction files may be organized anywhere below the manifest directory.
Secret inputs must be regular, current-user-owned files below
`.nvt-local/secrets/`, with mode `0600` or stricter:

```sh
install -d -m 0700 .nvt-local/secrets/github
install -m 0600 /safe/source/main-app.pem .nvt-local/secrets/github/main-app.pem
```

Declaring a Codex or Claude OAuth account enables **Manage credentials** in the
gateway. Enroll it there; the broker imports it into canonical private storage.

## Lifecycle

- `make local-init` validates and compiles the manifest, resolves inputs, and
  creates or adopts only exact-labeled state without starting the platform.
- `make local-up` reconciles state and starts the control plane, portal,
  persistent workstations, and configured producers.
- `make local-status` reports control-plane, producer, and workstation state.
- `make local-down` stops exact-owned containers while preserving volumes,
  credentials, databases, workspaces, and sessions.
- `make local-reset` explicitly removes only resources carrying the complete
  expected local-platform or local-controller ownership labels. It destroys
  credentials and workstation state, including anonymous Docker volumes
  attached to those verified containers.

Removing a workstation from the manifest is non-destructive. Immutable drift
for an existing workstation fails closed.

## Clean-break upgrade

There is no compatibility fallback or automatic migration from the former
local layout.

1. Preserve externally supplied PEM or PAT files you still need.
2. Create `nvt.local.yaml` and copy those files into private paths below
   `.nvt-local/secrets/`.
3. Run `make local-images local-init local-up`, then enroll Codex or Claude
   OAuth credentials through **Manage credentials**.
4. Verify workstations and producers, then explicitly remove the old local
   containers and volumes with the old checkout's Compose teardown. After
   preserving any externally supplied files you still need, remove the legacy
   `.broker/` directory. The new lifecycle never reads, adopts, or deletes
   those resources for you.

## Troubleshooting

- Missing, permissive, oversized, symlinked, or escaping inputs fail before
  trusted services start. Fix the named input and rerun `local-init`.
- `managed volume ownership conflict` means a same-name Docker volume lacks
  the complete expected label map. It is never adopted or deleted.
- An OAuth-backed broker may remain unready until its portal slot is enrolled;
  the gateway and portal remain available for enrollment.
- Do not prune labeled volumes when testing restart/resume behavior.
