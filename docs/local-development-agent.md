# Local development

The local platform is defined by `nvt.local.yaml`, private inputs beneath
`.nvt-local/`, and broker-managed OAuth enrollment. Generated configuration,
credentials, workspaces, Docker data, and sessions live in labeled Docker
volumes. No generated Compose or `.env` file is written to the host.

## Configure and start

```sh
cp nvt.local.example.yaml nvt.local.yaml
make local-images
make local-init
make local-up
make local-status
```

Before `local-init`, replace the example repository and create the referenced
PAT file. NVT scopes injection to that repository; the token's upstream
permissions remain the outer limit.

Open `http://nvt.agent.localhost:4090`. A workstation keeps its `/workspace`,
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
install -m 0600 /safe/source/token .nvt-local/secrets/github/token
```

A PAT is sufficient for workstation and workflow repository access. The
built-in GitHub comments producer uses a GitHub App account instead; see its
[configuration guide](../producers/github-comments/README.md).

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

Removing a workstation from the manifest is non-destructive and immutable
drift fails closed by default. Administrators can opt into Flux-style
convergence with `reconciliation.workstations.prune` and
`replaceOnImmutableChange`. `local-init` previews the enabled policy. If the
controller finds an exact-owned workstation to prune or replace, the apply is
refused unless `ALLOW_DESTRUCTIVE_RECONCILE=1` was supplied to `local-init` or
`local-up`; the refusal lists the exact workstation names and performs no
partial mutation. Producer runs, foreign projects, and unrelated history are
never candidates. Replacement finishes exact-owned container, network,
persistent-volume, broker-registration, and controller cleanup before the new
immutable snapshot becomes runnable.

For an approved in-place workstation reconciliation, the controller compares
the exact egress CA DNS-name set in its previous immutable snapshot with the
trusted desired snapshot. If it changed, the controller stops the agent and
egressd, asks `egress-ca-init` to validate the durable keypair against the old
set, and only then requests rotation in that workstation's private CA volume.
The replacement CA is published before egressd and the agent are recreated;
workspace, runtime-home, Docker-data, enrollment, and unrelated workstation
volumes are not touched. An unchanged set preserves the CA. Missing,
malformed, mismatched, or unexpectedly constrained CA material fails closed
without being treated as ordinary name drift. Repair that material explicitly
or restore the workstation's exact CA volume before retrying.

## Troubleshooting

- Missing, permissive, oversized, symlinked, or escaping inputs fail before
  trusted services start. Fix the named input and rerun `local-init`.
- `managed volume ownership conflict` means a same-name Docker volume lacks
  the complete expected label map. It is never adopted or deleted.
- An OAuth-backed broker may remain unready until its portal slot is enrolled;
  the gateway and portal remain available for enrollment.
- Do not prune labeled volumes when testing restart/resume behavior.
