# nvt-local-controller

`nvt-local-controller` is the trusted, provider-neutral lifecycle state service
for local resolved agent runs. This child implementation owns only the API,
SQLite state machine, deadlines, retention, and optimistic reconciliation
leases. It deliberately has no Docker socket and creates no execution resource.

Build the non-root image from the repository root:

```sh
make local-controller-build
```

`compose.infra.yaml` runs the image with a durable named state volume on the
internal `local-control-plane` network. It has no host port and is not reachable
from agent containers. See [the protocol](../protocol/local-controller.md) for
the complete API, state, recovery, and trust contracts.

Run focused checks with:

```sh
cd localcontroller
go vet ./...
go test -race -count=1 ./...
```
