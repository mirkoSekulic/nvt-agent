# nvt-local-controller

`nvt-local-controller` is the trusted, provider-neutral lifecycle controller
for local resolved agent runs. It owns the API, SQLite state machine, deadlines,
retention, optimistic reconciliation leases, and the Docker backend that
materializes a deterministic per-run stack.

Build the trusted control-plane image from the repository root:

```sh
make local-controller-build
```

`compose.infra.yaml` runs the image with a durable named state volume on the
internal `local-control-plane` network. The trusted controller alone receives
the host Docker socket and broker registry/key mount; it has no host port and is
not reachable from agent containers. Generated agent stacks use named resources
and never receive the host socket. See [the protocol](../protocol/local-controller.md)
for the complete API, state, recovery, cleanup, and zero-secret contracts.

Run focused checks with:

```sh
cd localcontroller
go vet ./...
go test -race -count=1 ./...
```

After building the runtime, DinD, broker, egressd, captured, and synthetic echo
images, the opt-in real-engine proof exercises transparent capture, the paired
egress identity, exact synthetic credential injection, and scans generated
Compose, container inspect/environment, logs, and agent files:

```sh
NVT_LOCAL_CONTROLLER_DOCKER_SMOKE=1 \
  go test -count=1 -run '^TestDockerBackendRealEngineSmoke$' ./internal/dockerbackend
```

This proof uses the repository's executable synthetic provider. Real
Codex/Claude account proofs are deliberately separate and non-hermetic.
