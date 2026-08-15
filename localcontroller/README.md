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
not reachable from agent containers. The network is defense in depth, not the
API authorization boundary: schedule producers, the gateway route reader, and
raw administration use distinct startup-loaded private bearers with disjoint
endpoint audiences. The gateway mounts only its route-reader file; the optional
administrator bearer is retained by the controller and omission disables raw
run management. Generated agent stacks use named resources
and never receive the host socket. Independent named-run and producer-schedule
documents compose without sharing producer bearer material. The optional producer scheduling config maps an
authenticated producer and allowed principal issuers to exact administrator
profile/workflow selections; omission disables scheduling. The gateway consumes
only bounded [local route metadata](../protocol/local-routes.md) and remains the
browser authorization/proxy boundary. Each run's untrusted network namespace is
isolated from the shared proxy bridge and sibling runs; the controller attaches
only the fixed label-verified, running (and, when configured, healthy) gateway
to each run-internal network. Cleanup uses only that fixed identity proof, so a
gateway outage cannot strand exact-owned run resources. See
[the protocol](../protocol/local-controller.md) for the complete API, state,
recovery, cleanup, and zero-secret contracts.

For installation, deterministic translation of existing `nvt-dev`, `studio`,
and `infra` configurations, verification, troubleshooting, and the unchanged
static Compose rollback path, see the
[local controller migration guide](../docs/local-controller-migration.md).

Run focused checks with:

```sh
cd localcontroller
go vet ./...
go test -race -count=1 ./...
```

After building the runtime, DinD, broker, egressd, captured, and synthetic echo
images, the opt-in real-engine proof exercises transparent capture, the paired
egress identity, exact synthetic credential injection, removal/recreation of
the agent container through the generic resume command, retained named state,
an agentd completion event observed from retained state after the agent stops,
lifecycle cleanup, and scans generated Compose, container inspect/environment,
logs, and agent files:

```sh
NVT_LOCAL_CONTROLLER_DOCKER_SMOKE=1 \
  go test -count=1 -run '^TestDockerBackendRealEngineSmoke$' ./internal/dockerbackend
```

This proof uses the repository's executable synthetic provider. Real
Codex/Claude account proofs are deliberately separate and non-hermetic.
