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
run management. Generated agent stacks use named resources and never receive
the host socket. One strict native YAML document owns reusable profiles,
workflows, backends, retentions, persistent workstations, and optional producer
schedule policy. Both kinds of selection use the same resolver without exposing
internal LocalRun or ResolvedAgentRun values. The gateway consumes
only bounded [local route metadata](../protocol/local-routes.md) and remains the
browser authorization/proxy boundary. Each run's untrusted network namespace is
isolated from the shared proxy bridge and sibling runs; the controller attaches
only the fixed label-verified, running (and, when configured, healthy) gateway
to each run-internal network. Cleanup uses only that fixed identity proof, so a
gateway outage cannot strand exact-owned run resources. See
[the protocol](../protocol/local-controller.md) for the complete API, state,
recovery, cleanup, and zero-secret contracts.

The shared proxy, gateway, broker, and controller restart automatically after
an ordinary Docker daemon or Docker Desktop restart. Enforced transparent
agents cannot race that recovery: their trusted startup gate accepts only a
fresh per-process acknowledgment for the current boot and network namespace.
The controller-owned confinement guard replaces and verifies both ordinary and
nested-Docker capture rules before the runtime entrypoint can run or resume.
On upgrade, a revision label replaces legacy ungated agent containers while
retaining their named data volumes. The nested-daemon smoke covers Linux
dockerd semantics; native Docker Desktop restart remains a platform smoke.
Docker data reset or volume pruning is intentionally outside restart recovery.

For installation, native workstation configuration, operation, and
troubleshooting, see [Native local workstations](../docs/local-development-agent.md).

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

The stronger restart proof uses a disposable nested daemon, restarts dockerd,
checks that the stale proof blocks an adversarial immediate direct request,
then verifies capture reinstallation, generic resume, mediated injection,
stable routes/volumes, proxy recovery, and secret absence:

```sh
NVT_LOCAL_CONTROLLER_DAEMON_RESTART_SMOKE=1 \
  go test -count=1 -run '^TestDockerBackendDaemonRestartSmoke$' ./internal/dockerbackend
```

This proof uses the repository's executable synthetic provider. Real
Codex/Claude account proofs are deliberately separate and non-hermetic.
