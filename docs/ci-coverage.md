# CI coverage map

This repository now splits CI into domain workflows so path filters stay
precise and every hermetic suite has a clear home.

## go.mod inventory

- `captured/go.mod` → `network.yml / captured`
- `egressd/go.mod` → `network.yml / egressd`
- `gateway/go.mod` → `kubernetes.yml / gateway`
- `localcontroller/go.mod` → `local-controller.yml / controller`
- `protocol/localroutes/go.mod` → `local-controller.yml / contract`
- `hostbundle/go.mod` → `host-bundle.yml / host-bundle`
- `protocol/guestenrollment/go.mod` → `kubernetes.yml / guest-enrollment`,
  including the real-yamux native workspace contract/conformance package
- `operator/go.mod` → `kubernetes.yml / operator` and `kubernetes.yml / operator-helm`
- `executiondrivers/qemu/go.mod` → `qemu.yml / real-guest-e2e` and
  `images.yml / build (qemu-execution-driver)`; both build the unpublished
  test/reference image locally
- `producers/github-comments/go.mod` → `kubernetes.yml / producer`
- `tests/agentd/go.mod` → `runtime.yml / agentd`
- `tests/broker/go.mod` → `broker.yml / broker`
- `tests/fixtures/echo/go.mod` → `images.yml / build`
- `tests/runtime/go.mod` → `runtime.yml / runtime`

## Suite inventory

### runtime

- `tests/runtime/agent_copy_test.go`
- `tests/runtime/broker_agents_test.go`
- `tests/runtime/broker_auth_files_test.go`
- `tests/runtime/compose_agent_test.go`
- `tests/runtime/event_webhook_test.go`
- `tests/runtime/git_host_credentials_test.go`
- `tests/runtime/github_watcher_test.go`
- `tests/runtime/initial_prompt_test.go`
- `tests/runtime/lifecycle_termination_test.go`
- `tests/runtime/mediated_admission_test.go`
- `tests/runtime/mediated_smoke_test.go`
- `tests/runtime/placeholder_file_test.go`
- `tests/runtime/plugin_exports_test.go`
- `tests/runtime/smoke_complete_test.go`
- `tests/runtime/compose-transparent-smoke.sh` → `network.yml / transparent-smoke`
- `tests/runtime/dind-bridge-capture-smoke.sh` → `network.yml / transparent-smoke`
  through the Compose smoke; its own path is also a workflow trigger.
- `tests/runtime/kind-required-network-smoke.sh` → `runtime.yml` job
  `required-docker-network`. The smoke exercises the production DinD
  entrypoint, so the job builds the `nvt-dind` image (`make dind-build`) before
  running it, and `runtime.yml` includes `dind/**` in its path filters.

### agentd

- `tests/agentd/agentd_conformance_test.go`

### broker

- `tests/broker/broker_conformance_test.go`
- `tests/broker/claude_auth_conformance_test.go`
- `tests/broker/claude_refresh_conformance_test.go`
- `tests/broker/injection_conformance_test.go`
- `tests/broker/injection_git_conformance_test.go`
- `tests/broker/injection_report_conformance_test.go`
- `tests/broker/placeholder_config_validation_test.go`
- `tests/broker/placeholder_file_conformance_test.go`
- `tests/broker/guest_enrollment_conformance_test.go` → real broker process,
  durable restart, dedicated authorization, strict bounds, replay, and
  execution-scope cleanup.
- `tests/broker/guest_enrollment_unit_test.go` → transactional SQLite issuer,
  pre/post-commit faults, capacity/GC, identity expiry, and redaction.

### operator

- `operator/executiondriver/conformance_test.go`
- `operator/executiondriver/host/host_test.go`
- `operator/executiondriver/hostapi/hostapi_test.go`
- `operator/executiondriver/registration/registration_test.go`
- `operator/executiondriver/protocol_test.go`
- `operator/config/broker/broker_manifest_test.go`
- `operator/internal/controller/agentrun_callback_test.go`
- `operator/internal/controller/agentrun_controller_test.go`
- `operator/internal/controller/agentschedule_controller_test.go`
- `operator/internal/controller/default_egress_mode_test.go`

### guest enrollment

- `protocol/guestenrollment/contract_test.go` → strict versioned types,
  bounds, UTF-8/duplicate-key rejection, token-digest handling, and redacted
  sensitive formatting.
- `protocol/guestenrollment/conformance_test.go` → durable fake issuer/guest
  exchange, exact binding, execution-scoped restart cleanup, concurrent single
  use, pre/post-commit fault injection, replay, expiry, bounded revocation
  tombstones, cancellation, capacity, and secret non-disclosure.
- `protocol/guestenrollment/runtime_identity_test.go` and
  `runtime_identity_conformance_test.go` → strict runtime status/rotation
  framing, digest-only identity handling, exact binding, single-winner CAS,
  predecessor replay denial, restart/lost-response recovery, expiry,
  revocation, and redaction.
- `protocol/guestenrollment/session_identity_test.go` and
  `session_identity_conformance_test.go` → fixed-audience session issuance and
  authentication, exact binding, bounded concurrent/lost-response reissue,
  restart, expiry, revocation, strict framing, and sensitive formatting.
- `protocol/guestenrollment/native_session_test.go` → strict outbound hello,
  exact binding/audience, local credential IPC framing, recursive duplicate-key
  rejection, message bounds, and redacted sensitive formatting.
- `broker/core/guest_enrollment_test.py` and
  `tests/broker/guest_enrollment_conformance_test.go` → the SQLite and real HTTP
  implementations of runtime-identity and guest-session authority, including
  transaction fault points, durable restart, authorization separation,
  per-credential admission bounds, cleanup, and plaintext canary scans.
- `hostbundle/guestidentity` → the native root-only client/store/state machine:
  strict TLS and files, initial exchange, status, scheduled rotation,
  successor-first ambiguous-response recovery, restart, revocation/expiry,
  atomic persistence faults, root-peer-only session credential IPC, bounds,
  and redacted output.
- `hostbundle/nativesession` → fixed-audience credential issuance, direct TLS
  establishment, bounded JSONL/agentd relay, reconnect/renewal, first-response
  loss, gateway denial, absolute framing deadlines, readiness, and redaction.

The `kubernetes.yml / operator-helm` job also runs the shell-level chart and
helper coverage aggregated by `tests/operator/helm/test.sh`:

- `tests/operator/broker-env-secret/test.sh`
- `tests/operator/codex-auth-secret/test.sh`
- `tests/operator/github-comments-producer-secret/test.sh`
- `tests/operator/kind/producer-kind-targets-test.sh`
- `tests/operator/kind/smoke-scheduler-job-test.sh`

### gateway

- `gateway/internal/gateway/server_test.go`

### local controller

- `protocol/localroutes` strict route/readiness metadata contract and bounds →
  `local-controller.yml / contract`
- `localcontroller/internal/controller` API-audience separation, scheduling,
  durable SQLite state, idempotency, concurrency, cancellation, TTL, restart,
  lifecycle cursor, and secret-safe response tests →
  `local-controller.yml / controller`
- `localcontroller/internal/dockerbackend` deterministic rendering, exact
  ownership, retry/cleanup, gateway availability and identity separation,
  network isolation, restart/resume, lifecycle observation, and secret-scan
  tests → `local-controller.yml / controller`

### producer

- `producers/github-comments/internal/producer/agentrun_test.go`
- `producers/github-comments/internal/producer/command_test.go`
- `producers/github-comments/internal/producer/config_test.go`
- `producers/github-comments/internal/producer/github_test.go`
- `producers/github-comments/internal/producer/idempotency_test.go`
- `producers/github-comments/internal/producer/poller_test.go`
- `producers/github-comments/internal/producer/prompt_test.go`
- `producers/github-comments/internal/producer/state_test.go`

### egressd

- `egressd/cmd/egress-ca-init/main_test.go`
- `egressd/internal/egress/ca_test.go`
- `egressd/internal/egress/config_forward_proxy_test.go`
- `egressd/internal/egress/destination_policy_test.go`
- `egressd/internal/egress/forward_proxy_mitm_test.go`
- `egressd/internal/egress/forward_proxy_test.go`
- `egressd/internal/egress/git_http_test.go`
- `egressd/internal/egress/proxy_test.go`
- `egressd/internal/egress/quota_test.go`
- `egressd/internal/egress/reporter_test.go`

### captured

- `captured/internal/capture/server_test.go`

### images

- `tests/runtime/git_credentials_smoke.sh` → `images.yml / build` (runtime
  matrix entry)
- `runtime/branding/test.sh` → runtime-focused local/unit validation
- `tests/runtime/code-server-branding-smoke.sh` → `images.yml / build`
  (runtime matrix entry, against the image built by that job)
- `dind/test.sh` and `tests/runtime/dind-kmsg-device-smoke.sh` → `images.yml / build`
  (DinD matrix entry; the integration smoke runs against the image built by
  that job)
- `tests/operator/execution-driver-host-image-smoke.sh` → `images.yml / build`
  (the host matrix entry copies the coordinated static host into the complete
  fake provider image and exercises authenticated protocol traffic)
- `nativeegressrelay/image-test.sh` → `images.yml / build` (the coordinated
  non-root relay image contains the static command and no shell, package
  manager, Git, or Go toolchain)
- `localcontroller/Dockerfile` → `images.yml / build (local-controller)`; the
  trusted controller binary and its local protocol replacement modules are
  compiled in the shipped Docker context.

### native host bundle

- `hostbundle/contract`, `bundle`, `oci`, and `install` adversarial tests →
  `host-bundle.yml / host-bundle`
- `hostbundle/guest_e2e_test.go` → `host-bundle.yml / host-bundle`; it builds an
  OCI layout, runs the real bootstrap CLI against a hermetic TLS registry by
  digest, installs and activates natively, starts the installed supervisor and
  real `agentd`, exchanges and rotates a synthetic-TLS-broker runtime identity
  through the installed root-owned daemon, requests a short-lived session
  credential over the real root-only socket, establishes and restarts the
  installed outbound client against a TLS fake gateway, relays agentd traffic,
  delivers a prompt, proves fail-closed session loss, and proves idempotent
  reuse. This is guest-side Linux coverage, not a production gateway proof.
- `hostbundle/build-test.sh` → `host-bundle.yml / build-contract (ubuntu-latest,
  macos-latest)`; it pins cleaned repository-relative and absolute outputs,
  deterministic tar/layout content, and non-empty/root output rejection using
  each platform's standard shell tooling.

### QEMU reference driver

- `executiondrivers/qemu/internal/config` and `internal/driver` → focused
  strict-configuration, idempotency, drift/restart, enrollment-handoff,
  cancellation, and cleanup tests under `-race`.
- `executiondrivers/qemu/image-smoke.sh` → `images.yml / build
  (qemu-execution-driver)`; it verifies the baked guest checksum and boots the
  packaged Linux guest under TCG through real JSONL initialization/reconcile.
  This is a local CI image, not a coordinated product publication.
- `tests/operator/kind/cases/qemu-external-execution.sh` → `qemu.yml /
  real-guest-e2e`; it boots an actual amd64 Linux guest under bounded TCG,
  performs production broker one-time enrollment, pulls and activates the real
  digest-pinned host bundle, performs a real runtime-identity rotation, obtains
  and authenticates a short-lived session credential against a synthetic TLS
  gateway, reaches real identity-daemon/session-daemon/supervisor/agentd/tmux
  readiness, restarts the driver
  host, and proves QEMU disk/process/state cleanup. It is a
  hermetic reference-provider proof, not a production gateway or mediated-VM
  networking claim.

### Azure execution driver

- `executiondrivers/azure/internal/config`, `internal/template`, and
  `internal/driver` -> strict class configuration, pinned Bicep/ARM identity,
  fake ARM/LRO convergence, lost-response recovery, protected handoff,
  confinement read-back, collision, restart, and exact deletion tests under
  `-race`.
- `executiondrivers/azure/image-test.sh` -> `images.yml / build
  (azure-execution-driver)`; it verifies the coordinated non-root image has the
  driver and repository-owned bootstrap input but no shell, Azure CLI, Bicep,
  Terraform, Git, or build tool. Live Azure is intentionally opt-in and absent
  from CI.

### kind workflow case files

`kind.yml` uses a PR tier for the three fast/representative cases and a full
matrix for `workflow_dispatch` and the nightly schedule.

- `tests/operator/kind/cases/mediated-egress.sh`
- `tests/operator/kind/cases/enforced-egress.sh`
- `tests/operator/kind/cases/transparent-egress.sh`
- `tests/operator/kind/cases/quota-egress.sh`
- `tests/operator/kind/cases/revocation.sh`
- `tests/operator/kind/cases/parallel-lifecycle.sh`

The harness and helper scripts are not standalone cases:

- `tests/operator/kind/smoke.sh`
- `tests/operator/kind/lib.sh`
- `tests/operator/kind/kind-command.sh`
- `tests/operator/kind/cases/forward-proxy-egress.sh`
- `tests/operator/kind/smoke-scheduler-job.sh`
- `tests/operator/kind/smoke-scheduler-job-test.sh`
- `tests/operator/kind/producer-kind-targets-test.sh`
- `tests/operator/kind/agentrun-payload.py`
- `tests/operator/kind/kind-calico.yaml`

## Manual-only checks

- `make codex-mediated-proof` is manual only because it requires real Codex
  host credentials and is explicitly excluded from CI. It gates on a real
  mediated turn plus a credential non-possession scan; it does not force a
  token refresh and reports refresh as unproven. See
  [Codex authentication](codex-auth.md).
- Any real OAuth / GitHub credential proof remains manual because it depends on
  private secrets and external account state that CI must not possess.

## Workflow summary

- `runtime.yml`: agentd and runtime conformance suites plus the nested kind
  required-Docker-network smoke
- `broker.yml`: broker conformance suite
- `network.yml`: egressd, captured, and transparent Compose smoke
- `kubernetes.yml`: operator, gateway, producer, and Helm/shell coverage
  plus the provider-neutral guest-enrollment and native-workspace yamux
  contract/conformance packages
- `local-controller.yml`: shared local-route contract plus local-controller
  API, persistence, reconciliation, Docker ownership, isolation, and cleanup
  coverage
- `images.yml`: shipped images, including the coordinated native-egress relay,
  plus local test/reference and fixture images,
  the runtime git-credentials smoke, and the execution-driver host's private
  enrollment-handoff smoke
- `host-bundle.yml`: native bundle trusted-core tests and guest-side lifecycle
  E2E
- `kind.yml`: mediated, enforced, transparent, quota, revocation, and
  parallel-lifecycle kind cases
- `qemu.yml`: digest-pinned QEMU reference driver plus real TCG guest lifecycle
