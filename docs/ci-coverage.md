# CI coverage map

This repository now splits CI into domain workflows so path filters stay
precise and every hermetic suite has a clear home.

## go.mod inventory

- `captured/go.mod` → `network.yml / captured`
- `egressd/go.mod` → `network.yml / egressd`
- `gateway/go.mod` → `kubernetes.yml / gateway`
- `operator/go.mod` → `kubernetes.yml / operator` and `kubernetes.yml / operator-helm`
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

### operator

- `operator/config/broker/broker_manifest_test.go`
- `operator/internal/controller/agentrun_callback_test.go`
- `operator/internal/controller/agentrun_controller_test.go`
- `operator/internal/controller/agentschedule_controller_test.go`
- `operator/internal/controller/default_egress_mode_test.go`

The `kubernetes.yml / operator-helm` job also runs the shell-level chart and
helper coverage aggregated by `tests/operator/helm/test.sh`:

- `tests/operator/broker-env-secret/test.sh`
- `tests/operator/codex-auth-secret/test.sh`
- `tests/operator/github-comments-producer-secret/test.sh`
- `tests/operator/kind/producer-kind-targets-test.sh`
- `tests/operator/kind/smoke-scheduler-job-test.sh`

### gateway

- `gateway/internal/gateway/server_test.go`

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

- `make phase6-real-codex-proof` is manual only because it requires real Codex
  host credentials and is explicitly excluded from CI.
- Any real OAuth / GitHub credential proof remains manual because it depends on
  private secrets and external account state that CI must not possess.

## Workflow summary

- `runtime.yml`: agentd and runtime conformance suites
- `broker.yml`: broker conformance suite
- `network.yml`: egressd, captured, and transparent Compose smoke
- `kubernetes.yml`: operator, gateway, producer, and Helm/shell coverage
- `images.yml`: all shipped/test fixture images plus the runtime git-credentials
  smoke
- `kind.yml`: mediated, enforced, transparent, quota, revocation, and
  parallel-lifecycle kind cases
