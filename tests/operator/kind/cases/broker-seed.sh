#!/usr/bin/env bash

# Broker seed reconciliation smoke. It updates an ordinary Kubernetes Secret
# and proves the existing broker Pod imports the new generation without a
# rollout, exec, PVC edit, or Kubernetes API access from the broker.

case_validate_config() {
  BROKER_SEED_TIMEOUT_SECONDS="${BROKER_SEED_TIMEOUT_SECONDS:-180}"
  require_positive_integer BROKER_SEED_TIMEOUT_SECONDS "${BROKER_SEED_TIMEOUT_SECONDS}"
}

case_render() {
  validate_chart_render \
    --set broker.persistence.enabled=true \
    --set broker.persistence.seedSecretName=broker-seed \
    --set broker.persistence.seedTargetDir=credentials
}

case_kind_setup() {
  make -C "${ROOT}" CLUSTER="${CLUSTER}" CREATE_CLUSTER="${CREATE_CLUSTER}" operator-kind-cluster
  make -C "${ROOT}" broker-build operator-build
  kind load docker-image nvt-broker:latest --name "${CLUSTER}"
  kind load docker-image nvt-operator:latest --name "${CLUSTER}"

  kubectl_smoke create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl_smoke apply -f -
  kubectl_smoke apply -f - <<YAML
apiVersion: v1
kind: PersistentVolume
metadata:
  name: nvt-broker-seed-${CLUSTER}
spec:
  capacity:
    storage: 1Gi
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Delete
  storageClassName: nvt-broker-seed
  hostPath:
    path: /var/local/nvt-broker-seed-${CLUSTER}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: nvt-broker-seed-state
  namespace: ${NAMESPACE}
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: nvt-broker-seed
  volumeName: nvt-broker-seed-${CLUSTER}
  resources:
    requests:
      storage: 1Gi
---
apiVersion: v1
kind: Secret
metadata:
  name: broker-seed
  namespace: ${NAMESPACE}
type: Opaque
stringData:
  credential.json: seed-generation-a
YAML

  helm upgrade --install nvt "${ROOT}/charts/nvt" \
    --kube-context "${KUBECTL_CONTEXT}" \
    -n "${NAMESPACE}" \
    --timeout "${ROLLOUT_TIMEOUT}" \
    --wait \
    --set broker.image.repository=nvt-broker \
    --set broker.image.tag=latest \
    --set broker.tls.enabled=false \
    --set broker.persistence.enabled=true \
    --set broker.persistence.existingClaim=nvt-broker-seed-state \
    --set broker.persistence.seedSecretName=broker-seed \
    --set broker.persistence.seedTargetDir=credentials \
    --set operator.image.repository=nvt-operator \
    --set operator.image.tag=latest
}

case_run() {
  local pod pod_uid restart_count
  pod="$(kubectl_smoke get pod -n "${NAMESPACE}" -l app.kubernetes.io/name=nvt-broker -o jsonpath='{.items[0].metadata.name}')"
  pod_uid="$(kubectl_smoke get pod "${pod}" -n "${NAMESPACE}" -o jsonpath='{.metadata.uid}')"
  restart_count="$(kubectl_smoke get pod "${pod}" -n "${NAMESPACE}" -o jsonpath='{.status.containerStatuses[0].restartCount}')"

  verify_broker_seed_generation initial seed-generation-a

  log "updating the mounted broker seed Secret without rolling the Deployment"
  kubectl_smoke create secret generic broker-seed \
    -n "${NAMESPACE}" \
    --from-literal=credential.json=seed-generation-c \
    --dry-run=client -o yaml | kubectl_smoke apply -f -

  verify_broker_seed_generation changed seed-generation-c
  kubectl_smoke wait --for=condition=Ready "pod/${pod}" -n "${NAMESPACE}" --timeout="${BROKER_SEED_TIMEOUT_SECONDS}s"

  local current_uid current_restart_count
  current_uid="$(kubectl_smoke get pod "${pod}" -n "${NAMESPACE}" -o jsonpath='{.metadata.uid}')"
  current_restart_count="$(kubectl_smoke get pod "${pod}" -n "${NAMESPACE}" -o jsonpath='{.status.containerStatuses[0].restartCount}')"
  [[ "${current_uid}" == "${pod_uid}" ]] || die "broker Pod was replaced during seed reconciliation"
  [[ "${current_restart_count}" == "${restart_count}" ]] || die "broker container restarted instead of supervising its child"

  local reconciliations
  reconciliations="$(kubectl_smoke logs "pod/${pod}" -n "${NAMESPACE}" | grep -c 'seed generation changed; broker restarting' || true)"
  [[ "${reconciliations}" -ge 2 ]] || die "broker did not report both initial and changed seed generations"
}

verify_broker_seed_generation() {
  local suffix="$1"
  local expected="$2"
  local job="broker-seed-verify-${suffix}"
  kubectl_smoke delete job "${job}" -n "${NAMESPACE}" --ignore-not-found >/dev/null
  kubectl_smoke apply -f - <<YAML
apiVersion: batch/v1
kind: Job
metadata:
  name: ${job}
  namespace: ${NAMESPACE}
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: verify
          image: nvt-broker:latest
          imagePullPolicy: IfNotPresent
          env:
            - name: EXPECTED_GENERATION
              value: ${expected}
            - name: VERIFY_TIMEOUT_SECONDS
              value: "${BROKER_SEED_TIMEOUT_SECONDS}"
          command:
            - python3
            - -c
            - |
              import os, pathlib, sys, time
              deadline = time.monotonic() + int(os.environ["VERIFY_TIMEOUT_SECONDS"])
              path = pathlib.Path("/state/credentials/credential.json")
              while time.monotonic() < deadline:
                  try:
                      if path.read_text(encoding="utf-8") == os.environ["EXPECTED_GENERATION"]:
                          raise SystemExit(0)
                  except OSError:
                      pass
                  time.sleep(0.2)
              raise SystemExit(1)
          volumeMounts:
            - name: state
              mountPath: /state
              readOnly: true
      volumes:
        - name: state
          persistentVolumeClaim:
            claimName: nvt-broker-seed-state
            readOnly: true
YAML
  if ! kubectl_smoke wait --for=condition=Complete "job/${job}" -n "${NAMESPACE}" --timeout="${BROKER_SEED_TIMEOUT_SECONDS}s"; then
    kubectl_smoke logs "job/${job}" -n "${NAMESPACE}" >&2 || true
    die "broker seed generation ${suffix} was not imported"
  fi
}
