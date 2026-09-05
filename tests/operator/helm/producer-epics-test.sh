#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT
ARGS=(nvt "${ROOT}/charts/nvt" --set producer.enabled=true --set producer.submission.admissionMode=profiled --set producer.epics.enabled=true --set producer.epics.workflow=implement-pr --set producer.submission.scheduleNamespace=work)
helm template "${ARGS[@]}" > "${WORKDIR}/epics.yaml"
python3 - "${WORKDIR}/epics.yaml" <<'PY'
import sys,yaml
resources=list(yaml.safe_load_all(open(sys.argv[1])))
role=next(x for x in resources if x['kind']=='Role' and 'producer' in x['metadata']['name'])
assert role['metadata']['namespace']=='work'
assert role['rules'][0]['verbs']==['get','list']
deployment=next(x for x in resources if x['kind']=='Deployment' and 'producer' in x['metadata']['name'])
assert deployment['spec']['strategy']['type']=='Recreate'
assert deployment['spec']['template']['spec'].get('automountServiceAccountToken',True)
config=next(x for x in resources if x['kind']=='ConfigMap' and 'producer' in x['metadata']['name'])
assert yaml.safe_load(config['data']['config.yaml'])['epics']=={'enabled':True,'workflow':'implement-pr'}
PY
for setting in producer.epics.maxParallel=0 producer.epics.maxParallel=17 producer.epics.maxParallel=1.5 producer.epics.unknown=x producer.epics.workflow=Bad producer.epics.enabled=false producer.replicaCount=2 producer.persistence.enabled=false producer.submission.admissionMode=legacy; do
  if helm template "${ARGS[@]}" --set "${setting}" > "${WORKDIR}/invalid.yaml" 2> "${WORKDIR}/error"; then
    echo "accepted invalid epic configuration: ${setting}" >&2
    exit 1
  fi
done
echo "producer epic Helm contract passed"
