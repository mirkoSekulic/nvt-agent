{{- define "nvt.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "nvt.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "nvt.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "nvt.namespace" -}}
{{- default .Release.Namespace .Values.namespace.name -}}
{{- end -}}

{{- define "nvt.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: nvt
{{- end -}}

{{- define "nvt.selectorLabels" -}}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: nvt
{{- end -}}

{{- define "nvt.image" -}}
{{- if not (kindIs "map" .image) -}}
{{- fail (printf "%s must use the 0.2 repository/tag/pullPolicy map; migrate 0.1 scalar image values before upgrading" .name) -}}
{{- end -}}
{{- $defaultTag := default .root.Chart.AppVersion .root.Values.global.imageTag -}}
{{- printf "%s:%s" .image.repository (default $defaultTag .image.tag) -}}
{{- end -}}

{{- define "nvt.validateImageValues" -}}
{{- $images := list
  (dict "name" "runtime.image" "value" .Values.runtime.image)
  (dict "name" "dind.image" "value" .Values.dind.image)
  (dict "name" "egress.egressd.image" "value" .Values.egress.egressd.image)
  (dict "name" "egress.captured.image" "value" .Values.egress.captured.image)
  (dict "name" "broker.image" "value" .Values.broker.image)
  (dict "name" "operator.image" "value" .Values.operator.image)
  (dict "name" "gateway.image" "value" .Values.gateway.image)
  (dict "name" "producer.image" "value" .Values.producer.image) -}}
{{- range $image := $images -}}
{{- if not (kindIs "map" $image.value) -}}
{{- fail (printf "%s must use the 0.2 repository/tag/pullPolicy map; migrate 0.1 scalar image values before upgrading" $image.name) -}}
{{- end -}}
{{- end -}}
{{- if and .Values.global.imageTag (not (regexMatch `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$` .Values.global.imageTag)) -}}
{{- fail "global.imageTag must be a valid immutable container tag" -}}
{{- end -}}
{{- end -}}

{{- define "nvt.runtimeImage" -}}
{{- include "nvt.image" (dict "root" . "name" "runtime.image" "image" .Values.runtime.image) -}}
{{- end -}}

{{- define "nvt.dindImage" -}}
{{- include "nvt.image" (dict "root" . "name" "dind.image" "image" .Values.dind.image) -}}
{{- end -}}

{{- define "nvt.brokerLabels" -}}
{{ include "nvt.labels" . }}
app.kubernetes.io/name: nvt-broker
app.kubernetes.io/component: broker
{{- end -}}

{{- define "nvt.brokerSelectorLabels" -}}
{{ include "nvt.selectorLabels" . }}
app.kubernetes.io/name: nvt-broker
app.kubernetes.io/component: broker
{{- end -}}

{{- define "nvt.operatorLabels" -}}
{{ include "nvt.labels" . }}
app.kubernetes.io/name: nvt-operator
app.kubernetes.io/component: operator
{{- end -}}

{{- define "nvt.operatorSelectorLabels" -}}
{{ include "nvt.selectorLabels" . }}
app.kubernetes.io/name: nvt-operator
app.kubernetes.io/component: operator
{{- end -}}

{{- define "nvt.gatewayLabels" -}}
{{ include "nvt.labels" . }}
app.kubernetes.io/name: nvt-agent-gateway
app.kubernetes.io/component: gateway
{{- end -}}

{{- define "nvt.gatewaySelectorLabels" -}}
{{ include "nvt.selectorLabels" . }}
app.kubernetes.io/name: nvt-agent-gateway
app.kubernetes.io/component: gateway
{{- end -}}

{{- define "nvt.producerName" -}}
{{- default "github-comments-producer" .Values.producer.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "nvt.producerFullname" -}}
{{- if .Values.producer.fullnameOverride -}}
{{- .Values.producer.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" (include "nvt.fullname" .) (include "nvt.producerName" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "nvt.producerLabels" -}}
{{ include "nvt.labels" . }}
app.kubernetes.io/name: {{ include "nvt.producerName" . }}
app.kubernetes.io/component: github-comments-producer
{{- end -}}

{{- define "nvt.producerSelectorLabels" -}}
{{ include "nvt.selectorLabels" . }}
app.kubernetes.io/name: {{ include "nvt.producerName" . }}
app.kubernetes.io/component: github-comments-producer
{{- end -}}

{{- define "nvt.producerServiceAccountName" -}}
{{- if .Values.producer.serviceAccount.create -}}
{{- default (include "nvt.producerFullname" .) .Values.producer.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.producer.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "nvt.producerAgentRunNamespace" -}}
{{- default (include "nvt.namespace" .) .Values.producer.agentRun.namespace -}}
{{- end -}}

{{- define "nvt.producerStateClaimName" -}}
{{- default (printf "%s-state" (include "nvt.producerFullname" .)) .Values.producer.persistence.existingClaim -}}
{{- end -}}

{{- define "nvt.producerPrivateKeyPath" -}}
{{- printf "%s/%s" (.Values.producer.githubApp.privateKeyMountPath | trimSuffix "/") .Values.producer.githubApp.privateKeyKey -}}
{{- end -}}

{{- /*
  Single source of truth for the broker TLS Secret name: a non-empty
  existingSecret wins, otherwise the chart-managed secretName. Every template
  that references the broker TLS Secret must use this helper so the broker
  can never serve one Secret while the operator projects another.
*/ -}}
{{- define "nvt.brokerTLSSecretName" -}}
{{- default .Values.broker.tls.secretName .Values.broker.tls.existingSecret -}}
{{- end -}}

{{- /*
  The chart-managed broker TLS Secret data (base64 values, JSON-encoded):
  an already-issued Secret is preserved via lookup so the trust anchor is
  stable across upgrades; otherwise a fresh CA + serving cert is generated
  ONCE per render and memoized on .Values, so every template that includes
  this helper (the Secret and the Deployment checksum) sees the same
  material — including under `helm template | kubectl apply`, where lookup
  is unavailable and each render regenerates.
*/ -}}
{{- define "nvt.brokerTLSSecretData" -}}
{{- $ns := include "nvt.namespace" . -}}
{{- $name := include "nvt.brokerTLSSecretName" . -}}
{{- $existing := lookup "v1" "Secret" $ns $name -}}
{{- if $existing -}}
{{- dict "tls.crt" (index $existing.data "tls.crt") "tls.key" (index $existing.data "tls.key") "ca.crt" (index $existing.data "ca.crt") | toJson -}}
{{- else -}}
{{- $cache := .Values._generatedBrokerTLS -}}
{{- if not $cache -}}
{{- $altNames := list "nvt-broker" (printf "nvt-broker.%s" $ns) (printf "nvt-broker.%s.svc" $ns) (printf "nvt-broker.%s.svc.cluster.local" $ns) -}}
{{- $ca := genCA "nvt-broker-ca" 3650 -}}
{{- $cert := genSignedCert "nvt-broker" nil $altNames 3650 $ca -}}
{{- $cache = dict "tls.crt" ($cert.Cert | b64enc) "tls.key" ($cert.Key | b64enc) "ca.crt" ($ca.Cert | b64enc) -}}
{{- $_ := set .Values "_generatedBrokerTLS" $cache -}}
{{- end -}}
{{- $cache | toJson -}}
{{- end -}}
{{- end -}}

{{- /*
  Restart trigger for the broker Deployment: the broker loads its TLS
  cert/key once at startup, so the pod template must change exactly when the
  Secret material changes. For the chart-managed Secret the checksum hashes
  the same memoized material the Secret template renders, so it is stable
  across material-preserving upgrades and changes whenever the rendered
  material does (including `helm template | kubectl apply` regeneration).
  For existingSecret the material is not rendered by the chart: hash the
  live Secret when lookup can see it, else the name. Out-of-band rotation of
  an existingSecret between upgrades still needs a manual
  `kubectl rollout restart deployment/nvt-broker`.
*/ -}}
{{/*
nvt.brokerConfigChecksum hashes the broker provider config (broker.yaml). The
broker loads providers once at startup and does NOT hot-reload them (unlike the
agents ConfigMap, which reloads by mtime), so a Helm upgrade that changes
broker.config must roll the Deployment or the running broker keeps the old
providers — the exact false failure hit in the real Codex proof.
*/ -}}
{{- define "nvt.brokerConfigChecksum" -}}
{{- .Values.broker.config | toYaml | sha256sum -}}
{{- end -}}

{{- define "nvt.brokerTLSChecksum" -}}
{{- if .Values.broker.tls.existingSecret -}}
{{- $existing := lookup "v1" "Secret" (include "nvt.namespace" .) .Values.broker.tls.existingSecret -}}
{{- if $existing -}}
{{- $existing.data | toJson | sha256sum -}}
{{- else -}}
{{- .Values.broker.tls.existingSecret | sha256sum -}}
{{- end -}}
{{- else -}}
{{- include "nvt.brokerTLSSecretData" . | sha256sum -}}
{{- end -}}
{{- end -}}
