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
