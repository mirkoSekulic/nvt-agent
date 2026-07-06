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
  Restart trigger for the broker Deployment: the broker loads its TLS
  cert/key once at startup, so the pod template must change when the Secret
  material changes. `lookup` returns the live Secret on real installs, making
  the checksum stable across upgrades that keep the same material and
  changing it when the material rotates. When lookup is unavailable (fresh
  install, `helm template`), fall back to hashing the configured name — any
  value works pre-install, and name changes still force a restart.
*/ -}}
{{- define "nvt.brokerTLSChecksum" -}}
{{- $name := include "nvt.brokerTLSSecretName" . -}}
{{- $existing := lookup "v1" "Secret" (include "nvt.namespace" .) $name -}}
{{- if $existing -}}
{{- $existing.data | toJson | sha256sum -}}
{{- else -}}
{{- $name | sha256sum -}}
{{- end -}}
{{- end -}}
