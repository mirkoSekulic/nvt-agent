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
