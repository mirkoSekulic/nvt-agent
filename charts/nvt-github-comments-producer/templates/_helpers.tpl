{{- define "nvt-github-comments-producer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "nvt-github-comments-producer.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "nvt-github-comments-producer.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "nvt-github-comments-producer.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "nvt-github-comments-producer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: nvt
app.kubernetes.io/component: github-comments-producer
{{- end -}}

{{- define "nvt-github-comments-producer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nvt-github-comments-producer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: nvt
app.kubernetes.io/component: github-comments-producer
{{- end -}}

{{- define "nvt-github-comments-producer.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "nvt-github-comments-producer.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "nvt-github-comments-producer.configMapName" -}}
{{- include "nvt-github-comments-producer.fullname" . -}}
{{- end -}}

{{- define "nvt-github-comments-producer.agentRunNamespace" -}}
{{- default .Release.Namespace .Values.agentRun.namespace -}}
{{- end -}}

{{- define "nvt-github-comments-producer.stateClaimName" -}}
{{- default (printf "%s-state" (include "nvt-github-comments-producer.fullname" .)) .Values.persistence.existingClaim -}}
{{- end -}}

{{- define "nvt-github-comments-producer.privateKeyPath" -}}
{{- printf "%s/%s" (.Values.githubApp.privateKeyMountPath | trimSuffix "/") .Values.githubApp.privateKeyKey -}}
{{- end -}}
