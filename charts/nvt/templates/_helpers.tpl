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

{{- define "nvt.brandingConfigMap" -}}
{{- $name := trim .Values.branding.existingConfigMap -}}
{{- if and $name (or (gt (len $name) 253) (not (regexMatch `^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*$` $name))) -}}
{{- fail "branding.existingConfigMap must be a valid Kubernetes ConfigMap name" -}}
{{- end -}}
{{- $name -}}
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
  (dict "name" "executionDrivers.hostImage" "value" .Values.executionDrivers.hostImage)
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

{{- define "nvt.executionDriverHostImage" -}}
{{- include "nvt.image" (dict "root" . "name" "executionDrivers.hostImage" "image" .Values.executionDrivers.hostImage) -}}
{{- end -}}

{{- define "nvt.executionDriverResourceName" -}}
{{- if le (add 21 (len .registration.name)) 63 -}}
{{- printf "nvt-execution-driver-%s" .registration.name -}}
{{- else -}}
{{- printf "nvt-ed-%s" (trunc 56 (sha256sum .registration.name)) -}}
{{- end -}}
{{- end -}}

{{- define "nvt.executionDriverServiceAccountName" -}}
{{- if .registration.serviceAccount.create -}}
{{- default (include "nvt.executionDriverResourceName" .) .registration.serviceAccount.name -}}
{{- else -}}
{{- .registration.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "nvt.executionDriverSecretData" -}}
{{- $root := .root -}}
{{- $registration := .registration -}}
{{- $name := include "nvt.executionDriverResourceName" . -}}
{{- $namespace := include "nvt.namespace" $root -}}
{{- $existing := lookup "v1" "Secret" $namespace $name -}}
{{- if $existing -}}
{{- dict "tls.crt" (index $existing.data "tls.crt") "tls.key" (index $existing.data "tls.key") "ca.crt" (index $existing.data "ca.crt") "auth-token" (index $existing.data "auth-token") | toJson -}}
{{- else -}}
{{- $cache := default (dict) $root.Values._generatedExecutionDriverSecrets -}}
{{- $data := index $cache $registration.name -}}
{{- if not $data -}}
{{- $service := $name -}}
{{- $altNames := list $service (printf "%s.%s" $service $namespace) (printf "%s.%s.svc" $service $namespace) (printf "%s.%s.svc.cluster.local" $service $namespace) -}}
{{- $ca := genCA (printf "%s-ca" $name) 3650 -}}
{{- $cert := genSignedCert $service nil $altNames 3650 $ca -}}
{{- $data = dict "tls.crt" ($cert.Cert | b64enc) "tls.key" ($cert.Key | b64enc) "ca.crt" ($ca.Cert | b64enc) "auth-token" (randAlphaNum 64 | b64enc) -}}
{{- $_ := set $cache $registration.name $data -}}
{{- $_ = set $root.Values "_generatedExecutionDriverSecrets" $cache -}}
{{- end -}}
{{- $data | toJson -}}
{{- end -}}
{{- end -}}

{{- define "nvt.executionDriverQuantity" -}}
{{- $raw := toString .value -}}
{{- if not (regexMatch `^\+?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+|[numkMGTPE]|[KMGTPE]i)?$` $raw) -}}
{{- fail (printf "execution driver %s %s must be a positive Kubernetes quantity" .name .field) -}}
{{- end -}}
{{- $value := 0.0 -}}
{{- if regexMatch `[eE][+-]?[0-9]+$` $raw -}}
{{- $value = float64 $raw -}}
{{- else -}}
{{- $suffix := regexFind `(?:[KMGTPE]i|[numkMGTPE])$` $raw -}}
{{- $number := trimSuffix $suffix $raw | float64 -}}
{{- $factors := dict "" "1" "n" "0.000000001" "u" "0.000001" "m" "0.001" "k" "1000" "M" "1000000" "G" "1000000000" "T" "1000000000000" "P" "1000000000000000" "E" "1000000000000000000" "Ki" "1024" "Mi" "1048576" "Gi" "1073741824" "Ti" "1099511627776" "Pi" "1125899906842624" "Ei" "1152921504606846976" -}}
{{- $value = mulf $number (index $factors $suffix | float64) -}}
{{- end -}}
{{- if le $value 0.0 -}}{{ fail (printf "execution driver %s %s must be a positive Kubernetes quantity" .name .field) }}{{- end -}}
{{- printf "%.17g" $value -}}
{{- end -}}

{{- define "nvt.validateExecutionDrivers" -}}
{{- $registrations := .Values.executionDrivers.registrations -}}
{{- if not (kindIs "slice" $registrations) -}}{{ fail "executionDrivers.registrations must be a list" }}{{- end -}}
{{- if gt (len $registrations) 32 -}}{{ fail "executionDrivers.registrations supports at most 32 entries" }}{{- end -}}
{{- $seen := dict -}}
{{- $seenServiceAccounts := dict -}}
{{- $seenExistingClaims := dict -}}
{{- range $registration := $registrations -}}
{{- $name := default "" $registration.name -}}
{{- if or (gt (len $name) 63) (not (regexMatch `^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$` $name)) -}}{{ fail "execution driver registration name must be a DNS label of at most 63 characters" }}{{- end -}}
{{- if hasKey $seen $name -}}{{ fail "execution driver registration names must be unique" }}{{- end -}}
{{- $_ := set $seen $name true -}}
{{- if not (regexMatch `^(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?/)(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*@sha256:[0-9a-f]{64}$` (default "" $registration.image)) -}}{{ fail (printf "execution driver %s image must be pinned by lowercase sha256 digest" $name) }}{{- end -}}
{{- if or (not (kindIs "slice" $registration.command)) (eq (len $registration.command) 0) (gt (len $registration.command) 128) (not (regexMatch `^/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$` (first $registration.command))) -}}{{ fail (printf "execution driver %s command must begin with a canonical absolute executable path" $name) }}{{- end -}}
{{- $commandBytes := 0 -}}
{{- range $argument := $registration.command -}}{{- if or (not (kindIs "string" $argument)) (eq $argument "") -}}{{ fail (printf "execution driver %s command contains an invalid argument" $name) }}{{- end -}}{{- $commandBytes = add $commandBytes (len $argument) -}}{{- end -}}
{{- if gt $commandBytes 16384 -}}{{ fail (printf "execution driver %s command exceeds the 16 KiB aggregate bound" $name) }}{{- end -}}
{{- if or (not $registration.resources) (not $registration.resources.requests.cpu) (not $registration.resources.requests.memory) (not $registration.resources.limits.cpu) (not $registration.resources.limits.memory) -}}{{ fail (printf "execution driver %s requires cpu/memory requests and limits" $name) }}{{- end -}}
{{- $requestCPU := include "nvt.executionDriverQuantity" (dict "name" $name "field" "resources.requests.cpu" "value" $registration.resources.requests.cpu) | float64 -}}
{{- $limitCPU := include "nvt.executionDriverQuantity" (dict "name" $name "field" "resources.limits.cpu" "value" $registration.resources.limits.cpu) | float64 -}}
{{- $requestMemory := include "nvt.executionDriverQuantity" (dict "name" $name "field" "resources.requests.memory" "value" $registration.resources.requests.memory) | float64 -}}
{{- $limitMemory := include "nvt.executionDriverQuantity" (dict "name" $name "field" "resources.limits.memory" "value" $registration.resources.limits.memory) | float64 -}}
{{- if or (gt $requestCPU $limitCPU) (gt $requestMemory $limitMemory) -}}{{ fail (printf "execution driver %s resource requests must not exceed limits" $name) }}{{- end -}}
{{- with $registration.storage -}}
{{- if .existingClaim -}}
{{- if or .size .storageClassName (gt (len .existingClaim) 253) (not (regexMatch `^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$` .existingClaim)) -}}{{ fail (printf "execution driver %s existing storage claim is invalid" $name) }}{{- end -}}
{{- if hasKey $seenExistingClaims .existingClaim -}}{{ fail "execution driver registrations must use distinct existing storage claims" }}{{- end -}}
{{- $_ := set $seenExistingClaims .existingClaim true -}}
{{- else -}}
{{- if not .size -}}{{ fail (printf "execution driver %s storage.size is required" $name) }}{{- end -}}
{{- $storageBytes := include "nvt.executionDriverQuantity" (dict "name" $name "field" "storage.size" "value" .size) | float64 -}}
{{- if or (lt $storageBytes 1073741824.0) (gt $storageBytes 1099511627776.0) -}}{{ fail (printf "execution driver %s storage.size must be between 1Gi and 1Ti" $name) }}{{- end -}}
{{- if and .storageClassName (or (gt (len .storageClassName) 253) (not (regexMatch `^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$` .storageClassName))) -}}{{ fail (printf "execution driver %s storageClassName is invalid" $name) }}{{- end -}}
{{- end -}}
{{- end -}}
{{- if not $registration.serviceAccount -}}{{ fail (printf "execution driver %s requires a ServiceAccount selection" $name) }}{{- end -}}
{{- if and (not $registration.serviceAccount.create) (not $registration.serviceAccount.name) -}}{{ fail (printf "execution driver %s existing ServiceAccount name is required" $name) }}{{- end -}}
{{- range $key, $value := (default (dict) $registration.serviceAccount.podLabels) -}}{{- if or (hasPrefix "app.kubernetes.io/" $key) (hasPrefix "nvt.dev/" $key) -}}{{ fail (printf "execution driver %s workload-identity Pod label uses a reserved key" $name) }}{{- end -}}{{- end -}}
{{- $serviceAccountName := $registration.serviceAccount.name -}}
{{- if and $registration.serviceAccount.create (not $serviceAccountName) -}}{{ $serviceAccountName = include "nvt.executionDriverResourceName" (dict "root" $ "registration" $registration) }}{{- end -}}
{{- if not (regexMatch `^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$` $serviceAccountName) -}}{{ fail (printf "execution driver %s ServiceAccount name is invalid" $name) }}{{- end -}}
{{- if hasKey $seenServiceAccounts $serviceAccountName -}}{{ fail "execution driver registrations must use distinct ServiceAccounts" }}{{- end -}}
{{- $_ = set $seenServiceAccounts $serviceAccountName true -}}
{{- $envSeen := dict -}}
{{- if gt (add (len (default (list) $registration.passEnv)) (len (default (list) $registration.secretEnvironment))) 64 -}}{{ fail (printf "execution driver %s environment allowlist exceeds 64 names" $name) }}{{- end -}}
{{- range $environmentName := (default (list) $registration.passEnv) -}}
{{- if or (eq $environmentName "NVT_EXECUTION_DRIVER_STATE_DIR") (not (regexMatch `^[A-Za-z_][A-Za-z0-9_]*$` $environmentName)) -}}{{ fail (printf "execution driver %s environment allowlist contains an invalid name" $name) }}{{- end -}}
{{- if hasKey $envSeen $environmentName -}}{{ fail (printf "execution driver %s environment allowlist names must be unique" $name) }}{{- end -}}
{{- $_ := set $envSeen $environmentName true -}}
{{- end -}}
{{- range $item := (default (list) $registration.secretEnvironment) -}}
{{- if or (eq $item.name "NVT_EXECUTION_DRIVER_STATE_DIR") (not (regexMatch `^[A-Za-z_][A-Za-z0-9_]*$` (default "" $item.name))) (not (regexMatch `^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$` (default "" $item.secretName))) (not (regexMatch `^[A-Za-z0-9._-]+$` (default "" $item.key))) -}}{{ fail (printf "execution driver %s secret environment entry is invalid" $name) }}{{- end -}}
{{- if hasKey $envSeen $item.name -}}{{ fail (printf "execution driver %s environment allowlist names must be unique" $name) }}{{- end -}}
{{- $_ := set $envSeen $item.name true -}}
{{- end -}}
{{- $fileSeen := dict -}}
{{- if gt (len (default (list) $registration.secretFiles)) 32 -}}{{ fail (printf "execution driver %s secret file projections exceed 32" $name) }}{{- end -}}
{{- range $file := (default (list) $registration.secretFiles) -}}
{{- if or (not (regexMatch `^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$` (default "" $file.name))) (not (regexMatch `^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$` (default "" $file.secretName))) (eq (len (default (list) $file.items)) 0) (gt (len (default (list) $file.items)) 64) -}}{{ fail (printf "execution driver %s secret file projection is invalid" $name) }}{{- end -}}
{{- if hasKey $fileSeen $file.name -}}{{ fail (printf "execution driver %s secret file names must be unique" $name) }}{{- end -}}
{{- $_ := set $fileSeen $file.name true -}}
{{- $pathSeen := dict -}}
{{- range $item := $file.items -}}{{- if or (not (regexMatch `^[A-Za-z0-9._-]+$` (default "" $item.key))) (not (regexMatch `^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$` (default "" $item.path))) (contains ".." $item.path) -}}{{ fail (printf "execution driver %s secret file item is invalid" $name) }}{{- end -}}{{- if hasKey $pathSeen $item.path -}}{{ fail (printf "execution driver %s secret file item paths must be unique" $name) }}{{- end -}}{{- $_ = set $pathSeen $item.path true -}}{{- end -}}
{{- end -}}
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
