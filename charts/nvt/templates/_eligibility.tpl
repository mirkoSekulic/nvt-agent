{{/* Shared Helm-side validation for the provider-neutral eligibility contract. */}}
{{- define "nvt.validateEligibility" -}}
{{- $policy := .policy -}}
{{- $prefix := .prefix -}}
{{- if ne (toJson $policy) "null" -}}
{{- if and $policy.default (ne $policy.default "deny") }}{{ fail (printf "%s.default must be deny" $prefix) }}{{ end -}}
{{- $rules := default (list) $policy.rules -}}
{{- if gt (len $rules) 64 }}{{ fail (printf "%s.rules must contain at most 64 entries" $prefix) }}{{ end -}}
{{- $seen := dict -}}
{{- range $index, $rule := $rules -}}
{{- if or (not (kindIs "string" $rule.id)) (not (regexMatch `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` $rule.id)) (hasKey $seen $rule.id) }}{{ fail (printf "%s.rules[%d].id must be a unique bounded identifier" $prefix $index) }}{{ end -}}
{{- $_ := set $seen $rule.id true -}}
{{- if ne $rule.effect "allow" }}{{ fail (printf "%s.rules[%d].effect must be allow" $prefix $index) }}{{ end -}}
{{- if $rule.owner }}{{ fail (printf "%s.rules[%d].owner is not an eligibility predicate" $prefix $index) }}{{ end -}}
{{- $hasScalar := or (not (empty $rule.claimPath)) (gt (len (default (list) $rule.values)) 0) -}}
{{- $where := default (dict) $rule.where -}}
{{- $hasWhere := or (not (empty $where.array)) (gt (len (default (list) $where.all)) 0) -}}
{{- $predicates := 0 -}}
{{- if $rule.authenticated }}{{ $predicates = add1 $predicates }}{{ end -}}
{{- if $hasScalar }}{{ $predicates = add1 $predicates }}{{ end -}}
{{- if $hasWhere }}{{ $predicates = add1 $predicates }}{{ end -}}
{{- if ne (int $predicates) 1 }}{{ fail (printf "%s.rules[%d] must define exactly one eligibility predicate" $prefix $index) }}{{ end -}}
{{- if $hasScalar }}{{ include "nvt.validateEligibilityPredicate" (dict "path" $rule.claimPath "values" $rule.values "field" (printf "%s.rules[%d]" $prefix $index)) }}{{ end -}}
{{- if $hasWhere -}}
{{- if or (not (regexMatch `^[A-Za-z_][A-Za-z0-9_-]*(?:\[\])?(?:\.[A-Za-z_][A-Za-z0-9_-]*(?:\[\])?)*$` $where.array)) (eq (len $where.all) 0) (gt (len $where.all) 16) }}{{ fail (printf "%s.rules[%d] requires a bounded where.array and 1..16 where.all conditions" $prefix $index) }}{{ end -}}
{{- range $conditionIndex, $condition := $where.all }}{{ include "nvt.validateEligibilityPredicate" (dict "path" $condition.claimPath "values" $condition.values "field" (printf "%s.rules[%d].where.all[%d]" $prefix $index $conditionIndex)) }}{{ end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "nvt.validateEligibilityPredicate" -}}
{{- if or (not (kindIs "string" .path)) (not (regexMatch `^[A-Za-z_][A-Za-z0-9_-]*(?:\[\])?(?:\.[A-Za-z_][A-Za-z0-9_-]*(?:\[\])?)*$` .path)) (eq (len .values) 0) (gt (len .values) 64) }}{{ fail (printf "%s requires a bounded claimPath and 1..64 values" .field) }}{{ end -}}
{{- if regexMatch `(?i)(^|[.\[\]_-])(pid|ssn|fodselsnummer|foedselsnummer)([.\[\]_-]|$)` .path }}{{ fail (printf "%s.claimPath must be non-sensitive" .field) }}{{ end -}}
{{- range $index, $value := .values }}{{ if or (not (kindIs "string" $value)) (eq $value "") (gt (len $value) 1024) (ne (trim $value) $value) }}{{ fail (printf "%s.values[%d] must be a bounded non-empty string" $.field $index) }}{{ end }}{{ end -}}
{{- end -}}

{{- define "nvt.validateClaimEnrichment" -}}
{{- $config := .config -}}
{{- $prefix := .prefix -}}
{{- if gt (len $config.sources) 8 }}{{ fail (printf "%s.sources must contain at most 8 entries" $prefix) }}{{ end -}}
{{- if gt (len $config.allowedHosts) 32 }}{{ fail (printf "%s.allowedHosts must contain at most 32 entries" $prefix) }}{{ end -}}
{{- if and $config.timeoutSeconds (or (lt (int $config.timeoutSeconds) 1) (gt (int $config.timeoutSeconds) 30)) }}{{ fail (printf "%s.timeoutSeconds must be between 1 and 30 when set" $prefix) }}{{ end -}}
{{- $limits := default (dict) $config.limits -}}
{{- range $name, $bound := dict "maxResponseBytes" 1048576 "maxDepth" 16 "maxArrayItems" 256 "maxObjectProperties" 256 "maxTotalNodes" 4096 "maxStringBytes" 8192 -}}
{{- $value := index $limits $name -}}
{{- if and $value (or (lt (int64 $value) 1) (gt (int64 $value) (int64 $bound))) }}{{ fail (printf "%s.limits.%s exceeds safe bounds" $prefix $name) }}{{ end -}}
{{- end -}}
{{- if and (gt (len $config.sources) 0) (eq (len $config.allowedHosts) 0) }}{{ fail (printf "%s.allowedHosts is required when sources are configured" $prefix) }}{{ end -}}
{{- range $index, $host := $config.allowedHosts }}{{ if not (regexMatch `^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$` $host) }}{{ fail (printf "%s.allowedHosts[%d] must be a normalized host without a port" $prefix $index) }}{{ end }}{{ end -}}
{{- range $index, $source := $config.sources -}}
{{- if not (regexMatch `^https://[^/@?#]+(?::[0-9]+)?(?:/[^?#]*)?$` $source.endpoint) }}{{ fail (printf "%s.sources[%d].endpoint must be an absolute HTTPS URL without credentials, query, or fragment" $prefix $index) }}{{ end -}}
{{- $hostAllowed := false -}}
{{- range $host := $config.allowedHosts }}{{ if regexMatch (printf `^https://%s(?::[0-9]+)?(?:/|$)` (regexQuoteMeta $host)) $source.endpoint }}{{ $hostAllowed = true }}{{ end }}{{ end -}}
{{- if not $hostAllowed }}{{ fail (printf "%s.sources[%d].endpoint host is not allowed" $prefix $index) }}{{ end -}}
{{- if not (regexMatch `^[a-z][a-z0-9_]{0,63}$` $source.outputClaim) }}{{ fail (printf "%s.sources[%d].outputClaim must be a safe top-level claim name" $prefix $index) }}{{ end -}}
{{- if and (ne $source.valuePath "$") (not (regexMatch `^[A-Za-z_][A-Za-z0-9_-]*(?:\[\])?(?:\.[A-Za-z_][A-Za-z0-9_-]*(?:\[\])?)*$` $source.valuePath)) }}{{ fail (printf "%s.sources[%d].valuePath must be $ or a safe JSON path" $prefix $index) }}{{ end -}}
{{- end -}}
{{- end -}}
