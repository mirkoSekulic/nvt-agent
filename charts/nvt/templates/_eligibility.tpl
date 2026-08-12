{{/* Shared Helm-side validation for the provider-neutral eligibility contract. */}}
{{- define "nvt.validatePolicyPath" -}}
{{- $path := .path -}}
{{- if or (not (kindIs "string" $path)) (eq $path "") (gt (len $path) 2048) (regexMatch `[[:cntrl:]]` $path) }}{{ fail (printf "%s requires a bounded claimPath" .field) }}{{ end -}}
{{- $segments := splitList "." $path -}}
{{- if gt (len $segments) 16 }}{{ fail (printf "%s claimPath must contain at most 16 segments" .field) }}{{ end -}}
{{- range $segment := $segments -}}
{{- $key := trimSuffix "[]" $segment -}}
{{- if or (eq $key "") (gt (len $key) 128) (contains "[]" $key) }}{{ fail (printf "%s requires a bounded claimPath" $.field) }}{{ end -}}
{{- end -}}
{{- end -}}

{{- define "nvt.rejectSensitivePolicyPath" -}}
{{- if regexMatch `(?i)(^|[.\[\]_-])(pid|ssn|fodselsnummer|foedselsnummer|fødselsnummer)([.\[\]_-]|$)` .path }}{{ fail (printf "%s must be a non-sensitive JSON path" .field) }}{{ end -}}
{{- end -}}

{{- define "nvt.rejectSensitiveEnrichmentPath" -}}
{{- $path := .path -}}
{{- include "nvt.rejectSensitivePolicyPath" (dict "path" $path "field" .field) -}}
{{- range $segment := splitList "." $path -}}
{{- $key := lower (trimSuffix "[]" $segment) -}}
{{- $compact := regexReplaceAll `[.\[\]_-]` $key "" -}}
{{- if and (ne $compact "authorizationdetails") (ne $compact "authorizedparties") (or (contains "authorization" $compact) (contains "token" $compact) (contains "secret" $compact) (contains "password" $compact) (contains "credential" $compact)) }}{{ fail (printf "%s must be a safe non-sensitive JSON path" $.field) }}{{ end -}}
{{- end -}}
{{- end -}}

{{- define "nvt.validateEligibility" -}}
{{- $policy := .policy -}}
{{- $prefix := .prefix -}}
{{- $allowFalseOwner := default false .allowFalseOwner -}}
{{- if ne (toJson $policy) "null" -}}
{{- if and $policy.default (ne $policy.default "deny") }}{{ fail (printf "%s.default must be deny" $prefix) }}{{ end -}}
{{- $rules := default (list) $policy.rules -}}
{{- if gt (len $rules) 64 }}{{ fail (printf "%s.rules must contain at most 64 entries" $prefix) }}{{ end -}}
{{- range $index, $rule := $rules -}}
{{- if or (not (kindIs "string" $rule.id)) (eq (trim $rule.id) "") (gt (len $rule.id) 128) (regexMatch `[[:cntrl:]]` $rule.id) }}{{ fail (printf "%s.rules[%d].id must be a bounded non-empty string without control characters" $prefix $index) }}{{ end -}}
{{- if ne $rule.effect "allow" }}{{ fail (printf "%s.rules[%d].effect must be allow" $prefix $index) }}{{ end -}}
{{- if hasKey $rule "owner" -}}
{{- if or (not $allowFalseOwner) (not (kindIs "bool" $rule.owner)) $rule.owner }}{{ fail (printf "%s.rules[%d].owner is not an eligibility predicate" $prefix $index) }}{{ end -}}
{{- end -}}
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
{{- include "nvt.validatePolicyPath" (dict "path" $where.array "field" (printf "%s.rules[%d].where.array" $prefix $index)) -}}
{{- include "nvt.rejectSensitivePolicyPath" (dict "path" $where.array "field" (printf "%s.rules[%d].where.array" $prefix $index)) -}}
{{- if or (eq (len (default (list) $where.all)) 0) (gt (len (default (list) $where.all)) 16) }}{{ fail (printf "%s.rules[%d] requires 1..16 where.all conditions" $prefix $index) }}{{ end -}}
{{- range $conditionIndex, $condition := $where.all }}{{ include "nvt.validateEligibilityPredicate" (dict "path" $condition.claimPath "values" $condition.values "field" (printf "%s.rules[%d].where.all[%d]" $prefix $index $conditionIndex)) }}{{ end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "nvt.validateEligibilityPredicate" -}}
{{- include "nvt.validatePolicyPath" (dict "path" .path "field" .field) -}}
{{- include "nvt.rejectSensitivePolicyPath" (dict "path" .path "field" (printf "%s.claimPath" .field)) -}}
{{- if or (not (kindIs "slice" .values)) (eq (len .values) 0) (gt (len .values) 64) }}{{ fail (printf "%s requires 1..64 values" .field) }}{{ end -}}
{{- range $index, $value := .values }}{{ if or (not (kindIs "string" $value)) (gt (len $value) 1024) }}{{ fail (printf "%s.values[%d] must be a bounded string" $.field $index) }}{{ end }}{{ end -}}
{{- end -}}

{{- define "nvt.validateClaimEnrichment" -}}
{{- $config := .config -}}
{{- $prefix := .prefix -}}
{{- $sources := default (list) $config.sources -}}
{{- $hosts := default (list) $config.allowedHosts -}}
{{- if gt (len $sources) 8 }}{{ fail (printf "%s.sources must contain at most 8 entries" $prefix) }}{{ end -}}
{{- if gt (len $hosts) 32 }}{{ fail (printf "%s.allowedHosts must contain at most 32 entries" $prefix) }}{{ end -}}
{{- if and $config.timeoutSeconds (or (lt (int $config.timeoutSeconds) 1) (gt (int $config.timeoutSeconds) 30)) }}{{ fail (printf "%s.timeoutSeconds must be between 1 and 30 when set" $prefix) }}{{ end -}}
{{- $limits := default (dict) $config.limits -}}
{{- range $name, $bound := dict "maxResponseBytes" 1048576 "maxDepth" 16 "maxArrayItems" 256 "maxObjectProperties" 256 "maxTotalNodes" 4096 "maxStringBytes" 8192 -}}
{{- $value := index $limits $name -}}
{{- if and $value (or (lt (int64 $value) 1) (gt (int64 $value) (int64 $bound))) }}{{ fail (printf "%s.limits.%s exceeds safe bounds" $prefix $name) }}{{ end -}}
{{- end -}}
{{- if and (gt (len $sources) 0) (eq (len $hosts) 0) }}{{ fail (printf "%s.allowedHosts is required when sources are configured" $prefix) }}{{ end -}}
{{- $seenHosts := dict -}}
{{- range $index, $host := $hosts -}}
{{- if or (not (kindIs "string" $host)) (gt (len $host) 253) (not (regexMatch `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$` $host)) }}{{ fail (printf "%s.allowedHosts[%d] must be a normalized lowercase DNS hostname or IPv4 address without a port" $prefix $index) }}{{ end -}}
{{- if hasKey $seenHosts $host }}{{ fail (printf "%s.allowedHosts[%d] is duplicated" $prefix $index) }}{{ end -}}
{{- $_ := set $seenHosts $host true -}}
{{- end -}}
{{- $seenClaims := dict -}}
{{- range $index, $source := $sources -}}
{{- if not (regexMatch `^https://[^/@?#]+(?::[0-9]+)?(?:/[^?#]*)?$` $source.endpoint) }}{{ fail (printf "%s.sources[%d].endpoint must be an absolute HTTPS URL without credentials, query, or fragment" $prefix $index) }}{{ end -}}
{{- $hostAllowed := false -}}
{{- range $host := $hosts }}{{ if regexMatch (printf `^https://%s(?::[0-9]+)?(?:/|$)` (regexQuoteMeta $host)) $source.endpoint }}{{ $hostAllowed = true }}{{ end }}{{ end -}}
{{- if not $hostAllowed }}{{ fail (printf "%s.sources[%d].endpoint host is not allowed" $prefix $index) }}{{ end -}}
{{- if or (not (kindIs "string" $source.outputClaim)) (not (regexMatch `^[a-z][a-z0-9_]{0,63}$` $source.outputClaim)) }}{{ fail (printf "%s.sources[%d].outputClaim must be a safe non-sensitive top-level claim name" $prefix $index) }}{{ end -}}
{{- include "nvt.rejectSensitiveEnrichmentPath" (dict "path" $source.outputClaim "field" (printf "%s.sources[%d].outputClaim" $prefix $index)) -}}
{{- if hasKey $seenClaims $source.outputClaim }}{{ fail (printf "%s.sources[%d].outputClaim is duplicated" $prefix $index) }}{{ end -}}
{{- $_ := set $seenClaims $source.outputClaim true -}}
{{- if ne $source.valuePath "$" -}}
{{- if or (not (kindIs "string" $source.valuePath)) (not (regexMatch `^[A-Za-z_][A-Za-z0-9_-]*(?:\[\])?(?:\.[A-Za-z_][A-Za-z0-9_-]*(?:\[\])?)*$` $source.valuePath)) (gt (len (splitList "." $source.valuePath)) 16) }}{{ fail (printf "%s.sources[%d].valuePath must be $ or a bounded JSON path" $prefix $index) }}{{ end -}}
{{- include "nvt.rejectSensitiveEnrichmentPath" (dict "path" $source.valuePath "field" (printf "%s.sources[%d].valuePath" $prefix $index)) -}}
{{- end -}}
{{- if hasKey $source "pagination" -}}
{{- if not (kindIs "map" $source.pagination) }}{{ fail (printf "%s.sources[%d].pagination must be an object" $prefix $index) }}{{ end -}}
{{- range $key, $_ := $source.pagination }}{{ if not (has $key (list "mode" "maxPages")) }}{{ fail (printf "%s.sources[%d].pagination has unknown key %s" $prefix $index $key) }}{{ end }}{{ end -}}
{{- $pagesNumeric := or (kindIs "float64" $source.pagination.maxPages) (kindIs "int64" $source.pagination.maxPages) -}}
{{- if or (ne $source.pagination.mode "link") (not $pagesNumeric) (not (regexMatch `^[0-9]+$` (toString $source.pagination.maxPages))) (lt (int $source.pagination.maxPages) 2) (gt (int $source.pagination.maxPages) 10) }}{{ fail (printf "%s.sources[%d].pagination must use link mode with maxPages between 2 and 10" $prefix $index) }}{{ end -}}
{{- if ne $source.valuePath "$" }}{{ fail (printf "%s.sources[%d].valuePath must be $ when pagination is configured" $prefix $index) }}{{ end -}}
{{- end -}}
{{- end -}}
{{- end -}}
