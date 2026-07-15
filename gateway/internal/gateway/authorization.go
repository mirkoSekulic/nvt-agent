package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"reflect"
	"strings"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

const (
	authorizationDefaultDeny  = "deny"
	authorizationEffectAllow  = "allow"
	authorizationDecisionDeny = "deny"
	claimSourceIDToken        = "id_token"
	claimSourceAccessToken    = "access_token"
	claimSourceUserInfo       = "userinfo"
)

type AuthorizationConfig struct {
	Default     string              `json:"default"`
	ClaimSource string              `json:"claimSource"`
	Rules       []AuthorizationRule `json:"rules"`
}

type AuthorizationRule struct {
	ID            string             `json:"id"`
	Effect        string             `json:"effect"`
	Authenticated bool               `json:"authenticated"`
	Owner         bool               `json:"owner"`
	ClaimPath     string             `json:"claimPath"`
	Values        []string           `json:"values"`
	Where         AuthorizationWhere `json:"where"`
}

type AuthorizationWhere struct {
	Array string                   `json:"array"`
	All   []AuthorizationCondition `json:"all"`
}

type AuthorizationCondition struct {
	ClaimPath string   `json:"claimPath"`
	Values    []string `json:"values"`
}

type AuthorizationDecision struct {
	Allowed bool
	RuleID  string
}

// Principal is the normalized identity produced by every authenticated mode.
// Issuer and Subject are the only ownership keys; DisplayName is display-only.
type Principal struct {
	Issuer      string
	Subject     string
	DisplayName string
	Claims      map[string]any
}

func (c AuthorizationConfig) validate() error {
	defaultDecision := c.Default
	if defaultDecision == "" {
		defaultDecision = authorizationDefaultDeny
	}
	if defaultDecision != authorizationDefaultDeny {
		return fmt.Errorf("auth.authorization.default must be %q", authorizationDefaultDeny)
	}
	claimSource := c.ClaimSource
	if claimSource == "" {
		claimSource = claimSourceIDToken
	}
	switch claimSource {
	case claimSourceIDToken, claimSourceAccessToken, claimSourceUserInfo:
	default:
		return fmt.Errorf("auth.authorization.claimSource must be one of %q, %q, or %q", claimSourceIDToken, claimSourceAccessToken, claimSourceUserInfo)
	}
	for index, rule := range c.Rules {
		if err := validateAuthorizationRule("auth.authorization", index, rule, true); err != nil {
			return err
		}
	}
	return nil
}

func validateAuthorizationRule(prefix string, index int, rule AuthorizationRule, allowOwner bool) error {
	if strings.TrimSpace(rule.ID) == "" {
		return fmt.Errorf("%s.rules[%d].id is required", prefix, index)
	}
	if rule.Effect != authorizationEffectAllow {
		return fmt.Errorf("%s.rules[%d].effect must be %q", prefix, index, authorizationEffectAllow)
	}
	if rule.Owner && !allowOwner {
		return fmt.Errorf("%s.rules[%d].owner is invalid because login admission has no AgentRun", prefix, index)
	}
	hasSimple := rule.ClaimPath != "" || len(rule.Values) > 0
	hasWhere := rule.Where.Array != "" || len(rule.Where.All) > 0
	predicateCount := 0
	for _, present := range []bool{rule.Authenticated, rule.Owner, hasSimple, hasWhere} {
		if present {
			predicateCount++
		}
	}
	if predicateCount != 1 {
		return fmt.Errorf("%s.rules[%d] must define exactly one of authenticated, owner, claimPath+values, or where.array+all", prefix, index)
	}
	if rule.Authenticated || rule.Owner {
		return nil
	}
	if hasSimple {
		if rule.ClaimPath == "" || len(rule.Values) == 0 {
			return fmt.Errorf("%s.rules[%d] requires claimPath and values", prefix, index)
		}
		if isSensitiveClaimPath(rule.ClaimPath) {
			return fmt.Errorf("%s.rules[%d].claimPath must not use pid, SSN, or fødselsnummer", prefix, index)
		}
		return nil
	}
	if rule.Where.Array == "" || len(rule.Where.All) == 0 {
		return fmt.Errorf("%s.rules[%d] requires where.array and where.all", prefix, index)
	}
	if isSensitiveClaimPath(rule.Where.Array) {
		return fmt.Errorf("%s.rules[%d].where.array must not use pid, SSN, or fødselsnummer", prefix, index)
	}
	for conditionIndex, condition := range rule.Where.All {
		if condition.ClaimPath == "" || len(condition.Values) == 0 {
			return fmt.Errorf("%s.rules[%d].where.all[%d] requires claimPath and values", prefix, index, conditionIndex)
		}
		if isSensitiveClaimPath(condition.ClaimPath) {
			return fmt.Errorf("%s.rules[%d].where.all[%d].claimPath must not use pid, SSN, or fødselsnummer", prefix, index, conditionIndex)
		}
	}
	return nil
}

func isSensitiveClaimPath(path string) bool {
	normalized := strings.ToLower(path)
	normalized = strings.ReplaceAll(normalized, "ø", "o")
	for _, part := range strings.FieldsFunc(normalized, func(r rune) bool {
		return r == '.' || r == '[' || r == ']'
	}) {
		switch part {
		case "pid", "ssn", "fodselsnummer", "foedselsnummer", "fødselsnummer":
			return true
		}
	}
	return false
}

func EvaluateAuthorization(policy AuthorizationConfig, principal Principal, run *nvtv1alpha1.AgentRun) AuthorizationDecision {
	for _, rule := range policy.Rules {
		if rule.Effect != authorizationEffectAllow {
			continue
		}
		if rule.Authenticated {
			return AuthorizationDecision{Allowed: true, RuleID: rule.ID}
		}
		if rule.Owner && principalOwnsAgentRun(principal, run) {
			return AuthorizationDecision{Allowed: true, RuleID: rule.ID}
		}
		if rule.ClaimPath != "" && claimPathMatches(principal.Claims, rule.ClaimPath, rule.Values) {
			return AuthorizationDecision{Allowed: true, RuleID: rule.ID}
		}
		if rule.Where.Array != "" && whereArrayMatches(principal.Claims, rule.Where) {
			return AuthorizationDecision{Allowed: true, RuleID: rule.ID}
		}
	}
	return AuthorizationDecision{Allowed: false}
}

func principalOwnsAgentRun(principal Principal, run *nvtv1alpha1.AgentRun) bool {
	if run == nil || principal.Issuer == "" || principal.Subject == "" || run.Spec.ProfileProvenance == nil || run.Spec.ProfileProvenance.Principal == nil {
		return false
	}
	owner := run.Spec.ProfileProvenance.Principal
	return owner.Issuer != "" && owner.Subject != "" && principal.Issuer == owner.Issuer && principal.Subject == owner.Subject
}

func logAuthorizationDecision(decision AuthorizationDecision, agentKey string, principal Principal) {
	ruleID := decision.RuleID
	if ruleID == "" {
		ruleID = "-"
	}
	outcome := authorizationDecisionDeny
	if decision.Allowed {
		outcome = "allow"
	}
	log.Printf("gateway authorization decision=%s rule=%s agent=%s principal_hash=%s", outcome, ruleID, sanitizeLogValue(agentKey), principalHash(principal))
}

func principalHash(principal Principal) string {
	if principal.Issuer == "" || principal.Subject == "" {
		return "-"
	}
	return shortHash(principal.Issuer + "\x00" + principal.Subject)
}

func sanitizeLogValue(value string) string {
	if value == "" {
		return "-"
	}
	value = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-' || r == '_' || r == '.':
			return r
		default:
			return '_'
		}
	}, value)
	if len(value) > 80 {
		return value[:80]
	}
	return value
}

func shortHash(value string) string {
	if value == "" {
		return "-"
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:16]
}

func whereArrayMatches(claims map[string]any, where AuthorizationWhere) bool {
	for _, item := range selectClaimValues(claims, where.Array) {
		itemMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		matches := true
		for _, condition := range where.All {
			if !claimPathMatches(itemMap, condition.ClaimPath, condition.Values) {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

func claimPathMatches(root any, path string, values []string) bool {
	want := map[string]struct{}{}
	for _, value := range values {
		want[value] = struct{}{}
	}
	for _, selected := range selectClaimValues(root, path) {
		if _, ok := want[valueToString(selected)]; ok {
			return true
		}
	}
	return false
}

func selectClaimValues(root any, path string) []any {
	if path == "" {
		return nil
	}
	current := []any{root}
	for _, rawSegment := range strings.Split(path, ".") {
		if rawSegment == "" {
			return nil
		}
		array := strings.HasSuffix(rawSegment, "[]")
		segment := strings.TrimSuffix(rawSegment, "[]")
		next := []any{}
		for _, value := range current {
			if segment != "" {
				object, ok := value.(map[string]any)
				if !ok {
					continue
				}
				value, ok = object[segment]
				if !ok {
					continue
				}
			}
			if array {
				for _, item := range asSlice(value) {
					next = append(next, item)
				}
			} else {
				next = append(next, value)
			}
		}
		current = next
	}
	return current
}

func asSlice(value any) []any {
	if value == nil {
		return nil
	}
	if values, ok := value.([]any); ok {
		return values
	}
	reflected := reflect.ValueOf(value)
	if reflected.Kind() != reflect.Slice && reflected.Kind() != reflect.Array {
		return nil
	}
	out := make([]any, 0, reflected.Len())
	for index := 0; index < reflected.Len(); index++ {
		out = append(out, reflected.Index(index).Interface())
	}
	return out
}

func valueToString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprint(value)
	}
}

func stripSensitiveClaims(claims map[string]any) map[string]any {
	return stripSensitiveMap(claims, "")
}

func stripSensitiveMap(input map[string]any, prefix string) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		if isSensitiveClaimPath(path) || isSensitiveClaimPath(key) {
			continue
		}
		output[key] = stripSensitiveValue(value, path)
	}
	return output
}

func stripSensitiveValue(value any, path string) any {
	switch typed := value.(type) {
	case map[string]any:
		return stripSensitiveMap(typed, path)
	case []any:
		output := make([]any, 0, len(typed))
		for _, item := range typed {
			output = append(output, stripSensitiveValue(item, path))
		}
		return output
	default:
		return value
	}
}
