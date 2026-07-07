package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"reflect"
	"strings"
)

const (
	authorizationDefaultDeny  = "deny"
	authorizationEffectAllow  = "allow"
	authorizationDecisionDeny = "deny"
)

type AuthorizationConfig struct {
	Default string              `json:"default"`
	Rules   []AuthorizationRule `json:"rules"`
}

type AuthorizationRule struct {
	ID            string             `json:"id"`
	Effect        string             `json:"effect"`
	Authenticated bool               `json:"authenticated"`
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

func (c AuthorizationConfig) validate() error {
	defaultDecision := c.Default
	if defaultDecision == "" {
		defaultDecision = authorizationDefaultDeny
	}
	if defaultDecision != authorizationDefaultDeny {
		return fmt.Errorf("auth.authorization.default must be %q", authorizationDefaultDeny)
	}
	for index, rule := range c.Rules {
		if strings.TrimSpace(rule.ID) == "" {
			return fmt.Errorf("auth.authorization.rules[%d].id is required", index)
		}
		if rule.Effect != authorizationEffectAllow {
			return fmt.Errorf("auth.authorization.rules[%d].effect must be %q", index, authorizationEffectAllow)
		}
		hasSimple := rule.ClaimPath != "" || len(rule.Values) > 0
		hasWhere := rule.Where.Array != "" || len(rule.Where.All) > 0
		if rule.Authenticated {
			if hasSimple || hasWhere {
				return fmt.Errorf("auth.authorization.rules[%d] authenticated rule must not include claimPath, values, or where", index)
			}
			continue
		}
		if hasSimple == hasWhere {
			return fmt.Errorf("auth.authorization.rules[%d] must define exactly one of authenticated, claimPath+values, or where.array+all", index)
		}
		if hasSimple {
			if rule.ClaimPath == "" || len(rule.Values) == 0 {
				return fmt.Errorf("auth.authorization.rules[%d] requires claimPath and values", index)
			}
			if isSensitiveClaimPath(rule.ClaimPath) {
				return fmt.Errorf("auth.authorization.rules[%d].claimPath must not use pid, SSN, or fødselsnummer", index)
			}
			continue
		}
		if rule.Where.Array == "" || len(rule.Where.All) == 0 {
			return fmt.Errorf("auth.authorization.rules[%d] requires where.array and where.all", index)
		}
		for conditionIndex, condition := range rule.Where.All {
			if condition.ClaimPath == "" || len(condition.Values) == 0 {
				return fmt.Errorf("auth.authorization.rules[%d].where.all[%d] requires claimPath and values", index, conditionIndex)
			}
			if isSensitiveClaimPath(condition.ClaimPath) {
				return fmt.Errorf("auth.authorization.rules[%d].where.all[%d].claimPath must not use pid, SSN, or fødselsnummer", index, conditionIndex)
			}
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

func EvaluateAuthorization(policy AuthorizationConfig, claims map[string]any) AuthorizationDecision {
	for _, rule := range policy.Rules {
		if rule.Effect != authorizationEffectAllow {
			continue
		}
		if rule.Authenticated {
			return AuthorizationDecision{Allowed: true, RuleID: rule.ID}
		}
		if rule.ClaimPath != "" && claimPathMatches(claims, rule.ClaimPath, rule.Values) {
			return AuthorizationDecision{Allowed: true, RuleID: rule.ID}
		}
		if rule.Where.Array != "" && whereArrayMatches(claims, rule.Where) {
			return AuthorizationDecision{Allowed: true, RuleID: rule.ID}
		}
	}
	return AuthorizationDecision{Allowed: false}
}

func logAuthorizationDecision(decision AuthorizationDecision, agentKey, subject string) {
	ruleID := decision.RuleID
	if ruleID == "" {
		ruleID = "-"
	}
	outcome := authorizationDecisionDeny
	if decision.Allowed {
		outcome = "allow"
	}
	log.Printf("gateway authorization decision=%s rule=%s agent=%s subject_hash=%s", outcome, ruleID, sanitizeLogValue(agentKey), shortHash(subject))
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
