package eligibility

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
)

const (
	DefaultDeny = "deny"
	EffectAllow = "allow"

	maxRules              = 64
	maxConditions         = 16
	maxValues             = 64
	maxRuleValueBytes     = 1024
	maxPathSegments       = 16
	maxSelectedClaimNodes = 512
)

var (
	ruleIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	claimPathPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*(?:\[\])?(?:\.[A-Za-z_][A-Za-z0-9_-]*(?:\[\])?)*$`)
)

// Policy is a provider-neutral, default-deny login eligibility contract.
type Policy struct {
	Default string `json:"default"`
	Rules   []Rule `json:"rules"`
}

type Rule struct {
	ID            string   `json:"id"`
	Effect        string   `json:"effect"`
	Authenticated bool     `json:"authenticated"`
	ClaimPath     string   `json:"claimPath"`
	Values        []string `json:"values"`
	Where         Where    `json:"where"`
}

type Where struct {
	Array string      `json:"array"`
	All   []Condition `json:"all"`
}

type Condition struct {
	ClaimPath string   `json:"claimPath"`
	Values    []string `json:"values"`
}

type Decision struct {
	Allowed bool
	RuleID  string
}

// Validate rejects ambiguous or unbounded policy configuration.
func (p Policy) Validate(prefix string) error {
	if prefix == "" {
		prefix = "eligibility"
	}
	decision := p.Default
	if decision == "" {
		decision = DefaultDeny
	}
	if decision != DefaultDeny {
		return fmt.Errorf("%s.default must be %q", prefix, DefaultDeny)
	}
	if len(p.Rules) > maxRules {
		return fmt.Errorf("%s.rules must contain at most %d entries", prefix, maxRules)
	}
	seen := make(map[string]struct{}, len(p.Rules))
	for index, rule := range p.Rules {
		if !ruleIDPattern.MatchString(rule.ID) {
			return fmt.Errorf("%s.rules[%d].id must be a bounded identifier", prefix, index)
		}
		if _, exists := seen[rule.ID]; exists {
			return fmt.Errorf("%s.rules[%d].id is duplicated", prefix, index)
		}
		seen[rule.ID] = struct{}{}
		if rule.Effect != EffectAllow {
			return fmt.Errorf("%s.rules[%d].effect must be %q", prefix, index, EffectAllow)
		}
		hasScalar := rule.ClaimPath != "" || len(rule.Values) > 0
		hasWhere := rule.Where.Array != "" || len(rule.Where.All) > 0
		predicates := 0
		for _, present := range []bool{rule.Authenticated, hasScalar, hasWhere} {
			if present {
				predicates++
			}
		}
		if predicates != 1 {
			return fmt.Errorf("%s.rules[%d] must define exactly one of authenticated, claimPath+values, or where.array+all", prefix, index)
		}
		if rule.Authenticated {
			continue
		}
		if hasScalar {
			if err := validatePredicate(prefix, index, -1, rule.ClaimPath, rule.Values); err != nil {
				return err
			}
			continue
		}
		if !validClaimPath(rule.Where.Array) || len(rule.Where.All) == 0 || len(rule.Where.All) > maxConditions {
			return fmt.Errorf("%s.rules[%d] requires a bounded where.array and 1..%d where.all conditions", prefix, index, maxConditions)
		}
		if isSensitivePath(rule.Where.Array) {
			return fmt.Errorf("%s.rules[%d].where.array must be a non-sensitive JSON path", prefix, index)
		}
		for conditionIndex, condition := range rule.Where.All {
			if err := validatePredicate(prefix, index, conditionIndex, condition.ClaimPath, condition.Values); err != nil {
				return err
			}
		}
	}
	return nil
}

func validatePredicate(prefix string, ruleIndex, conditionIndex int, path string, values []string) error {
	field := fmt.Sprintf("%s.rules[%d]", prefix, ruleIndex)
	if conditionIndex >= 0 {
		field = fmt.Sprintf("%s.where.all[%d]", field, conditionIndex)
	}
	if !validClaimPath(path) || len(values) == 0 || len(values) > maxValues {
		return fmt.Errorf("%s requires a bounded claimPath and 1..%d values", field, maxValues)
	}
	if isSensitivePath(path) {
		return fmt.Errorf("%s.claimPath must be a non-sensitive JSON path", field)
	}
	seen := make(map[string]struct{}, len(values))
	for valueIndex, value := range values {
		if value == "" || len(value) > maxRuleValueBytes || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("%s.values[%d] must be a bounded non-empty string", field, valueIndex)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s.values[%d] is duplicated", field, valueIndex)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validClaimPath(path string) bool {
	return claimPathPattern.MatchString(path) && len(strings.Split(path, ".")) <= maxPathSegments
}

func ValidClaimPath(path string) bool { return validClaimPath(path) }

// Evaluate applies the same fail-closed rule semantics in every consumer.
func Evaluate(policy Policy, claims map[string]any) Decision {
	for _, rule := range policy.Rules {
		if rule.Effect != EffectAllow {
			continue
		}
		if rule.Authenticated {
			return Decision{Allowed: true, RuleID: rule.ID}
		}
		if rule.ClaimPath != "" && claimPathMatches(claims, rule.ClaimPath, rule.Values) {
			return Decision{Allowed: true, RuleID: rule.ID}
		}
		if rule.Where.Array != "" && whereMatches(claims, rule.Where) {
			return Decision{Allowed: true, RuleID: rule.ID}
		}
	}
	return Decision{}
}

func whereMatches(claims map[string]any, where Where) bool {
	selected, ok := selectValues(claims, where.Array)
	if !ok {
		return false
	}
	for _, item := range selected {
		object, objectOK := item.(map[string]any)
		if !objectOK {
			continue
		}
		matches := true
		for _, condition := range where.All {
			if !claimPathMatches(object, condition.ClaimPath, condition.Values) {
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
	wanted := make(map[string]struct{}, len(values))
	for _, value := range values {
		wanted[value] = struct{}{}
	}
	selected, ok := selectValues(root, path)
	if !ok {
		return false
	}
	for _, value := range selected {
		if scalar, scalarOK := scalarString(value); scalarOK {
			if _, exists := wanted[scalar]; exists {
				return true
			}
		}
	}
	return false
}

// Select returns values selected by a bounded dotted JSON path. Array markers
// flatten only the named array; a path without [] retains the selected value.
func Select(root any, path string) ([]any, bool) {
	if path == "$" {
		return []any{root}, true
	}
	if !validClaimPath(path) {
		return nil, false
	}
	return selectValues(root, path)
}

func selectValues(root any, path string) ([]any, bool) {
	current := []any{root}
	for _, rawSegment := range strings.Split(path, ".") {
		array := strings.HasSuffix(rawSegment, "[]")
		segment := strings.TrimSuffix(rawSegment, "[]")
		next := make([]any, 0)
		for _, value := range current {
			object, ok := value.(map[string]any)
			if !ok {
				continue
			}
			value, ok = object[segment]
			if !ok {
				continue
			}
			if array {
				items, itemsOK := sliceValues(value)
				if !itemsOK || len(next)+len(items) > maxSelectedClaimNodes {
					return nil, false
				}
				next = append(next, items...)
			} else {
				if len(next) == maxSelectedClaimNodes {
					return nil, false
				}
				next = append(next, value)
			}
		}
		current = next
	}
	return current, true
}

func sliceValues(value any) ([]any, bool) {
	if values, ok := value.([]any); ok {
		return values, true
	}
	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() || (reflected.Kind() != reflect.Slice && reflected.Kind() != reflect.Array) {
		return nil, false
	}
	if reflected.Len() > maxSelectedClaimNodes {
		return nil, false
	}
	values := make([]any, 0, reflected.Len())
	for index := 0; index < reflected.Len(); index++ {
		if !reflected.Index(index).CanInterface() {
			return nil, false
		}
		values = append(values, reflected.Index(index).Interface())
	}
	return values, true
}

func scalarString(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case bool:
		if typed {
			return "true", true
		}
		return "false", true
	case json.Number:
		return typed.String(), true
	case float64:
		return fmt.Sprint(typed), true
	case float32:
		return fmt.Sprint(typed), true
	case int:
		return fmt.Sprint(typed), true
	case int8:
		return fmt.Sprint(typed), true
	case int16:
		return fmt.Sprint(typed), true
	case int32:
		return fmt.Sprint(typed), true
	case int64:
		return fmt.Sprint(typed), true
	case uint:
		return fmt.Sprint(typed), true
	case uint8:
		return fmt.Sprint(typed), true
	case uint16:
		return fmt.Sprint(typed), true
	case uint32:
		return fmt.Sprint(typed), true
	case uint64:
		return fmt.Sprint(typed), true
	default:
		return "", false
	}
}

func isSensitivePath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(path, "ø", "o"))
	for _, part := range strings.FieldsFunc(normalized, func(r rune) bool {
		return r == '.' || r == '[' || r == ']' || r == '-' || r == '_'
	}) {
		switch part {
		case "pid", "ssn", "fodselsnummer", "foedselsnummer":
			return true
		}
	}
	return false
}

// ParsePolicy strictly parses an optional eligibility policy. Empty input
// means the consumer's historical behavior remains in force.
func ParsePolicy(raw, prefix string) (*Policy, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var policy Policy
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return nil, fmt.Errorf("parse %s: %w", prefix, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse %s: trailing JSON value", prefix)
	}
	if err := policy.Validate(prefix); err != nil {
		return nil, err
	}
	return &policy, nil
}
