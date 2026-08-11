package eligibility

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestArrayEligibilityRequiresAllPredicatesOnOneObject(t *testing.T) {
	policy := Policy{Default: DefaultDeny, Rules: []Rule{{
		ID: "eligible-party", Effect: EffectAllow,
		Where: Where{Array: "authorization_details[].authorized_parties[]", All: []Condition{
			{ClaimPath: "organization.ID", Values: []string{"0192:123456789"}},
			{ClaimPath: "resource", Values: []string{"approved-resource"}},
		}},
	}}}
	if err := policy.Validate("eligibility"); err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"authorization_details": []any{map[string]any{"authorized_parties": []any{
		map[string]any{"organization": map[string]any{"ID": "0192:123456789"}, "resource": "approved-resource"},
	}}}}
	if decision := Evaluate(policy, claims); !decision.Allowed || decision.RuleID != "eligible-party" {
		t.Fatalf("matching object denied: %#v", decision)
	}
	claims["authorization_details"] = []any{map[string]any{"authorized_parties": []any{
		map[string]any{"organization": map[string]any{"ID": "0192:123456789"}, "resource": "other"},
		map[string]any{"organization": map[string]any{"ID": "other"}, "resource": "approved-resource"},
	}}}
	if decision := Evaluate(policy, claims); decision.Allowed {
		t.Fatalf("split-object predicates allowed: %#v", decision)
	}
}

func TestScalarEligibilityCompatibility(t *testing.T) {
	policy := Policy{Rules: []Rule{{ID: "group", Effect: EffectAllow, ClaimPath: "groups[]", Values: []string{"operators"}}}}
	for _, claims := range []map[string]any{
		{"groups": []any{"operators"}},
		{"groups": []string{"operators"}},
	} {
		if !Evaluate(policy, claims).Allowed {
			t.Fatalf("legacy scalar claim denied: %#v", claims)
		}
	}
	if Evaluate(policy, map[string]any{"groups": []any{map[string]any{"name": "operators"}}}).Allowed {
		t.Fatal("object was string-coerced into a scalar match")
	}
}

func TestEligibilityFailsClosedForMalformedOrExcessiveArrays(t *testing.T) {
	policy := Policy{Rules: []Rule{{
		ID: "member", Effect: EffectAllow,
		Where: Where{Array: "members[]", All: []Condition{{ClaimPath: "state", Values: []string{"active"}}}},
	}}}
	for _, claims := range []map[string]any{
		{"members": "not-an-array"},
		{"members": []any{"not-an-object"}},
		{"members": make([]any, maxSelectedClaimNodes+1)},
	} {
		if Evaluate(policy, claims).Allowed {
			t.Fatalf("malformed or excessive claims allowed: %#v", claims)
		}
	}
}

func TestPolicyValidationAndParsingAreStrictAndProviderNeutral(t *testing.T) {
	valid := `{"default":"deny","rules":[{"id":"member","effect":"allow","where":{"array":"members[]","all":[{"claimPath":"organization.ID","values":["0192:123456789"]}]}}]}`
	if _, err := ParsePolicy(valid, "auth.eligibility"); err != nil {
		t.Fatal(err)
	}
	invalid := []string{
		`{"default":"allow","rules":[]}`,
		`{"default":"deny","rules":[{"id":"member","effect":"allow","owner":true}]}`,
		`{"default":"deny","rules":[{"id":"member","effect":"allow","claimPath":"pid","values":["x"]}]}`,
		`{"default":"deny","rules":[],"unknown":true}`,
	}
	for _, raw := range invalid {
		if _, err := ParsePolicy(raw, "auth.eligibility"); err == nil {
			t.Fatalf("invalid policy accepted: %s", raw)
		}
	}
	large := strings.Repeat("x", maxRuleValueBytes+1)
	policy := Policy{Rules: []Rule{{ID: "member", Effect: EffectAllow, ClaimPath: "group", Values: []string{large}}}}
	if err := policy.Validate("auth.eligibility"); err == nil {
		t.Fatal("oversized predicate value accepted")
	}
	if _, ok := scalarString(json.Number("12345678901234567890")); !ok {
		t.Fatal("exact JSON number rejected")
	}
}
