package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/mirkoSekulic/nvt-agent/protocol/eligibility"
)

// AdmissionConfig controls whether an authenticated principal may receive a
// gateway session. It is deliberately independent from AgentRun authorization.
type AdmissionConfig = eligibility.Policy
type AdmissionRule = eligibility.Rule

// admissionRuleDocument is a gateway-only decoding shim for the former
// AuthorizationRule-shaped admission schema. Explicit owner:false had no
// semantics and remains accepted; owner:true remains invalid.
type admissionRuleDocument struct {
	eligibility.Rule
	Owner *bool `json:"owner,omitempty"`
}

type admissionPolicyDocument struct {
	Default string                  `json:"default"`
	Rules   []admissionRuleDocument `json:"rules"`
}

func validateAdmission(c AdmissionConfig) error {
	return c.Validate("auth.admission")
}

func EvaluateAdmission(policy AdmissionConfig, principal Principal) AuthorizationDecision {
	decision := eligibility.Evaluate(policy, principal.Claims)
	return AuthorizationDecision{Allowed: decision.Allowed, RuleID: decision.RuleID}
}

func logAdmissionDecision(decision AuthorizationDecision, principal Principal) {
	ruleID := decision.RuleID
	if ruleID == "" {
		ruleID = "-"
	}
	outcome := authorizationDecisionDeny
	if decision.Allowed {
		outcome = "allow"
	}
	log.Printf("gateway login admission decision=%s rule=%s principal_hash=%s", outcome, sanitizeLogValue(ruleID), principalHash(principal))
}

// ParseAdmissionConfig preserves the historical behavior when the value is
// absent by returning nil. A configured empty policy is valid and denies all.
func ParseAdmissionConfig(raw string) (*AdmissionConfig, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var document admissionPolicyDocument
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("parse gateway admission policy: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse gateway admission policy: trailing JSON value")
	}
	policy := AdmissionConfig{Default: document.Default, Rules: make([]AdmissionRule, 0, len(document.Rules))}
	for index, rule := range document.Rules {
		if rule.Owner != nil && *rule.Owner {
			return nil, fmt.Errorf("gateway admission policy.rules[%d].owner is not an eligibility predicate", index)
		}
		policy.Rules = append(policy.Rules, rule.Rule)
	}
	if err := validateAdmission(policy); err != nil {
		return nil, err
	}
	return &policy, nil
}
