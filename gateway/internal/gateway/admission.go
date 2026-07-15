package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
)

// AdmissionConfig controls whether an authenticated principal may receive a
// gateway session. It is deliberately independent from AgentRun authorization.
type AdmissionConfig struct {
	Default string              `json:"default"`
	Rules   []AuthorizationRule `json:"rules"`
}

func (c AdmissionConfig) validate() error {
	defaultDecision := c.Default
	if defaultDecision == "" {
		defaultDecision = authorizationDefaultDeny
	}
	if defaultDecision != authorizationDefaultDeny {
		return fmt.Errorf("auth.admission.default must be %q", authorizationDefaultDeny)
	}
	for index, rule := range c.Rules {
		if err := validateAuthorizationRule("auth.admission", index, rule, false); err != nil {
			return err
		}
	}
	return nil
}

func EvaluateAdmission(policy AdmissionConfig, principal Principal) AuthorizationDecision {
	for _, rule := range policy.Rules {
		if rule.Effect != authorizationEffectAllow || rule.Owner {
			continue
		}
		if rule.Authenticated {
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
	var config AdmissionConfig
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("parse gateway admission policy: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse gateway admission policy: trailing JSON value")
	}
	return &config, nil
}
