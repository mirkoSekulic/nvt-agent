package gateway

import (
	"log"

	"github.com/mirkoSekulic/nvt-agent/protocol/eligibility"
)

// AdmissionConfig controls whether an authenticated principal may receive a
// gateway session. It is deliberately independent from AgentRun authorization.
type AdmissionConfig = eligibility.Policy
type AdmissionRule = eligibility.Rule

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
	return eligibility.ParsePolicy(raw, "gateway admission policy")
}
