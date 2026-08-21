package egress

import (
	"fmt"
	"net/netip"
	"strings"
)

const maxDomainPolicyEntries = 256

// Validate checks the bounded policy shape after applying the same
// normalization used for requests. Duplicates after case/trailing-dot
// normalization are rejected so rendered policy remains unambiguous.
func (p DomainPolicy) Validate() error {
	if p.DefaultAction != "allow" && p.DefaultAction != "deny" {
		return fmt.Errorf("default_action must be allow or deny")
	}
	if len(p.Allow) > maxDomainPolicyEntries || len(p.Deny) > maxDomainPolicyEntries {
		return fmt.Errorf("allow and deny must contain at most %d entries each", maxDomainPolicyEntries)
	}
	for _, list := range []struct {
		name   string
		values []string
	}{{"allow", p.Allow}, {"deny", p.Deny}} {
		name, values := list.name, list.values
		seen := make(map[string]struct{}, len(values))
		for index, value := range values {
			normalized, err := normalizeDomainName(value)
			if err != nil {
				return fmt.Errorf("%s[%d]: %w", name, index, err)
			}
			if _, exists := seen[normalized]; exists {
				return fmt.Errorf("%s[%d] duplicates %q after normalization", name, index, normalized)
			}
			seen[normalized] = struct{}{}
		}
	}
	return nil
}

// Decide returns the sanitized allow/deny result and its audit reason. Deny
// always wins, including when a broader allow rule also matches.
func (p DomainPolicy) Decide(host string) (bool, string) {
	normalized, err := normalizeDomainName(host)
	if err != nil {
		// Under a strict policy, IP literals and unavailable/uninspectable names
		// fail closed. Under default allow they remain subject to the existing
		// IP destination and port policy.
		if p.DefaultAction == "deny" {
			return false, "domain_name_unavailable"
		}
		return true, "domain_default_allow"
	}
	for _, rule := range p.Deny {
		normalizedRule, _ := normalizeDomainName(rule)
		if domainRuleMatches(normalized, normalizedRule) {
			return false, "domain_deny_rule"
		}
	}
	for _, rule := range p.Allow {
		normalizedRule, _ := normalizeDomainName(rule)
		if domainRuleMatches(normalized, normalizedRule) {
			return true, "domain_allow_rule"
		}
	}
	if p.DefaultAction == "allow" {
		return true, "domain_default_allow"
	}
	return false, "domain_default_deny"
}

func normalizeDomainName(value string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "/\\@?#: \t\r\n%") {
		return "", fmt.Errorf("invalid domain")
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return "", fmt.Errorf("IP literals are not domain names")
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if value == "" || len(value) > 253 {
		return "", fmt.Errorf("invalid domain length")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid DNS label")
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return "", fmt.Errorf("domain must be an ASCII DNS name")
		}
	}
	return value, nil
}

func domainRuleMatches(host, rule string) bool {
	return host == rule || strings.HasSuffix(host, "."+rule)
}
