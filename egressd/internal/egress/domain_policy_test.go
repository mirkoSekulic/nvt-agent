package egress

import (
	"strings"
	"testing"
)

func TestDomainPolicyDecision(t *testing.T) {
	policy := DomainPolicy{
		DefaultAction: "deny",
		Allow:         []string{"Example.COM."},
		Deny:          []string{"private.example.com"},
	}
	for _, test := range []struct {
		host   string
		allow  bool
		reason string
	}{
		{"example.com", true, "domain_allow_rule"},
		{"API.EXAMPLE.COM.", true, "domain_allow_rule"},
		{"notexample.com", false, "domain_default_deny"},
		{"private.example.com", false, "domain_deny_rule"},
		{"deep.private.example.com", false, "domain_deny_rule"},
		{"203.0.113.10", false, "domain_name_unavailable"},
	} {
		allowed, reason := policy.Decide(test.host)
		if allowed != test.allow || reason != test.reason {
			t.Errorf("Decide(%q) = %v, %q; want %v, %q", test.host, allowed, reason, test.allow, test.reason)
		}
	}
}

func TestDomainPolicyDefaultAllowAndDenyPrecedence(t *testing.T) {
	policy := DomainPolicy{DefaultAction: "allow", Allow: []string{"private.example.com"}, Deny: []string{"example.com"}}
	if allowed, _ := policy.Decide("unlisted.example.net"); !allowed {
		t.Fatal("default allow denied an unlisted public domain")
	}
	if allowed, reason := policy.Decide("private.example.com"); allowed || reason != "domain_deny_rule" {
		t.Fatalf("deny did not win overlap: allowed=%v reason=%q", allowed, reason)
	}
	if allowed, _ := policy.Decide("8.8.8.8"); !allowed {
		t.Fatal("default allow should leave a public IP literal to the IP destination policy")
	}
}

func TestDomainPolicyValidation(t *testing.T) {
	valid := DomainPolicy{DefaultAction: "deny", Allow: []string{"EXAMPLE.com."}, Deny: []string{"pastebin.com"}}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, policy := range []DomainPolicy{
		{DefaultAction: ""},
		{DefaultAction: "deny", Allow: []string{"127.0.0.1"}},
		{DefaultAction: "deny", Allow: []string{"example.com", "EXAMPLE.COM."}},
		{DefaultAction: "allow", Deny: []string{"bad..example"}},
	} {
		if err := policy.Validate(); err == nil {
			t.Fatalf("invalid policy accepted: %#v", policy)
		}
	}
}

func TestDomainPolicyRejectsContradictoryInjectionRoute(t *testing.T) {
	config := ForwardProxyConfig{
		Listen:       "127.0.0.1:8470",
		DomainPolicy: &DomainPolicy{DefaultAction: "deny", Allow: []string{"allowed.example"}},
		InjectRoutes: []ForwardProxyInjectRoute{{Host: "blocked.example", Capability: "provider", Upstream: "blocked.example:443"}},
	}
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "denied by domain_policy") {
		t.Fatalf("contradictory injection route error = %v", err)
	}
}

func TestTransparentPolicyDecisionPrecedesInjectionSelection(t *testing.T) {
	proxy := &ForwardProxy{Config: ForwardProxyConfig{
		TransparentMode: true,
		DomainPolicy:    &DomainPolicy{DefaultAction: "deny", Allow: []string{"allowed.example"}},
		AllowPorts:      []int{443},
	}}
	if allowed, reason := proxy.allowed(connectTarget{host: "api.allowed.example", port: 443}); !allowed || reason != "domain_allow_rule" {
		t.Fatalf("allowed captured destination = %v, %q", allowed, reason)
	}
	if allowed, reason := proxy.allowed(connectTarget{host: "direct-bypass.example", port: 443}); allowed || reason != "domain_default_deny" {
		t.Fatalf("unlisted captured destination = %v, %q", allowed, reason)
	}
}
