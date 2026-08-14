package networkpolicy

import "testing"

func TestValidateRunNetworkPolicy(t *testing.T) {
	for name, test := range map[string]struct {
		pool      string
		protected string
		valid     bool
	}{
		"non-overlap":        {pool: "100.64.0.0/10", protected: "10.0.0.0/8 192.168.0.0/16", valid: true},
		"mixed-family":       {pool: "100.64.0.0/10", protected: "10.0.0.0/8 fd00:1234::/48", valid: true},
		"malformed":          {pool: "100.64.0.0/10", protected: "not-a-prefix"},
		"non-canonical":      {pool: "100.64.0.0/10", protected: "192.168.1.1/16"},
		"exact-overlap":      {pool: "100.64.0.0/10", protected: "100.64.0.0/10"},
		"nested-overlap":     {pool: "100.64.0.0/10", protected: "100.100.0.0/16"},
		"containing-overlap": {pool: "100.64.0.0/10", protected: "0.0.0.0/0"},
	} {
		t.Run(name, func(t *testing.T) {
			policy, err := ValidateRunNetworkPolicy(test.pool, test.protected)
			if test.valid {
				if err != nil || policy.Pool.String() != test.pool || policy.SubnetCapacity != 262144 {
					t.Fatalf("valid policy = %#v, %v", policy, err)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}
