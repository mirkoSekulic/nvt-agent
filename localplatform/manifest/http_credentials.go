package manifest

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Host-scoped injection is separate from repository-scoped Git mediation.
// It authorizes credential use at the named HTTPS destinations, not operations
// or URL paths. The selected provider remains responsible for wire credentials.
func validateHTTPMediation(name string, provider BrokerProvider) error {
	invalid := fmt.Errorf("broker provider %q has invalid host-scoped HTTP mediation", name)
	m := provider.Mediation
	if m.Materialization != "header-inject" || len(m.Hosts) == 0 || len(m.Hosts) > MaxItems || m.Username != "" || m.TargetMode != "" || uniqueStrings(m.Hosts) != nil {
		return invalid
	}
	for _, host := range m.Hosts {
		if normalized, ok := normalizeDomain(host); !ok || normalized != host {
			return invalid
		}
	}
	// These are the existing static injection config keys, not a new provider
	// framework. Require agreement so runtime routes and the broker host ceiling
	// cannot silently diverge. Absent injection-git already defaults to false.
	hosts, ok := providerStringList(provider.Config["injection-hosts"])
	if !ok {
		return invalid
	}
	hosts = append([]string(nil), hosts...)
	expected := append([]string(nil), m.Hosts...)
	sort.Strings(hosts)
	sort.Strings(expected)
	if !reflect.DeepEqual(hosts, expected) {
		return invalid
	}
	if git, exists := provider.Config["injection-git"]; exists && git != false {
		return invalid
	}
	if provider.Plugin == "token" {
		for key := range provider.Config {
			if !oneOf(key, "injection-hosts", "injection-git", "injection-header", "injection-scheme", "injection-basic-username") {
				return invalid
			}
		}
		if len(provider.Secrets) != 1 || provider.Secrets["token-file"] == "" || provider.Config["token-env"] != nil {
			return invalid
		}
		if _, basic := provider.Config["injection-basic-username"]; basic {
			username, ok := provider.Config["injection-basic-username"].(string)
			if !ok || username == "" || strings.ContainsAny(username, ":\x00\r\n") {
				return invalid
			}
			if _, scheme := provider.Config["injection-scheme"]; scheme {
				return invalid
			}
			if header, exists := provider.Config["injection-header"]; exists && header != "authorization" {
				return invalid
			}
		}
		if raw, exists := provider.Config["injection-scheme"]; exists {
			scheme, ok := raw.(string)
			if !ok || strings.ContainsAny(scheme, "\x00\r\n") {
				return invalid
			}
		}
	}
	return nil
}
