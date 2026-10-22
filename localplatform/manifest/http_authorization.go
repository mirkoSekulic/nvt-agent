package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

// HTTPCredentialAccess retains the names-only shorthand for legacy host grants.
type HTTPCredentialAccess struct {
	Provider      string                    `json:"provider"`
	Authorization *BrokerGrantAuthorization `json:"authorization,omitempty"`
}

func (a *HTTPCredentialAccess) UnmarshalJSON(data []byte) error {
	var name string
	if json.Unmarshal(data, &name) == nil && name != "" {
		*a = HTTPCredentialAccess{Provider: name}
		return nil
	}
	type plain HTTPCredentialAccess
	var value plain
	if err := strictJSON(data, &value); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if raw, present := fields["authorization"]; present {
		policy, err := decodeHTTPAuthorization(raw)
		if err != nil {
			return err
		}
		value.Authorization = policy
	}
	*a = HTTPCredentialAccess(value)
	return nil
}

func (a HTTPCredentialAccess) MarshalJSON() ([]byte, error) {
	if a.Authorization == nil {
		return json.Marshal(a.Provider)
	}
	type plain HTTPCredentialAccess
	return json.Marshal(plain(a))
}

func httpCredentialNames(entries []HTTPCredentialAccess) []string {
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.Provider
	}
	return names
}

var httpSegment = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

func validateHTTPAuthorization(policy *BrokerGrantAuthorization) error {
	invalid := errors.New("HTTP authorization requires defaultAction deny and bounded http.METHOD / http/host/path rules")
	if policy == nil || !oneOf(policy.DefaultAction, "", "deny") || len(policy.Rules) > 128 {
		return invalid
	}
	seen := map[string]bool{}
	for _, rule := range policy.Rules {
		if !oneOf(rule.Operation, "http.GET", "http.HEAD", "http.POST", "http.PUT", "http.PATCH", "http.DELETE", "http.OPTIONS") || !strings.HasPrefix(rule.Resource, "http/") {
			return invalid
		}
		host, path, found := strings.Cut(strings.TrimPrefix(rule.Resource, "http/"), "/")
		if !found || len(host) > 253 || len(path)+1 > 2048 {
			return invalid
		}
		for _, label := range strings.Split(host, ".") {
			if !validRunIDName(label) {
				return invalid
			}
		}
		parts := strings.Split(path, "/")
		if len(parts) > 64 {
			return invalid
		}
		if path != "" {
			for _, part := range parts {
				if part == "." || part == ".." || part != "*" && !httpSegment.MatchString(part) {
					return invalid
				}
			}
		}
		key := rule.Operation + " " + rule.Resource
		if seen[key] {
			return invalid
		}
		seen[key] = true
	}
	return nil
}

func tokenHTTPAuthorization(provider BrokerProvider) (*BrokerGrantAuthorization, error) {
	if provider.Allow == nil {
		return nil, nil
	}
	if provider.Plugin != "token" || provider.Mediation.Git || len(provider.Allow) != 1 || provider.Allow["authorization"] == nil {
		return nil, errors.New("explicit token allow must contain HTTP authorization on a separate non-Git provider")
	}
	data, err := json.Marshal(provider.Allow["authorization"])
	if err != nil {
		return nil, err
	}
	return decodeHTTPAuthorization(data)
}

func decodeHTTPAuthorization(data []byte) (*BrokerGrantAuthorization, error) {
	var policy BrokerGrantAuthorization
	if err := strictJSON(data, &policy); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	if fields == nil {
		return nil, errors.New("HTTP authorization must be an object")
	}
	for _, key := range []string{"defaultAction", "rules"} {
		if bytes.Equal(bytes.TrimSpace(fields[key]), []byte("null")) {
			return nil, errors.New("HTTP authorization fields must not be null")
		}
	}
	return &policy, validateHTTPAuthorization(&policy)
}

func compileHTTPAuthorization(policy *BrokerGrantAuthorization) *BrokerGrantAuthorization {
	result := cloneGrantAuthorization(policy)
	if result != nil {
		result.DefaultAction = "deny"
	}
	return result
}
