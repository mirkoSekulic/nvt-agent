package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
)

const MaxHTTPExposures = 64

// ProfileExpose selects named HTTP routes into the workstation's shared agent
// network namespace. Upstream hosts and route ownership remain controller-owned.
type ProfileExpose struct {
	HTTP []HTTPExposure `json:"http,omitempty"`
}

type HTTPExposure struct {
	Name       string `json:"name"`
	TargetPort int    `json:"targetPort"`
}

func (e *ProfileExpose) UnmarshalJSON(data []byte) error {
	type plain ProfileExpose
	var value plain
	if err := strictJSON(data, &value); err != nil {
		return err
	}
	// An omitted list is empty, but an explicitly supplied list must be an
	// array, consistent with the native backend's expose.http contract.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(fields["http"]), []byte("null")) {
		return errors.New("expose.http must be an array")
	}
	*e = ProfileExpose(value)
	return nil
}

func validateExpose(expose *ProfileExpose) error {
	if expose == nil {
		return nil
	}
	if len(expose.HTTP) > MaxHTTPExposures {
		return errors.New("expose.http must contain at most 64 routes")
	}
	seen := make(map[string]bool, len(expose.HTTP))
	for _, route := range expose.HTTP {
		if !validRunIDName(route.Name) || seen[route.Name] || route.TargetPort < 1 || route.TargetPort > 65535 {
			return errors.New("expose.http requires unique DNS-label names and target ports in 1..65535")
		}
		seen[route.Name] = true
	}
	return nil
}
