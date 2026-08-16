// Package plan defines the redacted managed-volume and mount contract shared
// by trusted state preparation and local service renderers.
package plan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

type Plan struct {
	Version string   `json:"version"`
	Project string   `json:"project"`
	Volumes []Volume `json:"volumes"`
	Mounts  []Mount  `json:"mounts"`
}

type Volume struct {
	Name      string            `json:"name"`
	Role      string            `json:"role"`
	Owner     string            `json:"owner"`
	Consumers []string          `json:"consumers,omitempty"`
	Labels    map[string]string `json:"labels"`
}

type Mount struct {
	Service  string `json:"service"`
	Volume   string `json:"volume"`
	Subpath  string `json:"subpath,omitempty"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"readOnly"`
}

// CanonicalJSON returns a stable redacted plan. Plan cannot represent secret
// bytes or host paths, so the result is safe for generated configuration.
func (value Plan) CanonicalJSON() ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), nil
}

// ShortID maps a logical private-input name to its non-secret mount name.
func ShortID(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:12])
}

func PrivateTarget(name string) string { return "/run/nvt-private/" + ShortID(name) }
