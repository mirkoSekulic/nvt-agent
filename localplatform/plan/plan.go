// Package plan defines the redacted managed-volume and mount contract shared
// by trusted state preparation and local service renderers.
package plan

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"strings"
)

type Plan struct {
	Version string   `json:"version"`
	Project string   `json:"project"`
	Volumes []Volume `json:"volumes"`
	Mounts  []Mount  `json:"mounts"`
}

// VolumeInventory is the bounded historical ownership record used by
// destructive reset. It contains ownership metadata only; secret bytes and
// host paths cannot be represented.
type VolumeInventory struct {
	Version string   `json:"version"`
	Project string   `json:"project"`
	Volumes []Volume `json:"volumes"`
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
	return canonicalJSON(value)
}

func (value VolumeInventory) CanonicalJSON() ([]byte, error) {
	return canonicalJSON(value)
}

func canonicalJSON(value any) ([]byte, error) {
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

func CredentialSlotName(account string) string {
	digest := sha256.Sum256([]byte("nvt.local-credential-slot/v1\x00" + account))
	return "slot-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:]))
}

const GeneratedConfigSuffix = "generated-config"

func StaticInputSuffix(owner, name string) string {
	return "input-" + ShortID(owner+"\x00"+name)
}

func GeneratedInputSuffix(name, consumer string) string {
	return "generated-" + ShortID(name+"\x00"+consumer)
}

func ProducerStateSuffix(name string) string {
	return "producer-" + ShortID(name) + "-state"
}

func VolumeName(project, suffix string) string { return project + "-" + suffix }
