// Package nativeegressattachment loads the installation-owned, non-secret
// provider attachment plan used only by mediated external VM executions.
package nativeegressattachment

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
)

const (
	EnvironmentConfigFile = "NVT_NATIVE_EGRESS_ATTACHMENT_CONFIG_FILE"
	ConfigVersion         = 1
	maxConfigBytes        = 32 << 10
)

type configDocument struct {
	Version              int                                               `json:"version"`
	Generation           int64                                             `json:"generation"`
	RelayHost            string                                            `json:"relayHost"`
	RelayPort            uint16                                            `json:"relayPort"`
	RelayServerName      string                                            `json:"relayServerName"`
	CAFile               string                                            `json:"caFile"`
	RequiredDestinations []executiondriver.NativeEgressRequiredDestination `json:"requiredDestinations"`
	Redirect             executiondriver.NativeEgressRedirectIntent        `json:"redirect"`
}

// LoadConfigured returns nil only when the feature is omitted. An explicitly
// configured but unavailable or malformed plan always fails startup.
func LoadConfigured() (*executiondriver.NativeEgressAttachment, error) {
	path := os.Getenv(EnvironmentConfigFile)
	if path == "" {
		return nil, nil
	}
	if !canonicalAbsolutePath(path) {
		return nil, errors.New("native egress attachment configuration is invalid")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > maxConfigBytes {
		return nil, errors.New("native egress attachment configuration is unavailable")
	}
	var document configDocument
	if executiondriver.DecodeStrictJSON(data, &document) != nil || document.Version != ConfigVersion || !canonicalAbsolutePath(document.CAFile) {
		return nil, errors.New("native egress attachment configuration is invalid")
	}
	ca, err := os.ReadFile(document.CAFile)
	if err != nil {
		return nil, errors.New("native egress attachment trust is unavailable")
	}
	canonicalCA, err := executiondriver.CanonicalNativeEgressCAPEM(ca)
	if err != nil {
		return nil, errors.New("native egress attachment trust is invalid")
	}
	destinations, err := executiondriver.CanonicalNativeEgressDestinations(document.RequiredDestinations)
	if err != nil {
		return nil, errors.New("native egress attachment configuration is invalid")
	}
	sealed, err := executiondriver.SealNativeEgressAttachment(executiondriver.NativeEgressAttachment{
		ContractVersion: executiondriver.NativeEgressAttachmentVersion,
		Generation:      document.Generation,
		Relay: executiondriver.NativeEgressRelayAttachment{
			Host: document.RelayHost, Port: document.RelayPort, ServerName: document.RelayServerName, CAPEM: canonicalCA,
		},
		RequiredDestinations: destinations,
		Redirect:             document.Redirect,
	})
	if err != nil {
		return nil, errors.New("native egress attachment configuration is invalid")
	}
	return &sealed, nil
}

func canonicalAbsolutePath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && filepath.Dir(value) != value && !strings.ContainsRune(value, 0)
}
