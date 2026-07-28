// Package nativesession owns the trusted native guest's short-lived outbound
// session. It never reads or persists the root runtime identity.
package nativesession

import (
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/contract"
)

const (
	ConfigurationVersion  = 1
	MaxConfigurationBytes = 64 << 10
	ReadinessFileName     = "session-ready"

	ReasonIdentityUnavailable Reason = "identity-unavailable"
	ReasonGatewayUnavailable  Reason = "gateway-unavailable"
	ReasonGatewayDenied       Reason = "gateway-denied"
	ReasonAgentdUnavailable   Reason = "agentd-unavailable"
	ReasonProtocolInvalid     Reason = "protocol-invalid"
	ReasonCredentialExpired   Reason = "credential-expired"
	ReasonConfiguration       Reason = "configuration-invalid"
)

type Configuration struct {
	Version            int    `json:"version"`
	RuntimeDirectory   string `json:"runtime_directory"`
	IdentitySocketPath string `json:"identity_socket_path"`
	AgentdSocketPath   string `json:"agentd_socket_path"`
	GatewayEndpoint    string `json:"gateway_endpoint"`
	CAPEMPath          string `json:"ca_pem_path"`
}

type Reason string

type Failure struct {
	reason    Reason
	temporary bool
	uncertain bool
}

func (failure *Failure) Error() string {
	return "native guest session unavailable: " + string(failure.reason)
}
func (failure *Failure) Reason() Reason  { return failure.reason }
func (failure *Failure) Temporary() bool { return failure.temporary }
func (failure *Failure) Uncertain() bool { return failure.uncertain }

func fail(reason Reason, temporary, uncertain bool) error {
	return &Failure{reason: reason, temporary: temporary, uncertain: uncertain}
}

func FailureDetails(err error) (Reason, bool, bool) {
	var value *Failure
	if !errors.As(err, &value) {
		return ReasonProtocolInvalid, false, false
	}
	return value.reason, value.temporary, value.uncertain
}

func LoadConfiguration(path string) (Configuration, error) {
	data, err := readProcessOwnedFile(path, MaxConfigurationBytes)
	if err != nil {
		return Configuration{}, fail(ReasonConfiguration, false, false)
	}
	defer zero(data)
	var value Configuration
	if contract.DecodeStrict(data, MaxConfigurationBytes, &value) != nil || validateConfiguration(value) != nil {
		return Configuration{}, fail(ReasonConfiguration, false, false)
	}
	return value, nil
}

func validateConfiguration(value Configuration) error {
	if value.Version != ConfigurationVersion || !validDirectory(value.RuntimeDirectory) ||
		!validFile(value.IdentitySocketPath) || !validFile(value.AgentdSocketPath) || !validFile(value.CAPEMPath) ||
		filepath.Dir(value.IdentitySocketPath) == value.RuntimeDirectory || filepath.Dir(value.AgentdSocketPath) == value.RuntimeDirectory ||
		value.IdentitySocketPath == value.AgentdSocketPath || validateGatewayEndpoint(value.GatewayEndpoint) != nil {
		return errors.New("native session configuration is invalid")
	}
	return nil
}

func validateGatewayEndpoint(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "tls" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.String() != value || strings.Contains(value, "\\") || parsed.Hostname() == "" || parsed.Port() == "" {
		return errors.New("native session gateway endpoint is invalid")
	}
	if net.ParseIP(parsed.Hostname()) != nil {
		return errors.New("native session gateway endpoint must use DNS")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return errors.New("native session gateway endpoint is invalid")
	}
	return nil
}

func validDirectory(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/" && !strings.ContainsRune(value, 0)
}

func validFile(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && filepath.Dir(value) != value && !strings.ContainsRune(value, 0)
}

func (Configuration) String() string   { return "[non-secret native session configuration]" }
func (Configuration) GoString() string { return "[non-secret native session configuration]" }

func ensureRuntimeDirectory(path string) error {
	if !validDirectory(path) {
		return errors.New("native session runtime directory is invalid")
	}
	if err := os.Mkdir(path, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o750 || info.Mode()&os.ModeSymlink != 0 || !ownedByProcess(info) {
		return errors.New("native session runtime directory is unsafe")
	}
	return nil
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
