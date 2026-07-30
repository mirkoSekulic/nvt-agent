// Package nativeegress owns the trusted native guest's purpose-separated
// mediated-egress session establishment. It never reads or persists the root
// runtime identity or an egress credential.
package nativeegress

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/contract"
	protocol "github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

const (
	ConfigurationVersion  = 1
	MaxConfigurationBytes = 64 << 10
	ReadinessFileName     = "egress-ready"
	CaptureInspectBytes   = 16 << 10
	CaptureMaxConnections = protocol.MaxActiveFlows

	ReasonIdentityUnavailable Reason = "identity-unavailable"
	ReasonRelayUnavailable    Reason = "relay-unavailable"
	ReasonRelayDenied         Reason = "relay-denied"
	ReasonProtocolInvalid     Reason = "protocol-invalid"
	ReasonCredentialExpired   Reason = "credential-expired"
	ReasonCaptureUnavailable  Reason = "capture-unavailable"
	ReasonConfiguration       Reason = "configuration-invalid"
)

type Configuration struct {
	Version            int                   `json:"version"`
	RuntimeDirectory   string                `json:"runtime_directory"`
	IdentitySocketPath string                `json:"identity_socket_path"`
	RelayEndpoint      string                `json:"relay_endpoint"`
	CAPEMPath          string                `json:"ca_pem_path"`
	Capture            *CaptureConfiguration `json:"capture,omitempty"`
}

// CaptureConfiguration is non-secret provider-owned transport plumbing. The
// listener is a literal guest loopback address; destination authority comes
// only from the kernel original-destination record and bounded preface
// inspection, never from this configuration.
type CaptureConfiguration struct {
	ListenAddress  string `json:"listen_address"`
	CapabilityHint string `json:"capability_hint,omitempty"`
}

type Reason string

type Failure struct {
	reason    Reason
	temporary bool
	uncertain bool
}

func (failure *Failure) Error() string {
	return "native guest egress unavailable: " + string(failure.reason)
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
		!validFile(value.IdentitySocketPath) || !validFile(value.CAPEMPath) ||
		filepath.Dir(value.IdentitySocketPath) == value.RuntimeDirectory ||
		value.IdentitySocketPath == value.CAPEMPath || validateRelayEndpoint(value.RelayEndpoint) != nil ||
		validateCaptureConfiguration(value.Capture) != nil {
		return errors.New("native egress configuration is invalid")
	}
	return nil
}

func validateCaptureConfiguration(value *CaptureConfiguration) error {
	if value == nil {
		return nil
	}
	host, portText, err := net.SplitHostPort(value.ListenAddress)
	if err != nil {
		return errors.New("native egress capture configuration is invalid")
	}
	address, err := netip.ParseAddr(host)
	port, portErr := strconv.Atoi(portText)
	if err != nil || address.Zone() != "" || !address.IsLoopback() || address.String() != host || portErr != nil ||
		port < 1024 || port > 65535 || portText != strconv.Itoa(port) {
		return errors.New("native egress capture configuration is invalid")
	}
	if protocol.ValidateDestination(protocol.Destination{
		Network:        protocol.NetworkTCP,
		Host:           "capture.invalid",
		Port:           443,
		CapabilityHint: value.CapabilityHint,
	}) != nil {
		return errors.New("native egress capture configuration is invalid")
	}
	return nil
}

func validateRelayEndpoint(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "tls" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.String() != value || strings.Contains(value, "\\") || parsed.Hostname() == "" || parsed.Port() == "" {
		return errors.New("native egress relay endpoint is invalid")
	}
	if net.ParseIP(parsed.Hostname()) != nil || !canonicalDNSName(parsed.Hostname()) {
		return errors.New("native egress relay endpoint must use DNS")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 || parsed.Port() != strconv.Itoa(port) {
		return errors.New("native egress relay endpoint is invalid")
	}
	return nil
}

func canonicalDNSName(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validDirectory(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/" && !strings.ContainsRune(value, 0)
}

func validFile(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && filepath.Dir(value) != value && !strings.ContainsRune(value, 0)
}

func (Configuration) String() string   { return "[non-secret native egress configuration]" }
func (Configuration) GoString() string { return "[non-secret native egress configuration]" }

func ensureRuntimeDirectory(path string, shared bool) error {
	if !validDirectory(path) {
		return errors.New("native egress runtime directory is invalid")
	}
	mode := os.FileMode(0o700)
	if shared {
		mode = 0o750
	}
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || info == nil {
		return errors.New("native egress runtime directory is unsafe")
	}
	actualMode := info.Mode().Perm()
	modeValid := actualMode == mode || (!shared && actualMode == 0o750)
	if !info.IsDir() || !modeValid || info.Mode()&os.ModeSymlink != 0 || !ownedByProcess(info) ||
		(actualMode == 0o750 && !groupOwnedByProcess(info)) {
		return errors.New("native egress runtime directory is unsafe")
	}
	return nil
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
