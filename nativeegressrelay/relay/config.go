// Package relay implements the trusted cluster-side admission, lifecycle, and
// bounded flow-transport boundary for nvt.native-egress/v1, including an
// optional exact-binding adapter to the existing per-run egressd CONNECT path.
package relay

import (
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

const (
	ConfigurationVersion       = 2
	MaxConfigurationBytes      = 64 << 10
	maxTrustFileBytes          = 1 << 20
	maxPendingTLSHandshakes    = 32
	defaultAuthenticationAgent = "nvt-native-egress-relay"
)

var dnsNamePattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)*$`)

// Configuration contains only non-secret listener and trust-file metadata.
// Private key and CA material are read from process-owned files.
type Configuration struct {
	Version                      int    `json:"version"`
	ListenAddress                string `json:"listen_address"`
	TLSCertificateFile           string `json:"tls_certificate_file"`
	TLSKeyFile                   string `json:"tls_key_file"`
	ControlListenAddress         string `json:"control_listen_address"`
	ControlTLSCertificateFile    string `json:"control_tls_certificate_file"`
	ControlTLSKeyFile            string `json:"control_tls_key_file"`
	ControlCredentialFile        string `json:"control_credential_file"`
	ControlTimeoutSeconds        int    `json:"control_timeout_seconds"`
	BrokerURL                    string `json:"broker_url"`
	BrokerServerName             string `json:"broker_server_name"`
	BrokerCAFile                 string `json:"broker_ca_file"`
	AuthenticationTimeoutSeconds int    `json:"authentication_timeout_seconds"`
	RevalidationIntervalSeconds  int    `json:"revalidation_interval_seconds"`
}

func LoadConfiguration(path string) (Configuration, error) {
	data, err := readProcessOwnedFile(path, MaxConfigurationBytes, true)
	if err != nil {
		return Configuration{}, errors.New("native egress relay configuration is invalid")
	}
	defer zero(data)
	var value Configuration
	if guestenrollment.DecodeStrictJSON(data, MaxConfigurationBytes, &value) != nil || value.validate() != nil {
		return Configuration{}, errors.New("native egress relay configuration is invalid")
	}
	return value, nil
}

func (config Configuration) validate() error {
	if config.Version != ConfigurationVersion || validateListenAddress(config.ListenAddress) != nil ||
		validateListenAddress(config.ControlListenAddress) != nil || config.ListenAddress == config.ControlListenAddress {
		return errors.New("native egress relay configuration is invalid")
	}
	paths := []string{
		config.TLSCertificateFile, config.TLSKeyFile, config.ControlTLSCertificateFile,
		config.ControlTLSKeyFile, config.ControlCredentialFile, config.BrokerCAFile,
	}
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if !validFilePath(path) {
			return errors.New("native egress relay configuration is invalid")
		}
		if _, exists := seen[path]; exists {
			return errors.New("native egress relay configuration is invalid")
		}
		seen[path] = struct{}{}
	}
	endpoint, err := url.Parse(config.BrokerURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.Opaque != "" ||
		endpoint.Path != "" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" ||
		endpoint.String() != config.BrokerURL || endpoint.Hostname() != config.BrokerServerName || !canonicalDNSName(config.BrokerServerName) {
		return errors.New("native egress relay configuration is invalid")
	}
	if port := endpoint.Port(); port != "" {
		parsed, parseErr := strconv.Atoi(port)
		if parseErr != nil || parsed < 1 || parsed > 65535 || port != strconv.Itoa(parsed) {
			return errors.New("native egress relay configuration is invalid")
		}
	}
	authenticationTimeout := time.Duration(config.AuthenticationTimeoutSeconds) * time.Second
	revalidationInterval := time.Duration(config.RevalidationIntervalSeconds) * time.Second
	controlTimeout := time.Duration(config.ControlTimeoutSeconds) * time.Second
	if authenticationTimeout <= 0 || authenticationTimeout > nativeegress.HandshakeTimeout ||
		revalidationInterval <= 0 || revalidationInterval > nativeegress.RevalidationInterval ||
		controlTimeout <= 0 || controlTimeout > nativeegress.TargetPublicationTimeout {
		return errors.New("native egress relay configuration is invalid")
	}
	return nil
}

func validateListenAddress(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || strings.ContainsAny(host, "\x00\r\n") {
		return errors.New("native egress relay listen address is invalid")
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort < 1 || parsedPort > 65535 || port != strconv.Itoa(parsedPort) {
		return errors.New("native egress relay listen address is invalid")
	}
	if host == "" {
		return nil
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" || address.String() != host {
		return errors.New("native egress relay listen address is invalid")
	}
	return nil
}

func canonicalDNSName(value string) bool {
	return value != "" && len(value) <= 253 && value == strings.ToLower(value) && net.ParseIP(value) == nil && dnsNamePattern.MatchString(value)
}

func validFilePath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && filepath.Dir(value) != value && !strings.ContainsRune(value, 0)
}

func loadServingTLS(config Configuration) (*tls.Config, error) {
	return loadTLSIdentity(config.TLSCertificateFile, config.TLSKeyFile, nil)
}

func loadControlTLS(config Configuration) (*tls.Config, error) {
	return loadTLSIdentity(config.ControlTLSCertificateFile, config.ControlTLSKeyFile, []string{"http/1.1"})
}

func loadTLSIdentity(certificateFile, keyFile string, nextProtocols []string) (*tls.Config, error) {
	certificatePEM, err := readProcessOwnedFile(certificateFile, maxTrustFileBytes, false)
	if err != nil {
		return nil, errors.New("native egress relay TLS identity is invalid")
	}
	defer zero(certificatePEM)
	keyPEM, err := readProcessOwnedFile(keyFile, maxTrustFileBytes, true)
	if err != nil {
		return nil, errors.New("native egress relay TLS identity is invalid")
	}
	defer zero(keyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, errors.New("native egress relay TLS identity is invalid")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate},
		NextProtos: append([]string(nil), nextProtocols...),
	}, nil
}

func (Configuration) String() string   { return "[native egress relay configuration]" }
func (Configuration) GoString() string { return "[native egress relay configuration]" }

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
