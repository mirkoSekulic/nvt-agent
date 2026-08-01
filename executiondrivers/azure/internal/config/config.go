package config

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"golang.org/x/crypto/ssh"
)

const (
	Version        = "nvt.azure-driver/v1"
	MaxConfigBytes = 96 << 10
)

var (
	digestPattern        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	uuidPattern          = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	resourceGroupPattern = regexp.MustCompile(`^[A-Za-z0-9_().-]{1,90}$`)
	locationPattern      = regexp.MustCompile(`^[a-z0-9]{2,32}$`)
	resourceNamePattern  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,80}$`)
	vmSizePattern        = regexp.MustCompile(`^Standard_[A-Za-z0-9_]{1,48}$`)
	dnsPattern           = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)*$`)
	numericDNSPattern    = regexp.MustCompile(`^[0-9.]+$`)
)

type Configuration struct {
	ContractVersion       string           `json:"contract_version"`
	SubscriptionID        string           `json:"subscription_id"`
	ResourceGroup         string           `json:"resource_group"`
	Location              string           `json:"location"`
	SubnetResourceID      string           `json:"subnet_resource_id"`
	VMImageResourceID     string           `json:"vm_image_resource_id"`
	GuestArchitecture     string           `json:"guest_architecture"`
	VMSize                string           `json:"vm_size"`
	OSDisk                OSDisk           `json:"os_disk"`
	HostBundle            Artifact         `json:"host_bundle"`
	RegistryCAPEM         string           `json:"registry_ca_pem,omitempty"`
	EnrollmentEndpoint    string           `json:"enrollment_endpoint"`
	EnrollmentCAPEM       string           `json:"enrollment_ca_pem"`
	NativeSessionEndpoint string           `json:"native_session_endpoint"`
	NativeSessionCAPEM    string           `json:"native_session_ca_pem"`
	NativeWorkspace       *NativeWorkspace `json:"native_workspace,omitempty"`
	SSHHostPublicKey      string           `json:"ssh_host_public_key"`
	Network               BootstrapNetwork `json:"network"`
	BootstrapTimeoutSec   int              `json:"bootstrap_timeout_seconds"`
}

type OSDisk struct {
	SizeGiB            int32  `json:"size_gib"`
	StorageAccountType string `json:"storage_account_type"`
}

type Artifact struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
}

type NativeWorkspace struct {
	Endpoint         string `json:"endpoint"`
	LoopbackEndpoint string `json:"loopback_endpoint"`
}

type BootstrapNetwork struct {
	DriverSourceCIDR string `json:"driver_source_cidr"`
	DNSServer        string `json:"dns_server"`
}

func Decode(raw json.RawMessage) (Configuration, error) {
	var value Configuration
	if len(raw) == 0 || len(raw) > MaxConfigBytes || executiondriver.DecodeStrictJSON(raw, &value) != nil || Validate(value) != nil {
		return Configuration{}, errors.New("Azure execution class configuration is invalid")
	}
	return value, nil
}

func Validate(value Configuration) error {
	if value.ContractVersion != Version || !uuidPattern.MatchString(value.SubscriptionID) ||
		!resourceGroupPattern.MatchString(value.ResourceGroup) || strings.HasSuffix(value.ResourceGroup, ".") ||
		!locationPattern.MatchString(value.Location) || !vmSizePattern.MatchString(value.VMSize) || value.GuestArchitecture != "amd64" {
		return errors.New("Azure execution class identity is invalid")
	}
	if validateSubnetID(value.SubnetResourceID) != nil || validateImageVersionID(value.VMImageResourceID) != nil {
		return errors.New("Azure immutable resource selection is invalid")
	}
	if value.OSDisk.SizeGiB < 30 || value.OSDisk.SizeGiB > 2048 ||
		(value.OSDisk.StorageAccountType != "Premium_LRS" && value.OSDisk.StorageAccountType != "StandardSSD_LRS") {
		return errors.New("Azure OS disk configuration is invalid")
	}
	if ValidateArtifact(value.HostBundle) != nil ||
		(value.RegistryCAPEM != "" && ValidateCAPEM(value.RegistryCAPEM, 32<<10) != nil) ||
		ValidateCAPEM(value.EnrollmentCAPEM, 32<<10) != nil || ValidateCAPEM(value.NativeSessionCAPEM, 32<<10) != nil ||
		validateHTTPSEndpoint(value.EnrollmentEndpoint) != nil || validateTLSEndpoint(value.NativeSessionEndpoint) != nil {
		return errors.New("Azure guest trust configuration is invalid")
	}
	if value.NativeWorkspace != nil {
		if validateTLSEndpoint(value.NativeWorkspace.Endpoint) != nil || validateLoopback(value.NativeWorkspace.LoopbackEndpoint) != nil {
			return errors.New("Azure native workspace configuration is invalid")
		}
	}
	key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(value.SSHHostPublicKey + "\n"))
	if err != nil || len(rest) != 0 || key.Type() != ssh.KeyAlgoED25519 || value.SSHHostPublicKey != strings.TrimSpace(value.SSHHostPublicKey) {
		return errors.New("Azure SSH host identity is invalid")
	}
	prefix, err := netip.ParsePrefix(value.Network.DriverSourceCIDR)
	if err != nil || prefix.String() != value.Network.DriverSourceCIDR || prefix != prefix.Masked() || !prefix.Addr().Is4() ||
		prefix.Bits() < 16 || prefix.Bits() > 32 || !prefix.Addr().IsPrivate() || prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() {
		return errors.New("Azure bootstrap source network is invalid")
	}
	dns, err := netip.ParseAddr(value.Network.DNSServer)
	if err != nil || dns.String() != value.Network.DNSServer || !dns.Is4() || dns.IsUnspecified() || dns.IsLoopback() ||
		dns.IsMulticast() || dns.IsLinkLocalUnicast() {
		return errors.New("Azure DNS server is invalid")
	}
	if value.BootstrapTimeoutSec < 30 || value.BootstrapTimeoutSec > 110 {
		return errors.New("Azure bootstrap timeout is invalid")
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > MaxConfigBytes {
		return errors.New("Azure execution class configuration is too large")
	}
	return nil
}

func validateHTTPSEndpoint(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Opaque != "" || parsed.Host == "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.String() != value ||
		!canonicalDNS(parsed.Hostname()) {
		return errors.New("HTTPS endpoint is invalid")
	}
	port := 443
	if parsed.Port() != "" {
		port, err = strconv.Atoi(parsed.Port())
		if err != nil || parsed.Port() != strconv.Itoa(port) {
			return errors.New("HTTPS endpoint is invalid")
		}
	}
	if port < 1 || port > 65535 {
		return errors.New("HTTPS endpoint is invalid")
	}
	return nil
}

func ValidateArtifact(value Artifact) error {
	if !digestPattern.MatchString(value.Digest) {
		return errors.New("artifact digest is invalid")
	}
	parsed, err := url.Parse(value.Repository)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.RawPath != "" || parsed.Hostname() == "" || (parsed.Port() != "" && parsed.Port() != "443") ||
		parsed.Path == "" || strings.HasSuffix(parsed.Path, "/") || parsed.String() != value.Repository || !canonicalDNS(parsed.Hostname()) {
		return errors.New("artifact repository is invalid")
	}
	for _, segment := range strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." || !resourceNamePattern.MatchString(segment) {
			return errors.New("artifact repository is invalid")
		}
	}
	return nil
}

func ValidateCAPEM(value string, limit int) error {
	if len(value) == 0 || len(value) > limit || strings.ContainsRune(value, 0) {
		return errors.New("CA is invalid")
	}
	rest := []byte(value)
	count := 0
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return errors.New("CA is invalid")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA {
			return errors.New("CA is invalid")
		}
		count++
		if count > 16 {
			return errors.New("CA is invalid")
		}
		rest = remaining
	}
	if count == 0 {
		return errors.New("CA is invalid")
	}
	return nil
}

func validateTLSEndpoint(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "tls" || parsed.User != nil || parsed.Opaque != "" || parsed.Host == "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.String() != value ||
		!canonicalDNS(parsed.Hostname()) || parsed.Port() == "" {
		return errors.New("TLS endpoint is invalid")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 || parsed.Port() != strconv.Itoa(port) {
		return errors.New("TLS endpoint is invalid")
	}
	return nil
}

func validateLoopback(value string) error {
	host, portText, err := splitHostPort(value)
	if err != nil || (host != "127.0.0.1" && host != "::1") {
		return errors.New("loopback endpoint is invalid")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || portText != strconv.Itoa(port) {
		return errors.New("loopback endpoint is invalid")
	}
	return nil
}

func splitHostPort(value string) (string, string, error) {
	if strings.HasPrefix(value, "[") {
		end := strings.Index(value, "]:")
		if end < 0 {
			return "", "", errors.New("endpoint is invalid")
		}
		return value[1:end], value[end+2:], nil
	}
	index := strings.LastIndexByte(value, ':')
	if index < 1 {
		return "", "", errors.New("endpoint is invalid")
	}
	return value[:index], value[index+1:], nil
}

func validateSubnetID(value string) error {
	parts := resourceIDParts(value)
	if len(parts) != 11 || parts[1] != "subscriptions" || !uuidPattern.MatchString(parts[2]) || parts[3] != "resourceGroups" ||
		!resourceGroupPattern.MatchString(parts[4]) || parts[5] != "providers" || parts[6] != "Microsoft.Network" ||
		parts[7] != "virtualNetworks" || !resourceNamePattern.MatchString(parts[8]) || parts[9] != "subnets" || !resourceNamePattern.MatchString(parts[10]) {
		return errors.New("subnet resource ID is invalid")
	}
	return nil
}

func validateImageVersionID(value string) error {
	parts := resourceIDParts(value)
	if len(parts) != 13 || parts[1] != "subscriptions" || !uuidPattern.MatchString(parts[2]) || parts[3] != "resourceGroups" ||
		!resourceGroupPattern.MatchString(parts[4]) || parts[5] != "providers" || parts[6] != "Microsoft.Compute" ||
		parts[7] != "galleries" || !resourceNamePattern.MatchString(parts[8]) || parts[9] != "images" ||
		!resourceNamePattern.MatchString(parts[10]) || parts[11] != "versions" || !canonicalImageVersion(parts[12]) {
		return errors.New("image version resource ID is invalid")
	}
	return nil
}

func resourceIDParts(value string) []string {
	if !strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.Contains(value, "//") {
		return nil
	}
	return strings.Split(value, "/")
}

func canonicalImageVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 || strconv.Itoa(number) != part {
			return false
		}
	}
	return true
}

func canonicalDNS(value string) bool {
	return len(value) <= 253 && value == strings.ToLower(value) && !numericDNSPattern.MatchString(value) && dnsPattern.MatchString(value)
}
