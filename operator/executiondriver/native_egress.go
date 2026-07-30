package executiondriver

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"hash"
	"math"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

const (
	NativeEgressAttachmentVersion = "nvt.native-egress-attachment/v1"

	MaxNativeEgressAttachmentBytes      = 96 << 10
	MaxNativeEgressCAPEMBytes           = 64 << 10
	MaxNativeEgressCACertificates       = 8
	MaxNativeEgressRequiredDestinations = 16
	NativeEgressRedirectModeCaptureTCP  = NativeEgressRedirectMode("capture-tcp")
	NativeEgressDestinationBootstrap    = NativeEgressDestinationPurpose("bootstrap")
	NativeEgressDestinationControl      = NativeEgressDestinationPurpose("control")
)

type NativeEgressDestinationPurpose string
type NativeEgressRedirectMode string

// NativeEgressAttachment is an operator-owned, non-secret provider plan. It
// carries public TLS trust and exact network intent, never an identity,
// credential, provider secret, command, or provider-specific configuration.
type NativeEgressAttachment struct {
	ContractVersion      string                            `json:"contract_version"`
	Generation           int64                             `json:"generation"`
	Relay                NativeEgressRelayAttachment       `json:"relay"`
	RequiredDestinations []NativeEgressRequiredDestination `json:"required_destinations"`
	Redirect             NativeEgressRedirectIntent        `json:"redirect"`
	Digest               string                            `json:"digest"`
}

type NativeEgressRelayAttachment struct {
	Host       string `json:"host"`
	Port       uint16 `json:"port"`
	ServerName string `json:"server_name"`
	CAPEM      string `json:"ca_pem"`
}

type NativeEgressRequiredDestination struct {
	Purpose NativeEgressDestinationPurpose `json:"purpose"`
	Host    string                         `json:"host"`
	Port    uint16                         `json:"port"`
}

type NativeEgressRedirectIntent struct {
	Mode                NativeEgressRedirectMode `json:"mode"`
	LoopbackAddress     string                   `json:"loopback_address"`
	TransparentTCPPort  uint16                   `json:"transparent_tcp_port"`
	ExplicitCONNECTPort uint16                   `json:"explicit_connect_port"`
}

var canonicalDNSPattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)*$`)
var numericAddressLikePattern = regexp.MustCompile(`^[0-9.]+$`)
var reservedNativeEgressPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// SealNativeEgressAttachment validates all non-digest fields and returns a
// copy carrying their canonical domain-separated digest.
func SealNativeEgressAttachment(value NativeEgressAttachment) (NativeEgressAttachment, error) {
	value.Digest = ""
	if err := validateNativeEgressAttachmentFields(value); err != nil {
		return NativeEgressAttachment{}, err
	}
	value.Digest = nativeEgressAttachmentDigest(value)
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > MaxNativeEgressAttachmentBytes {
		return NativeEgressAttachment{}, errors.New("native egress attachment size is invalid")
	}
	return value, nil
}

func ValidateNativeEgressAttachment(value NativeEgressAttachment) error {
	digest := value.Digest
	value.Digest = ""
	if err := validateNativeEgressAttachmentFields(value); err != nil {
		return err
	}
	if digest != nativeEgressAttachmentDigest(value) {
		return errors.New("native egress attachment digest is invalid")
	}
	value.Digest = digest
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > MaxNativeEgressAttachmentBytes {
		return errors.New("native egress attachment size is invalid")
	}
	return nil
}

func validateNativeEgressAttachmentFields(value NativeEgressAttachment) error {
	if value.ContractVersion != NativeEgressAttachmentVersion || value.Generation < 1 {
		return errors.New("native egress attachment version or generation is invalid")
	}
	if !canonicalNetworkHost(value.Relay.Host) || !canonicalDNS(value.Relay.ServerName) || value.Relay.Port == 0 {
		return errors.New("native egress relay attachment is invalid")
	}
	canonicalCA, err := CanonicalNativeEgressCAPEM([]byte(value.Relay.CAPEM))
	if err != nil || canonicalCA != value.Relay.CAPEM {
		return errors.New("native egress relay trust is invalid")
	}
	if len(value.RequiredDestinations) < 2 || len(value.RequiredDestinations) > MaxNativeEgressRequiredDestinations {
		return errors.New("native egress required destinations are invalid")
	}
	hasBootstrap, hasControl := false, false
	type endpointKey struct {
		host string
		port uint16
	}
	endpoints := make(map[endpointKey]struct{}, len(value.RequiredDestinations))
	for index, destination := range value.RequiredDestinations {
		switch destination.Purpose {
		case NativeEgressDestinationBootstrap:
			hasBootstrap = true
		case NativeEgressDestinationControl:
			hasControl = true
		default:
			return errors.New("native egress destination purpose is invalid")
		}
		if destination.Port == 0 || !canonicalNetworkHost(destination.Host) {
			return errors.New("native egress destination is invalid")
		}
		endpoint := endpointKey{host: destination.Host, port: destination.Port}
		if _, duplicate := endpoints[endpoint]; duplicate {
			return errors.New("native egress required destinations contain a duplicate endpoint")
		}
		endpoints[endpoint] = struct{}{}
		if index > 0 && !nativeEgressDestinationLess(value.RequiredDestinations[index-1], destination) {
			return errors.New("native egress destinations are not canonical")
		}
	}
	if !hasBootstrap || !hasControl {
		return errors.New("native egress bootstrap and control destinations are required")
	}
	if value.Redirect.Mode != NativeEgressRedirectModeCaptureTCP ||
		(value.Redirect.LoopbackAddress != "127.0.0.1" && value.Redirect.LoopbackAddress != "::1") ||
		value.Redirect.TransparentTCPPort < 1024 || value.Redirect.ExplicitCONNECTPort < 1024 ||
		value.Redirect.TransparentTCPPort == value.Redirect.ExplicitCONNECTPort {
		return errors.New("native egress redirect intent is invalid")
	}
	return nil
}

func CanonicalNativeEgressDestinations(values []NativeEgressRequiredDestination) ([]NativeEgressRequiredDestination, error) {
	if len(values) > MaxNativeEgressRequiredDestinations {
		return nil, errors.New("native egress required destinations are invalid")
	}
	result := append([]NativeEgressRequiredDestination(nil), values...)
	sort.Slice(result, func(left, right int) bool { return nativeEgressDestinationLess(result[left], result[right]) })
	for index := 1; index < len(result); index++ {
		if result[index-1].Host == result[index].Host && result[index-1].Port == result[index].Port {
			return nil, errors.New("native egress required destinations contain a duplicate endpoint")
		}
	}
	return result, nil
}

func nativeEgressDestinationLess(left, right NativeEgressRequiredDestination) bool {
	if left.Purpose != right.Purpose {
		return left.Purpose < right.Purpose
	}
	if left.Host != right.Host {
		return left.Host < right.Host
	}
	return left.Port < right.Port
}

// CanonicalNativeEgressCAPEM accepts only a bounded set of CA certificates and
// returns their exact canonical PEM encoding. Private keys and PEM metadata are
// rejected.
func CanonicalNativeEgressCAPEM(data []byte) (string, error) {
	if len(data) == 0 || len(data) > MaxNativeEgressCAPEMBytes {
		return "", errors.New("native egress CA bundle size is invalid")
	}
	rest := data
	result := make([]byte, 0, len(data))
	seen := map[[32]byte]struct{}{}
	count := 0
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return "", errors.New("native egress CA bundle is invalid")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA {
			return "", errors.New("native egress CA certificate is invalid")
		}
		digest := sha256.Sum256(certificate.Raw)
		if _, duplicate := seen[digest]; duplicate {
			return "", errors.New("native egress CA bundle contains a duplicate")
		}
		seen[digest] = struct{}{}
		count++
		if count > MaxNativeEgressCACertificates {
			return "", errors.New("native egress CA bundle contains too many certificates")
		}
		result = append(result, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
		rest = remaining
	}
	if count == 0 || len(result) > MaxNativeEgressCAPEMBytes {
		return "", errors.New("native egress CA bundle is invalid")
	}
	return string(result), nil
}

// NativeEgressDesiredGeneration composes a Kubernetes resource generation
// with the independently monotonic attachment generation. Zero attachment
// generation preserves the exact legacy value.
func NativeEgressDesiredGeneration(resourceGeneration, attachmentGeneration int64) (int64, error) {
	if resourceGeneration < 1 {
		resourceGeneration = 1
	}
	if attachmentGeneration < 0 || resourceGeneration > math.MaxInt64-attachmentGeneration {
		return 0, errors.New("desired generation is invalid")
	}
	return resourceGeneration + attachmentGeneration, nil
}

func nativeEgressAttachmentDigest(value NativeEgressAttachment) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(NativeEgressAttachmentVersion))
	_, _ = digest.Write([]byte{0})
	writeUint64(digest, uint64(value.Generation))
	writeString(digest, value.Relay.Host)
	writeUint16(digest, value.Relay.Port)
	writeString(digest, value.Relay.ServerName)
	writeString(digest, value.Relay.CAPEM)
	writeUint16(digest, uint16(len(value.RequiredDestinations)))
	for _, destination := range value.RequiredDestinations {
		writeString(digest, string(destination.Purpose))
		writeString(digest, destination.Host)
		writeUint16(digest, destination.Port)
	}
	writeString(digest, string(value.Redirect.Mode))
	writeString(digest, value.Redirect.LoopbackAddress)
	writeUint16(digest, value.Redirect.TransparentTCPPort)
	writeUint16(digest, value.Redirect.ExplicitCONNECTPort)
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func writeString(target hash.Hash, value string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = target.Write(length[:])
	_, _ = target.Write([]byte(value))
}

func writeUint16(target hash.Hash, value uint16) {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	_, _ = target.Write(encoded[:])
}

func writeUint64(target hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = target.Write(encoded[:])
}

func canonicalDNS(value string) bool {
	return len(value) <= 253 && !numericAddressLikePattern.MatchString(value) && canonicalDNSPattern.MatchString(value)
}

func canonicalNetworkHost(value string) bool {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return !strings.Contains(value, ":") && canonicalDNS(value)
	}
	if address.Zone() != "" || address.String() != value || address.Unmap() != address ||
		!address.IsGlobalUnicast() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range reservedNativeEgressPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func (NativeEgressAttachment) String() string   { return "[native egress attachment]" }
func (NativeEgressAttachment) GoString() string { return "[native egress attachment]" }
