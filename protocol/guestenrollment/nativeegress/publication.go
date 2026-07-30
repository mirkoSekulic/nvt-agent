package nativeegress

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

const (
	TargetPublicationVersion        = "nvt.native-egress-target-publication/v1"
	EgressdConnectTargetType        = "nvt.egressd-connect/v1"
	TargetSnapshotReplace           = "replace_snapshot"
	TargetSnapshotAck               = "snapshot_ack"
	TargetPublicationStatusRequest  = "status"
	TargetPublicationStatusResponse = "status_result"
	TargetPublicationError          = "error"
	TargetPublicationReasonNotFound = "not-found"
	TargetPublicationReasonCapacity = "capacity-exceeded"
	TargetPublicationReasonDenied   = "unauthorized"
	TargetPublicationReasonInvalid  = "invalid-request"
	TargetPublicationReasonConflict = "conflict"
	TargetPublicationReasonFailed   = "unavailable"

	TargetSnapshotPath = "/v1/native-egress-targets/snapshot"
	TargetStatusPath   = "/v1/native-egress-targets/status"

	MaxTargetPublicationTargets       = MaxSessionBindings
	MaxTargetConnectURLBytes          = 512
	MaxTargetPublicationRequestBytes  = 256 << 10
	MaxTargetPublicationResponseBytes = 4 << 10
	MaxTargetPublicationHeadersBytes  = 8 << 10
	MaxTargetPublicationConcurrency   = 16
	TargetPublicationTimeout          = 10 * time.Second

	RelayControlCredentialPrefix = "nvt_rc1_"
	RelayControlCredentialBytes  = 32
)

// PublishedTarget is trusted, non-secret control-plane topology. The complete
// binding selects exactly one per-run target; neither a guest nor a flow may
// supply or alter this value.
type PublishedTarget struct {
	Binding    guestenrollment.Binding `json:"binding"`
	TargetType string                  `json:"target_type"`
	ConnectURL string                  `json:"connect_url"`
}

// TargetSnapshot replaces the complete bounded target set. Targets must use
// canonical order so every implementation hashes the same byte sequence.
type TargetSnapshot struct {
	ContractVersion string            `json:"contract_version"`
	Type            string            `json:"type"`
	Generation      uint64            `json:"generation"`
	Digest          string            `json:"digest"`
	Targets         []PublishedTarget `json:"targets"`
}

type TargetSnapshotAcknowledgement struct {
	ContractVersion string `json:"contract_version"`
	Type            string `json:"type"`
	Generation      uint64 `json:"generation"`
	Digest          string `json:"digest"`
	TargetCount     int    `json:"target_count"`
}

type TargetStatusRequest struct {
	ContractVersion string `json:"contract_version"`
	Type            string `json:"type"`
}

// TargetStatus deliberately exposes no binding, target, listener, or other
// topology. Published=false is process-start deny-all; Published=true with a
// zero TargetCount is an intentionally applied empty snapshot.
type TargetStatus struct {
	ContractVersion string `json:"contract_version"`
	Type            string `json:"type"`
	Published       bool   `json:"published"`
	Generation      uint64 `json:"generation"`
	Digest          string `json:"digest"`
	TargetCount     int    `json:"target_count"`
}

type TargetPublicationFailure struct {
	ContractVersion string `json:"contract_version"`
	Type            string `json:"type"`
	Reason          string `json:"reason"`
}

func CanonicalTargetSnapshot(targets []PublishedTarget) ([]PublishedTarget, string, error) {
	if targets == nil || len(targets) > MaxTargetPublicationTargets {
		return nil, "", errors.New("native egress target publication is invalid")
	}
	canonical := make([]PublishedTarget, len(targets))
	copy(canonical, targets)
	for index := range canonical {
		if ValidatePublishedTarget(canonical[index]) != nil {
			return nil, "", errors.New("native egress target publication is invalid")
		}
	}
	sort.Slice(canonical, func(left, right int) bool {
		return comparePublishedTargets(canonical[left], canonical[right]) < 0
	})
	bindings := make(map[guestenrollment.Binding]struct{}, len(canonical))
	listeners := make(map[string]struct{}, len(canonical))
	for _, target := range canonical {
		if _, exists := bindings[target.Binding]; exists {
			return nil, "", errors.New("native egress target publication is invalid")
		}
		if _, exists := listeners[target.ConnectURL]; exists {
			return nil, "", errors.New("native egress target publication is invalid")
		}
		bindings[target.Binding] = struct{}{}
		listeners[target.ConnectURL] = struct{}{}
	}
	encoded, err := json.Marshal(canonical)
	if err != nil || len(encoded) > MaxTargetPublicationRequestBytes {
		return nil, "", errors.New("native egress target publication is invalid")
	}
	digestInput := bytes.NewBuffer(make([]byte, 0, len(encoded)))
	digestInput.WriteString(TargetPublicationVersion)
	digestInput.WriteByte(0)
	writeDigestUint32(digestInput, uint32(len(canonical)))
	for _, target := range canonical {
		writeDigestString(digestInput, target.Binding.AgentRunUID)
		writeDigestString(digestInput, target.Binding.ExecutionID)
		writeDigestString(digestInput, target.Binding.DriverRegistration)
		writeDigestUint64(digestInput, uint64(target.Binding.DesiredGeneration))
		writeDigestString(digestInput, target.Binding.GuestInstanceID)
		writeDigestString(digestInput, target.TargetType)
		writeDigestString(digestInput, target.ConnectURL)
	}
	sum := sha256.Sum256(digestInput.Bytes())
	return canonical, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ValidatePublishedTarget(value PublishedTarget) error {
	if guestenrollment.ValidateBinding(value.Binding) != nil || value.TargetType != EgressdConnectTargetType || ValidateEgressdConnectURL(value.ConnectURL) != nil {
		return errors.New("native egress published target is invalid")
	}
	return nil
}

func ValidateEgressdConnectURL(value string) error {
	if len(value) == 0 || len(value) > MaxTargetConnectURLBytes {
		return errors.New("native egress target URL is invalid")
	}
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.Scheme != "http" || endpoint.Host == "" || endpoint.User != nil || endpoint.Opaque != "" ||
		endpoint.Path != "" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" {
		return errors.New("native egress target URL is invalid")
	}
	host, portText := endpoint.Hostname(), endpoint.Port()
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || portText != strconv.Itoa(port) {
		return errors.New("native egress target URL is invalid")
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		if address.Zone() != "" || address.String() != host {
			return errors.New("native egress target URL is invalid")
		}
	} else if !canonicalHostname(host) {
		return errors.New("native egress target URL is invalid")
	}
	if value != "http://"+net.JoinHostPort(host, portText) {
		return errors.New("native egress target URL is invalid")
	}
	return nil
}

func ValidateTargetSnapshot(value TargetSnapshot) error {
	if value.ContractVersion != TargetPublicationVersion || value.Type != TargetSnapshotReplace || value.Generation == 0 || value.Targets == nil {
		return errors.New("native egress target snapshot is invalid")
	}
	canonical, digest, err := CanonicalTargetSnapshot(value.Targets)
	if err != nil || digest != value.Digest || !equalPublishedTargets(canonical, value.Targets) {
		return errors.New("native egress target snapshot is invalid")
	}
	return nil
}

func ValidateTargetSnapshotAcknowledgement(value TargetSnapshotAcknowledgement) error {
	if value.ContractVersion != TargetPublicationVersion || value.Type != TargetSnapshotAck || value.Generation == 0 ||
		guestenrollment.ValidateTokenDigest(value.Digest) != nil || value.TargetCount < 0 || value.TargetCount > MaxTargetPublicationTargets {
		return errors.New("native egress target snapshot acknowledgement is invalid")
	}
	return nil
}

func ValidateTargetStatusRequest(value TargetStatusRequest) error {
	if value.ContractVersion != TargetPublicationVersion || value.Type != TargetPublicationStatusRequest {
		return errors.New("native egress target status request is invalid")
	}
	return nil
}

func ValidateTargetStatus(value TargetStatus) error {
	if value.ContractVersion != TargetPublicationVersion || value.Type != TargetPublicationStatusResponse || value.TargetCount < 0 || value.TargetCount > MaxTargetPublicationTargets {
		return errors.New("native egress target status is invalid")
	}
	if !value.Published {
		if value.Generation != 0 || value.Digest != "" || value.TargetCount != 0 {
			return errors.New("native egress target status is invalid")
		}
		return nil
	}
	if value.Generation == 0 || guestenrollment.ValidateTokenDigest(value.Digest) != nil {
		return errors.New("native egress target status is invalid")
	}
	return nil
}

func ValidateTargetPublicationFailure(value TargetPublicationFailure) error {
	if value.ContractVersion != TargetPublicationVersion || value.Type != TargetPublicationError {
		return errors.New("native egress target publication failure is invalid")
	}
	switch value.Reason {
	case TargetPublicationReasonNotFound, TargetPublicationReasonCapacity, TargetPublicationReasonDenied,
		TargetPublicationReasonInvalid, TargetPublicationReasonConflict, TargetPublicationReasonFailed:
		return nil
	default:
		return errors.New("native egress target publication failure is invalid")
	}
}

func DecodeTargetSnapshot(data []byte) (TargetSnapshot, error) {
	var value TargetSnapshot
	if guestenrollment.DecodeStrictJSON(data, MaxTargetPublicationRequestBytes, &value) != nil || ValidateTargetSnapshot(value) != nil {
		return TargetSnapshot{}, errors.New("native egress target publication is invalid")
	}
	return value, nil
}

func EncodeTargetSnapshot(value TargetSnapshot) ([]byte, error) {
	if ValidateTargetSnapshot(value) != nil {
		return nil, errors.New("native egress target publication is invalid")
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > MaxTargetPublicationRequestBytes {
		return nil, errors.New("native egress target publication is invalid")
	}
	return encoded, nil
}

func DecodeTargetStatusRequest(data []byte) (TargetStatusRequest, error) {
	var value TargetStatusRequest
	if guestenrollment.DecodeStrictJSON(data, MaxTargetPublicationRequestBytes, &value) != nil || ValidateTargetStatusRequest(value) != nil {
		return TargetStatusRequest{}, errors.New("native egress target publication is invalid")
	}
	return value, nil
}

func EncodeTargetStatusRequest(value TargetStatusRequest) ([]byte, error) {
	if ValidateTargetStatusRequest(value) != nil {
		return nil, errors.New("native egress target publication is invalid")
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > MaxTargetPublicationRequestBytes {
		return nil, errors.New("native egress target publication is invalid")
	}
	return encoded, nil
}

func DecodeTargetSnapshotAcknowledgement(data []byte) (TargetSnapshotAcknowledgement, error) {
	var value TargetSnapshotAcknowledgement
	if guestenrollment.DecodeStrictJSON(data, MaxTargetPublicationResponseBytes, &value) != nil || ValidateTargetSnapshotAcknowledgement(value) != nil {
		return TargetSnapshotAcknowledgement{}, errors.New("native egress target publication is invalid")
	}
	return value, nil
}

func DecodeTargetStatus(data []byte) (TargetStatus, error) {
	var value TargetStatus
	if guestenrollment.DecodeStrictJSON(data, MaxTargetPublicationResponseBytes, &value) != nil || ValidateTargetStatus(value) != nil {
		return TargetStatus{}, errors.New("native egress target publication is invalid")
	}
	return value, nil
}

func DecodeTargetPublicationFailure(data []byte) (TargetPublicationFailure, error) {
	var value TargetPublicationFailure
	if guestenrollment.DecodeStrictJSON(data, MaxTargetPublicationResponseBytes, &value) != nil || ValidateTargetPublicationFailure(value) != nil {
		return TargetPublicationFailure{}, errors.New("native egress target publication is invalid")
	}
	return value, nil
}

func EncodeTargetSnapshotAcknowledgement(value TargetSnapshotAcknowledgement) ([]byte, error) {
	if ValidateTargetSnapshotAcknowledgement(value) != nil {
		return nil, errors.New("native egress target publication is invalid")
	}
	return encodeTargetPublicationResponse(value)
}

func EncodeTargetStatus(value TargetStatus) ([]byte, error) {
	if ValidateTargetStatus(value) != nil {
		return nil, errors.New("native egress target publication is invalid")
	}
	return encodeTargetPublicationResponse(value)
}

func EncodeTargetPublicationFailure(value TargetPublicationFailure) ([]byte, error) {
	if ValidateTargetPublicationFailure(value) != nil {
		return nil, errors.New("native egress target publication is invalid")
	}
	return encodeTargetPublicationResponse(value)
}

func GenerateRelayControlCredential() (string, error) {
	value := make([]byte, RelayControlCredentialBytes)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", errors.New("native egress relay control credential generation failed")
	}
	defer zero(value)
	return RelayControlCredentialPrefix + base64.RawURLEncoding.EncodeToString(value), nil
}

func ValidateRelayControlCredential(value string) error {
	if !strings.HasPrefix(value, RelayControlCredentialPrefix) {
		return errors.New("native egress relay control credential is invalid")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, RelayControlCredentialPrefix))
	if err != nil || len(decoded) != RelayControlCredentialBytes || value != RelayControlCredentialPrefix+base64.RawURLEncoding.EncodeToString(decoded) {
		zero(decoded)
		return errors.New("native egress relay control credential is invalid")
	}
	zero(decoded)
	return nil
}

func comparePublishedTargets(left, right PublishedTarget) int {
	leftFields := []string{left.Binding.AgentRunUID, left.Binding.ExecutionID, left.Binding.DriverRegistration, left.Binding.GuestInstanceID, left.TargetType, left.ConnectURL}
	rightFields := []string{right.Binding.AgentRunUID, right.Binding.ExecutionID, right.Binding.DriverRegistration, right.Binding.GuestInstanceID, right.TargetType, right.ConnectURL}
	for index := 0; index < 3; index++ {
		if comparison := strings.Compare(leftFields[index], rightFields[index]); comparison != 0 {
			return comparison
		}
	}
	if left.Binding.DesiredGeneration < right.Binding.DesiredGeneration {
		return -1
	}
	if left.Binding.DesiredGeneration > right.Binding.DesiredGeneration {
		return 1
	}
	for index := 3; index < len(leftFields); index++ {
		if comparison := strings.Compare(leftFields[index], rightFields[index]); comparison != 0 {
			return comparison
		}
	}
	return 0
}

func equalPublishedTargets(left, right []PublishedTarget) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func writeDigestString(destination *bytes.Buffer, value string) {
	writeDigestUint32(destination, uint32(len(value)))
	destination.WriteString(value)
}

func writeDigestUint32(destination *bytes.Buffer, value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	destination.Write(encoded[:])
}

func writeDigestUint64(destination *bytes.Buffer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	destination.Write(encoded[:])
}

func encodeTargetPublicationResponse(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > MaxTargetPublicationResponseBytes {
		return nil, errors.New("native egress target publication is invalid")
	}
	return encoded, nil
}

func (PublishedTarget) String() string   { return "[native egress published target]" }
func (PublishedTarget) GoString() string { return "[native egress published target]" }
func (TargetSnapshot) String() string    { return "[native egress complete target snapshot]" }
func (TargetSnapshot) GoString() string  { return "[native egress complete target snapshot]" }
