package guestenrollment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"time"
)

const (
	RuntimeIdentityVersion                  = "nvt.guest-runtime-identity/v1"
	RuntimeIdentityBytes                    = 32
	MaxRuntimeIdentityStatusRequestBytes    = 4 << 10
	MaxRuntimeIdentityRotateRequestBytes    = 16 << 10
	MaxRuntimeIdentityResponseBytes         = 16 << 10
	MaxRuntimeIdentityHistoryPerEnrollment  = 20_000
	MaxRuntimeIdentityHistoryAggregate      = MaxDurableEntries * MaxRuntimeIdentityHistoryPerEnrollment
	RuntimeIdentityCapacityPlanningInterval = 30 * time.Minute
	MinRuntimeIdentityLifecycleHorizon      = 365 * 24 * time.Hour
)

// RuntimeIdentityStatusRequest authenticates with the opaque identity in the
// transport Authorization header. The body repeats the exact non-secret
// binding so an identity cannot be moved to another execution or guest.
type RuntimeIdentityStatusRequest struct {
	ContractVersion string  `json:"contract_version"`
	Binding         Binding `json:"binding"`
}

// RuntimeIdentityStatus contains no bearer material. It describes only the
// exact active identity that authenticated the request.
type RuntimeIdentityStatus struct {
	ContractVersion string  `json:"contract_version"`
	IdentityType    string  `json:"identity_type"`
	Binding         Binding `json:"binding"`
	IssuedAt        string  `json:"issued_at"`
	ExpiresAt       string  `json:"expires_at"`
}

// RuntimeIdentityRotateRequest asks the issuer to atomically replace the
// authenticating identity with a client-generated successor. The successor is
// sent once over the authenticated TLS request and is persisted only as a
// digest. It is deliberately redacted from formatting.
type RuntimeIdentityRotateRequest struct {
	ContractVersion string  `json:"contract_version"`
	Binding         Binding `json:"binding"`
	Successor       string  `json:"successor"`
}

// RuntimeIdentityAuthority is the implementation-neutral runtime boundary.
// The current identity is supplied by the transport, not embedded in either
// request body.
type RuntimeIdentityAuthority interface {
	Authenticate(context.Context, string, RuntimeIdentityStatusRequest) (RuntimeIdentityStatus, error)
	Rotate(context.Context, string, RuntimeIdentityRotateRequest) (RuntimeIdentityStatus, error)
}

func GenerateRuntimeIdentity() (string, error) {
	return generateRuntimeIdentity(rand.Reader)
}

func generateRuntimeIdentity(source io.Reader) (string, error) {
	value := make([]byte, RuntimeIdentityBytes)
	if _, err := io.ReadFull(source, value); err != nil {
		return "", errors.New("guest runtime identity generation failed")
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func RuntimeIdentityDigest(identity string) (string, error) {
	if err := validateOpaque(identity, RuntimeIdentityBytes, RuntimeIdentityBytes); err != nil {
		return "", errors.New("guest runtime identity is invalid")
	}
	sum := sha256.Sum256([]byte(identity))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ValidateRuntimeIdentityDigest(value string) error {
	if !digestPattern.MatchString(value) {
		return errors.New("guest runtime identity digest is invalid")
	}
	return nil
}

func ValidateRuntimeIdentityStatusRequest(value RuntimeIdentityStatusRequest) error {
	if value.ContractVersion != RuntimeIdentityVersion || ValidateBinding(value.Binding) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func ValidateRuntimeIdentityStatus(value RuntimeIdentityStatus) error {
	if value.ContractVersion != RuntimeIdentityVersion || value.IdentityType != RuntimeIdentityType ||
		ValidateBinding(value.Binding) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	issued, expires, err := validateWindow(value.IssuedAt, value.ExpiresAt, MaxRuntimeIdentityLifetime)
	if err != nil || !issued.Before(expires) {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func ValidateRuntimeIdentityRotateRequest(value RuntimeIdentityRotateRequest) error {
	if value.ContractVersion != RuntimeIdentityVersion || ValidateBinding(value.Binding) != nil ||
		validateOpaque(value.Successor, RuntimeIdentityBytes, RuntimeIdentityBytes) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func DecodeRuntimeIdentityStatusRequest(data []byte) (RuntimeIdentityStatusRequest, error) {
	var value RuntimeIdentityStatusRequest
	if DecodeStrictJSON(data, MaxRuntimeIdentityStatusRequestBytes, &value) != nil || ValidateRuntimeIdentityStatusRequest(value) != nil {
		return RuntimeIdentityStatusRequest{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func DecodeRuntimeIdentityStatus(data []byte) (RuntimeIdentityStatus, error) {
	var value RuntimeIdentityStatus
	if DecodeStrictJSON(data, MaxRuntimeIdentityResponseBytes, &value) != nil || ValidateRuntimeIdentityStatus(value) != nil {
		return RuntimeIdentityStatus{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func DecodeRuntimeIdentityRotateRequest(data []byte) (RuntimeIdentityRotateRequest, error) {
	var value RuntimeIdentityRotateRequest
	if DecodeStrictJSON(data, MaxRuntimeIdentityRotateRequestBytes, &value) != nil || ValidateRuntimeIdentityRotateRequest(value) != nil {
		return RuntimeIdentityRotateRequest{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func (RuntimeIdentityRotateRequest) String() string {
	return "[sensitive guest runtime identity rotation request]"
}

func (RuntimeIdentityRotateRequest) GoString() string {
	return "[sensitive guest runtime identity rotation request]"
}
