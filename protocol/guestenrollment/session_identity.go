package guestenrollment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"time"
)

const (
	GuestSessionIdentityVersion          = "nvt.guest-session-identity/v1"
	GuestSessionCredentialType           = "nvt.guest-session-credential/v1"
	NativeGuestControlAudience           = "nvt.native-guest-control/v1"
	GuestSessionCredentialBytes          = 40
	GuestSessionCredentialRandomBytes    = 32
	MaxGuestSessionIssuanceSequence      = uint64(1<<63 - 1)
	MaxGuestSessionIssueRequestBytes     = 8 << 10
	MaxGuestSessionAuthRequestBytes      = 4 << 10
	MaxGuestSessionResponseBytes         = 16 << 10
	MaxLiveGuestSessionsPerBinding       = 2
	MaxGuestSessionCredentialLifetime    = 5 * time.Minute
	GuestSessionIdentityIssuePath        = "/v1/guest-session-identity/issue"
	GuestSessionIdentityAuthenticatePath = "/v1/guest-session-identity/authenticate"
)

// GuestSessionIssueRequest is authenticated by the exact active root-owned
// runtime identity supplied through the transport. The sole audience is a
// protocol constant rather than a caller-selected scope.
type GuestSessionIssueRequest struct {
	ContractVersion string  `json:"contract_version"`
	Binding         Binding `json:"binding"`
	Audience        string  `json:"audience"`
}

// GuestSessionCredential is returned only once. The broker persists its
// digest, never Opaque. Formatting is deliberately redacted below.
type GuestSessionCredential struct {
	Type      string `json:"type"`
	Opaque    string `json:"opaque"`
	Audience  string `json:"audience"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
}

type GuestSessionIssueResult struct {
	ContractVersion string                 `json:"contract_version"`
	Binding         Binding                `json:"binding"`
	Credential      GuestSessionCredential `json:"credential"`
}

// GuestSessionAuthenticateRequest is presented by a future trusted relay
// together with the session credential in transport authorization. It repeats
// the complete non-secret binding and fixed audience for exact matching.
type GuestSessionAuthenticateRequest struct {
	ContractVersion string  `json:"contract_version"`
	Binding         Binding `json:"binding"`
	Audience        string  `json:"audience"`
}

// GuestSessionStatus contains no credential material.
type GuestSessionStatus struct {
	ContractVersion string  `json:"contract_version"`
	CredentialType  string  `json:"credential_type"`
	Binding         Binding `json:"binding"`
	Audience        string  `json:"audience"`
	IssuedAt        string  `json:"issued_at"`
	ExpiresAt       string  `json:"expires_at"`
}

// GuestSessionAuthority is the implementation-neutral authority boundary.
// Runtime and session bearer values are transport credentials, not body data.
type GuestSessionAuthority interface {
	IssueGuestSession(context.Context, string, GuestSessionIssueRequest) (GuestSessionIssueResult, error)
	AuthenticateGuestSession(context.Context, string, GuestSessionAuthenticateRequest) (GuestSessionStatus, error)
}

func GenerateGuestSessionCredential(issuanceSequence uint64) (string, error) {
	return generateGuestSessionCredential(issuanceSequence, rand.Reader)
}

func generateGuestSessionCredential(issuanceSequence uint64, source io.Reader) (string, error) {
	if issuanceSequence == 0 || issuanceSequence > MaxGuestSessionIssuanceSequence {
		return "", errors.New("guest session credential generation failed")
	}
	value := make([]byte, GuestSessionCredentialBytes)
	binary.BigEndian.PutUint64(value[:8], issuanceSequence)
	if _, err := io.ReadFull(source, value[8:]); err != nil {
		return "", errors.New("guest session credential generation failed")
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func GuestSessionCredentialDigest(credential string) (string, error) {
	if err := validateGuestSessionCredential(credential); err != nil {
		return "", errors.New("guest session credential is invalid")
	}
	sum := sha256.Sum256([]byte(credential))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ValidateGuestSessionCredential validates the canonical opaque wire form
// without deriving or retaining a credential digest. Sensitive transports use
// this before handing the bearer to their authority boundary.
func ValidateGuestSessionCredential(credential string) error {
	if validateGuestSessionCredential(credential) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func ValidateGuestSessionIssueRequest(value GuestSessionIssueRequest) error {
	if value.ContractVersion != GuestSessionIdentityVersion || value.Audience != NativeGuestControlAudience ||
		ValidateBinding(value.Binding) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func ValidateGuestSessionIssueResult(value GuestSessionIssueResult) error {
	credential := value.Credential
	if value.ContractVersion != GuestSessionIdentityVersion || ValidateBinding(value.Binding) != nil ||
		credential.Type != GuestSessionCredentialType || credential.Audience != NativeGuestControlAudience ||
		validateGuestSessionCredential(credential.Opaque) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	issued, expires, err := validateWindow(credential.IssuedAt, credential.ExpiresAt, MaxGuestSessionCredentialLifetime)
	if err != nil || !issued.Before(expires) {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func validateGuestSessionCredential(credential string) error {
	if err := validateOpaque(credential, GuestSessionCredentialBytes, GuestSessionCredentialBytes); err != nil {
		return err
	}
	value, err := base64.RawURLEncoding.DecodeString(credential)
	if err != nil {
		return err
	}
	issuanceSequence := binary.BigEndian.Uint64(value[:8])
	if issuanceSequence == 0 || issuanceSequence > MaxGuestSessionIssuanceSequence {
		return errors.New("guest session credential issuance sequence is invalid")
	}
	return nil
}

func ValidateGuestSessionAuthenticateRequest(value GuestSessionAuthenticateRequest) error {
	if value.ContractVersion != GuestSessionIdentityVersion || value.Audience != NativeGuestControlAudience ||
		ValidateBinding(value.Binding) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func ValidateGuestSessionStatus(value GuestSessionStatus) error {
	if value.ContractVersion != GuestSessionIdentityVersion || value.CredentialType != GuestSessionCredentialType ||
		value.Audience != NativeGuestControlAudience || ValidateBinding(value.Binding) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	issued, expires, err := validateWindow(value.IssuedAt, value.ExpiresAt, MaxGuestSessionCredentialLifetime)
	if err != nil || !issued.Before(expires) {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func DecodeGuestSessionIssueRequest(data []byte) (GuestSessionIssueRequest, error) {
	var value GuestSessionIssueRequest
	if DecodeStrictJSON(data, MaxGuestSessionIssueRequestBytes, &value) != nil || ValidateGuestSessionIssueRequest(value) != nil {
		return GuestSessionIssueRequest{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func DecodeGuestSessionIssueResult(data []byte) (GuestSessionIssueResult, error) {
	var value GuestSessionIssueResult
	if DecodeStrictJSON(data, MaxGuestSessionResponseBytes, &value) != nil || ValidateGuestSessionIssueResult(value) != nil {
		return GuestSessionIssueResult{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func DecodeGuestSessionAuthenticateRequest(data []byte) (GuestSessionAuthenticateRequest, error) {
	var value GuestSessionAuthenticateRequest
	if DecodeStrictJSON(data, MaxGuestSessionAuthRequestBytes, &value) != nil || ValidateGuestSessionAuthenticateRequest(value) != nil {
		return GuestSessionAuthenticateRequest{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func DecodeGuestSessionStatus(data []byte) (GuestSessionStatus, error) {
	var value GuestSessionStatus
	if DecodeStrictJSON(data, MaxGuestSessionResponseBytes, &value) != nil || ValidateGuestSessionStatus(value) != nil {
		return GuestSessionStatus{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func (GuestSessionCredential) String() string {
	return "[sensitive guest session credential]"
}

func (GuestSessionCredential) GoString() string {
	return "[sensitive guest session credential]"
}

func (GuestSessionIssueResult) String() string {
	return "[sensitive guest session issue result]"
}

func (GuestSessionIssueResult) GoString() string {
	return "[sensitive guest session issue result]"
}
