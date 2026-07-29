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
	"strings"
	"time"
)

const (
	NativeEgressIdentityVersion          = "nvt.native-egress-identity/v1"
	NativeEgressCredentialType           = "nvt.native-egress-credential/v1"
	NativeEgressAudience                 = "nvt.native-egress/v1"
	NativeEgressCredentialPrefix         = "nvt_eg1_"
	NativeEgressCredentialBytes          = 40
	NativeEgressCredentialRandomBytes    = 32
	MaxNativeEgressCredentialLifetime    = 5 * time.Minute
	MaxLiveNativeEgressCredentials       = 2
	MaxNativeEgressIdentityEntries       = MaxDurableEntries
	MaxConcurrentNativeEgressIdentityOps = 64
	MaxNativeEgressIdentityOperationTime = MaxOperationDuration
	MaxNativeEgressIdentityRequestBytes  = 8 << 10
	MaxNativeEgressIdentityResponseBytes = 16 << 10

	NativeEgressIdentityIssuePath           = "/v1/native-egress-identity/issue"
	NativeEgressIdentityAuthenticatePath    = "/v1/native-egress-identity/authenticate"
	NativeEgressIdentityRevokeBindingPath   = "/v1/native-egress-identity/revoke-binding"
	NativeEgressIdentityRevokeExecutionPath = "/v1/native-egress-identity/revoke-execution"
)

// NativeEgressIssueRequest is authenticated by the active root-owned runtime
// identity at the transport boundary. Purpose is fixed and not caller chosen.
type NativeEgressIssueRequest struct {
	ContractVersion string  `json:"contract_version"`
	Binding         Binding `json:"binding"`
	Audience        string  `json:"audience"`
}

// NativeEgressCredential is returned once. Authorities persist only its
// digest and non-secret lifecycle metadata.
type NativeEgressCredential struct {
	Type      string `json:"type"`
	Opaque    string `json:"opaque"`
	Audience  string `json:"audience"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
}

type NativeEgressIssueResult struct {
	ContractVersion string                 `json:"contract_version"`
	Binding         Binding                `json:"binding"`
	Credential      NativeEgressCredential `json:"credential"`
}

// NativeEgressAuthenticateRequest repeats only the complete non-secret
// binding and fixed audience. The credential is transport authorization.
type NativeEgressAuthenticateRequest struct {
	ContractVersion string  `json:"contract_version"`
	Binding         Binding `json:"binding"`
	Audience        string  `json:"audience"`
}

type NativeEgressStatus struct {
	ContractVersion string  `json:"contract_version"`
	CredentialType  string  `json:"credential_type"`
	Binding         Binding `json:"binding"`
	Audience        string  `json:"audience"`
	Sequence        uint64  `json:"sequence"`
	IssuedAt        string  `json:"issued_at"`
	ExpiresAt       string  `json:"expires_at"`
}

type NativeEgressRevokeBindingRequest struct {
	ContractVersion string  `json:"contract_version"`
	Binding         Binding `json:"binding"`
}

type NativeEgressRevokeExecutionRequest struct {
	ContractVersion string         `json:"contract_version"`
	ExecutionScope  ExecutionScope `json:"execution_scope"`
}

// NativeEgressAuthority is implementation-swappable. IssueNativeEgress MUST
// authenticate the supplied runtime identity as the current active,
// unexpired identity for the complete exact Binding in the request; an
// expired, revoked, or rotated predecessor and an identity for another
// generation, guest instance, execution, or driver are not authority to choose
// a binding. Runtime and egress credential values are transport credentials and
// never body fields.
type NativeEgressAuthority interface {
	IssueNativeEgress(context.Context, string, NativeEgressIssueRequest) (NativeEgressIssueResult, error)
	AuthenticateNativeEgress(context.Context, string, NativeEgressAuthenticateRequest) (NativeEgressStatus, error)
	RevokeNativeEgressBinding(context.Context, NativeEgressRevokeBindingRequest) error
	RevokeNativeEgressExecution(context.Context, NativeEgressRevokeExecutionRequest) error
}

func GenerateNativeEgressCredential(sequence uint64) (string, error) {
	return generateNativeEgressCredential(sequence, rand.Reader)
}

func generateNativeEgressCredential(sequence uint64, source io.Reader) (string, error) {
	if sequence == 0 || sequence > MaxGuestSessionIssuanceSequence {
		return "", errors.New("native egress credential generation failed")
	}
	value := make([]byte, NativeEgressCredentialBytes)
	defer zeroBytes(value)
	binary.BigEndian.PutUint64(value[:8], sequence)
	if _, err := io.ReadFull(source, value[8:]); err != nil {
		return "", errors.New("native egress credential generation failed")
	}
	return NativeEgressCredentialPrefix + base64.RawURLEncoding.EncodeToString(value), nil
}

func NativeEgressCredentialSequence(credential string) (uint64, error) {
	value, err := decodeNativeEgressCredential(credential)
	if err != nil {
		return 0, errors.New("native egress credential is invalid")
	}
	defer zeroBytes(value)
	sequence := binary.BigEndian.Uint64(value[:8])
	if sequence == 0 || sequence > MaxGuestSessionIssuanceSequence {
		return 0, errors.New("native egress credential is invalid")
	}
	return sequence, nil
}

func NativeEgressCredentialDigest(credential string) (string, error) {
	if _, err := NativeEgressCredentialSequence(credential); err != nil {
		return "", errors.New("native egress credential is invalid")
	}
	sum := sha256.Sum256([]byte(credential))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ValidateNativeEgressCredential(credential string) error {
	_, err := NativeEgressCredentialSequence(credential)
	return err
}

func ValidateNativeEgressIssueRequest(value NativeEgressIssueRequest) error {
	if value.ContractVersion != NativeEgressIdentityVersion || value.Audience != NativeEgressAudience || ValidateBinding(value.Binding) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func ValidateNativeEgressIssueResult(value NativeEgressIssueResult) error {
	credential := value.Credential
	if value.ContractVersion != NativeEgressIdentityVersion || ValidateBinding(value.Binding) != nil ||
		credential.Type != NativeEgressCredentialType || credential.Audience != NativeEgressAudience || ValidateNativeEgressCredential(credential.Opaque) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	issued, expires, err := validateWindow(credential.IssuedAt, credential.ExpiresAt, MaxNativeEgressCredentialLifetime)
	if err != nil || !issued.Before(expires) {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func ValidateNativeEgressAuthenticateRequest(value NativeEgressAuthenticateRequest) error {
	if value.ContractVersion != NativeEgressIdentityVersion || value.Audience != NativeEgressAudience || ValidateBinding(value.Binding) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func ValidateNativeEgressStatus(value NativeEgressStatus) error {
	if value.ContractVersion != NativeEgressIdentityVersion || value.CredentialType != NativeEgressCredentialType ||
		value.Audience != NativeEgressAudience || value.Sequence == 0 || value.Sequence > MaxGuestSessionIssuanceSequence || ValidateBinding(value.Binding) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	issued, expires, err := validateWindow(value.IssuedAt, value.ExpiresAt, MaxNativeEgressCredentialLifetime)
	if err != nil || !issued.Before(expires) {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func ValidateNativeEgressRevokeBindingRequest(value NativeEgressRevokeBindingRequest) error {
	if value.ContractVersion != NativeEgressIdentityVersion || ValidateBinding(value.Binding) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func ValidateNativeEgressRevokeExecutionRequest(value NativeEgressRevokeExecutionRequest) error {
	if value.ContractVersion != NativeEgressIdentityVersion || ValidateExecutionScope(value.ExecutionScope) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func DecodeNativeEgressIssueRequest(data []byte) (NativeEgressIssueRequest, error) {
	var value NativeEgressIssueRequest
	if DecodeStrictJSON(data, MaxNativeEgressIdentityRequestBytes, &value) != nil || ValidateNativeEgressIssueRequest(value) != nil {
		return NativeEgressIssueRequest{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func DecodeNativeEgressIssueResult(data []byte) (NativeEgressIssueResult, error) {
	var value NativeEgressIssueResult
	if DecodeStrictJSON(data, MaxNativeEgressIdentityResponseBytes, &value) != nil || ValidateNativeEgressIssueResult(value) != nil {
		return NativeEgressIssueResult{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func DecodeNativeEgressAuthenticateRequest(data []byte) (NativeEgressAuthenticateRequest, error) {
	var value NativeEgressAuthenticateRequest
	if DecodeStrictJSON(data, MaxNativeEgressIdentityRequestBytes, &value) != nil || ValidateNativeEgressAuthenticateRequest(value) != nil {
		return NativeEgressAuthenticateRequest{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func DecodeNativeEgressStatus(data []byte) (NativeEgressStatus, error) {
	var value NativeEgressStatus
	if DecodeStrictJSON(data, MaxNativeEgressIdentityResponseBytes, &value) != nil || ValidateNativeEgressStatus(value) != nil {
		return NativeEgressStatus{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func DecodeNativeEgressRevokeBindingRequest(data []byte) (NativeEgressRevokeBindingRequest, error) {
	var value NativeEgressRevokeBindingRequest
	if DecodeStrictJSON(data, MaxNativeEgressIdentityRequestBytes, &value) != nil || ValidateNativeEgressRevokeBindingRequest(value) != nil {
		return NativeEgressRevokeBindingRequest{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func DecodeNativeEgressRevokeExecutionRequest(data []byte) (NativeEgressRevokeExecutionRequest, error) {
	var value NativeEgressRevokeExecutionRequest
	if DecodeStrictJSON(data, MaxNativeEgressIdentityRequestBytes, &value) != nil || ValidateNativeEgressRevokeExecutionRequest(value) != nil {
		return NativeEgressRevokeExecutionRequest{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func decodeNativeEgressCredential(credential string) ([]byte, error) {
	if !strings.HasPrefix(credential, NativeEgressCredentialPrefix) {
		return nil, errors.New("native egress credential is invalid")
	}
	encoded := strings.TrimPrefix(credential, NativeEgressCredentialPrefix)
	value, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(value) != NativeEgressCredentialBytes || base64.RawURLEncoding.EncodeToString(value) != encoded {
		zeroBytes(value)
		return nil, errors.New("native egress credential is invalid")
	}
	return value, nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func (NativeEgressCredential) String() string    { return "[sensitive native egress credential]" }
func (NativeEgressCredential) GoString() string  { return "[sensitive native egress credential]" }
func (NativeEgressIssueResult) String() string   { return "[sensitive native egress issue result]" }
func (NativeEgressIssueResult) GoString() string { return "[sensitive native egress issue result]" }
func (NativeEgressIssueRequest) String() string  { return "[native egress issue request]" }
func (NativeEgressIssueRequest) GoString() string {
	return "[native egress issue request]"
}
func (NativeEgressAuthenticateRequest) String() string {
	return "[native egress authenticate request]"
}
func (NativeEgressAuthenticateRequest) GoString() string {
	return "[native egress authenticate request]"
}
func (NativeEgressStatus) String() string   { return "[native egress status]" }
func (NativeEgressStatus) GoString() string { return "[native egress status]" }
func (NativeEgressRevokeBindingRequest) String() string {
	return "[native egress binding revocation]"
}
func (NativeEgressRevokeBindingRequest) GoString() string {
	return "[native egress binding revocation]"
}
func (NativeEgressRevokeExecutionRequest) String() string {
	return "[native egress execution revocation]"
}
func (NativeEgressRevokeExecutionRequest) GoString() string {
	return "[native egress execution revocation]"
}
