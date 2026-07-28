// Package guestenrollment defines the provider-neutral sensitive handoff
// between an enrollment issuer and one native NVT guest bootstrap instance.
// It contains no transport, broker, provider, or Kubernetes implementation.
package guestenrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	Version                    = "nvt.guest-enrollment/v1"
	RuntimeIdentityType        = "nvt.runtime-identity/v1"
	TokenBytes                 = 32
	MaxIssueRequestBytes       = 4 << 10
	MaxBootstrapEnvelopeBytes  = 16 << 10
	MaxExchangeRequestBytes    = 16 << 10
	MaxExchangeResultBytes     = 128 << 10
	MaxRevocationRequestBytes  = 4 << 10
	MaxExecutionIDBytes        = 256
	MaxAgentRunUIDBytes        = 128
	MaxDriverNameBytes         = 63
	MaxGuestInstanceIDBytes    = 256
	MaxExchangeURLBytes        = 2048
	MaxRuntimeIdentityBytes    = 64 << 10
	MaxEnrollmentTTLSeconds    = 900
	MaxRuntimeIdentityLifetime = 24 * time.Hour
	MaxOperationDuration       = 30 * time.Second
	MaxDurableEntries          = 10_000
	MaxTombstoneRetention      = 24 * time.Hour
	HandoffVersion             = "nvt.guest-enrollment-handoff/v1"
	MaxHandoffRequestBytes     = MaxBootstrapEnvelopeBytes + (4 << 10)
	MaxHandoffResponseBytes    = 4 << 10
)

var (
	driverNamePattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Binding identifies exactly one authorized execution and intended guest
// bootstrap instance. Every field participates in exact equality checks.
type Binding struct {
	AgentRunUID        string `json:"agent_run_uid"`
	ExecutionID        string `json:"execution_id"`
	DriverRegistration string `json:"driver_registration"`
	DesiredGeneration  int64  `json:"desired_generation"`
	GuestInstanceID    string `json:"guest_instance_id"`
}

// ExecutionScope is the stable, non-secret ownership key available from an
// immutable AgentRun after an orchestrator restart. It intentionally excludes
// desired generation and guest instance so cleanup covers every replacement.
type ExecutionScope struct {
	AgentRunUID        string `json:"agent_run_uid"`
	ExecutionID        string `json:"execution_id"`
	DriverRegistration string `json:"driver_registration"`
}

func (value Binding) ExecutionScope() ExecutionScope {
	return ExecutionScope{
		AgentRunUID: value.AgentRunUID, ExecutionID: value.ExecutionID,
		DriverRegistration: value.DriverRegistration,
	}
}

// IssuerConfiguration is trusted issuer-owned configuration. Issue callers do
// not select or override the destination that receives a bearer token.
type IssuerConfiguration struct {
	ExchangeURL string
}

// IssueRequest asks the issuer to create one short-lived, single-use token.
type IssueRequest struct {
	ContractVersion string  `json:"contract_version"`
	Binding         Binding `json:"binding"`
	TTLSeconds      int32   `json:"ttl_seconds"`
}

// BootstrapEnvelope is the only sensitive value delivered through the exact
// selected provider driver's guest-bootstrap mechanism. The driver treats its
// encoded form as opaque and must not persist it in ordinary provider state.
type BootstrapEnvelope struct {
	ContractVersion string  `json:"contract_version"`
	Binding         Binding `json:"binding"`
	ExchangeURL     string  `json:"exchange_url"`
	Token           string  `json:"token"`
	IssuedAt        string  `json:"issued_at"`
	ExpiresAt       string  `json:"expires_at"`
}

// ExchangeRequest is presented once by the intended guest. Repeating the
// request after a successful exchange is a rejected replay.
type ExchangeRequest struct {
	ContractVersion string  `json:"contract_version"`
	Binding         Binding `json:"binding"`
	Token           string  `json:"token"`
}

// RuntimeIdentity contains only a guest runtime identity. It is not a provider
// credential and not the separately issued egress identity.
type RuntimeIdentity struct {
	Type      string `json:"type"`
	Opaque    string `json:"opaque"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
}

// ExchangeResult returns sensitive runtime identity material to the guest.
type ExchangeResult struct {
	ContractVersion string          `json:"contract_version"`
	Binding         Binding         `json:"binding"`
	RuntimeIdentity RuntimeIdentity `json:"runtime_identity"`
}

// RevokeBindingRequest abandons one exact bootstrap handoff. It is not
// sufficient for AgentRun cleanup because one execution may have replacements.
type RevokeBindingRequest struct {
	ContractVersion string  `json:"contract_version"`
	Binding         Binding `json:"binding"`
}

// RevokeExecutionRequest durably revokes every generation and guest instance
// owned by the stable execution scope. This is the cleanup/restart primitive.
type RevokeExecutionRequest struct {
	ContractVersion string         `json:"contract_version"`
	ExecutionScope  ExecutionScope `json:"execution_scope"`
}

// CompleteExecutionCleanupRequest records the authoritative orchestrator's
// durable proof that exact-driver resource deletion has completed. It is
// valid only after execution-scoped revocation and makes the retained scope
// tombstone eligible for GC after its independent retention deadline.
type CompleteExecutionCleanupRequest struct {
	ContractVersion string         `json:"contract_version"`
	ExecutionScope  ExecutionScope `json:"execution_scope"`
}

type HandoffState string

const (
	HandoffStatePrepared HandoffState = "prepared"
	HandoffStateAccepted HandoffState = "accepted"
)

// HandoffPrepareRequest asks the exact driver to durably resolve one intended
// bootstrap instance before the issuer creates an enrollment token.
type HandoffPrepareRequest struct {
	ContractVersion   string         `json:"contract_version"`
	ExecutionScope    ExecutionScope `json:"execution_scope"`
	DesiredGeneration int64          `json:"desired_generation"`
}

// HandoffPrepareResult contains non-secret provider-side delivery state.
// NewlyPrepared is true exactly for the call that durably established this
// attempt. An older prepared attempt must be revoked and replaced before a
// new token is issued.
type HandoffPrepareResult struct {
	ContractVersion string       `json:"contract_version"`
	GuestInstanceID string       `json:"guest_instance_id"`
	State           HandoffState `json:"state"`
	NewlyPrepared   bool         `json:"newly_prepared"`
}

// HandoffReplaceRequest is valid only after Binding has been durably revoked
// at the issuer. The exact driver must return a distinct, freshly prepared
// bootstrap instance.
type HandoffReplaceRequest struct {
	ContractVersion string  `json:"contract_version"`
	Binding         Binding `json:"binding"`
}

// HandoffDeliverRequest is the dedicated sensitive channel. It is never part
// of DesiredExecution, its fingerprint, portable status, or ordinary state.
type HandoffDeliverRequest struct {
	ContractVersion string            `json:"contract_version"`
	Envelope        BootstrapEnvelope `json:"envelope"`
}

type HandoffAcknowledgement struct {
	ContractVersion string `json:"contract_version"`
}

// Handoff is implemented by the exact selected provider driver. Accepted and
// prepared state must survive driver-host and orchestrator restarts.
type Handoff interface {
	Prepare(context.Context, HandoffPrepareRequest) (HandoffPrepareResult, error)
	Replace(context.Context, HandoffReplaceRequest) (HandoffPrepareResult, error)
	Deliver(context.Context, HandoffDeliverRequest) error
}

// Issuer is the topology-neutral lifecycle boundary. A production
// implementation must durably and transactionally implement its semantics.
type Issuer interface {
	Issue(context.Context, IssueRequest) (BootstrapEnvelope, error)
	Exchange(context.Context, ExchangeRequest) (ExchangeResult, error)
	RevokeBinding(context.Context, RevokeBindingRequest) error
	RevokeExecution(context.Context, RevokeExecutionRequest) error
	CompleteExecutionCleanup(context.Context, CompleteExecutionCleanupRequest) error
}

type LifecycleState string

const (
	StateIssued   LifecycleState = "issued"
	StateConsumed LifecycleState = "consumed"
	StateExpired  LifecycleState = "expired"
	StateRevoked  LifecycleState = "revoked"
)

type FailureReason string

const (
	ReasonInvalidRequest  FailureReason = "invalid-request"
	ReasonCapacity        FailureReason = "capacity-exceeded"
	ReasonAlreadyIssued   FailureReason = "already-issued"
	ReasonInvalidToken    FailureReason = "invalid-token"
	ReasonBindingMismatch FailureReason = "binding-mismatch"
	ReasonExpired         FailureReason = "expired"
	ReasonRevoked         FailureReason = "revoked"
	ReasonAlreadyConsumed FailureReason = "already-consumed"
	ReasonIdentityFailure FailureReason = "identity-issuance-failed"
	ReasonStorageFailure  FailureReason = "issuer-storage-failed"
)

// Failure is deliberately value-free so an error cannot expose a token,
// identity, provider diagnostic, or request body.
type Failure struct {
	reason FailureReason
}

func (failure *Failure) Error() string {
	return "guest enrollment rejected: " + string(failure.reason)
}

func NewFailure(reason FailureReason) error {
	switch reason {
	case ReasonInvalidRequest, ReasonCapacity, ReasonAlreadyIssued, ReasonInvalidToken, ReasonBindingMismatch,
		ReasonExpired, ReasonRevoked, ReasonAlreadyConsumed, ReasonIdentityFailure, ReasonStorageFailure:
		return &Failure{reason: reason}
	default:
		return &Failure{reason: ReasonInvalidRequest}
	}
}

func FailureReasonOf(err error) (FailureReason, bool) {
	var failure *Failure
	if !errors.As(err, &failure) {
		return "", false
	}
	return failure.reason, true
}

// GenerateToken uses crypto/rand and returns the one canonical v1 token shape.
func GenerateToken() (string, error) {
	return generateToken(rand.Reader)
}

func generateToken(source io.Reader) (string, error) {
	value := make([]byte, TokenBytes)
	if _, err := io.ReadFull(source, value); err != nil {
		return "", errors.New("guest enrollment token generation failed")
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

// TokenDigest is safe to persist; the plaintext token is not.
func TokenDigest(token string) (string, error) {
	if err := validateOpaque(token, TokenBytes, TokenBytes); err != nil {
		return "", errors.New("guest enrollment token is invalid")
	}
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ValidateTokenDigest(value string) error {
	if !digestPattern.MatchString(value) {
		return errors.New("guest enrollment token digest is invalid")
	}
	return nil
}

func ValidateIssueRequest(value IssueRequest) error {
	if value.ContractVersion != Version || ValidateBinding(value.Binding) != nil ||
		value.TTLSeconds < 1 || value.TTLSeconds > MaxEnrollmentTTLSeconds {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func ValidateBootstrapEnvelope(value BootstrapEnvelope) error {
	if value.ContractVersion != Version || ValidateBinding(value.Binding) != nil || ValidateExchangeURL(value.ExchangeURL) != nil ||
		validateOpaque(value.Token, TokenBytes, TokenBytes) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	issued, expires, err := validateWindow(value.IssuedAt, value.ExpiresAt, time.Duration(MaxEnrollmentTTLSeconds)*time.Second)
	if err != nil || !issued.Before(expires) {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func ValidateExchangeRequest(value ExchangeRequest) error {
	if value.ContractVersion != Version || ValidateBinding(value.Binding) != nil || validateOpaque(value.Token, TokenBytes, TokenBytes) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func ValidateExchangeResult(value ExchangeResult) error {
	if value.ContractVersion != Version || ValidateBinding(value.Binding) != nil ||
		value.RuntimeIdentity.Type != RuntimeIdentityType ||
		validateOpaque(value.RuntimeIdentity.Opaque, TokenBytes, MaxRuntimeIdentityBytes) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	issued, expires, err := validateWindow(value.RuntimeIdentity.IssuedAt, value.RuntimeIdentity.ExpiresAt, MaxRuntimeIdentityLifetime)
	if err != nil || !issued.Before(expires) {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func ValidateRevokeBindingRequest(value RevokeBindingRequest) error {
	if value.ContractVersion != Version || ValidateBinding(value.Binding) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func ValidateRevokeExecutionRequest(value RevokeExecutionRequest) error {
	if value.ContractVersion != Version || ValidateExecutionScope(value.ExecutionScope) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func ValidateCompleteExecutionCleanupRequest(value CompleteExecutionCleanupRequest) error {
	if value.ContractVersion != Version || ValidateExecutionScope(value.ExecutionScope) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func ValidateHandoffPrepareRequest(value HandoffPrepareRequest) error {
	if value.ContractVersion != HandoffVersion || ValidateExecutionScope(value.ExecutionScope) != nil || value.DesiredGeneration < 1 {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func ValidateHandoffPrepareResult(value HandoffPrepareResult) error {
	if value.ContractVersion != HandoffVersion || !validText(value.GuestInstanceID, MaxGuestInstanceIDBytes) {
		return NewFailure(ReasonInvalidRequest)
	}
	switch value.State {
	case HandoffStatePrepared:
		return nil
	case HandoffStateAccepted:
		if !value.NewlyPrepared {
			return nil
		}
	}
	return NewFailure(ReasonInvalidRequest)
}

func ValidateHandoffReplaceRequest(value HandoffReplaceRequest) error {
	if value.ContractVersion != HandoffVersion || ValidateBinding(value.Binding) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func ValidateHandoffDeliverRequest(value HandoffDeliverRequest) error {
	if value.ContractVersion != HandoffVersion || ValidateBootstrapEnvelope(value.Envelope) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func ValidateHandoffAcknowledgement(value HandoffAcknowledgement) error {
	if value.ContractVersion != HandoffVersion {
		return NewFailure(ReasonInvalidRequest)
	}
	return nil
}

func ValidateBinding(value Binding) error {
	if ValidateExecutionScope(value.ExecutionScope()) != nil ||
		value.DesiredGeneration < 1 || !validText(value.GuestInstanceID, MaxGuestInstanceIDBytes) {
		return errors.New("guest enrollment binding is invalid")
	}
	return nil
}

func ValidateExecutionScope(value ExecutionScope) error {
	if !validText(value.AgentRunUID, MaxAgentRunUIDBytes) || !validText(value.ExecutionID, MaxExecutionIDBytes) ||
		len(value.DriverRegistration) > MaxDriverNameBytes || !driverNamePattern.MatchString(value.DriverRegistration) {
		return errors.New("guest enrollment execution scope is invalid")
	}
	return nil
}

func ValidateIssuerConfiguration(value IssuerConfiguration) error {
	return ValidateExchangeURL(value.ExchangeURL)
}

func DecodeIssueRequest(data []byte) (IssueRequest, error) {
	var value IssueRequest
	if DecodeStrictJSON(data, MaxIssueRequestBytes, &value) != nil || ValidateIssueRequest(value) != nil {
		return IssueRequest{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func DecodeBootstrapEnvelope(data []byte) (BootstrapEnvelope, error) {
	var value BootstrapEnvelope
	if DecodeStrictJSON(data, MaxBootstrapEnvelopeBytes, &value) != nil || ValidateBootstrapEnvelope(value) != nil {
		return BootstrapEnvelope{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func DecodeExchangeRequest(data []byte) (ExchangeRequest, error) {
	var value ExchangeRequest
	if DecodeStrictJSON(data, MaxExchangeRequestBytes, &value) != nil || ValidateExchangeRequest(value) != nil {
		return ExchangeRequest{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func DecodeExchangeResult(data []byte) (ExchangeResult, error) {
	var value ExchangeResult
	if DecodeStrictJSON(data, MaxExchangeResultBytes, &value) != nil || ValidateExchangeResult(value) != nil {
		return ExchangeResult{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func DecodeRevokeBindingRequest(data []byte) (RevokeBindingRequest, error) {
	var value RevokeBindingRequest
	if DecodeStrictJSON(data, MaxRevocationRequestBytes, &value) != nil || ValidateRevokeBindingRequest(value) != nil {
		return RevokeBindingRequest{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func DecodeRevokeExecutionRequest(data []byte) (RevokeExecutionRequest, error) {
	var value RevokeExecutionRequest
	if DecodeStrictJSON(data, MaxRevocationRequestBytes, &value) != nil || ValidateRevokeExecutionRequest(value) != nil {
		return RevokeExecutionRequest{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func DecodeCompleteExecutionCleanupRequest(data []byte) (CompleteExecutionCleanupRequest, error) {
	var value CompleteExecutionCleanupRequest
	if DecodeStrictJSON(data, MaxRevocationRequestBytes, &value) != nil || ValidateCompleteExecutionCleanupRequest(value) != nil {
		return CompleteExecutionCleanupRequest{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func DecodeHandoffPrepareRequest(data []byte) (HandoffPrepareRequest, error) {
	var value HandoffPrepareRequest
	if DecodeStrictJSON(data, MaxHandoffRequestBytes, &value) != nil || ValidateHandoffPrepareRequest(value) != nil {
		return HandoffPrepareRequest{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func DecodeHandoffPrepareResult(data []byte) (HandoffPrepareResult, error) {
	var value HandoffPrepareResult
	if DecodeStrictJSON(data, MaxHandoffResponseBytes, &value) != nil || ValidateHandoffPrepareResult(value) != nil {
		return HandoffPrepareResult{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func DecodeHandoffReplaceRequest(data []byte) (HandoffReplaceRequest, error) {
	var value HandoffReplaceRequest
	if DecodeStrictJSON(data, MaxHandoffRequestBytes, &value) != nil || ValidateHandoffReplaceRequest(value) != nil {
		return HandoffReplaceRequest{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func DecodeHandoffDeliverRequest(data []byte) (HandoffDeliverRequest, error) {
	var value HandoffDeliverRequest
	if DecodeStrictJSON(data, MaxHandoffRequestBytes, &value) != nil || ValidateHandoffDeliverRequest(value) != nil {
		return HandoffDeliverRequest{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

func DecodeHandoffAcknowledgement(data []byte) (HandoffAcknowledgement, error) {
	var value HandoffAcknowledgement
	if DecodeStrictJSON(data, MaxHandoffResponseBytes, &value) != nil || ValidateHandoffAcknowledgement(value) != nil {
		return HandoffAcknowledgement{}, NewFailure(ReasonInvalidRequest)
	}
	return value, nil
}

// DecodeStrictJSON rejects invalid UTF-8, unknown fields, trailing values, and
// duplicate keys recursively, including escaped-equivalent keys.
func DecodeStrictJSON(data []byte, maximum int, target any) error {
	if len(data) == 0 || len(data) > maximum || !utf8.Valid(data) {
		return errors.New("guest enrollment JSON is invalid")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return errors.New("guest enrollment JSON is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("guest enrollment JSON is invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("guest enrollment JSON is invalid")
	}
	return nil
}

func (BootstrapEnvelope) String() string   { return "[sensitive guest enrollment envelope]" }
func (BootstrapEnvelope) GoString() string { return "[sensitive guest enrollment envelope]" }
func (ExchangeRequest) String() string     { return "[sensitive guest enrollment exchange request]" }
func (ExchangeRequest) GoString() string   { return "[sensitive guest enrollment exchange request]" }
func (ExchangeResult) String() string      { return "[sensitive guest enrollment exchange result]" }
func (ExchangeResult) GoString() string    { return "[sensitive guest enrollment exchange result]" }
func (RuntimeIdentity) String() string     { return "[sensitive guest runtime identity]" }
func (RuntimeIdentity) GoString() string   { return "[sensitive guest runtime identity]" }
func (HandoffDeliverRequest) String() string {
	return "[sensitive guest enrollment handoff]"
}
func (HandoffDeliverRequest) GoString() string {
	return "[sensitive guest enrollment handoff]"
}

func FormatTimestamp(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format(time.RFC3339)
}

func ValidateExchangeURL(value string) error {
	if !validText(value, MaxExchangeURLBytes) {
		return errors.New("exchange URL is invalid")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.Path == "" || parsed.Path == "/" || path.Clean(parsed.Path) != parsed.Path || strings.Contains(parsed.Path, "\\") ||
		strings.Contains(parsed.Path, "//") || parsed.String() != value {
		return errors.New("exchange URL is invalid")
	}
	return nil
}

func validateWindow(issuedValue, expiresValue string, maximum time.Duration) (time.Time, time.Time, error) {
	issued, err := parseTimestamp(issuedValue)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	expires, err := parseTimestamp(expiresValue)
	if err != nil || expires.Sub(issued) > maximum {
		return time.Time{}, time.Time{}, errors.New("time window is invalid")
	}
	return issued, expires, nil
}

func parseTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || FormatTimestamp(parsed) != value {
		return time.Time{}, errors.New("timestamp is invalid")
	}
	return parsed, nil
}

func validateOpaque(value string, minimumBytes, maximumBytes int) error {
	if value == "" || len(value) > base64.RawURLEncoding.EncodedLen(maximumBytes) || strings.Contains(value, "=") {
		return errors.New("opaque value is invalid")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) < minimumBytes || len(decoded) > maximumBytes || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return errors.New("opaque value is invalid")
	}
	return nil
}

func validText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid object key")
			}
			if _, duplicate := keys[key]; duplicate {
				return errors.New("duplicate object key")
			}
			keys[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("unterminated object")
		}
		return nil
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("unterminated array")
		}
		return nil
	default:
		return errors.New("invalid JSON delimiter")
	}
}
