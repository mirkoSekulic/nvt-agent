// Package executiondriver defines the portable nvt execution-driver protocol.
// It intentionally contains no process supervision or Kubernetes integration;
// those are operator responsibilities layered above this contract.
package executiondriver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	ProtocolVersion = "nvt.execution-driver/v1"
	JSONRPCVersion  = "2.0"

	MaxMessageBytes        = 1 << 20
	MaxDesiredBytes        = 256 << 10
	MaxExecutionIDBytes    = 256
	MaxDriverNameBytes     = 128
	MaxExternalIDBytes     = 2048
	MaxFailureReasonBytes  = 128
	MaxFailureMessageBytes = 1024
	MaxRetryAfterSeconds   = 3600
)

type Method string

const (
	MethodInitialize Method = "initialize"
	MethodReconcile  Method = "reconcile"
	MethodObserve    Method = "observe"
	MethodDelete     Method = "delete"
	MethodShutdown   Method = "shutdown"
)

type Capability string

const (
	CapabilityReconcile Capability = "reconcile"
	CapabilityObserve   Capability = "observe"
	CapabilityDelete    Capability = "delete"
)

var requiredCapabilities = map[Capability]struct{}{
	CapabilityReconcile: {},
	CapabilityObserve:   {},
	CapabilityDelete:    {},
}

type WorkloadKind string

const (
	WorkloadKindPod WorkloadKind = "pod"
	WorkloadKindVM  WorkloadKind = "vm"
)

type Phase string

const (
	PhasePending      Phase = "pending"
	PhaseProvisioning Phase = "provisioning"
	PhaseRunning      Phase = "running"
	PhaseSucceeded    Phase = "succeeded"
	PhaseFailed       Phase = "failed"
	PhaseDeleting     Phase = "deleting"
	PhaseDeleted      Phase = "deleted"
	PhaseUnknown      Phase = "unknown"
)

type EndpointScheme string

const (
	EndpointSchemeHTTP  EndpointScheme = "http"
	EndpointSchemeHTTPS EndpointScheme = "https"
)

// Request and Response are the JSON-RPC 2.0 envelopes used on JSONL stdin and
// stdout. IDs are strings so implementations do not lose precision across
// languages.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Method  Method          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

type RPCError struct {
	Code    int     `json:"code"`
	Message string  `json:"message"`
	Data    Failure `json:"data"`
}

type InitializeParams struct {
	ProtocolVersion    string `json:"protocol_version"`
	DriverInstanceName string `json:"driver_instance_name"`
}

type InitializeResult struct {
	ProtocolVersion string       `json:"protocol_version"`
	Capabilities    []Capability `json:"capabilities"`
}

// DesiredExecution is an operator-owned, level-triggered desired state. The
// driver-specific configuration must be a JSON object. It is deliberately not
// part of the producer or AgentRun API in this protocol-only phase.
type DesiredExecution struct {
	ExecutionID   string          `json:"execution_id"`
	Generation    int64           `json:"generation"`
	WorkloadKind  WorkloadKind    `json:"workload_kind"`
	ClassName     string          `json:"class_name"`
	Configuration json.RawMessage `json:"configuration"`
}

type ReconcileParams struct {
	Desired DesiredExecution `json:"desired"`
}

type ExecutionParams struct {
	ExecutionID string `json:"execution_id"`
}

type Endpoint struct {
	Scheme EndpointScheme `json:"scheme"`
	Host   string         `json:"host"`
	Port   uint16         `json:"port"`
}

type Failure struct {
	Reason    string `json:"reason"`
	Message   string `json:"message,omitempty"`
	Retryable bool   `json:"retryable"`
}

// Status is the complete portable observation returned by reconcile, observe,
// and delete. It is not an AgentRun condition: the operator remains the sole
// owner of AgentRun status and maps validated observations according to its
// retry, timeout, and lifecycle policy.
type Status struct {
	Phase              Phase     `json:"phase"`
	Ready              bool      `json:"ready"`
	Endpoint           *Endpoint `json:"endpoint,omitempty"`
	ExternalResourceID string    `json:"external_resource_id,omitempty"`
	ObservedGeneration int64     `json:"observed_generation"`
	RetryAfterSeconds  *int32    `json:"retry_after_seconds,omitempty"`
	Failure            *Failure  `json:"failure,omitempty"`
}

type ShutdownResult struct{}

var (
	stableTokenPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
	namePattern        = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
)

func ValidateInitializeParams(value InitializeParams) error {
	if value.ProtocolVersion != ProtocolVersion {
		return errors.New("initialize protocol_version is unsupported")
	}
	if !validBoundedToken(value.DriverInstanceName, MaxDriverNameBytes, namePattern) {
		return errors.New("initialize driver_instance_name is invalid")
	}
	return nil
}

func ValidateInitializeResult(value InitializeResult) error {
	if value.ProtocolVersion != ProtocolVersion {
		return errors.New("initialize result protocol_version is unsupported")
	}
	seen := make(map[Capability]struct{}, len(value.Capabilities))
	for _, capability := range value.Capabilities {
		if _, allowed := requiredCapabilities[capability]; !allowed {
			return errors.New("initialize result contains an unsupported capability")
		}
		if _, duplicate := seen[capability]; duplicate {
			return errors.New("initialize result contains a duplicate capability")
		}
		seen[capability] = struct{}{}
	}
	for capability := range requiredCapabilities {
		if _, present := seen[capability]; !present {
			return errors.New("initialize result is missing a required capability")
		}
	}
	return nil
}

func ValidateReconcileParams(value ReconcileParams) error {
	if err := validateExecutionID(value.Desired.ExecutionID); err != nil {
		return err
	}
	if value.Desired.Generation < 1 {
		return errors.New("reconcile desired generation must be positive")
	}
	if value.Desired.WorkloadKind != WorkloadKindPod && value.Desired.WorkloadKind != WorkloadKindVM {
		return errors.New("reconcile desired workload_kind is invalid")
	}
	if !validBoundedToken(value.Desired.ClassName, MaxDriverNameBytes, namePattern) {
		return errors.New("reconcile desired class_name is invalid")
	}
	if len(value.Desired.Configuration) == 0 || len(value.Desired.Configuration) > MaxDesiredBytes {
		return errors.New("reconcile desired configuration size is invalid")
	}
	var configuration map[string]json.RawMessage
	if err := DecodeStrictJSON(value.Desired.Configuration, &configuration); err != nil || configuration == nil {
		return errors.New("reconcile desired configuration must be a JSON object")
	}
	return nil
}

func ValidateExecutionParams(value ExecutionParams) error {
	return validateExecutionID(value.ExecutionID)
}

func ValidateStatus(value Status) error {
	switch value.Phase {
	case PhasePending, PhaseProvisioning, PhaseRunning, PhaseSucceeded, PhaseFailed, PhaseDeleting, PhaseDeleted, PhaseUnknown:
	default:
		return errors.New("status phase is invalid")
	}
	if value.ObservedGeneration < 0 {
		return errors.New("status observed_generation must not be negative")
	}
	if value.Ready && (value.Phase != PhaseRunning || value.Endpoint == nil) {
		return errors.New("status ready requires a running phase and endpoint")
	}
	if value.Endpoint != nil {
		if err := validateEndpoint(*value.Endpoint); err != nil {
			return err
		}
	}
	if value.ExternalResourceID != "" && !validBoundedText(value.ExternalResourceID, MaxExternalIDBytes) {
		return errors.New("status external_resource_id is invalid")
	}
	if value.RetryAfterSeconds != nil && (*value.RetryAfterSeconds < 1 || *value.RetryAfterSeconds > MaxRetryAfterSeconds) {
		return errors.New("status retry_after_seconds is outside the supported range")
	}
	if value.Phase == PhaseFailed {
		if value.Failure == nil {
			return errors.New("failed status requires a sanitized failure")
		}
		if err := ValidateFailure(*value.Failure); err != nil {
			return err
		}
	} else if value.Failure != nil {
		return errors.New("status failure is only valid for the failed phase")
	}
	if value.Phase == PhaseDeleted {
		if value.Ready || value.Endpoint != nil || value.ExternalResourceID != "" || value.Failure != nil {
			return errors.New("deleted status must not retain runtime resource data")
		}
	}
	return nil
}

func ValidateReconcileStatus(value Status) error {
	if err := ValidateStatus(value); err != nil {
		return err
	}
	if value.Phase == PhaseDeleting || value.Phase == PhaseDeleted {
		return errors.New("reconcile status phase is invalid")
	}
	return nil
}

func ValidateObserveStatus(value Status) error {
	return ValidateStatus(value)
}

func ValidateDeleteStatus(value Status) error {
	if err := ValidateStatus(value); err != nil {
		return err
	}
	if value.Phase != PhaseDeleting && value.Phase != PhaseDeleted {
		return errors.New("delete status phase is invalid")
	}
	return nil
}

func ValidateFailure(value Failure) error {
	if !validBoundedToken(value.Reason, MaxFailureReasonBytes, stableTokenPattern) {
		return errors.New("failure reason is invalid")
	}
	if value.Message != "" && !validBoundedText(value.Message, MaxFailureMessageBytes) {
		return errors.New("failure message is invalid")
	}
	return nil
}

func ValidateRPCError(value RPCError) error {
	if value.Code > -32000 || value.Code < -32099 {
		return errors.New("JSON-RPC driver error code is invalid")
	}
	if value.Message != "driver error" {
		return errors.New("JSON-RPC driver error message is invalid")
	}
	return ValidateFailure(value.Data)
}

// DecodeStrictJSON rejects trailing values and unknown object fields. Framing,
// duplicate-key rejection, and the 1 MiB line bound remain transport-host
// responsibilities in the later executable-loading phase.
func DecodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func validateExecutionID(value string) error {
	if !validBoundedText(value, MaxExecutionIDBytes) {
		return errors.New("execution_id is invalid")
	}
	return nil
}

func validateEndpoint(value Endpoint) error {
	if value.Scheme != EndpointSchemeHTTP && value.Scheme != EndpointSchemeHTTPS {
		return errors.New("status endpoint scheme is invalid")
	}
	if value.Port == 0 {
		return errors.New("status endpoint port is invalid")
	}
	if net.ParseIP(value.Host) != nil {
		return nil
	}
	if len(value.Host) == 0 || len(value.Host) > 253 || value.Host != strings.ToLower(value.Host) {
		return errors.New("status endpoint host is invalid")
	}
	for _, label := range strings.Split(value.Host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("status endpoint host is invalid")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return errors.New("status endpoint host is invalid")
			}
		}
	}
	return nil
}

func validBoundedToken(value string, maxBytes int, pattern *regexp.Regexp) bool {
	return validBoundedText(value, maxBytes) && pattern.MatchString(value)
}

func validBoundedText(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func MarshalRequest(id string, method Method, params any) ([]byte, error) {
	if id == "" || !validBoundedText(id, 128) {
		return nil, errors.New("JSON-RPC request id is invalid")
	}
	encodedParams, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshal JSON-RPC params: %w", err)
	}
	encoded, err := json.Marshal(Request{JSONRPC: JSONRPCVersion, ID: id, Method: method, Params: encodedParams})
	if err != nil {
		return nil, fmt.Errorf("marshal JSON-RPC request: %w", err)
	}
	if len(encoded)+1 > MaxMessageBytes {
		return nil, errors.New("JSON-RPC request exceeds the message limit")
	}
	return encoded, nil
}
