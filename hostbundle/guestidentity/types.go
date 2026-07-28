// Package guestidentity owns the native guest's sensitive runtime identity.
// It is provider-neutral and deliberately separate from agentd and the agent
// session.
package guestidentity

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/contract"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

const (
	ConfigurationVersion  = 1
	StateVersion          = "nvt.guest-runtime-identity-state/v1"
	MaxConfigurationBytes = 64 << 10
	MaxStateBytes         = 256 << 10

	StateFileName     = "identity.json"
	ReadinessFileName = "identity-ready"

	ReasonEnrollmentPending   Reason = "enrollment-pending"
	ReasonBrokerUnavailable   Reason = "broker-unavailable"
	ReasonReplacementRequired Reason = "replacement-required"
	ReasonStateUnavailable    Reason = "state-unavailable"
	ReasonStateInvalid        Reason = "state-invalid"
	ReasonTrustInvalid        Reason = "trust-invalid"
	ReasonProtocolInvalid     Reason = "protocol-invalid"
)

var (
	minimumRotationInterval = guestenrollment.RuntimeIdentityCapacityPlanningInterval
	rotationRecoveryWindow  = 15 * time.Minute
	maximumRotationJitter   = 5 * time.Minute
	statusPollInterval      = 5 * time.Minute
	retryInterval           = 5 * time.Second
)

// Configuration contains paths only. The CA is not secret, and no bearer or
// enrollment envelope is valid configuration.
type Configuration struct {
	Version          int    `json:"version"`
	StateDirectory   string `json:"state_directory"`
	RuntimeDirectory string `json:"runtime_directory"`
	EnrollmentPath   string `json:"enrollment_path"`
	CAPEMPath        string `json:"ca_pem_path"`
}

// durableState is root-only sensitive state. It is intentionally not exposed
// through the provider-facing package boundary, and formatting is redacted.
type durableState struct {
	ContractVersion  string                           `json:"contract_version"`
	Binding          guestenrollment.Binding          `json:"binding"`
	BrokerURL        string                           `json:"broker_url"`
	RuntimeIdentity  *guestenrollment.RuntimeIdentity `json:"runtime_identity,omitempty"`
	PendingSuccessor string                           `json:"pending_successor,omitempty"`
	FailureReason    Reason                           `json:"failure_reason,omitempty"`
}

type Reason string

type Failure struct {
	reason    Reason
	temporary bool
	uncertain bool
}

func (failure *Failure) Error() string {
	return "guest runtime identity unavailable: " + string(failure.reason)
}

func (failure *Failure) Reason() Reason  { return failure.reason }
func (failure *Failure) Temporary() bool { return failure.temporary }
func (failure *Failure) Uncertain() bool { return failure.uncertain }

func failure(reason Reason, temporary, uncertain bool) error {
	return &Failure{reason: reason, temporary: temporary, uncertain: uncertain}
}

func FailureDetails(err error) (Reason, bool, bool) {
	var value *Failure
	if !errors.As(err, &value) {
		return ReasonProtocolInvalid, false, false
	}
	return value.reason, value.temporary, value.uncertain
}

func (durableState) String() string   { return "[sensitive guest runtime identity state]" }
func (durableState) GoString() string { return "[sensitive guest runtime identity state]" }

type Snapshot struct {
	Ready          bool
	Reason         Reason
	Binding        guestenrollment.Binding
	IssuedAt       string
	ExpiresAt      string
	NextRotationAt string
}

func (Snapshot) String() string   { return "[non-secret guest runtime identity health]" }
func (Snapshot) GoString() string { return "[non-secret guest runtime identity health]" }

func LoadConfiguration(path string) (Configuration, error) {
	data, err := readBoundedRegular(path, MaxConfigurationBytes, uint32(os.Geteuid()))
	if err != nil {
		return Configuration{}, failure(ReasonStateUnavailable, false, false)
	}
	var value Configuration
	if contract.DecodeStrict(data, MaxConfigurationBytes, &value) != nil || validateConfiguration(value) != nil {
		return Configuration{}, failure(ReasonStateInvalid, false, false)
	}
	return value, nil
}

func validateConfiguration(value Configuration) error {
	if value.Version != ConfigurationVersion || !validAbsoluteDirectory(value.StateDirectory) ||
		!validAbsoluteDirectory(value.RuntimeDirectory) || !validAbsoluteFile(value.EnrollmentPath) ||
		!validAbsoluteFile(value.CAPEMPath) || filepath.Dir(value.EnrollmentPath) != value.StateDirectory ||
		value.StateDirectory == value.RuntimeDirectory || value.CAPEMPath == value.EnrollmentPath ||
		value.CAPEMPath == filepath.Join(value.StateDirectory, StateFileName) {
		return errors.New("guest runtime identity configuration is invalid")
	}
	return nil
}

func validateState(value durableState) error {
	if value.ContractVersion != StateVersion || guestenrollment.ValidateBinding(value.Binding) != nil {
		return errors.New("guest runtime identity state is invalid")
	}
	if value.FailureReason != "" {
		if value.FailureReason != ReasonReplacementRequired || value.RuntimeIdentity != nil || value.PendingSuccessor != "" {
			return errors.New("guest runtime identity state is invalid")
		}
		if value.BrokerURL != "" && validateBrokerURL(value.BrokerURL) != nil {
			return errors.New("guest runtime identity state is invalid")
		}
		return nil
	}
	if validateBrokerURL(value.BrokerURL) != nil {
		return errors.New("guest runtime identity state is invalid")
	}
	if value.RuntimeIdentity == nil {
		return errors.New("guest runtime identity state is invalid")
	}
	if guestenrollment.ValidateExchangeResult(guestenrollment.ExchangeResult{
		ContractVersion: guestenrollment.Version,
		Binding:         value.Binding,
		RuntimeIdentity: *value.RuntimeIdentity,
	}) != nil {
		return errors.New("guest runtime identity state is invalid")
	}
	if value.PendingSuccessor != "" {
		if _, err := guestenrollment.RuntimeIdentityDigest(value.PendingSuccessor); err != nil || value.PendingSuccessor == value.RuntimeIdentity.Opaque {
			return errors.New("guest runtime identity state is invalid")
		}
	}
	return nil
}

func brokerURLFromExchange(exchangeURL string) (string, error) {
	if guestenrollment.ValidateExchangeURL(exchangeURL) != nil {
		return "", errors.New("guest runtime identity broker URL is invalid")
	}
	parsed, err := url.Parse(exchangeURL)
	if err != nil || parsed.Path != guestenrollment.EnrollmentExchangePath {
		return "", errors.New("guest runtime identity broker URL is invalid")
	}
	value := parsed.Scheme + "://" + parsed.Host
	if validateBrokerURL(value) != nil {
		return "", errors.New("guest runtime identity broker URL is invalid")
	}
	return value, nil
}

func validateBrokerURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.String() != value || strings.Contains(value, "\\") {
		return errors.New("guest runtime identity broker URL is invalid")
	}
	if parsed.Hostname() == "" {
		return errors.New("guest runtime identity broker URL is invalid")
	}
	if port := parsed.Port(); port != "" {
		number, parseErr := strconv.Atoi(port)
		if parseErr != nil || number < 1 || number > 65535 {
			return errors.New("guest runtime identity broker URL is invalid")
		}
	}
	return nil
}

func validAbsoluteDirectory(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/" && !strings.ContainsRune(value, 0)
}

func validAbsoluteFile(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && filepath.Dir(value) != value && !strings.ContainsRune(value, 0)
}
