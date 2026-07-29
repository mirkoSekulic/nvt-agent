package wire

import (
	"encoding/json"
	"errors"

	"github.com/mirkoSekulic/nvt-agent/executiondrivers/qemu/internal/config"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

const (
	Version          = "nvt.qemu-guest-control/v1"
	MaxMessageBytes  = 64 << 10
	StateConnected   = "connected"
	StateWaiting     = "waiting"
	StateEnrolled    = "enrolled"
	StateReady       = "ready"
	StateFailed      = "failed"
	RequestConfigure = "configure"
	RequestStatus    = "status"
	RequestDeliver   = "deliver"
)

type BootConfiguration struct {
	ContractVersion       string                  `json:"contract_version"`
	Binding               guestenrollment.Binding `json:"binding"`
	HostBundle            config.Artifact         `json:"host_bundle"`
	RegistryCAPEM         string                  `json:"registry_ca_pem,omitempty"`
	EnrollmentCAPEM       string                  `json:"enrollment_ca_pem"`
	NativeSessionEndpoint string                  `json:"native_session_endpoint"`
	NativeSessionCAPEM    string                  `json:"native_session_ca_pem"`
}

type Request struct {
	ContractVersion string                             `json:"contract_version"`
	Type            string                             `json:"type"`
	Configuration   *BootConfiguration                 `json:"configuration,omitempty"`
	Envelope        *guestenrollment.BootstrapEnvelope `json:"envelope,omitempty"`
}

type Response struct {
	ContractVersion string                   `json:"contract_version"`
	State           string                   `json:"state"`
	Binding         *guestenrollment.Binding `json:"binding,omitempty"`
	Error           string                   `json:"error,omitempty"`
}

func Encode(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(encoded)+1 > MaxMessageBytes {
		return nil, errors.New("QEMU guest control message exceeds the bound")
	}
	return append(encoded, '\n'), nil
}
