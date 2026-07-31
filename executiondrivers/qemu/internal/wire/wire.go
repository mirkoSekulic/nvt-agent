package wire

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/mirkoSekulic/nvt-agent/executiondrivers/qemu/internal/config"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

const (
	Version = "nvt.qemu-guest-control/v1"
	// A configure message may contain one independently bounded 64 KiB QEMU
	// class configuration plus the 96 KiB portable attachment. Keep the whole
	// private guest-control exchange finite while leaving explicit framing
	// headroom for the exact binding and request envelope.
	MaxMessageBytes  = 192 << 10
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
	ContractVersion        string                                  `json:"contract_version"`
	Binding                guestenrollment.Binding                 `json:"binding"`
	HostBundle             config.Artifact                         `json:"host_bundle"`
	RegistryCAPEM          string                                  `json:"registry_ca_pem,omitempty"`
	EnrollmentCAPEM        string                                  `json:"enrollment_ca_pem"`
	NativeSessionEndpoint  string                                  `json:"native_session_endpoint"`
	NativeSessionCAPEM     string                                  `json:"native_session_ca_pem"`
	NativeEgressAttachment *executiondriver.NativeEgressAttachment `json:"native_egress_attachment,omitempty"`
	NativeEgressProbe      *config.NativeEgressProbe               `json:"native_egress_probe,omitempty"`
}

type NativeEgressHostAlias struct {
	Host    string `json:"host"`
	Address string `json:"address"`
}

// NativeEgressHostAliases assigns deterministic guest-visible addresses only
// to the explicitly permitted relay/bootstrap/control hosts. QEMU's
// restrict=on backend owns the matching forwarding rules outside the guest.
func NativeEgressHostAliases(attachment executiondriver.NativeEgressAttachment) ([]NativeEgressHostAlias, error) {
	if executiondriver.ValidateNativeEgressAttachment(attachment) != nil {
		return nil, errors.New("QEMU native egress attachment is invalid")
	}
	hosts := map[string]struct{}{attachment.Relay.Host: {}}
	for _, destination := range attachment.RequiredDestinations {
		if destination.Host == attachment.Relay.ServerName && attachment.Relay.ServerName != attachment.Relay.Host {
			continue
		}
		hosts[destination.Host] = struct{}{}
	}
	ordered := make([]string, 0, len(hosts))
	for host := range hosts {
		ordered = append(ordered, host)
	}
	sort.Strings(ordered)
	aliases := make([]NativeEgressHostAlias, 0, len(ordered))
	for index, host := range ordered {
		aliases = append(aliases, NativeEgressHostAlias{Host: host, Address: fmt.Sprintf("10.0.2.%d", 100+index)})
	}
	if attachment.Relay.ServerName != attachment.Relay.Host {
		for _, alias := range aliases {
			if alias.Host == attachment.Relay.Host {
				aliases = append(aliases, NativeEgressHostAlias{Host: attachment.Relay.ServerName, Address: alias.Address})
				break
			}
		}
	}
	return aliases, nil
}

type Request struct {
	ContractVersion   string                             `json:"contract_version"`
	Type              string                             `json:"type"`
	Configuration     *BootConfiguration                 `json:"configuration,omitempty"`
	Envelope          *guestenrollment.BootstrapEnvelope `json:"envelope,omitempty"`
	NativeEgressCAPEM string                             `json:"native_egress_ca_pem,omitempty"`
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
