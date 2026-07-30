// Package nativeegressipc defines the bounded, credential-free local stream
// boundary between the guest capture process and the authenticated egress
// transport process. Exact binding and bearer material are deliberately not
// representable on this wire.
package nativeegressipc

import (
	"encoding/json"
	"errors"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/contract"
	protocol "github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

const (
	Version         = "nvt.native-egress-local-flow/v1"
	Open            = "open"
	Health          = "health"
	OpenAck         = "open_ack"
	OpenReject      = "open_reject"
	Ready           = "ready"
	MaxMessageBytes = protocol.MaxFrameBytes
	Deadline        = protocol.FlowOpenTimeout
)

type Request struct {
	Version     string                `json:"version"`
	Type        string                `json:"type"`
	Destination *protocol.Destination `json:"destination,omitempty"`
}

type Response struct {
	Version string `json:"version"`
	Type    string `json:"type"`
	Reason  string `json:"reason,omitempty"`
	Epoch   uint64 `json:"epoch,omitempty"`
}

func ValidateRequest(value Request) error {
	if value.Version != Version {
		return errors.New("local native egress request is invalid")
	}
	switch value.Type {
	case Open:
		if value.Destination == nil || protocol.ValidateDestination(*value.Destination) != nil {
			return errors.New("local native egress request is invalid")
		}
	case Health:
		if value.Destination != nil {
			return errors.New("local native egress request is invalid")
		}
	default:
		return errors.New("local native egress request is invalid")
	}
	return nil
}

func ValidateResponse(value Response) error {
	if value.Version != Version {
		return errors.New("local native egress response is invalid")
	}
	switch value.Type {
	case OpenAck:
		if value.Reason != "" || value.Epoch == 0 {
			return errors.New("local native egress response is invalid")
		}
	case OpenReject:
		if value.Reason != "denied" || value.Epoch != 0 {
			return errors.New("local native egress response is invalid")
		}
	case Ready:
		if value.Reason != "" || value.Epoch == 0 {
			return errors.New("local native egress response is invalid")
		}
	default:
		return errors.New("local native egress response is invalid")
	}
	return nil
}

func EncodeRequest(value Request) ([]byte, error) {
	if ValidateRequest(value) != nil {
		return nil, errors.New("local native egress request is invalid")
	}
	return encode(value)
}

func DecodeRequest(data []byte) (Request, error) {
	var value Request
	if contract.DecodeStrict(data, MaxMessageBytes, &value) != nil || ValidateRequest(value) != nil {
		return Request{}, errors.New("local native egress request is invalid")
	}
	return value, nil
}

func EncodeResponse(value Response) ([]byte, error) {
	if ValidateResponse(value) != nil {
		return nil, errors.New("local native egress response is invalid")
	}
	return encode(value)
}

func DecodeResponse(data []byte) (Response, error) {
	var value Response
	if contract.DecodeStrict(data, MaxMessageBytes, &value) != nil || ValidateResponse(value) != nil {
		return Response{}, errors.New("local native egress response is invalid")
	}
	return value, nil
}

func encode(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil || len(data)+1 > MaxMessageBytes {
		return nil, errors.New("local native egress message is invalid")
	}
	return append(data, '\n'), nil
}
