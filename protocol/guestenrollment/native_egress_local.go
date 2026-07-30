package guestenrollment

import (
	"encoding/json"
	"errors"
)

const (
	NativeEgressLocalVersion         = "nvt.native-egress-local/v1"
	NativeEgressCredentialIssue      = "issue_native_egress"
	NativeEgressCredentialResult     = "native_egress_result"
	NativeEgressCredentialError      = "error"
	MaxNativeEgressLocalMessageBytes = 32 << 10
)

// NativeEgressCredentialRequest deliberately has no runtime identity,
// binding, audience, broker URL, target, or provider input. The root-owned
// identity authority derives the exact fixed-purpose request from protected
// durable state.
type NativeEgressCredentialRequest struct {
	ContractVersion string `json:"contract_version"`
	Type            string `json:"type"`
}

type NativeEgressLocalError struct {
	Reason    string `json:"reason"`
	Temporary bool   `json:"temporary"`
	Uncertain bool   `json:"uncertain"`
}

type NativeEgressCredentialResponse struct {
	ContractVersion string                   `json:"contract_version"`
	Type            string                   `json:"type"`
	Result          *NativeEgressIssueResult `json:"result,omitempty"`
	Error           *NativeEgressLocalError  `json:"error,omitempty"`
}

func ValidateNativeEgressCredentialRequest(value NativeEgressCredentialRequest) error {
	if value.ContractVersion != NativeEgressLocalVersion || value.Type != NativeEgressCredentialIssue {
		return errors.New("native egress credential request is invalid")
	}
	return nil
}

func EncodeNativeEgressCredentialRequest(value NativeEgressCredentialRequest) ([]byte, error) {
	if ValidateNativeEgressCredentialRequest(value) != nil {
		return nil, errors.New("native egress credential request is invalid")
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded)+1 > MaxNativeEgressLocalMessageBytes {
		return nil, errors.New("native egress credential request is invalid")
	}
	return append(encoded, '\n'), nil
}

func DecodeNativeEgressCredentialRequest(data []byte) (NativeEgressCredentialRequest, error) {
	var value NativeEgressCredentialRequest
	if DecodeStrictJSON(data, MaxNativeEgressLocalMessageBytes, &value) != nil || ValidateNativeEgressCredentialRequest(value) != nil {
		return NativeEgressCredentialRequest{}, errors.New("native egress credential request is invalid")
	}
	return value, nil
}

func ValidateNativeEgressCredentialResponse(value NativeEgressCredentialResponse) error {
	if value.ContractVersion != NativeEgressLocalVersion {
		return errors.New("native egress credential response is invalid")
	}
	switch value.Type {
	case NativeEgressCredentialResult:
		if value.Result == nil || value.Error != nil || ValidateNativeEgressIssueResult(*value.Result) != nil {
			return errors.New("native egress credential response is invalid")
		}
	case NativeEgressCredentialError:
		if value.Result != nil || value.Error == nil || !nativeSessionReasonPattern.MatchString(value.Error.Reason) {
			return errors.New("native egress credential response is invalid")
		}
	default:
		return errors.New("native egress credential response is invalid")
	}
	return nil
}

func EncodeNativeEgressCredentialResponse(value NativeEgressCredentialResponse) ([]byte, error) {
	if ValidateNativeEgressCredentialResponse(value) != nil {
		return nil, errors.New("native egress credential response is invalid")
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded)+1 > MaxNativeEgressLocalMessageBytes {
		return nil, errors.New("native egress credential response is invalid")
	}
	return append(encoded, '\n'), nil
}

func DecodeNativeEgressCredentialResponse(data []byte) (NativeEgressCredentialResponse, error) {
	var value NativeEgressCredentialResponse
	if DecodeStrictJSON(data, MaxNativeEgressLocalMessageBytes, &value) != nil || ValidateNativeEgressCredentialResponse(value) != nil {
		return NativeEgressCredentialResponse{}, errors.New("native egress credential response is invalid")
	}
	return value, nil
}

func (NativeEgressCredentialRequest) String() string {
	return "[native egress credential request]"
}

func (NativeEgressCredentialRequest) GoString() string {
	return "[native egress credential request]"
}

func (NativeEgressCredentialResponse) String() string {
	return "[sensitive native egress credential response]"
}

func (NativeEgressCredentialResponse) GoString() string {
	return "[sensitive native egress credential response]"
}
