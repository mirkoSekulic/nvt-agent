package guestenrollment

import (
	"encoding/json"
	"errors"
	"regexp"
)

const (
	NativeSessionVersion                  = "nvt.native-session/v1"
	NativeSessionLocalVersion             = "nvt.native-session-local/v1"
	NativeSessionHello                    = "hello"
	NativeSessionHelloAck                 = "hello_ack"
	NativeSessionHelloReject              = "hello_reject"
	NativeSessionAgentdRequest            = "agentd_request"
	NativeSessionAgentdResponse           = "agentd_response"
	NativeSessionPing                     = "ping"
	NativeSessionPong                     = "pong"
	NativeSessionCredentialIssue          = "issue_guest_session"
	NativeSessionCredentialResult         = "guest_session_result"
	NativeSessionCredentialError          = "error"
	MaxNativeSessionFrameBytes            = 64 << 10
	MaxNativeSessionAgentdPayloadBytes    = 32 << 10
	MaxNativeSessionLocalMessageBytes     = 32 << 10
	MaxNativeSessionRequestsPerConnection = 1024
)

var (
	nativeSessionRequestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	nativeSessionReasonPattern    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,127}$`)
)

// NativeSessionMessage is one strictly validated JSONL frame on the outbound
// guest-to-gateway transport. Credential is populated only on the first hello
// and Payload contains one bounded agentd JSON object.
type NativeSessionMessage struct {
	ContractVersion string          `json:"contract_version"`
	Type            string          `json:"type"`
	Binding         *Binding        `json:"binding,omitempty"`
	Audience        string          `json:"audience,omitempty"`
	Credential      string          `json:"credential,omitempty"`
	RequestID       string          `json:"request_id,omitempty"`
	Payload         json.RawMessage `json:"payload,omitempty"`
	Reason          string          `json:"reason,omitempty"`
}

// NativeSessionCredentialRequest has deliberately no binding, bearer, or
// audience fields. The root-owned identity authority supplies all of them from
// its already authenticated durable state.
type NativeSessionCredentialRequest struct {
	ContractVersion string `json:"contract_version"`
	Type            string `json:"type"`
}

type NativeSessionLocalError struct {
	Reason    string `json:"reason"`
	Temporary bool   `json:"temporary"`
	Uncertain bool   `json:"uncertain"`
}

type NativeSessionCredentialResponse struct {
	ContractVersion string                   `json:"contract_version"`
	Type            string                   `json:"type"`
	Result          *GuestSessionIssueResult `json:"result,omitempty"`
	Error           *NativeSessionLocalError `json:"error,omitempty"`
}

func ValidateNativeSessionMessage(value NativeSessionMessage) error {
	if value.ContractVersion != NativeSessionVersion {
		return errors.New("native session frame is invalid")
	}
	noPayload := len(value.Payload) == 0
	switch value.Type {
	case NativeSessionHello:
		if value.Binding == nil || ValidateBinding(*value.Binding) != nil || value.Audience != NativeGuestControlAudience ||
			validateGuestSessionCredential(value.Credential) != nil || value.RequestID != "" || !noPayload || value.Reason != "" {
			return errors.New("native session hello is invalid")
		}
	case NativeSessionHelloAck:
		if value.Binding == nil || ValidateBinding(*value.Binding) != nil || value.Audience != NativeGuestControlAudience ||
			value.Credential != "" || value.RequestID != "" || !noPayload || value.Reason != "" {
			return errors.New("native session acknowledgement is invalid")
		}
	case NativeSessionHelloReject:
		if value.Binding != nil || value.Audience != "" || value.Credential != "" || value.RequestID != "" || !noPayload ||
			!nativeSessionReasonPattern.MatchString(value.Reason) {
			return errors.New("native session rejection is invalid")
		}
	case NativeSessionAgentdRequest, NativeSessionAgentdResponse:
		if value.Binding != nil || value.Audience != "" || value.Credential != "" ||
			!nativeSessionRequestIDPattern.MatchString(value.RequestID) || validateNativeSessionPayload(value.Payload) != nil || value.Reason != "" {
			return errors.New("native session relay frame is invalid")
		}
	case NativeSessionPing, NativeSessionPong:
		if value.Binding != nil || value.Audience != "" || value.Credential != "" || value.RequestID != "" || !noPayload || value.Reason != "" {
			return errors.New("native session control frame is invalid")
		}
	default:
		return errors.New("native session frame type is invalid")
	}
	return nil
}

func EncodeNativeSessionMessage(value NativeSessionMessage) ([]byte, error) {
	if ValidateNativeSessionMessage(value) != nil {
		return nil, errors.New("native session frame is invalid")
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded)+1 > MaxNativeSessionFrameBytes {
		return nil, errors.New("native session frame is invalid")
	}
	return append(encoded, '\n'), nil
}

func DecodeNativeSessionMessage(data []byte) (NativeSessionMessage, error) {
	var value NativeSessionMessage
	if DecodeStrictJSON(data, MaxNativeSessionFrameBytes, &value) != nil || ValidateNativeSessionMessage(value) != nil {
		return NativeSessionMessage{}, errors.New("native session frame is invalid")
	}
	return value, nil
}

func ValidateNativeSessionCredentialRequest(value NativeSessionCredentialRequest) error {
	if value.ContractVersion != NativeSessionLocalVersion || value.Type != NativeSessionCredentialIssue {
		return errors.New("native session credential request is invalid")
	}
	return nil
}

func EncodeNativeSessionCredentialRequest(value NativeSessionCredentialRequest) ([]byte, error) {
	if ValidateNativeSessionCredentialRequest(value) != nil {
		return nil, errors.New("native session credential request is invalid")
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded)+1 > MaxNativeSessionLocalMessageBytes {
		return nil, errors.New("native session credential request is invalid")
	}
	return append(encoded, '\n'), nil
}

func DecodeNativeSessionCredentialRequest(data []byte) (NativeSessionCredentialRequest, error) {
	var value NativeSessionCredentialRequest
	if DecodeStrictJSON(data, MaxNativeSessionLocalMessageBytes, &value) != nil || ValidateNativeSessionCredentialRequest(value) != nil {
		return NativeSessionCredentialRequest{}, errors.New("native session credential request is invalid")
	}
	return value, nil
}

func ValidateNativeSessionCredentialResponse(value NativeSessionCredentialResponse) error {
	if value.ContractVersion != NativeSessionLocalVersion {
		return errors.New("native session credential response is invalid")
	}
	switch value.Type {
	case NativeSessionCredentialResult:
		if value.Result == nil || value.Error != nil || ValidateGuestSessionIssueResult(*value.Result) != nil {
			return errors.New("native session credential response is invalid")
		}
	case NativeSessionCredentialError:
		if value.Result != nil || value.Error == nil || !nativeSessionReasonPattern.MatchString(value.Error.Reason) {
			return errors.New("native session credential response is invalid")
		}
	default:
		return errors.New("native session credential response is invalid")
	}
	return nil
}

func EncodeNativeSessionCredentialResponse(value NativeSessionCredentialResponse) ([]byte, error) {
	if ValidateNativeSessionCredentialResponse(value) != nil {
		return nil, errors.New("native session credential response is invalid")
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded)+1 > MaxNativeSessionLocalMessageBytes {
		return nil, errors.New("native session credential response is invalid")
	}
	return append(encoded, '\n'), nil
}

func DecodeNativeSessionCredentialResponse(data []byte) (NativeSessionCredentialResponse, error) {
	var value NativeSessionCredentialResponse
	if DecodeStrictJSON(data, MaxNativeSessionLocalMessageBytes, &value) != nil || ValidateNativeSessionCredentialResponse(value) != nil {
		return NativeSessionCredentialResponse{}, errors.New("native session credential response is invalid")
	}
	return value, nil
}

func validateNativeSessionPayload(value json.RawMessage) error {
	if len(value) == 0 || len(value) > MaxNativeSessionAgentdPayloadBytes {
		return errors.New("native session payload is invalid")
	}
	var object map[string]json.RawMessage
	if DecodeStrictJSON(value, MaxNativeSessionAgentdPayloadBytes, &object) != nil || object == nil || len(object) == 0 {
		return errors.New("native session payload is invalid")
	}
	return nil
}

func (NativeSessionMessage) String() string   { return "[sensitive native session frame]" }
func (NativeSessionMessage) GoString() string { return "[sensitive native session frame]" }
func (NativeSessionCredentialResponse) String() string {
	return "[sensitive native session credential response]"
}
func (NativeSessionCredentialResponse) GoString() string {
	return "[sensitive native session credential response]"
}
