package guestenrollment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestNativeSessionTransportFramesAreStrictAndRedacted(t *testing.T) {
	binding := validBinding()
	credential, err := generateGuestSessionCredential(1, bytes.NewReader(bytes.Repeat([]byte{0x72}, GuestSessionCredentialRandomBytes)))
	if err != nil {
		t.Fatal(err)
	}
	hello := NativeSessionMessage{
		ContractVersion: NativeSessionVersion, Type: NativeSessionHello,
		Binding: &binding, Audience: NativeGuestControlAudience, Credential: credential,
	}
	encoded, err := EncodeNativeSessionMessage(hello)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeNativeSessionMessage(encoded)
	if err != nil || decoded.Binding == nil || *decoded.Binding != binding {
		t.Fatalf("decode hello = %#v, %v", decoded, err)
	}
	for _, formatted := range []string{fmt.Sprint(decoded), fmt.Sprintf("%+v", decoded), fmt.Sprintf("%#v", decoded)} {
		if strings.Contains(formatted, credential) || !strings.Contains(formatted, "sensitive") {
			t.Fatalf("unsafe native-session formatting %q", formatted)
		}
	}

	payload := json.RawMessage(`{"type":"health"}`)
	for _, value := range []NativeSessionMessage{
		{ContractVersion: NativeSessionVersion, Type: NativeSessionHelloAck, Binding: &binding, Audience: NativeGuestControlAudience},
		{ContractVersion: NativeSessionVersion, Type: NativeSessionHelloReject, Reason: "unauthorized"},
		{ContractVersion: NativeSessionVersion, Type: NativeSessionAgentdRequest, RequestID: "request-1", Payload: payload},
		{ContractVersion: NativeSessionVersion, Type: NativeSessionAgentdResponse, RequestID: "request-1", Payload: json.RawMessage(`{"ok":true}`)},
		{ContractVersion: NativeSessionVersion, Type: NativeSessionPing},
		{ContractVersion: NativeSessionVersion, Type: NativeSessionPong},
	} {
		encoded, encodeErr := EncodeNativeSessionMessage(value)
		if encodeErr != nil {
			t.Fatalf("encode %s: %v", value.Type, encodeErr)
		}
		if _, decodeErr := DecodeNativeSessionMessage(encoded); decodeErr != nil {
			t.Fatalf("decode %s: %v", value.Type, decodeErr)
		}
	}

	for _, input := range [][]byte{
		[]byte(`{"contract_version":"nvt.native-session/v1","type":"ping","type":"pong"}`),
		[]byte(`{"contract_version":"nvt.native-session/v1","type":"agentd_request","request_id":"request-1","payload":{"type":"health","type":"prompt"}}`),
		append(encoded, 0xff),
		bytes.Repeat([]byte{'x'}, MaxNativeSessionFrameBytes+1),
	} {
		if _, err := DecodeNativeSessionMessage(input); err == nil {
			t.Fatalf("accepted malformed native-session frame %q", input)
		}
	}
	invalidHello := hello
	invalidHello.Audience = "caller-selected"
	if _, err := EncodeNativeSessionMessage(invalidHello); err == nil {
		t.Fatal("accepted caller-selected native-session audience")
	}
}

func TestNativeSessionLocalCredentialProtocolIsExact(t *testing.T) {
	request := NativeSessionCredentialRequest{ContractVersion: NativeSessionLocalVersion, Type: NativeSessionCredentialIssue}
	encodedRequest, err := EncodeNativeSessionCredentialRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeNativeSessionCredentialRequest(encodedRequest); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeNativeSessionCredentialRequest([]byte(`{"contract_version":"nvt.native-session-local/v1","type":"issue_guest_session","binding":{}}`)); err == nil {
		t.Fatal("local caller selected a binding")
	}

	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	binding := validBinding()
	credential, _ := generateGuestSessionCredential(2, bytes.NewReader(bytes.Repeat([]byte{0x73}, GuestSessionCredentialRandomBytes)))
	response := NativeSessionCredentialResponse{
		ContractVersion: NativeSessionLocalVersion, Type: NativeSessionCredentialResult,
		Result: &GuestSessionIssueResult{
			ContractVersion: GuestSessionIdentityVersion, Binding: binding,
			Credential: GuestSessionCredential{
				Type: GuestSessionCredentialType, Opaque: credential, Audience: NativeGuestControlAudience,
				IssuedAt: FormatTimestamp(now), ExpiresAt: FormatTimestamp(now.Add(MaxGuestSessionCredentialLifetime)),
			},
		},
	}
	encodedResponse, err := EncodeNativeSessionCredentialResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeNativeSessionCredentialResponse(encodedResponse)
	if err != nil || decoded.Result == nil || decoded.Result.Binding != binding {
		t.Fatalf("decode response = %#v, %v", decoded, err)
	}
	if strings.Contains(fmt.Sprintf("%#v", decoded), credential) {
		t.Fatal("local response formatting disclosed a credential")
	}
	errorResponse := NativeSessionCredentialResponse{
		ContractVersion: NativeSessionLocalVersion, Type: NativeSessionCredentialError,
		Error: &NativeSessionLocalError{Reason: "broker-unavailable", Temporary: true, Uncertain: true},
	}
	if encoded, err := EncodeNativeSessionCredentialResponse(errorResponse); err != nil {
		t.Fatal(err)
	} else if _, err := DecodeNativeSessionCredentialResponse(encoded); err != nil {
		t.Fatal(err)
	}
}
