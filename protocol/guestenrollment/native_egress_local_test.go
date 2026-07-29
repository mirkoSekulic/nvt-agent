package guestenrollment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestNativeEgressLocalCredentialBoundaryIsFixedStrictAndRedacted(t *testing.T) {
	request := NativeEgressCredentialRequest{
		ContractVersion: NativeEgressLocalVersion,
		Type:            NativeEgressCredentialIssue,
	}
	encoded, err := EncodeNativeEgressCredentialRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, []byte(`{"contract_version":"nvt.native-egress-local/v1","type":"issue_native_egress"}`+"\n")) {
		t.Fatalf("unexpected local request: %s", encoded)
	}
	if _, err := DecodeNativeEgressCredentialRequest(encoded); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{
		[]byte(`{"contract_version":"nvt.native-egress-local/v1","type":"issue_native_egress","binding":{}}`),
		[]byte(`{"contract_version":"nvt.native-egress-local/v1","type":"issue_native_egress","audience":"nvt.native-egress/v1"}`),
		[]byte(`{"contract_version":"nvt.native-egress-local/v1","contract_version":"nvt.native-egress-local/v1","type":"issue_native_egress"}`),
		append(append([]byte(nil), encoded...), encoded...),
		append(bytes.Repeat([]byte{' '}, MaxNativeEgressLocalMessageBytes), 'x'),
	} {
		if _, err := DecodeNativeEgressCredentialRequest(invalid); err == nil {
			t.Fatalf("invalid local request accepted: %q", invalid)
		}
	}

	binding := validBinding()
	credential, err := GenerateNativeEgressCredential(7)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	result := NativeEgressIssueResult{
		ContractVersion: NativeEgressIdentityVersion,
		Binding:         binding,
		Credential: NativeEgressCredential{
			Type: NativeEgressCredentialType, Opaque: credential, Audience: NativeEgressAudience,
			IssuedAt: FormatTimestamp(now), ExpiresAt: FormatTimestamp(now.Add(MaxNativeEgressCredentialLifetime)),
		},
	}
	response := NativeEgressCredentialResponse{
		ContractVersion: NativeEgressLocalVersion,
		Type:            NativeEgressCredentialResult,
		Result:          &result,
	}
	encodedResponse, err := EncodeNativeEgressCredentialResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeNativeEgressCredentialResponse(encodedResponse)
	if err != nil || decoded.Result == nil || decoded.Result.Credential.Opaque != credential {
		t.Fatalf("local response failed: %#v %v", decoded, err)
	}
	if strings.Contains(fmt.Sprintf("%#v", response), credential) || strings.Contains(fmt.Sprintf("%#v", request), credential) {
		t.Fatal("local credential formatting disclosed the bearer")
	}

	errorResponse := NativeEgressCredentialResponse{
		ContractVersion: NativeEgressLocalVersion,
		Type:            NativeEgressCredentialError,
		Error:           &NativeEgressLocalError{Reason: "broker-unavailable", Temporary: true, Uncertain: true},
	}
	encodedError, err := EncodeNativeEgressCredentialResponse(errorResponse)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if _, err := DecodeNativeEgressCredentialResponse(encodedError); err != nil || json.Unmarshal(encodedError, &raw) != nil {
		t.Fatal("valid bounded local error was rejected")
	}
}
