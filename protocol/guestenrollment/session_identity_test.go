package guestenrollment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestGuestSessionIdentityContractStrictValidationAndRedaction(t *testing.T) {
	binding := validBinding()
	credential, err := generateGuestSessionCredential(bytes.NewReader(bytes.Repeat([]byte{0x71}, GuestSessionCredentialBytes)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	issue := GuestSessionIssueRequest{
		ContractVersion: GuestSessionIdentityVersion,
		Binding:         binding,
		Audience:        NativeGuestControlAudience,
	}
	result := GuestSessionIssueResult{
		ContractVersion: GuestSessionIdentityVersion,
		Binding:         binding,
		Credential: GuestSessionCredential{
			Type: GuestSessionCredentialType, Opaque: credential, Audience: NativeGuestControlAudience,
			IssuedAt: FormatTimestamp(now), ExpiresAt: FormatTimestamp(now.Add(MaxGuestSessionCredentialLifetime)),
		},
	}
	authenticate := GuestSessionAuthenticateRequest{
		ContractVersion: GuestSessionIdentityVersion,
		Binding:         binding,
		Audience:        NativeGuestControlAudience,
	}
	status := GuestSessionStatus{
		ContractVersion: GuestSessionIdentityVersion,
		CredentialType:  GuestSessionCredentialType,
		Binding:         binding,
		Audience:        NativeGuestControlAudience,
		IssuedAt:        result.Credential.IssuedAt,
		ExpiresAt:       result.Credential.ExpiresAt,
	}

	issueJSON, _ := json.Marshal(issue)
	resultJSON, _ := json.Marshal(result)
	authJSON, _ := json.Marshal(authenticate)
	statusJSON, _ := json.Marshal(status)
	if _, err := DecodeGuestSessionIssueRequest(issueJSON); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeGuestSessionIssueResult(resultJSON); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeGuestSessionAuthenticateRequest(authJSON); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeGuestSessionStatus(statusJSON); err != nil {
		t.Fatal(err)
	}

	for _, input := range [][]byte{
		[]byte(`{"contract_version":"nvt.guest-session-identity/v1","binding":{},"audience":"nvt.native-guest-control/v1","audience":"nvt.native-guest-control/v1"}`),
		[]byte(`{"contract_version":"nvt.guest-session-identity/v1","binding":{},"audience":"arbitrary"}`),
		append(issueJSON, 0xff),
		append(issueJSON, bytes.Repeat([]byte{' '}, MaxGuestSessionIssueRequestBytes)...),
	} {
		if _, err := DecodeGuestSessionIssueRequest(input); err == nil {
			t.Fatalf("accepted invalid issue request %q", input)
		}
	}
	if _, err := DecodeGuestSessionAuthenticateRequest([]byte(`{"contract_version":"nvt.guest-session-identity/v1","binding":{"agent_run_uid":"uid","execution_id":"execution","driver_registration":"driver","desired_generation":1,"guest_instance_id":"guest"},"audience":"nvt.native-guest-control/v2"}`)); err == nil {
		t.Fatal("accepted caller-selected audience")
	}
	if ValidateGuestSessionIssueResult(GuestSessionIssueResult{
		ContractVersion: result.ContractVersion,
		Binding:         result.Binding,
		Credential: GuestSessionCredential{
			Type: GuestSessionCredentialType, Opaque: credential, Audience: NativeGuestControlAudience,
			IssuedAt:  result.Credential.IssuedAt,
			ExpiresAt: FormatTimestamp(now.Add(MaxGuestSessionCredentialLifetime + time.Second)),
		},
	}) == nil {
		t.Fatal("accepted overlong credential lifetime")
	}
	for _, formatted := range []string{fmt.Sprint(result), fmt.Sprintf("%+v", result), fmt.Sprintf("%#v", result), fmt.Sprint(result.Credential)} {
		if strings.Contains(formatted, credential) || !strings.Contains(formatted, "sensitive") {
			t.Fatalf("unsafe formatting %q", formatted)
		}
	}
	if digest, err := GuestSessionCredentialDigest(credential); err != nil || ValidateRuntimeIdentityDigest(digest) != nil || strings.Contains(digest, credential) {
		t.Fatalf("invalid digest %q: %v", digest, err)
	}
}

func TestGenerateGuestSessionCredentialUsesCanonicalRandomShape(t *testing.T) {
	credential, err := GenerateGuestSessionCredential()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GuestSessionCredentialDigest(credential); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", credential + "=", opaqueValue(GuestSessionCredentialBytes-1, 0x72)} {
		if _, err := GuestSessionCredentialDigest(invalid); err == nil {
			t.Fatalf("accepted invalid credential %q", invalid)
		}
	}
	if MaxLiveGuestSessionsPerBinding != 2 || MaxGuestSessionCredentialLifetime > 5*time.Minute {
		t.Fatalf("unsafe session bounds: live=%d lifetime=%s", MaxLiveGuestSessionsPerBinding, MaxGuestSessionCredentialLifetime)
	}
}
