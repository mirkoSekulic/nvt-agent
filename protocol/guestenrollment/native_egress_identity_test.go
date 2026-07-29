package guestenrollment

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestNativeEgressIdentityContractStrictPurposeValidationAndRedaction(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	binding := validBinding()
	credential, err := generateNativeEgressCredential(9, bytes.NewReader(bytes.Repeat([]byte{0x91}, NativeEgressCredentialRandomBytes)))
	if err != nil {
		t.Fatal(err)
	}
	issue := NativeEgressIssueRequest{ContractVersion: NativeEgressIdentityVersion, Binding: binding, Audience: NativeEgressAudience}
	result := NativeEgressIssueResult{
		ContractVersion: NativeEgressIdentityVersion,
		Binding:         binding,
		Credential: NativeEgressCredential{
			Type: NativeEgressCredentialType, Opaque: credential, Audience: NativeEgressAudience,
			IssuedAt: FormatTimestamp(now), ExpiresAt: FormatTimestamp(now.Add(MaxNativeEgressCredentialLifetime)),
		},
	}
	authenticate := NativeEgressAuthenticateRequest{ContractVersion: NativeEgressIdentityVersion, Binding: binding, Audience: NativeEgressAudience}
	status := NativeEgressStatus{
		ContractVersion: NativeEgressIdentityVersion, CredentialType: NativeEgressCredentialType,
		Binding: binding, Audience: NativeEgressAudience, Sequence: 9,
		IssuedAt: result.Credential.IssuedAt, ExpiresAt: result.Credential.ExpiresAt,
	}
	revokeBinding := NativeEgressRevokeBindingRequest{ContractVersion: NativeEgressIdentityVersion, Binding: binding}
	revokeExecution := NativeEgressRevokeExecutionRequest{ContractVersion: NativeEgressIdentityVersion, ExecutionScope: binding.ExecutionScope()}

	for name, testCase := range map[string]struct {
		value  any
		decode func([]byte) error
	}{
		"issue":            {issue, func(data []byte) error { _, err := DecodeNativeEgressIssueRequest(data); return err }},
		"result":           {result, func(data []byte) error { _, err := DecodeNativeEgressIssueResult(data); return err }},
		"authenticate":     {authenticate, func(data []byte) error { _, err := DecodeNativeEgressAuthenticateRequest(data); return err }},
		"status":           {status, func(data []byte) error { _, err := DecodeNativeEgressStatus(data); return err }},
		"binding revoke":   {revokeBinding, func(data []byte) error { _, err := DecodeNativeEgressRevokeBindingRequest(data); return err }},
		"execution revoke": {revokeExecution, func(data []byte) error { _, err := DecodeNativeEgressRevokeExecutionRequest(data); return err }},
	} {
		encoded, err := json.Marshal(testCase.value)
		if err != nil || testCase.decode(encoded) != nil {
			t.Fatalf("valid %s was rejected: %v", name, err)
		}
	}

	wrongPurpose, _ := json.Marshal(GuestSessionIssueRequest{ContractVersion: GuestSessionIdentityVersion, Binding: binding, Audience: NativeGuestControlAudience})
	if _, err := DecodeNativeEgressIssueRequest(wrongPurpose); err == nil {
		t.Fatal("native control purpose was accepted as native egress")
	}
	controlCredential, err := generateGuestSessionCredential(9, bytes.NewReader(bytes.Repeat([]byte{0x91}, GuestSessionCredentialRandomBytes)))
	if err != nil {
		t.Fatal(err)
	}
	if ValidateNativeEgressCredential(controlCredential) == nil || ValidateGuestSessionCredential(credential) == nil {
		t.Fatal("credential wire forms crossed purpose boundaries")
	}
	for _, invalid := range [][]byte{
		[]byte(`{"contract_version":"nvt.native-egress-identity/v1","binding":{},"audience":"nvt.native-egress/v1","audience":"nvt.native-egress/v1"}`),
		[]byte(`{"contract_version":"nvt.native-egress-identity/v1","binding":{},"audience":"arbitrary"}`),
		[]byte(`{"contract_version":"nvt.native-egress-identity/v1","binding":{},"audience":"nvt.native-egress/v1","token":"forbidden"}`),
		append(bytes.Repeat([]byte{' '}, MaxNativeEgressIdentityRequestBytes), 'x'),
	} {
		if _, err := DecodeNativeEgressIssueRequest(invalid); err == nil {
			t.Fatalf("invalid issue input accepted: %q", invalid)
		}
	}
	for _, formatted := range []string{fmt.Sprint(result), fmt.Sprintf("%+v", result), fmt.Sprintf("%#v", result), fmt.Sprint(result.Credential)} {
		if strings.Contains(formatted, credential) || !strings.Contains(formatted, "sensitive") {
			t.Fatalf("unsafe formatting %q", formatted)
		}
	}
	for _, formatted := range []string{fmt.Sprint(issue), fmt.Sprintf("%#v", authenticate), fmt.Sprintf("%+v", status), fmt.Sprint(revokeBinding), fmt.Sprint(revokeExecution)} {
		if strings.Contains(formatted, binding.AgentRunUID) || strings.Contains(formatted, binding.GuestInstanceID) {
			t.Fatalf("ordinary formatting exposed binding: %q", formatted)
		}
	}
	if digest, err := NativeEgressCredentialDigest(credential); err != nil || ValidateRuntimeIdentityDigest(digest) != nil || strings.Contains(digest, credential) {
		t.Fatalf("invalid digest %q: %v", digest, err)
	}
}

func TestNativeEgressCredentialCanonicalSequenceAndBounds(t *testing.T) {
	t.Parallel()
	credential, err := GenerateNativeEgressCredential(42)
	if err != nil {
		t.Fatal(err)
	}
	if sequence, err := NativeEgressCredentialSequence(credential); err != nil || sequence != 42 {
		t.Fatalf("sequence=%d error=%v", sequence, err)
	}
	encoded := strings.TrimPrefix(credential, NativeEgressCredentialPrefix)
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != NativeEgressCredentialBytes || binary.BigEndian.Uint64(decoded[:8]) != 42 {
		t.Fatalf("credential shape length=%d error=%v", len(decoded), err)
	}
	for _, sequence := range []uint64{0, MaxGuestSessionIssuanceSequence + 1} {
		if _, err := generateNativeEgressCredential(sequence, bytes.NewReader(bytes.Repeat([]byte{1}, NativeEgressCredentialRandomBytes))); err == nil {
			t.Fatalf("invalid sequence %d accepted", sequence)
		}
	}
	if _, err := generateNativeEgressCredential(1, bytes.NewReader(bytes.Repeat([]byte{1}, NativeEgressCredentialRandomBytes-1))); err == nil {
		t.Fatal("short random source accepted")
	}
	for _, invalid := range []string{"", strings.TrimPrefix(credential, NativeEgressCredentialPrefix), credential + "=", NativeEgressCredentialPrefix + "!!!!"} {
		if ValidateNativeEgressCredential(invalid) == nil {
			t.Fatalf("invalid credential accepted: %q", invalid)
		}
	}
	if MaxLiveNativeEgressCredentials != 2 || MaxNativeEgressCredentialLifetime > 5*time.Minute ||
		MaxConcurrentNativeEgressIdentityOps != 64 || MaxNativeEgressIdentityOperationTime > 30*time.Second {
		t.Fatalf("unsafe identity bounds live=%d lifetime=%s concurrency=%d operation=%s",
			MaxLiveNativeEgressCredentials, MaxNativeEgressCredentialLifetime, MaxConcurrentNativeEgressIdentityOps, MaxNativeEgressIdentityOperationTime)
	}
}

func TestNativeEgressIdentityRejectsOverlongWindowAndSequenceMismatch(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	credential, err := generateNativeEgressCredential(3, bytes.NewReader(bytes.Repeat([]byte{3}, NativeEgressCredentialRandomBytes)))
	if err != nil {
		t.Fatal(err)
	}
	result := NativeEgressIssueResult{
		ContractVersion: NativeEgressIdentityVersion, Binding: validBinding(),
		Credential: NativeEgressCredential{
			Type: NativeEgressCredentialType, Opaque: credential, Audience: NativeEgressAudience,
			IssuedAt: FormatTimestamp(now), ExpiresAt: FormatTimestamp(now.Add(MaxNativeEgressCredentialLifetime + time.Second)),
		},
	}
	if ValidateNativeEgressIssueResult(result) == nil {
		t.Fatal("overlong egress credential accepted")
	}
	status := NativeEgressStatus{
		ContractVersion: NativeEgressIdentityVersion, CredentialType: NativeEgressCredentialType,
		Binding: validBinding(), Audience: NativeEgressAudience, Sequence: 0,
		IssuedAt: FormatTimestamp(now), ExpiresAt: FormatTimestamp(now.Add(time.Minute)),
	}
	if ValidateNativeEgressStatus(status) == nil {
		t.Fatal("zero sequence status accepted")
	}
}
