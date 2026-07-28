package guestenrollment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestRuntimeIdentityContractStrictValidationAndRedaction(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	binding := validBinding()
	identity, err := generateRuntimeIdentity(bytes.NewReader(bytes.Repeat([]byte{0x41}, RuntimeIdentityBytes)))
	if err != nil {
		t.Fatal(err)
	}
	successor, err := generateRuntimeIdentity(bytes.NewReader(bytes.Repeat([]byte{0x42}, RuntimeIdentityBytes)))
	if err != nil {
		t.Fatal(err)
	}
	statusRequest := RuntimeIdentityStatusRequest{ContractVersion: RuntimeIdentityVersion, Binding: binding}
	rotateRequest := RuntimeIdentityRotateRequest{ContractVersion: RuntimeIdentityVersion, Binding: binding, Successor: successor}
	status := RuntimeIdentityStatus{
		ContractVersion: RuntimeIdentityVersion,
		IdentityType:    RuntimeIdentityType,
		Binding:         binding,
		IssuedAt:        FormatTimestamp(now),
		ExpiresAt:       FormatTimestamp(now.Add(time.Hour)),
	}

	statusRequestJSON, _ := json.Marshal(statusRequest)
	rotateRequestJSON, _ := json.Marshal(rotateRequest)
	statusJSON, _ := json.Marshal(status)
	if _, err := DecodeRuntimeIdentityStatusRequest(statusRequestJSON); err != nil {
		t.Fatalf("decode status request: %v", err)
	}
	if _, err := DecodeRuntimeIdentityRotateRequest(rotateRequestJSON); err != nil {
		t.Fatalf("decode rotate request: %v", err)
	}
	if _, err := DecodeRuntimeIdentityStatus(statusJSON); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if _, err := DecodeRuntimeIdentityStatusRequest(append(statusRequestJSON, bytes.Repeat([]byte{' '}, MaxRuntimeIdentityStatusRequestBytes)...)); err == nil {
		t.Fatal("oversized status request was accepted")
	}
	if _, err := DecodeRuntimeIdentityRotateRequest(append(rotateRequestJSON, bytes.Repeat([]byte{' '}, MaxRuntimeIdentityRotateRequestBytes)...)); err == nil {
		t.Fatal("oversized rotation request was accepted")
	}
	if digest, err := RuntimeIdentityDigest(identity); err != nil || ValidateRuntimeIdentityDigest(digest) != nil || strings.Contains(digest, identity) {
		t.Fatalf("runtime identity digest: %q, %v", digest, err)
	}
	formatted := fmt.Sprintf("%v %#v", rotateRequest, rotateRequest)
	if !strings.Contains(formatted, "sensitive") || strings.Contains(formatted, successor) {
		t.Fatal("rotation formatting disclosed the successor")
	}

	invalid := [][]byte{
		[]byte(`{"contract_version":"nvt.guest-runtime-identity/v1","binding":{},"successor":"` + successor + `","successor":"` + identity + `"}`),
		[]byte(`{"contract_version":"nvt.guest-runtime-identity/v1","binding":{"agent_run_uid":"uid","execution_id":"execution","driver_registration":"driver","desired_generation":1,"guest_instance_id":"guest"},"successor":"short"}`),
		append([]byte(`{"contract_version":"nvt.guest-runtime-identity/v1","binding":{"agent_run_uid":"uid","execution_id":"execution","driver_registration":"driver","desired_generation":1,"guest_instance_id":"`), 0xff),
	}
	for index, input := range invalid {
		if _, err := DecodeRuntimeIdentityRotateRequest(input); err == nil {
			t.Fatalf("invalid rotation %d was accepted", index)
		}
	}
	if _, err := DecodeRuntimeIdentityStatus([]byte(`{"contract_version":"nvt.guest-runtime-identity/v1","identity_type":"nvt.runtime-identity/v1","binding":{"agent_run_uid":"uid","execution_id":"execution","driver_registration":"driver","desired_generation":1,"guest_instance_id":"guest"},"issued_at":"2026-07-28T12:00:00Z","expires_at":"2026-07-29T12:00:01Z"}`)); err == nil {
		t.Fatal("overlong runtime identity window was accepted")
	}
}

func TestGenerateRuntimeIdentityUsesCanonicalRandomShape(t *testing.T) {
	t.Parallel()
	identity, err := GenerateRuntimeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RuntimeIdentityDigest(identity); err != nil {
		t.Fatalf("generated runtime identity is invalid: %v", err)
	}
	if _, err := RuntimeIdentityDigest(identity + "="); err == nil {
		t.Fatal("non-canonical runtime identity was accepted")
	}
}
