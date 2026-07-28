package guestenrollment

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestContractValidationAndStrictDecoding(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	binding := validBinding()
	token := opaqueValue(TokenBytes, 0x21)
	identity := opaqueValue(TokenBytes, 0x42)

	issue := IssueRequest{ContractVersion: Version, Binding: binding, TTLSeconds: 300}
	envelope := BootstrapEnvelope{
		ContractVersion: Version, Binding: binding, ExchangeURL: "https://enrollment.nvt-system.svc/v1/exchange", Token: token,
		IssuedAt: FormatTimestamp(now), ExpiresAt: FormatTimestamp(now.Add(5 * time.Minute)),
	}
	exchange := ExchangeRequest{ContractVersion: Version, Binding: binding, Token: token}
	result := ExchangeResult{
		ContractVersion: Version, Binding: binding,
		RuntimeIdentity: RuntimeIdentity{Type: RuntimeIdentityType, Opaque: identity, IssuedAt: FormatTimestamp(now), ExpiresAt: FormatTimestamp(now.Add(time.Hour))},
	}
	revokeBinding := RevokeBindingRequest{ContractVersion: Version, Binding: binding}
	revokeExecution := RevokeExecutionRequest{ContractVersion: Version, ExecutionScope: binding.ExecutionScope()}
	completeCleanup := CompleteExecutionCleanupRequest{ContractVersion: Version, ExecutionScope: binding.ExecutionScope()}

	for name, validation := range map[string]func() error{
		"issue":            func() error { return ValidateIssueRequest(issue) },
		"envelope":         func() error { return ValidateBootstrapEnvelope(envelope) },
		"exchange":         func() error { return ValidateExchangeRequest(exchange) },
		"result":           func() error { return ValidateExchangeResult(result) },
		"revoke binding":   func() error { return ValidateRevokeBindingRequest(revokeBinding) },
		"revoke execution": func() error { return ValidateRevokeExecutionRequest(revokeExecution) },
		"complete cleanup": func() error { return ValidateCompleteExecutionCleanupRequest(completeCleanup) },
	} {
		if err := validation(); err != nil {
			t.Fatalf("valid %s: %v", name, err)
		}
	}

	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeBootstrapEnvelope(encoded)
	if err != nil || decoded.Token != token || decoded.Binding != binding {
		t.Fatalf("decode valid envelope: %#v, %v", decoded, err)
	}
	issueJSON, _ := json.Marshal(issue)
	exchangeJSON, _ := json.Marshal(exchange)
	resultJSON, _ := json.Marshal(result)
	revokeBindingJSON, _ := json.Marshal(revokeBinding)
	revokeExecutionJSON, _ := json.Marshal(revokeExecution)
	completeCleanupJSON, _ := json.Marshal(completeCleanup)
	if _, err := DecodeIssueRequest(issueJSON); err != nil {
		t.Fatalf("decode issue: %v", err)
	}
	if _, err := DecodeExchangeRequest(exchangeJSON); err != nil {
		t.Fatalf("decode exchange: %v", err)
	}
	if _, err := DecodeExchangeResult(resultJSON); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if _, err := DecodeRevokeBindingRequest(revokeBindingJSON); err != nil {
		t.Fatalf("decode binding revoke: %v", err)
	}
	if _, err := DecodeRevokeExecutionRequest(revokeExecutionJSON); err != nil {
		t.Fatalf("decode execution revoke: %v", err)
	}
	if _, err := DecodeCompleteExecutionCleanupRequest(completeCleanupJSON); err != nil {
		t.Fatalf("decode cleanup completion: %v", err)
	}
	if _, err := DecodeCompleteExecutionCleanupRequest([]byte(`{"contract_version":"nvt.guest-enrollment/v1","execution_scope":{"agent_run_uid":"uid","execution_id":"execution","driver_registration":"driver"},"token":"forbidden"}`)); err == nil {
		t.Fatal("credential-bearing cleanup completion request was accepted")
	}
	if _, err := DecodeRevokeExecutionRequest([]byte(`{"contract_version":"nvt.guest-enrollment/v1","execution_scope":{"agent_run_uid":"uid","execution_id":"execution","driver_registration":"driver"},"token":"forbidden"}`)); err == nil {
		t.Fatal("credential-bearing execution revocation request was accepted")
	}

	invalid := [][]byte{
		{},
		append([]byte(`{"contract_version":"`+Version+`","binding":{"agent_run_uid":"uid-1","agent_run_uid":"uid-2"}}`), '\n'),
		append([]byte(`{"contract_version":"`+Version+`","binding":{"agent_run_uid":"uid-1","nested":{"key":1,"k\u0065y":2}}}`), '\n'),
		append([]byte(`{"contract_version":"`+Version+`","unknown":true}`), '\n'),
		append([]byte(`{"contract_version":"`+Version+`"} {}`), '\n'),
		{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'},
		bytes.Repeat([]byte{' '}, MaxBootstrapEnvelopeBytes+1),
	}
	for index, data := range invalid {
		if _, err := DecodeBootstrapEnvelope(data); err == nil {
			t.Fatalf("invalid envelope %d was accepted", index)
		}
	}
}

func TestSensitiveHandoffContractIsSeparateStrictAndRedacted(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	binding := validBinding()
	prepare := HandoffPrepareRequest{ContractVersion: HandoffVersion, ExecutionScope: binding.ExecutionScope(), DesiredGeneration: binding.DesiredGeneration}
	prepared := HandoffPrepareResult{ContractVersion: HandoffVersion, GuestInstanceID: binding.GuestInstanceID, State: HandoffStatePrepared, NewlyPrepared: true}
	replace := HandoffReplaceRequest{ContractVersion: HandoffVersion, Binding: binding}
	deliver := HandoffDeliverRequest{ContractVersion: HandoffVersion, Envelope: BootstrapEnvelope{
		ContractVersion: Version, Binding: binding, ExchangeURL: "https://issuer.example/v1/guest-enrollment/exchange",
		Token: opaqueValue(TokenBytes, 0x66), IssuedAt: FormatTimestamp(now), ExpiresAt: FormatTimestamp(now.Add(time.Minute)),
	}}
	ack := HandoffAcknowledgement{ContractVersion: HandoffVersion}
	for name, value := range map[string]any{"prepare": prepare, "prepared": prepared, "replace": replace, "deliver": deliver, "ack": ack} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		switch name {
		case "prepare":
			_, err = DecodeHandoffPrepareRequest(encoded)
		case "prepared":
			_, err = DecodeHandoffPrepareResult(encoded)
		case "replace":
			_, err = DecodeHandoffReplaceRequest(encoded)
		case "deliver":
			_, err = DecodeHandoffDeliverRequest(encoded)
		case "ack":
			_, err = DecodeHandoffAcknowledgement(encoded)
		}
		if err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
	}
	if prepared.State = HandoffStateAccepted; ValidateHandoffPrepareResult(prepared) == nil {
		t.Fatal("accepted state claimed a newly prepared attempt")
	}
	if prepared = (HandoffPrepareResult{ContractVersion: HandoffVersion, GuestInstanceID: binding.GuestInstanceID, State: HandoffStatePrepared}); ValidateHandoffPrepareResult(prepared) != nil {
		t.Fatal("repeat prepared observation was rejected")
	}
	if !strings.Contains(fmt.Sprint(deliver), "sensitive") || strings.Contains(fmt.Sprint(deliver), deliver.Envelope.Token) {
		t.Fatal("sensitive handoff formatting disclosed the token")
	}
	if _, err := DecodeHandoffDeliverRequest([]byte(`{"contract_version":"nvt.guest-enrollment-handoff/v1","envelope":null,"token":"forbidden"}`)); err == nil {
		t.Fatal("credential field outside the envelope was accepted")
	}
}

func TestContractRejectsInvalidFieldsAndBounds(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	validIssue := IssueRequest{ContractVersion: Version, Binding: validBinding(), TTLSeconds: 300}

	tests := []struct {
		name   string
		mutate func(*IssueRequest)
	}{
		{"version", func(value *IssueRequest) { value.ContractVersion = "nvt.guest-enrollment/v2" }},
		{"uid", func(value *IssueRequest) { value.Binding.AgentRunUID = "" }},
		{"execution", func(value *IssueRequest) { value.Binding.ExecutionID = strings.Repeat("x", MaxExecutionIDBytes+1) }},
		{"driver", func(value *IssueRequest) { value.Binding.DriverRegistration = "Invalid_Driver" }},
		{"generation", func(value *IssueRequest) { value.Binding.DesiredGeneration = 0 }},
		{"guest", func(value *IssueRequest) { value.Binding.GuestInstanceID = "bad\nvalue" }},
		{"ttl zero", func(value *IssueRequest) { value.TTLSeconds = 0 }},
		{"ttl large", func(value *IssueRequest) { value.TTLSeconds = MaxEnrollmentTTLSeconds + 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validIssue
			test.mutate(&value)
			if err := ValidateIssueRequest(value); err == nil {
				t.Fatal("invalid issue request was accepted")
			}
		})
	}

	for _, endpoint := range []string{
		"http://issuer.example/v1/exchange",
		"https://user@issuer.example/v1/exchange",
		"https://issuer.example/v1/exchange?token=x",
		"https://issuer.example/",
	} {
		if err := ValidateIssuerConfiguration(IssuerConfiguration{ExchangeURL: endpoint}); err == nil {
			t.Fatalf("invalid issuer-owned exchange endpoint was accepted: %s", endpoint)
		}
	}
	if err := ValidateIssuerConfiguration(IssuerConfiguration{ExchangeURL: "https://issuer.example/v1/exchange"}); err != nil {
		t.Fatalf("valid issuer-owned exchange endpoint was rejected: %v", err)
	}
	if _, err := DecodeIssueRequest([]byte(`{"contract_version":"nvt.guest-enrollment/v1","binding":{"agent_run_uid":"uid","execution_id":"execution","driver_registration":"driver","desired_generation":1,"guest_instance_id":"guest"},"issuer_url":"https://attacker.example/exchange","ttl_seconds":300}`)); err == nil {
		t.Fatal("caller-controlled issuer_url was accepted in an issue request")
	}

	envelope := BootstrapEnvelope{
		ContractVersion: Version, Binding: validBinding(), ExchangeURL: "https://issuer.example/v1/exchange",
		Token: opaqueValue(TokenBytes, 1), IssuedAt: FormatTimestamp(now), ExpiresAt: FormatTimestamp(now.Add(901 * time.Second)),
	}
	if err := ValidateBootstrapEnvelope(envelope); err == nil {
		t.Fatal("overlong enrollment lifetime was accepted")
	}
	envelope.ExpiresAt = FormatTimestamp(now.Add(time.Minute))
	envelope.Token += "="
	if err := ValidateBootstrapEnvelope(envelope); err == nil {
		t.Fatal("non-canonical token was accepted")
	}

	result := ExchangeResult{
		ContractVersion: Version, Binding: validBinding(),
		RuntimeIdentity: RuntimeIdentity{Type: RuntimeIdentityType, Opaque: opaqueValue(TokenBytes, 2), IssuedAt: FormatTimestamp(now), ExpiresAt: FormatTimestamp(now.Add(MaxRuntimeIdentityLifetime + time.Second))},
	}
	if err := ValidateExchangeResult(result); err == nil {
		t.Fatal("overlong runtime identity lifetime was accepted")
	}
}

func TestTokenGenerationDigestAndRedactedFormatting(t *testing.T) {
	t.Parallel()
	secureToken, err := GenerateToken()
	if err != nil {
		t.Fatalf("crypto/rand token: %v", err)
	}
	if _, err := TokenDigest(secureToken); err != nil {
		t.Fatalf("crypto/rand token shape: %v", err)
	}
	token, err := generateToken(bytes.NewReader(bytes.Repeat([]byte{0xa5}, TokenBytes)))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != TokenBytes {
		t.Fatalf("token shape: len=%d err=%v", len(decoded), err)
	}
	digest, err := TokenDigest(token)
	if err != nil || ValidateTokenDigest(digest) != nil || strings.Contains(digest, token) {
		t.Fatalf("token digest: %q, %v", digest, err)
	}
	if _, err := TokenDigest(token + "="); err == nil {
		t.Fatal("non-canonical token digest input was accepted")
	}

	envelope := BootstrapEnvelope{Token: token}
	request := ExchangeRequest{Token: token}
	result := ExchangeResult{RuntimeIdentity: RuntimeIdentity{Opaque: opaqueValue(TokenBytes, 4)}}
	for name, value := range map[string]any{"envelope": envelope, "request": request, "result": result} {
		formatted := fmt.Sprintf("%v %#v", value, value)
		if strings.Contains(formatted, token) || strings.Contains(formatted, result.RuntimeIdentity.Opaque) || !strings.Contains(formatted, "sensitive") {
			t.Fatalf("%s formatting was not redacted: %s", name, formatted)
		}
	}
	if err := NewFailure(FailureReason(token)); strings.Contains(err.Error(), token) || failureReason(t, err) != ReasonInvalidRequest {
		t.Fatalf("unrecognized failure reason was not sanitized: %v", err)
	}
}

func validBinding() Binding {
	return Binding{
		AgentRunUID: "3f203e6c-e244-4a75-9445-c24f34b26cd9", ExecutionID: "nvt-exec-0123456789abcdef",
		DriverRegistration: "qemu-lab", DesiredGeneration: 7, GuestInstanceID: "guest-boot-42",
	}
}

func opaqueValue(size int, value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, size))
}
