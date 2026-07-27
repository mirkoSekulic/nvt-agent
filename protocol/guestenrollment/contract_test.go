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

	issue := IssueRequest{ContractVersion: Version, Binding: binding, IssuerURL: "https://enrollment.nvt-system.svc/v1/exchange", TTLSeconds: 300}
	envelope := BootstrapEnvelope{
		ContractVersion: Version, Binding: binding, IssuerURL: issue.IssuerURL, Token: token,
		IssuedAt: FormatTimestamp(now), ExpiresAt: FormatTimestamp(now.Add(5 * time.Minute)),
	}
	exchange := ExchangeRequest{ContractVersion: Version, Binding: binding, Token: token}
	result := ExchangeResult{
		ContractVersion: Version, Binding: binding,
		RuntimeIdentity: RuntimeIdentity{Type: RuntimeIdentityType, Opaque: identity, IssuedAt: FormatTimestamp(now), ExpiresAt: FormatTimestamp(now.Add(time.Hour))},
	}
	revoke := RevokeRequest{ContractVersion: Version, Binding: binding}

	for name, validation := range map[string]func() error{
		"issue":    func() error { return ValidateIssueRequest(issue) },
		"envelope": func() error { return ValidateBootstrapEnvelope(envelope) },
		"exchange": func() error { return ValidateExchangeRequest(exchange) },
		"result":   func() error { return ValidateExchangeResult(result) },
		"revoke":   func() error { return ValidateRevokeRequest(revoke) },
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
	revokeJSON, _ := json.Marshal(revoke)
	if _, err := DecodeIssueRequest(issueJSON); err != nil {
		t.Fatalf("decode issue: %v", err)
	}
	if _, err := DecodeExchangeRequest(exchangeJSON); err != nil {
		t.Fatalf("decode exchange: %v", err)
	}
	if _, err := DecodeExchangeResult(resultJSON); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if _, err := DecodeRevokeRequest(revokeJSON); err != nil {
		t.Fatalf("decode revoke: %v", err)
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

func TestContractRejectsInvalidFieldsAndBounds(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	validIssue := IssueRequest{ContractVersion: Version, Binding: validBinding(), IssuerURL: "https://issuer.example/v1/exchange", TTLSeconds: 300}

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
		{"http", func(value *IssueRequest) { value.IssuerURL = "http://issuer.example/v1/exchange" }},
		{"userinfo", func(value *IssueRequest) { value.IssuerURL = "https://user@issuer.example/v1/exchange" }},
		{"query", func(value *IssueRequest) { value.IssuerURL += "?token=x" }},
		{"root", func(value *IssueRequest) { value.IssuerURL = "https://issuer.example/" }},
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

	envelope := BootstrapEnvelope{
		ContractVersion: Version, Binding: validBinding(), IssuerURL: validIssue.IssuerURL,
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
