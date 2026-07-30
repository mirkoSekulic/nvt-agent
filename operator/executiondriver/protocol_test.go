package executiondriver

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

const validDesiredFingerprint = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestValidateProtocolTypes(t *testing.T) {
	t.Parallel()

	if err := ValidateInitializeParams(InitializeParams{
		ProtocolVersion:    ProtocolVersion,
		DriverInstanceName: "test-driver",
	}); err != nil {
		t.Fatalf("valid initialize params: %v", err)
	}
	if err := ValidateInitializeResult(InitializeResult{
		ProtocolVersion: ProtocolVersion,
		Capabilities:    []Capability{CapabilityDelete, CapabilityReconcile, CapabilityObserve},
	}); err != nil {
		t.Fatalf("valid initialize result: %v", err)
	}

	configuration := json.RawMessage(`{"region":"test-1"}`)
	if err := ValidateReconcileParams(ReconcileParams{Desired: DesiredExecution{
		ExecutionID:        "issuer/subject/run-1",
		Generation:         1,
		DesiredFingerprint: validDesiredFingerprint,
		WorkloadKind:       WorkloadKindVM,
		ClassName:          "fake-small",
		Configuration:      configuration,
	}}); err != nil {
		t.Fatalf("valid reconcile params: %v", err)
	}

	status := Status{
		Phase:              PhaseRunning,
		Ready:              true,
		Endpoint:           &Endpoint{Scheme: EndpointSchemeHTTPS, Host: "driver.invalid", Port: 443},
		ExternalResourceID: "provider/resource/123",
		ObservedGeneration: 1,
		EgressConfinement: &EgressConfinementStatus{
			Boundary: EgressConfinementBoundaryInfrastructure,
			Ready:    true,
		},
	}
	if err := ValidateStatus(status); err != nil {
		t.Fatalf("valid status: %v", err)
	}
}

func TestEgressConfinementStatusIsOptionalCompatibleAndNonSecret(t *testing.T) {
	t.Parallel()
	legacy := Status{Phase: PhaseProvisioning, ObservedGeneration: 1}
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"phase":"provisioning","ready":false,"observed_generation":1}` {
		t.Fatalf("legacy status wire shape changed: %s", encoded)
	}
	if err := ValidateStatus(legacy); err != nil {
		t.Fatalf("legacy status rejected: %v", err)
	}
	confined := Status{
		Phase: PhaseRunning, Ready: true, ObservedGeneration: 2,
		Endpoint:          &Endpoint{Scheme: EndpointSchemeHTTPS, Host: "guest.invalid", Port: 443},
		EgressConfinement: &EgressConfinementStatus{Boundary: EgressConfinementBoundaryInfrastructure, Ready: true},
	}
	encoded, err = json.Marshal(confined)
	if err != nil || !bytes.Contains(encoded, []byte(`"egress_confinement":{"boundary":"infrastructure","ready":true}`)) {
		t.Fatalf("portable confinement status=%s error=%v", encoded, err)
	}
	confinementEncoded, err := json.Marshal(confined.EgressConfinement)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"token", "credential", "identity", "endpoint", "provider_state"} {
		if bytes.Contains(bytes.ToLower(confinementEncoded), []byte(forbidden)) {
			t.Fatalf("confinement assertion contains forbidden field %q: %s", forbidden, confinementEncoded)
		}
	}
}

func TestDesiredExecutionRemainsCredentialFree(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(DesiredExecution{
		ExecutionID:        "run-1",
		Generation:         1,
		DesiredFingerprint: validDesiredFingerprint,
		WorkloadKind:       WorkloadKindVM,
		ClassName:          "fake-small",
		Configuration:      json.RawMessage(`{"region":"test-1"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	want := []string{"class_name", "configuration", "desired_fingerprint", "execution_id", "generation", "workload_kind"}
	got := make([]string, 0, len(fields))
	for name := range fields {
		got = append(got, name)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("DesiredExecution wire fields changed: got %v want %v", got, want)
	}
	for _, forbidden := range []string{"enrollment", "token", "credential", "secret", "runtime_identity", "egress_identity"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("DesiredExecution contains forbidden sensitive field %q: %s", forbidden, encoded)
		}
	}
}

func TestValidateProtocolTypesFailClosed(t *testing.T) {
	t.Parallel()

	retryZero := int32(0)
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "unsupported protocol",
			err: ValidateInitializeParams(InitializeParams{
				ProtocolVersion:    "nvt.execution-driver/v2",
				DriverInstanceName: "test-driver",
			}),
		},
		{
			name: "missing capability",
			err: ValidateInitializeResult(InitializeResult{
				ProtocolVersion: ProtocolVersion,
				Capabilities:    []Capability{CapabilityReconcile, CapabilityObserve},
			}),
		},
		{
			name: "duplicate capability",
			err: ValidateInitializeResult(InitializeResult{
				ProtocolVersion: ProtocolVersion,
				Capabilities: []Capability{
					CapabilityReconcile, CapabilityObserve, CapabilityDelete, CapabilityDelete,
				},
			}),
		},
		{
			name: "configuration is not object",
			err: ValidateReconcileParams(ReconcileParams{Desired: DesiredExecution{
				ExecutionID:        "run-1",
				Generation:         1,
				DesiredFingerprint: validDesiredFingerprint,
				WorkloadKind:       WorkloadKindVM,
				ClassName:          "fake-small",
				Configuration:      json.RawMessage(`[]`),
			}}),
		},
		{
			name: "zero generation",
			err: ValidateReconcileParams(ReconcileParams{Desired: DesiredExecution{
				ExecutionID:        "run-1",
				DesiredFingerprint: validDesiredFingerprint,
				WorkloadKind:       WorkloadKindVM,
				ClassName:          "fake-small",
				Configuration:      json.RawMessage(`{}`),
			}}),
		},
		{
			name: "provider-specific workload kind",
			err: ValidateReconcileParams(ReconcileParams{Desired: DesiredExecution{
				ExecutionID:        "run-1",
				Generation:         1,
				DesiredFingerprint: validDesiredFingerprint,
				WorkloadKind:       WorkloadKind("azure-vm"),
				ClassName:          "fake-small",
				Configuration:      json.RawMessage(`{}`),
			}}),
		},
		{
			name: "ready without endpoint",
			err:  ValidateStatus(Status{Phase: PhaseRunning, Ready: true}),
		},
		{
			name: "provider-specific confinement boundary",
			err: ValidateStatus(Status{Phase: PhaseProvisioning, EgressConfinement: &EgressConfinementStatus{
				Boundary: EgressConfinementBoundary("azure-vnet"),
			}}),
		},
		{
			name: "guest-local confinement boundary",
			err: ValidateStatus(Status{Phase: PhaseProvisioning, EgressConfinement: &EgressConfinementStatus{
				Boundary: EgressConfinementBoundary("guest"), Ready: true,
			}}),
		},
		{
			name: "ready without confinement convergence",
			err: ValidateStatus(Status{
				Phase: PhaseRunning, Ready: true,
				Endpoint:          &Endpoint{Scheme: EndpointSchemeHTTPS, Host: "guest.invalid", Port: 443},
				EgressConfinement: &EgressConfinementStatus{Boundary: EgressConfinementBoundaryInfrastructure},
			}),
		},
		{
			name: "deleted with confinement assertion",
			err: ValidateStatus(Status{
				Phase:             PhaseDeleted,
				EgressConfinement: &EgressConfinementStatus{Boundary: EgressConfinementBoundaryInfrastructure},
			}),
		},
		{
			name: "failure outside failed phase",
			err: ValidateStatus(Status{
				Phase:   PhaseRunning,
				Failure: &Failure{Reason: "unexpected-failure"},
			}),
		},
		{
			name: "failed without failure",
			err:  ValidateStatus(Status{Phase: PhaseFailed}),
		},
		{
			name: "deleted with resource",
			err: ValidateStatus(Status{
				Phase:              PhaseDeleted,
				ExternalResourceID: "still-present",
			}),
		},
		{
			name: "invalid retry",
			err: ValidateStatus(Status{
				Phase:             PhaseProvisioning,
				RetryAfterSeconds: &retryZero,
			}),
		},
		{
			name: "unsafe RPC message",
			err: ValidateRPCError(RPCError{
				Code:    -32000,
				Message: "provider returned a token",
				Data:    Failure{Reason: "provider-failed"},
			}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if test.err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateMethodSpecificStatusPhases(t *testing.T) {
	t.Parallel()

	if err := ValidateReconcileStatus(Status{Phase: PhaseProvisioning}); err != nil {
		t.Fatalf("valid reconcile status: %v", err)
	}
	if err := ValidateReconcileStatus(Status{Phase: PhaseDeleted}); err == nil {
		t.Fatal("deleted reconcile status unexpectedly accepted")
	}
	if err := ValidateDeleteStatus(Status{Phase: PhaseDeleting}); err != nil {
		t.Fatalf("valid converging delete status: %v", err)
	}
	if err := ValidateDeleteStatus(Status{Phase: PhaseDeleted}); err != nil {
		t.Fatalf("valid completed delete status: %v", err)
	}
	if err := ValidateDeleteStatus(Status{Phase: PhaseRunning}); err == nil {
		t.Fatal("running delete status unexpectedly accepted")
	}
	if err := ValidateObserveStatus(Status{Phase: PhaseUnknown}); err != nil {
		t.Fatalf("valid unknown observation: %v", err)
	}
}

func TestDecodeStrictJSON(t *testing.T) {
	t.Parallel()

	type value struct {
		Name string `json:"name"`
	}
	var decoded value
	if err := DecodeStrictJSON([]byte(`{"name":"driver"}`), &decoded); err != nil {
		t.Fatalf("decode valid JSON: %v", err)
	}
	if decoded.Name != "driver" {
		t.Fatalf("decoded name = %q", decoded.Name)
	}

	for _, input := range []string{
		`{"name":"driver","unknown":true}`,
		`{"name":"driver"} {}`,
		`{"name":`,
		`{"name":"first","name":"second"}`,
		`{"name":"driver","nested":{"key":1,"key":2}}`,
		`{"name":"driver","nested":[{"key":1,"\u006bey":2}]}`,
	} {
		if err := DecodeStrictJSON([]byte(input), &decoded); err == nil {
			t.Fatalf("DecodeStrictJSON(%q) unexpectedly succeeded", input)
		}
	}
}

func TestDecodeStrictJSONRejectsInvalidUTF8(t *testing.T) {
	t.Parallel()

	type value struct {
		Name string `json:"name"`
	}
	decoded := value{Name: "unchanged"}
	input := append([]byte(`{"name":"`), 0xff)
	input = append(input, []byte(`"}`)...)
	if err := DecodeStrictJSON(input, &decoded); err == nil {
		t.Fatal("DecodeStrictJSON unexpectedly replaced invalid UTF-8")
	}
	if decoded.Name != "unchanged" {
		t.Fatalf("invalid UTF-8 mutated decoded value to %q", decoded.Name)
	}

	configuration := append([]byte(`{"nested":"`), 0xff)
	configuration = append(configuration, []byte(`"}`)...)
	if err := ValidateReconcileParams(ReconcileParams{Desired: DesiredExecution{
		ExecutionID:        "run-invalid-utf8",
		Generation:         1,
		DesiredFingerprint: validDesiredFingerprint,
		WorkloadKind:       WorkloadKindVM,
		ClassName:          "fake-small",
		Configuration:      configuration,
	}}); err == nil {
		t.Fatal("reconcile configuration with invalid UTF-8 unexpectedly accepted")
	}
}

func TestValidateDesiredFingerprint(t *testing.T) {
	t.Parallel()
	if err := ValidateDesiredFingerprint(validDesiredFingerprint); err != nil {
		t.Fatalf("valid desired fingerprint: %v", err)
	}

	for name, fingerprint := range map[string]string{
		"missing":        "",
		"missing prefix": strings.Repeat("0", 64),
		"short":          "sha256:" + strings.Repeat("0", 63),
		"long":           "sha256:" + strings.Repeat("0", 65),
		"uppercase":      "sha256:" + strings.Repeat("A", 64),
		"non-hex":        "sha256:" + strings.Repeat("z", 64),
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateDesiredFingerprint(fingerprint); err == nil {
				t.Fatalf("fingerprint %q unexpectedly accepted", fingerprint)
			}
		})
	}
}

func TestMarshalRequestBoundsAndDoesNotAddNewline(t *testing.T) {
	t.Parallel()

	encoded, err := MarshalRequest("request-1", MethodObserve, ExecutionParams{ExecutionID: "run-1"})
	if err != nil {
		t.Fatalf("MarshalRequest: %v", err)
	}
	if bytes.HasSuffix(encoded, []byte("\n")) {
		t.Fatal("MarshalRequest unexpectedly added transport framing")
	}
	if !bytes.Contains(encoded, []byte(`"jsonrpc":"2.0"`)) {
		t.Fatalf("request missing JSON-RPC version: %s", encoded)
	}
	if _, err := MarshalRequest(strings.Repeat("x", 129), MethodObserve, ExecutionParams{ExecutionID: "run-1"}); err == nil {
		t.Fatal("oversized request ID unexpectedly accepted")
	}
}
