package executiondriver

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

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
		ExecutionID:   "issuer/subject/run-1",
		Generation:    1,
		WorkloadKind:  WorkloadKindVM,
		ClassName:     "fake-small",
		Configuration: configuration,
	}}); err != nil {
		t.Fatalf("valid reconcile params: %v", err)
	}

	status := Status{
		Phase:              PhaseRunning,
		Ready:              true,
		Endpoint:           &Endpoint{Scheme: EndpointSchemeHTTPS, Host: "driver.invalid", Port: 443},
		ExternalResourceID: "provider/resource/123",
		ObservedGeneration: 1,
	}
	if err := ValidateStatus(status); err != nil {
		t.Fatalf("valid status: %v", err)
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
				ExecutionID:   "run-1",
				Generation:    1,
				WorkloadKind:  WorkloadKindVM,
				ClassName:     "fake-small",
				Configuration: json.RawMessage(`[]`),
			}}),
		},
		{
			name: "zero generation",
			err: ValidateReconcileParams(ReconcileParams{Desired: DesiredExecution{
				ExecutionID:   "run-1",
				WorkloadKind:  WorkloadKindVM,
				ClassName:     "fake-small",
				Configuration: json.RawMessage(`{}`),
			}}),
		},
		{
			name: "provider-specific workload kind",
			err: ValidateReconcileParams(ReconcileParams{Desired: DesiredExecution{
				ExecutionID:   "run-1",
				Generation:    1,
				WorkloadKind:  WorkloadKind("azure-vm"),
				ClassName:     "fake-small",
				Configuration: json.RawMessage(`{}`),
			}}),
		},
		{
			name: "ready without endpoint",
			err:  ValidateStatus(Status{Phase: PhaseRunning, Ready: true}),
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

func TestDesiredFingerprintCanonicalizesCompleteTuple(t *testing.T) {
	t.Parallel()

	base := DesiredExecution{
		ExecutionID:  "run-1",
		Generation:   4,
		WorkloadKind: WorkloadKindVM,
		ClassName:    "small",
		Configuration: json.RawMessage(
			`{"nested":{"enabled":true,"values":[1,0.10,1e-3]},"region":"test-1"}`,
		),
	}
	baseFingerprint, err := DesiredFingerprint(base)
	if err != nil {
		t.Fatalf("base fingerprint: %v", err)
	}

	equivalent := base
	equivalent.ExecutionID = "another-run"
	equivalent.Generation = 99
	equivalent.Configuration = json.RawMessage(
		` { "region" : "test-1", "nested" : { "values" : [1.0, 1e-1, 0.0010], "enabled" : true } } `,
	)
	equivalentFingerprint, err := DesiredFingerprint(equivalent)
	if err != nil {
		t.Fatalf("equivalent fingerprint: %v", err)
	}
	if equivalentFingerprint != baseFingerprint {
		t.Fatalf("semantically equivalent desired tuple changed fingerprint: base=%s equivalent=%s", baseFingerprint, equivalentFingerprint)
	}

	for name, mutate := range map[string]func(*DesiredExecution){
		"workload kind": func(value *DesiredExecution) { value.WorkloadKind = WorkloadKindPod },
		"class":         func(value *DesiredExecution) { value.ClassName = "large" },
		"configuration": func(value *DesiredExecution) {
			value.Configuration = json.RawMessage(`{"nested":{"enabled":false,"values":[1,0.1,0.001]},"region":"test-1"}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			fingerprint, err := DesiredFingerprint(changed)
			if err != nil {
				t.Fatalf("changed fingerprint: %v", err)
			}
			if fingerprint == baseFingerprint {
				t.Fatalf("changed %s did not change fingerprint", name)
			}
		})
	}
}

func TestDesiredFingerprintRejectsAmbiguousOrUnboundedConfiguration(t *testing.T) {
	t.Parallel()

	for name, configuration := range map[string]string{
		"top-level duplicate": `{"region":"first","region":"second"}`,
		"nested duplicate":    `{"nested":{"size":1,"size":2}}`,
		"unbounded exponent":  `{"size":1e99999}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DesiredFingerprint(DesiredExecution{
				ExecutionID:   "run-1",
				Generation:    1,
				WorkloadKind:  WorkloadKindVM,
				ClassName:     "small",
				Configuration: json.RawMessage(configuration),
			})
			if err == nil {
				t.Fatalf("ambiguous configuration %s unexpectedly accepted", configuration)
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
