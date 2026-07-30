package executiondriver

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testNativeEgressCAPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "native egress test CA"},
		NotBefore: time.Unix(1, 0), NotAfter: time.Unix(4_102_444_800, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}))
}

func testNativeEgressAttachment(t *testing.T) NativeEgressAttachment {
	t.Helper()
	value, err := SealNativeEgressAttachment(NativeEgressAttachment{
		ContractVersion: NativeEgressAttachmentVersion,
		Generation:      3,
		Relay: NativeEgressRelayAttachment{
			Host: "nvt-native-egress-relay.nvt-system.svc", Port: 7445,
			ServerName: "nvt-native-egress-relay.nvt-system.svc", CAPEM: testNativeEgressCAPEM(t),
		},
		RequiredDestinations: []NativeEgressRequiredDestination{
			{Purpose: NativeEgressDestinationBootstrap, Host: "nvt-broker.nvt-system.svc", Port: 7443},
			{Purpose: NativeEgressDestinationControl, Host: "nvt-gateway.nvt-system.svc", Port: 7444},
		},
		Redirect: NativeEgressRedirectIntent{
			Mode: NativeEgressRedirectModeCaptureTCP, LoopbackAddress: "127.0.0.1",
			TransparentTCPPort: 15001, ExplicitCONNECTPort: 15002,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestNativeEgressAttachmentStrictPortableContract(t *testing.T) {
	t.Parallel()
	value := testNativeEgressAttachment(t)
	if err := ValidateNativeEgressAttachment(value); err != nil {
		t.Fatalf("valid attachment: %v", err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"token", "credential", "private_key", "control_bearer", "provider_state", "shell", "iptables"} {
		if bytes.Contains(bytes.ToLower(encoded), []byte(forbidden)) {
			t.Fatalf("attachment contains forbidden field %q: %s", forbidden, encoded)
		}
	}
	if got := value.String(); got != "[native egress attachment]" || strings.Contains(got, value.Relay.Host) {
		t.Fatalf("unsafe String output: %q", got)
	}

	params := ReconcileParams{Desired: DesiredExecution{
		ExecutionID: "run-1", Generation: 4, DesiredFingerprint: validDesiredFingerprint,
		WorkloadKind: WorkloadKindVM, ClassName: "fake", Configuration: json.RawMessage(`{}`),
		NativeEgressAttachment: &value,
	}}
	if err := ValidateReconcileParams(params); err != nil {
		t.Fatalf("valid desired: %v", err)
	}
	params.Desired.WorkloadKind = WorkloadKindPod
	if err := ValidateReconcileParams(params); err == nil {
		t.Fatal("non-VM attachment unexpectedly accepted")
	}

	var decoded NativeEgressAttachment
	for _, input := range [][]byte{
		append(encoded, []byte(` {}`)...),
		bytes.Replace(encoded, []byte(`"generation":3`), []byte(`"generation":3,"generation":4`), 1),
		bytes.Replace(encoded, []byte(`"digest"`), []byte(`"unknown":true,"digest"`), 1),
	} {
		if err := DecodeStrictJSON(input, &decoded); err == nil {
			t.Fatalf("non-strict attachment unexpectedly decoded: %s", input)
		}
	}
}

func TestNativeEgressAttachmentRejectsMutationAndNonCanonicalNetwork(t *testing.T) {
	t.Parallel()
	valid := testNativeEgressAttachment(t)
	tests := map[string]func(*NativeEgressAttachment){
		"version":           func(v *NativeEgressAttachment) { v.ContractVersion = "nvt.native-egress-attachment/v2" },
		"zero generation":   func(v *NativeEgressAttachment) { v.Generation = 0 },
		"relay uppercase":   func(v *NativeEgressAttachment) { v.Relay.Host = "Relay.invalid" },
		"relay server name": func(v *NativeEgressAttachment) { v.Relay.ServerName = "relay.invalid." },
		"relay port":        func(v *NativeEgressAttachment) { v.Relay.Port = 0 },
		"private trust": func(v *NativeEgressAttachment) {
			v.Relay.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}))
		},
		"missing bootstrap": func(v *NativeEgressAttachment) { v.RequiredDestinations[0].Purpose = NativeEgressDestinationControl },
		"reserved IP":       func(v *NativeEgressAttachment) { v.RequiredDestinations[0].Host = "127.0.0.2" },
		"private IP":        func(v *NativeEgressAttachment) { v.RequiredDestinations[0].Host = "10.0.0.1" },
		"malformed IP":      func(v *NativeEgressAttachment) { v.RequiredDestinations[0].Host = "999.999.999.999" },
		"scoped IP":         func(v *NativeEgressAttachment) { v.RequiredDestinations[0].Host = "fe80::1%eth0" },
		"noncanonical DNS":  func(v *NativeEgressAttachment) { v.RequiredDestinations[0].Host = "-broker.invalid" },
		"overlong DNS label": func(v *NativeEgressAttachment) {
			v.RequiredDestinations[0].Host = strings.Repeat("a", 64) + ".invalid"
		},
		"duplicate CA": func(v *NativeEgressAttachment) { v.Relay.CAPEM += v.Relay.CAPEM },
		"too many endpoints": func(v *NativeEgressAttachment) {
			v.RequiredDestinations = make([]NativeEgressRequiredDestination, MaxNativeEgressRequiredDestinations+1)
		},
		"unsorted": func(v *NativeEgressAttachment) {
			v.RequiredDestinations[0], v.RequiredDestinations[1] = v.RequiredDestinations[1], v.RequiredDestinations[0]
		},
		"duplicate endpoint": func(v *NativeEgressAttachment) {
			v.RequiredDestinations[1].Host, v.RequiredDestinations[1].Port = v.RequiredDestinations[0].Host, v.RequiredDestinations[0].Port
		},
		"redirect mode":       func(v *NativeEgressAttachment) { v.Redirect.Mode = "iptables" },
		"redirect host":       func(v *NativeEgressAttachment) { v.Redirect.LoopbackAddress = "0.0.0.0" },
		"privileged port":     func(v *NativeEgressAttachment) { v.Redirect.TransparentTCPPort = 80 },
		"same redirect ports": func(v *NativeEgressAttachment) { v.Redirect.ExplicitCONNECTPort = v.Redirect.TransparentTCPPort },
		"digest":              func(v *NativeEgressAttachment) { v.Digest = validDesiredFingerprint },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := valid
			value.RequiredDestinations = append([]NativeEgressRequiredDestination(nil), valid.RequiredDestinations...)
			mutate(&value)
			if err := ValidateNativeEgressAttachment(value); err == nil {
				t.Fatal("mutated attachment unexpectedly accepted")
			}
		})
	}
}

func TestNativeEgressAttachmentGenerationAndLegacyWireCompatibility(t *testing.T) {
	t.Parallel()
	if got, err := NativeEgressDesiredGeneration(7, 0); err != nil || got != 7 {
		t.Fatalf("legacy desired generation=%d err=%v", got, err)
	}
	if got, err := NativeEgressDesiredGeneration(7, 3); err != nil || got != 10 {
		t.Fatalf("composed desired generation=%d err=%v", got, err)
	}
	legacy := DesiredExecution{
		ExecutionID: "run-1", Generation: 7, DesiredFingerprint: validDesiredFingerprint,
		WorkloadKind: WorkloadKindVM, ClassName: "fake", Configuration: json.RawMessage(`{}`),
	}
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"execution_id":"run-1","generation":7,"desired_fingerprint":"` + validDesiredFingerprint + `","workload_kind":"vm","class_name":"fake","configuration":{}}`
	if string(encoded) != want {
		t.Fatalf("legacy wire changed:\n got %s\nwant %s", encoded, want)
	}
	status := Status{Phase: PhaseProvisioning, EgressConfinement: &EgressConfinementStatus{
		Boundary: EgressConfinementBoundaryInfrastructure, AttachmentGeneration: 3, AttachmentDigest: testNativeEgressAttachment(t).Digest,
	}}
	if err := ValidateStatus(status); err != nil {
		t.Fatalf("valid attachment observation: %v", err)
	}
	status.EgressConfinement.AttachmentGeneration = 0
	if err := ValidateStatus(status); err == nil {
		t.Fatal("unpaired attachment observation unexpectedly accepted")
	}
}

func TestNativeEgressAttachmentAcceptsCanonicalPublicIPLiteral(t *testing.T) {
	t.Parallel()
	value := testNativeEgressAttachment(t)
	value.Digest = ""
	value.Relay.Host = "8.8.8.8"
	value.Relay.ServerName = "8.8.8.8"
	value.RequiredDestinations[0].Host = "1.1.1.1"
	sealed, err := SealNativeEgressAttachment(value)
	if err != nil || ValidateNativeEgressAttachment(sealed) != nil {
		t.Fatalf("canonical public IP attachment=%#v err=%v", sealed, err)
	}
}
