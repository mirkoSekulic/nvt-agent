package contract

import (
	"strings"
	"testing"
)

func validManifest() Manifest {
	return Manifest{
		ContractVersion:  Version,
		OS:               "linux",
		Architecture:     "amd64",
		BundleVersion:    "0.8.33-test",
		BuildID:          strings.Repeat("a", 40),
		NativeEntrypoint: "bin/nvt-guest-supervisor",
		ServiceIdentity:  "nvt-agent-guest.service",
		Compatibility:    Compatibility{AgentdProtocol: AgentdProtocolVersion, NativeSessionProtocol: NativeSessionProtocolVersion},
		Files:            []File{{Path: "bin/nvt-guest-supervisor", SHA256: "sha256:" + strings.Repeat("b", 64), Size: 1, Mode: 0o755}},
	}
}

func TestManifestRoundTripAndStrictJSON(t *testing.T) {
	manifest := validManifest()
	encoded, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeManifest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.BundleVersion != manifest.BundleVersion || decoded.Files[0] != manifest.Files[0] {
		t.Fatalf("unexpected round trip: %#v", decoded)
	}

	invalid := []string{
		`{"contract_version":"nvt.host-bundle/v1","contract_version":"nvt.host-bundle/v1"}`,
		`{"unknown":true}`,
		"{\"contract_version\":\"nvt.host-bundle/v1\",\"os\":\"linux\xff\"}",
	}
	for _, input := range invalid {
		if _, err := DecodeManifest([]byte(input)); err == nil {
			t.Fatalf("accepted invalid manifest %q", input)
		}
	}
}

func TestManifestValidationRejectsUnsafeAndAmbiguousFiles(t *testing.T) {
	tests := []func(*Manifest){
		func(manifest *Manifest) { manifest.NativeEntrypoint = "../bin/agent" },
		func(manifest *Manifest) { manifest.Files[0].Path = "/bin/agent" },
		func(manifest *Manifest) { manifest.Files[0].Mode = 0o4755 },
		func(manifest *Manifest) { manifest.Files = append(manifest.Files, manifest.Files[0]) },
		func(manifest *Manifest) { manifest.Architecture = "s390x" },
		func(manifest *Manifest) { manifest.Compatibility.AgentdProtocol = "nvt.agentd/v2" },
		func(manifest *Manifest) { manifest.Compatibility.NativeSessionProtocol = "nvt.native-session/v2" },
	}
	for index, mutate := range tests {
		manifest := validManifest()
		mutate(&manifest)
		if err := ValidateManifest(manifest); err == nil {
			t.Fatalf("case %d was accepted", index)
		}
	}
}
