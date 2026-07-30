package nativeegress

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

func publicationBinding(suffix string) guestenrollment.Binding {
	return guestenrollment.Binding{
		AgentRunUID: "run-" + suffix, ExecutionID: "execution-" + suffix,
		DriverRegistration: "driver-" + suffix, DesiredGeneration: 3, GuestInstanceID: "guest-" + suffix,
	}
}

func TestTargetPublicationCanonicalDigestAndStrictRoundTrip(t *testing.T) {
	targets := []PublishedTarget{
		{Binding: publicationBinding("b"), TargetType: EgressdConnectTargetType, ConnectURL: "http://egressd-b.example:8470"},
		{Binding: publicationBinding("a"), TargetType: EgressdConnectTargetType, ConnectURL: "http://egressd-a.example:8470"},
	}
	canonical, digest, err := CanonicalTargetSnapshot(targets)
	if err != nil || canonical[0].Binding != publicationBinding("a") || guestenrollment.ValidateTokenDigest(digest) != nil {
		t.Fatalf("canonical snapshot failed: %#v %q %v", canonical, digest, err)
	}
	if digest != "sha256:54b596604cb05852401d9122f3dc116f6b8a10479523784f04d755b4507c9209" {
		t.Fatalf("canonical digest changed: %q", digest)
	}
	canonicalAgain, digestAgain, err := CanonicalTargetSnapshot(canonical)
	if err != nil || digestAgain != digest || !equalPublishedTargets(canonicalAgain, canonical) {
		t.Fatal("canonical digest was not deterministic")
	}
	request := TargetSnapshot{
		ContractVersion: TargetPublicationVersion, Type: TargetSnapshotReplace,
		Generation: 7, Digest: digest, Targets: canonical,
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTargetSnapshot(encoded)
	if err != nil || decoded.Generation != request.Generation || decoded.Digest != request.Digest || !equalPublishedTargets(decoded.Targets, request.Targets) {
		t.Fatalf("snapshot round trip failed: %#v %v", decoded, err)
	}
	if encodedWithContract, err := EncodeTargetSnapshot(request); err != nil || !bytes.Equal(encodedWithContract, encoded) {
		t.Fatal("snapshot encoder did not preserve canonical request")
	}
	ack := TargetSnapshotAcknowledgement{
		ContractVersion: TargetPublicationVersion, Type: TargetSnapshotAck,
		Generation: request.Generation, Digest: request.Digest, TargetCount: len(request.Targets),
	}
	ackBytes, err := EncodeTargetSnapshotAcknowledgement(ack)
	if err != nil {
		t.Fatal(err)
	}
	if decodedAck, err := DecodeTargetSnapshotAcknowledgement(ackBytes); err != nil || decodedAck != ack {
		t.Fatal("snapshot acknowledgement round trip failed")
	}

	empty, emptyDigest, err := CanonicalTargetSnapshot([]PublishedTarget{})
	if err != nil || len(empty) != 0 || empty == nil || guestenrollment.ValidateTokenDigest(emptyDigest) != nil {
		t.Fatal("canonical applied-empty snapshot was rejected")
	}
	if _, _, err := CanonicalTargetSnapshot(nil); err == nil {
		t.Fatal("absent snapshot was confused with applied empty")
	}
}

func TestTargetPublicationRejectsMalformedNoncanonicalDuplicateAndDigestMismatch(t *testing.T) {
	validA := PublishedTarget{Binding: publicationBinding("a"), TargetType: EgressdConnectTargetType, ConnectURL: "http://egressd-a.example:8470"}
	validB := PublishedTarget{Binding: publicationBinding("b"), TargetType: EgressdConnectTargetType, ConnectURL: "http://egressd-b.example:8470"}
	canonical, digest, err := CanonicalTargetSnapshot([]PublishedTarget{validA, validB})
	if err != nil {
		t.Fatal(err)
	}
	valid := TargetSnapshot{ContractVersion: TargetPublicationVersion, Type: TargetSnapshotReplace, Generation: 1, Digest: digest, Targets: canonical}
	mutations := []func(*TargetSnapshot){
		func(value *TargetSnapshot) { value.ContractVersion = "nvt.native-egress-target-publication/v2" },
		func(value *TargetSnapshot) { value.Type = "patch" },
		func(value *TargetSnapshot) { value.Generation = 0 },
		func(value *TargetSnapshot) { value.Digest = "sha256:" + strings.Repeat("0", 64) },
		func(value *TargetSnapshot) { value.Targets = nil },
		func(value *TargetSnapshot) { value.Targets[0], value.Targets[1] = value.Targets[1], value.Targets[0] },
		func(value *TargetSnapshot) { value.Targets[0].TargetType = "nvt.workspace/v1" },
		func(value *TargetSnapshot) { value.Targets[0].ConnectURL = "http://EGRESSD.example:8470" },
	}
	for index, mutate := range mutations {
		value := valid
		value.Targets = append([]PublishedTarget(nil), valid.Targets...)
		mutate(&value)
		if ValidateTargetSnapshot(value) == nil {
			t.Fatalf("invalid snapshot mutation %d was accepted", index)
		}
	}
	if _, _, err := CanonicalTargetSnapshot([]PublishedTarget{validA, validA}); err == nil {
		t.Fatal("duplicate exact binding was accepted")
	}
	shared := validB
	shared.ConnectURL = validA.ConnectURL
	if _, _, err := CanonicalTargetSnapshot([]PublishedTarget{validA, shared}); err == nil {
		t.Fatal("duplicate canonical listener was accepted")
	}
	overflow := make([]PublishedTarget, MaxTargetPublicationTargets+1)
	for index := range overflow {
		overflow[index] = PublishedTarget{
			Binding: publicationBinding(fmt.Sprintf("bounded-%03d", index)), TargetType: EgressdConnectTargetType,
			ConnectURL: fmt.Sprintf("http://egressd-%03d.example:8470", index),
		}
	}
	if _, _, err := CanonicalTargetSnapshot(overflow); err == nil {
		t.Fatal("over-capacity snapshot was accepted")
	}

	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	targetField := []byte(`"connect_url":"http://egressd-a.example:8470"`)
	for name, malformed := range map[string][]byte{
		"duplicate nested": bytes.Replace(encoded, targetField, []byte(`"connect_url":"http://egressd-a.example:8470","connect_url":"http://other.example:8470"`), 1),
		"unknown":          append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"provider":"forbidden"}`)...),
		"trailing":         append(append([]byte(nil), encoded...), []byte(` {}`)...),
		"invalid UTF-8":    {'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'},
		"oversized":        bytes.Repeat([]byte{' '}, MaxTargetPublicationRequestBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeTargetSnapshot(malformed); err == nil {
				t.Fatal("malformed target publication was accepted")
			}
		})
	}
}

func TestTargetPublicationStatusAndCredentialAreBoundedAndRedacted(t *testing.T) {
	unpublished := TargetStatus{ContractVersion: TargetPublicationVersion, Type: TargetPublicationStatusResponse}
	if ValidateTargetStatus(unpublished) != nil {
		t.Fatal("unpublished deny-all status was rejected")
	}
	_, digest, err := CanonicalTargetSnapshot([]PublishedTarget{})
	if err != nil {
		t.Fatal(err)
	}
	appliedEmpty := TargetStatus{
		ContractVersion: TargetPublicationVersion, Type: TargetPublicationStatusResponse,
		Published: true, Generation: 1, Digest: digest,
	}
	if ValidateTargetStatus(appliedEmpty) != nil {
		t.Fatal("applied empty status was rejected")
	}
	invalid := appliedEmpty
	invalid.Published = false
	if ValidateTargetStatus(invalid) == nil {
		t.Fatal("unpublished status retained applied metadata")
	}
	failure := TargetPublicationFailure{
		ContractVersion: TargetPublicationVersion, Type: TargetPublicationError,
		Reason: TargetPublicationReasonConflict,
	}
	encodedFailure, err := EncodeTargetPublicationFailure(failure)
	if err != nil {
		t.Fatal(err)
	}
	if decodedFailure, err := DecodeTargetPublicationFailure(encodedFailure); err != nil || decodedFailure != failure {
		t.Fatal("generic failure did not round trip")
	}
	failure.Reason = "target-canary"
	if ValidateTargetPublicationFailure(failure) == nil {
		t.Fatal("unfrozen failure reason was accepted")
	}

	credential, err := GenerateRelayControlCredential()
	if err != nil || ValidateRelayControlCredential(credential) != nil {
		t.Fatalf("control credential generation failed: %v", err)
	}
	for _, value := range []string{
		"", credential + "=", strings.TrimPrefix(credential, RelayControlCredentialPrefix),
		RelayControlCredentialPrefix + strings.Repeat("a", 42),
	} {
		if ValidateRelayControlCredential(value) == nil {
			t.Fatalf("invalid relay control credential %q was accepted", value)
		}
	}
	target := PublishedTarget{Binding: publicationBinding("canary"), TargetType: EgressdConnectTargetType, ConnectURL: "http://topology-canary.example:8470"}
	for _, formatted := range []string{fmt.Sprint(target), fmt.Sprintf("%#v", target), fmt.Sprint(TargetSnapshot{Targets: []PublishedTarget{target}})} {
		if strings.Contains(formatted, "topology-canary") || strings.Contains(formatted, target.Binding.GuestInstanceID) {
			t.Fatalf("target formatting exposed topology: %q", formatted)
		}
	}
}
