package portal

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mirkoSekulic/nvt-agent/protocol/eligibility"
)

func TestConfigStrictlyRejectsUnknownDuplicateAndUnsafeSlotPolicy(t *testing.T) {
	valid, err := json.Marshal(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeConfig(strings.NewReader(string(valid))); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	invalid := []string{
		strings.Replace(string(valid), `"listenAddr":`, `"unknown":true,"listenAddr":`, 1),
		strings.Replace(string(valid), `"publicURL":`, `"publicURL":"https://duplicate.example","publicURL":`, 1),
		strings.Replace(string(valid), `"adapter":"codex-oauth-file"`, `"adapter":"auto-detect"`, 1),
		strings.Replace(string(valid), `"subject":"alice"`, `"subject":""`, 1),
		string(valid) + ` trailing`,
	}
	for index, raw := range invalid {
		if _, err := DecodeConfig(strings.NewReader(raw)); err == nil {
			t.Fatalf("invalid config %d accepted", index)
		}
	}
}

func TestConfigRejectsSharedSecretDestinationAcrossOwners(t *testing.T) {
	cfg := testConfig()
	cfg.Slots[1].DataKey = cfg.Slots[0].DataKey
	if cfg.Slots[0].Name == cfg.Slots[1].Name || cfg.Slots[0].Owner.Subject == cfg.Slots[1].Owner.Subject {
		t.Fatal("test requires distinct slot names and owners")
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "already assigned") {
		t.Fatal("shared Secret destination was accepted")
	}
}

func TestConfigRequiresExplicitExperimentalCodexDeviceAuthorization(t *testing.T) {
	cfg := testConfig()
	cfg.Enrollment.ExperimentalCodexDeviceAuth = false
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "experimental Codex device") {
		t.Fatal("ungated experimental Codex device authorization was accepted")
	}
	cfg.Slots = cfg.Slots[1:]
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Claude-only configuration incorrectly required the Codex gate: %v", err)
	}
}

func TestConfigValidatesOIDCEligibilityClaimSource(t *testing.T) {
	cfg := testConfig()
	cfg.Auth.Mode = authModeOIDC
	cfg.Auth.OIDC = OIDCConfig{
		IssuerURL: "https://identity.example.test", ClientID: "portal-client", CallbackPath: "/oauth2/callback",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default ID-token claim source rejected: %v", err)
	}
	for _, source := range []string{
		eligibility.ClaimSourceIDToken, eligibility.ClaimSourceAccessToken, eligibility.ClaimSourceUserInfo,
	} {
		cfg.Auth.OIDC.EligibilityClaimSource = source
		if err := cfg.Validate(); err != nil {
			t.Fatalf("claim source %q rejected: %v", source, err)
		}
	}
	cfg.Auth.OIDC.EligibilityClaimSource = "unverified_jwt"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unknown OIDC eligibility claim source accepted")
	}
}

func TestPortalEligibilityRejectsOwnerFieldEvenWhenFalse(t *testing.T) {
	cfg := testConfig()
	cfg.Auth.Eligibility = &eligibility.Policy{Rules: []eligibility.Rule{{
		ID: "authenticated", Effect: eligibility.EffectAllow, Authenticated: true,
	}}}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	withOwner := strings.Replace(string(raw), `"authenticated":true`, `"authenticated":true,"owner":false`, 1)
	if withOwner == string(raw) {
		t.Fatal("test did not insert the compatibility field")
	}
	if _, err := DecodeConfig(strings.NewReader(withOwner)); err == nil {
		t.Fatal("portal eligibility accepted gateway-only owner:false compatibility field")
	}
}

func TestConfigAppliesAndStrictlyValidatesEnrollmentBounds(t *testing.T) {
	cfg := testConfig()
	cfg.Enrollment = EnrollmentConfig{ExperimentalCodexDeviceAuth: true}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Enrollment.MaxSessions != 64 || cfg.Enrollment.MaxConcurrent != 2 || cfg.Enrollment.TimeoutSeconds != 600 ||
		cfg.Enrollment.MaxOutputBytes != 64*1024 {
		t.Fatal("enrollment defaults changed")
	}
	invalid := []EnrollmentConfig{
		{MaxSessions: 1, MaxConcurrent: 2, TimeoutSeconds: 600, MaxOutputBytes: 4096},
		{MaxSessions: 64, MaxConcurrent: 2, TimeoutSeconds: 59, MaxOutputBytes: 4096},
		{MaxSessions: 64, MaxConcurrent: 2, TimeoutSeconds: 3601, MaxOutputBytes: 4096},
		{MaxSessions: 64, MaxConcurrent: 2, TimeoutSeconds: 600, MaxOutputBytes: 4095},
	}
	for _, enrollment := range invalid {
		cfg := testConfig()
		cfg.Enrollment = enrollment
		if err := cfg.Validate(); err == nil {
			t.Fatal("invalid enrollment limits were accepted")
		}
	}
}
