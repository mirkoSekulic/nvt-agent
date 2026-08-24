package portal

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mirkoSekulic/nvt-agent/protocol/eligibility"
)

const (
	testDynamicTemplateOne = "approved-one"
	testDynamicTemplateTwo = "approved-two"
	testEligibleValue      = "approved"
	testEligibilityGroups  = "groups"
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
		IssuerURL: "https://identity.example.test", ClientID: testOIDCClientID, CallbackPath: testOAuthCallbackPath,
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

func TestConfigValidatesOAuth2AuthorizationResponseIssuer(t *testing.T) {
	cfg := testConfig()
	cfg.Auth.OAuth2.AuthorizationResponseIssuer = "https://identity.example.test/oauth"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid authorization response issuer rejected: %v", err)
	}
	cfg.Auth.OAuth2.AuthorizationResponseIssuer = "http://identity.example.test/oauth"
	if err := cfg.Validate(); err == nil {
		t.Fatal("insecure authorization response issuer accepted")
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

func testDynamicConfig() Config {
	cfg := testConfig()
	cfg.Slots = nil
	cfg.RecoveryUpload.Enabled = false
	cfg.Auth.Eligibility = &eligibility.Policy{
		Default: eligibility.DefaultDeny,
		Rules: []eligibility.Rule{{
			ID: "dynamic-admission", Effect: eligibility.EffectAllow, Authenticated: true,
		}},
	}
	cfg.Dynamic = DynamicConfig{
		Enabled: true,
		Broker: DynamicBrokerConfig{
			URL: "https://nvt-broker.nvt.svc:7347", CAFile: "/var/run/nvt-broker/ca.crt",
			AssertionKeyFile: "/var/run/nvt-broker/assertion-key",
		},
		Templates: []DynamicCredentialTemplate{
			{Name: testDynamicTemplateOne, Label: "Approved one", Adapter: AdapterCodexOAuthFile},
			{Name: testDynamicTemplateTwo, Label: "Approved two", Adapter: AdapterClaudeOAuthFile},
		},
	}
	if err := cfg.Validate(); err != nil {
		panic(err)
	}
	return cfg
}

func TestDynamicConfigIsExplicitMutuallyExclusiveAndStrict(t *testing.T) {
	valid := testDynamicConfig()
	if valid.Dynamic.Broker.AssertionTTLSeconds != defaultAssertionTTL ||
		valid.Dynamic.Broker.EligibilityLeaseSeconds != valid.Auth.Session.MaxAgeSeconds ||
		valid.Dynamic.Broker.RequestTimeoutSeconds != defaultBrokerTimeout ||
		valid.Dynamic.Broker.MaxResponseBytes != defaultBrokerResponse {
		t.Fatal("dynamic broker defaults were not applied")
	}
	invalid := make([]Config, 0, 10)

	withSlot := testDynamicConfig()
	withSlot.Slots = testConfig().Slots[:1]
	invalid = append(invalid, withSlot)

	withoutEligibility := testDynamicConfig()
	withoutEligibility.Auth.Eligibility = nil
	invalid = append(invalid, withoutEligibility)

	insecureBroker := testDynamicConfig()
	insecureBroker.Dynamic.Broker.URL = "http://nvt-broker.nvt.svc:7347"
	invalid = append(invalid, insecureBroker)

	brokerPath := testDynamicConfig()
	brokerPath.Dynamic.Broker.URL += "/api"
	invalid = append(invalid, brokerPath)

	duplicateTemplate := testDynamicConfig()
	duplicateTemplate.Dynamic.Templates[1].Name = duplicateTemplate.Dynamic.Templates[0].Name
	invalid = append(invalid, duplicateTemplate)

	unsupportedAdapter := testDynamicConfig()
	unsupportedAdapter.Dynamic.Templates[0].Adapter = "caller-plugin"
	invalid = append(invalid, unsupportedAdapter)

	controlLabel := testDynamicConfig()
	controlLabel.Dynamic.Templates[0].Label = "unsafe\tlabel"
	invalid = append(invalid, controlLabel)

	oversizedCredential := testDynamicConfig()
	oversizedCredential.Enrollment.MaxOutputBytes = maxBrokerCredential + 1
	invalid = append(invalid, oversizedCredential)

	oversizedRecovery := testDynamicConfig()
	oversizedRecovery.RecoveryUpload.Enabled = true
	oversizedRecovery.MaxUploadBytes = maxBrokerCredential + 1
	invalid = append(invalid, oversizedRecovery)

	wrongPrefix := testDynamicConfig()
	wrongPrefix.PublicURL = "https://portal.example/other"
	invalid = append(invalid, wrongPrefix)

	overlongEligibilityLease := testDynamicConfig()
	overlongEligibilityLease.Dynamic.Broker.EligibilityLeaseSeconds =
		overlongEligibilityLease.Auth.Session.MaxAgeSeconds + 1
	invalid = append(invalid, overlongEligibilityLease)

	for index := range invalid {
		if err := invalid[index].Validate(); err == nil {
			t.Fatalf("unsafe dynamic config %d was accepted", index)
		}
	}

	disabledWithDynamicConfig := testConfig()
	disabledWithDynamicConfig.Dynamic.Templates = []DynamicCredentialTemplate{{
		Name: "dormant", Label: "Dormant", Adapter: AdapterClaudeOAuthFile,
	}}
	if err := disabledWithDynamicConfig.Validate(); err == nil {
		t.Fatal("disabled dynamic mode accepted ambiguous dormant templates")
	}
}

func TestStaticConfigCompatibilityRemainsSlotOwnedWithoutDynamicMode(t *testing.T) {
	cfg := testConfig()
	if cfg.Dynamic.Enabled || len(cfg.Dynamic.Templates) != 0 {
		t.Fatal("static fixture unexpectedly enabled dynamic mode")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("existing static config was rejected: %v", err)
	}
	auth := &Authenticator{cfg: cfg}
	if !auth.admits(Principal{Issuer: testIdentityIssuer, Subject: testAliceSubject}, nil) ||
		auth.admits(Principal{Issuer: testIdentityIssuer, Subject: "previously-unknown"}, nil) {
		t.Fatal("static exact-owner admission behavior changed")
	}
}
