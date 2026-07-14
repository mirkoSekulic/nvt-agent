package producer

import "testing"

func TestConfigDefaultOperatorCallbackBaseURL(t *testing.T) {
	cfg := Config{
		Repositories: []Repository{{Owner: "acme", Name: "widget"}},
		GitHubApp: GitHubAppConfig{
			AppID:          123,
			InstallationID: 456,
			PrivateKeyPath: "/tmp/key.pem",
		},
		AgentRun: AgentRunConfig{
			Namespace:    "nvt",
			RuntimeImage: "runtime:latest",
		},
	}
	if err := cfg.ApplyDefaultsAndValidate(); err != nil {
		t.Fatal(err)
	}
	if cfg.OperatorCallbackBaseURL != defaultOperatorCallbackBaseURL {
		t.Fatalf("OperatorCallbackBaseURL = %q, want %q", cfg.OperatorCallbackBaseURL, defaultOperatorCallbackBaseURL)
	}
}

func TestConfigDefaultIdempotencyScope(t *testing.T) {
	cfg := validTestConfig()
	if err := cfg.ApplyDefaultsAndValidate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Idempotency.Scope != IdempotencyScopeIssue {
		t.Fatalf("Idempotency.Scope = %q, want %q", cfg.Idempotency.Scope, IdempotencyScopeIssue)
	}
}

func TestConfigDefaultSubmissionScheduleAdmission(t *testing.T) {
	cfg := validTestConfig()
	if err := cfg.ApplyDefaultsAndValidate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Submission.Mode != SubmissionModeScheduleAdmission ||
		cfg.Submission.AdmissionMode != AdmissionModeLegacy ||
		cfg.Submission.AdmissionBaseURL != defaultOperatorCallbackBaseURL ||
		cfg.Submission.ScheduleNamespace != "nvt" ||
		cfg.Submission.ScheduleName != defaultScheduleName {
		t.Fatalf("unexpected submission defaults: %#v", cfg.Submission)
	}
}

func TestConfigAcceptsProfiledAdmissionWithoutAgentRunSecurityConfig(t *testing.T) {
	cfg := validTestConfig()
	cfg.AgentRun = AgentRunConfig{}
	cfg.Submission = SubmissionConfig{
		Mode:               SubmissionModeScheduleAdmission,
		AdmissionMode:      AdmissionModeProfiled,
		AdmissionTokenFile: "/var/run/secrets/nvt-operator/token",
		ScheduleNamespace:  "nvt",
		ScheduleName:       "default",
	}
	if err := cfg.ApplyDefaultsAndValidate(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigRejectsInvalidProfiledAdmissionConfiguration(t *testing.T) {
	for _, test := range []struct {
		name      string
		mode      SubmissionMode
		tokenFile string
		admission AdmissionMode
	}{
		{name: "profiled direct", mode: SubmissionModeDirect, admission: AdmissionModeProfiled, tokenFile: "/token"},
		{name: "missing token", mode: SubmissionModeScheduleAdmission, admission: AdmissionModeProfiled},
		{name: "relative token", mode: SubmissionModeScheduleAdmission, admission: AdmissionModeProfiled, tokenFile: "token"},
		{name: "unknown admission mode", mode: SubmissionModeScheduleAdmission, admission: "automatic", tokenFile: "/token"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := validTestConfig()
			cfg.Submission = SubmissionConfig{
				Mode: test.mode, AdmissionMode: test.admission, AdmissionTokenFile: test.tokenFile,
				ScheduleNamespace: "nvt", ScheduleName: "default",
			}
			if err := cfg.ApplyDefaultsAndValidate(); err == nil {
				t.Fatal("expected configuration to fail")
			}
		})
	}
}

func TestConfigAcceptsCommentIdempotencyScope(t *testing.T) {
	cfg := validTestConfig()
	cfg.Idempotency.Scope = IdempotencyScopeComment
	if err := cfg.ApplyDefaultsAndValidate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Idempotency.Scope != IdempotencyScopeComment {
		t.Fatalf("Idempotency.Scope = %q, want %q", cfg.Idempotency.Scope, IdempotencyScopeComment)
	}
}

func TestConfigRejectsInvalidIdempotencyScope(t *testing.T) {
	cfg := validTestConfig()
	cfg.Idempotency.Scope = "repo"
	err := cfg.ApplyDefaultsAndValidate()
	if err == nil {
		t.Fatal("expected invalid idempotency scope to fail")
	}
	want := `idempotency.scope must be one of "issue" or "comment"`
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}
}

func TestConfigRejectsNegativeAgentRunTTL(t *testing.T) {
	cfg := validTestConfig()
	negative := int64(-1)
	cfg.AgentRun.TTL.CompletedTTLSeconds = &negative
	err := cfg.ApplyDefaultsAndValidate()
	if err == nil {
		t.Fatal("expected negative TTL to fail")
	}
	want := "agentRun.ttl.completedTTLSeconds must be greater than or equal to 0"
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}
}

func validTestConfig() Config {
	return Config{
		Repositories: []Repository{{Owner: "acme", Name: "widget"}},
		GitHubApp: GitHubAppConfig{
			AppID:          123,
			InstallationID: 456,
			PrivateKeyPath: "/tmp/key.pem",
		},
		AgentRun: AgentRunConfig{
			Namespace:    "nvt",
			RuntimeImage: "runtime:latest",
		},
	}
}
