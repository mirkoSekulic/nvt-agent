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
