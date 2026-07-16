package producer

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"
)

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

func TestConfigPersistentWorkspace(t *testing.T) {
	cfg := validTestConfig()
	cfg.AgentRun.WorkspaceMode = "Persistent"
	cfg.AgentRun.WorkspaceSize = "20Gi"
	cfg.AgentRun.WorkspaceStorageClassName = "managed-csi"
	if err := cfg.ApplyDefaultsAndValidate(); err != nil {
		t.Fatalf("validate persistent workspace: %v", err)
	}
	workspace, err := configuredAgentRunWorkspace(cfg.AgentRun)
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Size == nil || workspace.Size.Cmp(resource.MustParse("20Gi")) != 0 || workspace.StorageClassName != "managed-csi" {
		t.Fatalf("workspace = %#v", workspace)
	}
}

func TestConfigRejectsInvalidWorkspaceCombinations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AgentRunConfig)
		want   string
	}{
		{name: "unknown mode", mutate: func(config *AgentRunConfig) { config.WorkspaceMode = "Shared" }, want: "must be Ephemeral or Persistent"},
		{name: "persistent missing size", mutate: func(config *AgentRunConfig) { config.WorkspaceMode = "Persistent" }, want: "workspaceSize is required"},
		{name: "malformed size", mutate: func(config *AgentRunConfig) { config.WorkspaceMode, config.WorkspaceSize = "Persistent", "twenty" }, want: "positive Kubernetes resource quantity"},
		{name: "zero size", mutate: func(config *AgentRunConfig) { config.WorkspaceMode, config.WorkspaceSize = "Persistent", "0" }, want: "positive Kubernetes resource quantity"},
		{name: "ephemeral size", mutate: func(config *AgentRunConfig) { config.WorkspaceMode, config.WorkspaceSize = "Ephemeral", "1Gi" }, want: "require workspaceMode Persistent"},
		{name: "invalid storage class", mutate: func(config *AgentRunConfig) {
			config.WorkspaceMode, config.WorkspaceSize, config.WorkspaceStorageClassName = "Persistent", "1Gi", " Managed_CSI"
		}, want: "normalized DNS subdomain"},
		{name: "legacy broker grant", mutate: func(config *AgentRunConfig) {
			config.WorkspaceMode, config.WorkspaceSize = "Persistent", "1Gi"
			config.BrokerGrants = []BrokerGrant{{Provider: "github-main"}}
		}, want: "file-bundle brokerGrants"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validTestConfig()
			test.mutate(&cfg.AgentRun)
			err := cfg.ApplyDefaultsAndValidate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
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
