package producer

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"
)

const testDevelopmentWorkflow = "development"

func TestConfigValidatesCommandWorkflowMapping(t *testing.T) {
	cfg := validTestConfig()
	cfg.Submission = SubmissionConfig{Mode: SubmissionModeScheduleAdmission, AdmissionMode: AdmissionModeProfiled, AdmissionTokenFile: "/token", CommandWorkflows: map[CommandIntent]string{CommandIntentReview: "review-pr", CommandIntentRun: "generic-run"}}
	if err := cfg.ApplyDefaultsAndValidate(); err != nil {
		t.Fatal(err)
	}
	for command, workflow := range map[CommandIntent]string{"help": "review-pr", CommandIntentReview: "Bad_Name"} {
		invalid := validTestConfig()
		invalid.Submission = cfg.Submission
		invalid.Submission.CommandWorkflows = map[CommandIntent]string{command: workflow}
		if err := invalid.ApplyDefaultsAndValidate(); err == nil {
			t.Fatalf("accepted mapping %q: %q", command, workflow)
		}
	}
}

const testAcceptedReactionField = "accepted"

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
		cfg.Submission.ScheduleName != defaultScheduleName || cfg.Submission.Workflow != "" {
		t.Fatalf("unexpected submission defaults: %#v", cfg.Submission)
	}
}

func TestConfigDefaultsSchedulingReactionsEnabled(t *testing.T) {
	cfg := validTestConfig()
	if err := cfg.ApplyDefaultsAndValidate(); err != nil {
		t.Fatal(err)
	}
	if !cfg.SchedulingReactions.IsEnabled() || cfg.SchedulingReactions.Accepted != "+1" ||
		cfg.SchedulingReactions.Rejected != "-1" {
		t.Fatalf("unexpected scheduling reaction defaults: %#v", cfg.SchedulingReactions)
	}
}

func TestConfigAllowsSchedulingReactionsOptOutAndSupportedNames(t *testing.T) {
	disabled := false
	for _, reaction := range []string{"+1", "-1", "laugh", "confused", "heart", "hooray", "rocket", "eyes"} {
		cfg := validTestConfig()
		cfg.SchedulingReactions = SchedulingReactionsConfig{
			Enabled:  &disabled,
			Accepted: reaction,
			Rejected: reaction,
		}
		if err := cfg.ApplyDefaultsAndValidate(); err != nil {
			t.Fatalf("reaction %q: %v", reaction, err)
		}
		if cfg.SchedulingReactions.IsEnabled() {
			t.Fatalf("reaction %q unexpectedly enabled", reaction)
		}
	}
}

func TestConfigRejectsUnsupportedSchedulingReaction(t *testing.T) {
	for _, field := range []string{testAcceptedReactionField, "rejected"} {
		cfg := validTestConfig()
		cfg.SchedulingReactions.Accepted = "+1"
		cfg.SchedulingReactions.Rejected = "-1"
		if field == testAcceptedReactionField {
			cfg.SchedulingReactions.Accepted = "thumbsup"
		} else {
			cfg.SchedulingReactions.Rejected = "thumbsdown"
		}
		err := cfg.ApplyDefaultsAndValidate()
		if err == nil || !strings.Contains(err.Error(), "schedulingReactions."+field) {
			t.Fatalf("field %s error = %v", field, err)
		}
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

func TestSubmissionBackendDefaultsToKubernetesAndLocalRequiresProfiledAdmission(t *testing.T) {
	defaultConfig := validTestConfig()
	if err := defaultConfig.ApplyDefaultsAndValidate(); err != nil {
		t.Fatal(err)
	}
	if defaultConfig.Submission.Backend != SubmissionBackendKubernetes {
		t.Fatalf("default backend = %q", defaultConfig.Submission.Backend)
	}

	local := validTestConfig()
	local.AgentRun = AgentRunConfig{}
	local.Submission = SubmissionConfig{
		Mode: SubmissionModeScheduleAdmission, Backend: SubmissionBackendLocal, AdmissionMode: AdmissionModeProfiled,
		AdmissionBaseURL: "http://local-controller:7480", AdmissionTokenFile: "/run/secrets/local-controller/token",
		ScheduleNamespace: "unused", ScheduleName: "github", Workflow: testDevelopmentWorkflow,
	}
	if err := local.ApplyDefaultsAndValidate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){
		func(value *Config) { value.Submission.Mode = SubmissionModeDirect },
		func(value *Config) { value.Submission.AdmissionMode = AdmissionModeLegacy },
	} {
		invalid := local
		mutate(&invalid)
		if err := invalid.ApplyDefaultsAndValidate(); err == nil {
			t.Fatal("unsafe local submission mode accepted")
		}
	}
}

func TestConfigAcceptsStaticProfiledWorkflow(t *testing.T) {
	cfg := validTestConfig()
	cfg.AgentRun = AgentRunConfig{}
	cfg.Submission = SubmissionConfig{
		Mode: SubmissionModeScheduleAdmission, AdmissionMode: AdmissionModeProfiled,
		AdmissionTokenFile: "/var/run/secrets/nvt-operator/token", ScheduleNamespace: "nvt", ScheduleName: "default",
		Workflow: "review-pr",
	}
	if err := cfg.ApplyDefaultsAndValidate(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigRejectsInvalidStaticWorkflow(t *testing.T) {
	for _, test := range []struct {
		name      string
		workflow  string
		mode      SubmissionMode
		admission AdmissionMode
	}{
		{name: "legacy", workflow: "review-pr", mode: SubmissionModeScheduleAdmission, admission: AdmissionModeLegacy},
		{name: "direct", workflow: "review-pr", mode: SubmissionModeDirect, admission: AdmissionModeLegacy},
		{name: "not normalized", workflow: "Review PR", mode: SubmissionModeScheduleAdmission, admission: AdmissionModeProfiled},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := validTestConfig()
			cfg.Submission = SubmissionConfig{
				Mode: test.mode, AdmissionMode: test.admission, AdmissionTokenFile: "/token",
				ScheduleNamespace: "nvt", ScheduleName: "default", Workflow: test.workflow,
			}
			if err := cfg.ApplyDefaultsAndValidate(); err == nil {
				t.Fatal("expected invalid static workflow configuration")
			}
		})
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
		{name: "ephemeral Docker size", mutate: func(config *AgentRunConfig) { config.WorkspaceDockerSize = "20Gi" }, want: "require workspaceMode Persistent"},
		{name: "small Docker size", mutate: func(config *AgentRunConfig) {
			config.WorkspaceMode, config.WorkspaceSize, config.WorkspaceDockerSize = "Persistent", "5Gi", "512Mi"
		}, want: "between 1Gi and 1Ti"},
		{name: "large Docker size", mutate: func(config *AgentRunConfig) {
			config.WorkspaceMode, config.WorkspaceSize, config.WorkspaceDockerSize = "Persistent", "5Gi", "2Ti"
		}, want: "between 1Gi and 1Ti"},
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
