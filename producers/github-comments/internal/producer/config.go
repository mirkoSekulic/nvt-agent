//nolint:cyclop,err113,gocognit,gocyclo,gosec,modernize,govet // Config validation keeps field-specific errors and reads an operator-provided path.
package producer

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

const (
	defaultCommandPrefix           = "/nvtagent"
	defaultRuntimeType             = "codex"
	defaultAutonomy                = "trusted-local"
	defaultWorkspaceMode           = "Ephemeral"
	defaultOperatorCallbackBaseURL = "http://nvt-operator:8082"
	defaultSubmissionMode          = SubmissionModeScheduleAdmission
	defaultAdmissionMode           = AdmissionModeLegacy
	defaultScheduleName            = "default"
)

type IdempotencyScope string
type SubmissionMode string
type AdmissionMode string

const (
	IdempotencyScopeIssue   IdempotencyScope = "issue"
	IdempotencyScopeComment IdempotencyScope = "comment"

	SubmissionModeDirect            SubmissionMode = "direct"
	SubmissionModeScheduleAdmission SubmissionMode = "scheduleAdmission"

	AdmissionModeLegacy   AdmissionMode = "legacy"
	AdmissionModeProfiled AdmissionMode = "profiled"
)

type Config struct {
	CommandPrefixes         []string          `json:"commandPrefixes,omitempty"`
	AllowedAuthors          []string          `json:"allowedAuthors,omitempty"`
	PollInterval            Duration          `json:"pollInterval,omitempty"`
	Repositories            []Repository      `json:"repositories"`
	GitHubApp               GitHubAppConfig   `json:"githubApp"`
	State                   StateConfig       `json:"state,omitempty"`
	AgentRun                AgentRunConfig    `json:"agentRun"`
	AgentConfig             map[string]any    `json:"agentConfig,omitempty"`
	Idempotency             IdempotencyConfig `json:"idempotency,omitempty"`
	Submission              SubmissionConfig  `json:"submission,omitempty"`
	OperatorCallbackBaseURL string            `json:"operatorCallbackBaseURL,omitempty"`
	InitialSince            string            `json:"initialSince,omitempty"`
	GitHubAPIBaseURL        string            `json:"githubAPIBaseURL,omitempty"`
	UserAgent               string            `json:"userAgent,omitempty"`
}

type Repository struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

type GitHubAppConfig struct {
	AppID               int64  `json:"appID"`
	InstallationID      int64  `json:"installationID"`
	PrivateKeyPath      string `json:"privateKeyPath,omitempty"`
	PrivateKey          string `json:"privateKey,omitempty"`
	PrivateKeyBase64    string `json:"privateKeyBase64,omitempty"`
	PrivateKeyEnv       string `json:"privateKeyEnv,omitempty"`
	PrivateKeyBase64Env string `json:"privateKeyBase64Env,omitempty"`
}

type StateConfig struct {
	SQLitePath string `json:"sqlitePath,omitempty"`
}

type IdempotencyConfig struct {
	Scope IdempotencyScope `json:"scope,omitempty"`
}

type SubmissionConfig struct {
	Mode               SubmissionMode `json:"mode,omitempty"`
	AdmissionMode      AdmissionMode  `json:"admissionMode,omitempty"`
	AdmissionBaseURL   string         `json:"admissionBaseURL,omitempty"`
	AdmissionTokenFile string         `json:"admissionTokenFile,omitempty"`
	ScheduleNamespace  string         `json:"scheduleNamespace,omitempty"`
	ScheduleName       string         `json:"scheduleName,omitempty"`
	// Workflow is an optional static, non-secret workflow profile name for
	// profiled schedule admission.
	Workflow string `json:"workflow,omitempty"`
}

type AgentRunConfig struct {
	Namespace                 string        `json:"namespace"`
	RuntimeImage              string        `json:"runtimeImage"`
	RuntimeType               string        `json:"runtimeType,omitempty"`
	RuntimeAutonomy           string        `json:"runtimeAutonomy,omitempty"`
	RuntimeClassName          string        `json:"runtimeClassName,omitempty"`
	RuntimeAuthSecret         string        `json:"runtimeAuthSecret,omitempty"`
	RuntimeAuthMountPath      string        `json:"runtimeAuthMountPath,omitempty"`
	WorkspaceMode             string        `json:"workspaceMode,omitempty"`
	WorkspaceSize             string        `json:"workspaceSize,omitempty"`
	WorkspaceDockerSize       string        `json:"workspaceDockerSize,omitempty"`
	WorkspaceStorageClassName string        `json:"workspaceStorageClassName,omitempty"`
	BrokerGrants              []BrokerGrant `json:"brokerGrants,omitempty"`
	TTL                       AgentRunTTL   `json:"ttl,omitempty"`
}

type AgentRunTTL struct {
	ActiveDeadlineSeconds *int64 `json:"activeDeadlineSeconds,omitempty"`
	CompletedTTLSeconds   *int64 `json:"completedTTLSeconds,omitempty"`
	FailedTTLSeconds      *int64 `json:"failedTTLSeconds,omitempty"`
	RunRetentionSeconds   *int64 `json:"runRetentionSeconds,omitempty"`
}

type BrokerGrant struct {
	Provider     string   `json:"provider"`
	Repositories []string `json:"repositories"`
}

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err == nil {
		parsed, parseErr := time.ParseDuration(raw)
		if parseErr != nil {
			return fmt.Errorf("parse duration: %w", parseErr)
		}
		d.Duration = parsed
		return nil
	}
	var seconds float64
	if err := json.Unmarshal(data, &seconds); err != nil {
		return fmt.Errorf("parse duration seconds: %w", err)
	}
	d.Duration = time.Duration(seconds * float64(time.Second))
	return nil
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.ApplyDefaultsAndValidate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) ApplyDefaultsAndValidate() error {
	if len(c.CommandPrefixes) == 0 {
		c.CommandPrefixes = []string{defaultCommandPrefix}
	}
	if len(c.AllowedAuthors) == 0 {
		c.AllowedAuthors = []string{"*"}
	}
	if c.PollInterval.Duration == 0 {
		c.PollInterval.Duration = 30 * time.Second
	}
	if c.GitHubAPIBaseURL == "" {
		c.GitHubAPIBaseURL = "https://api.github.com"
	}
	if c.UserAgent == "" {
		c.UserAgent = "nvt-github-comments-producer"
	}
	if c.OperatorCallbackBaseURL == "" {
		c.OperatorCallbackBaseURL = defaultOperatorCallbackBaseURL
	}
	if c.Submission.Mode == "" {
		c.Submission.Mode = defaultSubmissionMode
	}
	if c.Submission.AdmissionMode == "" {
		c.Submission.AdmissionMode = defaultAdmissionMode
	}
	if c.Submission.AdmissionBaseURL == "" {
		c.Submission.AdmissionBaseURL = defaultOperatorCallbackBaseURL
	}
	if c.Submission.ScheduleNamespace == "" {
		c.Submission.ScheduleNamespace = c.AgentRun.Namespace
	}
	if c.Submission.ScheduleName == "" {
		c.Submission.ScheduleName = defaultScheduleName
	}
	if c.Idempotency.Scope == "" {
		c.Idempotency.Scope = IdempotencyScopeIssue
	}
	if c.State.SQLitePath == "" {
		c.State.SQLitePath = "/tmp/nvt-github-comments-state.db"
	}
	if c.AgentRun.RuntimeType == "" {
		c.AgentRun.RuntimeType = defaultRuntimeType
	}
	if c.AgentRun.RuntimeAutonomy == "" {
		c.AgentRun.RuntimeAutonomy = defaultAutonomy
	}
	if c.AgentRun.WorkspaceMode == "" {
		c.AgentRun.WorkspaceMode = defaultWorkspaceMode
	}
	if _, err := configuredAgentRunWorkspace(c.AgentRun); err != nil {
		return err
	}
	if len(c.Repositories) == 0 {
		return errors.New("repositories is required")
	}
	for i, prefix := range c.CommandPrefixes {
		if prefix == "" {
			return fmt.Errorf("commandPrefixes[%d] is required", i)
		}
	}
	for i, author := range c.AllowedAuthors {
		if author == "" {
			return fmt.Errorf("allowedAuthors[%d] is required", i)
		}
	}
	for i, repo := range c.Repositories {
		if repo.Owner == "" || repo.Name == "" {
			return fmt.Errorf("repositories[%d].owner and name are required", i)
		}
	}
	if c.Idempotency.Scope != IdempotencyScopeIssue && c.Idempotency.Scope != IdempotencyScopeComment {
		return fmt.Errorf("idempotency.scope must be one of %q or %q", IdempotencyScopeIssue, IdempotencyScopeComment)
	}
	if c.Submission.Mode != SubmissionModeDirect && c.Submission.Mode != SubmissionModeScheduleAdmission {
		return fmt.Errorf("submission.mode must be one of %q or %q", SubmissionModeDirect, SubmissionModeScheduleAdmission)
	}
	if c.Submission.AdmissionMode != AdmissionModeLegacy && c.Submission.AdmissionMode != AdmissionModeProfiled {
		return fmt.Errorf("submission.admissionMode must be one of %q or %q", AdmissionModeLegacy, AdmissionModeProfiled)
	}
	if c.Submission.AdmissionMode == AdmissionModeProfiled && c.Submission.Mode != SubmissionModeScheduleAdmission {
		return errors.New("submission.admissionMode profiled requires submission.mode scheduleAdmission")
	}
	if c.Submission.Workflow != "" {
		if c.Submission.Mode != SubmissionModeScheduleAdmission || c.Submission.AdmissionMode != AdmissionModeProfiled {
			return errors.New("submission.workflow requires profiled scheduleAdmission mode")
		}
		if len(utilvalidation.IsDNS1123Label(c.Submission.Workflow)) != 0 {
			return errors.New("submission.workflow must be a normalized DNS label")
		}
	}
	if c.GitHubApp.AppID == 0 {
		return errors.New("githubApp.appID is required")
	}
	if c.GitHubApp.InstallationID == 0 {
		return errors.New("githubApp.installationID is required")
	}
	if c.Submission.ScheduleNamespace == "" {
		return errors.New("submission.scheduleNamespace is required")
	}
	if c.Submission.ScheduleName == "" {
		return errors.New("submission.scheduleName is required")
	}
	if c.Submission.Mode == SubmissionModeScheduleAdmission && c.Submission.AdmissionBaseURL == "" {
		return errors.New("submission.admissionBaseURL is required when submission.mode is scheduleAdmission")
	}
	if c.Submission.AdmissionMode == AdmissionModeProfiled {
		if c.Submission.AdmissionTokenFile == "" {
			return errors.New("submission.admissionTokenFile is required in profiled admission mode")
		}
		if !filepath.IsAbs(c.Submission.AdmissionTokenFile) {
			return errors.New("submission.admissionTokenFile must be an absolute path")
		}
	} else {
		if c.AgentRun.Namespace == "" {
			return errors.New("agentRun.namespace is required")
		}
		if c.AgentRun.RuntimeImage == "" {
			return errors.New("agentRun.runtimeImage is required")
		}
	}
	if err := validateNonNegativeInt64(c.AgentRun.TTL.ActiveDeadlineSeconds, "agentRun.ttl.activeDeadlineSeconds"); err != nil {
		return err
	}
	if err := validateNonNegativeInt64(c.AgentRun.TTL.CompletedTTLSeconds, "agentRun.ttl.completedTTLSeconds"); err != nil {
		return err
	}
	if err := validateNonNegativeInt64(c.AgentRun.TTL.FailedTTLSeconds, "agentRun.ttl.failedTTLSeconds"); err != nil {
		return err
	}
	if err := validateNonNegativeInt64(c.AgentRun.TTL.RunRetentionSeconds, "agentRun.ttl.runRetentionSeconds"); err != nil {
		return err
	}
	return nil
}

func configuredAgentRunWorkspace(config AgentRunConfig) (nvtv1alpha1.AgentRunWorkspace, error) {
	mode := config.WorkspaceMode
	if mode == "" {
		mode = defaultWorkspaceMode
	}
	workspace := nvtv1alpha1.AgentRunWorkspace{Mode: nvtv1alpha1.AgentRunWorkspaceMode(mode)}
	switch workspace.Mode {
	case nvtv1alpha1.AgentRunWorkspaceEphemeral:
		if config.WorkspaceSize != "" || config.WorkspaceDockerSize != "" || config.WorkspaceStorageClassName != "" {
			return nvtv1alpha1.AgentRunWorkspace{}, errors.New("agentRun.workspaceSize, workspaceDockerSize, and workspaceStorageClassName require workspaceMode Persistent")
		}
	case nvtv1alpha1.AgentRunWorkspacePersistent:
		if config.WorkspaceSize == "" {
			return nvtv1alpha1.AgentRunWorkspace{}, errors.New("agentRun.workspaceSize is required when workspaceMode is Persistent")
		}
		quantity, err := resource.ParseQuantity(config.WorkspaceSize)
		if err != nil || quantity.Sign() <= 0 {
			return nvtv1alpha1.AgentRunWorkspace{}, errors.New("agentRun.workspaceSize must be a positive Kubernetes resource quantity")
		}
		workspace.Size = &quantity
		if config.WorkspaceDockerSize != "" {
			dockerQuantity, err := resource.ParseQuantity(config.WorkspaceDockerSize)
			minimum := resource.MustParse("1Gi")
			maximum := resource.MustParse("1Ti")
			if err != nil || dockerQuantity.Cmp(minimum) < 0 || dockerQuantity.Cmp(maximum) > 0 {
				return nvtv1alpha1.AgentRunWorkspace{}, errors.New("agentRun.workspaceDockerSize must be a Kubernetes resource quantity between 1Gi and 1Ti")
			}
			workspace.DockerSize = &dockerQuantity
		}
		if config.WorkspaceStorageClassName != "" {
			if strings.TrimSpace(config.WorkspaceStorageClassName) != config.WorkspaceStorageClassName ||
				len(utilvalidation.IsDNS1123Subdomain(config.WorkspaceStorageClassName)) != 0 {
				return nvtv1alpha1.AgentRunWorkspace{}, errors.New("agentRun.workspaceStorageClassName must be a normalized DNS subdomain")
			}
			workspace.StorageClassName = config.WorkspaceStorageClassName
		}
		if len(config.BrokerGrants) != 0 {
			return nvtv1alpha1.AgentRunWorkspace{}, errors.New("agentRun.workspaceMode Persistent is incompatible with legacy file-bundle brokerGrants")
		}
	default:
		return nvtv1alpha1.AgentRunWorkspace{}, errors.New("agentRun.workspaceMode must be Ephemeral or Persistent")
	}
	return workspace, nil
}

func validateNonNegativeInt64(value *int64, field string) error {
	if value == nil || *value >= 0 {
		return nil
	}
	return fmt.Errorf("%s must be greater than or equal to 0", field)
}

func AgentConfigJSON(config map[string]any) (apiextensionsv1.JSON, error) {
	if config == nil {
		config = map[string]any{}
	}
	data, err := json.Marshal(config)
	if err != nil {
		return apiextensionsv1.JSON{}, fmt.Errorf("marshal agent config: %w", err)
	}
	return apiextensionsv1.JSON{Raw: data}, nil
}
