//nolint:cyclop,err113,gocognit,gocyclo,gosec,modernize,govet // Config validation keeps field-specific errors and reads an operator-provided path.
package producer

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

const (
	defaultCommandPrefix = "/nvtagent"
	defaultRuntimeType   = "codex"
	defaultAutonomy      = "trusted-local"
	defaultWorkspaceMode = "Ephemeral"
)

type Config struct {
	CommandPrefixes  []string        `json:"commandPrefixes,omitempty"`
	AllowedAuthors   []string        `json:"allowedAuthors,omitempty"`
	PollInterval     Duration        `json:"pollInterval,omitempty"`
	Repositories     []Repository    `json:"repositories"`
	GitHubApp        GitHubAppConfig `json:"githubApp"`
	State            StateConfig     `json:"state,omitempty"`
	AgentRun         AgentRunConfig  `json:"agentRun"`
	AgentConfig      map[string]any  `json:"agentConfig,omitempty"`
	InitialSince     string          `json:"initialSince,omitempty"`
	GitHubAPIBaseURL string          `json:"githubAPIBaseURL,omitempty"`
	UserAgent        string          `json:"userAgent,omitempty"`
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

type AgentRunConfig struct {
	Namespace            string        `json:"namespace"`
	RuntimeImage         string        `json:"runtimeImage"`
	RuntimeType          string        `json:"runtimeType,omitempty"`
	RuntimeAutonomy      string        `json:"runtimeAutonomy,omitempty"`
	RuntimeClassName     string        `json:"runtimeClassName,omitempty"`
	RuntimeAuthSecret    string        `json:"runtimeAuthSecret,omitempty"`
	RuntimeAuthMountPath string        `json:"runtimeAuthMountPath,omitempty"`
	WorkspaceMode        string        `json:"workspaceMode,omitempty"`
	BrokerGrants         []BrokerGrant `json:"brokerGrants,omitempty"`
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
	if c.GitHubApp.AppID == 0 {
		return errors.New("githubApp.appID is required")
	}
	if c.GitHubApp.InstallationID == 0 {
		return errors.New("githubApp.installationID is required")
	}
	if c.AgentRun.Namespace == "" {
		return errors.New("agentRun.namespace is required")
	}
	if c.AgentRun.RuntimeImage == "" {
		return errors.New("agentRun.runtimeImage is required")
	}
	return nil
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
