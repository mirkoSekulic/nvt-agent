package producer

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

const defaultCommandPrefix = "/nvtagent"

type Config struct {
	CommandPrefixes  []string        `json:"commandPrefixes,omitempty"`
	PollInterval     Duration        `json:"pollInterval,omitempty"`
	Repositories     []Repository    `json:"repositories"`
	GitHubApp        GitHubAppConfig `json:"githubApp"`
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
			return parseErr
		}
		d.Duration = parsed
		return nil
	}
	var seconds float64
	if err := json.Unmarshal(data, &seconds); err != nil {
		return err
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
	if c.PollInterval.Duration == 0 {
		c.PollInterval.Duration = 30 * time.Second
	}
	if c.GitHubAPIBaseURL == "" {
		c.GitHubAPIBaseURL = "https://api.github.com"
	}
	if c.UserAgent == "" {
		c.UserAgent = "nvt-github-comments-producer"
	}
	if c.AgentRun.RuntimeType == "" {
		c.AgentRun.RuntimeType = "codex"
	}
	if c.AgentRun.RuntimeAutonomy == "" {
		c.AgentRun.RuntimeAutonomy = "trusted-local"
	}
	if c.AgentRun.WorkspaceMode == "" {
		c.AgentRun.WorkspaceMode = "Ephemeral"
	}
	if len(c.Repositories) == 0 {
		return fmt.Errorf("repositories is required")
	}
	for i, prefix := range c.CommandPrefixes {
		if prefix == "" {
			return fmt.Errorf("commandPrefixes[%d] is required", i)
		}
	}
	for i, repo := range c.Repositories {
		if repo.Owner == "" || repo.Name == "" {
			return fmt.Errorf("repositories[%d].owner and name are required", i)
		}
	}
	if c.GitHubApp.AppID == 0 {
		return fmt.Errorf("githubApp.appID is required")
	}
	if c.GitHubApp.InstallationID == 0 {
		return fmt.Errorf("githubApp.installationID is required")
	}
	if c.AgentRun.Namespace == "" {
		return fmt.Errorf("agentRun.namespace is required")
	}
	if c.AgentRun.RuntimeImage == "" {
		return fmt.Errorf("agentRun.runtimeImage is required")
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
