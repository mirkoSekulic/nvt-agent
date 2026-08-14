// Package resolvedrun defines the provider-neutral desired-run contract shared
// by trusted local execution backends. It deliberately contains no Kubernetes,
// Docker, process-supervision, or credential-loading behavior.
package resolvedrun

import "encoding/json"

const (
	ContractVersion = "nvt.resolved-agent-run/v1"

	MaxDocumentBytes              = 1 << 20
	MaxProfiles                   = 128
	MaxWorkflows                  = 128
	MaxExecutionBackends          = 32
	MaxRetentionPolicies          = 32
	MaxRepositories               = 128
	MaxCredentialProviderMappings = 64
	MaxBrokerGrants               = 64
	MaxWorkspaceInstructionsBytes = 64 << 10
)

// Principal is the immutable authenticated owner. DisplayName is presentation
// data only and never participates in authorization or selection.
type Principal struct {
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	DisplayName string `json:"display_name,omitempty"`
}

// RuntimeCommand is executed directly. It is never parsed by a shell.
type RuntimeCommand struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
}

// Runtime contains only non-secret process and bootstrap configuration.
type Runtime struct {
	RuntimeCommand
	Resume   *RuntimeCommand   `json:"resume,omitempty"`
	Env      map[string]string `json:"env,omitempty"`
	Autonomy string            `json:"autonomy"`
	User     string            `json:"user"`
	Preseed  []PreseedFile     `json:"preseed,omitempty"`
}

// PreseedFile is administrator-authored, non-secret content placed under the
// agent home. Exactly one of Content and JSON must be set.
type PreseedFile struct {
	Path      string          `json:"path"`
	Mode      string          `json:"mode"`
	Overwrite bool            `json:"overwrite"`
	Content   *string         `json:"content,omitempty"`
	JSON      json.RawMessage `json:"json,omitempty"`
}

// Tools is the bounded administrator-owned runtime tool configuration.
type Tools struct {
	Packages        []string `json:"packages,omitempty"`
	Mise            []string `json:"mise,omitempty"`
	AdditionalPaths []string `json:"additional_paths,omitempty"`
	Shell           []string `json:"shell,omitempty"`
}

// CodeServer is the non-secret code-server configuration. Settings values are
// JSON so booleans and numbers are retained without Kubernetes types.
type CodeServer struct {
	Extensions                 []string                   `json:"extensions,omitempty"`
	Settings                   map[string]json.RawMessage `json:"settings,omitempty"`
	AgentTerminalOpenOnStartup bool                       `json:"agent_terminal_open_on_startup,omitempty"`
}

// Repository is an exact administrator-owned checkout. CredentialProvider is
// an alias into the selected profile's approved mappings.
type Repository struct {
	ID                 string `json:"id"`
	URL                string `json:"url"`
	Path               string `json:"path,omitempty"`
	CredentialProvider string `json:"credential_provider,omitempty"`
}

// CredentialProviderMapping binds a public runtime alias to one broker
// provider and an exact bounded set of repository patterns.
type CredentialProviderMapping struct {
	Name           string   `json:"name"`
	BrokerProvider string   `json:"broker_provider"`
	Repositories   []string `json:"repositories,omitempty"`
}

// Broker is a set of non-secret capability grants. It never carries provider
// configuration, tokens, headers, credential files, or credential values.
type Broker struct {
	Grants []BrokerGrant `json:"grants,omitempty"`
}

type BrokerGrant struct {
	Provider              string            `json:"provider"`
	Repositories          []string          `json:"repositories,omitempty"`
	Capabilities          []string          `json:"capabilities,omitempty"`
	Preparations          []string          `json:"preparations,omitempty"`
	Materialization       string            `json:"materialization,omitempty"`
	EgressHosts           []string          `json:"egress_hosts,omitempty"`
	Git                   bool              `json:"git,omitempty"`
	Permissions           map[string]string `json:"permissions,omitempty"`
	Quota                 *BrokerGrantQuota `json:"quota,omitempty"`
	AllowInsecureUpstream bool              `json:"allow_insecure_upstream,omitempty"`
}

type BrokerGrantQuota struct {
	Requests int64 `json:"requests"`
}

// Egress is trusted execution policy. PairedEgressRequired tells the backend
// to provision a distinct paired egress identity; it is not an identity or
// credential itself.
type Egress struct {
	Mode                 string `json:"mode"`
	Transport            string `json:"transport,omitempty"`
	Enforced             bool   `json:"enforced,omitempty"`
	ProxyProvider        string `json:"proxy_provider,omitempty"`
	PairedEgressRequired bool   `json:"paired_egress_required,omitempty"`
	AllowInsecureBroker  bool   `json:"allow_insecure_broker,omitempty"`
	MaxConcurrentTunnels int32  `json:"max_concurrent_tunnels,omitempty"`
}

// Resources uses backend-neutral quantity strings. A backend must reject any
// resource it cannot honor rather than silently dropping it.
type Resources struct {
	CPURequest    string `json:"cpu_request,omitempty"`
	CPULimit      string `json:"cpu_limit,omitempty"`
	MemoryRequest string `json:"memory_request,omitempty"`
	MemoryLimit   string `json:"memory_limit,omitempty"`
}

type WorkspaceInstructions struct {
	Profile  string `json:"profile,omitempty"`
	Workflow string `json:"workflow,omitempty"`
}

type Persistence struct {
	Workspace    bool `json:"workspace"`
	RuntimeState bool `json:"runtime_state"`
	DockerData   bool `json:"docker_data,omitempty"`
}

type TTL struct {
	ActiveSeconds       int64 `json:"active_seconds,omitempty"`
	CompletedSeconds    int64 `json:"completed_seconds,omitempty"`
	FailedSeconds       int64 `json:"failed_seconds,omitempty"`
	RunRetentionSeconds int64 `json:"run_retention_seconds,omitempty"`
}

// ExecutionBackend selects one trusted backend implementation by stable name
// and provider-neutral kind. Backend configuration remains outside this
// portable resolved value.
type ExecutionBackend struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type RetentionPolicy struct {
	Name        string      `json:"name"`
	Persistence Persistence `json:"persistence"`
	TTL         TTL         `json:"ttl"`
}

// ResolvedAgentRun is the complete immutable, non-secret desired value handed
// to a trusted local execution backend.
type ResolvedAgentRun struct {
	ContractVersion       string                      `json:"contract_version"`
	RunID                 string                      `json:"run_id"`
	Principal             Principal                   `json:"principal"`
	Profile               string                      `json:"profile"`
	Workflow              string                      `json:"workflow"`
	Image                 string                      `json:"image"`
	Runtime               Runtime                     `json:"runtime"`
	Repositories          []Repository                `json:"repositories,omitempty"`
	CredentialProviders   []CredentialProviderMapping `json:"credential_providers,omitempty"`
	Tools                 Tools                       `json:"tools"`
	CodeServer            CodeServer                  `json:"code_server"`
	Broker                Broker                      `json:"broker"`
	Egress                Egress                      `json:"egress"`
	WorkspaceInstructions WorkspaceInstructions       `json:"workspace_instructions"`
	Resources             Resources                   `json:"resources"`
	Persistence           Persistence                 `json:"persistence"`
	Retention             string                      `json:"retention"`
	TTL                   TTL                         `json:"ttl"`
	Execution             ExecutionBackend            `json:"execution"`
}

// PlatformDefaults are trusted lowest-precedence defaults. Profile pointers
// replace complete blocks; partial security-policy merging is intentionally not
// supported.
type PlatformDefaults struct {
	Image      string     `json:"image"`
	Runtime    Runtime    `json:"runtime"`
	Tools      Tools      `json:"tools"`
	CodeServer CodeServer `json:"code_server"`
	Resources  Resources  `json:"resources"`
}

// Profile is trusted administrator configuration. Protected provider, broker,
// egress, retention, and backend policy can be selected but never supplied by
// a LocalRunRequest.
type Profile struct {
	Name                  string                      `json:"name"`
	Image                 string                      `json:"image,omitempty"`
	Runtime               *Runtime                    `json:"runtime,omitempty"`
	Tools                 *Tools                      `json:"tools,omitempty"`
	CodeServer            *CodeServer                 `json:"code_server,omitempty"`
	Resources             *Resources                  `json:"resources,omitempty"`
	CredentialProviders   []CredentialProviderMapping `json:"credential_providers,omitempty"`
	Broker                Broker                      `json:"broker"`
	Egress                Egress                      `json:"egress"`
	WorkspaceInstructions string                      `json:"workspace_instructions,omitempty"`
	AllowedBackends       []string                    `json:"allowed_backends"`
	DefaultBackend        string                      `json:"default_backend"`
	AllowedRetentions     []string                    `json:"allowed_retentions"`
}

// Workflow is trusted administrator configuration and is the sole owner of
// repository checkout and workflow guidance.
type Workflow struct {
	Name                  string       `json:"name"`
	Repositories          []Repository `json:"repositories,omitempty"`
	WorkspaceInstructions string       `json:"workspace_instructions,omitempty"`
}

type TrustedConfiguration struct {
	Defaults          PlatformDefaults   `json:"defaults"`
	Profiles          []Profile          `json:"profiles"`
	Workflows         []Workflow         `json:"workflows"`
	ExecutionBackends []ExecutionBackend `json:"execution_backends"`
	RetentionPolicies []RetentionPolicy  `json:"retention_policies"`
}

// LocalRunRequest is the complete caller-controlled selection surface. Its
// strict decoder rejects every additional field.
type LocalRunRequest struct {
	RunID     string    `json:"run_id"`
	Principal Principal `json:"principal"`
	Profile   string    `json:"profile"`
	Workflow  string    `json:"workflow"`
	Retention string    `json:"retention"`
	Backend   string    `json:"backend,omitempty"`
}
