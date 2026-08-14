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
	MaxAgentConfigBytes           = 256 << 10
	MaxPromptBytes                = 64 << 10
)

// Principal is the immutable authenticated owner. DisplayName is presentation
// data only and never participates in authorization or selection.
type Principal struct {
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	DisplayName string `json:"display_name,omitempty"`
}

// Runtime contains the runtime identity and trusted execution controls. The
// direct process command, resume command, preseed, tools, code-server, plugins,
// and exposure configuration live in the bounded AgentConfig object.
type Runtime struct {
	Type      string            `json:"type"`
	Autonomy  string            `json:"autonomy"`
	User      string            `json:"user"`
	Container *RuntimeContainer `json:"container,omitempty"`
	Docker    *RuntimeDocker    `json:"docker,omitempty"`
}

type RuntimeContainer struct {
	Capabilities []string `json:"capabilities,omitempty"`
}

type RuntimeDocker struct {
	KernelLogDevice  bool            `json:"kernel_log_device,omitempty"`
	RequiredNetworks []DockerNetwork `json:"required_networks,omitempty"`
}

type DockerNetwork struct {
	Name   string `json:"name"`
	Subnet string `json:"subnet"`
}

// Repository is an exact administrator-owned checkout. CredentialProvider is
// an alias into the selected profile's approved mappings.
type Repository struct {
	CheckoutTarget     string `json:"checkout_target"`
	BrokerRepository   string `json:"broker_repository"`
	URL                string `json:"url"`
	Path               string `json:"path,omitempty"`
	CredentialProvider string `json:"credential_provider,omitempty"`
}

// CredentialProviderMapping binds a public runtime alias to one broker
// provider and an exact bounded set of repository patterns.
type CredentialProviderMapping struct {
	Name           string   `json:"name"`
	BrokerProvider string   `json:"broker_provider"`
	MatchTargets   []string `json:"match_targets,omitempty"`
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

type Lifecycle struct {
	CompleteOn []string `json:"complete_on,omitempty"`
	FailOn     []string `json:"fail_on,omitempty"`
}

// AgentConfigBindings are non-secret, backend-provisioned endpoints needed to
// render the authoritative egress policy into the generic runtime config. They
// are deliberately outside ResolvedAgentRun because endpoint allocation is an
// execution-backend concern.
type AgentConfigBindings struct {
	ForwardProxyURL  string            `json:"forward_proxy_url,omitempty"`
	RedirectBaseURLs map[string]string `json:"redirect_base_urls,omitempty"`
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
	ContractVersion string    `json:"contract_version"`
	RunID           string    `json:"run_id"`
	Principal       Principal `json:"principal"`
	Profile         string    `json:"profile"`
	Workflow        string    `json:"workflow"`
	Image           string    `json:"image"`
	Runtime         Runtime   `json:"runtime"`
	// AgentConfig is the immutable non-controller-owned base. Backends must
	// execute RenderAgentConfig's result, not this base document directly.
	AgentConfig           json.RawMessage             `json:"agent_config"`
	Prompt                string                      `json:"prompt,omitempty"`
	Repositories          []Repository                `json:"repositories,omitempty"`
	CredentialProviders   []CredentialProviderMapping `json:"credential_providers,omitempty"`
	Broker                Broker                      `json:"broker"`
	Egress                Egress                      `json:"egress"`
	WorkspaceInstructions WorkspaceInstructions       `json:"workspace_instructions"`
	Resources             Resources                   `json:"resources"`
	Persistence           Persistence                 `json:"persistence"`
	Retention             string                      `json:"retention"`
	TTL                   TTL                         `json:"ttl"`
	Lifecycle             Lifecycle                   `json:"lifecycle"`
	Execution             ExecutionBackend            `json:"execution"`
}

// PlatformDefaults are trusted lowest-precedence defaults. Profile pointers
// replace complete blocks; partial security-policy merging is intentionally not
// supported.
type PlatformDefaults struct {
	Image       string          `json:"image"`
	Runtime     Runtime         `json:"runtime"`
	AgentConfig json.RawMessage `json:"agent_config"`
	Resources   Resources       `json:"resources"`
	Lifecycle   Lifecycle       `json:"lifecycle"`
}

// Profile is trusted administrator configuration. Protected provider, broker,
// egress, retention, and backend policy can be selected but never supplied by
// a LocalRunRequest.
type Profile struct {
	Name                  string                      `json:"name"`
	Image                 string                      `json:"image,omitempty"`
	Runtime               *Runtime                    `json:"runtime,omitempty"`
	AgentConfig           json.RawMessage             `json:"agent_config,omitempty"`
	Resources             *Resources                  `json:"resources,omitempty"`
	Lifecycle             *Lifecycle                  `json:"lifecycle,omitempty"`
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

// AuthorizedSelection and AuthorizationContext are trusted authentication and
// policy outputs. They are never decoded from the local-run request.
type AuthorizedSelection struct {
	Profile   string
	Workflows []string
}

type AuthorizationContext struct {
	Principal  Principal
	Selections []AuthorizedSelection
}

// LocalRunRequest is the complete caller-controlled surface. Identity is
// deliberately absent and every profile/workflow pair is checked against a
// separate trusted AuthorizationContext. Its strict decoder rejects every
// additional field.
type LocalRunRequest struct {
	RunID     string `json:"run_id"`
	Profile   string `json:"profile"`
	Workflow  string `json:"workflow"`
	Retention string `json:"retention"`
	Backend   string `json:"backend,omitempty"`
	Prompt    string `json:"prompt,omitempty"`
}
