package resolvedrun

import (
	"encoding/json"
	"errors"
)

var (
	ErrInvalidConfiguration = errors.New("invalid trusted resolved-run configuration")
	ErrInvalidRequest       = errors.New("invalid local-run request")
	ErrUnknownProfile       = errors.New("unknown profile")
	ErrUnknownWorkflow      = errors.New("unknown workflow")
	ErrSelectionDenied      = errors.New("local-run selection denied")
	ErrInvalidRenderBinding = errors.New("invalid agent-config render binding")
)

// Resolver holds an immutable validated snapshot of trusted configuration.
type Resolver struct {
	defaults   PlatformDefaults
	profiles   map[string]Profile
	workflows  map[string]Workflow
	backends   map[string]ExecutionBackend
	retentions map[string]RetentionPolicy
}

func NewResolver(configuration TrustedConfiguration) (*Resolver, error) {
	if len(configuration.Profiles) == 0 || len(configuration.Profiles) > MaxProfiles ||
		len(configuration.Workflows) == 0 || len(configuration.Workflows) > MaxWorkflows ||
		len(configuration.ExecutionBackends) == 0 || len(configuration.ExecutionBackends) > MaxExecutionBackends ||
		len(configuration.RetentionPolicies) == 0 || len(configuration.RetentionPolicies) > MaxRetentionPolicies {
		return nil, ErrInvalidConfiguration
	}
	if err := validateEffective(configuration.Defaults.Image, configuration.Defaults.Runtime,
		configuration.Defaults.AgentConfig, configuration.Defaults.Resources, configuration.Defaults.Lifecycle); err != nil {
		return nil, ErrInvalidConfiguration
	}

	resolver := &Resolver{
		defaults:   clone(configuration.Defaults),
		profiles:   make(map[string]Profile, len(configuration.Profiles)),
		workflows:  make(map[string]Workflow, len(configuration.Workflows)),
		backends:   make(map[string]ExecutionBackend, len(configuration.ExecutionBackends)),
		retentions: make(map[string]RetentionPolicy, len(configuration.RetentionPolicies)),
	}
	for _, backend := range configuration.ExecutionBackends {
		if !validName(backend.Name) || !validName(backend.Kind) {
			return nil, ErrInvalidConfiguration
		}
		if _, duplicate := resolver.backends[backend.Name]; duplicate {
			return nil, ErrInvalidConfiguration
		}
		resolver.backends[backend.Name] = backend
	}
	for _, retention := range configuration.RetentionPolicies {
		if !validName(retention.Name) || validateTTL(retention.TTL) != nil {
			return nil, ErrInvalidConfiguration
		}
		if _, duplicate := resolver.retentions[retention.Name]; duplicate {
			return nil, ErrInvalidConfiguration
		}
		resolver.retentions[retention.Name] = retention
	}
	for _, workflow := range configuration.Workflows {
		if !validName(workflow.Name) || len(workflow.Repositories) > MaxRepositories ||
			validateInstructions(workflow.WorkspaceInstructions) != nil || validateWorkflowRepositories(workflow.Repositories) != nil ||
			(workflow.Lifecycle != nil && validateLifecycle(*workflow.Lifecycle) != nil) {
			return nil, ErrInvalidConfiguration
		}
		if _, duplicate := resolver.workflows[workflow.Name]; duplicate {
			return nil, ErrInvalidConfiguration
		}
		resolver.workflows[workflow.Name] = clone(workflow)
	}
	for _, profile := range configuration.Profiles {
		if !validName(profile.Name) || validateInstructions(profile.WorkspaceInstructions) != nil ||
			len(profile.AllowedBackends) == 0 || len(profile.AllowedBackends) > MaxExecutionBackends ||
			len(profile.AllowedRetentions) == 0 || len(profile.AllowedRetentions) > MaxRetentionPolicies ||
			len(profile.CredentialProviders) > MaxCredentialProviderMappings {
			return nil, ErrInvalidConfiguration
		}
		if _, duplicate := resolver.profiles[profile.Name]; duplicate {
			return nil, ErrInvalidConfiguration
		}
		if profile.Image != "" && (profile.Image != stringTrimSpace(profile.Image) || containsControl(profile.Image)) {
			return nil, ErrInvalidConfiguration
		}
		image, runtime, agentConfig, resources, lifecycle := resolver.effective(profile)
		if validateEffective(image, runtime, agentConfig, resources, lifecycle) != nil ||
			validateBrokerAndEgress(profile.Broker, profile.Egress) != nil {
			return nil, ErrInvalidConfiguration
		}
		if err := validateAllowedSelections(profile, resolver.backends, resolver.retentions); err != nil {
			return nil, ErrInvalidConfiguration
		}
		// Repository authorization is checked per workflow at Resolve. Validate
		// the mapping itself here with an empty repository set.
		if validateMappingsAndRepositories(profile.CredentialProviders, nil, profile.Broker, profile.Egress) != nil {
			return nil, ErrInvalidConfiguration
		}
		if !validDefaultCredentialProvider(profile.DefaultCredentialProvider, profile.CredentialProviders) {
			return nil, ErrInvalidConfiguration
		}
		resolver.profiles[profile.Name] = clone(profile)
	}
	return resolver, nil
}

func validateWorkflowRepositories(repositories []Repository) error {
	identifiers := make(map[string]struct{}, len(repositories))
	paths := make(map[string]struct{}, len(repositories))
	for _, repository := range repositories {
		if !validRepositoryID(repository.CheckoutTarget) || repositoryTargetFromURL(repository.URL) != repository.CheckoutTarget ||
			(repository.Upstream != "" && repositoryTargetFromURL(repository.Upstream) == "") ||
			!validCheckoutPath(repository.Path) ||
			(repository.CredentialProvider == "" && repository.BrokerRepository != "") ||
			(repository.CredentialProvider == "" && repository.Identity != nil) ||
			(repository.CredentialProvider != "" && !validRepositoryID(repository.BrokerRepository)) ||
			(repository.CredentialProvider != "" && !validProvider(repository.CredentialProvider)) ||
			validateRepositoryIdentity(repository.Identity) != nil {
			return ErrInvalidConfiguration
		}
		if _, duplicate := identifiers[repository.CheckoutTarget]; duplicate {
			return ErrInvalidConfiguration
		}
		identifiers[repository.CheckoutTarget] = struct{}{}
		effectivePath := repository.Path
		if effectivePath == "" {
			effectivePath = pathBase(repository.CheckoutTarget)
		}
		if _, duplicate := paths[effectivePath]; duplicate {
			return ErrInvalidConfiguration
		}
		paths[effectivePath] = struct{}{}
	}
	return nil
}

func pathBase(value string) string {
	lastSlash := -1
	for index := len(value) - 1; index >= 0; index-- {
		if value[index] == '/' {
			lastSlash = index
			break
		}
	}
	base := value[lastSlash+1:]
	if len(base) > 4 && base[len(base)-4:] == ".git" {
		base = base[:len(base)-4]
	}
	return base
}

func (resolver *Resolver) Resolve(authorization AuthorizationContext, request LocalRunRequest) (ResolvedAgentRun, error) {
	if resolver == nil || ValidateLocalRunRequest(request) != nil || ValidateAuthorizationContext(authorization) != nil {
		return ResolvedAgentRun{}, ErrInvalidRequest
	}
	if !selectionAuthorized(authorization.Selections, request.Profile, request.Workflow) {
		return ResolvedAgentRun{}, ErrSelectionDenied
	}
	profile, exists := resolver.profiles[request.Profile]
	if !exists {
		return ResolvedAgentRun{}, ErrUnknownProfile
	}
	workflow, exists := resolver.workflows[request.Workflow]
	if !exists {
		return ResolvedAgentRun{}, ErrUnknownWorkflow
	}
	backendName := request.Backend
	if backendName == "" {
		backendName = profile.DefaultBackend
	}
	if !containsString(profile.AllowedBackends, backendName) || !containsString(profile.AllowedRetentions, request.Retention) {
		return ResolvedAgentRun{}, ErrSelectionDenied
	}
	backend, backendExists := resolver.backends[backendName]
	retention, retentionExists := resolver.retentions[request.Retention]
	if !backendExists || !retentionExists {
		return ResolvedAgentRun{}, ErrSelectionDenied
	}
	if err := validateMappingsAndRepositories(profile.CredentialProviders, workflow.Repositories, profile.Broker, profile.Egress); err != nil {
		return ResolvedAgentRun{}, ErrInvalidConfiguration
	}
	image, runtime, agentConfig, resources, lifecycle := resolver.effective(profile)
	if workflow.Lifecycle != nil {
		lifecycle = clone(*workflow.Lifecycle)
	}
	resolved := ResolvedAgentRun{
		ContractVersion: ContractVersion, RunID: request.RunID, Principal: authorization.Principal,
		Profile: profile.Name, Workflow: workflow.Name, Image: image, Runtime: runtime,
		AgentConfig: clone(agentConfig), Prompt: request.Prompt,
		Repositories: clone(workflow.Repositories), CredentialProviders: clone(profile.CredentialProviders),
		DefaultCredentialProvider: profile.DefaultCredentialProvider,
		Broker:                    clone(profile.Broker), Egress: profile.Egress,
		WorkspaceInstructions: WorkspaceInstructions{Profile: profile.WorkspaceInstructions, Workflow: workflow.WorkspaceInstructions},
		Resources:             resources, Persistence: retention.Persistence, Retention: retention.Name,
		TTL: retention.TTL, Lifecycle: lifecycle, Execution: backend,
	}
	if err := ValidateResolvedAgentRun(resolved); err != nil {
		return ResolvedAgentRun{}, ErrInvalidConfiguration
	}
	return clone(resolved), nil
}

func (resolver *Resolver) effective(profile Profile) (string, Runtime, json.RawMessage, Resources, Lifecycle) {
	image := resolver.defaults.Image
	if profile.Image != "" {
		image = profile.Image
	}
	runtime := clone(resolver.defaults.Runtime)
	if profile.Runtime != nil {
		runtime = clone(*profile.Runtime)
	}
	agentConfig := clone(resolver.defaults.AgentConfig)
	if len(profile.AgentConfig) != 0 {
		agentConfig = clone(profile.AgentConfig)
	}
	resources := resolver.defaults.Resources
	if profile.Resources != nil {
		resources = *profile.Resources
	}
	lifecycle := clone(resolver.defaults.Lifecycle)
	if profile.Lifecycle != nil {
		lifecycle = clone(*profile.Lifecycle)
	}
	return image, runtime, agentConfig, resources, lifecycle
}

func selectionAuthorized(selections []AuthorizedSelection, profile, workflow string) bool {
	for _, selection := range selections {
		if selection.Profile == profile && containsString(selection.Workflows, workflow) {
			return true
		}
	}
	return false
}

func validateAllowedSelections(profile Profile, backends map[string]ExecutionBackend, retentions map[string]RetentionPolicy) error {
	if !validName(profile.DefaultBackend) || !containsString(profile.AllowedBackends, profile.DefaultBackend) {
		return ErrInvalidConfiguration
	}
	seen := map[string]struct{}{}
	for _, name := range profile.AllowedBackends {
		if _, exists := backends[name]; !exists || !validName(name) {
			return ErrInvalidConfiguration
		}
		if _, duplicate := seen[name]; duplicate {
			return ErrInvalidConfiguration
		}
		seen[name] = struct{}{}
	}
	seen = map[string]struct{}{}
	for _, name := range profile.AllowedRetentions {
		if _, exists := retentions[name]; !exists || !validName(name) {
			return ErrInvalidConfiguration
		}
		if _, duplicate := seen[name]; duplicate {
			return ErrInvalidConfiguration
		}
		seen[name] = struct{}{}
	}
	return nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func clone[T any](value T) T {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic("resolvedrun: clone of contract value failed")
	}
	var result T
	if err := json.Unmarshal(encoded, &result); err != nil {
		panic("resolvedrun: clone of contract value failed")
	}
	return result
}

func stringTrimSpace(value string) string {
	start, end := 0, len(value)
	for start < end && (value[start] == ' ' || value[start] == '\t' || value[start] == '\r' || value[start] == '\n') {
		start++
	}
	for end > start && (value[end-1] == ' ' || value[end-1] == '\t' || value[end-1] == '\r' || value[end-1] == '\n') {
		end--
	}
	return value[start:end]
}
