package resolvedrun

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxNameBytes             = 63
	maxIssuerBytes           = 2048
	maxSubjectBytes          = 512
	maxDisplayNameBytes      = 512
	maxCommandBytes          = 4096
	maxArgumentBytes         = 16 << 10
	maxArguments             = 256
	maxEnvironmentVariables  = 128
	maxEnvironmentValueBytes = 16 << 10
	maxRuntimeCapabilities   = 64
	maxDockerNetworks        = 16
	maxLifecycleEvents       = 128
	maxPatternsPerProvider   = 256
	maxGrantValues           = 256
	maxTTLSeconds            = 365 * 24 * 60 * 60
)

var (
	namePattern            = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	providerPattern        = regexp.MustCompile(`^[A-Za-z0-9](?:[-._A-Za-z0-9]*[A-Za-z0-9])?$`)
	environmentPattern     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	capabilityPattern      = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
	linuxCapabilityPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	cpuQuantityPattern     = regexp.MustCompile(`^(?:0|[1-9][0-9]*)(?:m)?$`)
	memoryQuantityPattern  = regexp.MustCompile(`^(?:0|[1-9][0-9]*)(?:Ki|Mi|Gi|Ti|Pi)?$`)
)

var sensitiveEnvironmentSegments = []string{
	"TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "PRIVATE_KEY", "API_KEY", "AUTHORIZATION",
}

func ValidateLocalRunRequest(value LocalRunRequest) error {
	if !validName(value.RunID) {
		return errors.New("run_id is invalid")
	}
	if !validName(value.Profile) {
		return errors.New("profile is invalid")
	}
	if !validName(value.Workflow) {
		return errors.New("workflow is invalid")
	}
	if !validName(value.Retention) {
		return errors.New("retention is invalid")
	}
	if value.Backend != "" && !validName(value.Backend) {
		return errors.New("backend is invalid")
	}
	if len(value.Prompt) > MaxPromptBytes || strings.ContainsRune(value.Prompt, 0) || !utf8.ValidString(value.Prompt) {
		return errors.New("prompt is invalid")
	}
	return nil
}

func ValidateAuthorizationContext(value AuthorizationContext) error {
	if err := validatePrincipal(value.Principal); err != nil {
		return errors.New("authorization context is invalid")
	}
	if len(value.Selections) == 0 || len(value.Selections) > MaxProfiles {
		return errors.New("authorization context is invalid")
	}
	profiles := make(map[string]struct{}, len(value.Selections))
	for _, selection := range value.Selections {
		if !validName(selection.Profile) || len(selection.Workflows) == 0 || len(selection.Workflows) > MaxWorkflows {
			return errors.New("authorization context is invalid")
		}
		if _, duplicate := profiles[selection.Profile]; duplicate {
			return errors.New("authorization context is invalid")
		}
		profiles[selection.Profile] = struct{}{}
		if err := validateUniqueStrings(selection.Workflows, validName); err != nil {
			return errors.New("authorization context is invalid")
		}
	}
	return nil
}

func ValidateResolvedAgentRun(value ResolvedAgentRun) error {
	if value.ContractVersion != ContractVersion {
		return errors.New("contract_version is unsupported")
	}
	if err := ValidateLocalRunRequest(LocalRunRequest{
		RunID: value.RunID, Profile: value.Profile, Workflow: value.Workflow,
		Retention: value.Retention, Backend: value.Execution.Name, Prompt: value.Prompt,
	}); err != nil {
		return err
	}
	if err := validatePrincipal(value.Principal); err != nil {
		return err
	}
	if !validName(value.Execution.Kind) {
		return errors.New("execution kind is invalid")
	}
	if err := validateEffective(value.Image, value.Runtime, value.AgentConfig, value.Resources, value.Lifecycle); err != nil {
		return err
	}
	if len(value.Repositories) > MaxRepositories || len(value.CredentialProviders) > MaxCredentialProviderMappings {
		return errors.New("resolved repository configuration exceeds its limit")
	}
	if err := validateBrokerAndEgress(value.Broker, value.Egress); err != nil {
		return err
	}
	if err := validateMappingsAndRepositories(value.CredentialProviders, value.Repositories, value.Broker); err != nil {
		return err
	}
	if err := validateInstructions(value.WorkspaceInstructions.Profile); err != nil {
		return errors.New("profile workspace instructions are invalid")
	}
	if err := validateInstructions(value.WorkspaceInstructions.Workflow); err != nil {
		return errors.New("workflow workspace instructions are invalid")
	}
	if err := validateTTL(value.TTL); err != nil {
		return err
	}
	return nil
}

func validatePrincipal(value Principal) error {
	if len(value.Issuer) == 0 || len(value.Issuer) > maxIssuerBytes ||
		value.Issuer != strings.TrimSpace(value.Issuer) || containsControl(value.Issuer) {
		return errors.New("principal issuer is invalid")
	}
	parsed, err := url.Parse(value.Issuer)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.String() != value.Issuer {
		return errors.New("principal issuer is invalid")
	}
	if len(value.Subject) == 0 || len(value.Subject) > maxSubjectBytes ||
		value.Subject != strings.TrimSpace(value.Subject) || containsControl(value.Subject) {
		return errors.New("principal subject is invalid")
	}
	if len(value.DisplayName) > maxDisplayNameBytes || containsControl(value.DisplayName) {
		return errors.New("principal display_name is invalid")
	}
	return nil
}

func validateEffective(image string, runtime Runtime, agentConfig json.RawMessage, resources Resources, lifecycle Lifecycle) error {
	if image == "" || len(image) > 4096 || image != strings.TrimSpace(image) || containsControl(image) {
		return errors.New("image is invalid")
	}
	if err := validateRuntime(runtime); err != nil {
		return err
	}
	if err := validateAgentConfig(agentConfig); err != nil {
		return err
	}
	if err := validateLifecycle(lifecycle); err != nil {
		return err
	}
	return validateResources(resources)
}

func validateRuntime(value Runtime) error {
	if !validProvider(value.Type) {
		return errors.New("runtime type is invalid")
	}
	if (value.Autonomy != "trusted-local" && value.Autonomy != "interactive") ||
		(value.User != "root" && value.User != "non-root") {
		return errors.New("runtime autonomy or user is invalid")
	}
	if value.Container != nil {
		if len(value.Container.Capabilities) > maxRuntimeCapabilities ||
			validateUniqueStrings(value.Container.Capabilities, func(item string) bool {
				return len(item) <= 64 && linuxCapabilityPattern.MatchString(item)
			}) != nil {
			return errors.New("runtime container capabilities are invalid")
		}
	}
	if value.Docker != nil {
		if len(value.Docker.RequiredNetworks) > maxDockerNetworks {
			return errors.New("runtime Docker networks exceed their limit")
		}
		seen := map[string]struct{}{}
		for _, network := range value.Docker.RequiredNetworks {
			if !validName(network.Name) || !validDockerSubnet(network.Subnet) {
				return errors.New("runtime Docker network is invalid")
			}
			if _, duplicate := seen[network.Name]; duplicate {
				return errors.New("runtime Docker network is duplicated")
			}
			seen[network.Name] = struct{}{}
		}
	}
	return nil
}

func validateCommand(command string, args []any) error {
	if !validBoundedText(command, maxCommandBytes, false) || strings.ContainsAny(command, " \t") || len(args) > maxArguments {
		return errors.New("invalid command")
	}
	for _, raw := range args {
		argument, ok := raw.(string)
		if !ok || len(argument) > maxArgumentBytes || strings.ContainsRune(argument, 0) || !utf8.ValidString(argument) {
			return errors.New("invalid command argument")
		}
	}
	return nil
}

func validateAgentConfig(value json.RawMessage) error {
	if len(value) == 0 || len(value) > MaxAgentConfigBytes || rejectDuplicateKeys(value) != nil {
		return errors.New("agent_config is invalid")
	}
	var root map[string]any
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	if decoder.Decode(&root) != nil || root == nil || ensureDecoderEOF(decoder) != nil {
		return errors.New("agent_config is invalid")
	}
	runtime, ok := root["runtime"].(map[string]any)
	if !ok {
		return errors.New("agent_config runtime is invalid")
	}
	command, ok := runtime["command"].(string)
	args, argsOK := optionalAnySlice(runtime, "args")
	if !ok || !argsOK || validateCommand(command, args) != nil {
		return errors.New("agent_config runtime command is invalid")
	}
	if rawResume, present := runtime["resume"]; present {
		resume, ok := rawResume.(map[string]any)
		resumeCommand, commandOK := resume["command"].(string)
		resumeArgs, argsOK := optionalAnySlice(resume, "args")
		if !ok || !commandOK || !argsOK || validateCommand(resumeCommand, resumeArgs) != nil {
			return errors.New("agent_config runtime resume is invalid")
		}
	}
	if rawEnvironment, present := runtime["env"]; present {
		environment, ok := rawEnvironment.(map[string]any)
		if !ok || len(environment) > maxEnvironmentVariables {
			return errors.New("agent_config runtime environment is invalid")
		}
		for name, raw := range environment {
			text, ok := raw.(string)
			if !ok || len(name) > 128 || !environmentPattern.MatchString(name) || len(text) > maxEnvironmentValueBytes ||
				strings.ContainsRune(text, 0) || sensitiveEnvironmentName(name) {
				return errors.New("agent_config runtime environment is invalid")
			}
		}
	}
	return nil
}

func optionalAnySlice(object map[string]any, key string) ([]any, bool) {
	value, present := object[key]
	if !present {
		return nil, true
	}
	result, ok := value.([]any)
	return result, ok
}

func validateLifecycle(value Lifecycle) error {
	if len(value.CompleteOn) > maxLifecycleEvents || len(value.FailOn) > maxLifecycleEvents ||
		validateUniqueStrings(value.CompleteOn, validEventName) != nil || validateUniqueStrings(value.FailOn, validEventName) != nil {
		return errors.New("lifecycle is invalid")
	}
	seen := map[string]struct{}{}
	for _, event := range value.CompleteOn {
		seen[event] = struct{}{}
	}
	for _, event := range value.FailOn {
		if _, conflict := seen[event]; conflict {
			return errors.New("lifecycle event has conflicting outcomes")
		}
	}
	return nil
}

func validateResources(value Resources) error {
	if value.CPURequest != "" && !cpuQuantityPattern.MatchString(value.CPURequest) {
		return errors.New("CPU request is invalid")
	}
	if value.CPULimit != "" && !cpuQuantityPattern.MatchString(value.CPULimit) {
		return errors.New("CPU limit is invalid")
	}
	if value.MemoryRequest != "" && !memoryQuantityPattern.MatchString(value.MemoryRequest) {
		return errors.New("memory request is invalid")
	}
	if value.MemoryLimit != "" && !memoryQuantityPattern.MatchString(value.MemoryLimit) {
		return errors.New("memory limit is invalid")
	}
	return nil
}

func validateBrokerAndEgress(broker Broker, egress Egress) error {
	if len(broker.Grants) > MaxBrokerGrants {
		return errors.New("broker grants exceed their limit")
	}
	providers := make(map[string]struct{}, len(broker.Grants))
	for _, grant := range broker.Grants {
		if !validProvider(grant.Provider) {
			return errors.New("broker grant provider is invalid")
		}
		if _, duplicate := providers[grant.Provider]; duplicate {
			return errors.New("broker grant provider is duplicated")
		}
		providers[grant.Provider] = struct{}{}
		if len(grant.Repositories) > maxGrantValues || len(grant.Capabilities) > maxGrantValues ||
			len(grant.Preparations) > maxGrantValues || len(grant.EgressHosts) > maxGrantValues ||
			len(grant.Permissions) > maxGrantValues {
			return errors.New("broker grant exceeds its limit")
		}
		if err := validateUniqueStrings(grant.Repositories, validRepositoryPattern); err != nil {
			return errors.New("broker grant repositories are invalid")
		}
		if err := validateUniqueStrings(grant.Capabilities, validCapability); err != nil {
			return errors.New("broker grant capabilities are invalid")
		}
		if err := validateUniqueStrings(grant.Preparations, validCapability); err != nil {
			return errors.New("broker grant preparations are invalid")
		}
		if err := validateUniqueStrings(grant.EgressHosts, validEgressHost); err != nil {
			return errors.New("broker grant egress hosts are invalid")
		}
		for permission, access := range grant.Permissions {
			if !validCapability(permission) || (access != "read" && access != "write") {
				return errors.New("broker grant permissions are invalid")
			}
		}
		if grant.Quota != nil && (grant.Quota.Requests < 1 || grant.Quota.Requests > 1_000_000_000) {
			return errors.New("broker grant quota is invalid")
		}
		if grant.Git && (grant.Materialization != "header-inject" || grant.AllowInsecureUpstream) {
			return errors.New("git broker grant policy is invalid")
		}
		switch grant.Materialization {
		case "file-bundle", "header-inject", "placeholder-file":
		default:
			return errors.New("broker grant materialization is invalid")
		}
	}
	if egress.MaxConcurrentTunnels < 0 || egress.MaxConcurrentTunnels > 4096 {
		return errors.New("egress tunnel limit is invalid")
	}
	switch egress.Mode {
	case "direct":
		if egress.Transport != "" || egress.Enforced || egress.ProxyProvider != "" || egress.PairedEgressRequired || egress.MaxConcurrentTunnels != 0 {
			return errors.New("direct egress contains mediated policy")
		}
		for _, grant := range broker.Grants {
			if grant.Materialization != "file-bundle" {
				return errors.New("direct egress contains a mediated broker grant")
			}
		}
	case "mediated":
		if !egress.PairedEgressRequired || egress.ProxyProvider == "" {
			return errors.New("mediated egress lacks its paired identity or proxy provider")
		}
		switch egress.Transport {
		case "redirect", "forward-proxy", "transparent":
		default:
			return errors.New("mediated egress transport is invalid")
		}
		if _, exists := providers[egress.ProxyProvider]; !exists {
			return errors.New("mediated egress proxy provider is not granted")
		}
		if egress.MaxConcurrentTunnels != 0 && egress.Transport != "forward-proxy" && egress.Transport != "transparent" {
			return errors.New("mediated egress tunnel limit requires a tunnel transport")
		}
		for _, grant := range broker.Grants {
			if grant.Materialization != "header-inject" && grant.Materialization != "placeholder-file" {
				return errors.New("mediated egress contains a non-mediated broker grant")
			}
			if len(grant.EgressHosts) == 0 {
				return errors.New("mediated egress grant has no bounded host")
			}
		}
	default:
		return errors.New("egress mode is invalid")
	}
	return nil
}

func validateMappingsAndRepositories(mappings []CredentialProviderMapping, repositories []Repository, broker Broker) error {
	providers := make(map[string]BrokerGrant, len(broker.Grants))
	for _, grant := range broker.Grants {
		providers[grant.Provider] = grant
	}
	aliases := make(map[string]CredentialProviderMapping, len(mappings))
	for _, mapping := range mappings {
		if !validProvider(mapping.Name) || !validProvider(mapping.BrokerProvider) || len(mapping.MatchTargets) > maxPatternsPerProvider {
			return errors.New("credential provider mapping is invalid")
		}
		if _, duplicate := aliases[mapping.Name]; duplicate {
			return errors.New("credential provider mapping is duplicated")
		}
		if _, granted := providers[mapping.BrokerProvider]; !granted {
			return errors.New("credential provider mapping references an ungranted provider")
		}
		if err := validateUniqueStrings(mapping.MatchTargets, validRepositoryPattern); err != nil {
			return errors.New("credential provider match targets are invalid")
		}
		aliases[mapping.Name] = mapping
	}
	identifiers := make(map[string]struct{}, len(repositories))
	paths := make(map[string]struct{}, len(repositories))
	for _, repository := range repositories {
		if !validRepositoryID(repository.CheckoutTarget) || repositoryTargetFromURL(repository.URL) != repository.CheckoutTarget ||
			!validRepositoryID(repository.BrokerRepository) ||
			!validCheckoutPath(repository.Path) {
			return errors.New("workflow repository is invalid")
		}
		if _, duplicate := identifiers[repository.CheckoutTarget]; duplicate {
			return errors.New("workflow repository is duplicated")
		}
		identifiers[repository.CheckoutTarget] = struct{}{}
		effectivePath := repository.Path
		if effectivePath == "" {
			effectivePath = path.Base(strings.TrimSuffix(repository.CheckoutTarget, ".git"))
		}
		if _, duplicate := paths[effectivePath]; duplicate {
			return errors.New("workflow checkout path is duplicated")
		}
		paths[effectivePath] = struct{}{}
		if repository.CredentialProvider == "" {
			continue
		}
		mapping, exists := aliases[repository.CredentialProvider]
		if !exists || !patternsContain(mapping.MatchTargets, repository.CheckoutTarget) {
			return errors.New("workflow repository is not authorized by its credential mapping")
		}
		grant := providers[mapping.BrokerProvider]
		if !patternsContain(grant.Repositories, repository.BrokerRepository) {
			return errors.New("workflow repository is not authorized by its broker grant")
		}
	}
	return nil
}

func validateTTL(value TTL) error {
	for _, seconds := range []int64{value.ActiveSeconds, value.CompletedSeconds, value.FailedSeconds, value.RunRetentionSeconds} {
		if seconds < 0 || seconds > maxTTLSeconds {
			return errors.New("TTL is invalid")
		}
	}
	return nil
}

func validateInstructions(value string) error {
	if len(value) > MaxWorkspaceInstructionsBytes || strings.ContainsRune(value, 0) || !utf8.ValidString(value) {
		return errors.New("workspace instructions are invalid")
	}
	return nil
}

func validName(value string) bool {
	return len(value) <= maxNameBytes && namePattern.MatchString(value)
}

func validProvider(value string) bool {
	return len(value) <= 128 && providerPattern.MatchString(value)
}

func validCapability(value string) bool {
	return len(value) <= 128 && capabilityPattern.MatchString(value)
}

func validBoundedText(value string, maximum int, allowEmpty bool) bool {
	return (allowEmpty || value != "") && len(value) <= maximum && value == strings.TrimSpace(value) &&
		!containsControl(value) && utf8.ValidString(value)
}

func containsControl(value string) bool {
	return strings.ContainsAny(value, "\x00\r\n") || !utf8.ValidString(value)
}

func validateUniqueStrings(values []string, valid func(string) bool) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !valid(value) {
			return errors.New("invalid value")
		}
		if _, duplicate := seen[value]; duplicate {
			return errors.New("duplicate value")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validRepositoryID(value string) bool {
	if len(value) == 0 || len(value) > 1024 || value != strings.Trim(value, "/") || containsControl(value) || strings.Contains(value, "//") {
		return false
	}
	segments := strings.Split(value, "/")
	if len(segments) < 2 {
		return false
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, "?#@\\") {
			return false
		}
	}
	return true
}

func validRepositoryPattern(value string) bool {
	if strings.HasSuffix(value, "/*") {
		prefix := strings.TrimSuffix(value, "/*")
		return validRepositoryID(prefix + "/repository")
	}
	return validRepositoryID(value)
}

func patternsContain(patterns []string, repository string) bool {
	for _, pattern := range patterns {
		if pattern == repository || (strings.HasSuffix(pattern, "/*") && strings.HasPrefix(repository, strings.TrimSuffix(pattern, "*"))) {
			return true
		}
	}
	return false
}

func repositoryTargetFromURL(value string) string {
	if len(value) == 0 || len(value) > 4096 || containsControl(value) {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Host != strings.ToLower(parsed.Host) ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" ||
		strings.Contains(parsed.EscapedPath(), "%") || parsed.Path == "" || parsed.Path == "/" ||
		strings.HasSuffix(parsed.Path, "/") || hasDotPathSegment(strings.TrimPrefix(parsed.Path, "/")) ||
		net.ParseIP(parsed.Hostname()) != nil {
		return ""
	}
	if parsed.Host != parsed.Hostname() {
		port, err := strconv.Atoi(parsed.Port())
		if err != nil || port < 1 || port > 65535 {
			return ""
		}
	}
	identifier := parsed.Host + strings.TrimSuffix(parsed.Path, ".git")
	if !validRepositoryID(identifier) {
		return ""
	}
	return identifier
}

func validCheckoutPath(value string) bool {
	if value == "" {
		return true
	}
	return len(value) <= 1024 && value == strings.Trim(value, "/") && !strings.HasPrefix(value, "/") &&
		!hasDotPathSegment(value) && !containsControl(value) && !strings.Contains(value, "\\")
}

func hasDotPathSegment(value string) bool {
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func validEgressHost(value string) bool {
	if len(value) == 0 || len(value) > 512 || value != strings.ToLower(value) || containsControl(value) || strings.Contains(value, "://") {
		return false
	}
	parsed, err := url.Parse("https://" + value)
	if err != nil || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Hostname() == "" {
		return false
	}
	if net.ParseIP(parsed.Hostname()) != nil {
		return false
	}
	if parsed.Host != parsed.Hostname() {
		port, err := strconv.Atoi(parsed.Port())
		if err != nil || port < 1 || port > 65535 {
			return false
		}
	}
	return true
}

func sensitiveEnvironmentName(name string) bool {
	upper := strings.ToUpper(name)
	for _, segment := range sensitiveEnvironmentSegments {
		if upper == segment || strings.HasPrefix(upper, segment+"_") || strings.HasSuffix(upper, "_"+segment) ||
			strings.Contains(upper, "_"+segment+"_") {
			return true
		}
	}
	return false
}

func validDockerSubnet(value string) bool {
	ip, network, err := net.ParseCIDR(value)
	if err != nil || ip.To4() == nil || !ip.Equal(network.IP) {
		return false
	}
	ones, bits := network.Mask.Size()
	return bits == 32 && ones >= 16 && ones <= 30
}

func validEventName(value string) bool {
	return len(value) <= 256 && capabilityPattern.MatchString(value)
}

func ensureDecoderEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON data")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}
