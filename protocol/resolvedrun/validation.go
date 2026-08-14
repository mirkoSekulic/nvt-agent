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
	maxNameBytes               = 63
	maxIssuerBytes             = 2048
	maxSubjectBytes            = 512
	maxDisplayNameBytes        = 512
	maxCommandBytes            = 4096
	maxArgumentBytes           = 16 << 10
	maxArguments               = 256
	maxEnvironmentVariables    = 128
	maxEnvironmentValueBytes   = 16 << 10
	maxPreseedFiles            = 32
	maxPreseedFileBytes        = 64 << 10
	maxToolEntries             = 256
	maxCodeServerExtensions    = 128
	maxCodeServerSettings      = 256
	maxCodeServerSettingsBytes = 64 << 10
	maxPatternsPerProvider     = 256
	maxGrantValues             = 256
	maxTTLSeconds              = 365 * 24 * 60 * 60
)

var (
	namePattern           = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	providerPattern       = regexp.MustCompile(`^[A-Za-z0-9](?:[-._A-Za-z0-9]*[A-Za-z0-9])?$`)
	environmentPattern    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	capabilityPattern     = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
	packagePattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@+._/-]*$`)
	cpuQuantityPattern    = regexp.MustCompile(`^(?:0|[1-9][0-9]*)(?:m)?$`)
	memoryQuantityPattern = regexp.MustCompile(`^(?:0|[1-9][0-9]*)(?:Ki|Mi|Gi|Ti|Pi)?$`)
)

var sensitiveEnvironmentSegments = []string{
	"TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "PRIVATE_KEY", "API_KEY", "AUTHORIZATION",
}

func ValidateLocalRunRequest(value LocalRunRequest) error {
	if !validName(value.RunID) {
		return errors.New("run_id is invalid")
	}
	if err := validatePrincipal(value.Principal); err != nil {
		return err
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
	return nil
}

func ValidateResolvedAgentRun(value ResolvedAgentRun) error {
	if value.ContractVersion != ContractVersion {
		return errors.New("contract_version is unsupported")
	}
	if err := ValidateLocalRunRequest(LocalRunRequest{
		RunID: value.RunID, Principal: value.Principal, Profile: value.Profile,
		Workflow: value.Workflow, Retention: value.Retention, Backend: value.Execution.Name,
	}); err != nil {
		return err
	}
	if !validName(value.Execution.Kind) {
		return errors.New("execution kind is invalid")
	}
	if err := validateEffective(value.Image, value.Runtime, value.Tools, value.CodeServer, value.Resources); err != nil {
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

func validateEffective(image string, runtime Runtime, tools Tools, codeServer CodeServer, resources Resources) error {
	if image == "" || len(image) > 4096 || image != strings.TrimSpace(image) || containsControl(image) {
		return errors.New("image is invalid")
	}
	if err := validateRuntime(runtime); err != nil {
		return err
	}
	if err := validateTools(tools); err != nil {
		return err
	}
	if err := validateCodeServer(codeServer); err != nil {
		return err
	}
	return validateResources(resources)
}

func validateRuntime(value Runtime) error {
	if err := validateCommand(value.RuntimeCommand); err != nil {
		return errors.New("runtime command is invalid")
	}
	if value.Resume != nil {
		if err := validateCommand(*value.Resume); err != nil {
			return errors.New("runtime resume command is invalid")
		}
	}
	if (value.Autonomy != "trusted-local" && value.Autonomy != "interactive") ||
		(value.User != "root" && value.User != "non-root") {
		return errors.New("runtime autonomy or user is invalid")
	}
	if len(value.Env) > maxEnvironmentVariables {
		return errors.New("runtime environment exceeds its limit")
	}
	for name, environmentValue := range value.Env {
		if len(name) > 128 || !environmentPattern.MatchString(name) ||
			len(environmentValue) > maxEnvironmentValueBytes || strings.ContainsRune(environmentValue, 0) ||
			sensitiveEnvironmentName(name) {
			return errors.New("runtime environment is invalid")
		}
	}
	if len(value.Preseed) > maxPreseedFiles {
		return errors.New("runtime preseed exceeds its limit")
	}
	seen := make(map[string]struct{}, len(value.Preseed))
	for _, file := range value.Preseed {
		if !strings.HasPrefix(file.Path, "$HOME/") || len(file.Path) > 4096 || containsControl(file.Path) ||
			strings.Contains(file.Path, "//") || hasDotPathSegment(strings.TrimPrefix(file.Path, "$HOME/")) {
			return errors.New("runtime preseed path is invalid")
		}
		if _, duplicate := seen[file.Path]; duplicate {
			return errors.New("runtime preseed path is duplicated")
		}
		seen[file.Path] = struct{}{}
		if file.Mode != "0600" && file.Mode != "0644" {
			return errors.New("runtime preseed mode is invalid")
		}
		hasContent := file.Content != nil
		hasJSON := len(file.JSON) != 0
		if hasContent == hasJSON {
			return errors.New("runtime preseed must contain exactly one content form")
		}
		if hasContent && len(*file.Content) > maxPreseedFileBytes {
			return errors.New("runtime preseed content exceeds its limit")
		}
		if hasJSON {
			if len(file.JSON) > maxPreseedFileBytes || validateRawJSON(file.JSON) != nil {
				return errors.New("runtime preseed JSON is invalid")
			}
		}
	}
	return nil
}

func validateCommand(value RuntimeCommand) error {
	if !validBoundedText(value.Command, maxCommandBytes, false) ||
		strings.ContainsAny(value.Command, " \t") || len(value.Args) > maxArguments {
		return errors.New("invalid command")
	}
	for _, argument := range value.Args {
		if len(argument) > maxArgumentBytes || strings.ContainsRune(argument, 0) || !utf8.ValidString(argument) {
			return errors.New("invalid command argument")
		}
	}
	return nil
}

func validateTools(value Tools) error {
	if len(value.Packages) > maxToolEntries || len(value.Mise) > maxToolEntries ||
		len(value.AdditionalPaths) > maxToolEntries || len(value.Shell) > maxToolEntries {
		return errors.New("tools configuration exceeds its limit")
	}
	for _, values := range [][]string{value.Packages, value.Mise} {
		if err := validateUniqueStrings(values, func(item string) bool {
			return len(item) <= 512 && packagePattern.MatchString(item)
		}); err != nil {
			return errors.New("tools package configuration is invalid")
		}
	}
	if err := validateUniqueStrings(value.AdditionalPaths, func(item string) bool {
		return len(item) <= 4096 && strings.HasPrefix(item, "/") && !containsControl(item)
	}); err != nil {
		return errors.New("tools additional paths are invalid")
	}
	if err := validateUniqueStrings(value.Shell, func(item string) bool {
		return validBoundedText(item, 16<<10, false)
	}); err != nil {
		return errors.New("tools shell configuration is invalid")
	}
	return nil
}

func validateCodeServer(value CodeServer) error {
	if len(value.Extensions) > maxCodeServerExtensions || len(value.Settings) > maxCodeServerSettings {
		return errors.New("code-server configuration exceeds its limit")
	}
	if err := validateUniqueStrings(value.Extensions, func(item string) bool {
		return len(item) <= 256 && providerPattern.MatchString(item)
	}); err != nil {
		return errors.New("code-server extensions are invalid")
	}
	total := 0
	for name, setting := range value.Settings {
		if !validBoundedText(name, 256, false) || len(setting) > 4096 || validateRawJSON(setting) != nil {
			return errors.New("code-server settings are invalid")
		}
		total += len(name) + len(setting)
	}
	if total > maxCodeServerSettingsBytes {
		return errors.New("code-server settings exceed their byte limit")
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
		if !validProvider(mapping.Name) || !validProvider(mapping.BrokerProvider) || len(mapping.Repositories) > maxPatternsPerProvider {
			return errors.New("credential provider mapping is invalid")
		}
		if _, duplicate := aliases[mapping.Name]; duplicate {
			return errors.New("credential provider mapping is duplicated")
		}
		if _, granted := providers[mapping.BrokerProvider]; !granted {
			return errors.New("credential provider mapping references an ungranted provider")
		}
		if err := validateUniqueStrings(mapping.Repositories, validRepositoryPattern); err != nil {
			return errors.New("credential provider repository patterns are invalid")
		}
		aliases[mapping.Name] = mapping
	}
	identifiers := make(map[string]struct{}, len(repositories))
	paths := make(map[string]struct{}, len(repositories))
	for _, repository := range repositories {
		if !validRepositoryID(repository.ID) || repositoryIDFromURL(repository.URL) != repository.ID ||
			!validCheckoutPath(repository.Path) {
			return errors.New("workflow repository is invalid")
		}
		if _, duplicate := identifiers[repository.ID]; duplicate {
			return errors.New("workflow repository is duplicated")
		}
		identifiers[repository.ID] = struct{}{}
		effectivePath := repository.Path
		if effectivePath == "" {
			effectivePath = path.Base(strings.TrimSuffix(repository.ID, ".git"))
		}
		if _, duplicate := paths[effectivePath]; duplicate {
			return errors.New("workflow checkout path is duplicated")
		}
		paths[effectivePath] = struct{}{}
		if repository.CredentialProvider == "" {
			continue
		}
		mapping, exists := aliases[repository.CredentialProvider]
		if !exists || !patternsContain(mapping.Repositories, repository.ID) {
			return errors.New("workflow repository is not authorized by its credential mapping")
		}
		grant := providers[mapping.BrokerProvider]
		if !patternsContain(grant.Repositories, repository.ID) {
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

func repositoryIDFromURL(value string) string {
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

func validateRawJSON(value json.RawMessage) error {
	if err := rejectDuplicateKeys(value); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	if err := ensureDecoderEOF(decoder); err != nil {
		return err
	}
	return nil
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
