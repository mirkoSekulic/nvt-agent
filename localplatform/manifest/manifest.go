// Package manifest defines the behavior-inactive, administrator-authored
// nvt.dev/local/v1 local-platform contract.
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	APIVersion       = "nvt.dev/local/v1"
	MaxDocumentBytes = 1 << 20
	MaxDocumentNodes = 32768
	MaxDocumentDepth = 64
	MaxItems         = 256
	MaxNameBytes     = 63
	MaxStringBytes   = 4096
)

var (
	namePattern        = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$`)
	repositoryPattern  = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	digestImagePattern = regexp.MustCompile(`^[^[:space:]@]+@sha256:[a-f0-9]{64}$`)
	secretKeyPattern   = regexp.MustCompile(`(?i)(secret|token|password|passwd|private.?key|credential|api.?key)`)
)

type Manifest struct {
	APIVersion   string              `json:"apiVersion"`
	Secrets      map[string]Secret   `json:"secrets,omitempty"`
	Accounts     map[string]Account  `json:"accounts,omitempty"`
	Profiles     map[string]Profile  `json:"profiles"`
	Workstations []Workstation       `json:"workstations,omitempty"`
	Workflows    map[string]Workflow `json:"workflows"`
	Producers    []Producer          `json:"producers,omitempty"`
}

type Secret struct {
	File string `json:"file"`
}

type Account struct {
	Preset           string            `json:"preset"`
	AppID            string            `json:"appId,omitempty"`
	PrivateKeySecret string            `json:"privateKeySecret,omitempty"`
	TokenSecret      string            `json:"tokenSecret,omitempty"`
	Installations    map[string]string `json:"installations,omitempty"`
}

type Profile struct {
	Runtime      Runtime  `json:"runtime"`
	Accounts     []string `json:"accounts,omitempty"`
	Tools        Tools    `json:"tools,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Instructions *FileRef `json:"instructions,omitempty"`
	Editor       Editor   `json:"editor,omitempty"`
	Plugins      []string `json:"plugins,omitempty"`
}

type Runtime struct {
	Preset   string `json:"preset"`
	Autonomy string `json:"autonomy"`
}
type Tools struct {
	Packages []string `json:"packages,omitempty"`
	Mise     []string `json:"mise,omitempty"`
}

type FileRef struct {
	File string `json:"file"`
}
type Editor struct {
	Preset string `json:"preset,omitempty"`
}

type Workstation struct {
	Name         string   `json:"name"`
	Profile      string   `json:"profile"`
	Repositories []string `json:"repositories,omitempty"`
}

type Workflow struct {
	Profile    string `json:"profile"`
	Repository string `json:"repository"`
	Retention  string `json:"retention"`
}

type Producer struct {
	Name           string            `json:"name"`
	Preset         string            `json:"preset,omitempty"`
	Image          string            `json:"image,omitempty"`
	Account        string            `json:"account,omitempty"`
	Repository     string            `json:"repository,omitempty"`
	Prefix         string            `json:"prefix,omitempty"`
	AllowedAuthors []string          `json:"allowedAuthors,omitempty"`
	Workflow       string            `json:"workflow"`
	Config         map[string]any    `json:"config,omitempty"`
	Secrets        map[string]string `json:"secrets,omitempty"`
}

// Decode parses exactly one bounded YAML document and validates all references.
// It deliberately does not open referenced files.
func Decode(reader io.Reader) (Manifest, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxDocumentBytes+1))
	if err != nil || len(data) == 0 || len(data) > MaxDocumentBytes || !utf8.Valid(data) {
		return Manifest{}, errors.New("invalid local manifest document")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil || len(document.Content) != 1 {
		return Manifest{}, errors.New("invalid local manifest YAML")
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("local manifest must contain exactly one document")
	}
	nodes := 0
	if err := validateNode(document.Content[0], 0, &nodes); err != nil {
		return Manifest{}, err
	}
	var raw any
	if err := document.Content[0].Decode(&raw); err != nil {
		return Manifest{}, errors.New("invalid local manifest value")
	}
	canonical, err := json.Marshal(raw)
	if err != nil || len(canonical) > MaxDocumentBytes {
		return Manifest{}, errors.New("invalid local manifest value")
	}
	var result Manifest
	if err := strictJSON(canonical, &result); err != nil {
		return Manifest{}, fmt.Errorf("invalid local manifest schema: %w", err)
	}
	if err := result.Validate(); err != nil {
		return Manifest{}, err
	}
	return result, nil
}

func strictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) {
		return errors.New("trailing value")
	}
	return nil
}

func validateNode(node *yaml.Node, depth int, nodes *int) error {
	if node == nil || depth > MaxDocumentDepth {
		return errors.New("local manifest exceeds maximum depth")
	}
	*nodes++
	if *nodes > MaxDocumentNodes || node.Alias != nil || node.Anchor != "" {
		return errors.New("local manifest has too many nodes or uses aliases")
	}
	switch node.Kind {
	case yaml.MappingNode:
		if len(node.Content)%2 != 0 {
			return errors.New("invalid mapping")
		}
		seen := map[string]struct{}{}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "" {
				return errors.New("mapping keys must be non-empty strings")
			}
			if _, ok := seen[key.Value]; ok {
				return fmt.Errorf("duplicate key %q", key.Value)
			}
			seen[key.Value] = struct{}{}
			if err := validateNode(node.Content[i+1], depth+1, nodes); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if err := validateNode(child, depth+1, nodes); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		if node.Tag != "!!str" && node.Tag != "!!bool" && node.Tag != "!!int" && node.Tag != "!!null" {
			return fmt.Errorf("unsupported scalar tag %q", node.Tag)
		}
		if len(node.Value) > MaxStringBytes {
			return errors.New("local manifest scalar is too large")
		}
	default:
		return errors.New("unsupported YAML node")
	}
	return nil
}

func (m Manifest) Validate() error {
	if m.APIVersion != APIVersion {
		return fmt.Errorf("apiVersion must be %q", APIVersion)
	}
	if len(m.Profiles) == 0 || len(m.Workflows) == 0 {
		return errors.New("profiles and workflows are required")
	}
	for label, count := range map[string]int{"secrets": len(m.Secrets), "accounts": len(m.Accounts), "profiles": len(m.Profiles), "workstations": len(m.Workstations), "workflows": len(m.Workflows), "producers": len(m.Producers)} {
		if count > MaxItems {
			return fmt.Errorf("too many %s", label)
		}
	}
	for name, secret := range m.Secrets {
		if !validName(name) || !safeRelativePath(secret.File, ".nvt-local/secrets/") {
			return fmt.Errorf("invalid secret %q", name)
		}
	}
	for name, account := range m.Accounts {
		if !validName(name) || !oneOf(account.Preset, "codex-oauth", "claude-oauth", "github-app", "github-pat", "azure-devops-pat") {
			return fmt.Errorf("invalid account %q", name)
		}
		if account.PrivateKeySecret != "" && !has(m.Secrets, account.PrivateKeySecret) || account.TokenSecret != "" && !has(m.Secrets, account.TokenSecret) {
			return fmt.Errorf("account %q references an unknown secret", name)
		}
		if account.Preset == "github-app" && (account.AppID == "" || account.PrivateKeySecret == "" || len(account.Installations) == 0) {
			return fmt.Errorf("github-app account %q is incomplete", name)
		}
		if account.Preset != "github-app" && (account.AppID != "" || account.PrivateKeySecret != "" || len(account.Installations) != 0) {
			return fmt.Errorf("account %q has fields not valid for its preset", name)
		}
		if (account.Preset == "github-pat" || account.Preset == "azure-devops-pat") != (account.TokenSecret != "") {
			return fmt.Errorf("account %q has invalid tokenSecret", name)
		}
		for owner, installation := range account.Installations {
			if !validName(strings.ToLower(owner)) || installation == "" {
				return fmt.Errorf("account %q has an invalid installation", name)
			}
		}
	}
	for name, profile := range m.Profiles {
		if !validName(name) || !oneOf(profile.Runtime.Preset, "codex", "claude", "shell") || !oneOf(profile.Runtime.Autonomy, "trusted-local", "approval-required", "read-only") {
			return fmt.Errorf("invalid profile %q", name)
		}
		if err := uniqueRefs(profile.Accounts, m.Accounts, "account"); err != nil {
			return fmt.Errorf("profile %q: %w", name, err)
		}
		if err := uniqueStrings(profile.Tools.Packages); err != nil {
			return fmt.Errorf("profile %q packages: %w", name, err)
		}
		if err := uniqueStrings(profile.Tools.Mise); err != nil {
			return fmt.Errorf("profile %q mise: %w", name, err)
		}
		for _, capability := range profile.Capabilities {
			if !oneOf(capability, "SYS_PTRACE", "NET_ADMIN", "NET_RAW") {
				return fmt.Errorf("profile %q has invalid capability", name)
			}
		}
		if err := uniqueStrings(profile.Capabilities); err != nil {
			return err
		}
		if err := uniqueStrings(profile.Plugins); err != nil {
			return err
		}
		if profile.Instructions != nil && !safeRelativePath(profile.Instructions.File, "") {
			return fmt.Errorf("profile %q has unsafe instruction path", name)
		}
		if profile.Editor.Preset != "" && !oneOf(profile.Editor.Preset, "code-server", "none") {
			return fmt.Errorf("profile %q has invalid editor preset", name)
		}
	}
	seenWorkstations := map[string]struct{}{}
	for _, workstation := range m.Workstations {
		if !validName(workstation.Name) || !has(m.Profiles, workstation.Profile) {
			return fmt.Errorf("invalid workstation %q", workstation.Name)
		}
		if _, ok := seenWorkstations[workstation.Name]; ok {
			return fmt.Errorf("duplicate workstation %q", workstation.Name)
		}
		seenWorkstations[workstation.Name] = struct{}{}
		if err := repositories(workstation.Repositories); err != nil {
			return fmt.Errorf("workstation %q: %w", workstation.Name, err)
		}
	}
	for name, workflow := range m.Workflows {
		if !validName(name) || !has(m.Profiles, workflow.Profile) || !repositoryPattern.MatchString(workflow.Repository) || !oneOf(workflow.Retention, "disposable", "retained") {
			return fmt.Errorf("invalid workflow %q", name)
		}
	}
	seenProducers := map[string]struct{}{}
	for _, producer := range m.Producers {
		if !validName(producer.Name) || !has(m.Workflows, producer.Workflow) {
			return fmt.Errorf("invalid producer %q", producer.Name)
		}
		if _, ok := seenProducers[producer.Name]; ok {
			return fmt.Errorf("duplicate producer %q", producer.Name)
		}
		seenProducers[producer.Name] = struct{}{}
		if (producer.Preset == "") == (producer.Image == "") {
			return fmt.Errorf("producer %q must set exactly one of preset or image", producer.Name)
		}
		if producer.Preset != "" && producer.Preset != "github-comments" {
			return fmt.Errorf("producer %q has unknown preset", producer.Name)
		}
		if producer.Image != "" && !digestImagePattern.MatchString(producer.Image) {
			return fmt.Errorf("producer %q image must use an immutable sha256 digest", producer.Name)
		}
		if producer.Preset == "github-comments" && (!has(m.Accounts, producer.Account) || !repositoryPattern.MatchString(producer.Repository) || producer.Prefix == "" || len(producer.AllowedAuthors) == 0) {
			return fmt.Errorf("built-in producer %q is incomplete", producer.Name)
		}
		if producer.Image != "" && (producer.Account != "" || producer.Repository != "" || producer.Prefix != "" || len(producer.AllowedAuthors) != 0) {
			return fmt.Errorf("external producer %q uses built-in fields", producer.Name)
		}
		if err := uniqueStrings(producer.AllowedAuthors); err != nil {
			return err
		}
		for _, ref := range producer.Secrets {
			if !has(m.Secrets, ref) {
				return fmt.Errorf("producer %q references an unknown secret", producer.Name)
			}
		}
		for mountName := range producer.Secrets {
			if !validName(mountName) {
				return fmt.Errorf("producer %q has an invalid secret mount name", producer.Name)
			}
		}
		if err := validateConfig(producer.Config, 0); err != nil {
			return fmt.Errorf("producer %q config: %w", producer.Name, err)
		}
	}
	return nil
}

func validName(v string) bool { return len(v) <= MaxNameBytes && namePattern.MatchString(v) }
func oneOf(v string, values ...string) bool {
	for _, candidate := range values {
		if v == candidate {
			return true
		}
	}
	return false
}
func has[T any](values map[string]T, key string) bool { _, ok := values[key]; return ok }
func safeRelativePath(value, requiredPrefix string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") || strings.ContainsRune(value, 0) {
		return false
	}
	normalized := strings.TrimPrefix(value, "./")
	return normalized != "." && normalized == path.Clean(normalized) && (requiredPrefix == "" || strings.HasPrefix(normalized, requiredPrefix))
}
func uniqueStrings(values []string) error {
	if len(values) > MaxItems {
		return errors.New("too many values")
	}
	seen := map[string]struct{}{}
	for _, v := range values {
		if v == "" || len(v) > MaxStringBytes {
			return errors.New("invalid value")
		}
		if _, ok := seen[v]; ok {
			return fmt.Errorf("duplicate value %q", v)
		}
		seen[v] = struct{}{}
	}
	return nil
}
func uniqueRefs[T any](refs []string, values map[string]T, kind string) error {
	if err := uniqueStrings(refs); err != nil {
		return err
	}
	for _, ref := range refs {
		if !has(values, ref) {
			return fmt.Errorf("unknown %s %q", kind, ref)
		}
	}
	return nil
}
func repositories(values []string) error {
	if err := uniqueStrings(values); err != nil {
		return err
	}
	for _, v := range values {
		if !repositoryPattern.MatchString(v) {
			return fmt.Errorf("invalid repository %q", v)
		}
	}
	return nil
}
func validateConfig(value any, depth int) error {
	if depth > 16 {
		return errors.New("config is too deep")
	}
	switch typed := value.(type) {
	case nil, bool, string, json.Number, float64:
		if s, ok := typed.(string); ok && len(s) > MaxStringBytes {
			return errors.New("value too large")
		}
		return nil
	case []any:
		if len(typed) > MaxItems {
			return errors.New("too many values")
		}
		for _, v := range typed {
			if err := validateConfig(v, depth+1); err != nil {
				return err
			}
		}
	case map[string]any:
		if len(typed) > MaxItems {
			return errors.New("too many keys")
		}
		for k, v := range typed {
			if k == "" || len(k) > MaxNameBytes || secretKeyPattern.MatchString(k) {
				return fmt.Errorf("secret-bearing or invalid key %q", k)
			}
			if err := validateConfig(v, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unsupported config value")
	}
	return nil
}

// SortedNames returns map keys in the canonical compiler order.
func SortedNames[T any](values map[string]T) []string {
	result := make([]string, 0, len(values))
	for name := range values {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}
