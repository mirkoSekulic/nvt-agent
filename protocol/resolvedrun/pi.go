package resolvedrun

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// PiConfig is public administrator-owned configuration, never a Pi home or an
// auth/models.json import. Credential resolvers and arbitrary headers are absent
// deliberately. Extension source is executable workload code, not a boundary.
type PiConfig struct {
	Provider   string          `json:"provider"`
	BaseURL    string          `json:"baseUrl"`
	API        string          `json:"api"`
	Models     []PiModel       `json:"models"`
	Compat     map[string]bool `json:"compat,omitempty"`
	Settings   map[string]bool `json:"settings,omitempty"`
	Extensions []PiExtension   `json:"extensions,omitempty"`
}
type PiModel struct {
	ID            string `json:"id"`
	Name          string `json:"name,omitempty"`
	Reasoning     bool   `json:"reasoning,omitempty"`
	ContextWindow int    `json:"contextWindow,omitempty"`
	MaxTokens     int    `json:"maxTokens,omitempty"`
}
type PiExtension struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

func (p *PiConfig) DeepCopy() *PiConfig {
	if p == nil {
		return nil
	}
	raw, _ := json.Marshal(p)
	var out PiConfig
	_ = json.Unmarshal(raw, &out)
	return &out
}

var piIdentifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,255}$`)
var piExtensionName = regexp.MustCompile(`^[a-zA-Z0-9_-]+\.(ts|js|mjs)$`)

// ValidatePiSelection is shared by local compilation and Kubernetes admission.
// Errors never interpolate public input: rejected credential-shaped values must
// not escape into logs either.
func ValidatePiSelection(r Runtime) error {
	if r.Type != "pi" {
		if r.Pi != nil || r.CredentialProvider != "" {
			return errors.New("Pi configuration requires runtime type pi")
		}
		return nil
	}
	if r.Autonomy != "trusted-local" {
		return errors.New("Pi requires trusted-local autonomy; interactive tool approval is unsupported")
	}
	p := r.Pi
	if p == nil || !validProvider(r.CredentialProvider) {
		return errors.New("Pi requires public configuration and a credentialProvider")
	}
	if !validProvider(p.Provider) || (p.API != "openai-completions" && p.API != "openai-responses") {
		return errors.New("invalid Pi provider or API (supported: openai-completions, openai-responses)")
	}
	u, err := url.Parse(p.BaseURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || len(p.BaseURL) > 2048 || strings.ContainsAny(p.BaseURL, "!$%\\\x00\r\n\t ") || (u.Port() != "" && u.Port() != "443") || strings.ToLower(u.Hostname()) != u.Hostname() {
		return errors.New("Pi baseUrl must be a public HTTPS URL without credentials, query, fragment, or interpolation, on port 443")
	}
	if !validEgressHost(u.Hostname() + ":443") {
		return errors.New("invalid Pi endpoint host")
	}
	if len(p.Models) == 0 || len(p.Models) > 128 {
		return errors.New("Pi requires a bounded model catalog")
	}
	seen := map[string]bool{}
	selected := false
	for _, m := range p.Models {
		if !piIdentifier.MatchString(m.ID) || seen[m.ID] || len(m.Name) > 256 || strings.ContainsAny(m.Name, "\x00\r\n!$") || m.ContextWindow < 0 || m.ContextWindow > 10000000 || m.MaxTokens < 0 || m.MaxTokens > 10000000 {
			return errors.New("invalid Pi model catalog")
		}
		seen[m.ID] = true
		selected = selected || r.Model == p.Provider+"/"+m.ID
	}
	if !selected || len(r.Model) > 256 {
		return errors.New("Pi model must select provider/id from the managed catalog")
	}
	if !containsString([]string{"", "off", "minimal", "low", "medium", "high", "xhigh"}, r.Effort) {
		return errors.New("unsupported Pi thinking effort")
	}
	for key := range p.Compat {
		if !containsString([]string{"supportsStore", "supportsDeveloperRole", "supportsReasoningEffort", "supportsUsageInStreaming", "requiresToolResultName", "requiresAssistantAfterToolResult", "requiresThinkingAsText", "supportsStrictMode"}, key) {
			return errors.New("unsupported Pi compatibility setting")
		}
	}
	for key := range p.Settings {
		if !containsString([]string{"hideThinkingBlock", "collapseChangelog", "showHardwareCursor"}, key) {
			return errors.New("unsupported Pi public setting")
		}
	}
	if len(p.Extensions) > 32 {
		return errors.New("too many Pi extensions")
	}
	seen = map[string]bool{}
	for _, e := range p.Extensions {
		if len(e.Name) > 128 || !piExtensionName.MatchString(e.Name) || seen[e.Name] || len(e.Content) == 0 || len(e.Content) > 65536 || strings.ContainsRune(e.Content, 0) {
			return errors.New("invalid Pi extension asset")
		}
		seen[e.Name] = true
	}
	return nil
}

// ValidatePiBinding requires an injection-only provider and exact HTTPS routes.
// This does not implement per-model, inference-only, or billing authorization.
func ValidatePiBinding(r Runtime, e Egress, b Broker) error {
	if err := ValidatePiSelection(r); err != nil {
		return err
	}
	if r.Type != "pi" {
		return nil
	}
	if e.Mode != "mediated" || !isTunnelTransport(e.Transport) || e.ProxyProvider != r.CredentialProvider {
		return errors.New("Pi requires mediated tunnel egress with its explicit credentialProvider")
	}
	u, _ := url.Parse(r.Pi.BaseURL)
	count := 0
	for _, g := range b.Grants {
		if g.Provider != r.CredentialProvider {
			continue
		}
		count++
		if g.Git || g.AllowInsecureUpstream || g.Materialization != "header-inject" || len(g.Capabilities) != 1 || g.Capabilities[0] != "injection.headers" || len(g.Preparations) != 0 || len(g.Repositories) != 0 || (!containsString(g.EgressHosts, u.Hostname()+":443") && !containsString(g.EgressHosts, u.Hostname())) {
			return errors.New("Pi model binding requires an injection-only header-inject grant for the endpoint host")
		}
	}
	if count != 1 {
		return errors.New("Pi model credentialProvider must have exactly one grant")
	}
	return nil
}

// ManagedPiRuntime rejects raw command/argument/environment overrides, then
// renders the same launch contract for both backends. Bootstrap owns filesystem
// preparation; agentd still sees only an interactive terminal process.
func ManagedPiRuntime(config map[string]any, r Runtime) (map[string]any, error) {
	if err := ValidatePiSelection(r); err != nil {
		return nil, err
	}
	for key, value := range config {
		switch key {
		case "command":
			if value != "pi" {
				return nil, errors.New("Pi runtime command is managed")
			}
		case "args":
			args, ok := stringArguments(value)
			if !ok || len(args) != 0 {
				return nil, errors.New("Pi raw arguments conflict with managed runtime selection")
			}
		default:
			return nil, errors.New("Pi runtime fields are managed; configure runtime.pi and typed selectors")
		}
	}
	args := []string{"--model", r.Model, "--thinking", r.Effort}
	if r.Effort == "" {
		args[len(args)-1] = "off"
	}
	return map[string]any{"command": "pi", "args": args, "resume": map[string]any{"command": "pi", "args": append([]string(nil), args...)}, "pi": r.Pi}, nil
}
