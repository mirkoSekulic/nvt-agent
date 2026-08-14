package resolvedrun

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
)

const runtimePlaceholder = "NVT-PLACEHOLDER-NOT-A-KEY"

var managedControllerPlugins = map[string]struct{}{
	"git-host-credentials": {},
	"git-credentials":      {},
	"checkout-repos":       {},
}

// RenderAgentConfig applies the controller-owned fields of a resolved run to
// its immutable base agent_config. Prompt, egress and repositories have one
// source of truth: their typed ResolvedAgentRun fields. Backends supply only
// the non-secret endpoints they provisioned and must execute this rendered
// value, not the base value.
func RenderAgentConfig(run ResolvedAgentRun, bindings AgentConfigBindings) (json.RawMessage, error) {
	if ValidateResolvedAgentRun(run) != nil {
		return nil, ErrInvalidConfiguration
	}
	if validateRenderBindings(run, bindings) != nil {
		return nil, ErrInvalidRenderBinding
	}
	root, err := decodeAgentConfigObject(run.AgentConfig)
	if err != nil {
		return nil, ErrInvalidRenderBinding
	}
	runtime := cloneStringAnyMap(root["runtime"].(map[string]any))
	if run.Prompt != "" {
		runtime["initial-prompt"] = map[string]any{"delivery": "argument", "text": run.Prompt}
	}
	if run.Egress.Mode == "mediated" && isTunnelTransport(run.Egress.Transport) {
		runtime["proxy"] = map[string]any{"provider": run.Egress.ProxyProvider}
	}
	root["runtime"] = runtime

	plugins, _ := root["plugins"].([]any)
	root["plugins"] = append(renderRepositoryPlugins(run), plugins...)
	if run.Egress.Mode == "mediated" {
		root["egress"] = renderEgress(run, bindings)
	}

	rendered, err := json.Marshal(root)
	if err != nil || len(rendered) > MaxDocumentBytes {
		return nil, ErrInvalidRenderBinding
	}
	return rendered, nil
}

func decodeAgentConfigObject(raw json.RawMessage) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		return nil, err
	}
	if err := ensureDecoderEOF(decoder); err != nil {
		return nil, err
	}
	return root, nil
}

func cloneStringAnyMap(input map[string]any) map[string]any {
	result := make(map[string]any, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func renderRepositoryPlugins(run ResolvedAgentRun) []any {
	plugins := make([]any, 0, 3)
	if len(run.CredentialProviders) != 0 {
		providers := make([]any, 0, len(run.CredentialProviders))
		for _, mapping := range run.CredentialProviders {
			provider := map[string]any{
				"name": mapping.Name, "type": "broker", "broker-provider": mapping.BrokerProvider,
				"match": append([]string(nil), mapping.MatchTargets...),
			}
			if mapping.CredentialKind != "" {
				provider["credential-kind"] = mapping.CredentialKind
			}
			providers = append(providers, provider)
		}
		plugins = append(plugins, map[string]any{
			"name": "git-host-credentials", "source": "builtin", "config": map[string]any{"providers": providers},
		})
	}
	credentials := make([]any, 0, len(run.Repositories))
	checkouts := make([]any, 0, len(run.Repositories))
	for _, repository := range run.Repositories {
		checkout := map[string]any{"url": repository.URL}
		if repository.Path != "" {
			checkout["path"] = repository.Path
		}
		if repository.Upstream != "" {
			checkout["upstream"] = repository.Upstream
		}
		checkouts = append(checkouts, checkout)
		if repository.CredentialProvider != "" {
			credential := map[string]any{
				"match": repository.URL, "provider": repository.CredentialProvider,
			}
			if repository.Identity != nil {
				identity := map[string]any{"mode": repository.Identity.Mode}
				if repository.Identity.Mode == "explicit" {
					identity["name"] = repository.Identity.Name
					identity["email"] = repository.Identity.Email
				}
				credential["identity"] = identity
			}
			credentials = append(credentials, credential)
		}
	}
	if len(credentials) != 0 {
		plugins = append(plugins, map[string]any{
			"name": "git-credentials", "source": "builtin", "when": "before-agent",
			"config": map[string]any{"credentials": credentials},
		})
	}
	if len(checkouts) != 0 {
		plugins = append(plugins, map[string]any{
			"name": "checkout-repos", "source": "builtin", "when": "before-agent", "restart": "never",
			"config": map[string]any{"repos": checkouts},
		})
	}
	return plugins
}

func renderEgress(run ResolvedAgentRun, bindings AgentConfigBindings) map[string]any {
	grants := make([]any, 0, len(run.Broker.Grants))
	for _, grant := range run.Broker.Grants {
		entry := map[string]any{"provider": grant.Provider, "materialization": grant.Materialization}
		if run.Egress.Transport == "redirect" && grant.Materialization == "header-inject" {
			entry["base-url"] = bindings.RedirectBaseURLs[grant.Provider]
			entry["hosts"] = append([]string(nil), grant.EgressHosts...)
			entry["git"] = grant.Git
		}
		grants = append(grants, entry)
	}
	egress := map[string]any{
		"mode": "mediated", "transport": run.Egress.Transport,
		"placeholder": runtimePlaceholder, "grants": grants,
	}
	if run.Egress.Enforced {
		egress["enforcement"] = true
		egress["operator-prepared"] = true
	}
	if isTunnelTransport(run.Egress.Transport) {
		egress["forward-proxy-url"] = bindings.ForwardProxyURL
	}
	return egress
}

func validateRenderBindings(run ResolvedAgentRun, bindings AgentConfigBindings) error {
	if run.Egress.Mode == "direct" {
		if bindings.ForwardProxyURL != "" || len(bindings.RedirectBaseURLs) != 0 {
			return ErrInvalidRenderBinding
		}
		return nil
	}
	if run.Egress.Transport == "redirect" {
		if bindings.ForwardProxyURL != "" {
			return ErrInvalidRenderBinding
		}
		expected := map[string]struct{}{}
		for _, grant := range run.Broker.Grants {
			if grant.Materialization != "header-inject" {
				continue
			}
			expected[grant.Provider] = struct{}{}
			if !validRuntimeEndpoint(bindings.RedirectBaseURLs[grant.Provider]) {
				return ErrInvalidRenderBinding
			}
		}
		if len(bindings.RedirectBaseURLs) != len(expected) {
			return ErrInvalidRenderBinding
		}
		for provider := range bindings.RedirectBaseURLs {
			if _, exists := expected[provider]; !exists {
				return ErrInvalidRenderBinding
			}
		}
		return nil
	}
	if len(bindings.RedirectBaseURLs) != 0 || !validRuntimeEndpoint(bindings.ForwardProxyURL) {
		return ErrInvalidRenderBinding
	}
	return nil
}

func validRuntimeEndpoint(value string) bool {
	if len(value) == 0 || len(value) > 4096 || value != strings.TrimSpace(value) || containsControl(value) {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" &&
		parsed.User == nil && parsed.Path == "" && parsed.RawPath == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func isTunnelTransport(transport string) bool {
	return transport == "forward-proxy" || transport == "transparent"
}
