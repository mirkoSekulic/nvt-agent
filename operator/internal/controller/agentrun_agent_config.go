package controller

import (
	"fmt"
	"strings"

	"sigs.k8s.io/yaml"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

// RenderAgentConfigYAML converts the preserved AgentRun agent config payload to YAML.
func RenderAgentConfigYAML(agentRun *nvtv1alpha1.AgentRun) (string, error) {
	rawConfig := agentRun.Spec.Agent.Config.Raw
	if len(rawConfig) == 0 {
		rawConfig = []byte("{}")
	}

	if promptText := AgentRunPromptText(agentRun); promptText != "" ||
		AgentRunEgressMode(agentRun) == nvtv1alpha1.AgentRunEgressMediated ||
		AgentRunNeedsRuntimeRendering(agentRun) {
		config := map[string]any{}
		if err := yaml.Unmarshal(rawConfig, &config); err != nil {
			return "", fmt.Errorf("render AgentRun agent config: %w", err)
		}
		renderedConfig := config
		var err error
		renderedConfig, err = InjectAgentRunRuntimeConfig(renderedConfig, agentRun)
		if err != nil {
			return "", err
		}
		renderedConfig = InjectRuntimePreseed(renderedConfig, agentRun)
		if promptText != "" {
			renderedConfig, err = InjectRuntimeInitialPrompt(renderedConfig, promptText)
			if err != nil {
				return "", err
			}
		}
		if AgentRunEgressMode(agentRun) == nvtv1alpha1.AgentRunEgressMediated {
			renderedConfig = InjectMediatedEgressConfig(renderedConfig, agentRun)
		}
		if AgentRunLiteralZeroSecret(agentRun) {
			var err error
			renderedConfig, err = InjectLifecycleTerminationPlugin(renderedConfig, agentRun)
			if err != nil {
				return "", err
			}
		}
		rendered, err := yaml.Marshal(renderedConfig)
		if err != nil {
			return "", fmt.Errorf("render AgentRun agent config: %w", err)
		}
		return string(rendered), nil
	}

	rendered, err := yaml.JSONToYAML(rawConfig)
	if err != nil {
		return "", fmt.Errorf("render AgentRun agent config: %w", err)
	}

	return string(rendered), nil
}

func AgentRunNeedsRuntimeRendering(agentRun *nvtv1alpha1.AgentRun) bool {
	return agentRun.Spec.Runtime.Type != "" || agentRun.Spec.Runtime.Autonomy != "" ||
		agentRun.Spec.Runtime.Model != "" || agentRun.Spec.Runtime.Effort != ""
}

// InjectAgentRunRuntimeConfig translates the typed runtime selection into the
// generic runtime command contract consumed by bootstrap. Explicit runtime.args
// are an intentional complete override and are preserved byte-for-byte; when
// args are omitted, the operator supplies the established autonomy defaults.
func InjectAgentRunRuntimeConfig(config map[string]any, agentRun *nvtv1alpha1.AgentRun) (map[string]any, error) {
	runtimeConfig, exists := config["runtime"].(map[string]any)
	if !exists {
		if config["runtime"] != nil {
			return nil, fmt.Errorf("render AgentRun agent config: runtime must be an object")
		}
		runtimeConfig = map[string]any{}
	}
	runtimeConfig = cloneStringAnyMap(runtimeConfig)
	runtimeType := agentRun.Spec.Runtime.Type
	if runtimeType != "codex" && runtimeType != "claude" {
		return nil, fmt.Errorf("render AgentRun agent config: unsupported spec.runtime.type %q", runtimeType)
	}
	if command, present := runtimeConfig["command"]; present {
		if value, ok := command.(string); !ok || strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("render AgentRun agent config: runtime.command must be a non-empty string")
		}
	} else {
		runtimeConfig["command"] = runtimeType
	}
	if rawArgs, explicit := runtimeConfig["args"]; explicit {
		args, ok := rawArgs.([]any)
		if !ok {
			return nil, fmt.Errorf("render AgentRun agent config: runtime.args must be a list of strings")
		}
		for _, rawArg := range args {
			if _, ok := rawArg.(string); !ok {
				return nil, fmt.Errorf("render AgentRun agent config: runtime.args must be a list of strings")
			}
		}
	} else {
		switch agentRun.Spec.Runtime.Autonomy {
		case "trusted-local":
			if runtimeType == "codex" {
				runtimeConfig["args"] = []any{"--sandbox", "danger-full-access", "--ask-for-approval", "never"}
			} else {
				runtimeConfig["args"] = []any{"--dangerously-skip-permissions"}
			}
		case "interactive":
			runtimeConfig["args"] = []any{}
		default:
			return nil, fmt.Errorf("render AgentRun agent config: unsupported spec.runtime.autonomy %q", agentRun.Spec.Runtime.Autonomy)
		}
	}
	args := runtimeConfig["args"].([]any)
	args, err := injectRuntimeSelectionArgs(args, runtimeType, agentRun.Spec.Runtime.Model, agentRun.Spec.Runtime.Effort)
	if err != nil {
		return nil, fmt.Errorf("render AgentRun agent config: %w", err)
	}
	runtimeConfig["args"] = args
	if rawResume, present := runtimeConfig["resume"]; present {
		resume, ok := rawResume.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("render AgentRun agent config: runtime.resume must be an object")
		}
		resume = cloneStringAnyMap(resume)
		rawResumeArgs, present := resume["args"]
		if !present {
			rawResumeArgs = []any{}
		}
		resumeArgs, ok := rawResumeArgs.([]any)
		if !ok {
			return nil, fmt.Errorf("render AgentRun agent config: runtime.resume.args must be a list of strings")
		}
		for _, rawArg := range resumeArgs {
			if _, ok := rawArg.(string); !ok {
				return nil, fmt.Errorf("render AgentRun agent config: runtime.resume.args must be a list of strings")
			}
		}
		resumeArgs, err = injectRuntimeSelectionArgs(resumeArgs, runtimeType, agentRun.Spec.Runtime.Model, agentRun.Spec.Runtime.Effort)
		if err != nil {
			return nil, fmt.Errorf("render AgentRun agent config: runtime.resume: %w", err)
		}
		resume["args"] = resumeArgs
		runtimeConfig["resume"] = resume
	}
	updated := cloneStringAnyMap(config)
	updated["runtime"] = runtimeConfig
	return updated, nil
}

func injectRuntimeSelectionArgs(args []any, runtimeType, model, effort string) ([]any, error) {
	for index, raw := range args {
		arg := raw.(string)
		if model != "" && (arg == "--model" || arg == "-m" || strings.HasPrefix(arg, "--model=")) {
			return nil, fmt.Errorf("typed model conflicts with runtime args model selector")
		}
		if effort != "" {
			conflict := arg == "--effort" || strings.HasPrefix(arg, "--effort=")
			if runtimeType == "codex" {
				conflict = strings.HasPrefix(arg, "--config=model_reasoning_effort=") || strings.HasPrefix(arg, "-cmodel_reasoning_effort=") ||
					((arg == "--config" || arg == "-c") && index+1 < len(args) && strings.HasPrefix(args[index+1].(string), "model_reasoning_effort="))
			}
			if conflict {
				return nil, fmt.Errorf("typed effort conflicts with runtime args effort selector")
			}
		}
	}
	result := append([]any{}, args...)
	if model != "" {
		result = append(result, "--model", model)
	}
	if effort != "" {
		if runtimeType == "codex" {
			result = append(result, "--config", "model_reasoning_effort="+effort)
		} else {
			result = append(result, "--effort", effort)
		}
	}
	return result, nil
}

func AgentRunNeedsRuntimePreseed(agentRun *nvtv1alpha1.AgentRun) bool {
	return agentRun.Spec.Runtime.Type == "codex"
}

func InjectRuntimePreseed(config map[string]any, agentRun *nvtv1alpha1.AgentRun) map[string]any {
	if !AgentRunNeedsRuntimePreseed(agentRun) {
		return config
	}
	if _, ok := config["preseed"]; ok {
		return config
	}
	updated := cloneStringAnyMap(config)
	updated["preseed"] = map[string]any{
		"files": []any{
			map[string]any{
				"path":      "$HOME/.codex/config.toml",
				"mode":      "0600",
				"overwrite": false,
				"content":   "check_for_update_on_startup = false\n",
			},
		},
	}
	return updated
}

func InjectMediatedEgressConfig(config map[string]any, agentRun *nvtv1alpha1.AgentRun) map[string]any {
	enforced := AgentRunEgressEnforced(agentRun)
	forwardProxy := AgentRunEgressForwardProxy(agentRun)
	grants := []any{}
	routeIndex := 0
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		// In forward-proxy mode header-inject grants are reached through the
		// proxy (HTTP(S)_PROXY), not a per-route base URL. Still render the
		// grant metadata so runtime.proxy.provider can validate the selected
		// provider against egress.grants.
		if forwardProxy && AgentRunGrantMaterialization(grant) == nvtv1alpha1.AgentRunGrantHeaderInject {
			grants = append(grants, map[string]any{
				"provider":        grant.Provider,
				"materialization": string(nvtv1alpha1.AgentRunGrantHeaderInject),
			})
			continue
		}
		if AgentRunGrantMaterialization(grant) != nvtv1alpha1.AgentRunGrantHeaderInject {
			continue
		}
		baseURL := fmt.Sprintf("http://127.0.0.1:%d", egressRouteBasePort+routeIndex)
		if enforced {
			// Own-Pod egressd: every route is reached through the per-run
			// Service and terminates TLS under the per-agent CA.
			baseURL = fmt.Sprintf("https://%s:%d", EgressdServiceName(agentRun.Name), egressRouteBasePort+routeIndex)
		} else if grant.Git {
			baseURL = fmt.Sprintf("https://127.0.0.1:%d", egressRouteBasePort+routeIndex)
		}
		grants = append(grants, map[string]any{
			"provider":        grant.Provider,
			"materialization": string(nvtv1alpha1.AgentRunGrantHeaderInject),
			"base-url":        baseURL,
			"hosts":           append([]string(nil), grant.EgressHosts...),
			"git":             grant.Git,
		})
		routeIndex++
	}
	// placeholder-file grants carry no egressd route (edge injection is Phase
	// 6.2); bootstrap only needs the provider + mode to materialize the inert
	// placeholder auth file.
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		if AgentRunGrantMaterialization(grant) != nvtv1alpha1.AgentRunGrantPlaceholderFile {
			continue
		}
		grants = append(grants, map[string]any{
			"provider":        grant.Provider,
			"materialization": string(nvtv1alpha1.AgentRunGrantPlaceholderFile),
		})
	}
	updated := cloneStringAnyMap(config)
	egress := map[string]any{
		"mode":        string(nvtv1alpha1.AgentRunEgressMediated),
		"transport":   string(AgentRunEgressTransport(agentRun)),
		"placeholder": "NVT-PLACEHOLDER-NOT-A-KEY",
		"grants":      grants,
	}
	if enforced {
		egress["enforcement"] = true
		egress["operator-prepared"] = true
	}
	if forwardProxy {
		// Supply the endpoint for proxy-based transports. The transport field is
		// the sole behavior selector; the MITM leaf is trusted system-wide.
		proxyURL := fmt.Sprintf("http://%s:%d", EgressdServiceName(agentRun.Name), egressForwardProxyPort)
		if AgentRunEgressTransport(agentRun) == nvtv1alpha1.AgentRunEgressTransportTransparent {
			// Keep proxy-aware tools on the credential-less local transport too.
			// captured preserves explicit provider userinfo before relaying to the
			// paired egressd; bootstrap must not overwrite this with the Service.
			proxyURL = fmt.Sprintf("http://127.0.0.1:%d", capturedExplicitPort)
		}
		egress["forward-proxy-url"] = proxyURL
	}
	updated["egress"] = egress
	return updated
}

func AgentRunLiteralZeroSecret(agentRun *nvtv1alpha1.AgentRun) bool {
	return AgentRunEgressMode(agentRun) == nvtv1alpha1.AgentRunEgressMediated && AgentRunEgressEnforced(agentRun)
}

func InjectLifecycleTerminationPlugin(config map[string]any, agentRun *nvtv1alpha1.AgentRun) (map[string]any, error) {
	if agentRun.Spec.Lifecycle == nil || (len(agentRun.Spec.Lifecycle.CompleteOn) == 0 && len(agentRun.Spec.Lifecycle.FailOn) == 0) {
		return config, nil
	}
	plugins, err := agentConfigPlugins(config)
	if err != nil {
		return nil, err
	}
	updatedPlugins := make([]any, 0, len(plugins)+1)
	for _, raw := range plugins {
		plugin, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("render AgentRun agent config: plugins entries must be objects")
		}
		name, _ := plugin["name"].(string)
		if name == lifecycleReporterPlugin {
			return nil, fmt.Errorf("render AgentRun agent config: plugin %q is reserved for enforced zero-secret lifecycle reporting", lifecycleReporterPlugin)
		}
		if name == "event-webhook" && isOperatorLifecycleWebhook(plugin) {
			continue
		}
		if name == "smoke-complete" {
			plugin = cloneStringAnyMap(plugin)
			pluginConfig, _ := plugin["config"].(map[string]any)
			pluginConfig = cloneStringAnyMap(pluginConfig)
			if wait, present := pluginConfig["waitForPlugin"]; !present || wait == "event-webhook" {
				pluginConfig["waitForPlugin"] = lifecycleReporterPlugin
			}
			plugin["config"] = pluginConfig
		}
		updatedPlugins = append(updatedPlugins, plugin)
	}
	updatedPlugins = append(updatedPlugins, map[string]any{
		"name": lifecycleReporterPlugin, "source": "builtin", "when": "after-agent", "restart": "always",
		"config": map[string]any{
			"completeOn":             append([]string(nil), agentRun.Spec.Lifecycle.CompleteOn...),
			"failOn":                 append([]string(nil), agentRun.Spec.Lifecycle.FailOn...),
			"terminationMessagePath": "/dev/termination-log",
		},
	})
	updated := cloneStringAnyMap(config)
	updated["plugins"] = updatedPlugins
	return updated, nil
}

func isOperatorLifecycleWebhook(plugin map[string]any) bool {
	config, _ := plugin["config"].(map[string]any)
	urlValue, _ := config["url"].(string)
	auth, _ := config["auth"].(map[string]any)
	env, _ := auth["env"].(string)
	return strings.Contains(urlValue, "/v1/agentruns/") && strings.HasSuffix(urlValue, "/events") && env == callbackTokenKey
}

// AgentRunPromptText returns the configured prompt text when present and non-empty.
func AgentRunPromptText(agentRun *nvtv1alpha1.AgentRun) string {
	if agentRun.Spec.Prompt == nil {
		return ""
	}
	return agentRun.Spec.Prompt.Text
}

// InjectRuntimeInitialPrompt maps the typed AgentRun prompt onto the generic
// runtime launch contract. Bootstrap appends the text as the final command
// argument; it does not need to know which interactive agent implements that
// contract.
func InjectRuntimeInitialPrompt(config map[string]any, promptText string) (map[string]any, error) {
	runtimeConfig, ok := config["runtime"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("render AgentRun agent config: runtime must be an object")
	}
	if _, exists := runtimeConfig["initial-prompt"]; exists {
		return nil, fmt.Errorf("render AgentRun agent config: spec.prompt.text cannot be used when agent.config.runtime.initial-prompt is already configured")
	}

	runtimeConfig = cloneStringAnyMap(runtimeConfig)
	runtimeConfig["initial-prompt"] = map[string]any{
		"delivery": "argument",
		"text":     promptText,
	}
	updatedConfig := cloneStringAnyMap(config)
	updatedConfig["runtime"] = runtimeConfig
	return updatedConfig, nil
}

func agentConfigPlugins(config map[string]any) ([]any, error) {
	rawPlugins, ok := config["plugins"]
	if !ok || rawPlugins == nil {
		return nil, nil
	}
	plugins, ok := rawPlugins.([]any)
	if !ok {
		return nil, fmt.Errorf("render AgentRun agent config: plugins must be a list")
	}
	return plugins, nil
}

func cloneStringAnyMap(input map[string]any) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}
