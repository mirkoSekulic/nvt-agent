package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

var (
	errInvalidExecutionProfileConfiguration = errors.New("invalid execution profile configuration")
	errExecutionProfileSelectionDenied      = errors.New("execution profile selection denied")
)

// ResolvedExecutionProfile is the single immutable profile selected for a request.
type ResolvedExecutionProfile struct {
	Profile nvtv1alpha1.AgentScheduleExecutionProfile
}

// ExecutionProfileResolver resolves one profile without consulting producer-controlled fields.
type ExecutionProfileResolver interface {
	Resolve(*nvtv1alpha1.AgentSchedule, *nvtv1alpha1.AgentRunPrincipal) (*ResolvedExecutionProfile, error)
}

// StaticExecutionProfileResolver resolves exact issuer+subject rules from AgentSchedule.
type StaticExecutionProfileResolver struct{}

// ScheduleUsesExecutionProfiles reports whether any profiled-mode configuration is present.
func ScheduleUsesExecutionProfiles(schedule *nvtv1alpha1.AgentSchedule) bool {
	return schedule.Spec.Template != nil || len(schedule.Spec.Profiles) != 0 ||
		schedule.Spec.ProfileSelection != nil || len(schedule.Spec.AllowedProducers) != 0
}

func (StaticExecutionProfileResolver) Resolve(
	schedule *nvtv1alpha1.AgentSchedule,
	principal *nvtv1alpha1.AgentRunPrincipal,
) (*ResolvedExecutionProfile, error) {
	profiles, err := validateExecutionProfileSchedule(schedule)
	if err != nil {
		return nil, err
	}

	selection := schedule.Spec.ProfileSelection
	selected := ""
	if principal != nil {
		for i := range selection.Rules {
			rule := selection.Rules[i]
			if rule.Issuer == principal.Issuer && rule.Subject == principal.Subject {
				selected = rule.Profile
				break
			}
		}
	}
	if selected == "" {
		if selection.OnNoMatch != nvtv1alpha1.AgentScheduleOnNoMatchUseDefault {
			return nil, errExecutionProfileSelectionDenied
		}
		selected = selection.DefaultProfile
	}
	profile := profiles[selected]
	return &ResolvedExecutionProfile{Profile: *profile.DeepCopy()}, nil
}

func validateExecutionProfileSchedule(schedule *nvtv1alpha1.AgentSchedule) (map[string]nvtv1alpha1.AgentScheduleExecutionProfile, error) {
	if schedule.Spec.Template == nil || len(schedule.Spec.Profiles) == 0 ||
		schedule.Spec.ProfileSelection == nil || len(schedule.Spec.AllowedProducers) == 0 {
		return nil, errInvalidExecutionProfileConfiguration
	}
	template := schedule.Spec.Template
	if strings.TrimSpace(template.Image) == "" || strings.TrimSpace(template.Workspace.Mode) == "" {
		return nil, errInvalidExecutionProfileConfiguration
	}
	common, err := jsonObject(template.Agent.Config)
	if err != nil {
		return nil, errInvalidExecutionProfileConfiguration
	}
	if _, ownsRuntime := common["runtime"]; ownsRuntime {
		return nil, errInvalidExecutionProfileConfiguration
	}

	allowed := map[string]struct{}{}
	for _, producer := range schedule.Spec.AllowedProducers {
		if strings.TrimSpace(producer) == "" {
			return nil, errInvalidExecutionProfileConfiguration
		}
		if _, duplicate := allowed[producer]; duplicate {
			return nil, errInvalidExecutionProfileConfiguration
		}
		allowed[producer] = struct{}{}
	}

	profiles := make(map[string]nvtv1alpha1.AgentScheduleExecutionProfile, len(schedule.Spec.Profiles))
	for i := range schedule.Spec.Profiles {
		profile := schedule.Spec.Profiles[i]
		if strings.TrimSpace(profile.Name) == "" || strings.TrimSpace(profile.Runtime.Type) == "" ||
			strings.TrimSpace(profile.Runtime.Autonomy) == "" || profile.Egress == "" {
			return nil, errInvalidExecutionProfileConfiguration
		}
		if _, duplicate := profiles[profile.Name]; duplicate {
			return nil, errInvalidExecutionProfileConfiguration
		}
		if _, err := jsonObject(profile.AgentRuntimeConfig); err != nil {
			return nil, errInvalidExecutionProfileConfiguration
		}
		profiles[profile.Name] = profile
	}

	selection := schedule.Spec.ProfileSelection
	switch selection.OnNoMatch {
	case nvtv1alpha1.AgentScheduleOnNoMatchUseDefault:
		if selection.DefaultProfile == "" {
			return nil, errInvalidExecutionProfileConfiguration
		}
	case nvtv1alpha1.AgentScheduleOnNoMatchDeny:
		if len(selection.Rules) == 0 {
			return nil, errInvalidExecutionProfileConfiguration
		}
	default:
		return nil, errInvalidExecutionProfileConfiguration
	}
	if selection.DefaultProfile != "" {
		if _, exists := profiles[selection.DefaultProfile]; !exists {
			return nil, errInvalidExecutionProfileConfiguration
		}
	}
	selectors := map[string]struct{}{}
	for i := range selection.Rules {
		rule := selection.Rules[i]
		if strings.TrimSpace(rule.Issuer) == "" || strings.TrimSpace(rule.Subject) == "" {
			return nil, errInvalidExecutionProfileConfiguration
		}
		if _, exists := profiles[rule.Profile]; !exists {
			return nil, errInvalidExecutionProfileConfiguration
		}
		key := rule.Issuer + "\x00" + rule.Subject
		if _, duplicate := selectors[key]; duplicate {
			return nil, errInvalidExecutionProfileConfiguration
		}
		selectors[key] = struct{}{}
	}
	return profiles, nil
}

func jsonObject(value apiextensionsv1.JSON) (map[string]any, error) {
	raw := value.Raw
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, errors.New("JSON value must be an object")
	}
	return object, nil
}

func buildProfiledAgentRun(
	schedule *nvtv1alpha1.AgentSchedule,
	resolved *ResolvedExecutionProfile,
	producer string,
	principal *nvtv1alpha1.AgentRunPrincipal,
	prompt string,
) (*nvtv1alpha1.AgentRun, error) {
	template := schedule.Spec.Template
	profile := resolved.Profile
	config, err := jsonObject(template.Agent.Config)
	if err != nil {
		return nil, errInvalidExecutionProfileConfiguration
	}
	runtimeConfig, err := jsonObject(profile.AgentRuntimeConfig)
	if err != nil {
		return nil, errInvalidExecutionProfileConfiguration
	}
	config["runtime"] = runtimeConfig
	rawConfig, err := json.Marshal(config)
	if err != nil {
		return nil, errInvalidExecutionProfileConfiguration
	}

	run := &nvtv1alpha1.AgentRun{
		Spec: nvtv1alpha1.AgentRunSpec{
			Runtime:                   profile.Runtime,
			RuntimeAuth:               profile.RuntimeAuth.DeepCopy(),
			Image:                     template.Image,
			RuntimeClassName:          copyStringPointer(template.RuntimeClassName),
			Egress:                    profile.Egress,
			EgressAllowInsecureBroker: profile.EgressAllowInsecureBroker,
			EgressEnforcement:         profile.EgressEnforcement,
			EgressForwardProxy:        profile.EgressForwardProxy,
			EgressTransport:           profile.EgressTransport,
			Workspace:                 template.Workspace,
			Broker:                    profile.Broker.DeepCopy(),
			Agent:                     nvtv1alpha1.AgentRunAgent{Config: apiextensionsv1.JSON{Raw: rawConfig}},
			Lifecycle:                 template.Lifecycle.DeepCopy(),
			TTL:                       template.TTL.DeepCopy(),
			ProfileProvenance: &nvtv1alpha1.AgentRunProfileProvenance{
				AuthenticatedProducer: producer,
				ScheduleName:          schedule.Name,
				ScheduleUID:           string(schedule.UID),
				ScheduleGeneration:    schedule.Generation,
				SelectedProfile:       profile.Name,
				Principal:             copyPrincipal(principal),
			},
		},
	}
	if prompt != "" {
		run.Spec.Prompt = &nvtv1alpha1.AgentRunPrompt{Text: prompt}
	}
	return run, nil
}

func injectProfiledLifecycleCallback(run *nvtv1alpha1.AgentRun) error {
	if run.Spec.Lifecycle == nil ||
		(len(run.Spec.Lifecycle.CompleteOn) == 0 && len(run.Spec.Lifecycle.FailOn) == 0) ||
		AgentRunLiteralZeroSecret(run) {
		return nil
	}
	config, err := jsonObject(run.Spec.Agent.Config)
	if err != nil {
		return errInvalidExecutionProfileConfiguration
	}
	plugins, err := agentConfigPlugins(config)
	if err != nil {
		return errInvalidExecutionProfileConfiguration
	}
	for _, raw := range plugins {
		plugin, ok := raw.(map[string]any)
		if !ok {
			return errInvalidExecutionProfileConfiguration
		}
		if plugin["name"] == "event-webhook" {
			return errInvalidExecutionProfileConfiguration
		}
	}
	filters := uniqueStrings(append(
		append([]string(nil), run.Spec.Lifecycle.CompleteOn...),
		run.Spec.Lifecycle.FailOn...,
	))
	plugins = append(plugins, map[string]any{
		"name": "event-webhook", "source": "builtin", "when": "after-agent", "restart": "always",
		"config": map[string]any{
			"url":      fmt.Sprintf("http://nvt-operator:8082/v1/agentruns/%s/%s/events", run.Namespace, run.Name),
			"auth":     map[string]any{"type": "bearer-env", "env": callbackTokenKey},
			"filters":  filters,
			"delivery": map[string]any{"retry": map[string]any{"backoff-seconds": float64(1)}},
		},
	})
	config["plugins"] = plugins
	raw, err := json.Marshal(config)
	if err != nil {
		return errInvalidExecutionProfileConfiguration
	}
	run.Spec.Agent.Config = apiextensionsv1.JSON{Raw: raw}
	return nil
}

func uniqueStrings(values []string) []any {
	seen := map[string]struct{}{}
	result := make([]any, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func copyPrincipal(principal *nvtv1alpha1.AgentRunPrincipal) *nvtv1alpha1.AgentRunPrincipal {
	if principal == nil {
		return nil
	}
	copy := *principal
	return &copy
}

func copyStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
