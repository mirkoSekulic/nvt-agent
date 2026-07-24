package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

var (
	errInvalidExecutionProfileConfiguration = errors.New("invalid execution profile configuration")
	errExecutionProfileSelectionDenied      = errors.New("execution profile selection denied")
	errProducerNotAllowed                   = errors.New("producer is not allowed")
	errWorkflowSelectionDenied              = errors.New("workflow selection denied")
)

const maxWorkspaceInstructionsBytes = 64 * 1024

// ResolvedExecutionProfile is the single immutable profile selected for a request.
type ResolvedExecutionProfile struct {
	Profile nvtv1alpha1.AgentScheduleExecutionProfile
}

// ResolvedWorkflowProfile is the independently authorized workflow snapshot.
type ResolvedWorkflowProfile struct {
	Name                  string
	WorkspaceInstructions string
}

type validatedWorkflowConfiguration struct {
	legacyAllowed map[string]struct{}
	profiles      map[string]nvtv1alpha1.AgentScheduleWorkflowProfile
	policies      map[string]nvtv1alpha1.AgentScheduleProducerPolicy
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
		schedule.Spec.ProfileSelection != nil || len(schedule.Spec.AllowedProducers) != 0 ||
		len(schedule.Spec.WorkflowProfiles) != 0 || len(schedule.Spec.ProducerPolicies) != 0
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
		schedule.Spec.ProfileSelection == nil {
		return nil, errInvalidExecutionProfileConfiguration
	}
	template := schedule.Spec.Template
	if strings.TrimSpace(template.Image) == "" {
		return nil, errInvalidExecutionProfileConfiguration
	}
	common, err := jsonObject(template.Agent.Config)
	if err != nil {
		return nil, errInvalidExecutionProfileConfiguration
	}
	if _, ownsRuntime := common["runtime"]; ownsRuntime {
		return nil, errInvalidExecutionProfileConfiguration
	}
	if template.Agent.WorkspaceInstructions != "" || template.Agent.WorkflowInstructions != "" {
		return nil, errInvalidExecutionProfileConfiguration
	}

	if _, err := validateWorkflowConfiguration(schedule); err != nil {
		return nil, err
	}

	profiles := make(map[string]nvtv1alpha1.AgentScheduleExecutionProfile, len(schedule.Spec.Profiles))
	for i := range schedule.Spec.Profiles {
		profile := schedule.Spec.Profiles[i]
		if profile.EgressForwardProxy != nil {
			return nil, fmt.Errorf("spec.profiles[%d].egressForwardProxy is removed; use egressTransport", i)
		}
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
		if len(profile.WorkspaceInstructions) > maxWorkspaceInstructionsBytes {
			return nil, errInvalidExecutionProfileConfiguration
		}
		if err := validateEgressMaxConcurrentTunnels(profile.EgressMaxConcurrentTunnels); err != nil {
			return nil, errInvalidExecutionProfileConfiguration
		}
		if profile.EgressMaxConcurrentTunnels != 0 &&
			profile.EgressTransport != nvtv1alpha1.AgentRunEgressTransportForwardProxy &&
			profile.EgressTransport != nvtv1alpha1.AgentRunEgressTransportTransparent {
			return nil, errInvalidExecutionProfileConfiguration
		}
		if err := validateRuntimeCapabilities(profile.Runtime); err != nil {
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

func validateWorkflowConfiguration(schedule *nvtv1alpha1.AgentSchedule) (*validatedWorkflowConfiguration, error) {
	configuration := &validatedWorkflowConfiguration{}
	workflowMode := len(schedule.Spec.WorkflowProfiles) != 0 || len(schedule.Spec.ProducerPolicies) != 0
	if !workflowMode {
		if len(schedule.Spec.AllowedProducers) == 0 {
			return nil, errInvalidExecutionProfileConfiguration
		}
		configuration.legacyAllowed = make(map[string]struct{}, len(schedule.Spec.AllowedProducers))
		for _, producer := range schedule.Spec.AllowedProducers {
			if strings.TrimSpace(producer) == "" || producer != strings.TrimSpace(producer) {
				return nil, errInvalidExecutionProfileConfiguration
			}
			if _, duplicate := configuration.legacyAllowed[producer]; duplicate {
				return nil, errInvalidExecutionProfileConfiguration
			}
			configuration.legacyAllowed[producer] = struct{}{}
		}
		return configuration, nil
	}

	if len(schedule.Spec.AllowedProducers) != 0 || len(schedule.Spec.WorkflowProfiles) == 0 || len(schedule.Spec.ProducerPolicies) == 0 {
		return nil, errInvalidExecutionProfileConfiguration
	}
	configuration.profiles = make(map[string]nvtv1alpha1.AgentScheduleWorkflowProfile, len(schedule.Spec.WorkflowProfiles))
	for _, profile := range schedule.Spec.WorkflowProfiles {
		if len(utilvalidation.IsDNS1123Label(profile.Name)) != 0 || len(profile.WorkspaceInstructions) > maxWorkspaceInstructionsBytes {
			return nil, errInvalidExecutionProfileConfiguration
		}
		if _, duplicate := configuration.profiles[profile.Name]; duplicate {
			return nil, errInvalidExecutionProfileConfiguration
		}
		configuration.profiles[profile.Name] = profile
	}
	configuration.policies = make(map[string]nvtv1alpha1.AgentScheduleProducerPolicy, len(schedule.Spec.ProducerPolicies))
	for _, policy := range schedule.Spec.ProducerPolicies {
		if strings.TrimSpace(policy.Identity) == "" || policy.Identity != strings.TrimSpace(policy.Identity) {
			return nil, errInvalidExecutionProfileConfiguration
		}
		if _, duplicate := configuration.policies[policy.Identity]; duplicate {
			return nil, errInvalidExecutionProfileConfiguration
		}
		allowed := make(map[string]struct{}, len(policy.Workflows))
		for _, workflow := range policy.Workflows {
			if _, exists := configuration.profiles[workflow]; !exists {
				return nil, errInvalidExecutionProfileConfiguration
			}
			if _, duplicate := allowed[workflow]; duplicate {
				return nil, errInvalidExecutionProfileConfiguration
			}
			allowed[workflow] = struct{}{}
		}
		if policy.DefaultWorkflow != "" {
			if _, allowedDefault := allowed[policy.DefaultWorkflow]; !allowedDefault {
				return nil, errInvalidExecutionProfileConfiguration
			}
		}
		configuration.policies[policy.Identity] = policy
	}
	return configuration, nil
}

func resolveWorkflowForProducer(
	schedule *nvtv1alpha1.AgentSchedule,
	producer string,
	requested string,
) (*ResolvedWorkflowProfile, error) {
	configuration, err := validateWorkflowConfiguration(schedule)
	if err != nil {
		return nil, err
	}
	if configuration.legacyAllowed != nil {
		if _, allowed := configuration.legacyAllowed[producer]; !allowed {
			return nil, errProducerNotAllowed
		}
		if requested != "" {
			return nil, errWorkflowSelectionDenied
		}
		return nil, nil
	}
	policy, allowed := configuration.policies[producer]
	if !allowed {
		return nil, errProducerNotAllowed
	}
	selected := requested
	if selected == "" {
		selected = policy.DefaultWorkflow
	}
	if selected == "" {
		return nil, nil
	}
	allowedWorkflow := false
	for _, workflow := range policy.Workflows {
		if workflow == selected {
			allowedWorkflow = true
			break
		}
	}
	if !allowedWorkflow {
		return nil, errWorkflowSelectionDenied
	}
	profile, exists := configuration.profiles[selected]
	if !exists {
		return nil, errInvalidExecutionProfileConfiguration
	}
	return &ResolvedWorkflowProfile{Name: profile.Name, WorkspaceInstructions: profile.WorkspaceInstructions}, nil
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
	workflow *ResolvedWorkflowProfile,
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

	selectedWorkflow := ""
	workflowInstructions := ""
	if workflow != nil {
		selectedWorkflow = workflow.Name
		workflowInstructions = workflow.WorkspaceInstructions
	}
	run := &nvtv1alpha1.AgentRun{
		Spec: nvtv1alpha1.AgentRunSpec{
			Runtime:                    *profile.Runtime.DeepCopy(),
			RuntimeAuth:                profile.RuntimeAuth.DeepCopy(),
			Image:                      template.Image,
			RuntimeClassName:           copyStringPointer(template.RuntimeClassName),
			Resources:                  *template.Resources.DeepCopy(),
			Tolerations:                copyTolerations(template.Tolerations),
			Egress:                     profile.Egress,
			EgressAllowInsecureBroker:  profile.EgressAllowInsecureBroker,
			EgressEnforcement:          profile.EgressEnforcement,
			EgressTransport:            profile.EgressTransport,
			EgressMaxConcurrentTunnels: profile.EgressMaxConcurrentTunnels,
			Workspace:                  *template.Workspace.DeepCopy(),
			Broker:                     profile.Broker.DeepCopy(),
			Agent: nvtv1alpha1.AgentRunAgent{
				Config:                apiextensionsv1.JSON{Raw: rawConfig},
				WorkspaceInstructions: profile.WorkspaceInstructions,
				WorkflowInstructions:  workflowInstructions,
			},
			Lifecycle: template.Lifecycle.DeepCopy(),
			TTL:       template.TTL.DeepCopy(),
			ProfileProvenance: &nvtv1alpha1.AgentRunProfileProvenance{
				AuthenticatedProducer: producer,
				ScheduleName:          schedule.Name,
				ScheduleUID:           string(schedule.UID),
				ScheduleGeneration:    schedule.Generation,
				SelectedProfile:       profile.Name,
				SelectedWorkflow:      selectedWorkflow,
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

func copyTolerations(values []corev1.Toleration) []corev1.Toleration {
	if values == nil {
		return nil
	}
	result := make([]corev1.Toleration, len(values))
	for i := range values {
		values[i].DeepCopyInto(&result[i])
	}
	return result
}
