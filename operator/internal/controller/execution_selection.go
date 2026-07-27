package controller

import (
	"fmt"
	"strings"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
)

const (
	builtInKubernetesDriver             = "kubernetes"
	maxExecutionClassConfigurationBytes = executiondriver.MaxDesiredBytes
)

type effectiveExecutionSelection struct {
	Kind   nvtv1alpha1.AgentRunExecutionKind
	Driver string
}

func defaultExecutionSelection() effectiveExecutionSelection {
	return effectiveExecutionSelection{Kind: nvtv1alpha1.AgentRunExecutionPod, Driver: builtInKubernetesDriver}
}

func effectiveAgentRunExecution(agentRun *nvtv1alpha1.AgentRun) (effectiveExecutionSelection, error) {
	if agentRun.Spec.Execution == nil {
		return defaultExecutionSelection(), nil
	}
	if err := ValidateAgentRunExecution(agentRun); err != nil {
		return effectiveExecutionSelection{}, err
	}
	return effectiveExecutionSelection{
		Kind: agentRun.Spec.Execution.Kind, Driver: agentRun.Spec.Execution.Driver,
	}, nil
}

// ValidateAgentRunExecution validates the immutable resolved execution
// snapshot. Driver availability is deliberately checked by backend selection,
// not by this shape validator.
func ValidateAgentRunExecution(agentRun *nvtv1alpha1.AgentRun) error {
	execution := agentRun.Spec.Execution
	if execution == nil {
		return nil
	}
	if err := validateExecutionKindAndDriver(execution.Kind, execution.Driver); err != nil {
		return fmt.Errorf("spec.execution: %w", err)
	}
	if execution.Driver == builtInKubernetesDriver {
		if execution.Kind != nvtv1alpha1.AgentRunExecutionPod {
			return fmt.Errorf("spec.execution driver %q requires kind %q", builtInKubernetesDriver, nvtv1alpha1.AgentRunExecutionPod)
		}
		if execution.ClassRef != "" || len(execution.Configuration.Raw) != 0 {
			return fmt.Errorf("spec.execution built-in Kubernetes selection must not set classRef or configuration")
		}
		return nil
	}
	if len(utilvalidation.IsDNS1123Label(execution.ClassRef)) != 0 {
		return fmt.Errorf("spec.execution.classRef must be a DNS-1123 label")
	}
	if err := validateExecutionConfiguration(execution.Configuration); err != nil {
		return fmt.Errorf("spec.execution.configuration: %w", err)
	}
	return nil
}

func validateExecutionKindAndDriver(kind nvtv1alpha1.AgentRunExecutionKind, driver string) error {
	switch kind {
	case nvtv1alpha1.AgentRunExecutionPod, nvtv1alpha1.AgentRunExecutionVM:
	default:
		return fmt.Errorf("kind must be pod or vm")
	}
	if driver != strings.TrimSpace(driver) || len(utilvalidation.IsDNS1123Label(driver)) != 0 {
		return fmt.Errorf("driver must be a DNS-1123 label")
	}
	return nil
}

func validateExecutionConfiguration(configuration apiextensionsv1.JSON) error {
	if len(configuration.Raw) == 0 {
		return fmt.Errorf("must be present")
	}
	if len(configuration.Raw) > maxExecutionClassConfigurationBytes {
		return fmt.Errorf("must not exceed %d bytes", maxExecutionClassConfigurationBytes)
	}
	var object map[string]any
	if err := executiondriver.DecodeStrictJSON(configuration.Raw, &object); err != nil || object == nil {
		return fmt.Errorf("must be a JSON object")
	}
	return nil
}

func validateExecutionClasses(schedule *nvtv1alpha1.AgentSchedule) (map[string]nvtv1alpha1.AgentScheduleExecutionClass, error) {
	classes := make(map[string]nvtv1alpha1.AgentScheduleExecutionClass, len(schedule.Spec.ExecutionClasses))
	for i := range schedule.Spec.ExecutionClasses {
		class := schedule.Spec.ExecutionClasses[i]
		if len(utilvalidation.IsDNS1123Label(class.Name)) != 0 {
			return nil, fmt.Errorf("spec.executionClasses[%d].name must be a DNS-1123 label", i)
		}
		if _, duplicate := classes[class.Name]; duplicate {
			return nil, fmt.Errorf("spec.executionClasses[%d].name is duplicated", i)
		}
		if err := validateExecutionKindAndDriver(class.Kind, class.Driver); err != nil {
			return nil, fmt.Errorf("spec.executionClasses[%d]: %w", i, err)
		}
		if class.Driver == builtInKubernetesDriver {
			return nil, fmt.Errorf("spec.executionClasses[%d] must not configure the classless built-in Kubernetes driver", i)
		}
		if err := validateExecutionConfiguration(class.Configuration); err != nil {
			return nil, fmt.Errorf("spec.executionClasses[%d].configuration: %w", i, err)
		}
		classes[class.Name] = class
	}
	return classes, nil
}

func resolveProfileExecution(
	profile *nvtv1alpha1.AgentScheduleExecutionProfile,
	classes map[string]nvtv1alpha1.AgentScheduleExecutionClass,
) (*nvtv1alpha1.AgentRunExecution, error) {
	selection := profile.Execution
	if selection == nil {
		return nil, nil
	}
	if err := validateExecutionKindAndDriver(selection.Kind, selection.Driver); err != nil {
		return nil, err
	}
	if selection.Driver == builtInKubernetesDriver {
		if selection.Kind != nvtv1alpha1.AgentRunExecutionPod {
			return nil, fmt.Errorf("driver %q requires kind %q", builtInKubernetesDriver, nvtv1alpha1.AgentRunExecutionPod)
		}
		if selection.ClassRef != "" {
			return nil, fmt.Errorf("built-in Kubernetes selection must not set classRef")
		}
		return &nvtv1alpha1.AgentRunExecution{Kind: selection.Kind, Driver: selection.Driver}, nil
	}
	if len(utilvalidation.IsDNS1123Label(selection.ClassRef)) != 0 {
		return nil, fmt.Errorf("classRef must be a DNS-1123 label")
	}
	class, exists := classes[selection.ClassRef]
	if !exists {
		return nil, fmt.Errorf("execution class %q does not exist", selection.ClassRef)
	}
	if class.Kind != selection.Kind || class.Driver != selection.Driver {
		return nil, fmt.Errorf("execution class %q does not match selected kind and driver", selection.ClassRef)
	}
	return &nvtv1alpha1.AgentRunExecution{
		Kind: selection.Kind, Driver: selection.Driver, ClassRef: class.Name,
		Configuration: *class.Configuration.DeepCopy(),
	}, nil
}
