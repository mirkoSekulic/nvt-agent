// Package v1alpha1 contains API schema definitions for AgentRun resources.
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupVersion is the Kubernetes API group and version for AgentRun resources.
var GroupVersion = schema.GroupVersion{Group: "nvt.dev", Version: "v1alpha1"}

// SchemeBuilder registers AgentRun types with a runtime scheme.
var SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

// AddToScheme adds AgentRun types to a runtime scheme.
var AddToScheme = SchemeBuilder.AddToScheme

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion, &AgentRun{}, &AgentRunList{})
	return nil
}
