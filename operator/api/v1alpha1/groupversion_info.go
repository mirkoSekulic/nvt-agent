// Package v1alpha1 contains API schema definitions for nvt.dev resources.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupVersion is the Kubernetes API group and version for nvt.dev resources.
var GroupVersion = schema.GroupVersion{Group: "nvt.dev", Version: "v1alpha1"}

// SchemeBuilder registers nvt.dev types with a runtime scheme.
var SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

// AddToScheme adds nvt.dev types to a runtime scheme.
var AddToScheme = SchemeBuilder.AddToScheme

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion, &AgentRun{}, &AgentRunList{}, &AgentSchedule{}, &AgentScheduleList{})
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
