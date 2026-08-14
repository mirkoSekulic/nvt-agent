package controller

import (
	"encoding/json"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

// This test is intentionally a compatibility gate rather than a production
// dependency from Kubernetes reconciliation to the local resolved-run path.
// Existing AgentSchedule admission remains authoritative for Kubernetes.
func TestLocalResolvedRunContractMatchesExistingKubernetesProfileResolution(t *testing.T) {
	t.Parallel()
	schedule := testWorkflowProfiledAgentSchedule()
	schedule.Spec.Template.Image = "runtime:profiled"
	schedule.Spec.Template.Resources = corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2"), corev1.ResourceMemory: resource.MustParse("8Gi")},
		Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2"), corev1.ResourceMemory: resource.MustParse("8Gi")},
	}
	schedule.Spec.Profiles[0].AgentRuntimeConfig = rawJSON(`{"command":"codex","args":["--profiled"]}`)
	schedule.Spec.Profiles[0].WorkspaceInstructions = "Profile-owned guidance.\n"
	workflow, err := resolveWorkflowForProducer(
		schedule, "system:serviceaccount:nvt:nvt-github-comments-producer", "implement-pr",
	)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := (StaticExecutionProfileResolver{}).Resolve(schedule, nil)
	if err != nil {
		t.Fatal(err)
	}
	kubernetesRun, err := buildProfiledAgentRun(
		schedule, profile, "system:serviceaccount:nvt:nvt-github-comments-producer", nil, workflow, "",
	)
	if err != nil {
		t.Fatal(err)
	}
	kubernetesBefore, err := json.Marshal(kubernetesRun)
	if err != nil {
		t.Fatal(err)
	}

	configuration := resolvedrun.TrustedConfiguration{
		Defaults: resolvedrun.PlatformDefaults{
			Image: schedule.Spec.Template.Image,
			Runtime: resolvedrun.Runtime{
				RuntimeCommand: resolvedrun.RuntimeCommand{Command: "codex", Args: []string{"--profiled"}},
				Autonomy:       string(profile.Profile.Runtime.Autonomy), User: string(nvtv1alpha1.AgentRunUserRoot),
			},
			Resources: resolvedrun.Resources{CPURequest: "2", CPULimit: "2", MemoryRequest: "8Gi", MemoryLimit: "8Gi"},
		},
		Profiles: []resolvedrun.Profile{{
			Name: profile.Profile.Name,
			Broker: resolvedrun.Broker{Grants: []resolvedrun.BrokerGrant{{
				Provider:        profile.Profile.Broker.Grants[0].Provider,
				Repositories:    append([]string(nil), profile.Profile.Broker.Grants[0].Repositories...),
				Materialization: string(profile.Profile.Broker.Grants[0].Materialization),
			}}},
			Egress:                resolvedrun.Egress{Mode: string(profile.Profile.Egress)},
			WorkspaceInstructions: profile.Profile.WorkspaceInstructions,
			AllowedBackends:       []string{"container"}, DefaultBackend: "container", AllowedRetentions: []string{"ephemeral"},
		}},
		Workflows:         []resolvedrun.Workflow{{Name: workflow.Name, WorkspaceInstructions: workflow.WorkspaceInstructions}},
		ExecutionBackends: []resolvedrun.ExecutionBackend{{Name: "container", Kind: "container"}},
		RetentionPolicies: []resolvedrun.RetentionPolicy{{
			Name: "ephemeral", Persistence: resolvedrun.Persistence{},
		}},
	}
	resolver, err := resolvedrun.NewResolver(configuration)
	if err != nil {
		t.Fatal(err)
	}
	localRun, err := resolver.Resolve(resolvedrun.LocalRunRequest{
		RunID: "compatibility", Principal: resolvedrun.Principal{Issuer: "https://issuer.example", Subject: "subject-1"},
		Profile: profile.Profile.Name, Workflow: workflow.Name, Retention: "ephemeral",
	})
	if err != nil {
		t.Fatal(err)
	}

	var agentConfiguration struct {
		Runtime struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"runtime"`
	}
	if err := json.Unmarshal(kubernetesRun.Spec.Agent.Config.Raw, &agentConfiguration); err != nil {
		t.Fatal(err)
	}
	if localRun.Image != kubernetesRun.Spec.Image || localRun.Runtime.Command != agentConfiguration.Runtime.Command ||
		!reflect.DeepEqual(localRun.Runtime.Args, agentConfiguration.Runtime.Args) ||
		localRun.Runtime.Autonomy != kubernetesRun.Spec.Runtime.Autonomy ||
		localRun.Resources.CPURequest != kubernetesRun.Spec.Resources.Requests.Cpu().String() ||
		localRun.Resources.MemoryLimit != kubernetesRun.Spec.Resources.Limits.Memory().String() ||
		localRun.Broker.Grants[0].Provider != kubernetesRun.Spec.Broker.Grants[0].Provider ||
		localRun.Broker.Grants[0].Materialization != string(kubernetesRun.Spec.Broker.Grants[0].Materialization) ||
		localRun.Egress.Mode != string(kubernetesRun.Spec.Egress) ||
		localRun.WorkspaceInstructions.Profile != kubernetesRun.Spec.Agent.WorkspaceInstructions ||
		localRun.WorkspaceInstructions.Workflow != kubernetesRun.Spec.Agent.WorkflowInstructions {
		t.Fatalf("local and Kubernetes shared resolution diverged:\nlocal=%#v\nkubernetes=%#v", localRun, kubernetesRun.Spec)
	}
	kubernetesAfter, err := json.Marshal(kubernetesRun)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(kubernetesBefore, kubernetesAfter) {
		t.Fatal("local contract resolution mutated the existing Kubernetes AgentRun")
	}
}
