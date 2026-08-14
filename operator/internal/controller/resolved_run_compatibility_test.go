package controller

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"sigs.k8s.io/yaml"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

// This test is intentionally a compatibility gate rather than a production
// dependency from Kubernetes reconciliation to the local resolved-run path.
// It exercises the existing, unexported Kubernetes profile/workflow builder
// and proves that the portable contract can retain the complete desired agent
// behavior without changing the AgentRun.
func TestLocalResolvedRunContractMatchesExistingKubernetesProfileResolution(t *testing.T) {
	t.Parallel()
	const (
		checkoutTarget   = "github.com/Altinn/altinn-studio"
		brokerRepository = "Altinn/altinn-studio"
		prompt           = "Implement the reviewed change."
	)

	schedule := testWorkflowProfiledAgentSchedule()
	schedule.Spec.Template.Image = "runtime:profiled"
	schedule.Spec.Template.Resources = corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2"), corev1.ResourceMemory: resource.MustParse("8Gi")},
		Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2"), corev1.ResourceMemory: resource.MustParse("8Gi")},
	}
	schedule.Spec.Template.Agent.Config = rawJSON(`{
  "preseed":{"files":[{"path":"$HOME/.agent/config","mode":"0600","overwrite":false,"content":"check_for_update_on_startup = false\n"}]},
  "tools":{"packages":["git","jq"],"mise":["go@1.26"]},
  "code-server":{"extensions":["redhat.vscode-yaml"],"agentTerminal":{"openOnStartup":true}},
  "plugins":[
    {"name":"git-host-credentials","source":"builtin","config":{"providers":[{"name":"source","type":"broker","broker-provider":"source-app","match":["github.com/Altinn/*"]}]}},
    {"name":"git-credentials","source":"builtin","when":"before-agent","config":{"credentials":[{"match":"https://github.com/Altinn/altinn-studio.git","provider":"source"}]}},
    {"name":"checkout-repos","source":"builtin","when":"before-agent","restart":"never","config":{"repos":[{"url":"https://github.com/Altinn/altinn-studio.git","path":"altinn-studio"}]}},
    {"name":"github-watcher","source":"builtin","when":"after-agent","config":{"repositories":["Altinn/altinn-studio"]}}
  ],
  "expose":{"http":[{"name":"app","targetPort":3000}]}
}`)
	profileSpec := &schedule.Spec.Profiles[0]
	profileSpec.Runtime = nvtv1alpha1.AgentRunRuntime{
		Type: "codex", Autonomy: "trusted-local", User: nvtv1alpha1.AgentRunUserRoot,
		Container: &nvtv1alpha1.AgentRunRuntimeContainer{Capabilities: &nvtv1alpha1.AgentRunRuntimeCapabilities{Add: []corev1.Capability{"SYS_PTRACE"}}},
		Docker: &nvtv1alpha1.AgentRunRuntimeDocker{
			KernelLogDevice:  true,
			RequiredNetworks: []nvtv1alpha1.AgentRunDockerNetwork{{Name: "kind", Subnet: "172.31.250.0/24"}},
		},
	}
	profileSpec.AgentRuntimeConfig = rawJSON(`{"command":"agent-cli","args":["run","--profiled"],"resume":{"command":"agent-cli","args":["resume","--last"]},"env":{"NO_PROXY":"localhost,127.0.0.1"}}`)
	profileSpec.WorkspaceInstructions = "Profile-owned guidance.\n"
	profileSpec.Egress = nvtv1alpha1.AgentRunEgressDirect
	profileSpec.Broker = &nvtv1alpha1.AgentRunBroker{Grants: []nvtv1alpha1.AgentRunBrokerGrant{{
		Provider: "source-app", Repositories: []string{"Altinn/*"}, Materialization: nvtv1alpha1.AgentRunGrantFileBundle,
	}}}

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
		schedule, profile, "system:serviceaccount:nvt:nvt-github-comments-producer", nil, workflow, prompt,
	)
	if err != nil {
		t.Fatal(err)
	}
	kubernetesBefore, err := json.Marshal(kubernetesRun)
	if err != nil {
		t.Fatal(err)
	}

	runtime := portableRuntime(kubernetesRun.Spec.Runtime)
	lifecycle := portableLifecycle(kubernetesRun.Spec.Lifecycle)
	baseAgentConfig := portableBaseAgentConfig(t, kubernetesRun.Spec.Agent.Config.Raw)
	configuration := resolvedrun.TrustedConfiguration{
		Defaults: resolvedrun.PlatformDefaults{
			Image: kubernetesRun.Spec.Image, Runtime: runtime,
			AgentConfig: baseAgentConfig,
			Resources: resolvedrun.Resources{
				CPURequest:    kubernetesRun.Spec.Resources.Requests.Cpu().String(),
				CPULimit:      kubernetesRun.Spec.Resources.Limits.Cpu().String(),
				MemoryRequest: kubernetesRun.Spec.Resources.Requests.Memory().String(),
				MemoryLimit:   kubernetesRun.Spec.Resources.Limits.Memory().String(),
			},
			Lifecycle: lifecycle,
		},
		Profiles: []resolvedrun.Profile{{
			Name: profile.Profile.Name,
			CredentialProviders: []resolvedrun.CredentialProviderMapping{{
				Name: "source", BrokerProvider: "source-app", MatchTargets: []string{"github.com/Altinn/*"},
			}},
			Broker: resolvedrun.Broker{Grants: []resolvedrun.BrokerGrant{{
				Provider: "source-app", Repositories: append([]string(nil), kubernetesRun.Spec.Broker.Grants[0].Repositories...),
				Materialization: string(kubernetesRun.Spec.Broker.Grants[0].Materialization),
			}}},
			Egress:                resolvedrun.Egress{Mode: string(kubernetesRun.Spec.Egress)},
			WorkspaceInstructions: kubernetesRun.Spec.Agent.WorkspaceInstructions,
			AllowedBackends:       []string{"container"}, DefaultBackend: "container", AllowedRetentions: []string{"ephemeral"},
		}},
		Workflows: []resolvedrun.Workflow{{
			Name: workflow.Name, WorkspaceInstructions: kubernetesRun.Spec.Agent.WorkflowInstructions,
			Repositories: []resolvedrun.Repository{{
				CheckoutTarget: checkoutTarget, BrokerRepository: brokerRepository,
				URL: "https://github.com/Altinn/altinn-studio.git", Path: "altinn-studio", CredentialProvider: "source",
			}},
		}},
		ExecutionBackends: []resolvedrun.ExecutionBackend{{Name: "container", Kind: "container"}},
		RetentionPolicies: []resolvedrun.RetentionPolicy{{Name: "ephemeral", Persistence: resolvedrun.Persistence{}}},
	}
	resolver, err := resolvedrun.NewResolver(configuration)
	if err != nil {
		t.Fatal(err)
	}
	authorization := resolvedrun.AuthorizationContext{
		Principal:  resolvedrun.Principal{Issuer: "https://issuer.example", Subject: "subject-1"},
		Selections: []resolvedrun.AuthorizedSelection{{Profile: profile.Profile.Name, Workflows: []string{workflow.Name}}},
	}
	localRun, err := resolver.Resolve(authorization, resolvedrun.LocalRunRequest{
		RunID: "compatibility", Profile: profile.Profile.Name, Workflow: workflow.Name,
		Retention: "ephemeral", Prompt: prompt,
	})
	if err != nil {
		t.Fatal(err)
	}
	localRendered, err := resolvedrun.RenderAgentConfig(localRun, resolvedrun.AgentConfigBindings{})
	if err != nil {
		t.Fatal(err)
	}
	kubernetesRenderedYAML, err := RenderAgentConfigYAML(kubernetesRun)
	if err != nil {
		t.Fatal(err)
	}
	kubernetesRendered, err := yaml.YAMLToJSON([]byte(kubernetesRenderedYAML))
	if err != nil {
		t.Fatal(err)
	}
	var localRenderedObject, kubernetesRenderedObject map[string]any
	if err := json.Unmarshal(localRendered, &localRenderedObject); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(kubernetesRendered, &kubernetesRenderedObject); err != nil {
		t.Fatal(err)
	}

	if localRun.Image != kubernetesRun.Spec.Image || localRun.Runtime.Type != kubernetesRun.Spec.Runtime.Type ||
		!reflect.DeepEqual(localRun.Runtime, runtime) ||
		!bytes.Equal(localRun.AgentConfig, baseAgentConfig) ||
		!reflect.DeepEqual(localRenderedObject, kubernetesRenderedObject) ||
		localRun.Prompt != kubernetesRun.Spec.Prompt.Text ||
		!reflect.DeepEqual(localRun.Lifecycle, lifecycle) ||
		localRun.Resources.CPURequest != kubernetesRun.Spec.Resources.Requests.Cpu().String() ||
		localRun.Resources.MemoryLimit != kubernetesRun.Spec.Resources.Limits.Memory().String() ||
		localRun.Broker.Grants[0].Provider != kubernetesRun.Spec.Broker.Grants[0].Provider ||
		!reflect.DeepEqual(localRun.Broker.Grants[0].Repositories, []string{"Altinn/*"}) ||
		localRun.Repositories[0].CheckoutTarget != checkoutTarget ||
		localRun.Repositories[0].BrokerRepository != brokerRepository ||
		localRun.Egress.Mode != string(kubernetesRun.Spec.Egress) ||
		localRun.WorkspaceInstructions.Profile != kubernetesRun.Spec.Agent.WorkspaceInstructions ||
		localRun.WorkspaceInstructions.Workflow != kubernetesRun.Spec.Agent.WorkflowInstructions {
		t.Fatalf("local and Kubernetes desired behavior diverged:\nlocal=%#v\nkubernetes=%#v", localRun, kubernetesRun.Spec)
	}
	kubernetesAfter, err := json.Marshal(kubernetesRun)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kubernetesBefore, kubernetesAfter) {
		t.Fatal("local contract resolution mutated the existing Kubernetes AgentRun")
	}
}

func portableBaseAgentConfig(t *testing.T, raw []byte) json.RawMessage {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	managed := map[string]struct{}{"git-host-credentials": {}, "git-credentials": {}, "checkout-repos": {}}
	plugins, _ := root["plugins"].([]any)
	basePlugins := make([]any, 0, len(plugins))
	for _, rawPlugin := range plugins {
		plugin, ok := rawPlugin.(map[string]any)
		name, nameOK := plugin["name"].(string)
		if !ok || !nameOK {
			t.Fatalf("invalid compatibility plugin: %#v", rawPlugin)
		}
		if _, controlled := managed[name]; controlled {
			continue
		}
		basePlugins = append(basePlugins, plugin)
	}
	root["plugins"] = basePlugins
	result, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func portableRuntime(value nvtv1alpha1.AgentRunRuntime) resolvedrun.Runtime {
	result := resolvedrun.Runtime{Type: value.Type, Autonomy: value.Autonomy, User: string(value.User)}
	if value.Container != nil && value.Container.Capabilities != nil {
		result.Container = &resolvedrun.RuntimeContainer{Capabilities: make([]string, len(value.Container.Capabilities.Add))}
		for index, capability := range value.Container.Capabilities.Add {
			result.Container.Capabilities[index] = string(capability)
		}
	}
	if value.Docker != nil {
		result.Docker = &resolvedrun.RuntimeDocker{KernelLogDevice: value.Docker.KernelLogDevice}
		for _, network := range value.Docker.RequiredNetworks {
			result.Docker.RequiredNetworks = append(result.Docker.RequiredNetworks, resolvedrun.DockerNetwork{Name: network.Name, Subnet: network.Subnet})
		}
	}
	return result
}

func portableLifecycle(value *nvtv1alpha1.AgentRunLifecycle) resolvedrun.Lifecycle {
	if value == nil {
		return resolvedrun.Lifecycle{}
	}
	return resolvedrun.Lifecycle{
		CompleteOn: append([]string(nil), value.CompleteOn...),
		FailOn:     append([]string(nil), value.FailOn...),
	}
}
