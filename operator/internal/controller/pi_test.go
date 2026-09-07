package controller

import (
	"encoding/json"
	nvt "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
	"os"
	"sigs.k8s.io/yaml"
	"strings"
	"testing"
)

func piRun() *nvt.AgentRun {
	run := &nvt.AgentRun{}
	run.Spec.Runtime = nvt.AgentRunRuntime{Type: "pi", Autonomy: "trusted-local", Model: "custom/example-model", Effort: "off", CredentialProvider: "model-api", Pi: &nvt.AgentRunPiConfig{Provider: "custom", BaseURL: "https://models.example.test/v1", API: "openai-completions", Models: []nvt.AgentRunPiModel{{ID: "example-model"}}}}
	run.Spec.Egress = nvt.AgentRunEgressMediated
	run.Spec.EgressTransport = nvt.AgentRunEgressTransportForwardProxy
	run.Spec.Broker = &nvt.AgentRunBroker{Grants: []nvt.AgentRunBrokerGrant{{Provider: "model-api", Materialization: nvt.AgentRunGrantHeaderInject, EgressHosts: []string{"models.example.test:443"}}}}
	run.Spec.Agent.Config.Raw = []byte(`{"runtime":{"command":"pi","args":[]}}`)
	run.Spec.Prompt = &nvt.AgentRunPrompt{Text: "initial task"}
	return run
}
func TestPiKubernetesRenderingAndValidation(t *testing.T) {
	run := piRun()
	if err := ValidateAgentRunRuntimeCapabilities(run); err != nil {
		t.Fatal(err)
	}
	rendered, err := RenderAgentConfigYAML(run)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"command: pi", "provider: model-api", "text: initial task", "resume:", "thinking", "baseUrl: https://models.example.test/v1"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("missing %s: %s", want, rendered)
		}
	}
	for _, bad := range []string{"token-file", "apiKey", "--continue"} {
		if strings.Contains(rendered, bad) {
			t.Fatalf("unexpected field %s", bad)
		}
	}
	copy := run.Spec.Runtime.DeepCopy()
	copy.Pi.Models[0].ID = "changed"
	if run.Spec.Runtime.Pi.Models[0].ID != "example-model" {
		t.Fatal("Pi config deepcopy aliases")
	}
	for name, mutate := range map[string]func(*nvt.AgentRun){
		"autonomy": func(r *nvt.AgentRun) { r.Spec.Runtime.Autonomy = "interactive" },
		"model":    func(r *nvt.AgentRun) { r.Spec.Runtime.Model = "other/model" },
		"effort":   func(r *nvt.AgentRun) { r.Spec.Runtime.Effort = "max" },
		"provider": func(r *nvt.AgentRun) { r.Spec.Runtime.CredentialProvider = "missing" },
		"direct":   func(r *nvt.AgentRun) { r.Spec.Egress = nvt.AgentRunEgressDirect },
		"host":     func(r *nvt.AgentRun) { r.Spec.Broker.Grants[0].EgressHosts = []string{"other.test:443"} },
		"bundle":   func(r *nvt.AgentRun) { r.Spec.Broker.Grants[0].Materialization = nvt.AgentRunGrantFileBundle },
		"tls":      func(r *nvt.AgentRun) { r.Spec.Broker.Grants[0].AllowInsecureUpstream = true },
		"args":     func(r *nvt.AgentRun) { r.Spec.Agent.Config.Raw = []byte(`{"runtime":{"args":["--model","other"]}}`) },
		"resume": func(r *nvt.AgentRun) {
			r.Spec.Agent.Config.Raw = []byte(`{"runtime":{"resume":{"command":"pi","args":["--continue"]}}}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := piRun()
			mutate(r)
			if _, err := RenderAgentConfigYAML(r); err == nil {
				t.Fatal("invalid Pi configuration accepted")
			}
		})
	}
}
func TestPiLocalKubernetesManagedRuntimeParity(t *testing.T) {
	run := piRun()
	config, err := InjectAgentRunRuntimeConfig(map[string]any{"runtime": map[string]any{"command": "pi", "args": []any{}}}, run)
	if err != nil {
		t.Fatal(err)
	}
	got := config["runtime"].(map[string]any)
	delete(got, "proxy")
	want, err := resolvedrun.ManagedPiRuntime(map[string]any{"command": "pi", "args": []any{}}, piSelection(run.Spec.Runtime))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(want)
	if string(a) != string(b) {
		t.Fatalf("backends differ: %s / %s", a, b)
	}
}

func TestPiProducerAdmissionUsesExistingProfileContract(t *testing.T) {
	schedule := testProfiledAgentSchedule()
	pi := piRun()
	profile := &schedule.Spec.Profiles[0]
	profile.Runtime = pi.Spec.Runtime
	profile.AgentRuntimeConfig.Raw = []byte(`{"command":"pi"}`)
	profile.Broker = pi.Spec.Broker
	profile.Egress = pi.Spec.Egress
	profile.EgressTransport = pi.Spec.EgressTransport
	profile.EgressEnforcement = true
	profile.EgressAllowInsecureBroker = true
	if _, err := validateExecutionProfileSchedule(schedule); err != nil {
		t.Fatal(err)
	}
	fixture := newProfileAdmissionFixture(t, schedule)
	response := fixture.serve(t, profiledAdmissionBody(t, "pi-producer-task", nil, nil), "Bearer projected-token")
	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, 201, &decoded)
	run := fixture.run(t, decoded.AgentRun.Name)
	if run.Spec.Runtime.Type != "pi" || run.Spec.Runtime.CredentialProvider != "model-api" {
		t.Fatal("producer did not snapshot Pi runtime")
	}
	run.Spec.Prompt = &nvt.AgentRunPrompt{Text: "producer initial task"}
	rendered, err := RenderAgentConfigYAML(&run)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered, "producer initial task") || !strings.Contains(rendered, "resume:") {
		t.Fatal("producer prompt/resume contract missing")
	}
	profile.Runtime.Autonomy = "interactive"
	if _, err := validateExecutionProfileSchedule(schedule); err == nil {
		t.Fatal("invalid Pi profile accepted")
	}
	profile.Runtime.Autonomy = "trusted-local"
	profile.AgentRuntimeConfig.Raw = []byte(`{"command":"pi","args":["--thinking","high"]}`)
	if _, err := validateExecutionProfileSchedule(schedule); err == nil {
		t.Fatal("raw Pi selectors accepted at profile admission")
	}
}

func TestPiKubernetesExamples(t *testing.T) {
	raw, err := os.ReadFile("../../../examples/pi/agentrun.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var run nvt.AgentRun
	if err := yaml.Unmarshal(raw, &run); err != nil {
		t.Fatal(err)
	}
	if err := ValidateAgentRunRuntimeCapabilities(&run); err != nil {
		t.Fatal(err)
	}
	if _, err := RenderAgentConfigYAML(&run); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile("../../../examples/pi/values.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var values struct {
		AgentSchedule nvt.AgentScheduleSpec `json:"agentSchedule"`
	}
	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatal(err)
	}
	values.AgentSchedule.Template.Image = "runtime:pi-example" // supplied by the Helm template
	if _, err := validateExecutionProfileSchedule(&nvt.AgentSchedule{Spec: values.AgentSchedule}); err != nil {
		t.Fatal(err)
	}
}
