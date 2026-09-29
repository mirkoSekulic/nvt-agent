package controller

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

func TestAzureRenderedAgentEnvironment(t *testing.T) {
	run := transparentAgentRun(t)
	run.Spec.Broker.Grants = []nvtv1alpha1.AgentRunBrokerGrant{{Provider: "azure-one", Materialization: "header-inject", Resources: []string{"provider-scope/22222222-2222-2222-2222-222222222222"}, EgressHosts: []string{"management.azure.com:443", "api.loganalytics.io:443"}}}
	pod, err := DesiredAgentPod(run, testScheme(t))
	if err != nil {
		t.Fatal(err)
	}
	environment := map[string]string{}
	for _, container := range pod.Spec.Containers {
		if container.Name != "agent" {
			continue
		}
		for _, entry := range container.Env {
			if entry.ValueFrom != nil || strings.HasPrefix(entry.Name, "NVT_BROKER_") {
				t.Fatal("broker credential projection entered agent")
			}
			environment[entry.Name] = entry.Value
		}
	}
	if len(environment) == 0 {
		t.Fatal("missing rendered agent environment")
	}
	python := os.Getenv("NVT_AZURE_CLI_PYTHON")
	if python == "" {
		t.Skip("optional actual Azure CLI not installed; render invariant passed")
	}
	data, _ := json.Marshal(environment)
	command := exec.Command(python, filepath.Join("..", "..", "..", "tests", "azure-cli", "rendered_environment.py"))
	command.Stdin = bytes.NewReader(data)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual rendered operator env: %v\n%s", err, out)
	}
}
