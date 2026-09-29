package dockerbackend

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
	"gopkg.in/yaml.v3"
)

func TestAzureRenderedAgentEnvironment(t *testing.T) {
	backend, _, run, _ := testBackend(t)
	run.Repositories, run.CredentialProviders = nil, nil
	run.Egress.ProxyProvider = "azure-one"
	run.Broker.Grants = []resolvedrun.BrokerGrant{{Provider: "azure-one", Materialization: "header-inject", Resources: []string{"provider-scope/22222222-2222-2222-2222-222222222222"}, EgressHosts: []string{"management.azure.com:443", "api.loganalytics.io:443"}}}
	digest := strings.Repeat("a", 64)
	encoded, err := renderCompose(backend.config, run, digest, namesFor(backend.config, run.RunID, digest))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Services map[string]struct {
			Environment map[string]string `yaml:"environment"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	environment := document.Services["agent"].Environment
	if len(environment) == 0 {
		t.Fatal("missing rendered agent environment")
	}
	for key := range environment {
		if strings.HasPrefix(key, "NVT_BROKER_") {
			t.Fatal("broker identity entered agent")
		}
	}
	python := os.Getenv("NVT_AZURE_CLI_PYTHON")
	if python == "" {
		t.Skip("optional actual Azure CLI not installed; render invariant passed")
	}
	data, _ := json.Marshal(environment)
	command := exec.Command(python, filepath.Join("..", "..", "..", "tests", "azure-cli", "rendered_environment.py"))
	command.Stdin = bytes.NewReader(data)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual rendered local env: %v\n%s", err, out)
	}
}
