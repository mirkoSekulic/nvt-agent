package runtime_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAzureCLIInertAdapter(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	command := exec.Command("python3", filepath.Join(root, "runtime/plugins/azure-cli/adapter_test.py"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("adapter tests: %v\n%s", err, output)
	}
}

func TestAzureCLIActualCompatibility(t *testing.T) {
	python := os.Getenv("NVT_AZURE_CLI_PYTHON")
	if python == "" {
		t.Skip("optional Azure CLI environment not installed; see docs/azure-cli-mediation.md")
	}
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	command := exec.Command(python, filepath.Join(root, "tests/azure-cli/compatibility.py"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual CLI tests: %v\n%s", err, output)
	}
}
