package broker_test

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAzureExecutableProvider(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	command := exec.Command("python3", "-m", "unittest", "broker/providers/azure/provider_test.py")
	command.Dir = filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("Azure provider tests: %v\n%s", err, output)
	}
}
