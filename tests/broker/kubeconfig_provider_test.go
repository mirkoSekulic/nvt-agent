package broker_test

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestKubeconfigExecutableProvider(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	command := exec.Command("python3", "-m", "unittest", "broker/providers/kubeconfig/provider_test.py")
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("kubeconfig provider tests failed: %v\n%s", err, output)
	}
}
