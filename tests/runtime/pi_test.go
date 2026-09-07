package runtime_test

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPiManagedPublicConfiguration(t *testing.T) {
	cmd := exec.Command("python3", filepath.Join(repoRoot(t), "tests", "pi", "managed_test.py"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("managed Pi configuration: %v\n%s", err, out)
	}
}
