package broker_test

import (
	"os/exec"
	"testing"
)

func TestDynamicPrincipalAccountsUnit(t *testing.T) {
	root := repoRoot(t)
	command := exec.Command("python3", "-m", "unittest", "-v", "broker.core.dynamic_accounts_test")
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("dynamic principal account tests failed: %v\n%s", err, output)
	}
}
