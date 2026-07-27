package broker_test

import (
	"os/exec"
	"testing"
)

func TestGuestEnrollmentSQLiteIssuerUnit(t *testing.T) {
	root := repoRoot(t)
	command := exec.Command("python3", "-m", "unittest", "-v", "broker.core.guest_enrollment_test")
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("guest enrollment SQLite issuer tests failed: %v\n%s", err, output)
	}
}
