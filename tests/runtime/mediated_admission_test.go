package runtime_test

// Phase 0 skeletons for the run-level admission rules of mediated credential
// egress (protocol/injection.md "Materialization Modes";
// docs/mediated-egress-plan.md configuration surface).
//
// The run-level egress mode and every grant's materialization must agree,
// and a mismatch fails admission loudly in both directions — there is no
// downgrade or ignore path. This is one of the two main protections against
// silent-fallback (plan risk 2): without it, a direct run could quietly
// materialize a header-inject grant as a bundle, or a mediated run could
// quietly write bundles into a supposedly zero-secret container.
//
// The rule is enforced at two surfaces, both pinned here:
//   - operator: AgentSchedule admission (HTTP submission endpoint) rejects
//     the work item; the error names the offending grant and is surfaced on
//     the AgentRun status
//   - compose: `agent-init` validation exits non-zero naming the offending
//     grant before any container starts
//
// Skipped pending plan Phase 3 (operator/compose wiring), where admission
// gains the egress mode field. Bodies document the required assertions.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const admissionPending = "pending Phase 3 (docs/mediated-egress-plan.md): egress mode admission not implemented"

// TestAdmissionRejectsDirectRunWithHeaderInjectGrant pins the first
// direction: egress mode `direct` combined with any `header-inject` grant
// fails admission.
//
// Phase 3 wiring for this skeleton:
//  1. Configure an agent whose broker grants include
//     `materialization: header-inject`.
//  2. Submit work with `egress: direct` via the operator admission endpoint;
//     assert rejection (4xx), error message names the offending
//     provider/grant, and no AgentRun Pod is created.
//  3. Run compose `agent-init` without MEDIATED for the same agent; assert
//     non-zero exit naming the offending grant and no containers started.
//  4. Assert in both surfaces that no bundle was materialized as a
//     "helpful" downgrade.
func TestAdmissionRejectsDirectRunWithHeaderInjectGrant(t *testing.T) {
	runOperatorAdmissionValidationTest(t)
	root := repoRoot(t)
	name := "direct-header-inject"
	agentDir := filepath.Join(root, ".agents", name)
	if err := os.RemoveAll(agentDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(agentDir) })
	agentsFile := preserveBrokerAgentsFile(t, root)
	mustWriteFile(t, agentsFile, `agents:
- id: direct-header-inject
  token-sha256: sha256:0000000000000000000000000000000000000000000000000000000000000000
  grants:
    - provider: api-main
      materialization: header-inject
      repositories:
        - example/repo
`)
	home := t.TempDir()
	mustWriteFile(t, filepath.Join(home, ".codex", "auth.json"), "host-secret-auth\n")
	command := "HOME=" + shellQuote(home) + " bash " + shellQuote(filepath.Join(root, "scripts", "agent-init.sh"))
	cmd := commandWithEnv(command, nil, "--name", name)
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("agent-init unexpectedly succeeded:\n%s", output)
	}
	if !strings.Contains(string(output), "api-main") || !strings.Contains(string(output), "header-inject") {
		t.Fatalf("expected offending grant in output, got:\n%s", output)
	}
	if _, err := os.Stat(filepath.Join(agentDir, "auth", "codex", "auth.json")); err == nil {
		t.Fatalf("direct mismatch materialized auth bundle")
	}
}

// TestAdmissionRejectsMediatedRunWithFileBundleGrant pins the second
// direction: egress mode `mediated` combined with any `file-bundle` grant
// fails admission.
//
// Phase 3 wiring for this skeleton:
//  1. Configure an agent whose broker grants include a `file-bundle`
//     (or defaulted) materialization.
//  2. Submit work with `egress: mediated` via the operator admission
//     endpoint; assert rejection (4xx), error message names the offending
//     provider/grant, and no AgentRun Pod is created.
//  3. Run compose `agent-init MEDIATED=1` for the same agent; assert
//     non-zero exit naming the offending grant and no containers started.
//  4. Assert no hybrid run exists in either surface: a run must never start
//     with a sidecar present while bundles are also written.
func TestAdmissionRejectsMediatedRunWithFileBundleGrant(t *testing.T) {
	runOperatorAdmissionValidationTest(t)
	root := repoRoot(t)
	name := "mediated-file-bundle"
	agentDir := filepath.Join(root, ".agents", name)
	if err := os.RemoveAll(agentDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(agentDir) })
	agentsFile := preserveBrokerAgentsFile(t, root)
	mustWriteFile(t, agentsFile, `agents:
- id: mediated-file-bundle
  token-sha256: sha256:0000000000000000000000000000000000000000000000000000000000000000
  grants:
    - provider: bundle-main
      repositories:
        - example/repo
`)
	home := t.TempDir()
	command := "HOME=" + shellQuote(home) + " MEDIATED=1 bash " + shellQuote(filepath.Join(root, "scripts", "agent-init.sh"))
	cmd := commandWithEnv(command, nil, "--name", name)
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("agent-init unexpectedly succeeded:\n%s", output)
	}
	if !strings.Contains(string(output), "bundle-main") || !strings.Contains(string(output), "file-bundle") {
		t.Fatalf("expected offending grant in output, got:\n%s", output)
	}
	if _, err := os.Stat(filepath.Join(agentDir, "egressd.json")); err == nil {
		t.Fatalf("mediated mismatch wrote sidecar config")
	}
}

func runOperatorAdmissionValidationTest(t *testing.T) {
	t.Helper()
	root := repoRoot(t)
	cmd := exec.Command("go", "test", "./internal/controller", "-run", "Test(ValidateAgentRunEgressModeRejectsMismatches|ReconcileRejectsEgressMismatchBeforePodAndSecrets)", "-count=1")
	cmd.Dir = filepath.Join(root, "operator")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("operator admission validation test failed: %v\n%s", err, output)
	}
}

func preserveBrokerAgentsFile(t *testing.T, root string) string {
	t.Helper()
	path := filepath.Join(root, ".broker", "agents.yaml")
	var original []byte
	existed := false
	if data, err := os.ReadFile(path); err == nil {
		original = data
		existed = true
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if existed {
			_ = os.MkdirAll(filepath.Dir(path), 0o755)
			_ = os.WriteFile(path, original, 0o600)
			return
		}
		_ = os.Remove(path)
	})
	return path
}
