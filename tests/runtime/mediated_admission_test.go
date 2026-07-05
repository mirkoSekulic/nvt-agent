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

import "testing"

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
	t.Skip(admissionPending)
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
	t.Skip(admissionPending)
}
