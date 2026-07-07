package controller

import (
	"context"
	"net/http"
	"strings"
	"testing"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

func TestValidateDefaultEgressMode(t *testing.T) {
	t.Setenv("NVT_DEFAULT_EGRESS_MODE", "")
	if err := ValidateDefaultEgressMode(); err != nil {
		t.Fatalf("empty (direct) default must validate: %v", err)
	}
	t.Setenv("NVT_DEFAULT_EGRESS_MODE", "mediated")
	if err := ValidateDefaultEgressMode(); err != nil {
		t.Fatalf("mediated default must validate: %v", err)
	}
	t.Setenv("NVT_DEFAULT_EGRESS_MODE", "bogus")
	if err := ValidateDefaultEgressMode(); err == nil {
		t.Fatal("bogus default must fail validation")
	}
}

func TestApplyDefaultEgressModeNeverOverridesExplicit(t *testing.T) {
	t.Setenv("NVT_DEFAULT_EGRESS_MODE", "mediated")
	run := testAgentRun()
	run.Spec.Egress = nvtv1alpha1.AgentRunEgressDirect
	ApplyDefaultEgressMode(run)
	if run.Spec.Egress != nvtv1alpha1.AgentRunEgressDirect {
		t.Fatalf("explicit direct must survive a mediated default, got %q", run.Spec.Egress)
	}
}

func TestApplyDefaultEgressModeStampsEmpty(t *testing.T) {
	t.Setenv("NVT_DEFAULT_EGRESS_MODE", "mediated")
	run := testAgentRun()
	run.Spec.Egress = ""
	ApplyDefaultEgressMode(run)
	if run.Spec.Egress != nvtv1alpha1.AgentRunEgressMediated {
		t.Fatalf("empty egress must be stamped with the mediated default, got %q", run.Spec.Egress)
	}
}

// TestAgentRunEgressModeIgnoresKnob pins the CRD-default scope boundary: the
// operator never resolves empty egress from the env at read time (that would
// reintroduce the retroactive-reclassification hazard). A run with empty
// egress is direct regardless of the knob — the raw-kubectl path stays direct.
func TestAgentRunEgressModeIgnoresKnob(t *testing.T) {
	t.Setenv("NVT_DEFAULT_EGRESS_MODE", "mediated")
	run := testAgentRun()
	run.Spec.Egress = ""
	if AgentRunEgressMode(run) != nvtv1alpha1.AgentRunEgressDirect {
		t.Fatalf("AgentRunEgressMode must not read the knob; empty resolves to direct, got %q", AgentRunEgressMode(run))
	}
}

// TestAdmissionStampsDefaultEgressMode pins that the nvt admission path stamps
// the knob into spec.egress at creation, so the stored object is explicit.
func TestAdmissionStampsDefaultEgressMode(t *testing.T) {
	t.Setenv("NVT_DEFAULT_EGRESS_MODE", "direct")
	fixture := scheduleAdmissionFixture(t, testAgentSchedule())
	// Payload leaves spec.egress empty; the knob (direct) is stamped.
	body := scheduleAdmissionBody(t, "work-1", "https://example.test/1", map[string]any{})
	response, k8sClient := serveScheduleAdmission(t, fixture, body)

	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, http.StatusCreated, &decoded)
	if decoded.AgentRun == nil {
		t.Fatalf("expected an AgentRun, got %#v", decoded)
	}
	run := getScheduledAgentRun(context.Background(), t, k8sClient, decoded.AgentRun.Namespace, decoded.AgentRun.Name)
	if run.Spec.Egress != nvtv1alpha1.AgentRunEgressDirect {
		t.Fatalf("stored spec.egress must be explicit (direct), got %q", run.Spec.Egress)
	}
}

// TestAdmissionMediatedDefaultRejectsFileBundle pins that under a mediated
// default, a file-bundle grant fails admission loudly naming the grant — no
// silent downgrade.
func TestAdmissionMediatedDefaultRejectsFileBundle(t *testing.T) {
	t.Setenv("NVT_DEFAULT_EGRESS_MODE", "mediated")
	// TLS broker so validation reaches the materialization check rather than
	// stopping at the plaintext-broker guard.
	setTLSBrokerEnv(t)
	fixture := scheduleAdmissionFixture(t, testAgentSchedule())
	body := scheduleAdmissionBody(t, "work-1", "https://example.test/1", map[string]any{
		"spec": map[string]any{
			"broker": map[string]any{
				"grants": []any{map[string]any{
					"provider":        "bundle-main",
					"repositories":    []any{"example/repo"},
					"materialization": "file-bundle",
				}},
			},
		},
	})
	response, _ := serveScheduleAdmission(t, fixture, body)

	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, http.StatusBadRequest, &decoded)
	if decoded.Scheduled {
		t.Fatalf("mediated default + file-bundle grant must be rejected: %#v", decoded)
	}
	if !strings.Contains(decoded.Reason, "bundle-main") {
		t.Fatalf("rejection must name the grant, got %q", decoded.Reason)
	}
}
