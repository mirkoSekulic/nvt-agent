package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"sigs.k8s.io/yaml"
)

func TestHTTPAuthorizationAgentRunAndScheduleBrokerIntegration(t *testing.T) {
	t.Setenv("NVT_BROKER_URL", "https://nvt-broker:7347")
	t.Setenv("NVT_BROKER_CA_SECRET", "fixture-broker-ca")
	raw, err := os.ReadFile("../../../examples/http-authorization/agentrun.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var direct nvtv1alpha1.AgentRun
	if err := yaml.UnmarshalStrict(raw, &direct); err != nil {
		t.Fatal(err)
	}
	if err := ValidateAgentRunEgressMode(&direct); err != nil {
		t.Fatal(err)
	}
	schedule := testProfiledAgentSchedule()
	profile := &schedule.Spec.Profiles[0]
	profile.Broker = direct.Spec.Broker.DeepCopy()
	profile.Egress = direct.Spec.Egress
	profile.EgressEnforcement = direct.Spec.EgressEnforcement
	profile.EgressTransport = direct.Spec.EgressTransport
	profile.AgentRuntimeConfig = rawJSON(`{"command":"bash","args":["-lc","sleep infinity"],"proxy":{"provider":"api"}}`)
	fixture := newProfileAdmissionFixture(t, schedule)
	response := fixture.serve(t, profiledAdmissionBody(t, "http-policy-profile", nil, nil), "Bearer projected-token")
	var decoded scheduleAdmissionResponse
	decodeAdmissionResponse(t, response, http.StatusCreated, &decoded)
	admitted := fixture.run(t, decoded.AgentRun.Name)
	for name, run := range map[string]*nvtv1alpha1.AgentRun{"raw AgentRun": &direct, "AgentSchedule admission": &admitted} {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(BrokerAgentGrants(run.Spec.Broker))
			if err != nil {
				t.Fatal(err)
			}
			python, err := exec.LookPath("python3")
			if err != nil {
				t.Fatal(err)
			}
			python, err = filepath.Abs(python)
			if err != nil {
				t.Fatal(err)
			}
			command := exec.Command(python, "../../../tests/http-authorization/verify_policy.py")
			command.Env = []string{"PATH=" + filepath.Dir(python), "HOME=" + t.TempDir(), "PYTHONDONTWRITEBYTECODE=1"}
			if value := os.Getenv("LD_LIBRARY_PATH"); value != "" {
				command.Env = append(command.Env, "LD_LIBRARY_PATH="+value)
			}
			command.Stdin = bytes.NewReader(data)
			if out, err := command.CombinedOutput(); err != nil {
				t.Fatalf("projected policy did not enforce: %v\n%s", err, out)
			}
		})
	}
}
