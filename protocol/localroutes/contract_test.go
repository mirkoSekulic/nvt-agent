package localroutes

import (
	"encoding/json"
	"testing"
	"time"
)

func TestValidateRunAndList(t *testing.T) {
	run := Run{
		APIVersion: APIVersion, RunID: "run-1", State: "running", Ready: true,
		Principal: Principal{Issuer: "https://identity.example", Subject: "42", DisplayName: "Alice"},
		Profile:   "engineering", Workflow: "implement", CreatedAt: time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC),
		Session:   Endpoint{Host: "run-1.agent.localhost", Path: "/agents/run-1/"},
		Exposures: []Exposure{{Name: "app", Host: "app.run-1.agent.localhost"}},
	}
	if err := ValidateRun(run); err != nil {
		t.Fatal(err)
	}
	if err := ValidateList(List{APIVersion: APIVersion, Runs: []Run{run}}); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Run){
		"ready mismatch": func(value *Run) { value.Ready = false },
		"terminal":       func(value *Run) { value.State = "completed" },
		"unsafe path":    func(value *Run) { value.Session.Path = "/agents/%2e%2e/" },
		"host port":      func(value *Run) { value.Session.Host = "run.agent.localhost:4090" },
		"duplicate app": func(value *Run) {
			value.Exposures = append(value.Exposures, value.Exposures[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy := run
			copy.Exposures = append([]Exposure(nil), run.Exposures...)
			mutate(&copy)
			if ValidateRun(copy) == nil {
				t.Fatalf("invalid route accepted: %#v", copy)
			}
		})
	}
}

func TestStrictDecodeRejectsUnknownDuplicateAndOversizedDocuments(t *testing.T) {
	run := Run{
		APIVersion: APIVersion, RunID: "run-1", State: "running", Ready: true,
		Principal: Principal{Issuer: "https://identity.example", Subject: "42"}, Profile: "engineering", Workflow: "implement",
		CreatedAt: time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC), Session: Endpoint{Host: "run-1.agent.localhost", Path: "/agents/run-1/"}, Exposures: []Exposure{},
	}
	encoded, _ := json.Marshal(run)
	if _, err := DecodeRun(encoded); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{
		[]byte(`{"api_version":"nvt.local-routes/v1","api_version":"nvt.local-routes/v1"}`),
		append(encoded[:len(encoded)-1], []byte(`,"unknown":true}`)...),
		make([]byte, MaxDocumentBytes+1),
	} {
		if _, err := DecodeRun(invalid); err == nil {
			t.Fatal("invalid route document accepted")
		}
	}
}
