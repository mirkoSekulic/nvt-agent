package localroutes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestValidateRunAndList(t *testing.T) {
	run := Run{
		APIVersion: APIVersion, RunID: "run-1", State: "running", Ready: true,
		Principal: Principal{Issuer: "https://identity.example", Subject: "42", DisplayName: "Alice"},
		SourceURL: "https://github.com/acme/widget/issues/7#issuecomment-5307105878",
		Profile:   "engineering", Workflow: "implement", CreatedAt: time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC),
		Session:   Endpoint{Host: "run-1.agent.localhost", Path: "/agents/run-1/", UpstreamHost: "nvt-local-run-1-network", UpstreamPort: 4090},
		Exposures: []Exposure{{Name: "app", Host: "app.run-1.agent.localhost", UpstreamHost: "nvt-local-run-1-network", UpstreamPort: 3000}},
	}
	if err := ValidateRun(run); err != nil {
		t.Fatal(err)
	}
	if err := ValidateList(List{APIVersion: APIVersion, Runs: []Run{run}}); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Run){
		"ready mismatch":  func(value *Run) { value.Ready = false },
		"terminal":        func(value *Run) { value.State = "completed" },
		"unsafe path":     func(value *Run) { value.Session.Path = "/agents/%2e%2e/" },
		"host port":       func(value *Run) { value.Session.Host = "run.agent.localhost:4090" },
		"target URL":      func(value *Run) { value.Session.UpstreamHost = "http://run.internal" },
		"target port":     func(value *Run) { value.Session.UpstreamPort = 0 },
		"insecure source": func(value *Run) { value.SourceURL = "http://github.example/acme/widget/issues/7" },
		"source userinfo": func(value *Run) { value.SourceURL = "https://user@github.example/acme/widget/issues/7" },
		"source control":  func(value *Run) { value.SourceURL = "https://github.example/acme/widget/issues/7#issuecomment%0a7" },
		"source non-UTF8": func(value *Run) { value.SourceURL = "https://github.example/acme/widget/issues/7#issuecomment%ff7" },
		"source too long": func(value *Run) { value.SourceURL = "https://github.example/" + strings.Repeat("x", MaxSourceURLBytes) },
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
		CreatedAt: time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC), Session: Endpoint{Host: "run-1.agent.localhost", Path: "/agents/run-1/", UpstreamHost: "nvt-local-run-1-network", UpstreamPort: 4090}, Exposures: []Exposure{},
	}
	encoded, _ := json.Marshal(run)
	decoded, err := DecodeRun(encoded)
	if err != nil || decoded.SourceURL != run.SourceURL {
		t.Fatalf("source URL did not round trip: %#v, %v", decoded, err)
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
