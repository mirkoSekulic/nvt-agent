package config_test

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"

	serviceconfig "github.com/mirkoSekulic/nvt-agent/localplatform/config"
	"github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

func TestHTTPExposureRendersOnlySelectedProfile(t *testing.T) {
	data, err := os.ReadFile("../../examples/http-exposure/manifest.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	personal := m.Profiles["personal"]
	personal.Expose = nil
	m.Profiles["personal"] = personal
	m.Profiles["other"] = personal
	m.Workstations = append(m.Workstations, manifest.Workstation{Name: "other", Profile: "other"})
	render := func() ([]byte, map[string]resolvedrun.Profile) {
		t.Helper()
		compiled, err := manifest.Compile(m)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := serviceconfig.Controller(compiled, nil)
		if err != nil {
			t.Fatal(err)
		}
		var config resolvedrun.TrustedConfiguration
		if err := json.Unmarshal(encoded, &config); err != nil {
			t.Fatal(err)
		}
		if _, err := resolvedrun.NewResolver(config); err != nil {
			t.Fatal(err)
		}
		profiles := map[string]resolvedrun.Profile{}
		for _, profile := range config.Profiles {
			profiles[profile.Name] = profile
		}
		return encoded, profiles
	}
	baseline, baselineProfiles := render()
	if bytes.Contains(baseline, []byte(`"expose"`)) {
		t.Fatal("omitted exposure generated routes")
	}
	for _, routes := range [][]manifest.HTTPExposure{
		{{Name: "website", TargetPort: 4321}},
		{{Name: "website", TargetPort: 4321}, {Name: "api", TargetPort: 8080}},
	} {
		personal.Expose = &manifest.ProfileExpose{HTTP: routes}
		m.Profiles["personal"] = personal
		first, profiles := render()
		second, _ := render()
		if !bytes.Equal(first, second) {
			t.Fatal("render is nondeterministic")
		}
		for name, profile := range profiles {
			if name != "personal" && !reflect.DeepEqual(profile, baselineProfiles[name]) {
				t.Fatalf("unrelated profile %s changed", name)
			}
		}
		var settings map[string]json.RawMessage
		if err := json.Unmarshal(profiles["personal"].AgentConfig, &settings); err != nil {
			t.Fatal(err)
		}
		ordered := append([]manifest.HTTPExposure(nil), routes...)
		sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
		want, _ := json.Marshal(manifest.ProfileExpose{HTTP: ordered})
		if !bytes.Equal(settings["expose"], want) {
			t.Fatalf("native expose = %s, want %s", settings["expose"], want)
		}
		delete(settings, "expose")
		remaining, _ := json.Marshal(settings)
		if !bytes.Equal(remaining, baselineProfiles["personal"].AgentConfig) {
			t.Fatal("exposure changed unrelated agent settings")
		}
	}
	for _, expose := range []*manifest.ProfileExpose{nil, {}, {HTTP: []manifest.HTTPExposure{}}} {
		personal.Expose = expose
		m.Profiles["personal"] = personal
		got, _ := render()
		if !bytes.Equal(got, baseline) {
			t.Fatal("empty/removed exposure changed canonical rendered configuration")
		}
	}
}
