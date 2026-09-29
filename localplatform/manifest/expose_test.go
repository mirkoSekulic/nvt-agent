package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

func exposureManifest(expose string) string {
	return `apiVersion: nvt.dev/local/v1
retentionPolicies:
  persistent:
    persistence: {workspace: true, runtimeState: true, dockerData: true}
profiles:
  personal:
    runtime: {preset: shell, autonomy: approval-required}
` + expose + `
workstations:
  - {name: personal, profile: personal}
`
}

func TestHTTPExposureValidation(t *testing.T) {
	valid := []string{
		"", "    expose: {}", "    expose: {http: []}",
		"    expose: {http: [{name: website, targetPort: 4321}]}",
		"    expose: {http: [{name: z-site, targetPort: 1}, {name: a, targetPort: 65535}]}",
		"    expose: {http: [{name: " + strings.Repeat("a", 63) + ", targetPort: 80}]}",
	}
	var routes []string
	for i := 0; i < MaxHTTPExposures; i++ {
		routes = append(routes, fmt.Sprintf("{name: app-%d, targetPort: 4321}", i))
	}
	valid = append(valid, "    expose: {http: ["+strings.Join(routes, ",")+"]}")
	for _, input := range valid {
		if _, err := Decode(strings.NewReader(exposureManifest(input))); err != nil {
			t.Fatalf("valid exposure %q: %v", input, err)
		}
	}
	invalid := []string{
		"    expose: []", "    expose: true", "    expose: {http: null}",
		"    expose: {http: {name: app, targetPort: 80}}", "    expose: {http: [null]}",
		"    expose: {https: []}", "    expose: {http: [{name: app, targetPort: 80, source: agent}]}",
		"    expose: {http: [{name: app, targetPort: 80, upstream: 'http://example.test'}]}",
		"    expose: {http: [{name: app, targetPort: 80}, {name: app, targetPort: 81}]}",
		"    expose: {http: [" + strings.Join(append(routes, "{name: extra, targetPort: 80}"), ",") + "]}",
	}
	for _, name := range []string{"''", "App", "app.test", "app_1", "-app", "app-", "'*'", "123", strings.Repeat("a", 64)} {
		invalid = append(invalid, "    expose: {http: [{name: "+name+", targetPort: 80}]}")
	}
	for _, port := range []string{"0", "-1", "65536", "1.5", "80.0", "'80'", "true", "null", "[]", "{}", "999999999999999999999999"} {
		invalid = append(invalid, "    expose: {http: [{name: app, targetPort: "+port+"}]}")
	}
	invalid = append(invalid, "    expose: {http: [{name: app}]}", "    expose: {http: [{targetPort: 80}]}")
	for _, input := range invalid {
		if _, err := Decode(strings.NewReader(exposureManifest(input))); err == nil {
			t.Errorf("accepted invalid exposure: %s", input)
		}
	}
}

func TestHTTPExposureCompilationCanonicalizesOrderWithoutAliasing(t *testing.T) {
	m, err := Decode(strings.NewReader(exposureManifest("    expose: {http: [{name: z-site, targetPort: 4321}, {name: api, targetPort: 8080}]}")))
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(m)
	compiled, err := Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	routes := compiled.Controller.Profiles[0].Profile.Expose.HTTP
	if !reflect.DeepEqual(routes, []HTTPExposure{{Name: "api", TargetPort: 8080}, {Name: "z-site", TargetPort: 4321}}) {
		t.Fatal("routes are not in canonical name order")
	}
	canonical, err := compiled.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip Compiled
	if err := json.Unmarshal(canonical, &roundTrip); err != nil {
		t.Fatal(err)
	}
	other, err := roundTrip.CanonicalJSON()
	if err != nil || !bytes.Equal(canonical, other) {
		t.Fatal("compiled round trip changed")
	}
	reordered := m
	reordered.Profiles = cloneMap(m.Profiles)
	profile := reordered.Profiles["personal"]
	profile.Expose = &ProfileExpose{HTTP: []HTTPExposure{routes[0], routes[1]}}
	reordered.Profiles["personal"] = profile
	recompiled, err := Compile(reordered)
	if err != nil {
		t.Fatal(err)
	}
	other, err = recompiled.CanonicalJSON()
	if err != nil || !bytes.Equal(canonical, other) {
		t.Fatal("list order changed canonical configuration")
	}
	routes[0].Name = "changed"
	after, _ := json.Marshal(m)
	if !bytes.Equal(before, after) {
		t.Fatal("compiler mutated authored routes")
	}
}

func TestEmptyHTTPExposureHasOmittedCanonicalForm(t *testing.T) {
	var baseline []byte
	for _, expose := range []string{"", "    expose: {}", "    expose: {http: []}"} {
		m, err := Decode(strings.NewReader(exposureManifest(expose)))
		if err != nil {
			t.Fatal(err)
		}
		compiled, err := Compile(m)
		if err != nil {
			t.Fatal(err)
		}
		got, err := compiled.CanonicalJSON()
		if err != nil {
			t.Fatal(err)
		}
		if baseline == nil {
			baseline = got
		}
		if !bytes.Equal(baseline, got) || bytes.Contains(got, []byte(`"expose"`)) {
			t.Fatal("empty exposure changed canonical configuration")
		}
	}
}

func TestHTTPExposureExample(t *testing.T) {
	data, err := os.ReadFile("../../examples/http-exposure/manifest.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m, err := Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compile(m); err != nil {
		t.Fatal(err)
	}
	if got := m.Profiles["personal"].Expose.HTTP; !reflect.DeepEqual(got, []HTTPExposure{{Name: "website", TargetPort: 4321}}) {
		t.Fatalf("example routes: %#v", got)
	}
}
