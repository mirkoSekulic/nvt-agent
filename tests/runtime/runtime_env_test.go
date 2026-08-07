package runtime_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRuntimeEnvIsSharedByFreshAndResumeChildren(t *testing.T) {
	f := newFixture(t)
	freshCapture := filepath.Join(f.home, "fresh-environment.json")
	resumeCapture := filepath.Join(f.home, "resume-environment.json")
	interpolationMarker := filepath.Join(f.home, "shell-interpolation-ran")
	fresh := writeRuntimeEnvCapture(t, f, "fresh-runtime", freshCapture)
	resume := writeRuntimeEnvCapture(t, f, "resume-runtime", resumeCapture)
	literal := `${HOME}:$(touch ` + interpolationMarker + `)`
	config := f.writeAgentConfig(fmt.Sprintf(`
runtime:
  command: %s
  args: [fresh-argument]
  env:
    NVT_RUNTIME_ENV_TEST: configured
    lower_case_name: %s
  resume:
    command: %s
    args: [resume-argument]
`, quoteYAML(fresh), quoteYAML(literal), quoteYAML(resume)))
	f.runWithEnv(bootstrapBin(f.root), true, []string{"NVT_RUNTIME_ENV_TEST=inherited"}, config)

	commandFile := filepath.Join(f.home, ".nvt-agent", "agent-command.json")
	var document struct {
		Environment map[string]string `json:"env"`
		Resume      map[string]any    `json:"resume"`
	}
	decodeJSONFile(t, commandFile, &document)
	wantEnvironment := map[string]string{
		"NVT_RUNTIME_ENV_TEST": "configured",
		"lower_case_name":      literal,
	}
	if !reflect.DeepEqual(document.Environment, wantEnvironment) {
		t.Fatalf("unexpected persisted runtime environment: %#v", document.Environment)
	}
	if _, duplicated := document.Resume["env"]; duplicated {
		t.Fatalf("resume command duplicated the shared runtime environment: %#v", document.Resume)
	}

	executor := "python3 " + shellQuote(filepath.Join(f.root, "runtime", "core", "start-agent-session.py"))
	inherited := []string{"NVT_RUNTIME_ENV_TEST=inherited", "lower_case_name=inherited-lower"}
	f.runWithEnv(executor, true, inherited, commandFile, "fresh")
	f.runWithEnv(executor, true, inherited, commandFile, "resume")

	for index, capture := range []string{freshCapture, resumeCapture} {
		var got struct {
			Environment map[string]string `json:"environment"`
			Arguments   []string          `json:"arguments"`
		}
		decodeJSONFile(t, capture, &got)
		if !reflect.DeepEqual(got.Environment, wantEnvironment) {
			t.Fatalf("%s did not receive the shared overriding environment: %#v", capture, got.Environment)
		}
		wantArguments := [][]string{{"fresh-argument"}, {"resume-argument"}}[index]
		if !reflect.DeepEqual(got.Arguments, wantArguments) {
			t.Fatalf("%s received unexpected arguments: %#v", capture, got.Arguments)
		}
	}
	if _, err := os.Stat(interpolationMarker); !os.IsNotExist(err) {
		t.Fatalf("runtime.env value was shell-evaluated, stat error = %v", err)
	}
}

func TestRuntimeEnvAbsencePreservesCommandDocumentAndInheritedEnvironment(t *testing.T) {
	f := newFixture(t)
	capture := filepath.Join(f.home, "absence-environment.json")
	command := writeRuntimeEnvCapture(t, f, "absence-runtime", capture)
	config := f.writeAgentConfig(fmt.Sprintf("runtime:\n  command: %s\n  args: [unchanged]\n", quoteYAML(command)))
	f.runWithEnv(bootstrapBin(f.root), true, nil, config)

	commandFile := filepath.Join(f.home, ".nvt-agent", "agent-command.json")
	raw, err := os.ReadFile(commandFile)
	if err != nil {
		t.Fatal(err)
	}
	wantRaw := fmt.Sprintf("{\"command\":%s,\"args\":[\"unchanged\"]}\n", quoteJSON(command))
	if string(raw) != wantRaw {
		t.Fatalf("runtime.env absence changed the command document bytes:\ngot  %q\nwant %q", raw, wantRaw)
	}

	executor := "python3 " + shellQuote(filepath.Join(f.root, "runtime", "core", "start-agent-session.py"))
	f.runWithEnv(executor, true, []string{"NVT_RUNTIME_ENV_TEST=inherited"}, commandFile)
	var got struct {
		Environment map[string]string `json:"environment"`
	}
	decodeJSONFile(t, capture, &got)
	if got.Environment["NVT_RUNTIME_ENV_TEST"] != "inherited" {
		t.Fatalf("runtime.env absence stopped ordinary environment inheritance: %#v", got.Environment)
	}
}

func TestBootstrapRejectsMalformedRuntimeEnv(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		message string
	}{
		{"list", "runtime:\n  command: generic-runtime\n  env: []\n", "runtime.env must be a YAML object"},
		{"null", "runtime:\n  command: generic-runtime\n  env: null\n", "runtime.env must be a YAML object"},
		{"invalid dash", "runtime:\n  command: generic-runtime\n  env:\n    BAD-NAME: value\n", "invalid environment variable name 'BAD-NAME'"},
		{"invalid prefix", "runtime:\n  command: generic-runtime\n  env:\n    1BAD: value\n", "invalid environment variable name '1BAD'"},
		{"non string name", "runtime:\n  command: generic-runtime\n  env:\n    7: value\n", "invalid environment variable name 7"},
		{"number value", "runtime:\n  command: generic-runtime\n  env:\n    VALID_NAME: 7\n", "runtime.env.VALID_NAME must be a string"},
		{"boolean value", "runtime:\n  command: generic-runtime\n  env:\n    VALID_NAME: true\n", "runtime.env.VALID_NAME must be a string"},
		{"command required", "runtime:\n  env:\n    VALID_NAME: value\n", "runtime.command is required when runtime.env is configured"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			config := f.writeAgentConfig(test.config)
			output := f.runWithEnv(bootstrapBin(f.root), false, nil, config)
			if !strings.Contains(output, test.message) {
				t.Fatalf("expected %q, got:\n%s", test.message, output)
			}
		})
	}
}

func TestSessionExecutorRejectsMalformedRuntimeEnvDocument(t *testing.T) {
	tests := []struct {
		name     string
		document string
		message  string
	}{
		{"not object", `{"command":"generic-runtime","env":[]}`, "env must be an object"},
		{"null", `{"command":"generic-runtime","env":null}`, "env must be an object"},
		{"invalid name", `{"command":"generic-runtime","env":{"BAD-NAME":"value"}}`, "invalid environment variable name 'BAD-NAME'"},
		{"non string value", `{"command":"generic-runtime","env":{"VALID_NAME":7}}`, "env.VALID_NAME must be a string"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			commandFile := filepath.Join(f.home, "agent-command.json")
			if err := os.WriteFile(commandFile, []byte(test.document+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			executor := "python3 " + shellQuote(filepath.Join(f.root, "runtime", "core", "start-agent-session.py"))
			output := f.runWithEnv(executor, false, nil, commandFile)
			if !strings.Contains(output, test.message) {
				t.Fatalf("expected %q, got:\n%s", test.message, output)
			}
		})
	}
}

func TestRuntimeEnvIsNotExportedToEntrypointOrPlugins(t *testing.T) {
	f := newFixture(t)
	globalCapture := filepath.Join(f.home, "global-environment")
	pluginCapture := filepath.Join(f.home, "plugin-environment")
	plugin := f.writeTool("capture-plugin-environment", fmt.Sprintf(`#!/usr/bin/env bash
printf '%%s' "${NVT_RUNTIME_ONLY_VALUE-unset}" > %s
`, shellQuote(pluginCapture)))
	config := f.writeAgentConfig(fmt.Sprintf(`
runtime:
  command: generic-runtime
  env:
    NVT_RUNTIME_ONLY_VALUE: child-only
plugins:
  - name: environment-capture
    source: custom
    command: %s
    when: before-agent
    restart: never
`, quoteYAML(plugin)))

	script := fmt.Sprintf(`
set -euo pipefail
python3 %s %s
printf '%%s' "${NVT_RUNTIME_ONLY_VALUE-unset}" > %s
python3 %s before-agent %s
`, shellQuote(filepath.Join(f.root, "runtime", "core", "bootstrap.py")), shellQuote(config), shellQuote(globalCapture), shellQuote(filepath.Join(f.root, "runtime", "core", "run-plugins.py")), shellQuote(config))
	f.runWithEnv("bash", true, nil, "-c", script)

	for label, path := range map[string]string{"entrypoint": globalCapture, "plugin": pluginCapture} {
		value, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(value) != "unset" {
			t.Fatalf("%s received runtime-only environment: %q", label, value)
		}
	}
	persisted, err := os.ReadFile(filepath.Join(f.home, ".nvt-agent", "env"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), "NVT_RUNTIME_ONLY_VALUE") {
		t.Fatalf("runtime.env leaked into the globally sourced environment file:\n%s", persisted)
	}
}

func writeRuntimeEnvCapture(t *testing.T, f *fixture, name, capture string) string {
	t.Helper()
	return f.writeBin(name, fmt.Sprintf(`#!/usr/bin/env python3
import json
import os
import sys

with open(%s, "w", encoding="utf-8") as handle:
    json.dump({
        "environment": {
            "NVT_RUNTIME_ENV_TEST": os.environ.get("NVT_RUNTIME_ENV_TEST", ""),
            "lower_case_name": os.environ.get("lower_case_name", ""),
        },
        "arguments": sys.argv[1:],
    }, handle, sort_keys=True)
`, quoteJSON(capture)))
}

func quoteJSON(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}
