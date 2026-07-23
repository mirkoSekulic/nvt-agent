package runtime_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBootstrapAppendsInitialPromptAfterRuntimeArgs(t *testing.T) {
	f := newFixture(t)
	config := f.writeAgentConfig(`
runtime:
  command: test-agent
  args:
    - --dangerously-autonomous
    - --model
    - test-model
  initial-prompt:
    delivery: argument
    text: |-
      Inspect the workspace.
      Create the requested change.
`)

	f.runWithEnv("python3 "+shellQuote(filepath.Join(f.root, "runtime", "core", "bootstrap.py")), true, nil, config)

	var command struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	decodeJSONFile(t, filepath.Join(f.home, ".nvt-agent", "agent-command.json"), &command)
	want := []string{
		"--dangerously-autonomous",
		"--model",
		"test-model",
		"Inspect the workspace.\nCreate the requested change.",
	}
	if command.Command != "test-agent" || !reflect.DeepEqual(command.Args, want) {
		t.Fatalf("unexpected launch command: %#v", command)
	}

	capture := filepath.Join(f.home, "launched-args")
	f.writeBin("test-agent", fmt.Sprintf("#!/usr/bin/env bash\nprintf '%%s\\0' \"$@\" > %s\n", shellQuote(capture)))
	commandFile := filepath.Join(f.home, ".nvt-agent", "agent-command.json")
	f.runWithEnv(
		"python3 "+shellQuote(filepath.Join(f.root, "runtime", "core", "start-agent-session.py")),
		true,
		nil,
		commandFile,
	)
	data, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	parts := bytes.Split(bytes.TrimSuffix(data, []byte{0}), []byte{0})
	launched := make([]string, len(parts))
	for index, part := range parts {
		launched[index] = string(part)
	}
	if !reflect.DeepEqual(launched, want) {
		t.Fatalf("unexpected executed args: %#v", launched)
	}
}

func TestBootstrapLeavesRuntimeArgsUnchangedWithoutInitialPrompt(t *testing.T) {
	f := newFixture(t)
	config := f.writeAgentConfig(`
runtime:
  command: test-agent
  args: ["--yolo"]
`)

	f.runWithEnv("python3 "+shellQuote(filepath.Join(f.root, "runtime", "core", "bootstrap.py")), true, nil, config)

	var command map[string]any
	decodeJSONFile(t, filepath.Join(f.home, ".nvt-agent", "agent-command.json"), &command)
	encoded, err := json.Marshal(command["args"])
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `["--yolo"]` {
		t.Fatalf("runtime args changed without an initial prompt: %s", encoded)
	}
}

func TestBootstrapRejectsInvalidInitialPromptContract(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		message string
	}{
		{
			name:    "not object",
			config:  "runtime:\n  command: test-agent\n  initial-prompt: text\n",
			message: "runtime.initial-prompt must be a YAML object",
		},
		{
			name:    "unsupported delivery",
			config:  "runtime:\n  command: test-agent\n  initial-prompt:\n    delivery: session\n    text: work\n",
			message: "runtime.initial-prompt.delivery must be argument",
		},
		{
			name:    "empty text",
			config:  "runtime:\n  command: test-agent\n  initial-prompt:\n    delivery: argument\n    text: ''\n",
			message: "runtime.initial-prompt.text must be a non-empty string",
		},
		{
			name:    "whitespace text",
			config:  "runtime:\n  command: test-agent\n  initial-prompt:\n    delivery: argument\n    text: '   '\n",
			message: "runtime.initial-prompt.text must be a non-empty string",
		},
		{
			name:    "missing command",
			config:  "runtime:\n  initial-prompt:\n    delivery: argument\n    text: work\n",
			message: "runtime.command is required when runtime.initial-prompt is configured",
		},
		{
			name:    "unknown field",
			config:  "runtime:\n  command: test-agent\n  initial-prompt:\n    delivery: argument\n    text: work\n    retry: true\n",
			message: "runtime.initial-prompt has unsupported fields: retry",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			config := f.writeAgentConfig(test.config)
			output := f.runWithEnv("python3 "+shellQuote(filepath.Join(f.root, "runtime", "core", "bootstrap.py")), false, nil, config)
			if !strings.Contains(output, test.message) {
				t.Fatalf("expected %q, got:\n%s", test.message, output)
			}
		})
	}
}
