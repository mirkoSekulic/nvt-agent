package resolvedrun

import (
	"reflect"
	"strings"
	"testing"
)

func TestApplyRuntimeSelectionArgumentsRejectsConflictingCLIForms(t *testing.T) {
	tests := []struct {
		name      string
		selection Runtime
		args      []string
	}{
		{name: "codex long model", selection: Runtime{Type: "codex", Model: "typed"}, args: []string{"--model", "raw"}},
		{name: "codex assigned long model", selection: Runtime{Type: "codex", Model: "typed"}, args: []string{"--model=raw"}},
		{name: "codex short model", selection: Runtime{Type: "codex", Model: "typed"}, args: []string{"-m", "raw"}},
		{name: "codex attached short model", selection: Runtime{Type: "codex", Model: "typed"}, args: []string{"-mraw"}},
		{name: "codex assigned short model", selection: Runtime{Type: "codex", Model: "typed"}, args: []string{"-m=raw"}},
		{name: "codex config model", selection: Runtime{Type: "codex", Model: "typed"}, args: []string{"--config", "model=raw"}},
		{name: "codex short config model", selection: Runtime{Type: "codex", Model: "typed"}, args: []string{"-c", "model=raw"}},
		{name: "codex assigned config model", selection: Runtime{Type: "codex", Model: "typed"}, args: []string{"--config=model=raw"}},
		{name: "codex assigned short config model", selection: Runtime{Type: "codex", Model: "typed"}, args: []string{"-c=model=raw"}},
		{name: "codex attached short config model", selection: Runtime{Type: "codex", Model: "typed"}, args: []string{"-cmodel=raw"}},
		{name: "codex config effort", selection: Runtime{Type: "codex", Effort: "high"}, args: []string{"--config", "model_reasoning_effort=low"}},
		{name: "codex short config effort", selection: Runtime{Type: "codex", Effort: "high"}, args: []string{"-c", "model_reasoning_effort=low"}},
		{name: "codex assigned config effort", selection: Runtime{Type: "codex", Effort: "high"}, args: []string{"--config=model_reasoning_effort=low"}},
		{name: "codex assigned short config effort", selection: Runtime{Type: "codex", Effort: "high"}, args: []string{"-c=model_reasoning_effort=low"}},
		{name: "codex attached short config effort", selection: Runtime{Type: "codex", Effort: "high"}, args: []string{"-cmodel_reasoning_effort=low"}},
		{name: "claude long model", selection: Runtime{Type: "claude", Model: "typed"}, args: []string{"--model", "raw"}},
		{name: "claude attached short model", selection: Runtime{Type: "claude", Model: "typed"}, args: []string{"-mraw"}},
		{name: "claude assigned short model", selection: Runtime{Type: "claude", Model: "typed"}, args: []string{"-m=raw"}},
		{name: "claude effort", selection: Runtime{Type: "claude", Effort: "high"}, args: []string{"--effort", "low"}},
		{name: "claude assigned effort", selection: Runtime{Type: "claude", Effort: "high"}, args: []string{"--effort=low"}},
		{name: "codex end of options", selection: Runtime{Type: "codex", Model: "typed"}, args: []string{"--"}},
		{name: "claude end of options", selection: Runtime{Type: "claude", Effort: "high"}, args: []string{"--", "prompt"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ApplyRuntimeSelectionArguments(test.args, test.selection)
			if err == nil || !strings.Contains(err.Error(), "conflict") {
				t.Fatalf("error = %v, want selector conflict", err)
			}
		})
	}
}

func TestApplyRuntimeSelectionArgumentsPreservesIndependentRawSelection(t *testing.T) {
	tests := []struct {
		name      string
		selection Runtime
		args      []string
		want      []string
	}{
		{
			name: "typed codex model with raw effort", selection: Runtime{Type: "codex", Model: "typed"},
			args: []string{"-c", "model_reasoning_effort=low"},
			want: []string{"-c", "model_reasoning_effort=low", "--model", "typed"},
		},
		{
			name: "typed codex effort with raw model", selection: Runtime{Type: "codex", Effort: "high"},
			args: []string{"--config=model=raw"},
			want: []string{"--config=model=raw", "--config", "model_reasoning_effort=high"},
		},
		{
			name: "typed claude effort with raw model", selection: Runtime{Type: "claude", Effort: "high"},
			args: []string{"-mraw"}, want: []string{"-mraw", "--effort", "high"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ApplyRuntimeSelectionArguments(test.args, test.selection)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("args = %#v, want %#v", got, test.want)
			}
		})
	}
}
