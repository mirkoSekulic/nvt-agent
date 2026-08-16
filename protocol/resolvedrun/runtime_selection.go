package resolvedrun

import (
	"errors"
	"strings"
)

// ApplyRuntimeSelectionArguments appends trusted runtime selectors after
// rejecting raw arguments that would override or suppress them.
func ApplyRuntimeSelectionArguments(args []string, selection Runtime) ([]string, error) {
	if selection.Model == "" && selection.Effort == "" {
		return append([]string(nil), args...), nil
	}
	if selection.Type != "codex" && selection.Type != "claude" {
		return nil, errors.New("runtime selection is unsupported")
	}
	for index, arg := range args {
		if arg == "--" {
			return nil, errors.New("runtime args conflict with typed selection end-of-options boundary")
		}
		if selection.Model != "" && argumentSelectsModel(args, index, selection.Type) {
			return nil, errors.New("runtime args conflict with typed model")
		}
		if selection.Effort != "" && argumentSelectsEffort(args, index, selection.Type) {
			return nil, errors.New("runtime args conflict with typed effort")
		}
	}

	result := append([]string(nil), args...)
	switch selection.Type {
	case "codex":
		if selection.Model != "" {
			result = append(result, "--model", selection.Model)
		}
		if selection.Effort != "" {
			result = append(result, "--config", "model_reasoning_effort="+selection.Effort)
		}
	case "claude":
		if selection.Model != "" {
			result = append(result, "--model", selection.Model)
		}
		if selection.Effort != "" {
			result = append(result, "--effort", selection.Effort)
		}
	}
	return result, nil
}

func argumentSelectsModel(args []string, index int, runtimeType string) bool {
	arg := args[index]
	if arg == "--model" || strings.HasPrefix(arg, "--model=") ||
		(strings.HasPrefix(arg, "-m") && !strings.HasPrefix(arg, "--")) {
		return true
	}
	return runtimeType == "codex" && codexConfigKey(args, index) == "model"
}

func argumentSelectsEffort(args []string, index int, runtimeType string) bool {
	arg := args[index]
	if runtimeType == "claude" {
		return arg == "--effort" || strings.HasPrefix(arg, "--effort=")
	}
	return codexConfigKey(args, index) == "model_reasoning_effort"
}

func codexConfigKey(args []string, index int) string {
	arg := args[index]
	var assignment string
	switch {
	case arg == "--config" || arg == "-c":
		if index+1 >= len(args) {
			return ""
		}
		assignment = args[index+1]
	case strings.HasPrefix(arg, "--config="):
		assignment = strings.TrimPrefix(arg, "--config=")
	case strings.HasPrefix(arg, "-c") && !strings.HasPrefix(arg, "--"):
		assignment = strings.TrimPrefix(strings.TrimPrefix(arg, "-c"), "=")
	default:
		return ""
	}
	key, _, ok := strings.Cut(assignment, "=")
	if !ok {
		return ""
	}
	return strings.TrimSpace(key)
}
