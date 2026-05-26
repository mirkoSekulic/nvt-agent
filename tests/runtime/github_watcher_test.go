package runtime_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGithubWatchRegisterPersistsDynamicRegistration(t *testing.T) {
	f := newFixture(t)
	config := f.writePluginConfig("github-watcher.yaml", `
default-provider: fork-app
`)
	env := []string{"NVT_PLUGIN_CONFIG=" + config}

	f.runWithEnv(
		githubWatchBin(f.root),
		true,
		env,
		"register",
		"--repo", "my-user/my-repo",
		"--number", "123",
		"--label", "frontend",
		"--label", "urgent",
	)

	registryPath := filepath.Join(f.state, "plugins", "github-watcher", "registry.json")
	var registry map[string][]map[string]any
	decodeJSONFile(t, registryPath, &registry)
	if len(registry["prs"]) != 1 {
		t.Fatalf("expected one registration, got %#v", registry)
	}
	pr := registry["prs"][0]
	if pr["repo"] != "my-user/my-repo" || pr["provider"] != "fork-app" || pr["number"].(float64) != 123 {
		t.Fatalf("unexpected registration: %#v", pr)
	}
	labels, _ := pr["labels"].([]any)
	if len(labels) != 2 || labels[0] != "frontend" || labels[1] != "urgent" {
		t.Fatalf("unexpected labels: %#v", pr["labels"])
	}

	output := f.runWithEnv(githubWatchBin(f.root), true, env, "list")
	if !strings.Contains(output, "my-user/my-repo#123") || !strings.Contains(output, "labels=frontend,urgent") {
		t.Fatalf("unexpected list output:\n%s", output)
	}
}

func TestGithubWatchRegisterReplacesExistingRegistration(t *testing.T) {
	f := newFixture(t)
	config := f.writePluginConfig("github-watcher.yaml", "default-provider: fork-app\n")
	env := []string{"NVT_PLUGIN_CONFIG=" + config}

	f.runWithEnv(githubWatchBin(f.root), true, env, "register", "--repo", "my-user/my-repo", "--number", "123", "--label", "first")
	f.runWithEnv(githubWatchBin(f.root), true, env, "register", "--repo", "my-user/my-repo", "--number", "123", "--label", "second")

	data, err := os.ReadFile(filepath.Join(f.state, "plugins", "github-watcher", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var registry struct {
		PRs []map[string]any `json:"prs"`
	}
	if err := json.Unmarshal(data, &registry); err != nil {
		t.Fatal(err)
	}
	if len(registry.PRs) != 1 {
		t.Fatalf("expected replacement, got %s", data)
	}
	labels := registry.PRs[0]["labels"].([]any)
	if len(labels) != 1 || labels[0] != "second" {
		t.Fatalf("expected second label after replacement, got %s", data)
	}
}
