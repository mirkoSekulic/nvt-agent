//nolint:goconst // Tests repeat command text to keep cases self-contained.
package producer

import (
	"context"
	"encoding/json"
	"testing"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestSubmitBlocksExistingIdempotencyKeyRegardlessOfPhase(t *testing.T) {
	s := runtime.NewScheme()
	if err := scheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := nvtv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	key := IdempotencyKey("acme", "widget", 7)
	existing := &nvtv1alpha1.AgentRun{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "nvt",
			Name:      "existing",
			Annotations: map[string]string{
				IdempotencyAnnotation: key,
			},
		},
		Status: nvtv1alpha1.AgentRunStatus{Phase: nvtv1alpha1.AgentRunPhaseCompleted},
	}
	client := ctrlfake.NewClientBuilder().WithScheme(s).WithObjects(existing).Build()
	submitter := NewAgentRunSubmitter(client, Config{
		AgentRun: AgentRunConfig{
			Namespace:       "nvt",
			RuntimeImage:    "runtime:latest",
			RuntimeType:     "codex",
			RuntimeAutonomy: "trusted-local",
			WorkspaceMode:   "Ephemeral",
		},
	})
	created, gotKey, err := submitter.Submit(
		context.Background(),
		Repository{Owner: "acme", Name: "widget"},
		GitHubIssue{
			Number: 7,
			Title:  "broken",
		},
		nil,
		GitHubIssueComment{Body: "/nvtagent pr create"},
		Command{Prefix: "/nvtagent"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("expected duplicate to block creation")
	}
	if gotKey != key {
		t.Fatalf("got key %q want %q", gotKey, key)
	}
}

func TestBuildAgentRunSetsGitHubPRLifecycle(t *testing.T) {
	run := buildTestAgentRun(t, Config{
		OperatorCallbackBaseURL: "http://operator.test",
		AgentRun: AgentRunConfig{
			Namespace:       "nvt",
			RuntimeImage:    "runtime:latest",
			RuntimeType:     "codex",
			RuntimeAutonomy: "trusted-local",
			WorkspaceMode:   "Ephemeral",
		},
	})
	if run.Spec.Lifecycle == nil {
		t.Fatal("expected lifecycle")
	}
	wantCompleteOn := []string{"plugin.github.pr.merged", "plugin.github.pr.closed"}
	if !stringSlicesEqual(run.Spec.Lifecycle.CompleteOn, wantCompleteOn) {
		t.Fatalf("completeOn = %#v, want %#v", run.Spec.Lifecycle.CompleteOn, wantCompleteOn)
	}
	if len(run.Spec.Lifecycle.FailOn) != 0 {
		t.Fatalf("failOn = %#v, want empty", run.Spec.Lifecycle.FailOn)
	}
}

func TestBuildAgentRunInjectsEventWebhookPlugin(t *testing.T) {
	run := buildTestAgentRun(t, Config{
		OperatorCallbackBaseURL: "http://operator.test/",
		AgentRun: AgentRunConfig{
			Namespace:       "nvt",
			RuntimeImage:    "runtime:latest",
			RuntimeType:     "codex",
			RuntimeAutonomy: "trusted-local",
			WorkspaceMode:   "Ephemeral",
		},
		AgentConfig: map[string]any{
			"plugins": []any{
				map[string]any{"name": "checkout-repos", "source": "builtin"},
			},
		},
	})
	config := decodeAgentConfig(t, run)
	plugins := configPlugins(t, config)
	if len(plugins) != 2 {
		t.Fatalf("plugins = %#v, want original plus event-webhook", plugins)
	}
	firstPlugin, ok := plugins[0].(map[string]any)
	if !ok || firstPlugin["name"] != "checkout-repos" {
		t.Fatalf("existing plugin was not preserved first: %#v", plugins)
	}
	webhook := findPlugin(t, plugins, "event-webhook")
	if webhook["source"] != "builtin" || webhook["when"] != "after-agent" || webhook["restart"] != "always" {
		t.Fatalf("unexpected event-webhook metadata: %#v", webhook)
	}
	webhookConfig := mapValue(t, webhook, "config")
	wantURL := "http://operator.test/v1/agentruns/nvt/" + run.Name + "/events"
	if webhookConfig["url"] != wantURL {
		t.Fatalf("event-webhook url = %q, want %q", webhookConfig["url"], wantURL)
	}
	auth := mapValue(t, webhookConfig, "auth")
	if auth["type"] != "bearer-env" || auth["env"] != "NVT_OPERATOR_CALLBACK_TOKEN" {
		t.Fatalf("unexpected auth config: %#v", auth)
	}
	filters := listValue(t, webhookConfig, "filters")
	if len(filters) != 1 || filters[0] != "plugin.github.pr." {
		t.Fatalf("filters = %#v, want plugin.github.pr.", filters)
	}
}

func TestBuildAgentRunDoesNotDuplicateExistingEventWebhook(t *testing.T) {
	run := buildTestAgentRun(t, Config{
		OperatorCallbackBaseURL: "http://operator.test",
		AgentRun: AgentRunConfig{
			Namespace:       "nvt",
			RuntimeImage:    "runtime:latest",
			RuntimeType:     "codex",
			RuntimeAutonomy: "trusted-local",
			WorkspaceMode:   "Ephemeral",
		},
		AgentConfig: map[string]any{
			"plugins": []any{
				map[string]any{"name": "event-webhook", "source": "custom", "config": map[string]any{"url": "http://custom.test"}},
				map[string]any{"name": "github-watcher", "source": "builtin"},
			},
		},
	})
	plugins := configPlugins(t, decodeAgentConfig(t, run))
	if countPlugins(plugins, "event-webhook") != 1 {
		t.Fatalf("event-webhook plugin count = %d, want 1: %#v", countPlugins(plugins, "event-webhook"), plugins)
	}
	if findPlugin(t, plugins, "event-webhook")["source"] != "custom" {
		t.Fatalf("user-provided event-webhook was not preserved: %#v", plugins)
	}
	if findPlugin(t, plugins, "github-watcher")["source"] != "builtin" {
		t.Fatalf("unrelated plugin was not preserved: %#v", plugins)
	}
}

func TestBuildAgentRunEventWebhookInjectionIsDeterministic(t *testing.T) {
	cfg := Config{
		OperatorCallbackBaseURL: "http://operator.test",
		AgentRun: AgentRunConfig{
			Namespace:       "nvt",
			RuntimeImage:    "runtime:latest",
			RuntimeType:     "codex",
			RuntimeAutonomy: "trusted-local",
			WorkspaceMode:   "Ephemeral",
		},
		AgentConfig: map[string]any{
			"runtime": map[string]any{"command": "codex"},
			"plugins": []any{
				map[string]any{"name": "checkout-repos", "source": "builtin"},
			},
		},
	}
	first := buildTestAgentRun(t, cfg)
	second := buildTestAgentRun(t, cfg)
	if string(first.Spec.Agent.Config.Raw) != string(second.Spec.Agent.Config.Raw) {
		t.Fatalf("agent config injection is not deterministic:\nfirst:  %s\nsecond: %s", first.Spec.Agent.Config.Raw, second.Spec.Agent.Config.Raw)
	}
}

func buildTestAgentRun(t *testing.T, cfg Config) *nvtv1alpha1.AgentRun {
	t.Helper()
	submitter := NewAgentRunSubmitter(nil, cfg)
	run, err := submitter.buildAgentRun(
		Repository{Owner: "acme", Name: "widget"},
		GitHubIssue{Number: 7, Title: "broken"},
		nil,
		GitHubIssueComment{Body: "/nvtagent pr create", User: GitHubUser{Login: "alice"}},
		Command{Prefix: "/nvtagent"},
		IdempotencyKey("acme", "widget", 7),
	)
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func decodeAgentConfig(t *testing.T, run *nvtv1alpha1.AgentRun) map[string]any {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal(run.Spec.Agent.Config.Raw, &config); err != nil {
		t.Fatal(err)
	}
	return config
}

func configPlugins(t *testing.T, config map[string]any) []any {
	t.Helper()
	plugins, ok := config["plugins"].([]any)
	if !ok {
		t.Fatalf("plugins = %#v, want list", config["plugins"])
	}
	return plugins
}

func findPlugin(t *testing.T, plugins []any, name string) map[string]any {
	t.Helper()
	for _, rawPlugin := range plugins {
		plugin, ok := rawPlugin.(map[string]any)
		if !ok {
			continue
		}
		if plugin["name"] == name {
			return plugin
		}
	}
	t.Fatalf("missing plugin %q in %#v", name, plugins)
	return nil
}

func countPlugins(plugins []any, name string) int {
	count := 0
	for _, rawPlugin := range plugins {
		plugin, ok := rawPlugin.(map[string]any)
		if ok && plugin["name"] == name {
			count++
		}
	}
	return count
}

func mapValue(t *testing.T, values map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := values[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want map", key, values[key])
	}
	return value
}

func listValue(t *testing.T, values map[string]any, key string) []any {
	t.Helper()
	value, ok := values[key].([]any)
	if !ok {
		t.Fatalf("%s = %#v, want list", key, values[key])
	}
	return value
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
