//nolint:goconst // Tests repeat command text to keep cases self-contained.
package producer

import (
	"context"
	"encoding/json"
	"testing"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
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

func TestSubmitDefaultIssueScopeBlocksSecondCommandOnSameIssue(t *testing.T) {
	s := runtime.NewScheme()
	if err := scheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := nvtv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	client := ctrlfake.NewClientBuilder().WithScheme(s).Build()
	submitter := NewAgentRunSubmitter(client, Config{
		AgentRun: AgentRunConfig{
			Namespace:       "nvt",
			RuntimeImage:    "runtime:latest",
			RuntimeType:     "codex",
			RuntimeAutonomy: "trusted-local",
			WorkspaceMode:   "Ephemeral",
		},
	})
	repo := Repository{Owner: "acme", Name: "widget"}
	issue := GitHubIssue{Number: 7, Title: "broken"}
	firstCreated, firstKey, err := submitter.Submit(
		context.Background(),
		repo,
		issue,
		nil,
		GitHubIssueComment{ID: 101, Body: "/nvtagent pr create"},
		Command{Prefix: "/nvtagent"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !firstCreated {
		t.Fatal("expected first issue-scoped command to create an AgentRun")
	}
	secondCreated, secondKey, err := submitter.Submit(
		context.Background(),
		repo,
		issue,
		nil,
		GitHubIssueComment{ID: 202, Body: "/nvtagent pr create"},
		Command{Prefix: "/nvtagent"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if secondCreated {
		t.Fatal("expected issue-scoped second command on same issue to be blocked")
	}
	if firstKey != IdempotencyKey("acme", "widget", 7) || secondKey != firstKey {
		t.Fatalf("unexpected issue-scope keys: first=%q second=%q", firstKey, secondKey)
	}
}

func TestSubmitCommentScopeAllowsDistinctCommandsOnSameIssue(t *testing.T) {
	s := runtime.NewScheme()
	if err := scheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := nvtv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	client := ctrlfake.NewClientBuilder().WithScheme(s).Build()
	submitter := NewAgentRunSubmitter(client, Config{
		Idempotency: IdempotencyConfig{Scope: IdempotencyScopeComment},
		AgentRun: AgentRunConfig{
			Namespace:       "nvt",
			RuntimeImage:    "runtime:latest",
			RuntimeType:     "codex",
			RuntimeAutonomy: "trusted-local",
			WorkspaceMode:   "Ephemeral",
		},
	})
	repo := Repository{Owner: "acme", Name: "widget"}
	issue := GitHubIssue{Number: 7, Title: "broken"}
	firstCreated, firstKey, err := submitter.Submit(
		context.Background(),
		repo,
		issue,
		nil,
		GitHubIssueComment{ID: 101, Body: "/nvtagent pr create"},
		Command{Prefix: "/nvtagent"},
	)
	if err != nil {
		t.Fatal(err)
	}
	secondCreated, secondKey, err := submitter.Submit(
		context.Background(),
		repo,
		issue,
		nil,
		GitHubIssueComment{ID: 202, Body: "/nvtagent pr create"},
		Command{Prefix: "/nvtagent"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !firstCreated || !secondCreated {
		t.Fatalf("expected both comment-scoped commands to create AgentRuns, got first=%v second=%v", firstCreated, secondCreated)
	}
	if firstKey != CommentIdempotencyKey("acme", "widget", 7, 101) {
		t.Fatalf("first key = %q", firstKey)
	}
	if secondKey != CommentIdempotencyKey("acme", "widget", 7, 202) {
		t.Fatalf("second key = %q", secondKey)
	}
	if firstKey == secondKey {
		t.Fatalf("comment-scoped keys should be distinct: %q", firstKey)
	}
	firstRun := getAgentRun(t, client, "nvt", CommentAgentRunName("acme", "widget", 7, 101))
	secondRun := getAgentRun(t, client, "nvt", CommentAgentRunName("acme", "widget", 7, 202))
	if firstRun.Name == secondRun.Name {
		t.Fatalf("comment-scoped AgentRun names should be distinct: %q", firstRun.Name)
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

func TestBuildAgentRunSetsAccessMetadataAnnotations(t *testing.T) {
	run := buildTestAgentRun(t, Config{
		AgentRun: AgentRunConfig{
			Namespace:       "nvt",
			RuntimeImage:    "runtime:latest",
			RuntimeType:     "codex",
			RuntimeAutonomy: "trusted-local",
			WorkspaceMode:   "Ephemeral",
		},
	})
	if run.Annotations[AccessKeyAnnotation] != run.Name {
		t.Fatalf("access key = %q, want AgentRun name %q", run.Annotations[AccessKeyAnnotation], run.Name)
	}
	if run.Annotations[DisplayNameAnnotation] != "Issue #7 - PR create" {
		t.Fatalf("display name = %q", run.Annotations[DisplayNameAnnotation])
	}
	if run.Annotations[RequestedByAnnotation] != "alice" {
		t.Fatalf("requested by = %q", run.Annotations[RequestedByAnnotation])
	}
	if run.Annotations[AccessPortAnnotation] != "4090" {
		t.Fatalf("access port = %q", run.Annotations[AccessPortAnnotation])
	}
}

func TestBuildAgentRunSetsTTL(t *testing.T) {
	activeDeadline := int64(14400)
	completedTTL := int64(300)
	failedTTL := int64(3600)
	runRetention := int64(2592000)
	run := buildTestAgentRun(t, Config{
		AgentRun: AgentRunConfig{
			Namespace:       "nvt",
			RuntimeImage:    "runtime:latest",
			RuntimeType:     "codex",
			RuntimeAutonomy: "trusted-local",
			WorkspaceMode:   "Ephemeral",
			TTL: AgentRunTTL{
				ActiveDeadlineSeconds: &activeDeadline,
				CompletedTTLSeconds:   &completedTTL,
				FailedTTLSeconds:      &failedTTL,
				RunRetentionSeconds:   &runRetention,
			},
		},
	})
	if run.Spec.TTL == nil {
		t.Fatal("expected ttl")
	}
	if *run.Spec.TTL.ActiveDeadlineSeconds != activeDeadline {
		t.Fatalf("activeDeadlineSeconds = %d, want %d", *run.Spec.TTL.ActiveDeadlineSeconds, activeDeadline)
	}
	if *run.Spec.TTL.CompletedTTLSeconds != completedTTL {
		t.Fatalf("completedTTLSeconds = %d, want %d", *run.Spec.TTL.CompletedTTLSeconds, completedTTL)
	}
	if *run.Spec.TTL.FailedTTLSeconds != failedTTL {
		t.Fatalf("failedTTLSeconds = %d, want %d", *run.Spec.TTL.FailedTTLSeconds, failedTTL)
	}
	if *run.Spec.TTL.RunRetentionSeconds != runRetention {
		t.Fatalf("runRetentionSeconds = %d, want %d", *run.Spec.TTL.RunRetentionSeconds, runRetention)
	}
}

func TestBuildAgentRunOmitsEmptyTTL(t *testing.T) {
	run := buildTestAgentRun(t, Config{
		AgentRun: AgentRunConfig{
			Namespace:       "nvt",
			RuntimeImage:    "runtime:latest",
			RuntimeType:     "codex",
			RuntimeAutonomy: "trusted-local",
			WorkspaceMode:   "Ephemeral",
		},
	})
	if run.Spec.TTL != nil {
		t.Fatalf("ttl = %#v, want nil", run.Spec.TTL)
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
		GitHubIssueComment{ID: 101, Body: "/nvtagent pr create", User: GitHubUser{Login: "alice"}},
		Command{Prefix: "/nvtagent"},
		submitter.agentRunIdentity(
			Repository{Owner: "acme", Name: "widget"},
			GitHubIssue{Number: 7, Title: "broken"},
			GitHubIssueComment{ID: 101},
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func getAgentRun(t *testing.T, client ctrlclient.Client, namespace, name string) *nvtv1alpha1.AgentRun {
	t.Helper()
	var run nvtv1alpha1.AgentRun
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: namespace, Name: name}, &run); err != nil {
		t.Fatal(err)
	}
	return &run
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
