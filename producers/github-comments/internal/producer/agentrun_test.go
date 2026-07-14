//nolint:goconst // Tests repeat command text to keep cases self-contained.
package producer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
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

func TestSubmitScheduleAdmissionPostsAdmissionRequest(t *testing.T) {
	var gotRequest scheduleAdmissionRequest
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/schedules/nvt/default/admissions" {
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
		if err := json.NewDecoder(request.Body).Decode(&gotRequest); err != nil {
			t.Fatal(err)
		}
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write([]byte(`{"scheduled":true,"agentRun":{"namespace":"nvt","name":"run-1"}}`))
	}))
	defer server.Close()

	submitter := NewAgentRunSubmitterWithHTTP(nil, server.Client(), Config{
		Submission: SubmissionConfig{
			Mode:             SubmissionModeScheduleAdmission,
			AdmissionBaseURL: server.URL,
			ScheduleName:     "default",
		},
		AgentRun: AgentRunConfig{
			Namespace:       "nvt",
			RuntimeImage:    "runtime:latest",
			RuntimeType:     "codex",
			RuntimeAutonomy: "trusted-local",
			WorkspaceMode:   "Ephemeral",
		},
	})
	created, key, err := submitter.Submit(
		context.Background(),
		Repository{Owner: "acme", Name: "widget"},
		GitHubIssue{Number: 7, Title: "Broken widget", HTMLURL: "https://github.test/acme/widget/issues/7"},
		nil,
		GitHubIssueComment{ID: 101, Body: "/nvtagent pr create", User: GitHubUser{Login: "alice"}},
		Command{Prefix: "/nvtagent"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("expected scheduled admission to be created")
	}
	if gotRequest.Work.ID != key || gotRequest.Work.Title != "Broken widget" ||
		gotRequest.Work.URL != "https://github.test/acme/widget/issues/7" {
		t.Fatalf("unexpected work payload: %#v key=%q", gotRequest.Work, key)
	}
	if gotRequest.AgentRun.Name == "" || gotRequest.AgentRun.Spec.Prompt == nil {
		t.Fatalf("expected AgentRun payload with name and prompt, got %#v", gotRequest.AgentRun)
	}
	if gotRequest.AgentRun.Annotations[RequestedByAnnotation] != "alice" {
		t.Fatalf("requested-by annotation = %#v", gotRequest.AgentRun.Annotations)
	}
	if _, ok := gotRequest.AgentRun.Annotations[AccessKeyAnnotation]; ok {
		t.Fatalf("producer should not send access key annotation: %#v", gotRequest.AgentRun.Annotations)
	}
}

func TestSubmitProfiledScheduleAdmissionSendsOnlyWorkPrincipalAndPrompt(t *testing.T) {
	tokenFile := writeTestAdmissionToken(t, "first.header.signature")
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if authorization := request.Header.Get("Authorization"); authorization != "Bearer first.header.signature" {
			t.Fatalf("Authorization = %q", authorization)
		}
		if err := json.NewDecoder(request.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write([]byte(`{"scheduled":true}`))
	}))
	defer server.Close()

	submitter := profiledAdmissionSubmitter(server.Client(), server.URL, tokenFile)
	created, _, err := submitter.Submit(
		context.Background(),
		Repository{Owner: "acme", Name: "widget"},
		GitHubIssue{Number: 7, Title: "Broken widget", HTMLURL: "https://github.test/acme/widget/issues/7"},
		nil,
		GitHubIssueComment{ID: 101, Body: "/nvtagent fix it", User: GitHubUser{Login: "alice", ID: 424242}},
		Command{Prefix: "/nvtagent", AdditionalInstructions: "fix it"},
	)
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	if !reflect.DeepEqual(sortedMapKeys(got), []string{"input", "work"}) {
		t.Fatalf("top-level payload keys = %v, payload=%#v", sortedMapKeys(got), got)
	}
	work := mapValue(t, got, "work")
	if !reflect.DeepEqual(sortedMapKeys(work), []string{"id", "principal", "repository", "title", "url"}) {
		t.Fatalf("work keys = %v, work=%#v", sortedMapKeys(work), work)
	}
	if work["repository"] != "acme/widget" {
		t.Fatalf("repository = %#v", work["repository"])
	}
	principal := mapValue(t, work, "principal")
	wantPrincipal := map[string]any{
		"issuer": "https://github.com", "subject": "424242", "displayName": "alice",
	}
	if !reflect.DeepEqual(principal, wantPrincipal) {
		t.Fatalf("principal = %#v, want %#v", principal, wantPrincipal)
	}
	input := mapValue(t, got, "input")
	if !reflect.DeepEqual(sortedMapKeys(input), []string{"prompt"}) || !strings.Contains(input["prompt"].(string), "fix it") {
		t.Fatalf("input = %#v", input)
	}
	for _, forbidden := range []string{"agentRun", "profile", "provider", "broker", "grant", "proxy", "egress", "image", "tools", "plugins", "runtime"} {
		if strings.Contains(string(mustJSON(t, got)), `"`+forbidden+`"`) {
			t.Fatalf("profiled payload contains forbidden field %q: %#v", forbidden, got)
		}
	}
}

func TestProfiledAdmissionSubjectDoesNotDependOnLoginAndTokenRotates(t *testing.T) {
	tokenFile := writeTestAdmissionToken(t, "one.header.signature")
	var authorizations []string
	var subjects []string
	var displayNames []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		authorizations = append(authorizations, request.Header.Get("Authorization"))
		var payload profiledScheduleAdmissionRequest
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		subjects = append(subjects, payload.Work.Principal.Subject)
		displayNames = append(displayNames, payload.Work.Principal.DisplayName)
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write([]byte(`{"scheduled":true}`))
	}))
	defer server.Close()
	submitter := profiledAdmissionSubmitter(server.Client(), server.URL, tokenFile)
	for index, login := range []string{"old-login", "new-login"} {
		if index == 1 {
			if err := os.WriteFile(tokenFile, []byte("two.header.signature\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		_, _, err := submitter.Submit(context.Background(), Repository{Owner: "acme", Name: "widget"},
			GitHubIssue{Number: 7 + index}, nil,
			GitHubIssueComment{ID: int64(101 + index), Body: "/nvtagent", User: GitHubUser{Login: login, ID: 99}},
			Command{Prefix: "/nvtagent"})
		if err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(subjects, []string{"99", "99"}) || !reflect.DeepEqual(displayNames, []string{"old-login", "new-login"}) {
		t.Fatalf("subjects=%v displayNames=%v", subjects, displayNames)
	}
	if !reflect.DeepEqual(authorizations, []string{"Bearer one.header.signature", "Bearer two.header.signature"}) {
		t.Fatalf("Authorization headers = %#v", authorizations)
	}
}

func TestProfiledAdmissionInvalidIdentityAndTokenFailBeforeHTTP(t *testing.T) {
	secret := "canary.header.secret"
	tokenFile := writeTestAdmissionToken(t, secret)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests++
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write([]byte(`{"scheduled":true}`))
	}))
	defer server.Close()

	cases := []struct {
		name      string
		authorID  int64
		tokenPath string
	}{
		{name: "missing author ID", tokenPath: tokenFile},
		{name: "negative author ID", authorID: -1, tokenPath: tokenFile},
		{name: "missing token", authorID: 1, tokenPath: filepath.Join(t.TempDir(), "missing")},
		{name: "unreadable token", authorID: 1, tokenPath: t.TempDir()},
		{name: "empty token", authorID: 1, tokenPath: writeTestAdmissionToken(t, "")},
		{name: "malformed token", authorID: 1, tokenPath: writeTestAdmissionToken(t, secret+" extra")},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			submitter := profiledAdmissionSubmitter(server.Client(), server.URL, test.tokenPath)
			_, _, err := submitter.Submit(context.Background(), Repository{Owner: "acme", Name: "widget"}, GitHubIssue{Number: 7}, nil,
				GitHubIssueComment{ID: 101, User: GitHubUser{Login: "alice", ID: test.authorID}}, Command{})
			if err == nil {
				t.Fatal("expected failure")
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), test.tokenPath) {
				t.Fatalf("error exposed token material or path: %v", err)
			}
		})
	}
	if requests != 0 {
		t.Fatalf("HTTP requests = %d, want 0", requests)
	}
}

func TestProfiledAdmissionNeverFallsBackToLegacy(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			tokenFile := writeTestAdmissionToken(t, "test.header.signature")
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				requests++
				var payload map[string]any
				if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				if _, exists := payload["agentRun"]; exists {
					t.Fatalf("profiled request fell back to AgentRun payload: %#v", payload)
				}
				response.WriteHeader(status)
				_, _ = response.Write([]byte(`{"scheduled":false,"reason":"rejected"}`))
			}))
			defer server.Close()
			submitter := profiledAdmissionSubmitter(server.Client(), server.URL, tokenFile)
			_, _, err := submitter.Submit(context.Background(), Repository{Owner: "acme", Name: "widget"}, GitHubIssue{Number: 7}, nil,
				GitHubIssueComment{ID: 101, User: GitHubUser{Login: "alice", ID: 42}}, Command{})
			if err == nil || requests != 1 {
				t.Fatalf("err=%v requests=%d, want one failed profiled request", err, requests)
			}
		})
	}
}

func TestSubmitScheduleAdmissionDuplicateWorkIsNoOpSuccess(t *testing.T) {
	submitter := scheduleAdmissionSubmitterForStatus(t, http.StatusAccepted, `{"scheduled":false,"reason":"duplicate-work"}`)
	created, key, err := submitter.Submit(
		context.Background(),
		Repository{Owner: "acme", Name: "widget"},
		GitHubIssue{Number: 7, Title: "Broken widget"},
		nil,
		GitHubIssueComment{ID: 101, Body: "/nvtagent pr create", User: GitHubUser{Login: "alice"}},
		Command{Prefix: "/nvtagent"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if created || key == "" {
		t.Fatalf("created=%v key=%q, want no-op success with key", created, key)
	}
}

func TestSubmitScheduleAdmissionMaxParallelismIsDeferred(t *testing.T) {
	submitter := scheduleAdmissionSubmitterForStatus(t, http.StatusTooManyRequests, `{"scheduled":false,"reason":"max-parallelism-reached"}`)
	created, key, err := submitter.Submit(
		context.Background(),
		Repository{Owner: "acme", Name: "widget"},
		GitHubIssue{Number: 7, Title: "Broken widget"},
		nil,
		GitHubIssueComment{ID: 101, Body: "/nvtagent pr create", User: GitHubUser{Login: "alice"}},
		Command{Prefix: "/nvtagent"},
	)
	if !errors.Is(err, ErrSubmissionDeferred) {
		t.Fatalf("err = %v, want ErrSubmissionDeferred", err)
	}
	if created || key == "" {
		t.Fatalf("created=%v key=%q, want deferred with key", created, key)
	}
}

func TestSubmitScheduleAdmissionSuspendedIsDeferred(t *testing.T) {
	submitter := scheduleAdmissionSubmitterForStatus(t, http.StatusAccepted, `{"scheduled":false,"reason":"schedule-suspended"}`)
	created, key, err := submitter.Submit(
		context.Background(),
		Repository{Owner: "acme", Name: "widget"},
		GitHubIssue{Number: 7, Title: "Broken widget"},
		nil,
		GitHubIssueComment{ID: 101, Body: "/nvtagent pr create", User: GitHubUser{Login: "alice"}},
		Command{Prefix: "/nvtagent"},
	)
	if !errors.Is(err, ErrSubmissionDeferred) {
		t.Fatalf("err = %v, want ErrSubmissionDeferred", err)
	}
	if created || key == "" {
		t.Fatalf("created=%v key=%q, want deferred with key", created, key)
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

func TestBuildAgentRunSetsRequesterAnnotation(t *testing.T) {
	run := buildTestAgentRun(t, Config{
		AgentRun: AgentRunConfig{
			Namespace:       "nvt",
			RuntimeImage:    "runtime:latest",
			RuntimeType:     "codex",
			RuntimeAutonomy: "trusted-local",
			WorkspaceMode:   "Ephemeral",
		},
	})
	if run.Annotations[RequestedByAnnotation] != "alice" {
		t.Fatalf("requested by = %q", run.Annotations[RequestedByAnnotation])
	}
	for _, annotation := range []string{AccessKeyAnnotation, DisplayNameAnnotation, SourceURLAnnotation, AccessPortAnnotation} {
		if _, ok := run.Annotations[annotation]; ok {
			t.Fatalf("producer should not set %s: %#v", annotation, run.Annotations)
		}
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

func scheduleAdmissionSubmitterForStatus(t *testing.T, status int, body string) AgentRunSubmitter {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(status)
		_, _ = response.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return NewAgentRunSubmitterWithHTTP(nil, server.Client(), Config{
		Submission: SubmissionConfig{
			Mode:             SubmissionModeScheduleAdmission,
			AdmissionBaseURL: server.URL,
			ScheduleName:     "default",
		},
		AgentRun: AgentRunConfig{
			Namespace:       "nvt",
			RuntimeImage:    "runtime:latest",
			RuntimeType:     "codex",
			RuntimeAutonomy: "trusted-local",
			WorkspaceMode:   "Ephemeral",
		},
	})
}

func profiledAdmissionSubmitter(httpClient *http.Client, baseURL, tokenFile string) AgentRunSubmitter {
	return NewAgentRunSubmitterWithHTTP(nil, httpClient, Config{
		Submission: SubmissionConfig{
			Mode:               SubmissionModeScheduleAdmission,
			AdmissionMode:      AdmissionModeProfiled,
			AdmissionBaseURL:   baseURL,
			AdmissionTokenFile: tokenFile,
			ScheduleNamespace:  "nvt",
			ScheduleName:       "default",
		},
	})
}

func writeTestAdmissionToken(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func sortedMapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
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
