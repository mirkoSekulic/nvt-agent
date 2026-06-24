//nolint:goconst // Tests repeat repository literals to keep fixtures readable.
package producer

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestPollerDefaultsFirstRunSinceToStartupTime(t *testing.T) {
	startedAt := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	github := &fakeGitHubClient{}
	poller := NewPoller(testPollerConfig(""), github, AgentRunSubmitter{}, nil, slog.Default())
	poller.startedAt = startedAt

	if err := poller.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(github.listUpdatedSince) != 1 {
		t.Fatalf("expected one poll, got %d", len(github.listUpdatedSince))
	}
	if github.listUpdatedSince[0] == nil {
		t.Fatal("expected first poll to use a since cursor")
	}
	if !github.listUpdatedSince[0].Equal(startedAt) {
		t.Fatalf("got since %s want %s", github.listUpdatedSince[0], startedAt)
	}
}

func TestPollerInitialSinceOverridesStartupTime(t *testing.T) {
	initialSince := "2026-06-01T00:00:00Z"
	github := &fakeGitHubClient{}
	poller := NewPoller(testPollerConfig(initialSince), github, AgentRunSubmitter{}, nil, slog.Default())
	poller.startedAt = time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)

	if err := poller.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := github.listUpdatedSince[0]
	want, err := time.Parse(time.RFC3339, initialSince)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !got.Equal(want) {
		t.Fatalf("got since %v want %s", got, want)
	}
}

func TestPollerUsesPersistedCursorBeforeInitialSince(t *testing.T) {
	storedCursor := time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)
	state := newMemoryStateStore()
	if err := state.SetRepoCursor(context.Background(), "acme/widget", storedCursor); err != nil {
		t.Fatal(err)
	}
	github := &fakeGitHubClient{}
	poller := NewPoller(testPollerConfig("2026-06-01T00:00:00Z"), github, AgentRunSubmitter{}, state, slog.Default())

	if err := poller.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := github.listUpdatedSince[0]
	if got == nil || !got.Equal(storedCursor) {
		t.Fatalf("got since %v want persisted cursor %s", got, storedCursor)
	}
}

func TestPollerStoresMaxUpdatedCursor(t *testing.T) {
	state := newMemoryStateStore()
	first := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	second := time.Date(2026, 6, 23, 12, 5, 0, 0, time.UTC)
	github := &fakeGitHubClient{
		updatedComments: []GitHubIssueComment{
			{ID: 1, Body: "ignored", UpdatedAt: second},
			{ID: 2, Body: "ignored", UpdatedAt: first},
		},
	}
	poller := NewPoller(testPollerConfig(""), github, AgentRunSubmitter{}, state, slog.Default())
	poller.now = func() time.Time {
		return time.Date(2026, 6, 23, 11, 59, 0, 0, time.UTC)
	}

	if err := poller.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, found, err := state.GetRepoCursor(context.Background(), "acme/widget")
	if err != nil {
		t.Fatal(err)
	}
	if !found || !got.Equal(second) {
		t.Fatalf("got stored cursor %v want %s", got, second)
	}
}

func TestPollerStoresPollStartCursorWhenNoCommentsReturned(t *testing.T) {
	state := newMemoryStateStore()
	pollStartedAt := time.Date(2026, 6, 23, 12, 10, 0, 0, time.UTC)
	github := &fakeGitHubClient{}
	poller := NewPoller(testPollerConfig(""), github, AgentRunSubmitter{}, state, slog.Default())
	poller.now = func() time.Time {
		return pollStartedAt
	}

	if err := poller.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, found, err := state.GetRepoCursor(context.Background(), "acme/widget")
	if err != nil {
		t.Fatal(err)
	}
	if !found || !got.Equal(pollStartedAt) {
		t.Fatalf("got stored cursor %v want poll start %s", got, pollStartedAt)
	}
}

func TestPollerReopenedStoreUsesEmptyPollCursorInsteadOfStartupTime(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	firstStore, err := OpenSQLiteStateStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	pollStartedAt := time.Date(2026, 6, 23, 12, 10, 0, 0, time.UTC)
	firstGitHub := &fakeGitHubClient{}
	firstPoller := NewPoller(testPollerConfig(""), firstGitHub, AgentRunSubmitter{}, firstStore, slog.Default())
	firstPoller.startedAt = time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	firstPoller.now = func() time.Time {
		return pollStartedAt
	}
	pollErr := firstPoller.PollOnce(ctx)
	if pollErr != nil {
		t.Fatal(pollErr)
	}
	closeErr := firstStore.Close()
	if closeErr != nil {
		t.Fatal(closeErr)
	}

	reopened, err := OpenSQLiteStateStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	secondGitHub := &fakeGitHubClient{}
	secondPoller := NewPoller(testPollerConfig(""), secondGitHub, AgentRunSubmitter{}, reopened, slog.Default())
	secondPoller.startedAt = time.Date(2026, 6, 23, 12, 15, 0, 0, time.UTC)

	if err := secondPoller.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	got := secondGitHub.listUpdatedSince[0]
	if got == nil || !got.Equal(pollStartedAt) {
		t.Fatalf("got since %v want persisted empty-poll cursor %s", got, pollStartedAt)
	}
}

func TestPollerSkipsPullRequestIssueComments(t *testing.T) {
	github := &fakeGitHubClient{
		updatedComments: []GitHubIssueComment{{
			ID:       123,
			Body:     "/nvtagent pr create",
			IssueURL: "https://api.github.com/repos/acme/widget/issues/42",
			User:     GitHubUser{Login: "octo"},
		}},
		issue: GitHubIssue{
			Number:      42,
			Title:       "Existing PR",
			PullRequest: &GitHubPullRequest{URL: "https://api.github.com/repos/acme/widget/pulls/42"},
		},
	}
	poller := NewPoller(testPollerConfig(""), github, AgentRunSubmitter{}, nil, slog.Default())

	if err := poller.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if github.listIssueCommentsCalls != 0 {
		t.Fatalf("expected PR-backed issue to skip comment fetch, got %d calls", github.listIssueCommentsCalls)
	}
}

func TestPollerDefaultAllowedAuthorsAcceptsAnyCommandAuthor(t *testing.T) {
	cfg := testPollerConfig("")
	cfg.AllowedAuthors = nil
	if err := cfg.ApplyDefaultsAndValidate(); err != nil {
		t.Fatal(err)
	}
	created := pollCommandAndCountAgentRuns(t, cfg, "octo")
	if created != 1 {
		t.Fatalf("got %d AgentRuns, want 1", created)
	}
}

func TestPollerAllowedAuthorsAcceptsListedAuthor(t *testing.T) {
	cfg := testPollerConfig("")
	cfg.AllowedAuthors = []string{"octo"}
	if err := cfg.ApplyDefaultsAndValidate(); err != nil {
		t.Fatal(err)
	}
	created := pollCommandAndCountAgentRuns(t, cfg, "octo")
	if created != 1 {
		t.Fatalf("got %d AgentRuns, want 1", created)
	}
}

func TestPollerAllowedAuthorsRejectsUnlistedAuthor(t *testing.T) {
	cfg := testPollerConfig("")
	cfg.AllowedAuthors = []string{"maintainer"}
	if err := cfg.ApplyDefaultsAndValidate(); err != nil {
		t.Fatal(err)
	}
	created := pollCommandAndCountAgentRuns(t, cfg, "octo")
	if created != 0 {
		t.Fatalf("got %d AgentRuns, want 0", created)
	}
}

func TestPollerAllowedAuthorsWildcardAcceptsAnyAuthor(t *testing.T) {
	cfg := testPollerConfig("")
	cfg.AllowedAuthors = []string{"maintainer", "*"}
	if err := cfg.ApplyDefaultsAndValidate(); err != nil {
		t.Fatal(err)
	}
	created := pollCommandAndCountAgentRuns(t, cfg, "random-user")
	if created != 1 {
		t.Fatalf("got %d AgentRuns, want 1", created)
	}
}

func testPollerConfig(initialSince string) Config {
	return Config{
		CommandPrefixes: []string{defaultCommandPrefix},
		Repositories: []Repository{{
			Owner: "acme",
			Name:  "widget",
		}},
		InitialSince: initialSince,
		GitHubApp: GitHubAppConfig{
			AppID:          123,
			InstallationID: 456,
			PrivateKey:     "unused",
		},
		AgentRun: AgentRunConfig{
			Namespace:       "nvt",
			RuntimeImage:    "runtime:latest",
			RuntimeType:     defaultRuntimeType,
			RuntimeAutonomy: defaultAutonomy,
			WorkspaceMode:   defaultWorkspaceMode,
		},
	}
}

func pollCommandAndCountAgentRuns(t *testing.T, cfg Config, author string) int {
	t.Helper()
	ctx := context.Background()
	k8sClient := newFakeAgentRunClient(t)
	submitter := NewAgentRunSubmitter(k8sClient, cfg)
	github := &fakeGitHubClient{
		updatedComments: []GitHubIssueComment{{
			ID:        123,
			Body:      "/nvtagent pr create\nplease fix",
			IssueURL:  "https://api.github.com/repos/acme/widget/issues/42",
			UpdatedAt: time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC),
			User:      GitHubUser{Login: author},
		}},
		issue: GitHubIssue{
			Number:  42,
			Title:   "Broken widget",
			Body:    "Details",
			URL:     "https://api.github.com/repos/acme/widget/issues/42",
			HTMLURL: "https://github.com/acme/widget/issues/42",
		},
	}
	poller := NewPoller(cfg, github, submitter, newMemoryStateStore(), slog.Default())
	poller.now = func() time.Time {
		return time.Date(2026, 6, 23, 11, 59, 0, 0, time.UTC)
	}
	if err := poller.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var runs nvtv1alpha1.AgentRunList
	if err := k8sClient.List(ctx, &runs, ctrlclient.InNamespace(cfg.AgentRun.Namespace)); err != nil {
		t.Fatal(err)
	}
	return len(runs.Items)
}

func newFakeAgentRunClient(t *testing.T) ctrlclient.Client {
	t.Helper()
	s := runtime.NewScheme()
	if err := scheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := nvtv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return ctrlfake.NewClientBuilder().WithScheme(s).Build()
}

type fakeGitHubClient struct {
	updatedComments        []GitHubIssueComment
	issue                  GitHubIssue
	issueComments          []GitHubIssueComment
	listUpdatedSince       []*time.Time
	listIssueCommentsCalls int
}

func (f *fakeGitHubClient) ListUpdatedIssueComments(
	_ context.Context,
	_ Repository,
	since *time.Time,
) ([]GitHubIssueComment, error) {
	f.listUpdatedSince = append(f.listUpdatedSince, since)
	return f.updatedComments, nil
}

func (f *fakeGitHubClient) GetIssue(_ context.Context, _ Repository, _ int) (GitHubIssue, error) {
	return f.issue, nil
}

func (f *fakeGitHubClient) ListIssueComments(
	_ context.Context,
	_ Repository,
	_ int,
) ([]GitHubIssueComment, error) {
	f.listIssueCommentsCalls++
	return f.issueComments, nil
}
