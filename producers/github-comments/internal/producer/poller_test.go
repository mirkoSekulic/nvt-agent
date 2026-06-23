//nolint:goconst // Tests repeat repository literals to keep fixtures readable.
package producer

import (
	"context"
	"log/slog"
	"testing"
	"time"
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

func testPollerConfig(initialSince string) Config {
	return Config{
		CommandPrefixes: []string{defaultCommandPrefix},
		Repositories: []Repository{{
			Owner: "acme",
			Name:  "widget",
		}},
		InitialSince: initialSince,
	}
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
