package producer

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func epicPollerConfig() Config {
	cfg := testPollerConfig("")
	cfg.AllowedAuthors = []string{"*"}
	cfg.Epics = epicTestPolicy()
	cfg.Submission = SubmissionConfig{Mode: SubmissionModeScheduleAdmission, AdmissionMode: AdmissionModeProfiled}
	return cfg
}

func epicPollComment(action string, id int64) GitHubIssueComment {
	return GitHubIssueComment{ID: id, Body: "/nvtagent epic " + action, User: epicTestUser,
		IssueURL: "https://api.github.com/repos/acme/widget/issues/42", UpdatedAt: epicTestTime}
}

type epicCursorFailureStore struct{ *SQLiteStateStore }

func (s *epicCursorFailureStore) SetRepoCursor(context.Context, string, time.Time) error {
	return errors.New("injected cursor failure")
}

type epicCountingGitHub struct {
	*fakeGitHubClient
	issueReads int
}

func (g *epicCountingGitHub) GetIssue(ctx context.Context, repo Repository, number int) (GitHubIssue, error) {
	g.issueReads++
	return g.fakeGitHubClient.GetIssue(ctx, repo, number)
}

func TestEpicPollerDisabledAndUnauthorizedAreInert(t *testing.T) {
	for _, mode := range []string{"disabled", "wrong-id", "missing-id", "disallowed-login", "pull-request", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			store := openEpicTestStore(t, filepath.Join(t.TempDir(), "state.db"))
			cfg := epicPollerConfig()
			comment := epicPollComment("start", 1)
			github := &epicCountingGitHub{fakeGitHubClient: &fakeGitHubClient{issue: GitHubIssue{Number: 42}}}
			switch mode {
			case "disabled":
				cfg.Epics = EpicConfig{}
			case "wrong-id":
				comment.User.ID = 9999
			case "missing-id":
				comment.User.ID = 0
			case "disallowed-login":
				cfg.AllowedAuthors = []string{"someone-else"}
			case "pull-request":
				github.issue.PullRequest = &GitHubPullRequest{}
			case "malformed":
				comment.Body += "\nworkflow: evil"
			}
			github.updatedComments = []GitHubIssueComment{comment}
			poller := NewPoller(cfg, github, AgentRunSubmitter{}, store, nil)
			poller.now = func() time.Time { return epicTestTime }
			if err := poller.PollOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			records, err := store.ListEpics(context.Background(), epicTestRepo)
			if err != nil || len(records) != 0 || github.createIssueCommentCalls != 0 || len(github.reactions) != 0 {
				t.Fatalf("inert command had effects: %+v %v", records, err)
			}
			if mode != "pull-request" && github.issueReads != 0 {
				t.Fatal("inert command fetched issue")
			}
			cursor, found, err := store.GetRepoCursor(context.Background(), "acme/widget")
			if err != nil || !found || !cursor.Equal(epicTestTime) {
				t.Fatalf("changed cursor behavior: %v %v %v", cursor, found, err)
			}
		})
	}
}

func TestEpicPollerRestartAfterCursorFailure(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	store := openEpicTestStore(t, path)
	github := &fakeGitHubClient{issue: GitHubIssue{Number: 42, Body: "workflow: evil\nchildren: [999]"}, updatedComments: []GitHubIssueComment{
		epicPollComment("start", 1), epicPollComment("pause", 2), epicPollComment("retry", 3),
	}}
	poller := NewPoller(epicPollerConfig(), github, AgentRunSubmitter{}, &epicCursorFailureStore{store}, nil)
	poller.now = func() time.Time { return epicTestTime }
	if err := poller.PollOnce(ctx); err == nil {
		t.Fatal("expected cursor failure")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openEpicTestStore(t, path)
	poller = NewPoller(epicPollerConfig(), github, AgentRunSubmitter{}, store, nil)
	poller.now = func() time.Time { return epicTestTime }
	if err := poller.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	records, err := store.ListEpics(ctx, epicTestRepo)
	if err != nil || len(records) != 1 || records[0].Generation != 2 || records[0].State != EpicPending || records[0].Workflow != "implement-pr" {
		t.Fatalf("restart: %+v %v", records, err)
	}
	if github.createIssueCommentCalls != 0 || len(github.reactions) != 0 {
		t.Fatal("control command entered child submission/display path")
	}
	// A restart with no source comments still recovers the same reconciliation input.
	github.updatedComments = nil
	if err := poller.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.ListEpics(ctx, epicTestRepo)
	if err != nil || len(recovered) != 1 || recovered[0].Generation != 2 {
		t.Fatalf("comment-free recovery: %+v %v", recovered, err)
	}
}

func TestEpicPollerRequiresDurableValidState(t *testing.T) {
	github := &fakeGitHubClient{}
	poller := NewPoller(epicPollerConfig(), github, AgentRunSubmitter{}, nil, nil)
	if err := poller.PollOnce(context.Background()); err == nil {
		t.Fatal("enabled epic with memory-only state")
	}
	if len(github.listUpdatedSince) != 0 {
		t.Fatal("polled before validating durable state")
	}
	store := openEpicTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	epicCommand(t, store, CommandIntentEpicStart, 1)
	if _, err := store.db.Exec(`UPDATE producer_epics SET record='{"graph":"unsupported"}'`); err != nil {
		t.Fatal(err)
	}
	poller = NewPoller(epicPollerConfig(), github, AgentRunSubmitter{}, store, nil)
	if err := poller.PollOnce(context.Background()); err == nil {
		t.Fatal("polled with invalid recovered graph data")
	}
	if len(github.listUpdatedSince) != 0 {
		t.Fatal("invalid state did not fail closed")
	}
}

func assertNoPendingEpicStatuses(t *testing.T, store *SQLiteStateStore) {
	t.Helper()
	pending, err := store.ListPendingEpicStatuses(context.Background(), epicTestRepo)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending statuses: %+v %v", pending, err)
	}
}

func TestEpicStatusRecoveryRespectsAuthorization(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("disabled=%t", disabled), func(t *testing.T) {
			store := openEpicTestStore(t, filepath.Join(t.TempDir(), "state.db"))
			epicCommand(t, store, CommandIntentEpicStart, 1)
			epicCommand(t, store, CommandIntentEpicStatus, 2)
			cfg := epicPollerConfig()
			if disabled {
				cfg.Epics = EpicConfig{}
			} else {
				cfg.Epics.AllowedUserIDs = []int64{5678}
			}
			github := &fakeGitHubClient{filterUpdatedBySince: true}
			poller := NewPoller(cfg, github, AgentRunSubmitter{}, store, nil)
			if err := poller.PollOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if github.createIssueCommentCalls != 0 || github.listIssueCommentsCalls != 0 {
				t.Fatal("unauthorized recovery accessed thread")
			}
		})
	}
}

func (g *fakeGitHubClient) ListSubIssues(context.Context, Repository, int) ([]GitHubIssue, error) {
	return nil, errors.New("unavailable graph")
}
func (g *fakeGitHubClient) ListIssueBlockers(context.Context, Repository, int) ([]GitHubIssue, error) {
	return nil, errors.New("unavailable graph")
}
func (g *fakeGitHubClient) WriteEpicComment(context.Context, Repository, int, int64, string) (GitHubIssueComment, error) {
	return GitHubIssueComment{}, errors.New("unavailable display")
}
