//nolint:goconst // Tests repeat repository literals to keep fixtures readable.
package producer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var errReactionFailureNeedle = errors.New("REACTION-FAILURE-SECRET-NEEDLE")

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

func TestPollerDoesNotAdvanceCursorWhenSubmissionDeferred(t *testing.T) {
	ctx := context.Background()
	initialCursor := time.Date(2026, 6, 23, 10, 0, 0, 0, time.UTC)
	state := newMemoryStateStore()
	if err := state.SetRepoCursor(ctx, "acme/widget", initialCursor); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusTooManyRequests)
		_, _ = response.Write([]byte(`{"scheduled":false,"reason":"max-parallelism-reached"}`))
	}))
	defer server.Close()

	cfg := testPollerConfig("")
	cfg.AllowedAuthors = []string{"*"}
	cfg.Submission = SubmissionConfig{
		Mode:             SubmissionModeScheduleAdmission,
		AdmissionBaseURL: server.URL,
		ScheduleName:     "default",
	}
	github := &fakeGitHubClient{
		updatedComments: []GitHubIssueComment{{
			ID:        123,
			Body:      "/nvtagent pr create",
			IssueURL:  "https://api.github.com/repos/acme/widget/issues/42",
			UpdatedAt: time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC),
			User:      GitHubUser{Login: "octo"},
		}},
		issue: GitHubIssue{
			Number:  42,
			Title:   "Broken widget",
			HTMLURL: "https://github.com/acme/widget/issues/42",
		},
	}
	submitter := NewAgentRunSubmitterWithHTTP(nil, server.Client(), cfg)
	poller := NewPoller(cfg, github, submitter, state, slog.Default())
	if err := poller.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	got, found, err := state.GetRepoCursor(ctx, "acme/widget")
	if err != nil {
		t.Fatal(err)
	}
	if !found || !got.Equal(initialCursor) {
		t.Fatalf("cursor advanced after deferred submission: got %v want %s", got, initialCursor)
	}
}

func TestPollerReplaysAcceptedWorkAsDuplicateThenAdvancesAfterDeferredWorkSucceeds(t *testing.T) {
	ctx := context.Background()
	initialCursor := time.Date(2026, 6, 23, 10, 0, 0, 0, time.UTC)
	state := newMemoryStateStore()
	if err := state.SetRepoCursor(ctx, "acme/widget", initialCursor); err != nil {
		t.Fatal(err)
	}
	requestCount := 0
	seenWorkIDs := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var admission scheduleAdmissionRequest
		if err := json.NewDecoder(request.Body).Decode(&admission); err != nil {
			t.Fatal(err)
		}
		seenWorkIDs = append(seenWorkIDs, admission.Work.ID)
		requestCount++
		switch requestCount {
		case 1:
			response.WriteHeader(http.StatusCreated)
			_, _ = response.Write([]byte(`{"scheduled":true,"agentRun":{"namespace":"nvt","name":"run-a"}}`))
		case 2:
			response.WriteHeader(http.StatusTooManyRequests)
			_, _ = response.Write([]byte(`{"scheduled":false,"reason":"max-parallelism-reached"}`))
		case 3:
			response.WriteHeader(http.StatusAccepted)
			_, _ = response.Write([]byte(`{"scheduled":false,"reason":"duplicate-work"}`))
		case 4:
			response.WriteHeader(http.StatusCreated)
			_, _ = response.Write([]byte(`{"scheduled":true,"agentRun":{"namespace":"nvt","name":"run-b"}}`))
		default:
			t.Fatalf("unexpected admission request %d", requestCount)
		}
	}))
	defer server.Close()

	cfg := testPollerConfig("")
	cfg.AllowedAuthors = []string{"*"}
	cfg.Idempotency.Scope = IdempotencyScopeComment
	cfg.Submission = SubmissionConfig{
		Mode:             SubmissionModeScheduleAdmission,
		AdmissionBaseURL: server.URL,
		ScheduleName:     "default",
	}
	github := &fakeGitHubClient{
		updatedComments: []GitHubIssueComment{
			{
				ID:        101,
				Body:      "/nvtagent pr create",
				IssueURL:  "https://api.github.com/repos/acme/widget/issues/42",
				UpdatedAt: time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC),
				User:      GitHubUser{Login: "octo"},
			},
			{
				ID:        202,
				Body:      "/nvtagent pr create",
				IssueURL:  "https://api.github.com/repos/acme/widget/issues/43",
				UpdatedAt: time.Date(2026, 6, 23, 12, 1, 0, 0, time.UTC),
				User:      GitHubUser{Login: "octo"},
			},
		},
		issues: map[int]GitHubIssue{
			42: {Number: 42, Title: "A", HTMLURL: "https://github.com/acme/widget/issues/42"},
			43: {Number: 43, Title: "B", HTMLURL: "https://github.com/acme/widget/issues/43"},
		},
	}
	submitter := NewAgentRunSubmitterWithHTTP(nil, server.Client(), cfg)
	poller := NewPoller(cfg, github, submitter, state, slog.Default())
	pollStartedAt := time.Date(2026, 6, 23, 12, 2, 0, 0, time.UTC)
	poller.now = func() time.Time {
		return pollStartedAt
	}

	if err := poller.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	got, found, err := state.GetRepoCursor(ctx, "acme/widget")
	if err != nil {
		t.Fatal(err)
	}
	if !found || !got.Equal(initialCursor) {
		t.Fatalf("cursor advanced after first deferred poll: got %v want %s", got, initialCursor)
	}
	pollStartedAt = time.Date(2026, 6, 23, 12, 3, 0, 0, time.UTC)
	if err := poller.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	got, found, err = state.GetRepoCursor(ctx, "acme/widget")
	if err != nil {
		t.Fatal(err)
	}
	wantCursor := pollStartedAt
	if !found || !got.Equal(wantCursor) {
		t.Fatalf("cursor = %v want %s", got, wantCursor)
	}
	if requestCount != 4 {
		t.Fatalf("admission requests = %d want 4", requestCount)
	}
	if seenWorkIDs[0] != seenWorkIDs[2] || seenWorkIDs[1] != seenWorkIDs[3] {
		t.Fatalf("unexpected replay work IDs: %#v", seenWorkIDs)
	}
}

func TestPollerReactsOnlyToAuthoritativeTerminalAdmissionOutcomes(t *testing.T) {
	for _, test := range []struct {
		name         string
		body         string
		wantReaction string
		status       int
		wantError    bool
		wantDeferred bool
	}{
		{name: "created", status: http.StatusCreated, body: `{"scheduled":true}`, wantReaction: "+1"},
		{name: "accepted", status: http.StatusAccepted, body: `{"scheduled":true}`, wantReaction: "+1"},
		{name: "duplicate", status: http.StatusAccepted, body: `{"scheduled":false,"reason":"duplicate-work"}`, wantReaction: "+1"},
		{name: "definitive rejection", status: http.StatusForbidden, body: `{"scheduled":false,"reason":"principal-not-enrolled"}`, wantReaction: "-1"},
		{name: "suspended", status: http.StatusAccepted, body: `{"scheduled":false,"reason":"schedule-suspended"}`, wantDeferred: true},
		{name: "capacity", status: http.StatusTooManyRequests, body: `{"scheduled":false,"reason":"max-parallelism-reached"}`, wantDeferred: true},
		{name: "malformed", status: http.StatusCreated, body: `{`, wantError: true},
		{name: "server failure", status: http.StatusInternalServerError, body: `{"scheduled":false,"reason":"response-encode-failed"}`, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.WriteHeader(test.status)
				if _, err := response.Write([]byte(test.body)); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()

			cfg, github, state := schedulingReactionPollerFixture(t, server.URL)
			poller := NewPoller(
				cfg, github, NewAgentRunSubmitterWithHTTP(nil, server.Client(), cfg), state, slog.Default(),
			)
			err := poller.PollOnce(context.Background())
			if test.wantDeferred {
				if err != nil {
					t.Fatalf("deferred poll failed: %v", err)
				}
			} else if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError %v", err, test.wantError)
			}
			if test.wantReaction == "" {
				if len(github.reactions) != 0 {
					t.Fatalf("unexpected reactions: %#v", github.reactions)
				}
			} else if len(github.reactions) != 1 || github.reactions[0].commentID != 123 ||
				github.reactions[0].reaction != test.wantReaction {
				t.Fatalf("reactions = %#v, want %q on comment 123", github.reactions, test.wantReaction)
			}
		})
	}
}

//nolint:gocyclo // The integration-style regression checks two ordered admissions, reactions, cursor, and replay.
func TestPollerConsumesRejectedCommentAndContinuesToAcceptedComment(t *testing.T) {
	const rejectionNeedle = "DEFINITIVE-REJECTION-SECRET-NEEDLE"
	ctx := context.Background()
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requestCount++
		if requestCount == 1 {
			response.WriteHeader(http.StatusForbidden)
			if _, err := response.Write([]byte(
				`{"scheduled":false,"reason":"principal-not-enrolled","detail":"` + rejectionNeedle + `"}`,
			)); err != nil {
				t.Error(err)
			}
			return
		}
		response.WriteHeader(http.StatusCreated)
		if _, err := response.Write([]byte(`{"scheduled":true}`)); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()

	state := newMemoryStateStore()
	cfg := testPollerConfig("")
	cfg.AllowedAuthors = []string{"*"}
	cfg.Idempotency.Scope = IdempotencyScopeComment
	cfg.Submission = SubmissionConfig{
		Mode: SubmissionModeScheduleAdmission, AdmissionBaseURL: server.URL, ScheduleName: "default",
	}
	if err := cfg.ApplyDefaultsAndValidate(); err != nil {
		t.Fatal(err)
	}
	firstUpdated := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	secondUpdated := firstUpdated.Add(time.Minute)
	github := &fakeGitHubClient{
		filterUpdatedBySince: true,
		updatedComments: []GitHubIssueComment{
			{
				ID: 101, Body: "/nvtagent pr create",
				IssueURL: "https://api.github.com/repos/acme/widget/issues/41", UpdatedAt: firstUpdated,
				User: GitHubUser{Login: "octo", ID: 424242},
			},
			{
				ID: 202, Body: "/nvtagent pr create",
				IssueURL: "https://api.github.com/repos/acme/widget/issues/42", UpdatedAt: secondUpdated,
				User: GitHubUser{Login: "octo", ID: 424242},
			},
		},
		issues: map[int]GitHubIssue{
			41: {Number: 41, Title: "Rejected"},
			42: {Number: 42, Title: "Accepted"},
		},
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	poller := NewPoller(cfg, github, NewAgentRunSubmitterWithHTTP(nil, server.Client(), cfg), state, logger)
	poller.startedAt = firstUpdated.Add(-time.Minute)
	pollStartedAt := secondUpdated.Add(time.Minute)
	poller.now = func() time.Time { return pollStartedAt }

	if err := poller.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if requestCount != 2 {
		t.Fatalf("admission requests = %d, want 2", requestCount)
	}
	if !strings.Contains(logs.String(), "processed definitive schedule admission rejection") ||
		strings.Contains(logs.String(), rejectionNeedle) {
		t.Fatalf("definitive rejection log was missing or unsafe: %q", logs.String())
	}
	if len(github.reactions) != 2 || github.reactions[0].commentID != 101 || github.reactions[0].reaction != "-1" ||
		github.reactions[1].commentID != 202 || github.reactions[1].reaction != "+1" {
		t.Fatalf("reactions = %#v, want -1 then +1", github.reactions)
	}
	cursor, found, err := state.GetRepoCursor(ctx, "acme/widget")
	if err != nil || !found || !cursor.Equal(pollStartedAt) {
		t.Fatalf("cursor = %v found=%v err=%v, want %v", cursor, found, err, pollStartedAt)
	}

	poller.now = func() time.Time { return pollStartedAt.Add(time.Minute) }
	if err := poller.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if requestCount != 2 || len(github.reactions) != 2 {
		t.Fatalf("commands were resubmitted: requests=%d reactions=%#v", requestCount, github.reactions)
	}
}

func TestPollerSchedulingReactionOptOut(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusCreated)
		if _, err := response.Write([]byte(`{"scheduled":true}`)); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()

	cfg, github, state := schedulingReactionPollerFixture(t, server.URL)
	disabled := false
	cfg.SchedulingReactions.Enabled = &disabled
	poller := NewPoller(cfg, github, NewAgentRunSubmitterWithHTTP(nil, server.Client(), cfg), state, slog.Default())
	if err := poller.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(github.reactions) != 0 {
		t.Fatalf("disabled reactions were posted: %#v", github.reactions)
	}
}

func TestPollerReactionFailureNeverChangesAcceptedSchedulingOrCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusCreated)
		if _, err := response.Write([]byte(`{"scheduled":true}`)); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()

	cfg, github, state := schedulingReactionPollerFixture(t, server.URL)
	const secretNeedle = "REACTION-FAILURE-SECRET-NEEDLE"
	github.reactionErr = errReactionFailureNeedle
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	poller := NewPoller(cfg, github, NewAgentRunSubmitterWithHTTP(nil, server.Client(), cfg), state, logger)
	pollStartedAt := time.Date(2026, 6, 23, 13, 0, 0, 0, time.UTC)
	poller.now = func() time.Time { return pollStartedAt }
	if err := poller.PollOnce(context.Background()); err != nil {
		t.Fatalf("reaction failure changed accepted scheduling: %v", err)
	}
	cursor, found, err := state.GetRepoCursor(context.Background(), "acme/widget")
	if err != nil || !found || !cursor.Equal(pollStartedAt) {
		t.Fatalf("cursor = %v found=%v err=%v, want %v", cursor, found, err, pollStartedAt)
	}
	if len(github.reactions) != 1 || strings.Contains(logs.String(), secretNeedle) {
		t.Fatalf("reaction warning/calls were not sanitized: calls=%#v logs=%q", github.reactions, logs.String())
	}
}

func TestPollerAdmissionNetworkFailureDoesNotReact(t *testing.T) {
	cfg, github, state := schedulingReactionPollerFixture(t, "https://operator.invalid")
	httpClient := &http.Client{Transport: testRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})}
	poller := NewPoller(cfg, github, NewAgentRunSubmitterWithHTTP(nil, httpClient, cfg), state, slog.Default())
	if err := poller.PollOnce(context.Background()); err == nil {
		t.Fatal("expected uncertain admission failure")
	}
	if len(github.reactions) != 0 {
		t.Fatalf("uncertain admission posted reactions: %#v", github.reactions)
	}
}

func TestPollerInvalidAndUnauthorizedCommandsDoNotReact(t *testing.T) {
	cfg := testPollerConfig("")
	cfg.AllowedAuthors = []string{"maintainer"}
	github := &fakeGitHubClient{updatedComments: []GitHubIssueComment{
		{ID: 1, Body: "not a command", User: GitHubUser{Login: "maintainer"}},
		{ID: 2, Body: "/nvtagent pr create", User: GitHubUser{Login: "outsider"}},
	}}
	poller := NewPoller(cfg, github, AgentRunSubmitter{}, newMemoryStateStore(), slog.Default())
	if err := poller.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(github.reactions) != 0 {
		t.Fatalf("invalid or unauthorized commands posted reactions: %#v", github.reactions)
	}
}

func schedulingReactionPollerFixture(t *testing.T, admissionURL string) (Config, *fakeGitHubClient, StateStore) {
	t.Helper()
	state := newMemoryStateStore()
	cfg := testPollerConfig("")
	cfg.AllowedAuthors = []string{"*"}
	cfg.Submission = SubmissionConfig{
		Mode:             SubmissionModeScheduleAdmission,
		AdmissionBaseURL: admissionURL,
		ScheduleName:     "default",
	}
	if err := cfg.ApplyDefaultsAndValidate(); err != nil {
		t.Fatal(err)
	}
	github := &fakeGitHubClient{
		updatedComments: []GitHubIssueComment{{
			ID:        123,
			Body:      "/nvtagent pr create",
			IssueURL:  "https://api.github.com/repos/acme/widget/issues/42",
			UpdatedAt: time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC),
			User:      GitHubUser{Login: "octo", ID: 424242},
		}},
		issue: GitHubIssue{Number: 42, Title: "Broken widget", HTMLURL: "https://github.com/acme/widget/issues/42"},
	}
	return cfg, github, state
}

type testRoundTripper func(*http.Request) (*http.Response, error)

func (f testRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
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

func TestPollerSkipsReviewOnOrdinaryIssueWithoutAgentRun(t *testing.T) {
	github := &fakeGitHubClient{
		updatedComments: []GitHubIssueComment{{ID: 124, Body: "/nvtagent review", IssueURL: "https://api.github.com/repos/acme/widget/issues/42", User: GitHubUser{Login: "octo"}}},
		issue:           GitHubIssue{Number: 42, Title: "Ordinary issue"},
	}
	cfg := testPollerConfig("")
	k8sClient := newFakeAgentRunClient(t)
	poller := NewPoller(cfg, github, NewAgentRunSubmitter(k8sClient, cfg), nil, slog.Default())
	if err := poller.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	var runs nvtv1alpha1.AgentRunList
	if err := k8sClient.List(context.Background(), &runs); err != nil {
		t.Fatal(err)
	}
	if len(runs.Items) != 0 || github.listIssueCommentsCalls != 0 {
		t.Fatalf("invalid review placement fetched comments or created runs: calls=%d runs=%d", github.listIssueCommentsCalls, len(runs.Items))
	}
}

func TestCommandPlacementByIntent(t *testing.T) {
	tests := []struct {
		intent   CommandIntent
		pr, want bool
	}{
		{CommandIntentPRCreate, false, true}, {CommandIntentPRCreate, true, false},
		{CommandIntentReview, false, false}, {CommandIntentReview, true, true},
		{CommandIntentRun, false, true}, {CommandIntentRun, true, true},
		{CommandIntentPRContinue, false, false}, {CommandIntentPRContinue, true, true},
	}
	for _, test := range tests {
		if got := validCommandPlacement(test.intent, test.pr); got != test.want {
			t.Fatalf("intent=%q pr=%v got=%v", test.intent, test.pr, got)
		}
	}
}

func TestPollerHelpCommandPostsHelpAndReturnsWithoutSubmitting(t *testing.T) {
	github := &fakeGitHubClient{
		updatedComments: []GitHubIssueComment{{
			ID:       101,
			Body:     "/nvtagent --help",
			IssueURL: "https://api.github.com/repos/acme/widget/issues/42",
			User:     GitHubUser{Login: "octo"},
		}},
		issue: GitHubIssue{Number: 42, Title: "Any", HTMLURL: "https://github.com/acme/widget/issues/42"},
	}
	k8sClient := newFakeAgentRunClient(t)
	cfg := testPollerConfig("")
	cfg.AllowedAuthors = []string{"*"}
	poller := NewPoller(cfg, github, NewAgentRunSubmitter(k8sClient, cfg), nil, slog.Default())

	if err := poller.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if github.createIssueCommentCalls != 1 {
		t.Fatalf("help command expected one response comment, got %d", github.createIssueCommentCalls)
	}
	if !strings.HasPrefix(github.createdIssueCommentBody, helpResponse("/nvtagent")+"\n<!-- nvt-github-help-response:") {
		t.Fatalf("help response mismatch:\n%s", github.createdIssueCommentBody)
	}
	if github.listIssueCommentsCalls != 0 {
		t.Fatalf("help command fetched issue comments: %d", github.listIssueCommentsCalls)
	}
	var runs nvtv1alpha1.AgentRunList
	if err := k8sClient.List(context.Background(), &runs, ctrlclient.InNamespace(cfg.AgentRun.Namespace)); err != nil {
		t.Fatal(err)
	}
	if len(runs.Items) != 0 {
		t.Fatalf("help command unexpectedly created AgentRuns: %d", len(runs.Items))
	}
}

func TestHelpResponseIsFormalCompleteCommandReference(t *testing.T) {
	want := "```text\n" + `NVT GitHub Producer

USAGE
  /nvtagent --help
  /nvtagent pr create [-- <instructions>]
  /nvtagent review [-- <instructions>]
  /nvtagent run -- <instructions>
  /nvtagent pr continue [-- <instructions>]

COMMANDS
  --help
      Show this command reference. Valid on issues and pull requests.

  pr create
      Create and deliver a pull request. Valid only on ordinary issues.
      Additional instructions are optional.

  review
      Review the current pull request and post findings without approving,
      requesting changes, or modifying product code. Valid only on pull requests.
      Additional focus instructions are optional.

  run
      Perform one bounded task, post the result to the originating thread,
      and exit. Valid on issues and pull requests. Instructions are required.

  pr continue
      Start a durable pull-request maintenance session. The agent checks out
      the PR branch, reads reviews, comments, and checks, addresses actionable
      issues, watches for later activity, and remains active until merge or close.
      Valid only on pull requests. Additional instructions are optional.

INSTRUCTIONS
  Put the command on the first non-empty line. Add instructions either after
  a standalone -- on that line, or on the following lines. If both forms are
  used, the inline text is followed by a newline and then the multiline text.
  Bare trailing text without -- is invalid.` + "\n```"
	if got := helpResponse("/nvtagent"); got != want {
		t.Fatalf("help output:\n%s\nwant:\n%s", got, want)
	}
}

func TestHelpResponseMarkerRequiresLaterThreadComment(t *testing.T) {
	const marker = "<!-- nvt-github-help-response:marker -->"
	comments := []GitHubIssueComment{
		{ID: 100, Body: marker},
		{ID: 101, Body: "/nvtagent --help\n" + marker},
	}
	if helpResponseMarkerExists(comments, 101, marker) {
		t.Fatal("command or earlier comment forged delivered marker")
	}
	comments = append(comments, GitHubIssueComment{ID: 102, Body: helpResponse("/nvtagent") + "\n" + marker})
	if !helpResponseMarkerExists(comments, 101, marker) {
		t.Fatal("later response marker was not found")
	}
}

func TestPollerHelpCommandResponseIsIdempotentEvenWhenCommentReplays(t *testing.T) {
	ctx := context.Background()
	state := &failCursorOnceStateStore{StateStore: newMemoryStateStore(), remainingFailures: 1}
	github := &fakeGitHubClient{
		updatedComments: []GitHubIssueComment{{
			ID:       101,
			Body:     "/nvtagent --help",
			IssueURL: "https://api.github.com/repos/acme/widget/issues/42",
			User:     GitHubUser{Login: "octo"},
		}},
		issue: GitHubIssue{Number: 42, Title: "Any", HTMLURL: "https://github.com/acme/widget/issues/42"},
	}
	k8sClient := newFakeAgentRunClient(t)
	cfg := testPollerConfig("")
	cfg.AllowedAuthors = []string{"*"}
	poller := NewPoller(cfg, github, NewAgentRunSubmitter(k8sClient, cfg), state, slog.Default())
	poller.startedAt = time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)

	if err := poller.PollOnce(ctx); err == nil {
		t.Fatal("expected injected cursor failure")
	}
	if github.createIssueCommentCalls != 1 {
		t.Fatalf("help command expected one response comment, got %d", github.createIssueCommentCalls)
	}
	if err := poller.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if github.createIssueCommentCalls != 1 {
		t.Fatalf("help command replay produced duplicate response: got %d", github.createIssueCommentCalls)
	}
}

func TestPollerHelpCommandReconcilesAmbiguousPostWithoutDuplicate(t *testing.T) {
	github := &fakeGitHubClient{
		updatedComments: []GitHubIssueComment{{
			ID: 101, Body: "/nvtagent --help",
			IssueURL: "https://api.github.com/repos/acme/widget/issues/42",
			User:     GitHubUser{Login: "octo"},
		}},
		createIssueCommentErr: errors.New("injected post failure"),
	}
	cfg := testPollerConfig("")
	cfg.AllowedAuthors = []string{"*"}
	poller := NewPoller(cfg, github, NewAgentRunSubmitter(newFakeAgentRunClient(t), cfg), newMemoryStateStore(), slog.Default())
	if err := poller.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	github.issueComments = []GitHubIssueComment{{ID: 202, Body: github.createdIssueCommentBody}}
	github.createIssueCommentErr = nil
	if err := poller.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if github.createIssueCommentCalls != 1 {
		t.Fatalf("ambiguous accepted post was duplicated: attempts=%d", github.createIssueCommentCalls)
	}
}

func TestPollerHelpCommandRecoversPendingClaimCreatedBeforePost(t *testing.T) {
	ctx := context.Background()
	state := newMemoryStateStore()
	const marker = "<!-- nvt-github-help-response:00112233445566778899aabbccddeeff -->"
	record, created, err := state.GetOrCreateHelpResponse(ctx, "acme/widget", 101, marker, time.Now())
	if err != nil || !created || record.Marker != marker {
		t.Fatalf("seed pending response = %#v created=%v err=%v", record, created, err)
	}
	github := &fakeGitHubClient{updatedComments: []GitHubIssueComment{{
		ID: 101, Body: "/nvtagent --help",
		IssueURL: "https://api.github.com/repos/acme/widget/issues/42",
		User:     GitHubUser{Login: "octo"},
	}}}
	cfg := testPollerConfig("")
	cfg.AllowedAuthors = []string{"*"}
	poller := NewPoller(cfg, github, NewAgentRunSubmitter(newFakeAgentRunClient(t), cfg), state, slog.Default())
	if err := poller.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if github.createIssueCommentCalls != 1 || !strings.Contains(github.createdIssueCommentBody, marker) {
		t.Fatalf("pending response was not recovered: calls=%d body=%q", github.createIssueCommentCalls, github.createdIssueCommentBody)
	}
}

func TestPollerHelpCommandRetriesUnobservedPendingPostAfterLease(t *testing.T) {
	github := &fakeGitHubClient{
		updatedComments: []GitHubIssueComment{{
			ID: 101, Body: "/nvtagent --help",
			IssueURL: "https://api.github.com/repos/acme/widget/issues/42",
			User:     GitHubUser{Login: "octo"},
		}},
		createIssueCommentErr: errors.New("injected post failure"),
	}
	cfg := testPollerConfig("")
	cfg.AllowedAuthors = []string{"*"}
	poller := NewPoller(cfg, github, NewAgentRunSubmitter(newFakeAgentRunClient(t), cfg), newMemoryStateStore(), slog.Default())
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	poller.now = func() time.Time { return now }
	if err := poller.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	github.createIssueCommentErr = nil
	now = now.Add(helpResponseRetryDelay + time.Second)
	if err := poller.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if github.createIssueCommentCalls != 2 {
		t.Fatalf("unobserved pending post attempts = %d, want retry", github.createIssueCommentCalls)
	}
}

func TestPollerConsumesUnmappedCommandAndProcessesFollowingWork(t *testing.T) {
	ctx := context.Background()
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requestCount++
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write([]byte(`{"scheduled":true,"agentRun":{"namespace":"nvt","name":"valid-work"}}`))
	}))
	defer server.Close()

	firstUpdated := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	secondUpdated := firstUpdated.Add(time.Minute)
	thirdUpdated := secondUpdated.Add(time.Minute)
	cfg := testPollerConfig("")
	cfg.AllowedAuthors = []string{"*"}
	cfg.Submission = SubmissionConfig{
		Mode:               SubmissionModeScheduleAdmission,
		AdmissionMode:      AdmissionModeProfiled,
		AdmissionBaseURL:   server.URL,
		AdmissionTokenFile: writeTestAdmissionToken(t, testAdmissionToken("c2lnMQ")),
		ScheduleName:       "default",
		Workflow:           "implement-pr",
	}
	github := &fakeGitHubClient{
		updatedComments: []GitHubIssueComment{
			{ID: 300, Body: "/nvtagent run\ninspect it", IssueURL: "https://api.github.com/repos/acme/widget/issues/40", UpdatedAt: firstUpdated, User: GitHubUser{Login: "octo", ID: 7}},
			{ID: 301, Body: "/nvtagent review", IssueURL: "https://api.github.com/repos/acme/widget/issues/41", UpdatedAt: secondUpdated, User: GitHubUser{Login: "octo", ID: 7}},
			{ID: 302, Body: "/nvtagent pr create", IssueURL: "https://api.github.com/repos/acme/widget/issues/42", UpdatedAt: thirdUpdated, User: GitHubUser{Login: "octo", ID: 7}},
		},
		issues: map[int]GitHubIssue{
			40: {Number: 40, Title: "Run task"},
			41: {Number: 41, Title: "Review me", PullRequest: &GitHubPullRequest{HTMLURL: "https://github.com/acme/widget/pull/41"}},
			42: {Number: 42, Title: "Implement me", HTMLURL: "https://github.com/acme/widget/issues/42"},
		},
	}
	state := newMemoryStateStore()
	poller := NewPoller(cfg, github, NewAgentRunSubmitterWithHTTP(nil, server.Client(), cfg), state, slog.Default())
	poller.now = func() time.Time { return firstUpdated.Add(-time.Minute) }
	if err := poller.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if github.listIssueCommentsCalls != 3 {
		t.Fatalf("comment fetches = %d, want both commands processed", github.listIssueCommentsCalls)
	}
	if requestCount != 1 {
		t.Fatalf("admission requests = %d, want only following valid work", requestCount)
	}
	cursor, found, err := state.GetRepoCursor(ctx, "acme/widget")
	if err != nil {
		t.Fatal(err)
	}
	if !found || !cursor.Equal(thirdUpdated) {
		t.Fatalf("cursor = %v found=%v, want %v", cursor, found, thirdUpdated)
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
	cfg.Submission.Mode = SubmissionModeDirect
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
	updatedComments         []GitHubIssueComment
	issue                   GitHubIssue
	issues                  map[int]GitHubIssue
	issueComments           []GitHubIssueComment
	createIssueCommentCalls int
	createdIssueCommentBody string
	createIssueCommentErr   error
	listUpdatedSince        []*time.Time
	listIssueCommentsCalls  int
	filterUpdatedBySince    bool
	reactions               []fakeSchedulingReaction
	reactionErr             error
}

type failCursorOnceStateStore struct {
	StateStore
	remainingFailures int
}

func (s *failCursorOnceStateStore) SetRepoCursor(ctx context.Context, repoKey string, cursor time.Time) error {
	if s.remainingFailures > 0 {
		s.remainingFailures--
		return errors.New("injected cursor failure")
	}
	return s.StateStore.SetRepoCursor(ctx, repoKey, cursor)
}

type fakeSchedulingReaction struct {
	repo      Repository
	reaction  string
	commentID int64
}

func (f *fakeGitHubClient) ListUpdatedIssueComments(
	_ context.Context,
	_ Repository,
	since *time.Time,
) ([]GitHubIssueComment, error) {
	f.listUpdatedSince = append(f.listUpdatedSince, since)
	if f.filterUpdatedBySince && since != nil {
		filtered := make([]GitHubIssueComment, 0, len(f.updatedComments))
		for _, comment := range f.updatedComments {
			if comment.UpdatedAt.After(*since) {
				filtered = append(filtered, comment)
			}
		}
		return filtered, nil
	}
	return f.updatedComments, nil
}

func (f *fakeGitHubClient) GetIssue(_ context.Context, _ Repository, issueNumber int) (GitHubIssue, error) {
	if f.issues != nil {
		return f.issues[issueNumber], nil
	}
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

func (f *fakeGitHubClient) CreateIssueComment(
	_ context.Context,
	_ Repository,
	_ int,
	body string,
) error {
	f.createIssueCommentCalls++
	f.createdIssueCommentBody = body
	return f.createIssueCommentErr
}

func (f *fakeGitHubClient) CreateIssueCommentReaction(
	_ context.Context,
	repo Repository,
	commentID int64,
	reaction string,
) error {
	f.reactions = append(f.reactions, fakeSchedulingReaction{repo: repo, commentID: commentID, reaction: reaction})
	return f.reactionErr
}
