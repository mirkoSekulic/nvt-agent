package producer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func nativeIssue(number int) GitHubIssue {
	return GitHubIssue{ID: int64(1000 + number), Number: number, State: "open", Title: fmt.Sprintf("Issue %d", number), URL: fmt.Sprintf("https://api.github.com/repos/acme/widget/issues/%d", number), HTMLURL: fmt.Sprintf("https://github.com/acme/widget/issues/%d", number)}
}

type schedulingGitHub struct {
	*fakeGitHubClient
	children                                 []GitHubIssue
	blockers                                 map[int][]GitHubIssue
	threads                                  map[int][]GitHubIssueComment
	creates, edits                           map[int]int
	nextID                                   int64
	graphErr, listErr, writeErr, reactionErr bool
	ambiguous                                bool
}

func newSchedulingGitHub() *schedulingGitHub {
	return &schedulingGitHub{fakeGitHubClient: &fakeGitHubClient{issue: nativeIssue(42)}, blockers: map[int][]GitHubIssue{}, threads: map[int][]GitHubIssueComment{}, creates: map[int]int{}, edits: map[int]int{}, nextID: 100}
}
func (g *schedulingGitHub) ListSubIssues(context.Context, Repository, int) ([]GitHubIssue, error) {
	if g.graphErr {
		return nil, errors.New("graph unavailable")
	}
	return append([]GitHubIssue(nil), g.children...), nil
}
func (g *schedulingGitHub) ListIssueBlockers(_ context.Context, _ Repository, number int) ([]GitHubIssue, error) {
	return g.blockers[number], nil
}
func (g *schedulingGitHub) ListIssueComments(_ context.Context, _ Repository, number int) ([]GitHubIssueComment, error) {
	if g.listErr {
		return nil, errors.New("thread unavailable")
	}
	return g.threads[number], nil
}
func (g *schedulingGitHub) WriteEpicComment(_ context.Context, _ Repository, number int, id int64, body string) (GitHubIssueComment, error) {
	if g.writeErr {
		return GitHubIssueComment{}, errors.New("write failed")
	}
	comment := GitHubIssueComment{ID: id, Body: body, User: GitHubUser{ID: 77, Login: "producer[bot]", Type: "Bot"}}
	if id == 0 {
		g.nextID++
		comment.ID = g.nextID
		g.threads[number] = append(g.threads[number], comment)
		g.creates[number]++
	} else {
		found := false
		for i := range g.threads[number] {
			if g.threads[number][i].ID == id {
				g.threads[number][i] = comment
				found = true
			}
		}
		if !found {
			return GitHubIssueComment{}, errors.New("missing comment")
		}
		g.edits[number]++
	}
	if g.ambiguous {
		return GitHubIssueComment{}, errors.New("response lost after write")
	}
	return comment, nil
}
func (g *schedulingGitHub) CreateIssueCommentReaction(ctx context.Context, repo Repository, id int64, reaction string) error {
	if g.reactionErr {
		return errors.New("reaction failed")
	}
	return g.fakeGitHubClient.CreateIssueCommentReaction(ctx, repo, id, reaction)
}

type epicHarness struct {
	t        *testing.T
	path     string
	store    *SQLiteStateStore
	github   *schedulingGitHub
	poller   *Poller
	cfg      Config
	now      time.Time
	requests []profiledScheduleAdmissionRequest
	runs     map[string]bool
	outcome  string
}

func newEpicHarness(t *testing.T) *epicHarness {
	t.Helper()
	h := &epicHarness{t: t, path: filepath.Join(t.TempDir(), "state.db"), github: newSchedulingGitHub(), cfg: epicPollerConfig(), now: epicTestTime, runs: map[string]bool{}}
	h.store = openEpicTestStore(t, h.path)
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte(strings.Repeat("x", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/schedules/epics/admissions" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("x", 32) {
			t.Error("wrong admission path or credential")
		}
		var req profiledScheduleAdmissionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		h.requests = append(h.requests, req)
		switch h.outcome {
		case "rejected":
			w.WriteHeader(403)
			fmt.Fprint(w, `{"scheduled":false,"reason":"principal-not-eligible"}`)
			return
		case "deferred":
			w.WriteHeader(429)
			fmt.Fprint(w, `{"scheduled":false,"reason":"max-parallelism-reached"}`)
			return
		}
		duplicate := h.runs[req.Work.ID]
		h.runs[req.Work.ID] = true
		if h.outcome == "uncertain" {
			w.WriteHeader(201)
			fmt.Fprint(w, `{"scheduled":`)
			return
		}
		if duplicate {
			if h.outcome == "duplicate-without-identity" {
				w.WriteHeader(202)
				fmt.Fprint(w, `{"scheduled":false,"reason":"duplicate-work"}`)
				return
			}
			w.WriteHeader(202)
			fmt.Fprint(w, `{"scheduled":false,"reason":"duplicate-work","agentRun":{"namespace":"nvt","name":"accepted-run"}}`)
			return
		}
		w.WriteHeader(201)
		fmt.Fprint(w, `{"scheduled":true,"agentRun":{"namespace":"nvt","name":"accepted-run"}}`)
	}))
	t.Cleanup(server.Close)
	h.cfg.Submission = SubmissionConfig{Mode: SubmissionModeScheduleAdmission, AdmissionMode: AdmissionModeProfiled, Backend: SubmissionBackendLocal, AdmissionBaseURL: server.URL, AdmissionTokenFile: token, ScheduleName: "epics", Workflow: "wrong-default", CommandWorkflows: map[CommandIntent]string{CommandIntentPRCreate: "wrong-command-workflow"}}
	h.resetPoller()
	return h
}
func (h *epicHarness) resetPoller() {
	h.poller = NewPoller(h.cfg, h.github, NewAgentRunSubmitterWithHTTP(nil, http.DefaultClient, h.cfg), h.store, nil)
	h.poller.now = func() time.Time { return h.now }
	h.poller.startedAt = h.now.Add(-time.Minute)
}
func (h *epicHarness) restart() {
	h.t.Helper()
	if err := h.store.Close(); err != nil {
		h.t.Fatal(err)
	}
	h.store = openEpicTestStore(h.t, h.path)
	h.resetPoller()
}
func (h *epicHarness) poll() {
	h.t.Helper()
	h.now = h.now.Add(2 * time.Minute)
	if err := h.poller.PollOnce(context.Background()); err != nil {
		h.t.Fatal(err)
	}
}
func (h *epicHarness) record() (EpicRecord, EpicSchedule) {
	h.t.Helper()
	epics, err := h.store.ListEpics(context.Background(), epicTestRepo)
	if err != nil || len(epics) != 1 {
		h.t.Fatalf("epics %+v %v", epics, err)
	}
	r, err := h.store.LoadEpicSchedule(context.Background(), epicTestRepo, epics[0])
	if err != nil {
		h.t.Fatal(err)
	}
	return epics[0], r
}
func (h *epicHarness) body(issue int) string {
	h.t.Helper()
	if len(h.github.threads[issue]) != 1 {
		h.t.Fatalf("expected one status on #%d: %+v", issue, h.github.threads[issue])
	}
	return h.github.threads[issue][0].Body
}

func TestEpicDeterministicSchedulingAndPrincipal(t *testing.T) {
	for _, order := range [][]int{{3, 1, 2, 4}, {4, 2, 1, 3}, {2, 3, 4, 1}} {
		t.Run(fmt.Sprint(order), func(t *testing.T) {
			h := newEpicHarness(t)
			for _, n := range order {
				h.github.children = append(h.github.children, nativeIssue(n))
			}
			h.github.blockers[1] = []GitHubIssue{nativeIssue(3)}
			closed := nativeIssue(9)
			closed.State = "closed"
			h.github.blockers[2] = []GitHubIssue{closed}
			h.github.updatedComments = []GitHubIssueComment{epicPollComment("start", 1)}
			h.poll()
			h.restart()
			h.poll()
			h.poll()
			if len(h.requests) != 1 || len(h.runs) != 1 {
				t.Fatalf("duplicate admissions: %d / %d", len(h.requests), len(h.runs))
			}
			req := h.requests[0]
			if req.Workflow != "implement-pr" || req.Work.Principal.Subject != "1234" || req.Work.Principal.DisplayName != "maintainer" || req.Work.URL != nativeIssue(2).HTMLURL || req.Work.Repository != "acme/widget" || !strings.Contains(req.Input.Prompt, "Issue number: 2") {
				t.Fatalf("incorrect child/principal/workflow: %+v", req)
			}
			_, r := h.record()
			if len(r.Attempts) != 1 || r.Attempts[0].Source.ID != nativeIssue(2).ID || r.Attempts[0].State != "accepted" || r.Attempts[0].AgentRun.Name != "accepted-run" {
				t.Fatalf("lost accepted source: %+v", r)
			}
			body := h.body(42)
			for _, text := range []string{"| #1 | Blocked |", "| #2 | Running |", "| #3 | Queued |", "| #4 | Queued |"} {
				if !strings.Contains(body, text) {
					t.Fatal(body)
				}
			}
			if strings.Index(body, "#1 |") > strings.Index(body, "#2 |") {
				t.Fatal("unordered status")
			}
			if !strings.Contains(h.body(2), "nvt/accepted-run") {
				t.Fatal(h.body(2))
			}
			for _, n := range []int{1, 2, 3, 4, 42} {
				if h.github.creates[n] != 1 {
					t.Fatalf("duplicate status #%d", n)
				}
			}
		})
	}
}

func TestEpicAdmissionRejectionDoesNotAdvance(t *testing.T) {
	h := newEpicHarness(t)
	h.github.children = []GitHubIssue{nativeIssue(1), nativeIssue(2)}
	h.outcome = "rejected"
	epicCommand(t, h.store, CommandIntentEpicStart, 1)
	h.poll()
	h.restart()
	h.poll()
	epic, r := h.record()
	if epic.Generation != 1 || epic.State != EpicPending || len(r.Attempts) != 1 || r.Attempts[0].State != "rejected" || r.Attempts[0].AgentRun != nil || len(h.requests) != 1 || len(h.runs) != 0 {
		t.Fatalf("rejection advanced: %+v %+v", epic, r)
	}
	if !strings.Contains(h.body(42), "| #1 | Failed |") || !strings.Contains(h.body(1), "admission rejected") {
		t.Fatal(h.body(42))
	}
	h.outcome = ""
	epicCommand(t, h.store, CommandIntentEpicPause, 2)
	epicCommand(t, h.store, CommandIntentEpicRetry, 3)
	h.poll()
	epic, r = h.record()
	if epic.Generation != 2 || len(h.requests) != 2 || len(h.runs) != 1 || len(r.Attempts) != 2 || r.Attempts[1].State != "accepted" || h.requests[0].Work.ID == h.requests[1].Work.ID {
		t.Fatal("explicit retry did not reserve new attempt")
	}
	if h.github.creates[42] != 1 || h.github.creates[1] != 1 || h.github.edits[1] == 0 {
		t.Fatal("retry appended status noise")
	}
}

func TestEpicUncertainAdmissionRecoveryFreezesRequest(t *testing.T) {
	h := newEpicHarness(t)
	h.github.children = []GitHubIssue{nativeIssue(1), nativeIssue(2)}
	h.outcome = "uncertain"
	epicCommand(t, h.store, CommandIntentEpicStart, 1)
	h.poll()
	_, r := h.record()
	if r.Attempts[0].State != "pending" || len(h.runs) != 1 {
		t.Fatal("missing durable uncertain attempt")
	}
	h.restart()
	h.github.children[0].Body = "changed mutable instructions"
	h.github.children[0].Title = "changed title"
	// An explicit control retry may not abandon an uncertain identity.
	epicCommand(t, h.store, CommandIntentEpicPause, 2)
	epicCommand(t, h.store, CommandIntentEpicRetry, 3)
	h.outcome = ""
	h.poll()
	h.poll()
	_, r = h.record()
	if len(h.runs) != 1 || len(h.requests) != 2 || len(r.Attempts) != 1 || r.Attempts[0].State != "accepted" || !reflect.DeepEqual(h.requests[0], h.requests[1]) {
		t.Fatalf("unsafe replay: %+v", h.requests)
	}
}

type acceptedSaveFailure struct{ *SQLiteStateStore }

func (s *acceptedSaveFailure) SaveEpicSchedule(ctx context.Context, repo Repository, epic EpicRecord, r *EpicSchedule) error {
	for _, a := range r.Attempts {
		if a.State == "accepted" {
			return errors.New("crash before accepted state commit")
		}
	}
	return s.SQLiteStateStore.SaveEpicSchedule(ctx, repo, epic, r)
}
func TestEpicRestartAfterAcceptedStateWriteFailure(t *testing.T) {
	h := newEpicHarness(t)
	h.github.children = []GitHubIssue{nativeIssue(1)}
	epicCommand(t, h.store, CommandIntentEpicStart, 1)
	h.poller.State = &acceptedSaveFailure{h.store}
	if err := h.poller.PollOnce(context.Background()); err == nil {
		t.Fatal("expected crash")
	}
	h.restart()
	h.poll()
	h.poll()
	_, r := h.record()
	if len(h.runs) != 1 || len(h.requests) != 2 || r.Attempts[0].AgentRun.Name != "accepted-run" {
		t.Fatal("did not recover accepted identity")
	}
}

func TestEpicStatusFailuresNeverDuplicateAdmission(t *testing.T) {
	for _, failure := range []string{"post", "ambiguous", "reaction", "edit"} {
		t.Run(failure, func(t *testing.T) {
			h := newEpicHarness(t)
			h.github.children = []GitHubIssue{nativeIssue(1), nativeIssue(2)}
			epicCommand(t, h.store, CommandIntentEpicStart, 1)
			epicCommand(t, h.store, CommandIntentEpicStatus, 2)
			h.github.writeErr = failure == "post"
			h.github.ambiguous = failure == "ambiguous"
			h.github.reactionErr = failure == "reaction"
			if failure == "edit" {
				h.outcome = "deferred"
			}
			h.poll()
			if failure == "edit" {
				h.outcome = ""
				h.github.writeErr = true
				h.poll()
			}
			h.restart()
			h.github.writeErr = false
			h.github.ambiguous = false
			h.github.reactionErr = false
			h.poll()
			h.poll()
			if len(h.runs) != 1 {
				t.Fatalf("duplicate runs: %d", len(h.runs))
			}
			wantRequests := 1
			if failure == "edit" {
				wantRequests = 2
			}
			if len(h.requests) != wantRequests {
				t.Fatalf("display failure retried scheduling: %d", len(h.requests))
			}
			for _, n := range []int{1, 2, 42} {
				if h.github.creates[n] != 1 {
					t.Fatalf("duplicate comment #%d: %d", n, h.github.creates[n])
				}
			}
			if !strings.Contains(h.body(1), "nvt/accepted-run") {
				t.Fatal(h.body(1))
			}
			if len(h.github.reactions) != 1 {
				t.Fatalf("reaction not recovered once: %+v", h.github.reactions)
			}
			assertNoPendingEpicStatuses(t, h.store)
		})
	}
}

func TestEpicAcceptedSlotSurvivesControlsAndGraphChanges(t *testing.T) {
	h := newEpicHarness(t)
	h.github.children = []GitHubIssue{nativeIssue(1), nativeIssue(2)}
	epicCommand(t, h.store, CommandIntentEpicStart, 1)
	h.poll()
	epicCommand(t, h.store, CommandIntentEpicPause, 2)
	epicCommand(t, h.store, CommandIntentEpicRetry, 3)
	h.github.children[0].State = "closed"
	h.poll()
	h.restart()
	h.github.children = h.github.children[1:]
	h.poll()
	epicCommand(t, h.store, CommandIntentEpicCancel, 4)
	h.poll()
	if len(h.requests) != 1 || len(h.runs) != 1 {
		t.Fatal("accepted slot released before verified merge support")
	}
	if !strings.Contains(h.body(42), "| #1 | Running |") {
		t.Fatal("removed accepted child disappeared")
	}
}

func TestEpicBlockedPendingAndGraphFailureDoNotSchedule(t *testing.T) {
	h := newEpicHarness(t)
	h.github.children = []GitHubIssue{nativeIssue(1), nativeIssue(2)}
	h.outcome = "deferred"
	epicCommand(t, h.store, CommandIntentEpicStart, 1)
	h.poll()
	h.outcome = ""
	h.github.blockers[1] = []GitHubIssue{nativeIssue(2)}
	h.poll()
	if len(h.requests) != 1 {
		t.Fatal("blocked reserved child submitted")
	}
	h.github.graphErr = true
	h.restart()
	h.poll()
	if len(h.requests) != 1 || !strings.Contains(h.body(42), "**Failed**") {
		t.Fatal("unavailable graph allowed admission")
	}
	h.github.graphErr = false
	h.github.blockers = nil
	h.poll()
	if len(h.requests) != 2 || len(h.runs) != 1 {
		t.Fatal("did not recover reserved attempt")
	}
}

func TestEpicStatusCommandsRefreshOneCurrentProjection(t *testing.T) {
	h := newEpicHarness(t)
	epicCommand(t, h.store, CommandIntentEpicStart, 1)
	epicCommand(t, h.store, CommandIntentEpicStatus, 2)
	h.github.writeErr = true
	h.poll()
	epicCommand(t, h.store, CommandIntentEpicPause, 3)
	epicCommand(t, h.store, CommandIntentEpicStatus, 4)
	h.restart()
	h.github.updatedComments = nil
	h.github.writeErr = false
	h.poll()
	h.poll()
	if h.github.creates[42] != 1 || !strings.Contains(h.body(42), "**paused**") {
		t.Fatal("status snapshot was appended or stale")
	}
	assertNoPendingEpicStatuses(t, h.store)
}

func TestEpicProjectionRejectsHumanMarkerCopy(t *testing.T) {
	h := newEpicHarness(t)
	epicCommand(t, h.store, CommandIntentEpicStart, 1)
	projection, err := h.store.GetEpicProjection(context.Background(), epicTestRepo, 42, 42)
	if err != nil {
		t.Fatal(err)
	}
	h.github.threads[42] = []GitHubIssueComment{{ID: 1, Body: projection.Marker, User: GitHubUser{Type: "User"}}}
	h.poll()
	if h.github.creates[42] != 1 || h.github.edits[42] != 0 {
		t.Fatal("human marker hijacked projection")
	}
}

func TestEpicScheduleCASAndValidation(t *testing.T) {
	h := newEpicHarness(t)
	epic := epicCommand(t, h.store, CommandIntentEpicStart, 1).Epic
	r := EpicSchedule{Version: 1}
	stale := r
	if err := h.store.SaveEpicSchedule(context.Background(), epicTestRepo, *epic, &r); err != nil {
		t.Fatal(err)
	}
	if err := h.store.SaveEpicSchedule(context.Background(), epicTestRepo, *epic, &stale); !errors.Is(err, errEpicStateChanged) {
		t.Fatalf("stale scheduling write: %v", err)
	}
	epicCommand(t, h.store, CommandIntentEpicPause, 2)
	if err := h.store.SaveEpicSchedule(context.Background(), epicTestRepo, *epic, &r); !errors.Is(err, errEpicStateChanged) {
		t.Fatalf("ignored concurrent pause: %v", err)
	}
	if _, err := h.store.db.Exec(`UPDATE epic_scheduling SET record='{"version":99}'`); err != nil {
		t.Fatal(err)
	}
	if err := h.poller.PollOnce(context.Background()); err == nil {
		t.Fatal("corrupt scheduling state did not fail closed")
	}
	if len(h.github.listUpdatedSince) != 0 {
		t.Fatal("polled before validating scheduling state")
	}
}

func TestEpicGraphValidation(t *testing.T) {
	for _, name := range []string{"cycle", "self", "parent", "duplicate-child", "duplicate-id", "duplicate-dependency", "cross-repo-child", "pull-request", "missing-id", "unknown-state", "inconsistent", "wrong-url"} {
		t.Run(name, func(t *testing.T) {
			children := []EpicGraphChild{{Issue: nativeIssue(1)}, {Issue: nativeIssue(2)}}
			switch name {
			case "cycle":
				children[0].Blockers = []GitHubIssue{nativeIssue(2)}
				children[1].Blockers = []GitHubIssue{nativeIssue(1)}
			case "self":
				children[0].Blockers = []GitHubIssue{nativeIssue(1)}
			case "parent":
				children[0].Blockers = []GitHubIssue{nativeIssue(42)}
			case "duplicate-child":
				children[1] = children[0]
			case "duplicate-id":
				children[1].Issue.ID = children[0].Issue.ID
			case "duplicate-dependency":
				children[0].Blockers = []GitHubIssue{nativeIssue(9), nativeIssue(9)}
			case "cross-repo-child":
				children[0].Issue.URL = strings.ReplaceAll(children[0].Issue.URL, "widget", "another")
				children[0].Issue.HTMLURL = strings.ReplaceAll(children[0].Issue.HTMLURL, "widget", "another")
			case "pull-request":
				children[0].Issue.PullRequest = &GitHubPullRequest{}
			case "missing-id":
				children[0].Issue.ID = 0
			case "unknown-state":
				children[0].Issue.State = ""
			case "inconsistent":
				dep := nativeIssue(2)
				dep.State = "closed"
				children[0].Blockers = []GitHubIssue{dep}
			case "wrong-url":
				children[0].Issue.URL = nativeIssue(3).URL
			}
			if err := validateEpicGraph(epicTestRepo, 42, children); err == nil {
				t.Fatal("accepted invalid graph")
			}
		})
	}
	external := nativeIssue(9)
	external.URL = strings.ReplaceAll(external.URL, "widget", "other")
	external.HTMLURL = strings.ReplaceAll(external.HTMLURL, "widget", "other")
	children := []EpicGraphChild{{Issue: nativeIssue(1), Blockers: []GitHubIssue{external}}}
	if err := validateEpicGraph(epicTestRepo, 42, children); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(epicChildBlockReason(children[0]), "acme/other#9") {
		t.Fatal("external open dependency did not block")
	}
	children[0].Blockers[0].State = "closed"
	if epicChildBlockReason(children[0]) != "" {
		t.Fatal("closed external dependency blocked")
	}
}

func TestEpicDenialAfterLostAcceptanceCannotReleaseAttempt(t *testing.T) {
	h := newEpicHarness(t)
	h.github.children = []GitHubIssue{nativeIssue(1), nativeIssue(2)}
	h.outcome = "uncertain"
	epicCommand(t, h.store, CommandIntentEpicStart, 1)
	h.poll()
	h.restart()
	h.outcome = "rejected"
	h.poll()
	_, r := h.record()
	if r.Attempts[0].State != "pending" || !r.Attempts[0].MayBeAccepted || !strings.Contains(h.body(1), "**Failed**") {
		t.Fatal("later denial erased uncertain acceptance")
	}
	epicCommand(t, h.store, CommandIntentEpicPause, 2)
	epicCommand(t, h.store, CommandIntentEpicRetry, 3)
	h.outcome = ""
	h.poll()
	if len(h.runs) != 1 || len(h.requests) != 3 || h.requests[0].Work.ID != h.requests[2].Work.ID {
		t.Fatal("control retry duplicated lost acceptance")
	}
}

func TestEpicDuplicateWithoutRunIdentityKeepsAcceptedSlot(t *testing.T) {
	h := newEpicHarness(t)
	h.github.children = []GitHubIssue{nativeIssue(1), nativeIssue(2)}
	h.outcome = "uncertain"
	epicCommand(t, h.store, CommandIntentEpicStart, 1)
	h.poll()
	h.restart()
	// Both supported authorities can omit AgentRun on duplicate-work.
	h.outcome = "duplicate-without-identity"
	h.poll()
	h.poll()
	_, r := h.record()
	if len(h.runs) != 1 || len(h.requests) != 2 || r.Attempts[0].State != "accepted" || r.Attempts[0].AgentRun != nil || !strings.Contains(h.body(1), "unavailable in admission response") {
		t.Fatal("missing identity released or resubmitted accepted work")
	}
}

func TestEpicDisplayLookupFailureDoesNotBlockOtherWork(t *testing.T) {
	h := newEpicHarness(t)
	h.github.children = []GitHubIssue{nativeIssue(1)}
	epicCommand(t, h.store, CommandIntentEpicStart, 1)
	h.github.ambiguous = true
	h.poll()
	h.restart()
	h.github.ambiguous = false
	h.github.listErr = true
	h.cfg.Repositories = append(h.cfg.Repositories, Repository{Owner: "acme", Name: "second"})
	h.resetPoller()
	h.github.updatedComments = []GitHubIssueComment{{ID: 20, Body: "/nvtagent --help", User: epicTestUser, IssueURL: "https://api.github.com/repos/acme/widget/issues/50", UpdatedAt: h.now}}
	h.poll()
	if h.github.createIssueCommentCalls != 2 || len(h.requests) != 1 {
		t.Fatal("unavailable status thread blocked normal commands or duplicated admission")
	}
	for _, key := range []string{"acme/widget", "acme/second"} {
		cursor, found, err := h.store.GetRepoCursor(context.Background(), key)
		if err != nil || !found || !cursor.Equal(h.now) {
			t.Fatalf("blocked cursor %s: %v %v %v", key, cursor, found, err)
		}
	}
	h.github.listErr = false
	h.github.updatedComments = nil
	h.poll()
	if h.github.creates[42] != 1 || h.github.creates[1] != 1 {
		t.Fatal("lost uncertain display across lookup failure")
	}
}

func TestEpicNoEligibleChildAndControlGates(t *testing.T) {
	for _, mode := range []string{"blocked", "closed", "paused", "canceled", "cycle", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			h := newEpicHarness(t)
			h.github.children = []GitHubIssue{nativeIssue(1)}
			epicCommand(t, h.store, CommandIntentEpicStart, 1)
			switch mode {
			case "blocked":
				h.github.blockers[1] = []GitHubIssue{nativeIssue(9)}
			case "closed":
				h.github.children[0].State = "closed"
			case "paused":
				epicCommand(t, h.store, CommandIntentEpicPause, 2)
			case "canceled":
				epicCommand(t, h.store, CommandIntentEpicCancel, 2)
			case "cycle":
				h.github.children = append(h.github.children, nativeIssue(2))
				h.github.blockers[1] = []GitHubIssue{nativeIssue(2)}
				h.github.blockers[2] = []GitHubIssue{nativeIssue(1)}
			case "revoked":
				h.cfg.Epics.AllowedUserIDs = []int64{5678}
				h.resetPoller()
			}
			h.poll()
			h.restart()
			h.poll()
			if len(h.requests) != 0 {
				t.Fatal("ineligible epic admitted a child")
			}
		})
	}
}
