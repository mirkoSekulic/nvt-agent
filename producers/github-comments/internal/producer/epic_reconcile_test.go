package producer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

type epicFakeGitHub struct {
	verified  map[int]epicVerifiedPR
	phases    map[string]nvtv1alpha1.AgentRunPhase
	poller    *Poller
	recovered *scheduleAdmissionAgentRun
	prs       map[int][]EpicPR
	prErr     error
	fakeGitHubClient
	graph      []EpicGraphNode
	graphErr   error
	displayErr bool
	allow      bool
	displays   map[int]string
}

func (f *epicFakeGitHub) CanControlEpic(context.Context, Repository, GitHubUser) (bool, error) {
	return f.allow, nil
}
func (f *epicFakeGitHub) LoadEpicGraph(context.Context, Repository, int) ([]EpicGraphNode, error) {
	return f.graph, f.graphErr
}
func (f *epicFakeGitHub) UpsertEpicComment(_ context.Context, _ Repository, n int, _ string, body string, _ int64) error {
	if f.displayErr {
		return errors.New("display unavailable")
	}
	f.displays[n] = body
	return nil
}

func epicNode(n int, deps ...int) EpicGraphNode {
	return EpicGraphNode{Issue: GitHubIssue{ID: int64(100 + n), Number: n, State: "open", RepositoryURL: "https://api.github.com/repos/o/r", HTMLURL: fmt.Sprintf("https://github.com/o/r/issues/%d", n)}, Dependencies: deps}
}
func epicFixture(t *testing.T, handler http.HandlerFunc) (*Poller, *epicFakeGitHub, func() Epic, func()) {
	t.Helper()
	ctx := context.Background()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	s := profiledAdmissionSubmitter(server.Client(), server.URL, writeTestAdmissionToken(t, testAdmissionToken("ZXBpYw")))
	cfg := s.config
	cfg.Repositories = []Repository{{Owner: "o", Name: "r"}}
	cfg.CommandPrefixes = []string{"/nvtagent"}
	cfg.AllowedAuthors = []string{"*"}
	cfg.Epics = EpicConfig{Enabled: true, Workflow: "implement-pr", MaxParallel: 1}
	cfg.GitHubApp.AppID = 10
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := OpenSQLiteStateStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	gh := &epicFakeGitHub{allow: true, graph: []EpicGraphNode{epicNode(3, 2), epicNode(2)}, displays: map[int]string{}}
	gh.issues = map[int]GitHubIssue{1: {Number: 1}}
	gh.updatedComments = []GitHubIssueComment{{ID: 1, IssueURL: "https://api.github.com/repos/o/r/issues/1", Body: "/nvtagent epic start", User: GitHubUser{ID: 42, Login: "maintainer"}}}
	p := NewPoller(cfg, gh, s, store, nil)
	p.EpicRuns = gh
	gh.poller = p
	gh.phases = map[string]nvtv1alpha1.AgentRunPhase{}
	read := func() Epic {
		t.Helper()
		es, err := p.State.(*SQLiteStateStore).ListEpics(ctx, cfg.Repositories[0])
		if err != nil || len(es) != 1 {
			t.Fatal(es, err)
		}
		return es[0]
	}
	restart := func() {
		t.Helper()
		if err := p.State.Close(); err != nil {
			t.Fatal(err)
		}
		s, err := OpenSQLiteStateStore(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		p.State = s
	}
	t.Cleanup(func() { p.State.Close() })
	return p, gh, read, restart
}
func acceptedEpic(w http.ResponseWriter) {
	w.WriteHeader(201)
	fmt.Fprint(w, `{"scheduled":true,"agentRun":{"namespace":"nvt","name":"child-run"}}`)
}

func TestEpicScheduleRestartAndDisplayFailure(t *testing.T) {
	calls := 0
	p, gh, read, restart := epicFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req profiledScheduleAdmissionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if req.Workflow != "implement-pr" || req.Work.Principal.Subject != "42" || req.Work.URL != "https://github.com/o/r/issues/2" {
			t.Errorf("bad request %#v", req)
		}
		acceptedEpic(w)
	})
	gh.displayErr = true
	if p.PollOnce(context.Background()) == nil {
		t.Fatal("expected display failure")
	}
	e := read()
	if calls != 1 || e.Children[0].Run == nil || e.Children[1].State != "Blocked" {
		t.Fatal(calls, e)
	}
	restart()
	gh.displayErr = false
	for range 3 {
		if err := p.PollOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 || len(gh.displays) != 3 || !strings.Contains(gh.displays[2], "nvt/child-run") || !strings.Contains(gh.displays[3], "verified merge of #2") {
		t.Fatal(calls, gh.displays)
	}
}
func TestEpicUncertainAdmissionReplaysExactRequest(t *testing.T) {
	var requests []profiledScheduleAdmissionRequest
	p, gh, read, restart := epicFixture(t, func(w http.ResponseWriter, r *http.Request) {
		var req profiledScheduleAdmissionRequest
		json.NewDecoder(r.Body).Decode(&req)
		requests = append(requests, req)
		if len(requests) == 1 {
			w.WriteHeader(429)
			fmt.Fprint(w, `{"scheduled":false,"reason":"max-parallelism-reached"}`)
			return
		}
		w.WriteHeader(202)
		fmt.Fprint(w, `{"scheduled":false,"reason":"duplicate-work","agentRun":{"namespace":"nvt","name":"existing"}}`)
	})
	if p.PollOnce(context.Background()) == nil {
		t.Fatal("uncertain response")
	}
	restart()
	gh.graph[1].Issue.Body = "edited after admission"
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 2 || requests[0].Work.ID != requests[1].Work.ID || requests[0].Input.Prompt != requests[1].Input.Prompt || read().Children[0].Run.Name != "existing" {
		t.Fatal(requests, read())
	}
}
func TestEpicAdmissionRejectionPauses(t *testing.T) {
	calls := 0
	p, _, read, _ := epicFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(403)
		fmt.Fprint(w, `{"scheduled":false,"reason":"principal-not-eligible"}`)
	})
	_ = p.PollOnce(context.Background())
	e := read()
	if e.State != "paused" || e.Children[0].State != "Failed" || e.Children[0].Run != nil {
		t.Fatal(e)
	}
	_ = p.PollOnce(context.Background())
	if calls != 1 {
		t.Fatal(calls)
	}
}
func TestEpicDisabledAndUnauthorizedAreInert(t *testing.T) {
	p, gh, _, _ := epicFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected admission") })
	p.Config.Epics.Enabled = false
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.Config.Epics.Enabled = true
	gh.allow = false
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	es, err := p.State.(*SQLiteStateStore).ListEpics(context.Background(), p.Config.Repositories[0])
	if err != nil || len(es) != 0 {
		t.Fatal(es, err)
	}
}
func TestEpicGraphValidationAndParallelEligibility(t *testing.T) {
	repo := Repository{Owner: "o", Name: "r"}
	for _, graph := range [][]EpicGraphNode{nil, {epicNode(2, 2)}, {epicNode(2, 3)}, {epicNode(2, 3), epicNode(3, 2)}, {epicNode(2), epicNode(2)}, {epicNode(1)}, {epicNode(2, 3, 3), epicNode(3)}} {
		if validateEpicGraph(repo, 1, graph) == nil {
			t.Fatal("accepted", graph)
		}
	}
	foreign := epicNode(2)
	foreign.Issue.RepositoryURL = "https://api.github.com/repos/other/r"
	if validateEpicGraph(repo, 1, []EpicGraphNode{foreign}) == nil {
		t.Fatal("cross repository")
	}
	e := Epic{Repository: repo, Parent: 1}
	if err := installEpicGraph(&e, []EpicGraphNode{epicNode(4), epicNode(3, 2), epicNode(2)}); err != nil {
		t.Fatal(err)
	}
	projectEligibility(&e)
	if e.Children[0].State != "Queued" || e.Children[1].State != "Blocked" || e.Children[2].State != "Queued" {
		t.Fatal(e)
	}
	e.Children[0].Issue.State = "closed"
	projectEligibility(&e)
	if e.Children[1].State != "Blocked" {
		t.Fatal("closure unblocked child")
	}
}

func (f *epicFakeGitHub) LinkedEpicPRs(_ context.Context, _ Repository, n int) ([]EpicPR, error) {
	return f.prs[n], f.prErr
}

func (f *epicFakeGitHub) VerifyEpicPR(_ context.Context, _ Repository, n int) (epicVerifiedPR, error) {
	if pr, ok := f.verified[n]; ok {
		return pr, nil
	}
	b := false
	pr := epicVerifiedPR{NodeID: fmt.Sprintf("PR_%d", n), Number: n, State: "open", Merged: &b}
	pr.Base.Repo.FullName = "o/r"
	return pr, nil
}
func (f *epicFakeGitHub) FindEpicRun(context.Context, Repository, string) (*scheduleAdmissionAgentRun, error) {
	return f.recovered, nil
}
func (f *epicFakeGitHub) Get(ctx context.Context, ns, name string) (*nvtv1alpha1.AgentRun, error) {
	es, err := f.poller.State.(*SQLiteStateStore).ListEpics(ctx, Repository{Owner: "o", Name: "r"})
	if err != nil {
		return nil, err
	}
	var key string
	for _, e := range es {
		for _, c := range e.Children {
			if c.Run != nil && c.Run.Name == name || c.AdmissionPending && f.recovered != nil && name == f.recovered.Name {
				key = c.Key
			}
		}
	}
	return &nvtv1alpha1.AgentRun{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID("uid-" + name), Annotations: map[string]string{"nvt.dev/work-id": key, "nvt.dev/work-repository": "o/r"}}, Status: nvtv1alpha1.AgentRunStatus{Phase: f.phases[name]}}, nil
}
