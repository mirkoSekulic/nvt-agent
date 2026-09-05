package producer

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

func epicCommand(t *testing.T, p *Poller, id int64, action string) {
	t.Helper()
	if err := p.State.(*SQLiteStateStore).ApplyEpicCommand(context.Background(), p.Config.Repositories[0], 1, GitHubUser{ID: 42, Login: "maintainer"}, id, action, p.Config.Epics); err != nil {
		t.Fatal(err)
	}
}
func setVerified(gh *epicFakeGitHub, n int, merged bool) {
	pr := epicVerifiedPR{NodeID: fmt.Sprintf("PR_%d", n), Number: n, State: "closed", Merged: &merged}
	pr.Base.Repo.FullName = "o/r"
	if merged {
		date := "2026-09-05T12:00:00Z"
		pr.MergedAt = &date
	}
	if gh.verified == nil {
		gh.verified = map[int]epicVerifiedPR{}
	}
	gh.verified[n] = pr
}
func TestEpicSequentialMergeEndToEnd(t *testing.T) {
	calls := 0
	p, gh, read, restart := epicFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(201)
		fmt.Fprintf(w, `{"scheduled":true,"agentRun":{"namespace":"nvt","name":"run-%d"}}`, calls)
	})
	poll := func() {
		t.Helper()
		if err := p.PollOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	poll()
	first := read().Children[0]
	gh.prs = map[int][]EpicPR{2: {epicPRFor(first, 9)}}
	poll()
	restart()
	poll()
	if calls != 1 {
		t.Fatal("open PR advanced")
	}
	// A successful AgentRun and closed issue are not merge evidence.
	gh.phases["run-1"] = nvtv1alpha1.AgentRunPhaseCompleted
	gh.graph[1].Issue.State = "closed"
	poll()
	if calls != 1 {
		t.Fatal("run completion advanced")
	}
	setVerified(gh, 9, true)
	restart()
	gh.displayErr = true
	if p.PollOnce(context.Background()) == nil {
		t.Fatal("expected display failure")
	}
	if calls != 2 || read().Children[0].State != "Completed" {
		t.Fatal(calls, read())
	}
	restart()
	gh.displayErr = false
	poll()
	poll()
	if calls != 2 {
		t.Fatal("replayed merge duplicated child")
	}
	second := read().Children[1]
	gh.prs[3] = []EpicPR{epicPRFor(second, 10)}
	setVerified(gh, 10, true)
	poll()
	if read().State != "completed" || calls != 2 {
		t.Fatal(read(), calls)
	}
	restart()
	poll()
	if read().State != "completed" || calls != 2 {
		t.Fatal("terminal replay")
	}
}
func TestEpicClosedUnmergedRetryRequiresTerminalRunAndNewAttempt(t *testing.T) {
	calls := 0
	p, gh, read, _ := epicFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(201)
		fmt.Fprintf(w, `{"scheduled":true,"agentRun":{"namespace":"nvt","name":"run-%d"}}`, calls)
	})
	_ = p.PollOnce(context.Background())
	first := read().Children[0]
	pr := epicPRFor(first, 9)
	pr.State = "CLOSED"
	gh.prs = map[int][]EpicPR{2: {pr}}
	setVerified(gh, 9, false)
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if read().State != "paused" || calls != 1 {
		t.Fatal(read())
	}
	epicCommand(t, p, 2, "resume")
	_ = p.PollOnce(context.Background())
	if calls != 1 {
		t.Fatal("resume retried failed child")
	}
	epicCommand(t, p, 3, "retry")
	_ = p.PollOnce(context.Background())
	if calls != 1 {
		t.Fatal("retry duplicated live run")
	}
	gh.phases["run-1"] = nvtv1alpha1.AgentRunPhaseCompleted
	epicCommand(t, p, 4, "retry")
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	c := read().Children[0]
	if calls != 2 || c.Attempt != 2 || c.Key == first.Key || c.PR != nil || len(c.History) != 1 || read().Children[1].Run != nil {
		t.Fatal(c, calls)
	}
}
func TestEpicRunFailureRecoveryAndAmbiguityRetry(t *testing.T) {
	t.Run("run failure", func(t *testing.T) {
		calls := 0
		p, gh, read, restart := epicFixture(t, func(w http.ResponseWriter, r *http.Request) { calls++; acceptedEpic(w) })
		_ = p.PollOnce(context.Background())
		gh.phases["child-run"] = nvtv1alpha1.AgentRunPhaseFailed
		_ = p.PollOnce(context.Background())
		if read().State != "paused" {
			t.Fatal(read())
		}
		restart()
		epicCommand(t, p, 2, "retry")
		if err := p.PollOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		if calls != 2 || read().Children[0].Attempt != 2 {
			t.Fatal(read(), calls)
		}
	})
	t.Run("ambiguity", func(t *testing.T) {
		calls := 0
		p, gh, read, _ := epicFixture(t, func(w http.ResponseWriter, r *http.Request) { calls++; acceptedEpic(w) })
		_ = p.PollOnce(context.Background())
		c := read().Children[0]
		gh.prs = map[int][]EpicPR{2: {epicPRFor(c, 9), epicPRFor(c, 10)}}
		_ = p.PollOnce(context.Background())
		gh.prs[2] = gh.prs[2][:1]
		epicCommand(t, p, 2, "retry")
		if err := p.PollOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		if calls != 1 || read().State != "active" || read().Children[0].PR == nil {
			t.Fatal(read(), calls)
		}
	})
}
func TestEpicPauseCancelAndGraphChange(t *testing.T) {
	calls := 0
	p, gh, read, _ := epicFixture(t, func(w http.ResponseWriter, r *http.Request) { calls++; acceptedEpic(w) })
	_ = p.PollOnce(context.Background())
	epicCommand(t, p, 2, "pause")
	c := read().Children[0]
	gh.prs = map[int][]EpicPR{2: {epicPRFor(c, 9)}}
	setVerified(gh, 9, true)
	_ = p.PollOnce(context.Background())
	if calls != 1 || read().Children[0].State != "Completed" || read().State != "paused" {
		t.Fatal(read())
	}
	gh.graph = []EpicGraphNode{epicNode(2)}
	epicCommand(t, p, 3, "resume")
	_ = p.PollOnce(context.Background())
	if read().State != "paused" || calls != 1 {
		t.Fatal("deleted child admitted")
	}
	gh.graph = []EpicGraphNode{epicNode(2), epicNode(3, 2)}
	epicCommand(t, p, 4, "cancel")
	epicCommand(t, p, 5, "resume")
	epicCommand(t, p, 6, "retry")
	_ = p.PollOnce(context.Background())
	if calls != 1 || read().State != "cancelled" {
		t.Fatal("cancel restarted")
	}
}
func TestEpicLostAdmissionRecoversIdentityWithoutResubmission(t *testing.T) {
	calls := 0
	p, gh, read, restart := epicFixture(t, func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(503) })
	if p.PollOnce(context.Background()) == nil {
		t.Fatal("expected lost response")
	}
	first := read().Children[0]
	restart()
	gh.recovered = &scheduleAdmissionAgentRun{Namespace: "nvt", Name: "accepted-before-crash"}
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || read().Children[0].Key != first.Key || read().Children[0].Run.Name != "accepted-before-crash" {
		t.Fatal(read(), calls)
	}
}
func TestEpicUnrecoverableAdmissionFailsClosed(t *testing.T) {
	calls := 0
	p, _, read, restart := epicFixture(t, func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(503) })
	_ = p.PollOnce(context.Background())
	restart()
	_ = p.PollOnce(context.Background())
	epicCommand(t, p, 2, "retry")
	_ = p.PollOnce(context.Background())
	if calls != 1 || read().State != "paused" {
		t.Fatal("uncertain attempt duplicated", read())
	}
}
func TestEpicPermanentAndTransientGitHubErrors(t *testing.T) {
	for _, status := range []int{404, 410, 422, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			p, gh, read, _ := epicFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected admission") })
			gh.graphErr = &epicAPIError{Status: status}
			_ = p.PollOnce(context.Background())
			want := "active"
			if status < 429 {
				want = "paused"
			}
			if read().State != want {
				t.Fatal(read())
			}
		})
	}
}
func TestEpicParallelismOnlyAdmitsIndependentChildren(t *testing.T) {
	calls := 0
	p, gh, read, _ := epicFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(201)
		fmt.Fprintf(w, `{"scheduled":true,"agentRun":{"namespace":"nvt","name":"run-%d"}}`, calls)
	})
	p.Config.Epics.MaxParallel = 2
	gh.graph = []EpicGraphNode{epicNode(4), epicNode(3, 2), epicNode(2)}
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	e := read()
	if calls != 2 || e.Children[1].Run != nil || e.Children[2].Run == nil {
		t.Fatal(e, calls)
	}
}

func TestEpicCancelRemainsTerminalAfterObservationError(t *testing.T) {
	calls := 0
	p, gh, read, _ := epicFixture(t, func(w http.ResponseWriter, r *http.Request) { calls++; acceptedEpic(w) })
	_ = p.PollOnce(context.Background())
	epicCommand(t, p, 2, "cancel")
	gh.prErr = &epicAPIError{Status: 404}
	_ = p.PollOnce(context.Background())
	epicCommand(t, p, 3, "resume")
	gh.prErr = nil
	_ = p.PollOnce(context.Background())
	if calls != 1 || read().State != "cancelled" {
		t.Fatal(read(), calls)
	}
}

func TestEpicPinnedAdmissionScopeAndFailureRetry(t *testing.T) {
	calls := 0
	p, _, read, _ := epicFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(403)
			fmt.Fprint(w, `{"scheduled":false,"reason":"principal-not-eligible"}`)
			return
		}
		acceptedEpic(w)
	})
	_ = p.PollOnce(context.Background())
	if read().State != "paused" {
		t.Fatal(read())
	}
	epicCommand(t, p, 2, "retry")
	_ = p.PollOnce(context.Background())
	if calls != 2 || read().Children[0].Attempt != 2 {
		t.Fatal(read())
	}
	p.Submitter.config.Submission.ScheduleName = "different"
	_ = p.PollOnce(context.Background())
	if read().State != "paused" {
		t.Fatal("schedule scope changed")
	}
}

func TestEpicDuplicateAdmissionWithoutIdentityRecoversRetainedRun(t *testing.T) {
	calls := 0
	p, gh, read, restart := epicFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(202)
		fmt.Fprint(w, `{"scheduled":false,"reason":"duplicate-work"}`)
	})
	if p.PollOnce(context.Background()) == nil {
		t.Fatal("missing run identity accepted")
	}
	restart()
	gh.recovered = &scheduleAdmissionAgentRun{Namespace: "nvt", Name: "retained"}
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || read().Children[0].Run.Name != "retained" {
		t.Fatal(calls, read())
	}
}

func TestEpicRejectsWrongMergeIdentityAndIncompleteEvidence(t *testing.T) {
	for _, kind := range []string{"identity", "missing-merge", "missing-time", "wrong-repository"} {
		t.Run(kind, func(t *testing.T) {
			p, gh, read, _ := epicFixture(t, func(w http.ResponseWriter, r *http.Request) { acceptedEpic(w) })
			_ = p.PollOnce(context.Background())
			c := read().Children[0]
			gh.prs = map[int][]EpicPR{2: {epicPRFor(c, 9)}}
			setVerified(gh, 9, true)
			pr := gh.verified[9]
			switch kind {
			case "identity":
				pr.NodeID = "PR_other"
			case "missing-merge":
				pr.Merged = nil
			case "missing-time":
				pr.MergedAt = nil
			case "wrong-repository":
				pr.Base.Repo.FullName = "other/repo"
			}
			gh.verified[9] = pr
			if p.PollOnce(context.Background()) == nil {
				t.Fatal("accepted invalid merge evidence")
			}
			if read().State != "paused" || read().Children[1].Run != nil || read().Children[0].State == "Completed" {
				t.Fatal(read())
			}
		})
	}
}

func TestEpicLostAdmissionRecoversEvenIfChildAlreadyClosed(t *testing.T) {
	calls := 0
	p, gh, read, restart := epicFixture(t, func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(503) })
	_ = p.PollOnce(context.Background())
	c := read().Children[0]
	restart()
	gh.recovered = &scheduleAdmissionAgentRun{Namespace: "nvt", Name: "recovered"}
	gh.graph[1].Issue.State = "closed"
	gh.prs = map[int][]EpicPR{2: {epicPRFor(c, 9)}}
	setVerified(gh, 9, true)
	// The next child may be submitted; the recovered first child must not be repeated.
	_ = p.PollOnce(context.Background())
	e := read()
	if e.Children[0].State != "Completed" || e.Children[0].Run.Name != "recovered" || calls != 2 {
		t.Fatal(e, calls)
	}
}
