package producer

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
)

func TestEpicCommandsAndConfig(t *testing.T) {
	for _, action := range []string{"start", "status", "pause", "resume", "cancel", "retry"} {
		c, ok := ParseCommand("/nvtagent epic "+action, []string{"/nvtagent"})
		if !ok || c.Intent != CommandIntentEpic || c.EpicAction != action {
			t.Fatal(action, c)
		}
		for _, suffix := range []string{" -- workflow=evil", "\nworkflow: evil", " extra"} {
			if _, ok := ParseCommand("/nvtagent epic "+action+suffix, []string{"/nvtagent"}); ok {
				t.Fatal("accepted override", suffix)
			}
		}
	}
	var ep EpicConfig
	if err := json.Unmarshal([]byte(`{"enabled":true,"profile":"evil"}`), &ep); err == nil {
		t.Fatal("unknown field")
	}
	s := SubmissionConfig{Mode: SubmissionModeScheduleAdmission, AdmissionMode: AdmissionModeProfiled, Backend: SubmissionBackendKubernetes}
	for _, c := range []EpicConfig{{Workflow: "x"}, {Enabled: true}, {Enabled: true, Workflow: "Bad"}, {Enabled: true, Workflow: "x", MaxParallel: -1}, {Enabled: true, Workflow: "x", MaxParallel: 17}} {
		if c.validate(s) == nil {
			t.Fatal(c)
		}
	}
	ep = EpicConfig{Enabled: true, Workflow: "implement-pr"}
	if err := ep.validate(s); err != nil || ep.MaxParallel != 1 {
		t.Fatal(ep, err)
	}
	s.Backend = SubmissionBackendLocal
	if ep.validate(s) == nil {
		t.Fatal("unsupported backend")
	}
}

func TestEpicCommandTransactionsAndRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := OpenSQLiteStateStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{Owner: "o", Name: "r"}
	user := GitHubUser{ID: 42, Login: "maintainer"}
	cfg := EpicConfig{Enabled: true, Workflow: "implement-pr", MaxParallel: 1}
	apply := func(id int64, action string, u GitHubUser) {
		t.Helper()
		if err := s.ApplyEpicCommand(ctx, repo, 1, u, id, action, cfg); err != nil {
			t.Fatal(err)
		}
	}
	read := func() Epic {
		t.Helper()
		es, err := s.ListEpics(ctx, repo)
		if err != nil || len(es) != 1 {
			t.Fatal(es, err)
		}
		return es[0]
	}
	apply(1, "start", user)
	initial := read()
	apply(1, "cancel", user)
	if read().Version != initial.Version {
		t.Fatal("duplicate edited command applied")
	}
	apply(2, "pause", GitHubUser{ID: 43, Login: "other"})
	if read().State != "active" {
		t.Fatal("ownership changed")
	}
	apply(3, "pause", user)
	if read().State != "paused" {
		t.Fatal("pause")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenSQLiteStateStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if read().State != "paused" || read().Principal.ID != 42 {
		t.Fatal("restart")
	}
	apply(4, "resume", user)
	stale := read()
	current := read()
	current.Reason = "test"
	if err := s.SaveEpic(ctx, &current); err != nil {
		t.Fatal(err)
	}
	if s.SaveEpic(ctx, &stale) != errEpicConflict {
		t.Fatal("stale writer accepted")
	}
	bad := cfg
	bad.Workflow = ""
	if s.ApplyEpicCommand(ctx, repo, 2, user, 5, "start", bad) == nil {
		t.Fatal("bad transaction accepted")
	}
	if err := s.ApplyEpicCommand(ctx, repo, 2, user, 5, "start", cfg); err != nil {
		t.Fatal("receipt was not rolled back", err)
	}
	if epicAttemptKey(initial, 2, 1) == epicAttemptKey(initial, 2, 2) {
		t.Fatal("attempt keys collide")
	}
	apply(6, "cancel", user)
	apply(7, "resume", user)
	if readAll, _ := s.ListEpics(ctx, repo); readAll[0].State != "cancelled" {
		t.Fatal("cancel resumed")
	}
}

func TestEpicStrictConfigurationAndPersistedState(t *testing.T) {
	for _, raw := range []string{`null`, `{"enabled":null}`, `{"enabled":true,"workflow":"x","maxParallel":0}`, `{"enabled":true,"workflow":"x","maxParallel":1.5}`, `{"enabled":true,"workflow":"x","maxParallel":null}`} {
		var cfg EpicConfig
		if json.Unmarshal([]byte(raw), &cfg) == nil {
			t.Fatal("accepted malformed config", raw)
		}
	}
	p, _, read, _ := epicFixture(t, func(w http.ResponseWriter, r *http.Request) { acceptedEpic(w) })
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	initial := read()
	for _, mutate := range []func(*Epic){func(e *Epic) { e.Children[0].State = "Completed" }, func(e *Epic) { e.Children[0].Key = "other" }, func(e *Epic) { e.Children[0].Failure = "unknown" }, func(e *Epic) { e.Children[0].Dependencies = []int{3} }} {
		data, _ := json.Marshal(initial)
		var e Epic
		json.Unmarshal(data, &e)
		mutate(&e)
		if e.validate() == nil {
			t.Fatal("invalid durable state accepted", e)
		}
	}
	var e Epic
	if decodeEpic([]byte(`{"Unknown":true}`), &e) == nil {
		t.Fatal("unknown durable field")
	}
}
