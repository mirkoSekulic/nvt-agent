package producer

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func nativePR(number int) EpicPRCandidate {
	return EpicPRCandidate{ID: fmt.Sprintf("PR_%d", number), Number: number, URL: fmt.Sprintf("https://github.com/acme/widget/pull/%d", number), State: "OPEN", Body: "Implementation\n\nCloses #1\nPart of #42\n", Repository: EpicPRRepository{ID: "R_widget", NameWithOwner: "acme/widget"}}
}

func TestEpicUniquePRAssociationSurvivesRestartAndDisplayFailure(t *testing.T) {
	h := newEpicHarness(t)
	h.github.children = []GitHubIssue{nativeIssue(1), nativeIssue(2)}
	h.github.prs = []EpicPRCandidate{nativePR(50), nativePR(50)} // Duplicate pages are one immutable PR.
	h.github.writeErr = true
	epicCommand(t, h.store, CommandIntentEpicStart, 1)
	h.poll()
	_, record := h.record()
	association := record.Attempts[0].PR
	if association == nil || association.NodeID != "PR_50" || association.RepositoryID != "R_widget" || association.Repository != "acme/widget" || association.ObservedAt.IsZero() {
		t.Fatalf("missing durable identity: %+v", association)
	}
	calls := h.github.prCalls
	h.restart()
	h.github.writeErr = false
	// Once established, the identity survives loss of linkage, a different PR,
	// issue closure/removal, and GitHub outages. No merge-driven advancement.
	h.github.prs = []EpicPRCandidate{nativePR(51)}
	h.github.prErr = true
	h.github.children = []GitHubIssue{nativeIssue(2)}
	h.poll()
	_, recovered := h.record()
	if !reflect.DeepEqual(association, recovered.Attempts[0].PR) || h.github.prCalls != calls || len(h.requests) != 1 {
		t.Fatal("replaced association or advanced accepted work after restart")
	}
	for _, issue := range []int{1, 42} {
		if body := h.body(issue); !strings.Contains(body, "PR open") || !strings.Contains(body, association.URL) {
			t.Fatal(body)
		}
	}
	if !strings.Contains(h.body(1), "nvt/accepted-run") {
		t.Fatal("lost AgentRun projection")
	}
}

func TestEpicNoNativeCandidateIgnoresCompletionProse(t *testing.T) {
	for _, claim := range []string{"Done; PR https://github.com/acme/widget/pull/50", "Closes #1\nPart of #42\nImplementation completed and merged"} {
		t.Run(claim, func(t *testing.T) {
			h := newEpicHarness(t)
			child := nativeIssue(1)
			child.Body = claim
			h.github.children = []GitHubIssue{child, nativeIssue(2)}
			h.github.threads[1] = []GitHubIssueComment{{ID: 10, Body: claim, User: GitHubUser{Type: "User", Login: "maintainer"}}, {ID: 11, Body: claim, User: GitHubUser{Type: "Bot", Login: "agent[bot]"}}}
			epicCommand(t, h.store, CommandIntentEpicStart, 1)
			h.poll()
			h.restart()
			h.poll()
			epic, record := h.record()
			status, _, _ := epicChildStatus(epic, record, record.Children[0])
			if record.Attempts[0].PR != nil || status != "Running" || epic.State != EpicPending || len(h.requests) != 1 {
				t.Fatalf("prose became authority: %+v", record)
			}
			if !strings.Contains(h.body(42), "| #1 | Running |") {
				t.Fatal(h.body(42))
			}
		})
	}
}

func TestEpicAmbiguousPRsPauseDurablyAndRequireExplicitResume(t *testing.T) {
	h := newEpicHarness(t)
	h.github.children = []GitHubIssue{nativeIssue(1), nativeIssue(2)}
	h.github.prs = []EpicPRCandidate{nativePR(51), nativePR(50)}
	h.github.writeErr = true
	epicCommand(t, h.store, CommandIntentEpicStart, 1)
	h.poll()
	epic, record := h.record()
	if epic.State != EpicPaused || record.PRAmbiguity == "" || record.Attempts[0].PR != nil {
		t.Fatalf("guessed mapping: %+v %+v", epic, record)
	}
	h.restart()
	h.github.writeErr = false
	h.poll()
	for _, issue := range []int{1, 42} {
		body := h.body(issue)
		if !strings.Contains(body, "multiple linked open PRs") || !strings.Contains(body, nativePR(50).URL) || !strings.Contains(body, nativePR(51).URL) || !strings.Contains(body, "resume") {
			t.Fatal(body)
		}
	}
	epicCommand(t, h.store, CommandIntentEpicResume, 2)
	h.poll()
	epic, _ = h.record()
	if epic.State != EpicPaused {
		t.Fatal("resume bypassed unresolved ambiguity")
	}
	h.github.prErr = true
	h.poll()
	_, record = h.record()
	if record.PRAmbiguity == "" {
		t.Fatal("unavailable read cleared ambiguity")
	}
	h.github.prErr = false
	h.github.prs = []EpicPRCandidate{nativePR(50)}
	h.poll()
	epic, record = h.record()
	if epic.State != EpicPaused || record.PRAmbiguity != "" || record.Attempts[0].PR == nil {
		t.Fatal("resolution lost association or resumed automatically")
	}
	epicCommand(t, h.store, CommandIntentEpicResume, 3)
	h.poll()
	if len(h.requests) != 1 {
		t.Fatal("association released admission slot")
	}
}

func TestEpicPRCandidateValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*EpicPRCandidate)
		wantErr bool
	}{
		{"closed", func(p *EpicPRCandidate) { p.State = "CLOSED" }, false},
		{"merged", func(p *EpicPRCandidate) { p.State = "MERGED" }, false},
		{"other-repo", func(p *EpicPRCandidate) { p.Repository.NameWithOwner = "other/widget" }, false},
		{"missing-parent", func(p *EpicPRCandidate) { p.Body = "Closes #1" }, false},
		{"wrong-parent", func(p *EpicPRCandidate) { p.Body = "Closes #1\nPart of #420" }, false},
		{"pasted-url", func(p *EpicPRCandidate) { p.Body = "https://github.com/acme/widget/issues/42" }, false},
		{"missing-node", func(p *EpicPRCandidate) { p.ID = "" }, true},
		{"missing-repo-id", func(p *EpicPRCandidate) { p.Repository.ID = "" }, true},
		{"wrong-url", func(p *EpicPRCandidate) { p.URL = "https://github.com/other/widget/pull/50" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := nativePR(50)
			tc.mutate(&candidate)
			matches, err := epicPRCandidates(epicTestRepo, 42, nativeIssue(1), []EpicPRCandidate{candidate}, epicTestTime)
			if (err != nil) != tc.wantErr || len(matches) != 0 {
				t.Fatalf("invalid candidate accepted: %+v %v", matches, err)
			}
		})
	}
	conflict := nativePR(50)
	conflict.ID = "another-node"
	if _, err := epicPRCandidates(epicTestRepo, 42, nativeIssue(1), []EpicPRCandidate{nativePR(50), conflict}, epicTestTime); err == nil {
		t.Fatal("accepted conflicting immutable identities")
	}
}

func TestEpicPRPersistenceRejectsReplacementAndStalePause(t *testing.T) {
	h := newEpicHarness(t)
	h.github.children = []GitHubIssue{nativeIssue(1)}
	h.github.prs = []EpicPRCandidate{nativePR(50)}
	epicCommand(t, h.store, CommandIntentEpicStart, 1)
	h.poll()
	for _, mutate := range []func(*EpicSchedule){
		func(r *EpicSchedule) { r.Attempts[0].PR = nil },
		func(r *EpicSchedule) { r.Attempts[0].PR.NodeID = "PR_replacement" },
		func(r *EpicSchedule) { r.Attempts = nil },
	} {
		epic, record := h.record()
		mutate(&record)
		if err := h.store.SaveEpicSchedule(context.Background(), epicTestRepo, epic, &record); err == nil {
			t.Fatal("rewrote established association")
		}
	}
	// A concurrent cancel must win over an association or automatic pause.
	other := newEpicHarness(t)
	other.github.children = []GitHubIssue{nativeIssue(1)}
	epicCommand(t, other.store, CommandIntentEpicStart, 1)
	other.poll()
	stale, record := other.record()
	epicCommand(t, other.store, CommandIntentEpicCancel, 2)
	record.PRAmbiguity = "multiple linked PRs"
	if err := other.store.PauseEpicForPRAmbiguity(context.Background(), epicTestRepo, &stale, &record); err == nil {
		t.Fatal("stale pause overwrote cancel")
	}
	current, saved := other.record()
	if current.State != EpicCanceled || saved.PRAmbiguity != "" {
		t.Fatal("partial ambiguity commit")
	}
}

func TestEpicPRStateUpgradePreservesReviewedRequests(t *testing.T) {
	h := newEpicHarness(t)
	h.github.children = []GitHubIssue{nativeIssue(1)}
	epicCommand(t, h.store, CommandIntentEpicStart, 1)
	h.poll()
	_, record := h.record()
	record.Version = 1
	record.Attempts[0].PRReason = ""
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.db.Exec(`UPDATE epic_scheduling SET record=?`, string(raw)); err != nil {
		t.Fatal(err)
	}
	h.restart()
	_, upgraded := h.record()
	if upgraded.Version != 2 || !reflect.DeepEqual(record.Attempts, upgraded.Attempts) {
		t.Fatal("upgrade changed frozen requests")
	}
	h.github.prs = []EpicPRCandidate{nativePR(50)}
	h.poll()
	_, upgraded = h.record()
	if upgraded.Attempts[0].PR == nil || len(h.requests) != 1 {
		t.Fatal("reviewed accepted work was rescheduled or not associated")
	}
}

func TestEpicPromptContractLeavesOrdinaryPRCreateUnchanged(t *testing.T) {
	child := nativeIssue(1)
	ordinary := buildPrompt(epicTestRepo, child, nil, GitHubIssueComment{}, Command{Intent: CommandIntentPRCreate})
	epic := buildEpicPrompt(epicTestRepo, child, nil, GitHubIssueComment{}, 42)
	for _, text := range []string{"Closes #1", "Part of #42", "exactly one delivery PR", "Do not merge"} {
		if !strings.Contains(epic, text) || strings.Contains(ordinary, text) {
			t.Fatalf("epic contract leaked or missing: %s", text)
		}
	}
	if !strings.Contains(ordinary, "Refs #1") || !strings.Contains(epic, "github-watch") || !strings.HasPrefix(epic, ordinary) {
		t.Fatal("ordinary PR create contract changed")
	}
}

func TestEpicPRURLUsesNativeSourceHost(t *testing.T) {
	child := nativeIssue(1)
	child.HTMLURL = "https://github.example.com/Acme/Widget/issues/1"
	pr := nativePR(50)
	pr.Repository.NameWithOwner = "Acme/Widget"
	pr.URL = "https://github.example.com/Acme/Widget/pull/50"
	matches, err := epicPRCandidates(epicTestRepo, 42, child, []EpicPRCandidate{pr}, epicTestTime)
	if err != nil || len(matches) != 1 || matches[0].URL != pr.URL || matches[0].Repository != "acme/widget" {
		t.Fatalf("lost enterprise/case identity: %+v %v", matches, err)
	}
	pr.URL = "https://github.com/Acme/Widget/pull/50"
	if _, err := epicPRCandidates(epicTestRepo, 42, child, []EpicPRCandidate{pr}, epicTestTime); err == nil {
		t.Fatal("accepted PR on a different GitHub host")
	}
}

func TestEpicPRRestartRejectsCorruptAssociation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*EpicSchedule)
	}{
		{"node-id", func(r *EpicSchedule) { r.Attempts[0].PR.NodeID = "" }},
		{"repository-id", func(r *EpicSchedule) { r.Attempts[0].PR.RepositoryID = "" }},
		{"repository", func(r *EpicSchedule) { r.Attempts[0].PR.Repository = "other/widget" }},
		{"url", func(r *EpicSchedule) { r.Attempts[0].PR.URL = nativePR(51).URL }},
		{"observation", func(r *EpicSchedule) { r.Attempts[0].PR.ObservedAt = epicTestTime }},
		{"unaccepted", func(r *EpicSchedule) { r.Attempts[0].State = "pending" }},
		{"old-version", func(r *EpicSchedule) { r.Version = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newEpicHarness(t)
			h.github.children = []GitHubIssue{nativeIssue(1)}
			h.github.prs = []EpicPRCandidate{nativePR(50)}
			epicCommand(t, h.store, CommandIntentEpicStart, 1)
			h.poll()
			_, record := h.record()
			tc.mutate(&record)
			raw, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.store.db.Exec(`UPDATE epic_scheduling SET record=?`, string(raw)); err != nil {
				t.Fatal(err)
			}
			h.restart()
			if err := h.poller.PollOnce(context.Background()); err == nil {
				t.Fatal("corrupt PR state recovered")
			}
			if len(h.requests) != 1 {
				t.Fatal("invalid recovery admitted work")
			}
		})
	}
}
