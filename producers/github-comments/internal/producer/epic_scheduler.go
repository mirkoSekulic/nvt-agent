package producer

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func (p *Poller) reconcileEpics(ctx context.Context, repo Repository) error {
	store, ok := p.State.(EpicSchedulingStore)
	if !ok {
		return errors.New("epics require durable scheduling storage")
	}
	epics, err := store.ListEpics(ctx, repo)
	if err != nil {
		return err
	}
	for _, epic := range epics {
		id, _ := strconv.ParseInt(epic.Initiator.Subject, 10, 64)
		if !p.Config.Epics.allows(id) {
			continue
		}
		github, ok := p.GitHub.(EpicGitHubClient)
		if !ok {
			return errors.New("epics require native GitHub graph and comment editing support")
		}
		record, err := store.LoadEpicSchedule(ctx, repo, epic)
		if err != nil {
			return err
		}
		children, graphErr := p.loadEpicGraph(ctx, github, repo, epic.ParentIssue)
		record.GraphError = ""
		if graphErr != nil {
			record.GraphError = graphErr.Error()
		} else {
			record.Children = children
			// A removed/transferred accepted child still owns its slot and its display.
			for _, a := range record.Attempts {
				for _, child := range children {
					if child.Issue.Number == a.Source.Number && child.Issue.ID != a.Source.ID {
						record.GraphError = "child identity changed since admission"
					}
				}
			}
		}
		if err := store.SaveEpicSchedule(ctx, repo, epic, &record); err != nil {
			return err
		}
		if epic.State == EpicPending && record.GraphError == "" {
			if err := p.scheduleEpicChild(ctx, store, repo, epic, &record); err != nil {
				return err
			}
		}
		if err := p.associateEpicPRs(ctx, store, repo, &epic, &record); err != nil {
			return err
		}
		// Display errors never alter admission state or block other epics/repos.
		if err := p.projectEpic(ctx, store, github, repo, epic, record); err != nil {
			return err
		}
	}
	return nil
}

func (p *Poller) scheduleEpicChild(ctx context.Context, store EpicSchedulingStore, repo Repository, epic EpicRecord, record *EpicSchedule) error {
	pending := -1
	for i, a := range record.Attempts {
		if a.State == "accepted" {
			return nil
		} // Accepted work retains its slot; merge advancement is a later stage.
		if a.State == "pending" {
			pending = i
		}
		if a.State == "rejected" && a.Generation == epic.Generation {
			return nil
		}
	}
	if pending < 0 {
		for _, child := range record.Children {
			if epicChildBlockReason(child) != "" {
				continue
			}
			comments, err := p.GitHub.ListIssueComments(ctx, repo, child.Issue.Number)
			if err != nil {
				record.GraphError = "child context unavailable"
				return store.SaveEpicSchedule(ctx, repo, epic, record)
			}
			key, err := EpicAdmissionKey(repo, epic.ParentIssue, child.Issue.Number, epic.Generation, 1)
			if err != nil {
				return err
			}
			userID, _ := strconv.ParseInt(epic.Initiator.Subject, 10, 64)
			source := GitHubIssueComment{User: GitHubUser{ID: userID, Login: epic.Initiator.DisplayName}}
			request := profiledScheduleAdmissionRequest{
				Workflow: epic.Workflow,
				Work:     profiledScheduleAdmissionWork{ID: key, Title: child.Issue.Title, URL: child.Issue.HTMLURL, Repository: epic.Repository, Principal: epic.Initiator},
				Input:    profiledScheduleAdmissionInput{Prompt: buildEpicPrompt(repo, child.Issue, comments, source, epic.ParentIssue)},
			}
			if len(request.Input.Prompt) > maxResolvedRunPromptBytes {
				record.GraphError = "child prompt exceeds admission limit"
				return store.SaveEpicSchedule(ctx, repo, epic, record)
			}
			record.Attempts = append(record.Attempts, EpicAttempt{Generation: epic.Generation, Source: child.Issue, Request: request, State: "pending"})
			pending = len(record.Attempts) - 1
			if err := store.SaveEpicSchedule(ctx, repo, epic, record); err != nil {
				return err
			}
			break
		}
	}
	if pending < 0 {
		return nil
	}
	a := &record.Attempts[pending]
	// Even a retry of an uncertain POST requires a current unblocked source.
	eligible := false
	for _, child := range record.Children {
		if child.Issue.ID == a.Source.ID && child.Issue.Number == a.Source.Number && epicChildBlockReason(child) == "" {
			eligible = true
		}
	}
	if !eligible {
		return nil
	}
	var token string
	var err error
	if p.Submitter.config.Submission.Backend == SubmissionBackendLocal {
		token, err = readLocalAdmissionToken(p.Submitter.config.Submission.AdmissionTokenFile)
	} else {
		token, err = readAdmissionToken(p.Submitter.config.Submission.AdmissionTokenFile)
	}
	if err != nil {
		a.Reason = "admission credentials unavailable"
		return store.SaveEpicSchedule(ctx, repo, epic, record)
	}
	// Mark the crash window before POST. A later denial cannot prove that an
	// earlier ambiguous request was never accepted (authorization can change
	// before the authority checks its deduplication ledger).
	wasUncertain := a.MayBeAccepted
	a.MayBeAccepted = true
	if err := store.SaveEpicSchedule(ctx, repo, epic, record); err != nil {
		return err
	}
	result, submitErr := p.Submitter.postScheduleAdmission(ctx, a.Request, token, agentRunIdentity{Key: a.Request.Work.ID})
	switch result.Outcome {
	case schedulingOutcomeAccepted:
		a.MayBeAccepted = false
		a.State, a.Reason, a.AgentRun, a.AcceptedAt = "accepted", "", result.AgentRun, p.now().UTC()
	case schedulingOutcomeRejected:
		if wasUncertain {
			a.Reason = "admission rejected after uncertain delivery; retaining the original work identity"
		} else {
			a.MayBeAccepted = false
			a.State, a.Reason = "rejected", "admission rejected; pause then retry after correcting admission policy"
		}
	case schedulingOutcomeDeferred:
		a.MayBeAccepted = wasUncertain
		a.Reason = "admission deferred by schedule capacity or suspension"
	default:
		a.Reason = "admission outcome uncertain; retrying the same work identity"
	}
	if submitErr != nil {
		p.Logger.Warn("epic admission not accepted", "repo", epic.Repository, "issue", a.Source.Number, "reason", a.Reason)
	}
	return store.SaveEpicSchedule(ctx, repo, epic, record)
}

func epicChildStatus(epic EpicRecord, record EpicSchedule, child EpicGraphChild) (string, string, *EpicAttempt) {
	for i := len(record.Attempts) - 1; i >= 0; i-- {
		a := &record.Attempts[i]
		if a.Source.Number != child.Issue.Number {
			continue
		}
		switch a.State {
		case "accepted":
			if record.PRAmbiguity != "" {
				return "Blocked", record.PRAmbiguity, a
			}
			if a.PR != nil {
				return "PR open", "associated PR: " + a.PR.URL + "; awaiting merge advancement support", a
			}
			return "Running", firstNonEmpty(a.PRReason, "awaiting a verified linked PR"), a
		case "rejected":
			if a.Generation == epic.Generation {
				return "Failed", a.Reason, a
			}
		case "pending":
			if strings.HasPrefix(a.Reason, "admission rejected") {
				return "Failed", a.Reason, a
			}
			if record.GraphError != "" {
				return "Blocked", record.GraphError, a
			}
			if reason := epicChildBlockReason(child); reason != "" {
				return "Blocked", reason, a
			}
			if epic.State != EpicPending {
				return "Blocked", "epic is " + string(epic.State), a
			}
			return "Queued", firstNonEmpty(a.Reason, "admission pending"), a
		}
	}
	if record.GraphError != "" {
		return "Blocked", record.GraphError, nil
	}
	if reason := epicChildBlockReason(child); reason != "" {
		return "Blocked", reason, nil
	}
	if epic.State != EpicPending {
		return "Blocked", "epic is " + string(epic.State), nil
	}
	return "Queued", "waiting for the epic admission slot", nil
}

func epicRunDescription(a *EpicAttempt) string {
	if a == nil || a.State != "accepted" {
		return ""
	}
	identity := "unavailable in admission response"
	if a.AgentRun != nil {
		identity = a.AgentRun.Name
		if a.AgentRun.Namespace != "" {
			identity = a.AgentRun.Namespace + "/" + identity
		}
	}
	return fmt.Sprintf("\n\nAccepted AgentRun/session: `%s`. Accepted at %s.\nWork ID: `%s`.", identity, a.AcceptedAt.Format("2006-01-02T15:04:05Z"), a.Request.Work.ID)
}

func (p *Poller) projectEpic(ctx context.Context, store EpicSchedulingStore, github EpicGitHubClient, repo Repository, epic EpicRecord, record EpicSchedule) error {
	children := append([]EpicGraphChild(nil), record.Children...)
	for _, a := range record.Attempts {
		found := false
		for _, child := range children {
			if child.Issue.Number == a.Source.Number {
				found = true
			}
		}
		if !found {
			children = append(children, EpicGraphChild{Issue: a.Source})
		}
	}
	sort.Slice(children, func(i, j int) bool { return children[i].Issue.Number < children[j].Issue.Number })
	var parent strings.Builder
	fmt.Fprintf(&parent, "Epic #%d: **%s** (generation %d). Workflow: `%s`; maxParallel: %d.\n", epic.ParentIssue, epic.State, epic.Generation, epic.Workflow, epic.MaxParallel)
	if record.GraphError != "" {
		fmt.Fprintf(&parent, "\n**Failed**: %s. Scheduling is blocked.\n", record.GraphError)
	}
	if record.PRAmbiguity != "" {
		fmt.Fprintf(&parent, "\n**PR ambiguity**: %s.\n", record.PRAmbiguity)
	}
	parent.WriteString("\n| Child | Status | Detail |\n| --- | --- | --- |\n")
	for _, child := range children {
		status, reason, attempt := epicChildStatus(epic, record, child)
		fmt.Fprintf(&parent, "| #%d | %s | %s |\n", child.Issue.Number, status, reason)
		body := fmt.Sprintf("Epic #%d · Child #%d: **%s**.\n\n%s.%s", epic.ParentIssue, child.Issue.Number, status, reason, epicRunDescription(attempt))
		outcome := schedulingOutcomeNone
		if attempt != nil && attempt.State == "accepted" {
			outcome = schedulingOutcomeAccepted
		}
		if attempt != nil && attempt.State == "rejected" {
			outcome = schedulingOutcomeRejected
		}
		if _, err := p.projectEpicComment(ctx, store, github, repo, epic.ParentIssue, child.Issue.Number, body, p.reactionForOutcome(outcome)); err != nil {
			return err
		}
	}
	delivered, err := p.projectEpicComment(ctx, store, github, repo, epic.ParentIssue, epic.ParentIssue, parent.String(), "")
	if err != nil || !delivered {
		return err
	}
	// Stage-one status receipts now refresh the single current parent projection.
	replies, err := store.ListPendingEpicStatuses(ctx, repo)
	if err != nil {
		return err
	}
	for _, reply := range replies {
		if reply.Snapshot.ParentIssue != epic.ParentIssue {
			continue
		}
		key := "epic:" + epic.Repository
		marker, err := newHelpResponseMarker()
		if err != nil {
			return err
		}
		if _, _, err := p.State.GetOrCreateHelpResponse(ctx, key, reply.CommentID, marker, p.now()); err != nil {
			return err
		}
		if err := p.State.SetHelpResponseDelivered(ctx, key, reply.CommentID, p.now()); err != nil {
			return err
		}
	}
	return nil
}
