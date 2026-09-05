package producer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

type epicGitHub interface {
	LoadEpicGraph(context.Context, Repository, int) ([]EpicGraphNode, error)
	UpsertEpicComment(context.Context, Repository, int, string, string, int64) error
}

func (p *Poller) reconcileEpics(ctx context.Context, repo Repository) error {
	store, ok := p.State.(*SQLiteStateStore)
	if !ok {
		return errors.New("epics require SQLite state")
	}
	gh, ok := p.GitHub.(epicGitHub)
	if !ok {
		return errors.New("epic GitHub client unavailable")
	}
	epics, err := store.ListEpics(ctx, repo)
	if err != nil {
		return err
	}
	var errs []error
	for i := range epics {
		e := &epics[i]
		if err := p.reconcileEpic(ctx, store, gh, e); err != nil {
			errs = append(errs, err)
		}
		// Display is an independent projection; retry on every poll, including terminal epics.
		if err := p.displayEpic(ctx, gh, e); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (p *Poller) reconcileEpic(ctx context.Context, store *SQLiteStateStore, gh epicGitHub, e *Epic) error {
	if e.State != "active" {
		return nil
	}
	graph, err := gh.LoadEpicGraph(ctx, e.Repository, e.Parent)
	if err != nil {
		return err
	}
	if err := installEpicGraph(e, graph); err != nil {
		e.State = "paused"
		e.Reason = err.Error()
		return store.SaveEpic(ctx, e)
	}
	projectEligibility(e)
	if err := store.SaveEpic(ctx, e); err != nil {
		return err
	}
	active := 0
	for _, c := range e.Children {
		if c.Run != nil && c.State != "Completed" || c.Key != "" && c.Run == nil {
			active++
		}
	}
	for i := range e.Children {
		c := &e.Children[i]
		if c.State != "Queued" || c.Run != nil {
			continue
		}
		if c.Key == "" {
			if active >= e.MaxParallel {
				break
			}
			c.Key = epicAttemptKey(*e, c.Issue.Number, c.Attempt)
			comments, err := p.GitHub.ListIssueComments(ctx, e.Repository, c.Issue.Number)
			if err != nil {
				return err
			}
			c.Prompt = buildPrompt(e.Repository, c.Issue, comments, GitHubIssueComment{User: e.Principal}, Command{Intent: CommandIntentPRCreate})
			c.ScheduledAt = p.now().UTC()
			// Persist the exact request before the network call: uncertain admission replays it.
			if err := store.SaveEpic(ctx, e); err != nil {
				return err
			}
			active++
		}
		s := p.Submitter
		s.config.Submission.Workflow = e.Workflow
		s.config.Submission.CommandWorkflows = map[CommandIntent]string{CommandIntentPRCreate: e.Workflow}
		result, err := s.submitScheduleAdmission(ctx, e.Repository, c.Issue, nil, GitHubIssueComment{User: e.Principal}, Command{Intent: CommandIntentPRCreate, epicPrompt: c.Prompt}, agentRunIdentity{Key: c.Key})
		switch result.Outcome {
		case schedulingOutcomeAccepted:
			if result.AgentRun == nil || result.AgentRun.Name == "" || result.AgentRun.Namespace == "" {
				c.Reason = "Admission accepted without a run identity; replaying the same attempt"
				if saveErr := store.SaveEpic(ctx, e); saveErr != nil {
					return saveErr
				}
				return errors.New(c.Reason)
			}
			c.Run = result.AgentRun
			c.State = "Running"
			c.Reason = "Accepted by schedule admission"
			c.Reaction = p.reactionForOutcome(result.Outcome)
			c.ReactionPending = c.Reaction != ""
		case schedulingOutcomeRejected:
			c.State = "Failed"
			c.Reason = "Admission rejected; correct policy or credentials and use epic retry"
			c.Key = ""
			c.Prompt = ""
			e.State = "paused"
			e.Reason = c.Reason
			c.Reaction = p.reactionForOutcome(result.Outcome)
			c.ReactionPending = c.Reaction != ""
		default:
			c.Reason = "Admission deferred or uncertain; retrying the same attempt"
		}
		if saveErr := store.SaveEpic(ctx, e); saveErr != nil {
			return saveErr
		}
		if e.State != "active" {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func childStatus(c EpicChild) string {
	result := fmt.Sprintf("#%d: **%s** — %s (attempt %d)", c.Issue.Number, c.State, c.Reason, c.Attempt)
	if c.Run != nil {
		result += fmt.Sprintf("\nAgentRun: `%s/%s`; scheduled %s.", c.Run.Namespace, c.Run.Name, c.ScheduledAt.Format(time.RFC3339))
	}
	return result
}
func (p *Poller) displayEpic(ctx context.Context, gh epicGitHub, e *Epic) error {
	var parent strings.Builder
	fmt.Fprintf(&parent, "NVT epic #%d: **%s**\n\n%s\n\n", e.Parent, e.State, e.Reason)
	var errs []error
	for _, c := range e.Children {
		status := childStatus(c)
		parent.WriteString(status + "\n\n")
		marker := e.Marker + fmt.Sprintf("<!-- child:%d -->", c.Issue.Number)
		if err := gh.UpsertEpicComment(ctx, e.Repository, c.Issue.Number, marker, fmt.Sprintf("Part of #%d\n\n%s\nEpic: %s. %s", e.Parent, status, e.State, e.Reason), p.Config.GitHubApp.AppID); err != nil {
			errs = append(errs, err)
		}
	}
	if err := gh.UpsertEpicComment(ctx, e.Repository, e.Parent, e.Marker, parent.String(), p.Config.GitHubApp.AppID); err != nil {
		errs = append(errs, err)
	}
	// Reaction retries also stay independent of admission and command cursor progress.
	dirty := false
	for i := range e.Children {
		c := &e.Children[i]
		if c.ReactionPending {
			if err := p.GitHub.CreateIssueCommentReaction(ctx, e.Repository, e.CommandID, c.Reaction); err != nil {
				errs = append(errs, err)
			} else {
				c.ReactionPending = false
				dirty = true
			}
		}
	}
	if dirty {
		if err := p.State.(*SQLiteStateStore).SaveEpic(ctx, e); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
