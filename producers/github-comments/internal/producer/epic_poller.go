package producer

import (
	"context"
	"errors"
	"fmt"
)

func (p *Poller) handleEpicCommand(ctx context.Context, repo Repository, comment GitHubIssueComment, command Command) error {
	if !p.Config.Epics.allows(comment.User.ID) {
		return nil
	}
	store, ok := p.State.(EpicStateStore)
	if !ok {
		return errors.New("epics require durable epic state storage")
	}
	parent, ok := IssueNumberFromIssueURL(comment.IssueURL)
	if !ok || parent <= 0 {
		return nil
	}
	issue, err := p.GitHub.GetIssue(ctx, repo, parent)
	if err != nil {
		return fmt.Errorf("get epic parent: %w", err)
	}
	if issue.PullRequest != nil || issue.Number != parent {
		return nil
	}
	result, err := store.ApplyEpicCommand(ctx, repo, parent, comment.User, command.Intent, comment.ID, p.Config.Epics, p.now())
	if err != nil {
		return fmt.Errorf("apply epic command: %w", err)
	}
	if result.Reason != "" {
		p.Logger.Info("epic command rejected", "repo", canonicalEpicRepository(repo), "issue", parent, "commentID", comment.ID, "reason", result.Reason)
		return nil
	}
	p.Logger.Info("epic command recorded", "repo", result.Epic.Repository, "issue", parent,
		"commentID", comment.ID, "state", result.Epic.State, "generation", result.Epic.Generation,
		"reconciliation", result.Epic.Reconciliation)
	return nil
}
