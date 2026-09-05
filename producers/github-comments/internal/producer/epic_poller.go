package producer

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

func (p *Poller) reconcileEpicStatusReplies(ctx context.Context, repo Repository) (bool, error) {
	store, ok := p.State.(EpicStateStore)
	if !ok {
		return false, errors.New("epics require durable epic state storage")
	}
	replies, err := store.ListPendingEpicStatuses(ctx, repo)
	if err != nil {
		return false, fmt.Errorf("recover pending epic statuses: %w", err)
	}
	deferred := false
	for _, reply := range replies {
		// The receipt already passed the incoming command's login filter. Recheck
		// current authorization using the immutable principal, not a stale login.
		userID, err := strconv.ParseInt(reply.Snapshot.Initiator.Subject, 10, 64)
		if err != nil {
			return false, err
		}
		if !p.Config.Epics.allows(userID) {
			continue
		}
		pending, err := p.deliverEpicStatus(ctx, repo, reply.Snapshot.ParentIssue, reply.CommentID, reply.Snapshot)
		if err != nil {
			return false, err
		}
		deferred = deferred || pending
	}
	return deferred, nil
}

func (p *Poller) handleEpicCommand(ctx context.Context, repo Repository, comment GitHubIssueComment, command Command) (bool, error) {
	if !p.Config.Epics.allows(comment.User.ID) {
		return false, nil
	}
	store, ok := p.State.(EpicStateStore)
	if !ok {
		return false, errors.New("epics require durable epic state storage")
	}
	parent, ok := IssueNumberFromIssueURL(comment.IssueURL)
	if !ok || parent <= 0 {
		return false, nil
	}
	issue, err := p.GitHub.GetIssue(ctx, repo, parent)
	if err != nil {
		return false, fmt.Errorf("get epic parent: %w", err)
	}
	if issue.PullRequest != nil || issue.Number != parent {
		return false, nil
	}
	result, err := store.ApplyEpicCommand(ctx, repo, parent, comment.User, command.Intent, comment.ID, p.Config.Epics, p.now())
	if err != nil {
		return false, fmt.Errorf("apply epic command: %w", err)
	}
	if result.Reason != "" {
		p.Logger.Info("epic command rejected", "repo", canonicalEpicRepository(repo), "issue", parent, "commentID", comment.ID, "reason", result.Reason)
		return false, nil
	}
	p.Logger.Info("epic command recorded", "repo", result.Epic.Repository, "issue", parent,
		"commentID", comment.ID, "state", result.Epic.State, "generation", result.Epic.Generation,
		"reconciliation", result.Epic.Reconciliation)
	if command.Intent != CommandIntentEpicStatus {
		return false, nil
	}
	return p.deliverEpicStatus(ctx, repo, parent, comment.ID, *result.Epic)
}

// A requested status reply uses the existing durable help reply mechanism in a
// separate namespace. Unlike help responses, these receipts are retained after
// cursor advancement so a replay returns the original snapshot without a new
// reply. Edited parent/child status projections belong to the scheduling stage.
func (p *Poller) deliverEpicStatus(ctx context.Context, repo Repository, parent int, commentID int64, epic EpicRecord) (bool, error) {
	key := "epic:" + canonicalEpicRepository(repo)
	marker, err := newHelpResponseMarker()
	if err != nil {
		return false, err
	}
	now := p.now().UTC()
	record, created, err := p.State.GetOrCreateHelpResponse(ctx, key, commentID, marker, now)
	if err != nil {
		return false, err
	}
	if !validHelpResponseMarker(record.Marker) {
		return false, errors.New("invalid epic status response marker")
	}
	if record.Status == HelpResponseDelivered {
		return false, nil
	}
	if !created {
		comments, err := p.GitHub.ListIssueComments(ctx, repo, parent)
		if err != nil {
			return false, err
		}
		if helpResponseMarkerExists(comments, commentID, record.Marker) {
			return false, p.State.SetHelpResponseDelivered(ctx, key, commentID, now)
		}
	}
	attempt, err := p.State.TryBeginHelpResponseAttempt(ctx, key, commentID, now, now.Add(-helpResponseRetryDelay))
	if err != nil {
		return false, err
	}
	if !attempt {
		return true, nil
	}
	body := fmt.Sprintf("Epic #%d: **%s** (generation %d). Workflow: `%s`; maxParallel: %d.\n\nReconciliation: `%s`. Child scheduling is unavailable in this stage.\n%s",
		parent, epic.State, epic.Generation, epic.Workflow, epic.MaxParallel, epic.Reconciliation, record.Marker)
	if err := p.GitHub.CreateIssueComment(ctx, repo, parent, body); err != nil {
		p.Logger.Warn("epic status delivery uncertain; retaining pending response", "repo", canonicalEpicRepository(repo), "issue", parent)
		return true, nil
	}
	return false, p.State.SetHelpResponseDelivered(ctx, key, commentID, now)
}
