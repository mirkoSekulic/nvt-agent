package producer

import (
	"context"
	"strings"
)

func (p *Poller) projectEpicComment(ctx context.Context, store EpicSchedulingStore, github EpicGitHubClient, repo Repository, parent, issue int, body, reaction string) (bool, error) {
	record, err := store.GetEpicProjection(ctx, repo, parent, issue)
	if err != nil {
		return false, err
	}
	// Bound each display attempt below its durable retry lease.
	ctx, cancel := context.WithTimeout(ctx, schedulingReactionTimeout)
	defer cancel()
	body += "\n" + record.Marker
	if record.Body == body && (reaction == "" || record.Reaction == reaction) {
		return true, nil
	}
	claimed, err := store.ClaimEpicProjection(ctx, repo, parent, issue, p.now())
	if err != nil || !claimed {
		return false, err
	}
	// Recover an uncertain create using the private nonce committed before POST.
	// Only bot-authored comments qualify; choose the earliest match, so copies of
	// an already published marker cannot redirect the producer's edits.
	if record.CommentID == 0 {
		comments, listErr := p.GitHub.ListIssueComments(ctx, repo, issue)
		if listErr != nil {
			p.Logger.Warn("epic status lookup unavailable", "repo", canonicalEpicRepository(repo), "issue", issue)
			return false, nil
		}
		for _, comment := range comments {
			if comment.ID > 0 && comment.User.Type == "Bot" && strings.Contains(comment.Body, record.Marker) && (record.CommentID == 0 || comment.ID < record.CommentID) {
				record.CommentID, record.Body = comment.ID, comment.Body
			}
		}
		if record.CommentID != 0 {
			if err := store.SaveEpicProjection(ctx, repo, parent, issue, record); err != nil {
				return false, err
			}
		}
	}
	if record.Body != body {
		comment, writeErr := github.WriteEpicComment(ctx, repo, issue, record.CommentID, body)
		if writeErr != nil {
			p.Logger.Warn("epic status write unavailable; retaining projection", "repo", canonicalEpicRepository(repo), "issue", issue)
		} else {
			record.CommentID, record.Body = comment.ID, body
			if err := store.SaveEpicProjection(ctx, repo, parent, issue, record); err != nil {
				return false, err
			}
		}
	}
	if reaction != "" && record.CommentID != 0 && record.Reaction != reaction {
		if err := p.GitHub.CreateIssueCommentReaction(ctx, repo, record.CommentID, reaction); err != nil {
			p.Logger.Warn("epic status reaction unavailable", "repo", canonicalEpicRepository(repo), "issue", issue)
		} else {
			record.Reaction = reaction
			if err := store.SaveEpicProjection(ctx, repo, parent, issue, record); err != nil {
				return false, err
			}
		}
	}
	return record.Body == body, nil
}
