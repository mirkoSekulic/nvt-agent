//nolint:funlen,govet,gocognit // Poller groups dependencies before mutable cursor state and keeps repo polling flow linear.
package producer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

const schedulingReactionTimeout = 5 * time.Second

type pendingSchedulingReaction struct {
	commentID int64
	reaction  string
}

type Poller struct {
	Config    Config
	GitHub    GitHubClient
	Submitter AgentRunSubmitter
	State     StateStore
	Logger    *slog.Logger
	startedAt time.Time
	now       func() time.Time
}

func NewPoller(
	cfg Config,
	github GitHubClient,
	submitter AgentRunSubmitter,
	state StateStore,
	logger *slog.Logger,
) *Poller {
	if logger == nil {
		logger = slog.Default()
	}
	if state == nil {
		state = newMemoryStateStore()
	}
	return &Poller{
		Config:    cfg,
		GitHub:    github,
		Submitter: submitter,
		State:     state,
		Logger:    logger,
		startedAt: time.Now(),
		now:       time.Now,
	}
}

func (p *Poller) Run(ctx context.Context) error {
	ticker := time.NewTicker(p.Config.PollInterval.Duration)
	defer ticker.Stop()
	if err := p.PollOnce(ctx); err != nil {
		p.Logger.Error("poll failed", "error", err)
	}
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("poller context done: %w", ctx.Err())
		case <-ticker.C:
			if err := p.PollOnce(ctx); err != nil {
				p.Logger.Error("poll failed", "error", err)
			}
		}
	}
}

func (p *Poller) PollOnce(ctx context.Context) error {
	for _, repo := range p.Config.Repositories {
		if err := p.pollRepo(ctx, repo); err != nil {
			return err
		}
	}
	return nil
}

func (p *Poller) pollRepo(ctx context.Context, repo Repository) error {
	key := repo.Owner + "/" + repo.Name
	pendingReactions := make([]pendingSchedulingReaction, 0)
	defer func() {
		p.postSchedulingReactions(ctx, repo, pendingReactions)
	}()
	var since *time.Time
	storedCursor, foundCursor, err := p.State.GetRepoCursor(ctx, key)
	if err != nil {
		return fmt.Errorf("get poll cursor for %s: %w", key, err)
	}
	switch {
	case foundCursor:
		since = &storedCursor
	case p.Config.InitialSince != "":
		parsed, err := time.Parse(time.RFC3339, p.Config.InitialSince)
		if err != nil {
			return fmt.Errorf("parse initialSince: %w", err)
		}
		since = &parsed
	default:
		since = &p.startedAt
	}
	pollStartedAt := p.now().UTC()
	comments, err := p.GitHub.ListUpdatedIssueComments(ctx, repo, since)
	if err != nil {
		return fmt.Errorf("list updated issue comments for %s: %w", key, err)
	}
	nextCursor := pollStartedAt
	deferredSubmission := false
	for _, comment := range comments {
		if comment.UpdatedAt.After(nextCursor) {
			nextCursor = comment.UpdatedAt
		}
		command, ok := ParseCommand(comment.Body, p.Config.CommandPrefixes)
		if !ok {
			continue
		}
		if !IsAllowedAuthor(comment.User.Login, p.Config.AllowedAuthors) {
			p.Logger.Info(
				"skipping command comment from disallowed author",
				"repo",
				key,
				"commentID",
				comment.ID,
				"author",
				comment.User.Login,
			)
			continue
		}
		if command.Intent == CommandIntentHelp {
			issueNumber, ok := IssueNumberFromIssueURL(comment.IssueURL)
			if !ok {
				p.Logger.Warn("help request missing parseable issue URL", "repo", key, "commentID", comment.ID)
				continue
			}
			if err := p.GitHub.CreateIssueComment(ctx, repo, issueNumber, helpResponse(command.Prefix)); err != nil {
				return err
			}
			continue
		}
		issueNumber, ok := IssueNumberFromIssueURL(comment.IssueURL)
		if !ok {
			p.Logger.Warn("matching command comment missing parseable issue URL", "repo", key, "commentID", comment.ID)
			continue
		}
		issue, err := p.GitHub.GetIssue(ctx, repo, issueNumber)
		if err != nil {
			return fmt.Errorf("get issue %s#%d: %w", key, issueNumber, err)
		}
		if !validCommandPlacement(command.Intent, issue.PullRequest != nil) {
			p.Logger.Info(
				"skipping command with invalid placement",
				"repo",
				key,
				"issue",
				issueNumber,
				"commentID",
				comment.ID,
				"intent",
				command.Intent,
			)
			continue
		}
		issueComments, err := p.GitHub.ListIssueComments(ctx, repo, issueNumber)
		if err != nil {
			return fmt.Errorf("list issue comments %s#%d: %w", key, issueNumber, err)
		}
		result, err := p.Submitter.submitWithOutcome(ctx, repo, issue, issueComments, comment, command)
		created := result.Created
		idempotencyKey := result.IdempotencyKey
		pendingReactions = p.appendSchedulingReaction(pendingReactions, comment.ID, result.Outcome)
		if errors.Is(err, ErrSubmissionDeferred) {
			p.Logger.Info(
				"deferred command submission",
				"repo",
				key,
				"issue",
				issueNumber,
				"commentID",
				comment.ID,
				"idempotencyKey",
				idempotencyKey,
			)
			deferredSubmission = true
			continue
		}
		if result.Outcome == schedulingOutcomeRejected {
			reason := "schedule-admission-rejected"
			if errors.Is(err, errCommandDisabled) {
				reason = "command-disabled"
			}
			p.Logger.Info(
				"processed definitive schedule admission rejection",
				"repo",
				key,
				"issue",
				issueNumber,
				"commentID",
				comment.ID,
				"reason",
				reason,
			)
			continue
		}
		if err != nil {
			return err
		}
		p.Logger.Info(
			"processed command comment",
			"repo",
			key,
			"issue",
			issueNumber,
			"commentID",
			comment.ID,
			"created",
			created,
			"idempotencyKey",
			idempotencyKey,
		)
	}
	if deferredSubmission {
		p.Logger.Info("not advancing poll cursor because at least one command submission was deferred", "repo", key)
		return nil
	}
	if err := p.State.SetRepoCursor(ctx, key, nextCursor); err != nil {
		return fmt.Errorf("set poll cursor for %s: %w", key, err)
	}
	return nil
}

func validCommandPlacement(intent CommandIntent, isPullRequest bool) bool {
	switch intent {
	case CommandIntentPRCreate:
		return !isPullRequest
	case CommandIntentReview:
		return isPullRequest
	case CommandIntentPRContinue:
		return isPullRequest
	case CommandIntentRun:
		return true
	default:
		return false
	}
}

func helpResponse(prefix string) string {
	return "Available commands:\n\n" + strings.Join([]string{
		"Syntax:",
		"",
		fmt.Sprintf("%s --help", prefix),
		"",
		"Commands:",
		fmt.Sprintf("%s pr create", prefix),
		"  Create and ship a pull request from an ordinary issue thread.",
		fmt.Sprintf("%s review", prefix),
		"  Open a review workflow on the current PR and post findings as a PR comment.",
		fmt.Sprintf("%s run -- <instructions>", prefix),
		"  Execute one bounded cooperative task on issues and pull requests.",
		fmt.Sprintf("%s pr continue -- <optional instructions>", prefix),
		"  Enter PR maintenance mode, inspect prior reviews/comments/checks,",
		"  address actionable items, register github-watch, and keep running.",
		"- pr create is valid on ordinary issues.",
		"- review and pr continue are valid only on pull requests.",
		"- run is valid on issues and pull requests.",
		"- pr continue runs a long-lived PR maintenance workflow.",
	}, "\n")
}

func (p *Poller) reactionForOutcome(outcome schedulingOutcome) string {
	if !p.Config.SchedulingReactions.IsEnabled() {
		return ""
	}
	switch outcome {
	case schedulingOutcomeAccepted:
		if p.Config.SchedulingReactions.Accepted != "" {
			return p.Config.SchedulingReactions.Accepted
		}
		return defaultAcceptedReaction
	case schedulingOutcomeRejected:
		if p.Config.SchedulingReactions.Rejected != "" {
			return p.Config.SchedulingReactions.Rejected
		}
		return defaultRejectedReaction
	case schedulingOutcomeNone, schedulingOutcomeDeferred, schedulingOutcomeUncertain:
		return ""
	}
	return ""
}

func (p *Poller) appendSchedulingReaction(
	pending []pendingSchedulingReaction,
	commentID int64,
	outcome schedulingOutcome,
) []pendingSchedulingReaction {
	reaction := p.reactionForOutcome(outcome)
	if reaction == "" {
		return pending
	}
	return append(pending, pendingSchedulingReaction{commentID: commentID, reaction: reaction})
}

func (p *Poller) postSchedulingReactions(
	parent context.Context,
	repo Repository,
	pending []pendingSchedulingReaction,
) {
	if len(pending) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), schedulingReactionTimeout)
	defer cancel()
	for _, item := range pending {
		err := p.GitHub.CreateIssueCommentReaction(ctx, repo, item.commentID, item.reaction)
		if err != nil {
			p.Logger.Warn(
				"failed to add best-effort scheduling reaction",
				"repo",
				repo.Owner+"/"+repo.Name,
				"commentID",
				item.commentID,
				"reason",
				"github-reaction-unavailable",
			)
		}
	}
}
