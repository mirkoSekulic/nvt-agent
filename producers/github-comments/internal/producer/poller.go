//nolint:funlen,govet,gocognit // Poller groups dependencies before mutable cursor state and keeps repo polling flow linear.
package producer

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

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
		issueNumber, ok := IssueNumberFromIssueURL(comment.IssueURL)
		if !ok {
			p.Logger.Warn("matching command comment missing parseable issue URL", "repo", key, "commentID", comment.ID)
			continue
		}
		issue, err := p.GitHub.GetIssue(ctx, repo, issueNumber)
		if err != nil {
			return fmt.Errorf("get issue %s#%d: %w", key, issueNumber, err)
		}
		if issue.PullRequest != nil {
			p.Logger.Info(
				"skipping pr-backed issue comment",
				"repo",
				key,
				"issue",
				issueNumber,
				"commentID",
				comment.ID,
			)
			continue
		}
		issueComments, err := p.GitHub.ListIssueComments(ctx, repo, issueNumber)
		if err != nil {
			return fmt.Errorf("list issue comments %s#%d: %w", key, issueNumber, err)
		}
		created, idempotencyKey, err := p.Submitter.Submit(ctx, repo, issue, issueComments, comment, command)
		if err != nil {
			return err
		}
		p.Logger.Info(
			"processed pr create comment",
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
	if err := p.State.SetRepoCursor(ctx, key, nextCursor); err != nil {
		return fmt.Errorf("set poll cursor for %s: %w", key, err)
	}
	return nil
}
