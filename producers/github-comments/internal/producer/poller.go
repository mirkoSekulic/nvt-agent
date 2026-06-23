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
	Logger    *slog.Logger
	since     map[string]time.Time
}

func NewPoller(cfg Config, github GitHubClient, submitter AgentRunSubmitter, logger *slog.Logger) *Poller {
	if logger == nil {
		logger = slog.Default()
	}
	return &Poller{
		Config:    cfg,
		GitHub:    github,
		Submitter: submitter,
		Logger:    logger,
		since:     map[string]time.Time{},
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
			return ctx.Err()
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
	if value, ok := p.since[key]; ok {
		since = &value
	} else if p.Config.InitialSince != "" {
		parsed, err := time.Parse(time.RFC3339, p.Config.InitialSince)
		if err != nil {
			return fmt.Errorf("parse initialSince: %w", err)
		}
		since = &parsed
	}
	comments, err := p.GitHub.ListUpdatedIssueComments(ctx, repo, since)
	if err != nil {
		return fmt.Errorf("list updated issue comments for %s: %w", key, err)
	}
	maxUpdated := time.Time{}
	for _, comment := range comments {
		if comment.UpdatedAt.After(maxUpdated) {
			maxUpdated = comment.UpdatedAt
		}
		command, ok := ParseCommand(comment.Body, p.Config.CommandPrefixes)
		if !ok {
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
		issueComments, err := p.GitHub.ListIssueComments(ctx, repo, issueNumber)
		if err != nil {
			return fmt.Errorf("list issue comments %s#%d: %w", key, issueNumber, err)
		}
		created, idempotencyKey, err := p.Submitter.Submit(ctx, repo, issue, issueComments, comment, command)
		if err != nil {
			return err
		}
		p.Logger.Info("processed pr create comment", "repo", key, "issue", issueNumber, "commentID", comment.ID, "created", created, "idempotencyKey", idempotencyKey)
	}
	if !maxUpdated.IsZero() {
		p.since[key] = maxUpdated
	}
	return nil
}
