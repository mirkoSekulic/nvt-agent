//nolint:funlen,govet,gocognit // Poller groups dependencies before mutable cursor state and keeps repo polling flow linear.
package producer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

const schedulingReactionTimeout = 5 * time.Second
const helpResponseRetryDelay = time.Minute
const helpResponseMarkerPrefix = "<!-- nvt-github-help-response:"

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
	if p.Config.Epics.Enabled {
		if err := p.Config.Epics.validate(p.Config.Submission); err != nil {
			return err
		}
		store, ok := p.State.(EpicStateStore)
		if !ok {
			return errors.New("epics require durable epic state storage")
		}
		for _, repo := range p.Config.Repositories {
			if _, err := store.ListEpics(ctx, repo); err != nil {
				return fmt.Errorf("recover epic state: %w", err)
			}
		}
	}
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
		if isEpicIntent(command.Intent) {
			deferred, err := p.handleEpicCommand(ctx, repo, comment, command)
			if err != nil {
				return err
			}
			deferredSubmission = deferredSubmission || deferred
			continue
		}
		if command.Intent == CommandIntentHelp {
			issueNumber, ok := IssueNumberFromIssueURL(comment.IssueURL)
			if !ok {
				p.Logger.Warn("help request missing parseable issue URL", "repo", key, "commentID", comment.ID)
				continue
			}
			marker, err := newHelpResponseMarker()
			if err != nil {
				return fmt.Errorf("create help response marker: %w", err)
			}
			now := p.now().UTC()
			record, created, err := p.State.GetOrCreateHelpResponse(ctx, key, comment.ID, marker, now)
			if err != nil {
				return fmt.Errorf("get or create help response: %w", err)
			}
			if !validHelpResponseMarker(record.Marker) {
				return errors.New("invalid persisted help response marker")
			}
			if record.Status == HelpResponseDelivered {
				p.Logger.Info("skipping duplicate help request already answered", "repo", key, "commentID", comment.ID, "issue", issueNumber)
				continue
			}
			if !created {
				threadComments, listErr := p.GitHub.ListIssueComments(ctx, repo, issueNumber)
				if listErr != nil {
					return fmt.Errorf("reconcile pending help response: %w", listErr)
				}
				if helpResponseMarkerExists(threadComments, comment.ID, record.Marker) {
					if err := p.State.SetHelpResponseDelivered(ctx, key, comment.ID, now); err != nil {
						return fmt.Errorf("record reconciled help response: %w", err)
					}
					continue
				}
			}
			attempt, err := p.State.TryBeginHelpResponseAttempt(ctx, key, comment.ID, now, now.Add(-helpResponseRetryDelay))
			if err != nil {
				return fmt.Errorf("begin help response attempt: %w", err)
			}
			if !attempt {
				deferredSubmission = true
				p.Logger.Info("pending help response attempt is still within its retry window", "repo", key, "commentID", comment.ID)
				continue
			}
			if err := p.GitHub.CreateIssueComment(ctx, repo, issueNumber, helpResponseComment(command.Prefix, record.Marker)); err != nil {
				deferredSubmission = true
				p.Logger.Warn("help response delivery outcome is uncertain; retaining pending state", "repo", key, "commentID", comment.ID, "error", err)
				continue
			}
			if err := p.State.SetHelpResponseDelivered(ctx, key, comment.ID, now); err != nil {
				return fmt.Errorf("record delivered help response: %w", err)
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
		var issueComments []GitHubIssueComment
		if !isCooperativeIntent(command.Intent) {
			issueComments, err = p.GitHub.ListIssueComments(ctx, repo, issueNumber)
			if err != nil {
				return fmt.Errorf("list issue comments %s#%d: %w", key, issueNumber, err)
			}
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
			} else if errors.Is(err, errCommandPromptTooLarge) {
				reason = "command-prompt-too-large"
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
	if err := p.State.DeleteDeliveredHelpResponses(ctx, key); err != nil {
		return fmt.Errorf("clean delivered help responses for %s: %w", key, err)
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
	return "```text\n" + strings.Join([]string{
		"NVT GitHub Producer",
		"",
		"USAGE",
		fmt.Sprintf("  %s --help", prefix),
		fmt.Sprintf("  %s pr create [-- <instructions>]", prefix),
		fmt.Sprintf("  %s review [-- <instructions>]", prefix),
		fmt.Sprintf("  %s run -- <instructions>", prefix),
		fmt.Sprintf("  %s pr continue [-- <instructions>]", prefix),
		"",
		"COMMANDS",
		"  --help",
		"      Show this command reference. Valid on issues and pull requests.",
		"",
		"  pr create",
		"      Create and deliver a pull request. Valid only on ordinary issues.",
		"      Additional instructions are optional.",
		"",
		"  review",
		"      Review the current pull request and post findings without approving,",
		"      requesting changes, or modifying product code. Valid only on pull requests.",
		"      Additional focus instructions are optional.",
		"",
		"  run",
		"      Perform one bounded task, post the result to the originating thread,",
		"      and exit. Valid on issues and pull requests. Instructions are required.",
		"",
		"  pr continue",
		"      Start a durable pull-request maintenance session. The agent checks out",
		"      the PR branch, reads reviews, comments, and checks, addresses actionable",
		"      issues, watches for later activity, and remains active until merge or close.",
		"      Valid only on pull requests. Additional instructions are optional.",
		"",
		"INSTRUCTIONS",
		"  Put the command on the first non-empty line. Add instructions either after",
		"  a standalone -- on that line, or on the following lines. If both forms are",
		"  used, the inline text is followed by a newline and then the multiline text.",
		"  Bare trailing text without -- is invalid.",
	}, "\n") + "\n```"
}

func newHelpResponseMarker() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return helpResponseMarkerPrefix + hex.EncodeToString(raw) + " -->", nil
}

func helpResponseComment(prefix, marker string) string {
	return helpResponse(prefix) + "\n" + marker
}

func helpResponseMarkerExists(comments []GitHubIssueComment, commandCommentID int64, marker string) bool {
	if marker == "" {
		return false
	}
	for _, comment := range comments {
		if comment.ID > commandCommentID && strings.Contains(comment.Body, marker) {
			return true
		}
	}
	return false
}

func validHelpResponseMarker(marker string) bool {
	raw, ok := strings.CutPrefix(marker, helpResponseMarkerPrefix)
	if !ok || !strings.HasSuffix(raw, " -->") {
		return false
	}
	raw = strings.TrimSuffix(raw, " -->")
	if len(raw) != 32 {
		return false
	}
	_, err := hex.DecodeString(raw)
	return err == nil
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
