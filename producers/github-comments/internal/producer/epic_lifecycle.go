package producer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type epicRunObserver interface {
	Get(context.Context, string, string) (*nvtv1alpha1.AgentRun, error)
	FindEpicRun(context.Context, Repository, string) (*scheduleAdmissionAgentRun, error)
}

func (s AgentRunSubmitter) FindEpicRun(ctx context.Context, repo Repository, key string) (*scheduleAdmissionAgentRun, error) {
	if s.client == nil {
		return nil, errors.New("epic Kubernetes observer unavailable")
	}
	var runs nvtv1alpha1.AgentRunList
	if err := s.client.List(ctx, &runs, ctrlclient.InNamespace(s.config.Submission.ScheduleNamespace), ctrlclient.MatchingLabels{"nvt.dev/schedule": s.config.Submission.ScheduleName}); err != nil {
		return nil, err
	}
	var found *scheduleAdmissionAgentRun
	for _, run := range runs.Items {
		if run.Annotations["nvt.dev/work-id"] == key && strings.EqualFold(run.Annotations["nvt.dev/work-repository"], epicRepoKey(repo)) {
			if found != nil {
				return nil, errors.New("multiple retained AgentRuns for epic attempt")
			}
			found = &scheduleAdmissionAgentRun{Namespace: run.Namespace, Name: run.Name}
		}
	}
	return found, nil
}

type epicVerifiedPR struct {
	NodeID   string  `json:"node_id"`
	Number   int     `json:"number"`
	State    string  `json:"state"`
	Merged   *bool   `json:"merged"`
	MergedAt *string `json:"merged_at"`
	HTMLURL  string  `json:"html_url"`
	Base     struct {
		Repo struct {
			FullName string `json:"full_name"`
		} `json:"repo"`
	} `json:"base"`
}
type epicMergeGitHub interface {
	VerifyEpicPR(context.Context, Repository, int) (epicVerifiedPR, error)
}

func (c *GitHubAPIClient) VerifyEpicPR(ctx context.Context, repo Repository, number int) (epicVerifiedPR, error) {
	var result epicVerifiedPR
	err := c.epicJSON(ctx, "GET", fmt.Sprintf("/repos/%s/%s/pulls/%d", repo.Owner, repo.Name, number), nil, &result)
	return result, err
}
func failEpicChild(e *Epic, c *EpicChild, kind, reason string) {
	c.Failure = kind
	c.State = "Failed"
	c.Reason = reason
	e.State = "paused"
	e.Reason = reason
}

func (p *Poller) observeEpicWork(ctx context.Context, e *Epic) error {
	gh, ok := p.GitHub.(epicMergeGitHub)
	if !ok {
		return errors.New("epic merge verification unavailable")
	}
	completed := 0
	for i := range e.Children {
		c := &e.Children[i]
		if c.State == "Completed" {
			completed++
			continue
		}
		if c.PR != nil && c.Failure != "mapping" {
			pr, err := gh.VerifyEpicPR(ctx, e.Repository, c.PR.Number)
			if err != nil {
				return err
			}
			if pr.NodeID != c.PR.ID || pr.Number != c.PR.Number || !strings.EqualFold(pr.Base.Repo.FullName, epicRepoKey(e.Repository)) || pr.Merged == nil || (pr.State != "open" && pr.State != "closed") || (*pr.Merged && (pr.State != "closed" || pr.MergedAt == nil || *pr.MergedAt == "")) {
				return errors.New("associated PR identity or merge response invalid")
			}
			if *pr.Merged {
				c.Merged = true
				c.State = "Completed"
				c.Failure = ""
				c.Reason = "GitHub verified the associated PR merge"
				completed++
				continue
			}
			if pr.State == "closed" {
				failEpicChild(e, c, "pr-closed", "PR closed without merge; close any other attempt PRs and wait for the run to terminate, then epic retry")
			}
		}
		if c.Run != nil && !c.RunTerminal {
			if p.EpicRuns == nil {
				return errors.New("epic run observer unavailable")
			}
			run, err := p.EpicRuns.Get(ctx, c.Run.Namespace, c.Run.Name)
			if err != nil {
				return err
			}
			if run.UID == "" || run.Annotations["nvt.dev/work-id"] != c.Key || !strings.EqualFold(run.Annotations["nvt.dev/work-repository"], epicRepoKey(e.Repository)) || c.RunUID != "" && c.RunUID != string(run.UID) {
				return errors.New("accepted AgentRun identity changed")
			}
			c.RunUID = string(run.UID)
			switch run.Status.Phase {
			case nvtv1alpha1.AgentRunPhaseFailed, nvtv1alpha1.AgentRunPhaseDeadlineExceeded:
				c.RunTerminal = true
				c.RunFailed = true
				if c.Failure != "mapping" && c.Failure != "pr-closed" {
					failEpicChild(e, c, "run", "AgentRun failed; close any unmerged attempt PRs, then epic retry")
				}
			case nvtv1alpha1.AgentRunPhaseCompleted:
				c.RunTerminal = true
			case "", nvtv1alpha1.AgentRunPhasePending, nvtv1alpha1.AgentRunPhaseRunning:
			default:
				return errors.New("unknown AgentRun phase")
			}
		}
		if c.RunTerminal && c.RunFailed && c.Failure == "" {
			failEpicChild(e, c, "run", "AgentRun failed; close any unmerged attempt PRs, then epic retry")
		}
		if c.Run == nil && c.Issue.State == "closed" {
			failEpicChild(e, c, "issue-closed", "Child issue closed before admission; reopen it, then epic retry")
		}
	}
	if completed == len(e.Children) && completed > 0 {
		e.State = "completed"
		e.Reason = "All children have verified merged PRs"
	}
	return nil
}

func (p *Poller) observePausedEpic(ctx context.Context, store *SQLiteStateStore, e *Epic) error {
	wasCancelled := e.State == "cancelled"
	// Pausing prevents admissions, but verified merges and run failures remain visible.
	err := p.recoverEpicAdmissions(ctx, e)
	if err == nil {
		err = p.associateEpicPRs(ctx, e)
	}
	if err == nil {
		err = p.observeEpicWork(ctx, e)
	}
	if wasCancelled {
		e.State = "cancelled"
		e.Reason = "Cancelled by initiator; existing runs are not terminated"
	}
	if err != nil {
		return p.epicReadError(ctx, store, e, err)
	}
	return store.SaveEpic(ctx, e)
}

func (p *Poller) retryEpic(ctx context.Context, e *Epic) error {
	e.RetryRequested = false
	gh, ok := p.GitHub.(epicPRGitHub)
	if !ok {
		return errors.New("epic PR discovery unavailable")
	}
	// Refresh terminal status before deciding whether a fresh attempt is safe.
	if err := p.observeEpicWork(ctx, e); err != nil {
		return err
	}
	for i := range e.Children {
		c := &e.Children[i]
		if c.State != "Failed" {
			continue
		}
		switch c.Failure {
		case "mapping":
			c.State = "Running"
			if c.PR != nil {
				c.State = "PR open"
			}
			c.Failure = ""
			c.Reason = "Rechecking native PR association"
			continue
		case "issue-closed":
			if c.Issue.State == "open" {
				c.State = "Queued"
				c.Failure = ""
				c.Reason = ""
			}
			continue
		case "run", "pr-closed":
			if !c.RunTerminal {
				c.Reason = "Retry blocked: prior AgentRun is not terminal"
				continue
			}
			prs, err := gh.LinkedEpicPRs(ctx, e.Repository, c.Issue.Number)
			if err != nil {
				return err
			}
			unsafe := false
			for _, pr := range prs {
				if err := validateEpicPR(pr); err != nil {
					return err
				}
				if pr.HeadRefName == c.Key && strings.EqualFold(pr.Repository.NameWithOwner, epicRepoKey(e.Repository)) && pr.State != "CLOSED" {
					unsafe = true
				}
			}
			if unsafe {
				c.Reason = "Retry blocked: prior attempt has an open or merged PR; reconcile its native association first"
				continue
			}
		case "admission":
		default:
			continue
		}
		c.History = append(c.History, EpicAttempt{Attempt: c.Attempt, Key: c.Key, Run: c.Run, PR: c.PR, Reason: c.Reason})
		c.Attempt++
		c.Key = ""
		c.Prompt = ""
		c.Run = nil
		c.RunUID = ""
		c.RunTerminal = false
		c.RunFailed = false
		c.PR = nil
		c.Merged = false
		c.AdmissionPending = false
		c.Failure = ""
		c.State = "Queued"
		c.Reason = "Explicit retry starts a new attempt"
	}
	failed := false
	for _, c := range e.Children {
		failed = failed || c.State == "Failed"
	}
	if !failed && e.State != "completed" {
		e.State = "active"
		e.Reason = ""
	}
	return nil
}

func (p *Poller) epicReadError(ctx context.Context, store *SQLiteStateStore, e *Epic, err error) error {
	// Keep raw API bodies and credentials out of public status. Reads are retried
	// only after resume for permanent/malformed responses; transient errors retain state.
	if epicPermanentError(err) && e.State != "cancelled" {
		e.State = "paused"
		e.RetryRequested = false
		e.Reason = "Epic reconciliation stopped: " + safeEpicError(err) + ". Correct access or restore the native graph/identity, then resume or retry."
		if saveErr := store.SaveEpic(ctx, e); saveErr != nil {
			return saveErr
		}
	}
	return err
}
func safeEpicError(err error) string {
	var api *epicAPIError
	if errors.As(err, &api) {
		return fmt.Sprintf("GitHub HTTP %d", api.Status)
	}
	return "invalid or unavailable authoritative GitHub/AgentRun data"
}
func epicPermanentError(err error) bool {
	var network net.Error
	if errors.As(err, &network) || apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err) || apierrors.IsTooManyRequests(err) || apierrors.IsServiceUnavailable(err) {
		return false
	}
	var api *epicAPIError
	if errors.As(err, &api) {
		return api.Status >= 400 && api.Status < 500 && api.Status != 429 && api.Status != 403 || api.Status == 403 && !api.RateLimited
	}
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

type epicAPIError struct {
	Status      int
	RateLimited bool
}

func (e *epicAPIError) Error() string { return fmt.Sprintf("epic GitHub HTTP %d", e.Status) }

func (p *Poller) recoverEpicAdmissions(ctx context.Context, e *Epic) error {
	for i := range e.Children {
		c := &e.Children[i]
		if !c.AdmissionPending || c.Run != nil {
			continue
		}
		if p.EpicRuns == nil {
			return errors.New("epic run observer unavailable")
		}
		run, err := p.EpicRuns.FindEpicRun(ctx, e.Repository, c.Key)
		if err != nil {
			return err
		}
		if run == nil {
			if e.State != "cancelled" {
				e.State = "paused"
				e.Reason = "Admission outcome unknown and no retained AgentRun found; resume rechecks without resubmitting"
			}
			continue
		}
		c.Run = run
		c.AdmissionPending = false
		c.State = "Running"
		c.Failure = ""
		c.Reason = "Recovered accepted AgentRun by exact work key"
		c.Reaction = p.reactionForOutcome(schedulingOutcomeAccepted)
		c.ReactionPending = c.Reaction != ""
	}
	return nil
}
