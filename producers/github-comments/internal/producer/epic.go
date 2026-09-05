package producer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
)

// EpicConfig is administrator-owned. User IDs are immutable GitHub subjects;
// allowedAuthors remains only an additional login filter, not authorization.
type EpicConfig struct {
	Enabled        bool    `json:"enabled"`
	Workflow       string  `json:"workflow,omitempty"`
	MaxParallel    *int    `json:"maxParallel,omitempty"`
	AllowedUserIDs []int64 `json:"allowedUserIDs,omitempty"`
}

func (c *EpicConfig) UnmarshalJSON(data []byte) error {
	type plain EpicConfig
	var value plain
	if err := decodeEpicJSON(data, &value); err != nil {
		return err
	}
	*c = EpicConfig(value)
	return nil
}

func decodeEpicJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("unexpected trailing epic data")
	}
	return nil
}

func (c EpicConfig) parallelism() int {
	if c.MaxParallel == nil {
		return 1
	}
	return *c.MaxParallel
}

func (c EpicConfig) validate(submission SubmissionConfig) error {
	if !c.Enabled {
		if c.Workflow != "" || c.MaxParallel != nil || len(c.AllowedUserIDs) != 0 {
			return errors.New("epics settings require epics.enabled")
		}
		return nil
	}
	if submission.Mode != SubmissionModeScheduleAdmission || submission.AdmissionMode != AdmissionModeProfiled {
		return errors.New("epics require profiled scheduleAdmission mode")
	}
	if c.Workflow == "" || len(utilvalidation.IsDNS1123Label(c.Workflow)) != 0 {
		return errors.New("epics.workflow must be a normalized DNS label")
	}
	// Parallel graph scheduling is deliberately unsupported in the initial contract.
	if c.parallelism() != 1 {
		return errors.New("epics.maxParallel currently supports only 1")
	}
	if len(c.AllowedUserIDs) == 0 {
		return errors.New("epics.allowedUserIDs must explicitly authorize at least one GitHub user ID")
	}
	seen := map[int64]bool{}
	for _, id := range c.AllowedUserIDs {
		if id <= 0 || seen[id] {
			return errors.New("epics.allowedUserIDs must contain unique positive GitHub user IDs")
		}
		seen[id] = true
	}
	return nil
}

func (c EpicConfig) allows(userID int64) bool {
	if !c.Enabled || userID <= 0 {
		return false
	}
	for _, allowed := range c.AllowedUserIDs {
		if allowed == userID {
			return true
		}
	}
	return false
}

func isEpicIntent(intent CommandIntent) bool {
	switch intent {
	case CommandIntentEpicStart, CommandIntentEpicStatus, CommandIntentEpicPause,
		CommandIntentEpicResume, CommandIntentEpicCancel, CommandIntentEpicRetry:
		return true
	default:
		return false
	}
}

type EpicLifecycle string

const (
	EpicPending  EpicLifecycle = "pending"
	EpicPaused   EpicLifecycle = "paused"
	EpicCanceled EpicLifecycle = "canceled"
)

// EpicRecord is the versioned reconciliation input. Stage one has no graph or
// child admissions: every record is explicitly gated on loading a native graph.
// A later implementation must migrate and validate this contract before work
// can advance. Unknown fields, graph data and lifecycle values fail closed.
type EpicRecord struct {
	Version        int                        `json:"version"`
	Repository     string                     `json:"repository"`
	ParentIssue    int                        `json:"parentIssue"`
	Initiator      profiledAdmissionPrincipal `json:"initiator"`
	Workflow       string                     `json:"workflow"`
	MaxParallel    int                        `json:"maxParallel"`
	State          EpicLifecycle              `json:"state"`
	Generation     int64                      `json:"generation"`
	Reconciliation string                     `json:"reconciliation"`
	StartCommentID int64                      `json:"startCommentID"`
	LastCommandID  int64                      `json:"lastCommandID"`
	CreatedAt      time.Time                  `json:"createdAt"`
	UpdatedAt      time.Time                  `json:"updatedAt"`
}

var epicRepositoryPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*/[a-z0-9_.-]+$`)

func canonicalEpicRepository(repo Repository) string {
	return strings.ToLower(repo.Owner + "/" + repo.Name)
}

func (e EpicRecord) Validate() error {
	subject, err := strconv.ParseInt(e.Initiator.Subject, 10, 64)
	if e.Version != 1 || !epicRepositoryPattern.MatchString(e.Repository) || e.ParentIssue <= 0 ||
		e.Initiator.Issuer != githubPrincipalIssuer || err != nil || subject <= 0 ||
		strconv.FormatInt(subject, 10) != e.Initiator.Subject || e.Initiator.DisplayName == "" ||
		e.Workflow == "" || len(utilvalidation.IsDNS1123Label(e.Workflow)) != 0 ||
		e.MaxParallel != 1 || e.Generation <= 0 || e.Reconciliation != "awaiting-graph" ||
		e.StartCommentID <= 0 || e.LastCommandID <= 0 || e.CreatedAt.IsZero() || e.UpdatedAt.Before(e.CreatedAt) {
		return errors.New("invalid or unsupported epic state")
	}
	switch e.State {
	case EpicPending, EpicPaused, EpicCanceled:
		return nil
	default:
		return errors.New("unsupported epic lifecycle")
	}
}

// These keys do not depend on comment text, a poll cursor, current policy, or
// process-local state. Attempt numbers are positive and scoped to a generation.
func EpicChildAttemptKey(repo Repository, parent, child int, generation, attempt int64) (string, error) {
	key := canonicalEpicRepository(repo)
	if !epicRepositoryPattern.MatchString(key) || parent <= 0 || child <= 0 || child == parent || generation <= 0 || attempt <= 0 {
		return "", errors.New("invalid epic child attempt identity")
	}
	return fmt.Sprintf("github:%s:epic:%d:generation:%d:child:%d:attempt:%d", key, parent, generation, child, attempt), nil
}

func EpicAdmissionKey(repo Repository, parent, child int, generation, attempt int64) (string, error) {
	key, err := EpicChildAttemptKey(repo, parent, child, generation, attempt)
	if err != nil {
		return "", err
	}
	return key + ":intent:create_pr", nil
}

// EpicCommandResult is retained with the command receipt, including negative
// outcomes. An edited or replayed comment cannot become a new control command.
type EpicCommandResult struct {
	Epic   *EpicRecord `json:"epic,omitempty"`
	Reason string      `json:"reason,omitempty"`
}

func transitionEpic(current *EpicRecord, repo string, parent int, user GitHubUser, intent CommandIntent, commentID int64, policy EpicConfig, now time.Time) EpicCommandResult {
	if current == nil {
		if intent != CommandIntentEpicStart {
			return EpicCommandResult{Reason: "not-started"}
		}
		return EpicCommandResult{Epic: &EpicRecord{
			Version: 1, Repository: repo, ParentIssue: parent,
			Initiator: profiledAdmissionPrincipal{Issuer: githubPrincipalIssuer, Subject: strconv.FormatInt(user.ID, 10), DisplayName: user.Login},
			Workflow:  policy.Workflow, MaxParallel: policy.parallelism(), State: EpicPending, Generation: 1,
			Reconciliation: "awaiting-graph", StartCommentID: commentID, LastCommandID: commentID, CreatedAt: now, UpdatedAt: now,
		}}
	}
	if current.Initiator.Subject != strconv.FormatInt(user.ID, 10) {
		return EpicCommandResult{Reason: "not-initiator"}
	}
	next := *current
	switch intent {
	case CommandIntentEpicStatus:
		return EpicCommandResult{Epic: &next}
	case CommandIntentEpicStart:
		if next.State == EpicCanceled {
			return EpicCommandResult{Reason: "terminal-epic"}
		}
		return EpicCommandResult{Epic: &next}
	case CommandIntentEpicPause:
		if next.State != EpicPending && next.State != EpicPaused {
			return EpicCommandResult{Reason: "invalid-transition"}
		}
		next.State = EpicPaused
	case CommandIntentEpicResume, CommandIntentEpicRetry:
		if next.State != EpicPaused {
			return EpicCommandResult{Reason: "invalid-transition"}
		}
		next.State = EpicPending
		if intent == CommandIntentEpicRetry {
			if next.Generation == math.MaxInt64 {
				return EpicCommandResult{Reason: "generation-exhausted"}
			}
			next.Generation++
		}
	case CommandIntentEpicCancel:
		if next.State == EpicCanceled {
			return EpicCommandResult{Epic: &next}
		}
		next.State = EpicCanceled
	default:
		return EpicCommandResult{Reason: "unsupported-command"}
	}
	next.LastCommandID = commentID
	if now.After(next.UpdatedAt) {
		next.UpdatedAt = now
	}
	return EpicCommandResult{Epic: &next}
}
