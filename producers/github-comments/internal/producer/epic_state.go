package producer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
)

// EpicConfig is administrator-owned. Epics require durable, profiled admission.
type EpicConfig struct {
	Enabled     bool   `json:"enabled"`
	Workflow    string `json:"workflow,omitempty"`
	MaxParallel int    `json:"maxParallel,omitempty"`
}

func (c *EpicConfig) UnmarshalJSON(data []byte) error {
	type plain EpicConfig
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("epics must be an object")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, raw := range fields {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return errors.New("epic fields cannot be null")
		}
	}
	if raw, ok := fields["maxParallel"]; ok {
		var n int
		if err := json.Unmarshal(raw, &n); err != nil || n < 1 || n > 16 {
			return errors.New("epics.maxParallel must be between 1 and 16")
		}
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode((*plain)(c))
}
func (c *EpicConfig) validate(s SubmissionConfig) error {
	if !c.Enabled {
		if c.Workflow != "" || c.MaxParallel != 0 {
			return errors.New("epics workflow/maxParallel require enabled: true")
		}
		return nil
	}
	if c.Workflow == "" || len(utilvalidation.IsDNS1123Label(c.Workflow)) != 0 {
		return errors.New("epics.workflow must be a normalized DNS label")
	}
	if c.MaxParallel == 0 {
		c.MaxParallel = 1
	}
	if c.MaxParallel < 1 || c.MaxParallel > 16 {
		return errors.New("epics.maxParallel must be between 1 and 16")
	}
	if s.Mode != SubmissionModeScheduleAdmission || s.AdmissionMode != AdmissionModeProfiled || s.Backend != SubmissionBackendKubernetes {
		return errors.New("epics require Kubernetes profiled scheduleAdmission")
	}
	return nil
}

type Epic struct {
	AdmissionScope string
	RetryRequested bool
	Repository     Repository
	Parent         int
	Principal      GitHubUser
	Workflow       string
	MaxParallel    int
	Generation     int
	State          string
	Reason         string
	Version        int64
	Marker         string
	CommandID      int64
	Children       []EpicChild
}
type EpicChild struct {
	RequestTitle     string
	RequestURL       string
	Failure          string
	RunUID           string
	RunTerminal      bool
	RunFailed        bool
	AdmissionPending bool
	History          []EpicAttempt
	Merged           bool
	PR               *EpicPR
	Prompt           string
	Reaction         string
	ReactionPending  bool
	Issue            GitHubIssue
	Dependencies     []int
	Attempt          int
	State            string
	Reason           string
	Key              string
	Run              *scheduleAdmissionAgentRun
	ScheduledAt      time.Time
}

func epicAttemptKey(e Epic, child, attempt int) string {
	raw := fmt.Sprintf("github-epic:%s/%s:%d:%d:%d:%d", strings.ToLower(e.Repository.Owner), strings.ToLower(e.Repository.Name), e.Parent, e.Generation, child, attempt)
	sum := sha256.Sum256([]byte(raw))
	return "github-epic-" + hex.EncodeToString(sum[:])
}

func (e Epic) validate() error {
	if e.Repository.Owner == "" || e.Repository.Name == "" || e.Parent <= 0 || e.Principal.ID <= 0 || e.Principal.Login == "" || e.Generation < 1 || e.MaxParallel < 1 || e.MaxParallel > 16 || e.Workflow == "" || len(utilvalidation.IsDNS1123Label(e.Workflow)) != 0 || !validHelpResponseMarker(e.Marker) {
		return errors.New("invalid epic identity or policy")
	}
	switch e.State {
	case "active", "paused", "cancelled", "completed":
	default:
		return errors.New("invalid epic lifecycle")
	}
	if e.State == "completed" && len(e.Children) == 0 {
		return errors.New("completed epic has no children")
	}
	if len(e.Children) > maxEpicChildren {
		return errors.New("too many persisted epic children")
	}
	seen := map[int]bool{}
	for _, c := range e.Children {
		if c.Issue.Number <= 0 || c.Issue.Number == e.Parent || seen[c.Issue.Number] || c.Attempt < 1 {
			return errors.New("invalid epic child identity")
		}
		seen[c.Issue.Number] = true
		switch c.Failure {
		case "", "mapping", "run", "pr-closed", "admission", "issue-closed":
		default:
			return errors.New("unknown epic failure kind")
		}
		switch c.State {
		case "Blocked", "Queued", "Running", "PR open", "Completed", "Failed":
		default:
			return errors.New("invalid epic child state")
		}
		if c.Key != "" && c.Key != epicAttemptKey(e, c.Issue.Number, c.Attempt) {
			return errors.New("invalid epic attempt key")
		}
		if c.Key != "" && (c.Prompt == "" || c.ScheduledAt.IsZero()) {
			return errors.New("epic attempt missing durable request")
		}
		if (c.State == "Running" || c.State == "PR open" || c.State == "Completed") && c.Run == nil {
			return errors.New("epic child state requires an accepted run")
		}
		if c.State == "PR open" && c.PR == nil || c.State == "Completed" && (c.PR == nil || !c.Merged) {
			return errors.New("epic child state requires verified PR evidence")
		}
		if c.State == "Failed" && (c.Reason == "" || c.Failure == "") {
			return errors.New("epic failure requires an actionable reason")
		}
		if c.RunTerminal && c.Run == nil || c.RunFailed && !c.RunTerminal {
			return errors.New("invalid terminal run state")
		}
		if c.PR != nil && (c.PR.ID == "" || c.PR.Number <= 0 || c.PR.HeadRefName != c.Key || !strings.EqualFold(c.PR.Repository.NameWithOwner, epicRepoKey(e.Repository))) {
			return errors.New("invalid persisted PR identity")
		}
		if c.Run != nil && (c.Key == "" || c.Run.Name == "" || c.Run.Namespace == "") {
			return errors.New("invalid accepted epic run")
		}
	}
	if len(e.Children) > 0 {
		graph := make([]EpicGraphNode, 0, len(e.Children))
		runs := map[string]bool{}
		completed := 0
		for _, c := range e.Children {
			graph = append(graph, EpicGraphNode{Issue: c.Issue, Dependencies: c.Dependencies})
			if c.State == "Completed" {
				completed++
			}
			if c.Run != nil {
				key := c.Run.Namespace + "/" + c.Run.Name
				if runs[key] {
					return errors.New("AgentRun associated with multiple epic children")
				}
				runs[key] = true
			}
		}
		if err := validateEpicGraph(e.Repository, e.Parent, graph); err != nil {
			return err
		}
		if e.State == "completed" && completed != len(e.Children) {
			return errors.New("epic completed without every child merge")
		}
	}
	return nil
}

func (s *SQLiteStateStore) migrateEpics(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS epics (
 repo TEXT NOT NULL, parent INTEGER NOT NULL, version INTEGER NOT NULL, data TEXT NOT NULL,
 PRIMARY KEY(repo,parent));
 CREATE TABLE IF NOT EXISTS epic_commands (
 repo TEXT NOT NULL, comment INTEGER NOT NULL, PRIMARY KEY(repo,comment));`)
	return err
}
func epicRepoKey(r Repository) string { return strings.ToLower(r.Owner + "/" + r.Name) }

func (s *SQLiteStateStore) ListEpics(ctx context.Context, repo Repository) ([]Epic, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM epics WHERE repo=? ORDER BY parent`, epicRepoKey(repo))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Epic
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var e Epic
		if err := decodeEpic(raw, &e); err != nil {
			return nil, err
		}
		if err := e.validate(); err != nil {
			return nil, err
		}
		result = append(result, e)
	}
	return result, rows.Err()
}

var errEpicConflict = errors.New("epic changed during reconciliation; retry")

func (s *SQLiteStateStore) SaveEpic(ctx context.Context, e *Epic) error {
	if err := e.validate(); err != nil {
		return err
	}
	next := *e
	next.Version++
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE epics SET version=?, data=? WHERE repo=? AND parent=? AND version=?`, next.Version, data, epicRepoKey(e.Repository), e.Parent, e.Version)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errEpicConflict
	}
	*e = next
	return nil
}

// Command receipt and state change commit atomically. Receipt IDs survive cursor replay.
func (s *SQLiteStateStore) ApplyEpicCommand(ctx context.Context, repo Repository, parent int, user GitHubUser, commentID int64, action string, cfg EpicConfig) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO epic_commands(repo,comment) VALUES(?,?) ON CONFLICT DO NOTHING`, epicRepoKey(repo), commentID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return tx.Commit()
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT data FROM epics WHERE repo=? AND parent=?`, epicRepoKey(repo), parent).Scan(&raw)
	var e Epic
	if errors.Is(err, sql.ErrNoRows) {
		if action != "start" {
			return tx.Commit()
		}
		marker, err := newHelpResponseMarker()
		if err != nil {
			return err
		}
		e = Epic{Repository: repo, Parent: parent, Principal: user, Workflow: cfg.Workflow, MaxParallel: cfg.MaxParallel, Generation: 1, State: "active", Marker: marker, CommandID: commentID}
	} else {
		if err != nil {
			return err
		}
		if err := decodeEpic(raw, &e); err != nil {
			return err
		}
		if err := e.validate(); err != nil {
			return err
		}
		// Even another repository maintainer cannot change credential ownership.
		if e.Principal.ID != user.ID {
			return tx.Commit()
		}
		switch action {
		case "start", "status":
		case "pause":
			if e.State == "active" {
				e.State = "paused"
				e.Reason = "Paused by initiator"
			}
		case "cancel":
			if e.State != "completed" {
				e.State = "cancelled"
				e.Reason = "Cancelled by initiator; existing runs are not terminated"
			}
		case "resume":
			if e.State == "paused" {
				failed := false
				for _, c := range e.Children {
					failed = failed || c.State == "Failed"
				}
				if !failed {
					e.State = "active"
					e.Reason = ""
				}
			}
		case "retry":
			if e.State == "paused" {
				e.RetryRequested = true
			}

		default:
			return errors.New("unsupported epic command")
		}
	}
	e.Version++
	if err := e.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO epics(repo,parent,version,data) VALUES(?,?,?,?) ON CONFLICT(repo,parent) DO UPDATE SET version=excluded.version,data=excluded.data`, epicRepoKey(repo), parent, e.Version, data)
	if err != nil {
		return err
	}
	return tx.Commit()
}

type epicAuthorizer interface {
	CanControlEpic(context.Context, Repository, GitHubUser) (bool, error)
}

func (p *Poller) handleEpicCommand(ctx context.Context, repo Repository, comment GitHubIssueComment, command Command) error {
	store, ok := p.State.(*SQLiteStateStore)
	if !ok {
		return errors.New("epics require SQLite state")
	}
	auth, ok := p.GitHub.(epicAuthorizer)
	if !ok {
		return errors.New("epic authorization unavailable")
	}
	if comment.User.ID <= 0 || !IsAllowedAuthor(comment.User.Login, p.Config.AllowedAuthors) {
		return nil
	}
	allowed, err := auth.CanControlEpic(ctx, repo, comment.User)
	if err != nil {
		return err
	}
	if !allowed {
		return nil
	}
	parent, ok := IssueNumberFromIssueURL(comment.IssueURL)
	if !ok {
		return nil
	}
	issue, err := p.GitHub.GetIssue(ctx, repo, parent)
	if err != nil {
		return err
	}
	if issue.PullRequest != nil {
		return nil
	}
	return store.ApplyEpicCommand(ctx, repo, parent, comment.User, comment.ID, command.EpicAction, p.Config.Epics)
}

type EpicAttempt struct {
	Attempt int
	Key     string
	Run     *scheduleAdmissionAgentRun
	PR      *EpicPR
	Reason  string
}

func decodeEpic(raw []byte, e *Epic) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(e)
}
