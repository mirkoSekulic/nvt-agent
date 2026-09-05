package producer

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
)

type EpicAttempt struct {
	PR            *EpicPRAssociation               `json:"pr,omitempty"`
	PRReason      string                           `json:"prReason,omitempty"`
	MayBeAccepted bool                             `json:"mayBeAccepted,omitempty"`
	Generation    int64                            `json:"generation"`
	Source        GitHubIssue                      `json:"source"`
	Request       profiledScheduleAdmissionRequest `json:"request"`
	State         string                           `json:"state"` // pending (possibly accepted remotely), accepted, rejected
	Reason        string                           `json:"reason,omitempty"`
	AgentRun      *scheduleAdmissionAgentRun       `json:"agentRun,omitempty"`
	AcceptedAt    time.Time                        `json:"acceptedAt,omitempty"`
}

type EpicSchedule struct {
	PRAmbiguity string           `json:"prAmbiguity,omitempty"`
	Version     int              `json:"version"`
	Children    []EpicGraphChild `json:"children"`
	Attempts    []EpicAttempt    `json:"attempts"`
	GraphError  string           `json:"graphError,omitempty"`
	Revision    int64            `json:"-"`
}

type EpicSchedulingStore interface {
	EpicStateStore
	LoadEpicSchedule(context.Context, Repository, EpicRecord) (EpicSchedule, error)
	SaveEpicSchedule(context.Context, Repository, EpicRecord, *EpicSchedule) error
	PauseEpicForPRAmbiguity(context.Context, Repository, *EpicRecord, *EpicSchedule) error
	GetEpicProjection(context.Context, Repository, int, int) (EpicProjection, error)
	ClaimEpicProjection(context.Context, Repository, int, int, time.Time) (bool, error)
	SaveEpicProjection(context.Context, Repository, int, int, EpicProjection) error
}

var errEpicStateChanged = errors.New("epic state changed during reconciliation")

func (s *SQLiteStateStore) migrateEpicScheduling(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS epic_scheduling (
 repo_key TEXT NOT NULL, parent_issue INTEGER NOT NULL, revision INTEGER NOT NULL, record TEXT NOT NULL,
 PRIMARY KEY(repo_key, parent_issue)
);
CREATE TABLE IF NOT EXISTS epic_projections (
 repo_key TEXT NOT NULL, parent_issue INTEGER NOT NULL, issue_number INTEGER NOT NULL,
 marker TEXT NOT NULL, comment_id INTEGER NOT NULL DEFAULT 0, body TEXT NOT NULL DEFAULT '',
 reaction TEXT NOT NULL DEFAULT '', attempted_at INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(repo_key, parent_issue, issue_number)
)`)
	return err
}

func (r EpicSchedule) validate(repo Repository, epic EpicRecord) error {
	if (r.Version != 1 && r.Version != 2) || r.Revision < 0 {
		return errors.New("unsupported epic scheduling state")
	}
	if err := validateEpicGraph(repo, epic.ParentIssue, r.Children); err != nil {
		return err
	}
	if r.Version == 1 && r.PRAmbiguity != "" {
		return errors.New("PR state in version-one scheduling record")
	}
	keys := map[string]bool{}
	active, accepted := 0, 0
	for _, a := range r.Attempts {
		if r.Version == 1 && (a.PR != nil || a.PRReason != "") {
			return errors.New("PR state in version-one scheduling record")
		}
		if a.State != "accepted" && (a.PR != nil || a.PRReason != "") {
			return errors.New("unaccepted attempt has PR state")
		}
		if a.PR != nil {
			if err := a.PR.validate(repo, a.Source); err != nil {
				return err
			}
			if a.PR.ObservedAt.Before(a.AcceptedAt) || a.PRReason != "" || r.PRAmbiguity != "" {
				return errors.New("contradictory epic PR association")
			}
		}
		key, err := EpicAdmissionKey(repo, epic.ParentIssue, a.Source.Number, a.Generation, 1)
		sourceRepo, sourceErr := epicIssueRepository(a.Source)
		if err != nil || sourceErr != nil || a.Generation > epic.Generation ||
			sourceRepo != epic.Repository || a.Source.State != "open" || a.Request.Work.ID != key || keys[key] {
			return errors.New("invalid epic attempt identity")
		}
		if a.Request.Workflow != epic.Workflow || a.Request.Work.Principal != epic.Initiator ||
			a.Request.Work.Repository != epic.Repository || a.Request.Work.URL != a.Source.HTMLURL ||
			a.Request.Work.Title != a.Source.Title || a.Request.Work.Group != "" ||
			a.Request.Input.Prompt == "" || len(a.Request.Input.Prompt) > maxResolvedRunPromptBytes {
			return errors.New("invalid epic attempt request")
		}
		keys[key] = true
		switch a.State {
		case "pending":
			active++
		case "accepted":
			accepted++
			if a.MayBeAccepted {
				return errors.New("accepted attempt is still uncertain")
			}
			active++
			if a.AcceptedAt.IsZero() {
				return errors.New("missing accepted time")
			}
		case "rejected":
			if a.MayBeAccepted {
				return errors.New("rejected attempt may already be accepted")
			}
		default:
			return errors.New("unsupported epic attempt state")
		}
		if a.State != "accepted" && (a.AgentRun != nil || !a.AcceptedAt.IsZero()) {
			return errors.New("unaccepted attempt has run identity")
		}
		if a.AgentRun != nil && (len(utilvalidation.IsDNS1123Subdomain(a.AgentRun.Name)) != 0 || (a.AgentRun.Namespace != "" && len(utilvalidation.IsDNS1123Label(a.AgentRun.Namespace)) != 0)) {
			return errors.New("invalid accepted AgentRun identity")
		}
	}
	if r.PRAmbiguity != "" && accepted != 1 {
		return errors.New("PR ambiguity requires an accepted child")
	}
	if active > epic.MaxParallel {
		return errors.New("epic admission capacity exceeded")
	}
	return nil
}

func (s *SQLiteStateStore) LoadEpicSchedule(ctx context.Context, repo Repository, epic EpicRecord) (EpicSchedule, error) {
	var raw string
	var revision int64
	err := s.db.QueryRowContext(ctx, `SELECT revision, record FROM epic_scheduling WHERE repo_key=? AND parent_issue=?`, epic.Repository, epic.ParentIssue).Scan(&revision, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return EpicSchedule{Version: 2}, nil
	}
	if err != nil {
		return EpicSchedule{}, err
	}
	var record EpicSchedule
	if err := decodeEpicJSON([]byte(raw), &record); err != nil {
		return EpicSchedule{}, err
	}
	record.Revision = revision
	if err := record.validate(repo, epic); err != nil {
		return EpicSchedule{}, err
	}
	// Upgrade the reviewed stage-two records in memory; frozen admission
	// requests and work identities remain byte-for-byte unchanged.
	record.Version = 2
	return record, nil
}

// CAS serializes graph selection and durable reservation before any network
// admission. Commands participate through the exact control-record comparison.
func (s *SQLiteStateStore) SaveEpicSchedule(ctx context.Context, repo Repository, epic EpicRecord, record *EpicSchedule) error {
	return s.saveEpicSchedule(ctx, repo, epic, record, nil)
}

// Ambiguity and the control pause commit together, before any status write.
func (s *SQLiteStateStore) PauseEpicForPRAmbiguity(ctx context.Context, repo Repository, epic *EpicRecord, record *EpicSchedule) error {
	if record.PRAmbiguity == "" || epic.State == EpicCanceled {
		return errors.New("invalid epic PR pause")
	}
	next := *epic
	next.State = EpicPaused
	if err := s.saveEpicSchedule(ctx, repo, *epic, record, &next); err != nil {
		return err
	}
	*epic = next
	return nil
}

func (s *SQLiteStateStore) saveEpicSchedule(ctx context.Context, repo Repository, epic EpicRecord, record *EpicSchedule, next *EpicRecord) error {
	if err := record.validate(repo, epic); err != nil {
		return err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Serialize writers before reading the previous association. Control commands
	// also write this row, so a concurrent pause/cancel invalidates the snapshot.
	if _, err := tx.ExecContext(ctx, `UPDATE producer_epics SET record=record WHERE repo_key=? AND parent_issue=?`, epic.Repository, epic.ParentIssue); err != nil {
		return err
	}
	var previousRaw string
	previousErr := tx.QueryRowContext(ctx, `SELECT record FROM epic_scheduling WHERE repo_key=? AND parent_issue=?`, epic.Repository, epic.ParentIssue).Scan(&previousRaw)
	if previousErr == nil {
		var previous EpicSchedule
		if err := decodeEpicJSON([]byte(previousRaw), &previous); err != nil {
			return err
		}
		for _, old := range previous.Attempts {
			if old.PR == nil {
				continue
			}
			preserved := false
			for _, a := range record.Attempts {
				if a.Request.Work.ID == old.Request.Work.ID && a.Source.ID == old.Source.ID && reflect.DeepEqual(a.PR, old.PR) {
					preserved = true
				}
			}
			if !preserved {
				return errors.New("established epic PR association is immutable")
			}
		}
	} else if !errors.Is(previousErr, sql.ErrNoRows) {
		return previousErr
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO epic_scheduling(repo_key,parent_issue,revision,record) VALUES (?,?,1,?)
ON CONFLICT(repo_key,parent_issue) DO UPDATE SET revision=revision+1,record=excluded.record WHERE revision=?`, epic.Repository, epic.ParentIssue, string(raw), record.Revision)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errEpicStateChanged
	}
	var control string
	if err := tx.QueryRowContext(ctx, `SELECT record FROM producer_epics WHERE repo_key=? AND parent_issue=?`, epic.Repository, epic.ParentIssue).Scan(&control); err != nil {
		return err
	}
	current, err := decodeEpicRecord(control, epic.Repository, epic.ParentIssue)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, epic) {
		return errEpicStateChanged
	}
	if next != nil {
		if err := next.Validate(); err != nil {
			return err
		}
		controlJSON, err := json.Marshal(next)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE producer_epics SET record=? WHERE repo_key=? AND parent_issue=?`, string(controlJSON), epic.Repository, epic.ParentIssue); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	record.Revision++
	return nil
}

type EpicProjection struct {
	Marker    string
	CommentID int64
	Body      string
	Reaction  string
}

func (s *SQLiteStateStore) GetEpicProjection(ctx context.Context, repo Repository, parent, issue int) (EpicProjection, error) {
	marker, err := newHelpResponseMarker()
	if err != nil {
		return EpicProjection{}, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO epic_projections(repo_key,parent_issue,issue_number,marker) VALUES (?,?,?,?) ON CONFLICT DO NOTHING`, canonicalEpicRepository(repo), parent, issue, marker)
	if err != nil {
		return EpicProjection{}, err
	}
	var record EpicProjection
	err = s.db.QueryRowContext(ctx, `SELECT marker,comment_id,body,reaction FROM epic_projections WHERE repo_key=? AND parent_issue=? AND issue_number=?`, canonicalEpicRepository(repo), parent, issue).Scan(&record.Marker, &record.CommentID, &record.Body, &record.Reaction)
	if err != nil {
		return record, err
	}
	if !validHelpResponseMarker(record.Marker) || record.CommentID < 0 {
		return record, errors.New("invalid epic projection")
	}
	return record, nil
}

func (s *SQLiteStateStore) ClaimEpicProjection(ctx context.Context, repo Repository, parent, issue int, now time.Time) (bool, error) {
	result, err := s.db.ExecContext(ctx, `UPDATE epic_projections SET attempted_at=? WHERE repo_key=? AND parent_issue=? AND issue_number=? AND attempted_at<=?`, now.UnixNano(), canonicalEpicRepository(repo), parent, issue, now.Add(-helpResponseRetryDelay).UnixNano())
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

func (s *SQLiteStateStore) SaveEpicProjection(ctx context.Context, repo Repository, parent, issue int, record EpicProjection) error {
	result, err := s.db.ExecContext(ctx, `UPDATE epic_projections SET comment_id=?,body=?,reaction=? WHERE repo_key=? AND parent_issue=? AND issue_number=? AND marker=? AND (comment_id=0 OR comment_id=?)`, record.CommentID, record.Body, record.Reaction, canonicalEpicRepository(repo), parent, issue, record.Marker, record.CommentID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("%w: projection identity", errEpicStateChanged)
	}
	return nil
}
