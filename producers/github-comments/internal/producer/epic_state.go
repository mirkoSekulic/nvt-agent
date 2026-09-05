package producer

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// EpicStateStore is separate from cursor/help state so opting out keeps existing
// stores and commands unchanged. Enabling epics requires a durable implementation.
type EpicStateStore interface {
	ApplyEpicCommand(context.Context, Repository, int, GitHubUser, CommandIntent, int64, EpicConfig, time.Time) (EpicCommandResult, error)
	ListEpics(context.Context, Repository) ([]EpicRecord, error)
	ListPendingEpicStatuses(context.Context, Repository) ([]EpicStatusReply, error)
}

type EpicStatusReply struct {
	CommentID int64
	Snapshot  EpicRecord
}

// The committed status command is the delivery obligation, even if the process
// stopped before creating response state. Keep its original snapshot and exclude
// delivered responses without depending on the repository cursor or source feed.
func (s *SQLiteStateStore) ListPendingEpicStatuses(ctx context.Context, repo Repository) ([]EpicStatusReply, error) {
	key := canonicalEpicRepository(repo)
	rows, err := s.db.QueryContext(ctx, `SELECT c.comment_id, c.parent_issue, c.subject, c.result
FROM epic_command_receipts c
LEFT JOIN help_comment_responses h ON h.repo_key = ? AND h.comment_id = c.comment_id
WHERE c.repo_key = ? AND c.intent = 'epic-status'
AND (h.status IS NULL OR h.status <> 'delivered')
ORDER BY c.comment_id`, "epic:"+key, key)
	if err != nil {
		return nil, fmt.Errorf("list pending epic statuses: %w", err)
	}
	defer rows.Close()
	var replies []EpicStatusReply
	for rows.Next() {
		var commentID int64
		var parent int
		var subject, raw string
		if err := rows.Scan(&commentID, &parent, &subject, &raw); err != nil {
			return nil, err
		}
		var result EpicCommandResult
		if err := decodeEpicJSON([]byte(raw), &result); err != nil {
			return nil, err
		}
		if err := validateEpicResult(result, key, parent, subject); err != nil {
			return nil, err
		}
		if result.Epic != nil {
			replies = append(replies, EpicStatusReply{CommentID: commentID, Snapshot: *result.Epic})
		}
	}
	return replies, rows.Err()
}

func (s *SQLiteStateStore) migrateEpics(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS producer_epics (
 repo_key TEXT NOT NULL,
 parent_issue INTEGER NOT NULL CHECK(parent_issue > 0),
 record TEXT NOT NULL,
 PRIMARY KEY(repo_key, parent_issue)
);
CREATE TABLE IF NOT EXISTS epic_command_receipts (
 repo_key TEXT NOT NULL,
 comment_id INTEGER NOT NULL CHECK(comment_id > 0),
 parent_issue INTEGER NOT NULL CHECK(parent_issue > 0),
 subject TEXT NOT NULL,
 intent TEXT NOT NULL CHECK(intent IN ('epic-start','epic-status','epic-pause','epic-resume','epic-cancel','epic-retry')),
 result TEXT NOT NULL,
 PRIMARY KEY(repo_key, comment_id)
)`)
	if err != nil {
		return fmt.Errorf("migrate epic state: %w", err)
	}
	return s.migrateEpicScheduling(ctx)
}

func decodeEpicRecord(raw, repo string, parent int) (EpicRecord, error) {
	var record EpicRecord
	if err := decodeEpicJSON([]byte(raw), &record); err != nil {
		return EpicRecord{}, fmt.Errorf("decode epic state: %w", err)
	}
	if err := record.Validate(); err != nil {
		return EpicRecord{}, err
	}
	if record.Repository != repo || record.ParentIssue != parent {
		return EpicRecord{}, errors.New("epic identity does not match storage key")
	}
	return record, nil
}

// ListEpics recovers reconciliation input without consulting comments or cursors.
// Any malformed record rejects the entire repository snapshot.
func (s *SQLiteStateStore) ListEpics(ctx context.Context, repo Repository) ([]EpicRecord, error) {
	key := canonicalEpicRepository(repo)
	rows, err := s.db.QueryContext(ctx, `SELECT parent_issue, record FROM producer_epics WHERE repo_key = ? ORDER BY parent_issue`, key)
	if err != nil {
		return nil, fmt.Errorf("list epics: %w", err)
	}
	defer rows.Close()
	records := []EpicRecord{}
	for rows.Next() {
		var parent int
		var raw string
		if err := rows.Scan(&parent, &raw); err != nil {
			return nil, err
		}
		record, err := decodeEpicRecord(raw, key, parent)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

// ApplyEpicCommand commits the state and delivery receipt together, before the
// caller advances a poll cursor or writes any display. Receipt claiming is the
// first transactional statement to serialize writers before reading state.
func (s *SQLiteStateStore) ApplyEpicCommand(ctx context.Context, repo Repository, parent int, user GitHubUser, intent CommandIntent, commentID int64, policy EpicConfig, now time.Time) (EpicCommandResult, error) {
	if err := policy.validate(SubmissionConfig{Mode: SubmissionModeScheduleAdmission, AdmissionMode: AdmissionModeProfiled}); err != nil {
		return EpicCommandResult{}, err
	}
	if !policy.allows(user.ID) {
		return EpicCommandResult{Reason: "unauthorized"}, nil
	}
	key := canonicalEpicRepository(repo)
	if !epicRepositoryPattern.MatchString(key) || parent <= 0 || commentID <= 0 || user.Login == "" || now.IsZero() || !isEpicIntent(intent) {
		return EpicCommandResult{Reason: "invalid-command"}, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return EpicCommandResult{}, err
	}
	defer tx.Rollback()
	subject := strconv.FormatInt(user.ID, 10)
	claim, err := tx.ExecContext(ctx, `INSERT INTO epic_command_receipts(repo_key, comment_id, parent_issue, subject, intent, result)
VALUES (?, ?, ?, ?, ?, '{}') ON CONFLICT(repo_key, comment_id) DO NOTHING`, key, commentID, parent, subject, intent)
	if err != nil {
		return EpicCommandResult{}, err
	}
	count, err := claim.RowsAffected()
	if err != nil {
		return EpicCommandResult{}, err
	}
	if count == 0 {
		var storedParent int
		var storedSubject, storedIntent, raw string
		if err := tx.QueryRowContext(ctx, `SELECT parent_issue, subject, intent, result FROM epic_command_receipts WHERE repo_key = ? AND comment_id = ?`, key, commentID).
			Scan(&storedParent, &storedSubject, &storedIntent, &raw); err != nil {
			return EpicCommandResult{}, err
		}
		if storedParent != parent || storedSubject != subject || storedIntent != string(intent) {
			return EpicCommandResult{Reason: "delivery-conflict"}, nil
		}
		var result EpicCommandResult
		if err := decodeEpicJSON([]byte(raw), &result); err != nil {
			return EpicCommandResult{}, err
		}
		if err := validateEpicResult(result, key, parent, subject); err != nil {
			return EpicCommandResult{}, err
		}
		return result, nil
	}
	var raw string
	var current *EpicRecord
	err = tx.QueryRowContext(ctx, `SELECT record FROM producer_epics WHERE repo_key = ? AND parent_issue = ?`, key, parent).Scan(&raw)
	if err == nil {
		record, decodeErr := decodeEpicRecord(raw, key, parent)
		if decodeErr != nil {
			return EpicCommandResult{}, decodeErr
		}
		current = &record
	} else if !errors.Is(err, sql.ErrNoRows) {
		return EpicCommandResult{}, err
	}
	result := transitionEpic(current, key, parent, user, intent, commentID, policy, now.UTC())
	if err := validateEpicResult(result, key, parent, subject); err != nil {
		return EpicCommandResult{}, err
	}
	if result.Epic != nil {
		recordJSON, err := json.Marshal(result.Epic)
		if err != nil {
			return EpicCommandResult{}, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO producer_epics(repo_key, parent_issue, record) VALUES (?, ?, ?)
ON CONFLICT(repo_key, parent_issue) DO UPDATE SET record = excluded.record`, key, parent, string(recordJSON)); err != nil {
			return EpicCommandResult{}, err
		}
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return EpicCommandResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE epic_command_receipts SET result = ? WHERE repo_key = ? AND comment_id = ?`, string(resultJSON), key, commentID); err != nil {
		return EpicCommandResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return EpicCommandResult{}, err
	}
	return result, nil
}

func validateEpicResult(result EpicCommandResult, repo string, parent int, subject string) error {
	if result.Epic != nil {
		if result.Reason != "" || result.Epic.Repository != repo || result.Epic.ParentIssue != parent || result.Epic.Initiator.Subject != subject {
			return errors.New("contradictory epic command result")
		}
		return result.Epic.Validate()
	}
	switch result.Reason {
	case "not-started", "not-initiator", "terminal-epic", "invalid-transition", "generation-exhausted":
		return nil
	default:
		return errors.New("invalid epic command receipt")
	}
}
