package producer

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	// Register the pure-Go SQLite driver for database/sql in the producer.
	_ "modernc.org/sqlite"
)

var errSQLiteStatePathRequired = errors.New("sqlite state path is required")

const helpResponseTimeFormat = "2006-01-02T15:04:05.000000000Z07:00"

type StateStore interface {
	GetRepoCursor(ctx context.Context, repoKey string) (time.Time, bool, error)
	SetRepoCursor(ctx context.Context, repoKey string, cursor time.Time) error
	GetOrCreateHelpResponse(ctx context.Context, repoKey string, commentID int64, marker string, now time.Time) (HelpResponseRecord, bool, error)
	TryBeginHelpResponseAttempt(ctx context.Context, repoKey string, commentID int64, now, retryBefore time.Time) (bool, error)
	SetHelpResponseDelivered(ctx context.Context, repoKey string, commentID int64, now time.Time) error
	DeleteDeliveredHelpResponses(ctx context.Context, repoKey string) error
	Close() error
}

type HelpResponseStatus string

const (
	HelpResponsePending   HelpResponseStatus = "pending"
	HelpResponseDelivered HelpResponseStatus = "delivered"
)

type HelpResponseRecord struct {
	Marker      string
	Status      HelpResponseStatus
	AttemptedAt *time.Time
}

type SQLiteStateStore struct {
	db *sql.DB
}

func OpenSQLiteStateStore(ctx context.Context, path string) (*SQLiteStateStore, error) {
	if path == "" {
		return nil, errSQLiteStatePathRequired
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create sqlite state directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite state: %w", err)
	}
	store := &SQLiteStateStore{db: db}
	if err := store.migrate(ctx); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return nil, fmt.Errorf("migrate sqlite state: %w; close sqlite state: %w", err, closeErr)
		}
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStateStore) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS repo_cursors (
	repo_key TEXT PRIMARY KEY,
	cursor_updated_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
)`)
	if err != nil {
		return fmt.Errorf("migrate sqlite state: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS help_comment_responses (
	repo_key TEXT NOT NULL,
	comment_id INTEGER NOT NULL,
	marker TEXT NOT NULL,
	status TEXT NOT NULL CHECK(status IN ('pending', 'delivered')),
	attempted_at TEXT,
	updated_at TEXT NOT NULL,
	PRIMARY KEY (repo_key, comment_id)
)`)
	if err != nil {
		return fmt.Errorf("migrate sqlite state: %w", err)
	}
	return nil
}

func (s *SQLiteStateStore) GetRepoCursor(ctx context.Context, repoKey string) (time.Time, bool, error) {
	var raw string
	err := s.db.QueryRowContext(
		ctx,
		`SELECT cursor_updated_at FROM repo_cursors WHERE repo_key = ?`,
		repoKey,
	).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("get repo cursor: %w", err)
	}
	cursor, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("parse repo cursor: %w", err)
	}
	return cursor, true, nil
}

func (s *SQLiteStateStore) SetRepoCursor(ctx context.Context, repoKey string, cursor time.Time) error {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO repo_cursors (repo_key, cursor_updated_at, updated_at)
VALUES (?, ?, ?)
ON CONFLICT(repo_key) DO UPDATE SET
	cursor_updated_at = excluded.cursor_updated_at,
	updated_at = excluded.updated_at`,
		repoKey,
		cursor.UTC().Format(time.RFC3339Nano),
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("set repo cursor: %w", err)
	}
	return nil
}

func (s *SQLiteStateStore) GetOrCreateHelpResponse(
	ctx context.Context,
	repoKey string,
	commentID int64,
	marker string,
	now time.Time,
) (HelpResponseRecord, bool, error) {
	result, err := s.db.ExecContext(
		ctx,
		`INSERT INTO help_comment_responses (repo_key, comment_id, marker, status, attempted_at, updated_at)
VALUES (?, ?, ?, 'pending', NULL, ?)
ON CONFLICT(repo_key, comment_id) DO NOTHING`,
		repoKey,
		commentID,
		marker,
		now.UTC().Format(helpResponseTimeFormat),
	)
	if err != nil {
		return HelpResponseRecord{}, false, fmt.Errorf("create help response state: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return HelpResponseRecord{}, false, fmt.Errorf("read help response create result: %w", err)
	}
	created := rows == 1
	var rawStatus, rawAttempted string
	err = s.db.QueryRowContext(ctx, `SELECT marker, status, COALESCE(attempted_at, '')
FROM help_comment_responses WHERE repo_key = ? AND comment_id = ?`, repoKey, commentID).
		Scan(&marker, &rawStatus, &rawAttempted)
	if err != nil {
		return HelpResponseRecord{}, false, fmt.Errorf("get help response state: %w", err)
	}
	record := HelpResponseRecord{Marker: marker, Status: HelpResponseStatus(rawStatus)}
	if record.Status != HelpResponsePending && record.Status != HelpResponseDelivered {
		return HelpResponseRecord{}, false, errors.New("invalid help response state")
	}
	if rawAttempted != "" {
		attemptedAt, parseErr := time.Parse(helpResponseTimeFormat, rawAttempted)
		if parseErr != nil {
			return HelpResponseRecord{}, false, fmt.Errorf("parse help response attempt: %w", parseErr)
		}
		record.AttemptedAt = &attemptedAt
	}
	return record, created, nil
}

func (s *SQLiteStateStore) TryBeginHelpResponseAttempt(
	ctx context.Context,
	repoKey string,
	commentID int64,
	now, retryBefore time.Time,
) (bool, error) {
	result, err := s.db.ExecContext(ctx, `UPDATE help_comment_responses
SET attempted_at = ?, updated_at = ?
WHERE repo_key = ? AND comment_id = ? AND status = 'pending'
AND (attempted_at IS NULL OR attempted_at <= ?)`,
		now.UTC().Format(helpResponseTimeFormat), now.UTC().Format(helpResponseTimeFormat), repoKey, commentID,
		retryBefore.UTC().Format(helpResponseTimeFormat),
	)
	if err != nil {
		return false, fmt.Errorf("begin help response attempt: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read help response attempt result: %w", err)
	}
	return rows == 1, nil
}

func (s *SQLiteStateStore) SetHelpResponseDelivered(ctx context.Context, repoKey string, commentID int64, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE help_comment_responses
SET status = 'delivered', updated_at = ?
WHERE repo_key = ? AND comment_id = ? AND status = 'pending'`,
		now.UTC().Format(helpResponseTimeFormat), repoKey, commentID,
	)
	if err != nil {
		return fmt.Errorf("set help response delivered: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return errors.New("set help response delivered")
	}
	if rows == 0 {
		var status string
		if err := s.db.QueryRowContext(ctx, `SELECT status FROM help_comment_responses
WHERE repo_key = ? AND comment_id = ?`, repoKey, commentID).Scan(&status); err != nil || status != string(HelpResponseDelivered) {
			return errors.New("set help response delivered")
		}
	}
	return nil
}

func (s *SQLiteStateStore) DeleteDeliveredHelpResponses(ctx context.Context, repoKey string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM help_comment_responses WHERE repo_key = ? AND status = 'delivered'`, repoKey); err != nil {
		return fmt.Errorf("delete delivered help responses: %w", err)
	}
	return nil
}

func (s *SQLiteStateStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("close sqlite state: %w", err)
	}
	return nil
}

type memoryStateStore struct {
	cursors         map[string]time.Time
	helpResponses   map[string]map[int64]HelpResponseRecord
	helpResponsesMu sync.Mutex
	mu              sync.Mutex
}

func newMemoryStateStore() *memoryStateStore {
	return &memoryStateStore{
		cursors:       map[string]time.Time{},
		helpResponses: map[string]map[int64]HelpResponseRecord{},
	}
}

func (s *memoryStateStore) GetRepoCursor(_ context.Context, repoKey string) (time.Time, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cursor, ok := s.cursors[repoKey]
	if !ok {
		return time.Time{}, false, nil
	}
	return cursor, true, nil
}

func (s *memoryStateStore) SetRepoCursor(_ context.Context, repoKey string, cursor time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cursors[repoKey] = cursor
	return nil
}

func (s *memoryStateStore) GetOrCreateHelpResponse(
	_ context.Context,
	repoKey string,
	commentID int64,
	marker string,
	_ time.Time,
) (HelpResponseRecord, bool, error) {
	s.helpResponsesMu.Lock()
	defer s.helpResponsesMu.Unlock()
	comments, ok := s.helpResponses[repoKey]
	if !ok {
		comments = map[int64]HelpResponseRecord{}
		s.helpResponses[repoKey] = comments
	}
	if record, exists := comments[commentID]; exists {
		return record, false, nil
	}
	record := HelpResponseRecord{Marker: marker, Status: HelpResponsePending}
	comments[commentID] = record
	return record, true, nil
}

func (s *memoryStateStore) TryBeginHelpResponseAttempt(
	_ context.Context,
	repoKey string,
	commentID int64,
	now, retryBefore time.Time,
) (bool, error) {
	s.helpResponsesMu.Lock()
	defer s.helpResponsesMu.Unlock()
	record, exists := s.helpResponses[repoKey][commentID]
	if !exists || record.Status != HelpResponsePending || record.AttemptedAt != nil && record.AttemptedAt.After(retryBefore) {
		return false, nil
	}
	attemptedAt := now.UTC()
	record.AttemptedAt = &attemptedAt
	s.helpResponses[repoKey][commentID] = record
	return true, nil
}

func (s *memoryStateStore) SetHelpResponseDelivered(_ context.Context, repoKey string, commentID int64, _ time.Time) error {
	s.helpResponsesMu.Lock()
	defer s.helpResponsesMu.Unlock()
	record, exists := s.helpResponses[repoKey][commentID]
	if !exists {
		return errors.New("set help response delivered")
	}
	if record.Status == HelpResponseDelivered {
		return nil
	}
	if record.Status != HelpResponsePending {
		return errors.New("set help response delivered")
	}
	record.Status = HelpResponseDelivered
	s.helpResponses[repoKey][commentID] = record
	return nil
}

func (s *memoryStateStore) DeleteDeliveredHelpResponses(_ context.Context, repoKey string) error {
	s.helpResponsesMu.Lock()
	defer s.helpResponsesMu.Unlock()
	for commentID, record := range s.helpResponses[repoKey] {
		if record.Status == HelpResponseDelivered {
			delete(s.helpResponses[repoKey], commentID)
		}
	}
	return nil
}

func (s *memoryStateStore) Close() error {
	return nil
}
