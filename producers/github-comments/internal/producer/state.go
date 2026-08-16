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

type StateStore interface {
	GetRepoCursor(ctx context.Context, repoKey string) (time.Time, bool, error)
	SetRepoCursor(ctx context.Context, repoKey string, cursor time.Time) error
	ClaimHelpResponse(ctx context.Context, repoKey string, commentID int64, claimedAt time.Time) (bool, error)
	ReleaseHelpResponse(ctx context.Context, repoKey string, commentID int64) error
	Close() error
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
CREATE TABLE IF NOT EXISTS help_comment_claims (
	repo_key TEXT NOT NULL,
	comment_id INTEGER NOT NULL,
	claimed_at TEXT NOT NULL,
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

func (s *SQLiteStateStore) ClaimHelpResponse(ctx context.Context, repoKey string, commentID int64, claimedAt time.Time) (bool, error) {
	result, err := s.db.ExecContext(
		ctx,
		`INSERT INTO help_comment_claims (repo_key, comment_id, claimed_at, updated_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(repo_key, comment_id) DO NOTHING`,
		repoKey,
		commentID,
		claimedAt.UTC().Format(time.RFC3339Nano),
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return false, fmt.Errorf("claim help response: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read help response claim result: %w", err)
	}
	return rows == 1, nil
}

func (s *SQLiteStateStore) ReleaseHelpResponse(ctx context.Context, repoKey string, commentID int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM help_comment_claims WHERE repo_key = ? AND comment_id = ?`, repoKey, commentID); err != nil {
		return fmt.Errorf("release help response: %w", err)
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
	helpResponses   map[string]map[int64]time.Time
	helpResponsesMu sync.Mutex
	mu              sync.Mutex
}

func newMemoryStateStore() *memoryStateStore {
	return &memoryStateStore{
		cursors:       map[string]time.Time{},
		helpResponses: map[string]map[int64]time.Time{},
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

func (s *memoryStateStore) ClaimHelpResponse(_ context.Context, repoKey string, commentID int64, claimedAt time.Time) (bool, error) {
	s.helpResponsesMu.Lock()
	defer s.helpResponsesMu.Unlock()
	comments, ok := s.helpResponses[repoKey]
	if !ok {
		comments = map[int64]time.Time{}
		s.helpResponses[repoKey] = comments
	}
	if _, exists := comments[commentID]; exists {
		return false, nil
	}
	comments[commentID] = claimedAt
	return true, nil
}

func (s *memoryStateStore) ReleaseHelpResponse(_ context.Context, repoKey string, commentID int64) error {
	s.helpResponsesMu.Lock()
	defer s.helpResponsesMu.Unlock()
	delete(s.helpResponses[repoKey], commentID)
	return nil
}

func (s *memoryStateStore) Close() error {
	return nil
}
