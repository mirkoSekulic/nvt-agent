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
	cursors map[string]time.Time
	mu      sync.Mutex
}

func newMemoryStateStore() *memoryStateStore {
	return &memoryStateStore{cursors: map[string]time.Time{}}
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

func (s *memoryStateStore) Close() error {
	return nil
}
