package producer

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteStateStorePersistsCursorAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	want := time.Date(2026, 6, 23, 12, 34, 56, 789, time.UTC)

	store, err := OpenSQLiteStateStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	setErr := store.SetRepoCursor(ctx, "acme/widget", want)
	if setErr != nil {
		t.Fatal(setErr)
	}
	closeErr := store.Close()
	if closeErr != nil {
		t.Fatal(closeErr)
	}

	reopened, err := OpenSQLiteStateStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := reopened.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
	}()
	got, found, err := reopened.GetRepoCursor(ctx, "acme/widget")
	if err != nil {
		t.Fatal(err)
	}
	if !found || !got.Equal(want) {
		t.Fatalf("got cursor %v want %s", got, want)
	}
}

func TestSQLiteStateStorePersistsHelpResponseClaimAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")

	store, err := OpenSQLiteStateStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimHelpResponse(ctx, "acme/widget", 9001, time.Date(2026, 6, 23, 12, 34, 56, 789, time.UTC))
	if err != nil || !claimed {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenSQLiteStateStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := reopened.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
	}()
	claimed, err = reopened.ClaimHelpResponse(ctx, "acme/widget", 9001, time.Now())
	if err != nil || claimed {
		t.Fatal("expected persisted help response marker")
	}
	if err := reopened.ReleaseHelpResponse(ctx, "acme/widget", 9001); err != nil {
		t.Fatal(err)
	}
	claimed, err = reopened.ClaimHelpResponse(ctx, "acme/widget", 9001, time.Now())
	if err != nil || !claimed {
		t.Fatal("expected released help response marker to be claimable")
	}
}
