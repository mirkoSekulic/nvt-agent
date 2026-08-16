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

func TestSQLiteStateStorePersistsAndTransitionsHelpResponse(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	now := time.Date(2026, 6, 23, 12, 34, 56, 789, time.UTC)

	store, err := OpenSQLiteStateStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	record, created, err := store.GetOrCreateHelpResponse(ctx, "acme/widget", 9001, "marker-one", now)
	if err != nil || !created || record.Marker != "marker-one" || record.Status != HelpResponsePending {
		t.Fatalf("created record = %#v created=%v err=%v", record, created, err)
	}
	attempted, err := store.TryBeginHelpResponseAttempt(ctx, "acme/widget", 9001, now, now.Add(-time.Minute))
	if err != nil || !attempted {
		t.Fatalf("first attempt = %v err=%v", attempted, err)
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
	record, created, err = reopened.GetOrCreateHelpResponse(ctx, "acme/widget", 9001, "marker-two", now.Add(time.Second))
	if err != nil || created || record.Marker != "marker-one" || record.Status != HelpResponsePending || record.AttemptedAt == nil || !record.AttemptedAt.Equal(now) {
		t.Fatalf("reopened record = %#v created=%v err=%v", record, created, err)
	}
	attempted, err = reopened.TryBeginHelpResponseAttempt(ctx, "acme/widget", 9001, now.Add(30*time.Second), now.Add(-30*time.Second))
	if err != nil || attempted {
		t.Fatalf("recent attempt was reacquired = %v err=%v", attempted, err)
	}
	attempted, err = reopened.TryBeginHelpResponseAttempt(ctx, "acme/widget", 9001, now.Add(2*time.Minute), now.Add(time.Minute))
	if err != nil || !attempted {
		t.Fatalf("stale attempt was not reacquired = %v err=%v", attempted, err)
	}
	if err := reopened.SetHelpResponseDelivered(ctx, "acme/widget", 9001, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	record, created, err = reopened.GetOrCreateHelpResponse(ctx, "acme/widget", 9001, "marker-three", now)
	if err != nil || created || record.Status != HelpResponseDelivered {
		t.Fatalf("delivered record = %#v created=%v err=%v", record, created, err)
	}
	if err := reopened.DeleteDeliveredHelpResponses(ctx, "acme/widget"); err != nil {
		t.Fatal(err)
	}
	record, created, err = reopened.GetOrCreateHelpResponse(ctx, "acme/widget", 9001, "marker-four", now)
	if err != nil || !created || record.Marker != "marker-four" {
		t.Fatalf("record after cleanup = %#v created=%v err=%v", record, created, err)
	}
}
