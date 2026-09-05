package producer

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var epicTestRepo = Repository{Owner: "acme", Name: "widget"}
var epicTestUser = GitHubUser{ID: 1234, Login: "maintainer"}
var epicTestTime = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

func epicTestPolicy() EpicConfig {
	return EpicConfig{Enabled: true, Workflow: "implement-pr", AllowedUserIDs: []int64{1234, 5678}}
}

func TestEpicCommandGrammar(t *testing.T) {
	for _, action := range []string{"start", "status", "pause", "resume", "cancel", "retry"} {
		command := "/custom epic " + action
		got, ok := ParseCommand("\n"+command+"\n", []string{"/custom"})
		if !ok || got.Intent != CommandIntent("epic-"+action) {
			t.Fatalf("did not parse %s: %+v", command, got)
		}
		for _, suffix := range []string{" -- workflow=evil", " --", " profile=evil", "\nworkflow: evil", "\n/nvtagent run -- bad"} {
			if _, ok := ParseCommand(command+suffix, []string{"/custom"}); ok {
				t.Fatalf("accepted override %q", command+suffix)
			}
		}
	}
	for _, command := range []string{"/custom epic", "/custom epic delete", "/custom epic Start", "/nvtagent epic start"} {
		if _, ok := ParseCommand(command, []string{"/custom"}); ok {
			t.Fatalf("accepted %q", command)
		}
	}
}

func TestEpicConfigValidation(t *testing.T) {
	cfg := validTestConfig()
	if err := cfg.ApplyDefaultsAndValidate(); err != nil || cfg.Epics.Enabled {
		t.Fatalf("default epics: %+v, %v", cfg.Epics, err)
	}
	cfg.Submission = SubmissionConfig{Mode: SubmissionModeScheduleAdmission, AdmissionMode: AdmissionModeProfiled, AdmissionTokenFile: "/token"}
	cfg.Epics = epicTestPolicy()
	if err := cfg.ApplyDefaultsAndValidate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Epics.parallelism() != 1 {
		t.Fatal("expected sequential default")
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Epics.Enabled = false },
		func(c *Config) { c.Epics.Workflow = "" },
		func(c *Config) { c.Epics.Workflow = "Bad_Profile" },
		func(c *Config) { c.Epics.MaxParallel = new(int) },
		func(c *Config) { n := 2; c.Epics.MaxParallel = &n },
		func(c *Config) { n := -1; c.Epics.MaxParallel = &n },
		func(c *Config) { c.Epics.AllowedUserIDs = nil },
		func(c *Config) { c.Epics.AllowedUserIDs = []int64{0} },
		func(c *Config) { c.Epics.AllowedUserIDs = []int64{-1} },
		func(c *Config) { c.Epics.AllowedUserIDs = []int64{1234, 1234} },
		func(c *Config) { c.Submission.AdmissionMode = AdmissionModeLegacy },
		func(c *Config) { c.Submission.Mode = SubmissionModeDirect },
	} {
		bad := cfg
		mutate(&bad)
		if err := bad.ApplyDefaultsAndValidate(); err == nil {
			t.Fatalf("accepted invalid config %+v", bad.Epics)
		}
	}
	for _, raw := range []string{
		`{"enabled":true,"profile":"evil"}`,
		`{"enabled":true,"workflow":"ok","unknown":1}`,
		`{"enabled":true,"allowedUserIDs":["*"]}`,
		`{"enabled":"true"}`,
	} {
		var policy EpicConfig
		if err := json.Unmarshal([]byte(raw), &policy); err == nil {
			t.Fatalf("accepted malformed config %s", raw)
		}
	}
	// Exercise the real YAML loading path as well as direct config validation.
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var configJSON map[string]json.RawMessage
	if err := json.Unmarshal(data, &configJSON); err != nil {
		t.Fatal(err)
	}
	configJSON["pollInterval"] = json.RawMessage(`"30s"`)
	data, err = json.Marshal(configJSON)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("epics:\n  enabled: true\n  profile: evil\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("YAML accepted issue-controlled profile")
	}
}

func openEpicTestStore(t *testing.T, path string) *SQLiteStateStore {
	t.Helper()
	store, err := OpenSQLiteStateStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store
}

func epicCommand(t *testing.T, store *SQLiteStateStore, intent CommandIntent, id int64) EpicCommandResult {
	t.Helper()
	result, err := store.ApplyEpicCommand(context.Background(), epicTestRepo, 42, epicTestUser, intent, id, epicTestPolicy(), epicTestTime)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestEpicRestartAndReplay(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	store := openEpicTestStore(t, path)
	initial := epicCommand(t, store, CommandIntentEpicStart, 1)
	if initial.Epic == nil || initial.Epic.State != EpicPending || initial.Epic.Generation != 1 {
		t.Fatalf("start: %+v", initial)
	}
	if got := epicCommand(t, store, CommandIntentEpicPause, 2); got.Epic.State != EpicPaused {
		t.Fatal(got)
	}
	retried := epicCommand(t, store, CommandIntentEpicRetry, 3)
	if retried.Epic.Generation != 2 || retried.Epic.State != EpicPending {
		t.Fatal(retried)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openEpicTestStore(t, path)
	if got := epicCommand(t, store, CommandIntentEpicStart, 1); !reflect.DeepEqual(got, initial) {
		t.Fatalf("replay lost original result: %+v", got)
	}
	epicCommand(t, store, CommandIntentEpicPause, 2)
	epicCommand(t, store, CommandIntentEpicRetry, 3)
	records, err := store.ListEpics(ctx, Repository{Owner: "ACME", Name: "Widget"})
	if err != nil || len(records) != 1 || !reflect.DeepEqual(records[0], *retried.Epic) {
		t.Fatalf("restart/replay mutated state: %+v %v", records, err)
	}
	changedPolicy := epicTestPolicy()
	changedPolicy.Workflow = "new-workflow"
	result, err := store.ApplyEpicCommand(ctx, epicTestRepo, 42, GitHubUser{ID: 1234, Login: "renamed"}, CommandIntentEpicStatus, 4, changedPolicy, epicTestTime)
	if err != nil || result.Epic.Workflow != "implement-pr" || result.Epic.Initiator.DisplayName != "maintainer" {
		t.Fatalf("lost initiating policy: %+v %v", result, err)
	}
	if got := epicCommand(t, store, CommandIntentEpicCancel, 3); got.Reason != "delivery-conflict" {
		t.Fatal("edited comment changed command")
	}
}

func TestEpicAuthorizationAndRejectedReplay(t *testing.T) {
	ctx := context.Background()
	store := openEpicTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	for _, id := range []int64{0, -1, 9999} {
		got, err := store.ApplyEpicCommand(ctx, epicTestRepo, 42, GitHubUser{ID: id, Login: epicTestUser.Login}, CommandIntentEpicStart, 1, epicTestPolicy(), epicTestTime)
		if err != nil || got.Reason != "unauthorized" {
			t.Fatalf("unauthorized start: %+v %v", got, err)
		}
	}
	if result := epicCommand(t, store, CommandIntentEpicPause, 2); result.Reason != "not-started" {
		t.Fatal(result)
	}
	epicCommand(t, store, CommandIntentEpicStart, 3)
	if result := epicCommand(t, store, CommandIntentEpicPause, 2); result.Reason != "not-started" {
		t.Fatal("replayed rejection became an action")
	}
	for index, intent := range []CommandIntent{CommandIntentEpicStart, CommandIntentEpicStatus, CommandIntentEpicPause, CommandIntentEpicResume, CommandIntentEpicCancel, CommandIntentEpicRetry} {
		got, err := store.ApplyEpicCommand(ctx, epicTestRepo, 42, GitHubUser{ID: 5678, Login: "other"}, intent, 100+int64(index), epicTestPolicy(), epicTestTime)
		if err != nil || got.Reason != "not-initiator" {
			t.Fatalf("other allowed principal controlled epic: %+v %v", got, err)
		}
	}
	revoked := epicTestPolicy()
	revoked.AllowedUserIDs = []int64{5678}
	got, err := store.ApplyEpicCommand(ctx, epicTestRepo, 42, epicTestUser, CommandIntentEpicStart, 3, revoked, epicTestTime)
	if err != nil || got.Reason != "unauthorized" {
		t.Fatalf("replay bypassed revocation: %+v %v", got, err)
	}
}

func TestEpicBoundedTransitions(t *testing.T) {
	store := openEpicTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	epicCommand(t, store, CommandIntentEpicStart, 1)
	for _, step := range []struct {
		intent     CommandIntent
		state      EpicLifecycle
		generation int64
		reason     string
	}{
		{CommandIntentEpicRetry, "", 0, "invalid-transition"},
		{CommandIntentEpicResume, "", 0, "invalid-transition"},
		{CommandIntentEpicPause, EpicPaused, 1, ""},
		{CommandIntentEpicStart, EpicPaused, 1, ""},
		{CommandIntentEpicResume, EpicPending, 1, ""},
		{CommandIntentEpicCancel, EpicCanceled, 1, ""},
		{CommandIntentEpicCancel, EpicCanceled, 1, ""},
		{CommandIntentEpicStart, "", 0, "terminal-epic"},
		{CommandIntentEpicPause, "", 0, "invalid-transition"},
		{CommandIntentEpicRetry, "", 0, "invalid-transition"},
		{CommandIntentEpicResume, "", 0, "invalid-transition"},
		{CommandIntentEpicStatus, EpicCanceled, 1, ""},
	} {
		var id int64
		if err := store.db.QueryRow(`SELECT count(*)+10 FROM epic_command_receipts`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		result := epicCommand(t, store, step.intent, id)
		if result.Reason != step.reason || (step.reason == "" && (result.Epic.State != step.state || result.Epic.Generation != step.generation)) {
			t.Fatalf("%s: %+v", step.intent, result)
		}
	}
}

func TestEpicTransactionRollback(t *testing.T) {
	ctx := context.Background()
	store := openEpicTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	epicCommand(t, store, CommandIntentEpicStart, 1)
	// Fail after the state write but before completing the receipt. Neither write
	// may survive; retry must still be able to use this comment ID.
	if _, err := store.db.Exec(`CREATE TRIGGER fail_epic_receipt BEFORE UPDATE ON epic_command_receipts BEGIN SELECT RAISE(ABORT, 'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyEpicCommand(ctx, epicTestRepo, 42, epicTestUser, CommandIntentEpicPause, 2, epicTestPolicy(), epicTestTime); err == nil {
		t.Fatal("expected injected failure")
	}
	records, err := store.ListEpics(ctx, epicTestRepo)
	if err != nil || len(records) != 1 || records[0].State != EpicPending {
		t.Fatalf("partial commit: %+v %v", records, err)
	}
	var count int
	if err := store.db.QueryRow(`SELECT count(*) FROM epic_command_receipts WHERE comment_id=2`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial receipt: %d %v", count, err)
	}
	if _, err := store.db.Exec(`DROP TRIGGER fail_epic_receipt`); err != nil {
		t.Fatal(err)
	}
	if got := epicCommand(t, store, CommandIntentEpicPause, 2); got.Epic.State != EpicPaused {
		t.Fatal(got)
	}
}

func TestEpicStateFailsClosed(t *testing.T) {
	store := openEpicTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	original := epicCommand(t, store, CommandIntentEpicStart, 1).Epic
	for _, mutate := range []func(map[string]any){
		func(e map[string]any) { e["version"] = 2 },
		func(e map[string]any) { e["state"] = "running" },
		func(e map[string]any) { e["generation"] = 0 },
		func(e map[string]any) { e["maxParallel"] = 2 },
		func(e map[string]any) { e["reconciliation"] = "ready" },
		func(e map[string]any) { e["graph"] = map[string]any{"children": []int{42}} },
		func(e map[string]any) { e["graph"] = "malformed" },
		func(e map[string]any) { e["parentIssue"] = 43 },
		func(e map[string]any) { e["repository"] = "other/repo" },
		func(e map[string]any) { e["profile"] = "evil" },
		func(e map[string]any) { e["workflow"] = "" },
		func(e map[string]any) { e["updatedAt"] = "2020-01-01T00:00:00Z" },
		func(e map[string]any) { e["initiator"].(map[string]any)["subject"] = "01234" },
	} {
		raw, _ := json.Marshal(original)
		var value map[string]any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		mutate(value)
		raw, _ = json.Marshal(value)
		if _, err := store.db.Exec(`UPDATE producer_epics SET record=?`, string(raw)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ListEpics(context.Background(), epicTestRepo); err == nil {
			t.Fatalf("recovered unsupported state %s", raw)
		}
		if _, err := store.ApplyEpicCommand(context.Background(), epicTestRepo, 42, epicTestUser, CommandIntentEpicPause, 2, epicTestPolicy(), epicTestTime); err == nil {
			t.Fatalf("changed invalid state %s", raw)
		}
	}
	original.State = EpicPaused
	original.Generation = math.MaxInt64
	if got := transitionEpic(original, original.Repository, 42, epicTestUser, CommandIntentEpicRetry, 3, epicTestPolicy(), epicTestTime); got.Reason != "generation-exhausted" {
		t.Fatal("generation overflow")
	}
}

func TestEpicIdentityKeys(t *testing.T) {
	base, err := EpicChildAttemptKey(epicTestRepo, 42, 43, 1, 1)
	if err != nil || base != "github:acme/widget:epic:42:generation:1:child:43:attempt:1" {
		t.Fatalf("key: %s %v", base, err)
	}
	admission, err := EpicAdmissionKey(Repository{Owner: "ACME", Name: "Widget"}, 42, 43, 1, 1)
	if err != nil || admission != base+":intent:create_pr" {
		t.Fatalf("admission: %s %v", admission, err)
	}
	keys := map[string]bool{base: true}
	for _, values := range [][4]int64{{44, 43, 1, 1}, {42, 44, 1, 1}, {42, 43, 2, 1}, {42, 43, 1, 2}} {
		key, err := EpicChildAttemptKey(epicTestRepo, int(values[0]), int(values[1]), values[2], values[3])
		if err != nil || keys[key] {
			t.Fatalf("key collision: %s %v", key, err)
		}
		keys[key] = true
	}
	for _, values := range [][4]int64{{42, 42, 1, 1}, {0, 43, 1, 1}, {42, 43, 0, 1}, {42, 43, 1, 0}} {
		if _, err := EpicAdmissionKey(epicTestRepo, int(values[0]), int(values[1]), values[2], values[3]); err == nil {
			t.Fatal("accepted invalid identity")
		}
	}
	if strings.Contains(admission, "comment") {
		t.Fatal("comment-dependent key")
	}
}

// Compile-time assertion ensures SQLite supplies the independent durable contract.
var _ EpicStateStore = (*SQLiteStateStore)(nil)

func TestEpicConcurrentDelivery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	stores := []*SQLiteStateStore{openEpicTestStore(t, path), openEpicTestStore(t, path)}
	epicCommand(t, stores[0], CommandIntentEpicStart, 1)
	epicCommand(t, stores[0], CommandIntentEpicPause, 2)
	done := make(chan error, 8)
	for index := range 8 {
		go func() {
			result, err := stores[index%2].ApplyEpicCommand(context.Background(), epicTestRepo, 42, epicTestUser, CommandIntentEpicRetry, 3, epicTestPolicy(), epicTestTime)
			if err == nil && (result.Epic == nil || result.Epic.Generation != 2) {
				err = fmt.Errorf("unexpected concurrent result: %+v", result)
			}
			done <- err
		}()
	}
	for range 8 {
		if err := <-done; err != nil && !strings.Contains(err.Error(), "SQLITE_BUSY") {
			t.Fatal(err)
		}
	}
	// After concurrent transactions finish, replay exactly as the next poll
	// would after a transient SQLite write lock. No partial receipt may remain.
	result := epicCommand(t, stores[0], CommandIntentEpicRetry, 3)
	if result.Epic == nil || result.Epic.Generation != 2 {
		t.Fatalf("retry: %+v", result)
	}

	records, err := stores[1].ListEpics(context.Background(), epicTestRepo)
	if err != nil || len(records) != 1 || records[0].Generation != 2 {
		t.Fatalf("concurrent generation: %+v %v", records, err)
	}
	var count int
	if err := stores[0].db.QueryRow(`SELECT count(*) FROM epic_command_receipts`).Scan(&count); err != nil || count != 3 {
		t.Fatalf("receipts: %d %v", count, err)
	}
}

func TestPendingEpicStatusesValidateReceipts(t *testing.T) {
	store := openEpicTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	epicCommand(t, store, CommandIntentEpicStatus, 1) // Rejected: no epic exists yet.
	epicCommand(t, store, CommandIntentEpicStart, 2)
	epicCommand(t, store, CommandIntentEpicStatus, 3)
	replies, err := store.ListPendingEpicStatuses(context.Background(), epicTestRepo)
	if err != nil || len(replies) != 1 || replies[0].CommentID != 3 {
		t.Fatalf("pending replies: %+v %v", replies, err)
	}
	if _, err := store.db.Exec(`UPDATE epic_command_receipts SET result='{"unknown":true}' WHERE comment_id=3`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListPendingEpicStatuses(context.Background(), epicTestRepo); err == nil {
		t.Fatal("accepted malformed status receipt during recovery")
	}
}
