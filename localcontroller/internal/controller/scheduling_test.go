package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	localmanifest "github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
)

const schedulingTestToken = "LOCAL-SCHEDULING-TOKEN-0123456789abcdef"

func TestLocalManifestProducerNameMatchesScheduleValidator(t *testing.T) {
const raw = `apiVersion: nvt.dev/local/v1
retentionPolicies:
  disposable: {ttl: {activeSeconds: 604800}}
profiles:
  engineering:
    runtime: {preset: shell, autonomy: approval-required}
repositories:
  widget:
    url: https://example.test/acme/widget.git
    checkoutTarget: example.test/acme/widget
workflows:
  development: {profile: engineering, repository: widget, retention: disposable}
producers:
  - name: github-comments
    image: ghcr.io/example/producer@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    runtimeIdentity: {uid: 1000, gid: 1000}
    workflow: development
    allowedPrincipalIssuers: [https://identity.example.test]
`
	decoded, err := localmanifest.Decode(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("decode local manifest: %v", err)
	}
	compiled, err := localmanifest.Compile(decoded)
	if err != nil {
		t.Fatalf("compile local manifest: %v", err)
	}
	if len(compiled.Controller.ProducerAdmissions) != 1 {
		t.Fatalf("producer admissions = %#v", compiled.Controller.ProducerAdmissions)
	}
	admission := compiled.Controller.ProducerAdmissions[0]
	if !validRunID(admission.Producer) {
		t.Fatalf("compiled producer %q is not a valid schedule name", admission.Producer)
	}
	selectedProfile := ""
	for _, workflow := range compiled.Controller.Workflows {
		if workflow.Name == admission.Workflow {
			selectedProfile = workflow.Workflow.Profile
		}
	}
	if !validRunID(selectedProfile) {
		t.Fatalf("compiled profile %q is not valid schedule authorization", selectedProfile)
	}

	clock := &fakeClock{value: time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "producer-token")
	if err := os.WriteFile(tokenPath, []byte(schedulingTestToken), 0o600); err != nil {
		t.Fatal(err)
	}
	document := testNativeConfiguration()
	document.Schedules = []scheduleConfig{{Name: admission.Producer, Producers: []scheduleProducerConfig{{
		Identity: admission.Identity, TokenFile: tokenPath, AllowedPrincipalIssuers: admission.AllowedPrincipalIssuers,
		Selections: []scheduleSelection{{Profile: selectedProfile, Workflow: admission.Workflow}}, DefaultWorkflow: admission.Workflow,
		Retention: "disposable", Backend: "container",
	}}}}
	configPath := filepath.Join(directory, "local-controller.yaml")
	if err := os.WriteFile(configPath, mustJSON(t, document), 0o600); err != nil {
		t.Fatal(err)
	}
	if scheduler, err := LoadScheduler(configPath, store); err != nil || scheduler == nil {
		t.Fatalf("controller rejected compiled producer schedule: scheduler=%#v err=%v", scheduler, err)
	}

	dotted := strings.Replace(raw, "name: github-comments", "name: github.comments", 1)
	if _, err := localmanifest.Decode(strings.NewReader(dotted)); err == nil {
		t.Fatal("dotted producer name passed local-manifest decode")
	}
	dottedProfile := strings.Replace(raw, "engineering:", "engineering.team:", 1)
	dottedProfile = strings.Replace(dottedProfile, "profile: engineering", "profile: engineering.team", 1)
	if _, err := localmanifest.Decode(strings.NewReader(dottedProfile)); err == nil {
		t.Fatal("dotted selected profile passed local-manifest decode")
	}
}

func TestLocalSchedulingIsOptionalAndRejectsNonPrivateToken(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	disabled, err := LoadScheduler("", store)
	if err != nil || disabled != nil {
		t.Fatalf("omitted scheduler = %#v err=%v", disabled, err)
	}
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "token")
	if err := os.WriteFile(tokenPath, []byte(schedulingTestToken), 0o644); err != nil {
		t.Fatal(err)
	}
	document := testNativeConfiguration()
	document.Schedules = []scheduleConfig{{Name: "github", Producers: []scheduleProducerConfig{{
		Identity: "producer", TokenFile: tokenPath, AllowedPrincipalIssuers: []string{"https://identity.example.test"},
		Selections: []scheduleSelection{{Profile: "engineering", Workflow: "development"}}, DefaultWorkflow: "development", Retention: "disposable",
	}}}}
	path := filepath.Join(directory, "local-controller.yaml")
	if err := os.WriteFile(path, mustJSON(t, document), 0o600); err != nil {
		t.Fatal(err)
	}
	if scheduler, err := LoadScheduler(path, store); err == nil || scheduler != nil {
		t.Fatal("non-private scheduling bearer was accepted")
	}
}

func TestConfiguredWorkstationsBootstrapIdempotentlyAndRejectDrift(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	directory := t.TempDir()
	document := testNativeConfiguration()
	document.Workstations = []workstationConfig{{
		Name: "nvt", Principal: resolvedrun.Principal{Issuer: "https://local.nvt.test", Subject: "workstation-nvt"},
		Profile: "engineering", Workflow: "development", Retention: "persistent", Backend: "container",
	}}
	path := filepath.Join(directory, "local-controller.yaml")
	if err := os.WriteFile(path, mustJSON(t, document), 0o600); err != nil {
		t.Fatal(err)
	}
	scheduler, err := LoadScheduler(path, store)
	if err != nil || scheduler == nil {
		t.Fatalf("load local runs = %#v %v", scheduler, err)
	}
	if err := scheduler.BootstrapWorkstations(context.Background()); err != nil {
		t.Fatal(err)
	}
	restarted, err := LoadScheduler(path, store)
	if err != nil || restarted.BootstrapWorkstations(context.Background()) != nil {
		t.Fatalf("idempotent bootstrap failed: %v", err)
	}
	listed, err := store.List(context.Background(), 10, "")
	if err != nil || len(listed.Runs) != 1 || listed.Runs[0].RunID != "nvt" || listed.Runs[0].Subject != "workstation-nvt" {
		t.Fatalf("bootstrapped runs = %#v err=%v", listed, err)
	}
	document.Workstations[0].Principal.DisplayName = "changed immutable selection"
	if err := os.WriteFile(path, mustJSON(t, document), 0o600); err != nil {
		t.Fatal(err)
	}
	drifted, err := LoadScheduler(path, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := drifted.BootstrapWorkstations(context.Background()); !errors.Is(err, ErrConflict) {
		t.Fatalf("configuration drift = %v, want conflict", err)
	}
}

func TestConfiguredWorkstationsBootstrapIsAtomic(t *testing.T) {
	t.Run("later drift", func(t *testing.T) {
		clock := &fakeClock{value: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
		store, _ := openTestStore(t, clock, 4)
		original := writeWorkstationDocument(t, []workstationConfig{testWorkstation("second", "")})
		scheduler, err := LoadScheduler(original, store)
		if err != nil || scheduler.BootstrapWorkstations(context.Background()) != nil {
			t.Fatalf("initial bootstrap: %v", err)
		}
		before, err := store.Get(context.Background(), "second")
		if err != nil {
			t.Fatal(err)
		}
		clock.value = clock.value.Add(24 * time.Hour)
		attempt := writeWorkstationDocument(t, []workstationConfig{testWorkstation("first", ""), testWorkstation("second", "changed")})
		scheduler, err = LoadScheduler(attempt, store)
		if err != nil {
			t.Fatal(err)
		}
		if err := scheduler.BootstrapWorkstations(context.Background()); !errors.Is(err, ErrConflict) {
			t.Fatalf("drift error = %v", err)
		}
		clock.value = before.UpdatedAt
		assertRunIDs(t, store, "second")
		after, err := store.Get(context.Background(), "second")
		if err != nil || after.State != before.State || after.Revision != before.Revision || after.UpdatedAt != before.UpdatedAt {
			t.Fatalf("rejected batch mutated existing state: before=%#v after=%#v err=%v", before, after, err)
		}
	})

	t.Run("capacity", func(t *testing.T) {
		clock := &fakeClock{value: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
		store, _ := openTestStore(t, clock, 2)
		if _, err := store.Create(context.Background(), CreateInput{IdempotencyKey: "existing-work-key", ResolvedRun: testResolvedRun(t, "existing", false)}); err != nil {
			t.Fatal(err)
		}
		attempt := writeWorkstationDocument(t, []workstationConfig{testWorkstation("first", ""), testWorkstation("second", "")})
		scheduler, err := LoadScheduler(attempt, store)
		if err != nil {
			t.Fatal(err)
		}
		if err := scheduler.BootstrapWorkstations(context.Background()); !errors.Is(err, ErrCapacityExceeded) {
			t.Fatalf("capacity error = %v", err)
		}
		assertRunIDs(t, store, "existing")
	})

	t.Run("tombstone", func(t *testing.T) {
		clock := &fakeClock{value: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
		store, _ := openTestStore(t, clock, 4)
		original := writeWorkstationDocument(t, []workstationConfig{testWorkstation("second", "")})
		scheduler, err := LoadScheduler(original, store)
		if err != nil || scheduler.BootstrapWorkstations(context.Background()) != nil {
			t.Fatalf("initial bootstrap: %v", err)
		}
		stopping, _, err := store.Delete(context.Background(), "second")
		if err != nil {
			t.Fatal(err)
		}
		claimed := claimRun(t, store, stopping, "cleanup")
		if _, err := store.UpdateStatus(context.Background(), StatusInput{RunID: "second", Owner: "cleanup", ExpectedRevision: claimed.Revision, State: StateCompleted, Reason: "cleanup-complete"}); !errors.Is(err, ErrGone) {
			t.Fatalf("tombstone completion = %v", err)
		}
		attempt := writeWorkstationDocument(t, []workstationConfig{testWorkstation("first", ""), testWorkstation("second", "")})
		scheduler, err = LoadScheduler(attempt, store)
		if err != nil {
			t.Fatal(err)
		}
		if err := scheduler.BootstrapWorkstations(context.Background()); !errors.Is(err, ErrGone) {
			t.Fatalf("tombstone error = %v", err)
		}
		listed, listErr := store.List(context.Background(), 10, "")
		if listErr != nil || len(listed.Runs) != 0 {
			t.Fatalf("tombstone batch changed visible state: %#v %v", listed, listErr)
		}
		if _, err := store.Get(context.Background(), "first"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("partial first run exists: %v", err)
		}
	})
}

func TestConfiguredWorkstationsBootstrapReclaimsExpiredCapacityAfterRestart(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	store, path := openTestStore(t, clock, 2)
	for _, runID := range []string{"expired-a", "expired-b"} {
		if _, err := store.Create(context.Background(), CreateInput{IdempotencyKey: "expired-key-" + runID, ResolvedRun: testResolvedRun(t, runID, false)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	clock.value = clock.value.Add(24 * time.Hour)
	restarted, err := OpenStore(context.Background(), path, StoreOptions{MaxActiveRuns: 2, MaxClaimLease: time.Minute, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	scheduler, err := LoadScheduler(writeWorkstationDocument(t, []workstationConfig{testWorkstation("first", ""), testWorkstation("second", "")}), restarted)
	if err != nil {
		t.Fatal(err)
	}
	if err := scheduler.BootstrapWorkstations(context.Background()); err != nil {
		t.Fatalf("expired downtime capacity blocked named bootstrap: %v", err)
	}
	listed, err := restarted.List(context.Background(), 10, "")
	if err != nil || len(listed.Runs) != 4 {
		t.Fatalf("restart rows = %#v err=%v", listed, err)
	}
	states := map[string]State{}
	for _, run := range listed.Runs {
		states[run.RunID] = run.State
	}
	if states["expired-a"] != StateStopping || states["expired-b"] != StateStopping || states["first"] != StatePending || states["second"] != StatePending {
		t.Fatalf("atomic deadline/bootstrap states = %#v", states)
	}
}

func testWorkstation(runID, displayName string) workstationConfig {
	return workstationConfig{
		Name: runID, Principal: resolvedrun.Principal{Issuer: "https://local.nvt.test", Subject: "workstation-" + runID, DisplayName: displayName},
		Profile: "engineering", Workflow: "development", Retention: "persistent", Backend: "container",
	}
}

func writeWorkstationDocument(t *testing.T, workstations []workstationConfig) string {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "local-controller.yaml")
	document := testNativeConfiguration()
	document.Workstations = workstations
	if err := os.WriteFile(path, mustJSON(t, document), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertRunIDs(t *testing.T, store *Store, expected ...string) {
	t.Helper()
	listed, err := store.List(context.Background(), 10, "")
	if err != nil || len(listed.Runs) != len(expected) {
		t.Fatalf("runs = %#v err=%v", listed, err)
	}
	for index, runID := range expected {
		if listed.Runs[index].RunID != runID {
			t.Fatalf("runs = %#v, want %v", listed.Runs, expected)
		}
	}
}

func TestLocalSchedulingAuthorizesSelectionIsIdempotentAndSupportsStatusCancel(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 4)
	var logs bytes.Buffer
	scheduler := testScheduler(t, store, schedulingTestToken)
	handler := NewHTTPHandlerWithServices(store, log.New(&logs, "", 0), nil, nil, scheduler)
	body := testAdmissionBody(t, "https://identity.example.test", "subject-1", "development", "Implement the bounded change")

	created := scheduleRequest(t, handler, http.MethodPost, "/v1/schedules/github/admissions", body, schedulingTestToken)
	if created.Code != http.StatusCreated || !containsAll(created.Body.String(), `"scheduled":true`, `"namespace":"local"`, `"state":"pending"`) {
		t.Fatalf("created = %d %s", created.Code, created.Body.String())
	}
	restartedScheduler := testScheduler(t, store, schedulingTestToken)
	restartedHandler := NewHTTPHandlerWithServices(store, log.New(&logs, "", 0), nil, nil, restartedScheduler)
	replayed := scheduleRequest(t, restartedHandler, http.MethodPost, "/v1/schedules/github/admissions", body, schedulingTestToken)
	if replayed.Code != http.StatusAccepted || replayed.Body.String() != `{"scheduled":false,"reason":"duplicate-work"}`+"\n" {
		t.Fatalf("replay = %d %s", replayed.Code, replayed.Body.String())
	}
	runs, err := store.List(context.Background(), 10, "")
	if err != nil || len(runs.Runs) != 1 {
		t.Fatalf("durable runs = %#v err=%v", runs, err)
	}
	snapshot, _, err := store.ResolvedSnapshot(context.Background(), runs.Runs[0].RunID)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolvedrun.DecodeResolvedAgentRun(snapshot)
	clear(snapshot)
	if err != nil || resolved.Principal.Issuer != "https://identity.example.test" || resolved.Principal.Subject != "subject-1" ||
		resolved.Profile != "engineering" || resolved.Workflow != "development" || resolved.Prompt != "Implement the bounded change" ||
		resolved.Execution.Name != "container" || resolved.Retention != "disposable" {
		t.Fatalf("resolved trusted selection = %#v err=%v", resolved, err)
	}
	status := scheduleRequest(t, restartedHandler, http.MethodGet, "/v1/schedules/github/work?work_id=acme/widget/issues/7", nil, schedulingTestToken)
	if status.Code != http.StatusOK || !containsAll(status.Body.String(), `"scheduled":true`, `"state":"pending"`) {
		t.Fatalf("status = %d %s", status.Code, status.Body.String())
	}
	cancelled := scheduleRequest(t, restartedHandler, http.MethodPost, "/v1/schedules/github/work/cancel?work_id=acme/widget/issues/7", nil, schedulingTestToken)
	if cancelled.Code != http.StatusAccepted || !strings.Contains(cancelled.Body.String(), `"state":"stopping"`) {
		t.Fatalf("cancel = %d %s", cancelled.Code, cancelled.Body.String())
	}
	if strings.Contains(logs.String(), schedulingTestToken) || strings.Contains(created.Body.String()+replayed.Body.String(), schedulingTestToken) {
		t.Fatalf("scheduling token disclosed: logs=%s", logs.String())
	}
}

func TestLocalSchedulingActiveWorkGroupPrecedesCapacityAndTerminalAllowsReplacement(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 1)
	scheduler := testScheduler(t, store, schedulingTestToken)
	handler := NewHTTPHandlerWithServices(store, nil, nil, nil, scheduler)
	const group = "github:acme/widget:issue:7:intent:pr-continue"
	// Before the group field existed, pr-continue used the stable group value as
	// its work ID. A rolling upgrade must still recognize that active session.
	firstBody := testAdmissionBodyWithWork(t, group, "")
	secondBody := testAdmissionBodyWithWork(t, "continue-comment-202", group)

	created := scheduleRequest(t, handler, http.MethodPost, "/v1/schedules/github/admissions", firstBody, schedulingTestToken)
	if created.Code != http.StatusCreated {
		t.Fatalf("first admission = %d %s", created.Code, created.Body.String())
	}
	duplicate := scheduleRequest(t, handler, http.MethodPost, "/v1/schedules/github/admissions", secondBody, schedulingTestToken)
	if duplicate.Code != http.StatusAccepted || duplicate.Body.String() != `{"scheduled":false,"reason":"duplicate-work"}`+"\n" {
		t.Fatalf("active group at capacity = %d %s", duplicate.Code, duplicate.Body.String())
	}

	listed, err := store.List(context.Background(), 10, "")
	if err != nil || len(listed.Runs) != 1 {
		t.Fatalf("runs = %#v err=%v", listed, err)
	}
	stopping, _, err := store.Delete(context.Background(), listed.Runs[0].RunID)
	if err != nil {
		t.Fatal(err)
	}
	claimed := claimRun(t, store, stopping, "cleanup")
	if _, err := store.UpdateStatus(context.Background(), StatusInput{
		RunID: claimed.RunID, Owner: "cleanup", ExpectedRevision: claimed.Revision,
		State: StateCompleted, Reason: "cleanup-complete",
	}); !errors.Is(err, ErrGone) {
		t.Fatalf("terminal transition = %v", err)
	}

	replacement := scheduleRequest(t, handler, http.MethodPost, "/v1/schedules/github/admissions", secondBody, schedulingTestToken)
	if replacement.Code != http.StatusCreated {
		t.Fatalf("replacement admission = %d %s", replacement.Code, replacement.Body.String())
	}
	thirdBody := testAdmissionBodyWithWork(t, "continue-comment-303", group)
	duplicate = scheduleRequest(t, handler, http.MethodPost, "/v1/schedules/github/admissions", thirdBody, schedulingTestToken)
	if duplicate.Code != http.StatusAccepted || !strings.Contains(duplicate.Body.String(), `"reason":"duplicate-work"`) {
		t.Fatalf("replacement group was not exclusive = %d %s", duplicate.Code, duplicate.Body.String())
	}
}

func TestWorkstationsAndDisposableSchedulesSharePolicyAcrossRestart(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	store, path := openTestStore(t, clock, 8)
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "producer-token")
	if err := os.WriteFile(tokenPath, []byte(schedulingTestToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "local-controller.yaml")
	document := testNativeConfiguration()
	document.Schedules = []scheduleConfig{{Name: "github", Producers: []scheduleProducerConfig{{
		Identity: "github-comments", TokenFile: tokenPath, AllowedPrincipalIssuers: []string{"https://identity.example.test"},
		Selections: []scheduleSelection{{Profile: "engineering", Workflow: "development"}}, DefaultWorkflow: "development",
		Retention: "disposable", Backend: "container",
	}}}}
	document.Workstations = []workstationConfig{testWorkstation("nvt", "NVT development")}
	if err := os.WriteFile(configPath, mustJSON(t, document), 0o600); err != nil {
		t.Fatal(err)
	}
	scheduler, err := LoadScheduler(configPath, store)
	if err != nil || scheduler.BootstrapWorkstations(context.Background()) != nil {
		t.Fatalf("composed startup = %#v %v", scheduler, err)
	}
	handler := NewHTTPHandlerWithServices(store, nil, nil, nil, scheduler)
	response := scheduleRequest(t, handler, http.MethodPost, "/v1/schedules/github/admissions",
		testAdmissionBody(t, "https://identity.example.test", "producer-subject", "development", "disposable work"), schedulingTestToken)
	if response.Code != http.StatusCreated {
		t.Fatalf("disposable admission = %d %s", response.Code, response.Body.String())
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenStore(context.Background(), path, StoreOptions{MaxActiveRuns: 8, MaxClaimLease: time.Minute, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restartedScheduler, err := LoadScheduler(configPath, restarted)
	if err != nil || restartedScheduler.BootstrapWorkstations(context.Background()) != nil {
		t.Fatalf("composed restart = %#v %v", restartedScheduler, err)
	}
	listed, err := restarted.List(context.Background(), 10, "")
	if err != nil || len(listed.Runs) != 2 {
		t.Fatalf("composed durable runs = %#v %v", listed, err)
	}
	var namedPersistent, disposable bool
	for _, run := range listed.Runs {
		namedPersistent = namedPersistent || run.RunID == "nvt" && run.Persistent
		disposable = disposable || strings.HasPrefix(run.RunID, "local-") && !run.Persistent && run.DeadlineAt != nil
	}
	if !namedPersistent || !disposable {
		t.Fatalf("composed retention semantics = %#v", listed.Runs)
	}
}

func TestNativeWorkstationAddAndRemovalAreAtomicAndNonDestructive(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 8)
	firstPath := writeWorkstationDocument(t, []workstationConfig{testWorkstation("nvt", "NVT"), testWorkstation("studio", "Studio")})
	first, err := LoadScheduler(firstPath, store)
	if err != nil || first.BootstrapWorkstations(context.Background()) != nil {
		t.Fatalf("initial workstations: %v", err)
	}
	nvtBefore, err := store.Get(context.Background(), "nvt")
	if err != nil {
		t.Fatal(err)
	}
	removedPath := writeWorkstationDocument(t, []workstationConfig{testWorkstation("nvt", "NVT")})
	removed, err := LoadScheduler(removedPath, store)
	if err != nil || removed.BootstrapWorkstations(context.Background()) != nil {
		t.Fatalf("non-destructive removal replay: %v", err)
	}
	assertRunIDs(t, store, "nvt", "studio")
	addedPath := writeWorkstationDocument(t, []workstationConfig{
		testWorkstation("infra", "Infra"), testWorkstation("nvt", "NVT"),
	})
	added, err := LoadScheduler(addedPath, store)
	if err != nil || added.BootstrapWorkstations(context.Background()) != nil {
		t.Fatalf("workstation addition: %v", err)
	}
	assertRunIDs(t, store, "infra", "nvt", "studio")
	nvtAfter, err := store.Get(context.Background(), "nvt")
	if err != nil || nvtAfter.Revision != nvtBefore.Revision || nvtAfter.SnapshotDigest != nvtBefore.SnapshotDigest {
		t.Fatalf("existing workstation mutated: before=%#v after=%#v err=%v", nvtBefore, nvtAfter, err)
	}
}

func TestNativeConfigurationRejectsLegacyMixedAndAmbiguousShapes(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 8)
	valid := testNativeConfiguration()
	valid.Workstations = []workstationConfig{testWorkstation("nvt", "NVT")}
	validJSON := string(mustJSON(t, valid))
	deadline := testNativeConfiguration()
	deadline.Workstations = []workstationConfig{testWorkstation("nvt", "NVT")}
	deadline.RetentionPolicies[1].TTL.ActiveSeconds = 3600
	runRetention := testNativeConfiguration()
	runRetention.Workstations = []workstationConfig{testWorkstation("nvt", "NVT")}
	runRetention.RetentionPolicies[1].TTL.RunRetentionSeconds = 3600
	completedRetention := testNativeConfiguration()
	completedRetention.Workstations = []workstationConfig{testWorkstation("nvt", "NVT")}
	completedRetention.RetentionPolicies[1].TTL.CompletedSeconds = 3600
	failedRetention := testNativeConfiguration()
	failedRetention.Workstations = []workstationConfig{testWorkstation("nvt", "NVT")}
	failedRetention.RetentionPolicies[1].TTL.FailedSeconds = 3600
	for name, document := range map[string]string{
		"local_runs":          strings.TrimSuffix(validJSON, "}") + `,"local_runs":[]}`,
		"source_agent":        strings.Replace(validJSON, `"name":"nvt"`, `"name":"nvt","source_agent":"nvt-dev"`, 1),
		"duplicate name":      strings.Replace(validJSON, `"workstations":[`, `"workstations":[`+string(mustJSON(t, testWorkstation("nvt", "duplicate")))+`,`, 1),
		"duplicate profile":   strings.Replace(validJSON, `"profiles":[`, `"profiles":[`+string(mustJSON(t, valid.Profiles[0]))+`,`, 1),
		"unknown profile":     strings.Replace(validJSON, `"profile":"engineering"`, `"profile":"missing"`, 1),
		"unknown workflow":    strings.Replace(validJSON, `"workflow":"development"`, `"workflow":"missing"`, 1),
		"invalid name":        strings.Replace(validJSON, `"name":"nvt"`, `"name":"../nvt"`, 1),
		"nonpersistent":       strings.Replace(validJSON, `"retention":"persistent"`, `"retention":"disposable"`, 1),
		"active deadline":     string(mustJSON(t, deadline)),
		"run retention":       string(mustJSON(t, runRetention)),
		"completed retention": string(mustJSON(t, completedRetention)),
		"failed retention":    string(mustJSON(t, failedRetention)),
		"duplicate yaml":      "api_version: nvt.local-platform/v1\napi_version: nvt.local-platform/v1\n",
		"yaml alias":          "api_version: nvt.local-platform/v1\ndefaults: &defaults {}\nprofiles: []\nworkflows: []\nexecution_backends: []\nretention_policies: []\nworkstations: []\nschedules: []\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "local-controller.yaml")
			if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
				t.Fatal(err)
			}
			if loaded, err := LoadScheduler(path, store); err == nil || loaded != nil {
				t.Fatal("invalid or legacy native configuration was accepted")
			}
		})
	}
}

func TestNativeConfigurationNeverPersistsProducerBearer(t *testing.T) {
	const secretNeedle = "NATIVE-CONFIG-PRODUCER-SECRET-NEEDLE-0123456789"
	clock := &fakeClock{value: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	store, statePath := openTestStore(t, clock, 8)
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "producer-token")
	if err := os.WriteFile(tokenPath, []byte(secretNeedle), 0o600); err != nil {
		t.Fatal(err)
	}
	document := testNativeConfiguration()
	document.Workstations = []workstationConfig{testWorkstation("nvt", "NVT")}
	document.Schedules = []scheduleConfig{{Name: "github", Producers: []scheduleProducerConfig{{
		Identity: "github-comments", TokenFile: tokenPath, AllowedPrincipalIssuers: []string{"https://identity.example.test"},
		Selections: []scheduleSelection{{Profile: "engineering", Workflow: "development"}}, DefaultWorkflow: "development",
		Retention: "disposable", Backend: "container",
	}}}}
	configPath := filepath.Join(directory, "local-controller.yaml")
	if err := os.WriteFile(configPath, mustJSON(t, document), 0o600); err != nil {
		t.Fatal(err)
	}
	scheduler, err := LoadScheduler(configPath, store)
	if err != nil || scheduler.BootstrapWorkstations(context.Background()) != nil {
		t.Fatalf("native config = %#v err=%v", scheduler, err)
	}
	handler := NewHTTPHandlerWithServices(store, nil, nil, nil, scheduler)
	response := scheduleRequest(t, handler, http.MethodPost, "/v1/schedules/github/admissions",
		testAdmissionBody(t, "https://identity.example.test", "subject", "development", "work"), secretNeedle)
	if response.Code != http.StatusCreated {
		t.Fatalf("schedule = %d %s", response.Code, response.Body.String())
	}
	state, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(state), secretNeedle) || strings.Contains(response.Body.String(), secretNeedle) {
		t.Fatal("producer bearer crossed into durable or API state")
	}
}

func TestLocalSchedulingDeniesUntrustedSelectionBeforeBackendAndBoundsCapacity(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	store, _ := openTestStore(t, clock, 1)
	scheduler := testScheduler(t, store, schedulingTestToken)
	handler := NewHTTPHandlerWithServices(store, nil, nil, nil, scheduler)
	backend := newFakeBackend()
	reconciler, err := NewReconciler(store, backend, "scheduler-controller", 30*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}

	for name, body := range map[string][]byte{
		"issuer":              testAdmissionBody(t, "https://other.example.test", "subject-1", "development", "prompt"),
		"workflow":            testAdmissionBody(t, "https://identity.example.test", "subject-1", "administrator", "prompt"),
		"profile override":    admissionOverride(t, "profile"),
		"backend override":    admissionOverride(t, "backend"),
		"image override":      admissionOverride(t, "image"),
		"credential override": admissionOverride(t, "credential"),
		"repository override": admissionOverride(t, "repository"),
	} {
		t.Run(name, func(t *testing.T) {
			response := scheduleRequest(t, handler, http.MethodPost, "/v1/schedules/github/admissions", body, schedulingTestToken)
			if response.Code != http.StatusForbidden && response.Code != http.StatusBadRequest {
				t.Fatalf("denial = %d %s", response.Code, response.Body.String())
			}
		})
	}
	if err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	ensureCalls := backend.ensureCalls
	backend.mu.Unlock()
	if ensureCalls != 0 {
		t.Fatalf("unauthorized selection reached backend %d times", ensureCalls)
	}
	listed, err := store.List(context.Background(), 10, "")
	if err != nil || len(listed.Runs) != 0 {
		t.Fatalf("unauthorized selection created state: %#v %v", listed, err)
	}

	first := scheduleRequest(t, handler, http.MethodPost, "/v1/schedules/github/admissions", testAdmissionBody(t, "https://identity.example.test", "subject-1", "development", "first"), schedulingTestToken)
	if first.Code != http.StatusCreated {
		t.Fatalf("first = %d %s", first.Code, first.Body.String())
	}
	secondBody := testAdmissionBody(t, "https://identity.example.test", "subject-1", "development", "second")
	var second map[string]any
	if err := json.Unmarshal(secondBody, &second); err != nil {
		t.Fatal(err)
	}
	second["work"].(map[string]any)["id"] = "acme/widget/issues/8"
	secondResponse := scheduleRequest(t, handler, http.MethodPost, "/v1/schedules/github/admissions", mustJSON(t, second), schedulingTestToken)
	if secondResponse.Code != http.StatusTooManyRequests || secondResponse.Body.String() != `{"scheduled":false,"reason":"max-parallelism-reached"}`+"\n" {
		t.Fatalf("capacity = %d %s", secondResponse.Code, secondResponse.Body.String())
	}
}

func admissionOverride(t *testing.T, field string) []byte {
	t.Helper()
	valid := testAdmissionBody(t, "https://identity.example.test", "subject-1", "development", "prompt")
	return append(valid[:len(valid)-1], []byte(`,"`+field+`":"forbidden"}`)...)
}

func TestLocalSchedulingAcceptsValidatedSourceURLFragment(t *testing.T) {
	clock := &fakeClock{value: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	store, path := openTestStore(t, clock, 1)
	handler := NewHTTPHandlerWithServices(store, nil, nil, nil, testScheduler(t, store, schedulingTestToken))
	body := testAdmissionBody(t, "https://identity.example.test", "subject-1", "development", "work")
	var admission map[string]any
	if err := json.Unmarshal(body, &admission); err != nil {
		t.Fatal(err)
	}
	const sourceURL = "https://github.com/acme/widget/issues/7#issuecomment-5304285434"
	admission["work"].(map[string]any)["url"] = sourceURL
	response := scheduleRequest(t, handler, http.MethodPost, "/v1/schedules/github/admissions", mustJSON(t, admission), schedulingTestToken)
	if response.Code != http.StatusCreated {
		t.Fatalf("fragment source URL admission = %d %s", response.Code, response.Body.String())
	}
	listed, err := store.List(context.Background(), 1, "")
	if err != nil || len(listed.Runs) != 1 || listed.Runs[0].SourceURL != sourceURL {
		t.Fatalf("admitted source metadata = %#v, %v", listed, err)
	}
	snapshot, _, err := store.ResolvedSnapshot(context.Background(), listed.Runs[0].RunID)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolvedrun.DecodeResolvedAgentRun(snapshot)
	clear(snapshot)
	if err != nil || resolved.SourceURL != sourceURL {
		t.Fatalf("resolved source metadata = %#v, %v", resolved, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenStore(context.Background(), path, StoreOptions{MaxActiveRuns: 1, MaxClaimLease: time.Minute, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	durable, err := restarted.Get(context.Background(), listed.Runs[0].RunID)
	if err != nil || durable.SourceURL != sourceURL {
		t.Fatalf("source metadata after restart = %#v, %v", durable, err)
	}
}

func TestScheduleSourceURLRejectsUnsafeFragments(t *testing.T) {
	for name, sourceURL := range map[string]string{
		"encoded newline": "https://github.example/acme/widget/issues/7#issuecomment%0a7",
		"encoded null":    "https://github.example/acme/widget/issues/7#issuecomment%007",
		"invalid escape":  "https://github.example/acme/widget/issues/7#issuecomment%zz7",
		"userinfo":        "https://user@github.example/acme/widget/issues/7#issuecomment-7",
		"insecure scheme": "http://github.example/acme/widget/issues/7#issuecomment-7",
	} {
		t.Run(name, func(t *testing.T) {
			if validScheduleURL(sourceURL) {
				t.Fatalf("unsafe source URL was accepted: %q", sourceURL)
			}
		})
	}
}

func testScheduler(t *testing.T, store *Store, token string) *Scheduler {
	t.Helper()
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "producer-token")
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configuration := testSchedulingTrustedConfiguration()
	document := nativeConfigurationFromTrusted(configuration)
	document.Schedules = []scheduleConfig{{Name: "github", Producers: []scheduleProducerConfig{{
		Identity: "github-comments", TokenFile: tokenPath, AllowedPrincipalIssuers: []string{"https://identity.example.test"},
		Selections: []scheduleSelection{{Profile: "engineering", Workflow: "development"}}, DefaultWorkflow: "development", Retention: "disposable", Backend: "container",
	}}}}
	configPath := filepath.Join(directory, "local-controller.yaml")
	if err := os.WriteFile(configPath, mustJSON(t, document), 0o600); err != nil {
		t.Fatal(err)
	}
	scheduler, err := LoadScheduler(configPath, store)
	if err != nil {
		t.Fatal(err)
	}
	return scheduler
}

func testSchedulingTrustedConfiguration() resolvedrun.TrustedConfiguration {
	return resolvedrun.TrustedConfiguration{
		Defaults: resolvedrun.PlatformDefaults{
			Image: "registry.example/runtime:stable", Runtime: resolvedrun.Runtime{Type: "generic-agent", Autonomy: "interactive", User: "root"},
			AgentConfig: json.RawMessage(`{"runtime":{"command":"agent-cli","args":[]},"plugins":[]}`),
		},
		Profiles: []resolvedrun.Profile{{
			Name: "engineering", Broker: resolvedrun.Broker{}, Egress: resolvedrun.Egress{Mode: "direct"},
			AllowedBackends: []string{"container"}, DefaultBackend: "container", AllowedRetentions: []string{"disposable", "persistent"},
		}},
		Workflows:         []resolvedrun.Workflow{{Name: "development"}},
		ExecutionBackends: []resolvedrun.ExecutionBackend{{Name: "container", Kind: "container"}},
		RetentionPolicies: []resolvedrun.RetentionPolicy{
			{Name: "disposable", TTL: resolvedrun.TTL{ActiveSeconds: 3600, CompletedSeconds: 60, FailedSeconds: 60}},
			{Name: "persistent", Persistence: resolvedrun.Persistence{Workspace: true, RuntimeState: true, DockerData: true}},
		},
	}
}

func testNativeConfiguration() nativeConfiguration {
	return nativeConfigurationFromTrusted(testSchedulingTrustedConfiguration())
}

func nativeConfigurationFromTrusted(trusted resolvedrun.TrustedConfiguration) nativeConfiguration {
	return nativeConfiguration{
		APIVersion: NativeConfigAPIVersion, Defaults: trusted.Defaults, Profiles: trusted.Profiles,
		Workflows: trusted.Workflows, ExecutionBackends: trusted.ExecutionBackends, RetentionPolicies: trusted.RetentionPolicies,
	}
}

func testAdmissionBody(t *testing.T, issuer, subject, workflow, prompt string) []byte {
	t.Helper()
	return mustJSON(t, map[string]any{
		"workflow": workflow,
		"work": map[string]any{
			"id": "acme/widget/issues/7", "title": "Issue 7", "url": "https://github.example/acme/widget/issues/7", "repository": "acme/widget",
			"principal": map[string]any{"issuer": issuer, "subject": subject, "displayName": "Alice"},
		},
		"input": map[string]any{"prompt": prompt},
	})
}

func testAdmissionBodyWithWork(t *testing.T, workID, group string) []byte {
	t.Helper()
	return mustJSON(t, map[string]any{
		"workflow": "development",
		"work": map[string]any{
			"id": workID, "group": group, "title": "PR maintenance",
			"url": "https://github.example/acme/widget/pull/7", "repository": "acme/widget",
			"principal": map[string]any{
				"issuer": "https://identity.example.test", "subject": "subject-1", "displayName": "Alice",
			},
		},
		"input": map[string]any{"prompt": "Continue maintaining this PR"},
	})
}

func scheduleRequest(t *testing.T, handler http.Handler, method, path string, body []byte, token string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, "http://local-controller.test"+path, bytes.NewReader(body))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
