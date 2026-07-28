package guestidentity

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

type brokerMode string

const (
	modeNormal           brokerMode = "normal"
	modeLoseBeforeCommit brokerMode = "lose-before-commit"
	modeLoseAfterCommit  brokerMode = "lose-after-commit"
	modeOversizedStatus  brokerMode = "oversized-status"
	modeRedirectStatus   brokerMode = "redirect-status"
	modeSlowStatus       brokerMode = "slow-status"
	modeSlowBodyStatus   brokerMode = "slow-body-status"
	modeLoseExchange     brokerMode = "lose-exchange-response"
	modeOversizeExchange brokerMode = "oversized-exchange"
	modeThrottleExchange brokerMode = "throttled-exchange"
	modeRejectRotate     brokerMode = "reject-rotate"
)

type testBroker struct {
	mu          sync.Mutex
	binding     guestenrollment.Binding
	token       string
	current     string
	issuedAt    time.Time
	expiresAt   time.Time
	mode        brokerMode
	modeUsed    bool
	rotateCount int
	statusCount int
	proposals   []string
	redirectURL string
	statusHook  func()
}

func (broker *testBroker) serve(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	switch request.URL.Path {
	case guestenrollment.EnrollmentExchangePath:
		var value guestenrollment.ExchangeRequest
		if json.NewDecoder(request.Body).Decode(&value) != nil || value.Token != broker.token || value.Binding != broker.binding {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		broker.mu.Lock()
		mode := broker.mode
		if mode == modeLoseExchange || mode == modeOversizeExchange {
			broker.modeUsed = true
		}
		status := broker.exchangeResultLocked()
		broker.mu.Unlock()
		if mode == modeThrottleExchange {
			writer.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if mode == modeLoseExchange {
			<-request.Context().Done()
			return
		}
		if mode == modeOversizeExchange {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write(bytes.Repeat([]byte{'x'}, guestenrollment.MaxExchangeResultBytes+1))
			return
		}
		writeJSON(writer, status)
	case guestenrollment.RuntimeIdentityStatusPath:
		broker.status(writer, request)
	case guestenrollment.RuntimeIdentityRotatePath:
		broker.rotate(writer, request)
	default:
		writer.WriteHeader(http.StatusNotFound)
	}
}

func (broker *testBroker) status(writer http.ResponseWriter, request *http.Request) {
	broker.mu.Lock()
	broker.statusCount++
	mode := broker.mode
	hook := broker.statusHook
	if mode == modeOversizedStatus || mode == modeRedirectStatus || mode == modeSlowStatus || mode == modeSlowBodyStatus {
		broker.modeUsed = true
	}
	broker.mu.Unlock()
	if hook != nil {
		hook()
	}
	switch mode {
	case modeOversizedStatus:
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(bytes.Repeat([]byte{'x'}, guestenrollment.MaxRuntimeIdentityResponseBytes+1))
		return
	case modeRedirectStatus:
		http.Redirect(writer, request, broker.redirectURL, http.StatusFound)
		return
	case modeSlowStatus:
		select {
		case <-request.Context().Done():
		case <-time.After(250 * time.Millisecond):
		}
		return
	case modeSlowBodyStatus:
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		select {
		case <-request.Context().Done():
		case <-time.After(250 * time.Millisecond):
		}
		return
	}
	var value guestenrollment.RuntimeIdentityStatusRequest
	if json.NewDecoder(request.Body).Decode(&value) != nil || value.Binding != broker.binding {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	if bearer(request) != broker.current {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	writeJSON(writer, broker.statusLocked())
}

func (broker *testBroker) rotate(writer http.ResponseWriter, request *http.Request) {
	var value guestenrollment.RuntimeIdentityRotateRequest
	if json.NewDecoder(request.Body).Decode(&value) != nil || value.Binding != broker.binding {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	broker.mu.Lock()
	if bearer(request) != broker.current {
		broker.mu.Unlock()
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	broker.proposals = append(broker.proposals, value.Successor)
	mode := broker.mode
	if mode == modeRejectRotate {
		broker.mu.Unlock()
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	if !broker.modeUsed && mode == modeLoseBeforeCommit {
		broker.modeUsed = true
		broker.mu.Unlock()
		<-request.Context().Done()
		return
	}
	broker.current = value.Successor
	broker.issuedAt = time.Now().UTC().Truncate(time.Second)
	broker.expiresAt = broker.issuedAt.Add(time.Hour)
	broker.rotateCount++
	status := broker.statusLocked()
	if !broker.modeUsed && mode == modeLoseAfterCommit {
		broker.modeUsed = true
		broker.mu.Unlock()
		<-request.Context().Done()
		return
	}
	broker.mu.Unlock()
	writeJSON(writer, status)
}

func (broker *testBroker) statusLocked() guestenrollment.RuntimeIdentityStatus {
	return guestenrollment.RuntimeIdentityStatus{
		ContractVersion: guestenrollment.RuntimeIdentityVersion,
		IdentityType:    guestenrollment.RuntimeIdentityType,
		Binding:         broker.binding,
		IssuedAt:        guestenrollment.FormatTimestamp(broker.issuedAt),
		ExpiresAt:       guestenrollment.FormatTimestamp(broker.expiresAt),
	}
}

func (broker *testBroker) exchangeResultLocked() guestenrollment.ExchangeResult {
	return guestenrollment.ExchangeResult{
		ContractVersion: guestenrollment.Version,
		Binding:         broker.binding,
		RuntimeIdentity: guestenrollment.RuntimeIdentity{
			Type: guestenrollment.RuntimeIdentityType, Opaque: broker.current,
			IssuedAt: guestenrollment.FormatTimestamp(broker.issuedAt), ExpiresAt: guestenrollment.FormatTimestamp(broker.expiresAt),
		},
	}
}

func TestRuntimeEnrollsRotatesAndRecoversAcrossRestart(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	fixture := newRuntimeFixture(t, clock.Add(-36*time.Minute), clock.Add(24*time.Minute), modeNormal)
	successor := opaque(0x44)
	fixture.runtime.Generate = func() (string, error) { return successor, nil }
	fixture.runtime.Now = func() time.Time { return clock }

	snapshot, _, err := fixture.runtime.Reconcile(context.Background())
	if err != nil || !snapshot.Ready || snapshot.Binding != fixture.broker.binding {
		t.Fatalf("first reconcile = %#v, %v", snapshot, err)
	}
	if _, err := os.Stat(fixture.configuration.EnrollmentPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("successful enrollment retained the one-time envelope")
	}
	state, exists, err := fixture.store.load()
	if err != nil || !exists || state.RuntimeIdentity == nil || state.RuntimeIdentity.Opaque != successor || state.PendingSuccessor != "" {
		t.Fatalf("rotated state = %#v, %v", state, err)
	}
	assertPrivateState(t, fixture.configuration, state)

	restarted, _ := NewRuntime(fixture.store, fixture.client)
	restarted.Now = func() time.Time { return clock.Add(time.Minute) }
	restarted.Generate = func() (string, error) { t.Fatal("restart generated an unnecessary successor"); return "", nil }
	snapshot, _, err = restarted.Reconcile(context.Background())
	if err != nil || !snapshot.Ready {
		t.Fatalf("restart reconcile = %#v, %v", snapshot, err)
	}
	fixture.broker.mu.Lock()
	if fixture.broker.rotateCount != 1 {
		t.Fatalf("rotation count = %d", fixture.broker.rotateCount)
	}
	fixture.broker.mu.Unlock()
}

func TestEnrollmentResponseLossAndMalformedSuccessRequireReplacement(t *testing.T) {
	for _, mode := range []brokerMode{modeLoseExchange, modeOversizeExchange} {
		t.Run(string(mode), func(t *testing.T) {
			clock := time.Now().UTC().Truncate(time.Second)
			fixture := newRuntimeFixture(t, clock, clock.Add(time.Hour), mode)
			if err := fixture.runtime.Initialize(context.Background()); err == nil {
				t.Fatal("uncertain enrollment was accepted")
			}
			state, exists, err := fixture.store.load()
			if err != nil || !exists || state.FailureReason != ReasonReplacementRequired || state.RuntimeIdentity != nil {
				t.Fatalf("failure state = %#v, %v", state, err)
			}
			if _, err := os.Stat(fixture.configuration.EnrollmentPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed enrollment retained bearer envelope")
			}
		})
	}
}

func TestDefiniteBrokerUnavailabilityRetainsOneTimeEnvelope(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	fixture := newRuntimeFixture(t, clock, clock.Add(time.Hour), modeThrottleExchange)
	err := fixture.runtime.Initialize(context.Background())
	if err == nil || strings.Contains(err.Error(), fixture.broker.token) {
		t.Fatalf("broker failure = %v", err)
	}
	if _, statErr := os.Stat(fixture.configuration.EnrollmentPath); statErr != nil {
		t.Fatal("definitely unconsumed envelope was removed")
	}
	if _, exists, loadErr := fixture.store.load(); loadErr != nil || exists {
		t.Fatalf("broker failure created identity state: exists=%v err=%v", exists, loadErr)
	}
}

func TestExpiredIdentityFailsClosedWithoutBrokerAvailability(t *testing.T) {
	t.Run("expired before broker call", func(t *testing.T) {
		clock := time.Now().UTC().Truncate(time.Second)
		fixture := newRuntimeFixture(t, clock.Add(-time.Hour), clock, modeSlowStatus)
		if err := fixture.runtime.Initialize(context.Background()); err != nil {
			t.Fatal(err)
		}
		fixture.runtime.Now = func() time.Time { return clock }

		snapshot, _, err := fixture.runtime.Reconcile(context.Background())
		if err == nil || snapshot.Ready || snapshot.Reason != ReasonReplacementRequired {
			t.Fatalf("expired reconcile = %#v, %v", snapshot, err)
		}
		if _, temporary, _ := FailureDetails(err); temporary {
			t.Fatal("expired identity returned a retry-only outcome")
		}
		state, exists, loadErr := fixture.store.load()
		if loadErr != nil || !exists || state.FailureReason != ReasonReplacementRequired ||
			state.RuntimeIdentity != nil || state.PendingSuccessor != "" {
			t.Fatalf("expired durable state = %#v, %v", state, loadErr)
		}
		fixture.broker.mu.Lock()
		statusCount := fixture.broker.statusCount
		fixture.broker.mu.Unlock()
		if statusCount != 0 {
			t.Fatalf("expired identity made %d broker status calls", statusCount)
		}
	})

	t.Run("expiry while unavailable status is in flight", func(t *testing.T) {
		clock := time.Now().UTC().Truncate(time.Second)
		fixture := newRuntimeFixture(t, clock.Add(-time.Hour), clock.Add(time.Second), modeSlowStatus)
		if err := fixture.runtime.Initialize(context.Background()); err != nil {
			t.Fatal(err)
		}
		calls := 0
		fixture.runtime.Now = func() time.Time {
			calls++
			if calls <= 2 {
				return clock
			}
			return clock.Add(time.Second)
		}

		snapshot, _, err := fixture.runtime.Reconcile(context.Background())
		if err == nil || snapshot.Ready || snapshot.Reason != ReasonReplacementRequired {
			t.Fatalf("in-flight expiry reconcile = %#v, %v", snapshot, err)
		}
		if _, temporary, _ := FailureDetails(err); temporary {
			t.Fatal("in-flight expiry returned a retry-only outcome")
		}
		state, _, loadErr := fixture.store.load()
		if loadErr != nil || state.FailureReason != ReasonReplacementRequired || state.RuntimeIdentity != nil || state.PendingSuccessor != "" {
			t.Fatalf("in-flight expiry durable state = %#v, %v", state, loadErr)
		}
		fixture.broker.mu.Lock()
		statusCount := fixture.broker.statusCount
		fixture.broker.mu.Unlock()
		if statusCount != 1 {
			t.Fatalf("unavailable status calls = %d", statusCount)
		}
	})
}

func TestCommittedIdentityRetriesEnvelopeRemovalBeforeReadiness(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	fixture := newRuntimeFixture(t, clock, clock.Add(time.Hour), modeNormal)
	removeAttempts := 0
	fixture.store.removePath = func(path string) error {
		removeAttempts++
		if removeAttempts == 1 {
			return errors.New("NVT_ENVELOPE_REMOVE_SECRET_CANARY")
		}
		return os.Remove(path)
	}
	firstSnapshot, _, firstErr := fixture.runtime.Reconcile(context.Background())
	if firstErr == nil || firstSnapshot.Ready || strings.Contains(firstErr.Error(), "CANARY") {
		t.Fatalf("first envelope removal = %#v, %v", firstSnapshot, firstErr)
	}
	state, exists, err := fixture.store.load()
	if err != nil || !exists || state.RuntimeIdentity == nil {
		t.Fatalf("committed identity = %#v, %v", state, err)
	}
	if _, err := os.Stat(fixture.configuration.EnrollmentPath); err != nil {
		t.Fatal("failed removal did not retain the envelope for retry")
	}

	directorySyncs := 0
	fixture.store.syncPath = func(path string) error {
		directorySyncs++
		file, openErr := os.Open(path)
		if openErr != nil {
			return openErr
		}
		defer file.Close()
		return file.Sync()
	}
	fixture.broker.statusHook = func() {
		if _, statErr := os.Stat(fixture.configuration.EnrollmentPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("broker status observed retained enrollment envelope: %v", statErr)
		}
	}
	restarted, err := NewRuntime(fixture.store, fixture.client)
	if err != nil {
		t.Fatal(err)
	}
	restarted.Now = func() time.Time { return clock }
	snapshot, _, err := restarted.Reconcile(context.Background())
	if err != nil || !snapshot.Ready {
		t.Fatalf("restart reconcile = %#v, %v", snapshot, err)
	}
	if removeAttempts != 2 || directorySyncs == 0 {
		t.Fatalf("removal attempts=%d directory syncs=%d", removeAttempts, directorySyncs)
	}
	if _, err := os.Stat(fixture.configuration.EnrollmentPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("consumed envelope remains after readiness: %v", err)
	}
}

func TestInvalidIssuerEndpointPersistsReplacementAcrossRestart(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	fixture := newRuntimeFixture(t, clock, clock.Add(time.Hour), modeNormal)
	data, err := os.ReadFile(fixture.configuration.EnrollmentPath)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := guestenrollment.DecodeBootstrapEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	envelope.ExchangeURL = fixture.server.URL + "/prefix" + guestenrollment.EnrollmentExchangePath
	encoded, _ := json.Marshal(envelope)
	if err := os.WriteFile(fixture.configuration.EnrollmentPath, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.Initialize(context.Background()); err == nil {
		t.Fatal("invalid issuer endpoint was accepted")
	}
	restarted, err := NewRuntime(fixture.store, fixture.client)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := restarted.Reconcile(context.Background())
	if err == nil || snapshot.Reason != ReasonReplacementRequired {
		t.Fatalf("replacement state after restart = %#v, %v", snapshot, err)
	}
}

func TestAcceptEnvelopeIsExactAndIdempotent(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	fixture := newRuntimeFixture(t, clock, clock.Add(time.Hour), modeNormal)
	data, err := os.ReadFile(fixture.configuration.EnrollmentPath)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := guestenrollment.DecodeBootstrapEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fixture.configuration.EnrollmentPath); err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.AcceptEnvelope(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.AcceptEnvelope(context.Background(), envelope); err != nil {
		t.Fatalf("exact redelivery was not idempotent: %v", err)
	}
	wrong := envelope
	wrong.Binding.GuestInstanceID = "different-guest"
	if err := fixture.runtime.AcceptEnvelope(context.Background(), wrong); err == nil {
		t.Fatal("different bootstrap binding replaced active state")
	}
	state, _, _ := fixture.store.load()
	if state.Binding != envelope.Binding {
		t.Fatal("different bootstrap binding mutated state")
	}
}

func TestAmbiguousRotationRecoveryNeverGeneratesSecondCandidate(t *testing.T) {
	for _, mode := range []brokerMode{modeLoseBeforeCommit, modeLoseAfterCommit} {
		t.Run(string(mode), func(t *testing.T) {
			clock := time.Now().UTC().Truncate(time.Second)
			fixture := newRuntimeFixture(t, clock.Add(-36*time.Minute), clock.Add(24*time.Minute), mode)
			if err := fixture.runtime.Initialize(context.Background()); err != nil {
				t.Fatal(err)
			}
			successor := opaque(0x55)
			generations := 0
			fixture.runtime.Generate = func() (string, error) { generations++; return successor, nil }
			fixture.runtime.Now = func() time.Time { return clock }
			if _, _, err := fixture.runtime.Reconcile(context.Background()); err == nil {
				t.Fatal("ambiguous response was accepted")
			}
			state, _, err := fixture.store.load()
			if err != nil || state.PendingSuccessor != successor {
				t.Fatalf("pending state = %#v, %v", state, err)
			}

			restarted, _ := NewRuntime(fixture.store, fixture.client)
			restarted.Now = func() time.Time { return clock.Add(time.Second) }
			restarted.Generate = fixture.runtime.Generate
			snapshot, _, err := restarted.Reconcile(context.Background())
			if err != nil || !snapshot.Ready || generations != 1 {
				t.Fatalf("recovery = %#v, %v generations=%d", snapshot, err, generations)
			}
			fixture.broker.mu.Lock()
			defer fixture.broker.mu.Unlock()
			if fixture.broker.rotateCount != 1 || len(fixture.broker.proposals) == 0 {
				t.Fatalf("broker rotations=%d proposals=%v", fixture.broker.rotateCount, fixture.broker.proposals)
			}
			for _, proposal := range fixture.broker.proposals {
				if proposal != successor {
					t.Fatal("recovery submitted a different successor")
				}
			}
		})
	}
}

func TestAmbiguousStateWithNeitherCandidateActiveRequiresReplacement(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	fixture := newRuntimeFixture(t, clock, clock.Add(time.Hour), modeNormal)
	if err := fixture.runtime.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, _, err := fixture.store.load()
	if err != nil {
		t.Fatal(err)
	}
	state.PendingSuccessor = opaque(0x52)
	if err := fixture.store.save(state); err != nil {
		t.Fatal(err)
	}
	fixture.broker.mu.Lock()
	fixture.broker.current = opaque(0x53)
	fixture.broker.mu.Unlock()
	snapshot, _, err := fixture.runtime.Reconcile(context.Background())
	if err == nil || snapshot.Reason != ReasonReplacementRequired || snapshot.Ready {
		t.Fatalf("unrecoverable ambiguity = %#v, %v", snapshot, err)
	}
	failed, _, loadErr := fixture.store.load()
	if loadErr != nil || failed.FailureReason != ReasonReplacementRequired || failed.RuntimeIdentity != nil || failed.PendingSuccessor != "" {
		t.Fatalf("replacement state = %#v, %v", failed, loadErr)
	}
}

func TestDefinitelyRejectedPendingSuccessorRequiresReplacement(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	fixture := newRuntimeFixture(t, clock, clock.Add(time.Hour), modeRejectRotate)
	if err := fixture.runtime.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, _, err := fixture.store.load()
	if err != nil {
		t.Fatal(err)
	}
	state.PendingSuccessor = opaque(0x54)
	if err := fixture.store.save(state); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := fixture.runtime.Reconcile(context.Background())
	if err == nil || snapshot.Reason != ReasonReplacementRequired {
		t.Fatalf("rejected pending successor = %#v, %v", snapshot, err)
	}
}

func TestPersistenceFailureRevocationAndCorruptionFailClosed(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	fixture := newRuntimeFixture(t, clock.Add(-36*time.Minute), clock.Add(24*time.Minute), modeNormal)
	if err := fixture.runtime.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	prior, _, _ := fixture.store.load()
	fixture.store.beforeCommit = func() error { return errors.New("NVT_SECRET_COMMIT_CANARY") }
	fixture.runtime.Generate = func() (string, error) { return opaque(0x66), nil }
	fixture.runtime.Now = func() time.Time { return clock }
	if _, _, err := fixture.runtime.Reconcile(context.Background()); err == nil || strings.Contains(err.Error(), "CANARY") {
		t.Fatalf("persistence failure = %v", err)
	}
	fixture.store.beforeCommit = nil
	after, _, _ := fixture.store.load()
	if prior.RuntimeIdentity.Opaque != after.RuntimeIdentity.Opaque || after.PendingSuccessor != "" {
		t.Fatal("pre-commit failure changed durable identity")
	}
	fixture.broker.mu.Lock()
	if fixture.broker.rotateCount != 0 {
		t.Fatal("rotation started before successor persistence")
	}
	fixture.broker.current = opaque(0x77) // execution revocation/identity removal
	fixture.broker.mu.Unlock()
	if snapshot, _, err := fixture.runtime.Reconcile(context.Background()); err == nil || snapshot.Reason != ReasonReplacementRequired {
		t.Fatalf("revocation result = %#v, %v", snapshot, err)
	}
	failed, _, _ := fixture.store.load()
	if failed.FailureReason != ReasonReplacementRequired || failed.RuntimeIdentity != nil {
		t.Fatalf("revocation retained bearer state: %#v", failed)
	}

	if err := os.WriteFile(fixture.store.statePath, []byte(`{"contract_version":"broken"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.runtime.Reconcile(context.Background()); err == nil || strings.Contains(err.Error(), fixture.broker.token) {
		t.Fatalf("corrupt state = %v", err)
	}
}

func TestAtomicStateFileSyncFailurePreservesPriorState(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	fixture := newRuntimeFixture(t, clock, clock.Add(time.Hour), modeNormal)
	if err := fixture.runtime.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	prior, _, err := fixture.store.load()
	if err != nil {
		t.Fatal(err)
	}
	next := prior
	next.PendingSuccessor = opaque(0x69)
	fixture.store.syncFile = func(*os.File) error { return errors.New("NVT_SYNC_SECRET_CANARY") }
	if err := fixture.store.save(next); err == nil || strings.Contains(err.Error(), "CANARY") {
		t.Fatalf("file sync failure = %v", err)
	}
	fixture.store.syncFile = nil
	current, _, err := fixture.store.load()
	if err != nil || current.PendingSuccessor != "" || current.RuntimeIdentity.Opaque != prior.RuntimeIdentity.Opaque {
		t.Fatalf("pre-publication sync changed state = %#v, %v", current, err)
	}
	matches, err := filepath.Glob(filepath.Join(fixture.configuration.StateDirectory, ".identity-*.tmp"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary identity state remained: %v, %v", matches, err)
	}
}

func TestStoreRejectsUnsafeAndNonCanonicalState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "identity")
	configuration := Configuration{
		Version: ConfigurationVersion, StateDirectory: root, RuntimeDirectory: filepath.Join(t.TempDir(), "run"),
		EnrollmentPath: filepath.Join(root, "enrollment.json"), CAPEMPath: filepath.Join(t.TempDir(), "ca.pem"),
	}
	store, err := OpenStore(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.statePath, []byte(`{"contract_version":"x","contract_version":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.load(); err == nil {
		t.Fatal("duplicate JSON key was accepted")
	}
	if err := os.Remove(store.statePath); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, store.statePath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.load(); err == nil {
		t.Fatal("symlink state was accepted")
	}
	unsafeParent := filepath.Join(t.TempDir(), "agent-writable")
	if err := os.Mkdir(unsafeParent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeParent, 0o777); err != nil {
		t.Fatal(err)
	}
	unsafeConfiguration := configuration
	unsafeConfiguration.StateDirectory = filepath.Join(unsafeParent, "identity")
	unsafeConfiguration.EnrollmentPath = filepath.Join(unsafeConfiguration.StateDirectory, "enrollment.json")
	if _, err := OpenStore(unsafeConfiguration); err == nil {
		t.Fatal("identity state below a writable parent was accepted")
	}
	if _, err := os.Stat(unsafeConfiguration.StateDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected identity configuration created state in an unsafe parent")
	}
}

func TestConfigurationAndTrustFilesAreStrictAndPrivate(t *testing.T) {
	root := filepath.Join(t.TempDir(), "identity")
	configuration := Configuration{
		Version: ConfigurationVersion, StateDirectory: root, RuntimeDirectory: filepath.Join(t.TempDir(), "run"),
		EnrollmentPath: filepath.Join(root, "enrollment.json"), CAPEMPath: filepath.Join(t.TempDir(), "ca.pem"),
	}
	encoded, _ := json.Marshal(configuration)
	configPath := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(configPath, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if loaded, err := LoadConfiguration(configPath); err != nil || loaded != configuration {
		t.Fatalf("load configuration = %#v, %v", loaded, err)
	}
	if err := os.WriteFile(configPath, append(encoded, []byte(`{"token":"NVT_CONFIG_SECRET_CANARY"}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfiguration(configPath); err == nil || strings.Contains(err.Error(), "CANARY") {
		t.Fatalf("unknown sensitive configuration field = %v", err)
	}
	if err := os.Chmod(configPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfiguration(configPath); err == nil {
		t.Fatal("world-readable identity configuration was accepted")
	}
	unsafeConfigDirectory := filepath.Join(t.TempDir(), "unsafe-config")
	if err := os.Mkdir(unsafeConfigDirectory, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeConfigDirectory, 0o777); err != nil {
		t.Fatal(err)
	}
	unsafeConfigPath := filepath.Join(unsafeConfigDirectory, "identity.json")
	if err := os.WriteFile(unsafeConfigPath, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfiguration(unsafeConfigPath); err == nil {
		t.Fatal("identity configuration below a writable parent was accepted")
	}

	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	trustPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(trustPath, pemCertificate(server.Certificate().Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewClientFromFile(trustPath); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(trustPath), "ca-link.pem")
	if err := os.Symlink(trustPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewClientFromFile(link); err == nil {
		t.Fatal("symlinked trust file was accepted")
	}
	unsafeTrustDirectory := filepath.Join(t.TempDir(), "unsafe-trust")
	if err := os.Mkdir(unsafeTrustDirectory, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeTrustDirectory, 0o777); err != nil {
		t.Fatal(err)
	}
	unsafeTrustPath := filepath.Join(unsafeTrustDirectory, "ca.pem")
	if err := os.WriteFile(unsafeTrustPath, pemCertificate(server.Certificate().Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewClientFromFile(unsafeTrustPath); err == nil {
		t.Fatal("trust file below a writable parent was accepted")
	}
	for _, endpoint := range []string{
		"http://broker.example" + guestenrollment.EnrollmentExchangePath,
		"https://broker.example/prefix" + guestenrollment.EnrollmentExchangePath,
		"https://broker.example:99999" + guestenrollment.EnrollmentExchangePath,
		"https://broker.example" + guestenrollment.EnrollmentExchangePath + "?redirect=true",
	} {
		if _, err := brokerURLFromExchange(endpoint); err == nil {
			t.Fatalf("unsafe broker endpoint %q was accepted", endpoint)
		}
	}
}

type runtimeFixture struct {
	configuration Configuration
	store         *Store
	client        *Client
	runtime       *Runtime
	broker        *testBroker
	server        *httptest.Server
}

func newRuntimeFixture(t *testing.T, issuedAt, expiresAt time.Time, mode brokerMode) runtimeFixture {
	t.Helper()
	binding := guestenrollment.Binding{
		AgentRunUID: "11111111-1111-1111-1111-111111111111", ExecutionID: "nvt-exec-test",
		DriverRegistration: "test-driver", DesiredGeneration: 1, GuestInstanceID: "guest-test",
	}
	broker := &testBroker{binding: binding, token: opaque(0x21), current: opaque(0x31), issuedAt: issuedAt, expiresAt: expiresAt, mode: mode}
	server := httptest.NewTLSServer(http.HandlerFunc(broker.serve))
	t.Cleanup(server.Close)
	certificate := server.Certificate()
	caPEM := pemCertificate(certificate.Raw)
	client, err := newClient(caPEM, 150*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "identity")
	configuration := Configuration{
		Version: ConfigurationVersion, StateDirectory: root, RuntimeDirectory: filepath.Join(t.TempDir(), "run"),
		EnrollmentPath: filepath.Join(root, "enrollment.json"), CAPEMPath: filepath.Join(t.TempDir(), "ca.pem"),
	}
	store, err := OpenStore(configuration)
	if err != nil {
		t.Fatal(err)
	}
	envelope := guestenrollment.BootstrapEnvelope{
		ContractVersion: guestenrollment.Version, Binding: binding,
		ExchangeURL: server.URL + guestenrollment.EnrollmentExchangePath, Token: broker.token,
		IssuedAt: guestenrollment.FormatTimestamp(time.Now().Add(-time.Minute)), ExpiresAt: guestenrollment.FormatTimestamp(time.Now().Add(time.Minute)),
	}
	data, _ := json.Marshal(envelope)
	if err := os.WriteFile(configuration.EnrollmentPath, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime, _ := NewRuntime(store, client)
	return runtimeFixture{configuration: configuration, store: store, client: client, runtime: runtime, broker: broker, server: server}
}

func assertPrivateState(t *testing.T, configuration Configuration, state durableState) {
	t.Helper()
	info, err := os.Stat(filepath.Join(configuration.StateDirectory, StateFileName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %v, %v", info, err)
	}
	directory, err := os.Stat(configuration.StateDirectory)
	if err != nil || directory.Mode().Perm() != 0o700 {
		t.Fatalf("state directory mode = %v, %v", directory, err)
	}
	formatted := strings.Join([]string{state.String(), state.GoString(), Snapshot{Binding: state.Binding}.String()}, " ")
	if strings.Contains(formatted, state.RuntimeIdentity.Opaque) {
		t.Fatal("formatted state disclosed identity")
	}
}

func bearer(request *http.Request) string {
	return strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
}

func writeJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(value)
}

func opaque(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, guestenrollment.RuntimeIdentityBytes))
}

func pemCertificate(raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
}

func TestClientRejectsTLSRedirectOversizeAndTimeoutWithoutDisclosure(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	for _, mode := range []brokerMode{modeOversizedStatus, modeSlowStatus, modeSlowBodyStatus} {
		t.Run(string(mode), func(t *testing.T) {
			fixture := newRuntimeFixture(t, clock, clock.Add(time.Hour), mode)
			if err := fixture.runtime.Initialize(context.Background()); err != nil {
				t.Fatal(err)
			}
			state, _, _ := fixture.store.load()
			_, err := fixture.client.Status(context.Background(), state.BrokerURL, state.RuntimeIdentity.Opaque, state.Binding)
			if err == nil || strings.Contains(err.Error(), state.RuntimeIdentity.Opaque) {
				t.Fatalf("bounded client error = %v", err)
			}
		})
	}

	redirected := 0
	attacker := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected++ }))
	defer attacker.Close()
	fixture := newRuntimeFixture(t, clock, clock.Add(time.Hour), modeRedirectStatus)
	fixture.broker.redirectURL = attacker.URL
	if err := fixture.runtime.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, _, _ := fixture.store.load()
	if _, err := fixture.client.Status(context.Background(), state.BrokerURL, state.RuntimeIdentity.Opaque, state.Binding); err == nil || redirected != 0 {
		t.Fatalf("redirect result err=%v redirected=%d", err, redirected)
	}

	wrongClient, err := newClient(pemCertificate(attacker.Certificate().Raw), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongClient.Status(context.Background(), state.BrokerURL, state.RuntimeIdentity.Opaque, state.Binding); err == nil {
		t.Fatal("broker signed by an untrusted CA was accepted")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()
	started := time.Now()
	if _, err := fixture.client.Status(context.Background(), "https://"+listener.Addr().String(), state.RuntimeIdentity.Opaque, state.Binding); err == nil || time.Since(started) > time.Second {
		t.Fatalf("stalled TLS handshake was not bounded: %v", err)
	}
	select {
	case connection := <-accepted:
		_ = connection.Close()
	case <-time.After(time.Second):
		t.Fatal("stalled TLS fixture was not accepted")
	}
}

func TestProductionScheduleNeverRotatesBeforePlanningInterval(t *testing.T) {
	if minimumRotationInterval < guestenrollment.RuntimeIdentityCapacityPlanningInterval {
		t.Fatalf("minimum rotation interval = %s", minimumRotationInterval)
	}
	if rotationRecoveryWindow < 10*time.Minute || statusPollInterval <= 0 {
		t.Fatal("runtime identity recovery schedule is unsafe")
	}
	binding := guestenrollment.Binding{
		AgentRunUID: "11111111-1111-1111-1111-111111111111", ExecutionID: "execution",
		DriverRegistration: "driver", DesiredGeneration: 1, GuestInstanceID: "guest-a",
	}
	first := rotationJitter(binding, opaque(0x11))
	if first != rotationJitter(binding, opaque(0x11)) || first < 0 || first >= maximumRotationJitter {
		t.Fatal("rotation jitter is not deterministic and bounded")
	}
	binding.GuestInstanceID = "guest-b"
	if first == rotationJitter(binding, opaque(0x11)) {
		t.Fatal("distinct guests synchronize their rotation jitter")
	}
}
