package guestenrollment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	maxFakeEntries  = 64
	fakeExchangeURL = "https://enrollment.nvt-system.svc/v1/guest-enrollment/exchange"
)

var errFakeResponseLost = errors.New("simulated enrollment response loss")

type fakeExchangeFault int

const (
	fakeNoFault fakeExchangeFault = iota
	fakeFailBeforeCommit
	fakeLoseResponseAfterCommit
)

type fakeRecord struct {
	TokenDigest           string         `json:"token_digest"`
	Binding               Binding        `json:"binding"`
	IssuedAt              string         `json:"issued_at"`
	ExpiresAt             string         `json:"expires_at"`
	State                 LifecycleState `json:"state"`
	RuntimeIdentityDigest string         `json:"runtime_identity_digest,omitempty"`
	TerminalAt            string         `json:"terminal_at,omitempty"`
}

type fakeTombstone struct {
	DeleteAfter string `json:"delete_after"`
}

type fakeDurableStore struct {
	mu                  sync.Mutex
	records             map[string]fakeRecord
	bindingTombstones   map[Binding]fakeTombstone
	executionTombstones map[ExecutionScope]fakeTombstone
	activeIdentities    map[string]ExecutionScope
}

type fakeIssuer struct {
	store          *fakeDurableStore
	configuration  IssuerConfiguration
	now            func() time.Time
	random         io.Reader
	identity       func(Binding, time.Time) (RuntimeIdentity, error)
	diagnosticSink func(string)
	faultMu        sync.Mutex
	nextFault      fakeExchangeFault
}

type fakeGuest struct {
	binding             Binding
	expectedExchangeURL string
	issuer              Issuer
}

func (guest fakeGuest) bootstrap(ctx context.Context, encodedEnvelope []byte) (ExchangeResult, error) {
	envelope, err := DecodeBootstrapEnvelope(encodedEnvelope)
	if err != nil {
		return ExchangeResult{}, err
	}
	if envelope.Binding != guest.binding {
		return ExchangeResult{}, NewFailure(ReasonBindingMismatch)
	}
	if envelope.ExchangeURL != guest.expectedExchangeURL {
		return ExchangeResult{}, NewFailure(ReasonInvalidRequest)
	}
	result, err := guest.issuer.Exchange(ctx, ExchangeRequest{ContractVersion: Version, Binding: guest.binding, Token: envelope.Token})
	envelope.Token = ""
	if err != nil {
		return ExchangeResult{}, err
	}
	if ValidateExchangeResult(result) != nil || result.Binding != guest.binding {
		return ExchangeResult{}, NewFailure(ReasonIdentityFailure)
	}
	return result, nil
}

func newFakeIssuer(store *fakeDurableStore, now func() time.Time, random io.Reader, identity func(Binding, time.Time) (RuntimeIdentity, error)) *fakeIssuer {
	return &fakeIssuer{
		store: store, configuration: IssuerConfiguration{ExchangeURL: fakeExchangeURL},
		now: now, random: random, identity: identity, diagnosticSink: func(string) {},
	}
}

func (issuer *fakeIssuer) setNextFault(value fakeExchangeFault) {
	issuer.faultMu.Lock()
	defer issuer.faultMu.Unlock()
	issuer.nextFault = value
}

func (issuer *fakeIssuer) takeNextFault() fakeExchangeFault {
	issuer.faultMu.Lock()
	defer issuer.faultMu.Unlock()
	value := issuer.nextFault
	issuer.nextFault = fakeNoFault
	return value
}

func (store *fakeDurableStore) initializeLocked() {
	if store.records == nil {
		store.records = make(map[string]fakeRecord)
	}
	if store.bindingTombstones == nil {
		store.bindingTombstones = make(map[Binding]fakeTombstone)
	}
	if store.executionTombstones == nil {
		store.executionTombstones = make(map[ExecutionScope]fakeTombstone)
	}
	if store.activeIdentities == nil {
		store.activeIdentities = make(map[string]ExecutionScope)
	}
}

func (store *fakeDurableStore) usedEntriesLocked() int {
	return len(store.records) + len(store.bindingTombstones) + len(store.executionTombstones)
}

func fakeTombstoneAt(now time.Time) fakeTombstone {
	return fakeTombstone{DeleteAfter: FormatTimestamp(now.UTC().Truncate(time.Second).Add(MaxTombstoneRetention))}
}

func (issuer *fakeIssuer) Issue(ctx context.Context, request IssueRequest) (BootstrapEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return BootstrapEnvelope{}, err
	}
	if err := ValidateIssueRequest(request); err != nil {
		issuer.diagnosticSink("issue invalid-request")
		return BootstrapEnvelope{}, err
	}
	if ValidateIssuerConfiguration(issuer.configuration) != nil {
		return BootstrapEnvelope{}, NewFailure(ReasonInvalidRequest)
	}
	now := issuer.now().UTC().Truncate(time.Second)
	issuer.store.mu.Lock()
	defer issuer.store.mu.Unlock()
	issuer.store.initializeLocked()
	if issuer.store.usedEntriesLocked() >= maxFakeEntries {
		return BootstrapEnvelope{}, NewFailure(ReasonCapacity)
	}
	if _, revoked := issuer.store.executionTombstones[request.Binding.ExecutionScope()]; revoked {
		return BootstrapEnvelope{}, NewFailure(ReasonRevoked)
	}
	if _, revoked := issuer.store.bindingTombstones[request.Binding]; revoked {
		return BootstrapEnvelope{}, NewFailure(ReasonRevoked)
	}
	for _, existing := range issuer.store.records {
		if existing.Binding == request.Binding {
			if existing.State == StateRevoked {
				return BootstrapEnvelope{}, NewFailure(ReasonRevoked)
			}
			return BootstrapEnvelope{}, NewFailure(ReasonAlreadyIssued)
		}
	}
	token, err := generateToken(issuer.random)
	if err != nil {
		issuer.diagnosticSink("issue token-generation-failed")
		return BootstrapEnvelope{}, NewFailure(ReasonIdentityFailure)
	}
	digest, _ := TokenDigest(token)
	if _, collision := issuer.store.records[digest]; collision {
		return BootstrapEnvelope{}, NewFailure(ReasonIdentityFailure)
	}
	record := fakeRecord{
		TokenDigest: digest, Binding: request.Binding, IssuedAt: FormatTimestamp(now),
		ExpiresAt: FormatTimestamp(now.Add(time.Duration(request.TTLSeconds) * time.Second)), State: StateIssued,
	}
	issuer.store.records[digest] = record
	return BootstrapEnvelope{
		ContractVersion: Version, Binding: request.Binding, ExchangeURL: issuer.configuration.ExchangeURL, Token: token,
		IssuedAt: record.IssuedAt, ExpiresAt: record.ExpiresAt,
	}, nil
}

func (issuer *fakeIssuer) Exchange(ctx context.Context, request ExchangeRequest) (ExchangeResult, error) {
	if err := ctx.Err(); err != nil {
		return ExchangeResult{}, err
	}
	if err := ValidateExchangeRequest(request); err != nil {
		issuer.diagnosticSink("exchange invalid-request")
		return ExchangeResult{}, err
	}
	digest, _ := TokenDigest(request.Token)
	fault := issuer.takeNextFault()
	result, err := issuer.store.consumeTransaction(digest, request.Binding, issuer.now().UTC().Truncate(time.Second), issuer.identity, fault)
	if err != nil {
		return ExchangeResult{}, err
	}
	if fault == fakeLoseResponseAfterCommit {
		return ExchangeResult{}, errFakeResponseLost
	}
	return result, nil
}

// consumeTransaction is the fake durable-store transaction seam. All staged
// identity data and the consumed state become visible together at the commit
// assignment below. Fault injection occurs on either side of that boundary.
func (store *fakeDurableStore) consumeTransaction(
	digest string,
	binding Binding,
	now time.Time,
	identityFactory func(Binding, time.Time) (RuntimeIdentity, error),
	fault fakeExchangeFault,
) (ExchangeResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.initializeLocked()
	if _, revoked := store.executionTombstones[binding.ExecutionScope()]; revoked {
		return ExchangeResult{}, NewFailure(ReasonRevoked)
	}
	if _, revoked := store.bindingTombstones[binding]; revoked {
		return ExchangeResult{}, NewFailure(ReasonRevoked)
	}
	record, found := store.records[digest]
	if !found {
		return ExchangeResult{}, NewFailure(ReasonInvalidToken)
	}
	switch record.State {
	case StateConsumed:
		return ExchangeResult{}, NewFailure(ReasonAlreadyConsumed)
	case StateRevoked:
		return ExchangeResult{}, NewFailure(ReasonRevoked)
	case StateExpired:
		return ExchangeResult{}, NewFailure(ReasonExpired)
	case StateIssued:
	default:
		return ExchangeResult{}, NewFailure(ReasonInvalidToken)
	}
	expires, _ := parseTimestamp(record.ExpiresAt)
	if !now.Before(expires) {
		record.State = StateExpired
		record.TerminalAt = FormatTimestamp(now)
		store.records[digest] = record
		return ExchangeResult{}, NewFailure(ReasonExpired)
	}
	if record.Binding != binding {
		return ExchangeResult{}, NewFailure(ReasonBindingMismatch)
	}
	identity, err := identityFactory(record.Binding, now)
	if err != nil || ValidateExchangeResult(ExchangeResult{ContractVersion: Version, Binding: record.Binding, RuntimeIdentity: identity}) != nil {
		return ExchangeResult{}, NewFailure(ReasonIdentityFailure)
	}
	if fault == fakeFailBeforeCommit {
		return ExchangeResult{}, NewFailure(ReasonStorageFailure)
	}
	record.State = StateConsumed
	identityDigest := sha256.Sum256([]byte(identity.Opaque))
	record.RuntimeIdentityDigest = "sha256:" + hex.EncodeToString(identityDigest[:])
	if _, collision := store.activeIdentities[record.RuntimeIdentityDigest]; collision {
		return ExchangeResult{}, NewFailure(ReasonIdentityFailure)
	}
	store.records[digest] = record
	store.activeIdentities[record.RuntimeIdentityDigest] = record.Binding.ExecutionScope()
	return ExchangeResult{ContractVersion: Version, Binding: record.Binding, RuntimeIdentity: identity}, nil
}

func (issuer *fakeIssuer) RevokeBinding(ctx context.Context, request RevokeBindingRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateRevokeBindingRequest(request); err != nil {
		return err
	}
	issuer.store.mu.Lock()
	defer issuer.store.mu.Unlock()
	issuer.store.initializeLocked()
	if _, revoked := issuer.store.executionTombstones[request.Binding.ExecutionScope()]; revoked {
		return nil
	}
	if _, present := issuer.store.bindingTombstones[request.Binding]; !present {
		matchingRecords := 0
		for _, record := range issuer.store.records {
			if record.Binding == request.Binding {
				matchingRecords++
			}
		}
		if issuer.store.usedEntriesLocked()+1-matchingRecords > maxFakeEntries {
			return NewFailure(ReasonCapacity)
		}
		issuer.store.bindingTombstones[request.Binding] = fakeTombstoneAt(issuer.now())
	}
	for digest, record := range issuer.store.records {
		if record.Binding == request.Binding {
			delete(issuer.store.activeIdentities, record.RuntimeIdentityDigest)
			delete(issuer.store.records, digest)
		}
	}
	return nil
}

func (issuer *fakeIssuer) RevokeExecution(ctx context.Context, request RevokeExecutionRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateRevokeExecutionRequest(request); err != nil {
		return err
	}
	issuer.store.mu.Lock()
	defer issuer.store.mu.Unlock()
	issuer.store.initializeLocked()
	if _, present := issuer.store.executionTombstones[request.ExecutionScope]; !present {
		coveredBindingTombstones := 0
		matchingRecords := 0
		for binding := range issuer.store.bindingTombstones {
			if binding.ExecutionScope() == request.ExecutionScope {
				coveredBindingTombstones++
			}
		}
		for _, record := range issuer.store.records {
			if record.Binding.ExecutionScope() == request.ExecutionScope {
				matchingRecords++
			}
		}
		if issuer.store.usedEntriesLocked()+1-coveredBindingTombstones-matchingRecords > maxFakeEntries {
			return NewFailure(ReasonCapacity)
		}
		issuer.store.executionTombstones[request.ExecutionScope] = fakeTombstoneAt(issuer.now())
	}
	// Repeat the compaction even when the scope tombstone already exists. A
	// production transactional store cannot expose partial scope revocation,
	// but level-triggered cleanup must also converge inconsistent recovered
	// state rather than treating the tombstone alone as proof of completion.
	for binding := range issuer.store.bindingTombstones {
		if binding.ExecutionScope() == request.ExecutionScope {
			delete(issuer.store.bindingTombstones, binding)
		}
	}
	for digest, record := range issuer.store.records {
		if record.Binding.ExecutionScope() == request.ExecutionScope {
			delete(issuer.store.activeIdentities, record.RuntimeIdentityDigest)
			delete(issuer.store.records, digest)
		}
	}
	return nil
}

func (store *fakeDurableStore) snapshot() []byte {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.initializeLocked()
	bindingTombstones := make([]Binding, 0, len(store.bindingTombstones))
	for binding := range store.bindingTombstones {
		bindingTombstones = append(bindingTombstones, binding)
	}
	executionTombstones := make([]ExecutionScope, 0, len(store.executionTombstones))
	for scope := range store.executionTombstones {
		executionTombstones = append(executionTombstones, scope)
	}
	activeIdentities := make(map[string]ExecutionScope, len(store.activeIdentities))
	for digest, scope := range store.activeIdentities {
		activeIdentities[digest] = scope
	}
	encoded, _ := json.Marshal(struct {
		Records             map[string]fakeRecord     `json:"records"`
		BindingTombstones   []Binding                 `json:"binding_tombstones"`
		ExecutionTombstones []ExecutionScope          `json:"execution_tombstones"`
		ActiveIdentities    map[string]ExecutionScope `json:"active_identity_digests"`
	}{Records: store.records, BindingTombstones: bindingTombstones, ExecutionTombstones: executionTombstones, ActiveIdentities: activeIdentities})
	return encoded
}

func (store *fakeDurableStore) state(token string) LifecycleState {
	digest, _ := TokenDigest(token)
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.records[digest].State
}

func (store *fakeDurableStore) recordPresent(token string) bool {
	digest, _ := TokenDigest(token)
	store.mu.Lock()
	defer store.mu.Unlock()
	_, present := store.records[digest]
	return present
}

func (store *fakeDurableStore) runtimeIdentityActive(token string) bool {
	digest, _ := TokenDigest(token)
	store.mu.Lock()
	defer store.mu.Unlock()
	record, present := store.records[digest]
	if !present || record.RuntimeIdentityDigest == "" {
		return false
	}
	_, active := store.activeIdentities[record.RuntimeIdentityDigest]
	return active
}

func (store *fakeDurableStore) usedEntries() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.initializeLocked()
	return store.usedEntriesLocked()
}

func (store *fakeDurableStore) activeRuntimeIdentities(scope ExecutionScope) int {
	store.mu.Lock()
	defer store.mu.Unlock()
	active := 0
	for _, identityScope := range store.activeIdentities {
		if identityScope == scope {
			active++
		}
	}
	return active
}

// garbageCollectCompleted models the only permitted tombstone GC boundary:
// retention elapsed and the authoritative orchestrator has completed cleanup
// for a scope it will no longer authorize for issuance.
func (store *fakeDurableStore) garbageCollectCompleted(now time.Time, completed map[ExecutionScope]struct{}) int {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.initializeLocked()
	removed := 0
	for binding, tombstone := range store.bindingTombstones {
		deleteAfter, _ := parseTimestamp(tombstone.DeleteAfter)
		if _, complete := completed[binding.ExecutionScope()]; complete && !now.Before(deleteAfter) {
			delete(store.bindingTombstones, binding)
			removed++
		}
	}
	for scope, tombstone := range store.executionTombstones {
		deleteAfter, _ := parseTimestamp(tombstone.DeleteAfter)
		if _, complete := completed[scope]; complete && !now.Before(deleteAfter) {
			delete(store.executionTombstones, scope)
			removed++
		}
	}
	for digest, record := range store.records {
		_, identityActive := store.activeIdentities[record.RuntimeIdentityDigest]
		if _, complete := completed[record.Binding.ExecutionScope()]; !complete || record.TerminalAt == "" || identityActive {
			continue
		}
		terminalAt, _ := parseTimestamp(record.TerminalAt)
		if !now.Before(terminalAt.Add(MaxTombstoneRetention)) {
			delete(store.records, digest)
			removed++
		}
	}
	return removed
}

func TestFakeIssuerGuestConformanceValidRestartAndReplay(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	store := &fakeDurableStore{records: map[string]fakeRecord{}}
	request := validIssueRequest()
	issuerBeforeRestart := newFakeIssuer(store, func() time.Time { return now }, deterministicRandom(1), validIdentityFactory(0x51))
	envelope, err := issuerBeforeRestart.Issue(context.Background(), request)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := ValidateBootstrapEnvelope(envelope); err != nil {
		t.Fatalf("envelope: %v", err)
	}
	if bytes.Contains(store.snapshot(), []byte(envelope.Token)) {
		t.Fatal("durable state retained the plaintext token")
	}

	// A new issuer process with only the durable store must complete exchange.
	issuerAfterRestart := newFakeIssuer(store, func() time.Time { return now.Add(time.Second) }, deterministicRandom(2), validIdentityFactory(0x51))
	encodedEnvelope, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	result, err := (fakeGuest{binding: request.Binding, expectedExchangeURL: fakeExchangeURL, issuer: issuerAfterRestart}).bootstrap(context.Background(), encodedEnvelope)
	if err != nil {
		t.Fatalf("exchange after restart: %v", err)
	}
	if result.Binding != request.Binding || result.RuntimeIdentity.Type != RuntimeIdentityType || store.state(envelope.Token) != StateConsumed {
		t.Fatalf("unexpected exchange result/state: %#v %s", result.Binding, store.state(envelope.Token))
	}
	if _, err := issuerAfterRestart.Exchange(context.Background(), ExchangeRequest{ContractVersion: Version, Binding: request.Binding, Token: envelope.Token}); failureReason(t, err) != ReasonAlreadyConsumed {
		t.Fatalf("replay reason: %v", err)
	}
	if !store.runtimeIdentityActive(envelope.Token) {
		t.Fatal("successful exchange did not activate one runtime identity")
	}
	if err := issuerAfterRestart.RevokeBinding(context.Background(), RevokeBindingRequest{ContractVersion: Version, Binding: request.Binding}); err != nil {
		t.Fatalf("revoke consumed enrollment: %v", err)
	}
	if store.activeRuntimeIdentities(request.Binding.ExecutionScope()) != 0 {
		t.Fatal("revocation left the runtime identity active")
	}
	if _, err := issuerAfterRestart.Exchange(context.Background(), ExchangeRequest{ContractVersion: Version, Binding: request.Binding, Token: envelope.Token}); failureReason(t, err) != ReasonRevoked {
		t.Fatalf("exchange after runtime-identity revocation: %v", err)
	}
}

func TestFakeIssuerOwnsCanonicalExchangeEndpoint(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	store := &fakeDurableStore{}
	issuer := newFakeIssuer(store, func() time.Time { return now }, deterministicRandom(0x31), validIdentityFactory(0x32))
	issuer.configuration = IssuerConfiguration{ExchangeURL: "https://issuer-owned.example/v1/exchange"}
	envelope, err := issuer.Issue(context.Background(), validIssueRequest())
	if err != nil {
		t.Fatal(err)
	}
	if envelope.ExchangeURL != issuer.configuration.ExchangeURL {
		t.Fatalf("envelope endpoint = %q, want issuer-owned %q", envelope.ExchangeURL, issuer.configuration.ExchangeURL)
	}
}

func TestFakeIssuerExecutionScopedRevocationSurvivesRestart(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	store := &fakeDurableStore{}
	issuer := newFakeIssuer(store, func() time.Time { return now }, deterministicRandom(0x41), validIdentityFactory(0x42))

	firstRequest := validIssueRequest()
	firstRequest.Binding.DesiredGeneration = 1
	firstRequest.Binding.GuestInstanceID = "guest-first"
	first, err := issuer.Issue(context.Background(), firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Exchange(context.Background(), ExchangeRequest{ContractVersion: Version, Binding: first.Binding, Token: first.Token}); err != nil {
		t.Fatal(err)
	}
	secondRequest := firstRequest
	secondRequest.Binding.DesiredGeneration = 2
	secondRequest.Binding.GuestInstanceID = "guest-replacement"
	second, err := issuer.Issue(context.Background(), secondRequest)
	if err != nil {
		t.Fatal(err)
	}

	unrelatedRequest := validIssueRequest()
	unrelatedRequest.Binding.AgentRunUID = "unrelated-run-uid"
	unrelatedRequest.Binding.ExecutionID = "unrelated-execution"
	unrelatedRequest.Binding.GuestInstanceID = "unrelated-guest"
	unrelated, err := issuer.Issue(context.Background(), unrelatedRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Exchange(context.Background(), ExchangeRequest{ContractVersion: Version, Binding: unrelated.Binding, Token: unrelated.Token}); err != nil {
		t.Fatal(err)
	}

	// A replacement issuer and orchestrator know only stable, non-secret scope.
	restarted := newFakeIssuer(store, func() time.Time { return now.Add(time.Second) }, deterministicRandom(0x51), validIdentityFactory(0x52))
	scope := first.Binding.ExecutionScope()
	if err := restarted.RevokeExecution(context.Background(), RevokeExecutionRequest{ContractVersion: Version, ExecutionScope: scope}); err != nil {
		t.Fatalf("execution-scoped revoke after restart: %v", err)
	}
	for _, envelope := range []BootstrapEnvelope{first, second} {
		if store.recordPresent(envelope.Token) {
			t.Fatalf("binding record was not compacted into the scope tombstone")
		}
		if _, err := restarted.Exchange(context.Background(), ExchangeRequest{ContractVersion: Version, Binding: envelope.Binding, Token: envelope.Token}); failureReason(t, err) != ReasonRevoked {
			t.Fatalf("revoked binding exchanged: %v", err)
		}
	}
	if store.activeRuntimeIdentities(scope) != 0 {
		t.Fatal("execution-scoped revoke left a runtime identity active")
	}
	thirdRequest := secondRequest
	thirdRequest.Binding.DesiredGeneration = 3
	thirdRequest.Binding.GuestInstanceID = "guest-after-cleanup"
	if _, err := restarted.Issue(context.Background(), thirdRequest); failureReason(t, err) != ReasonRevoked {
		t.Fatalf("execution tombstone did not reject a new binding: %v", err)
	}
	if store.state(unrelated.Token) != StateConsumed || !store.runtimeIdentityActive(unrelated.Token) || store.activeRuntimeIdentities(unrelated.Binding.ExecutionScope()) != 1 {
		t.Fatal("execution-scoped revoke affected an unrelated execution")
	}
}

func TestFakeIssuerTransactionalExchangeFaults(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)

	t.Run("failure before durable commit", func(t *testing.T) {
		store := &fakeDurableStore{}
		issuer := newFakeIssuer(store, func() time.Time { return now }, deterministicRandom(0x61), validIdentityFactory(0x62))
		envelope, err := issuer.Issue(context.Background(), validIssueRequest())
		if err != nil {
			t.Fatal(err)
		}
		issuer.setNextFault(fakeFailBeforeCommit)
		_, err = issuer.Exchange(context.Background(), ExchangeRequest{ContractVersion: Version, Binding: envelope.Binding, Token: envelope.Token})
		if failureReason(t, err) != ReasonStorageFailure || store.state(envelope.Token) != StateIssued || store.runtimeIdentityActive(envelope.Token) {
			t.Fatalf("pre-commit failure mutated state: err=%v state=%s active=%v", err, store.state(envelope.Token), store.runtimeIdentityActive(envelope.Token))
		}
		restarted := newFakeIssuer(store, func() time.Time { return now.Add(time.Second) }, deterministicRandom(0x63), validIdentityFactory(0x64))
		if _, err := restarted.Exchange(context.Background(), ExchangeRequest{ContractVersion: Version, Binding: envelope.Binding, Token: envelope.Token}); err != nil {
			t.Fatalf("issued token did not recover after pre-commit failure: %v", err)
		}
	})

	t.Run("commit succeeds but response is lost", func(t *testing.T) {
		store := &fakeDurableStore{}
		issuer := newFakeIssuer(store, func() time.Time { return now }, deterministicRandom(0x71), validIdentityFactory(0x72))
		envelope, err := issuer.Issue(context.Background(), validIssueRequest())
		if err != nil {
			t.Fatal(err)
		}
		issuer.setNextFault(fakeLoseResponseAfterCommit)
		_, err = issuer.Exchange(context.Background(), ExchangeRequest{ContractVersion: Version, Binding: envelope.Binding, Token: envelope.Token})
		if !errors.Is(err, errFakeResponseLost) || store.state(envelope.Token) != StateConsumed || !store.runtimeIdentityActive(envelope.Token) {
			t.Fatalf("post-commit response loss state: err=%v state=%s active=%v", err, store.state(envelope.Token), store.runtimeIdentityActive(envelope.Token))
		}
		restarted := newFakeIssuer(store, func() time.Time { return now.Add(time.Second) }, deterministicRandom(0x73), validIdentityFactory(0x74))
		if _, err := restarted.Exchange(context.Background(), ExchangeRequest{ContractVersion: Version, Binding: envelope.Binding, Token: envelope.Token}); failureReason(t, err) != ReasonAlreadyConsumed {
			t.Fatalf("response-loss replay was not denied: %v", err)
		}
		if err := restarted.RevokeExecution(context.Background(), RevokeExecutionRequest{ContractVersion: Version, ExecutionScope: envelope.Binding.ExecutionScope()}); err != nil {
			t.Fatal(err)
		}
		if store.activeRuntimeIdentities(envelope.Binding.ExecutionScope()) != 0 || store.recordPresent(envelope.Token) {
			t.Fatal("recovery revocation did not disable the committed identity")
		}
	})

	t.Run("identity failure is sanitized and uncommitted", func(t *testing.T) {
		store := &fakeDurableStore{}
		issuer := newFakeIssuer(store, func() time.Time { return now }, deterministicRandom(0x81), func(Binding, time.Time) (RuntimeIdentity, error) {
			return RuntimeIdentity{}, errors.New("identity-secret-canary")
		})
		envelope, err := issuer.Issue(context.Background(), validIssueRequest())
		if err != nil {
			t.Fatal(err)
		}
		_, err = issuer.Exchange(context.Background(), ExchangeRequest{ContractVersion: Version, Binding: envelope.Binding, Token: envelope.Token})
		if failureReason(t, err) != ReasonIdentityFailure || strings.Contains(err.Error(), "identity-secret-canary") || store.state(envelope.Token) != StateIssued || store.runtimeIdentityActive(envelope.Token) {
			t.Fatalf("identity failure was not fail-closed and sanitized: %v", err)
		}
	})
}

func TestFakeIssuerGuestConformanceAtomicSingleConsumption(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	store := &fakeDurableStore{records: map[string]fakeRecord{}}
	var identities atomic.Int32
	issuer := newFakeIssuer(store, func() time.Time { return now }, deterministicRandom(3), func(binding Binding, issued time.Time) (RuntimeIdentity, error) {
		identities.Add(1)
		return validIdentityFactory(0x62)(binding, issued)
	})
	envelope, err := issuer.Issue(context.Background(), validIssueRequest())
	if err != nil {
		t.Fatal(err)
	}

	const workers = 32
	var wait sync.WaitGroup
	var success atomic.Int32
	var consumed atomic.Int32
	start := make(chan struct{})
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, exchangeErr := issuer.Exchange(context.Background(), ExchangeRequest{ContractVersion: Version, Binding: envelope.Binding, Token: envelope.Token})
			if exchangeErr == nil {
				success.Add(1)
			} else if reason, ok := FailureReasonOf(exchangeErr); ok && reason == ReasonAlreadyConsumed {
				consumed.Add(1)
			} else {
				t.Errorf("unexpected exchange error: %v", exchangeErr)
			}
		}()
	}
	close(start)
	wait.Wait()
	if success.Load() != 1 || consumed.Load() != workers-1 || identities.Load() != 1 {
		t.Fatalf("success=%d consumed=%d identities=%d", success.Load(), consumed.Load(), identities.Load())
	}
}

func TestFakeIssuerGuestConformanceExactBinding(t *testing.T) {
	t.Parallel()
	mutations := map[string]func(*Binding){
		"agent run UID": func(value *Binding) { value.AgentRunUID += "-wrong" },
		"execution ID":  func(value *Binding) { value.ExecutionID += "-wrong" },
		"driver":        func(value *Binding) { value.DriverRegistration = "other-driver" },
		"generation":    func(value *Binding) { value.DesiredGeneration++ },
		"guest":         func(value *Binding) { value.GuestInstanceID += "-wrong" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
			store := &fakeDurableStore{records: map[string]fakeRecord{}}
			issuer := newFakeIssuer(store, func() time.Time { return now }, deterministicRandom(byte(len(name))), validIdentityFactory(0x71))
			envelope, err := issuer.Issue(context.Background(), validIssueRequest())
			if err != nil {
				t.Fatal(err)
			}
			wrong := envelope.Binding
			mutate(&wrong)
			_, err = issuer.Exchange(context.Background(), ExchangeRequest{ContractVersion: Version, Binding: wrong, Token: envelope.Token})
			if failureReason(t, err) != ReasonBindingMismatch || store.state(envelope.Token) != StateIssued {
				t.Fatalf("wrong binding did not fail without consumption: %v", err)
			}
			if _, err = issuer.Exchange(context.Background(), ExchangeRequest{ContractVersion: Version, Binding: envelope.Binding, Token: envelope.Token}); err != nil {
				t.Fatalf("correct binding after rejection: %v", err)
			}
		})
	}
}

func TestFakeIssuerGuestConformanceExpiryRevocationAndIdempotency(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	store := &fakeDurableStore{records: map[string]fakeRecord{}}
	current := now
	issuer := newFakeIssuer(store, func() time.Time { return current }, deterministicRandom(8), validIdentityFactory(0x81))

	expiringRequest := validIssueRequest()
	expiringRequest.TTLSeconds = 1
	expiring, err := issuer.Issue(context.Background(), expiringRequest)
	if err != nil {
		t.Fatal(err)
	}
	current = now.Add(time.Second)
	if _, err = issuer.Exchange(context.Background(), ExchangeRequest{ContractVersion: Version, Binding: expiring.Binding, Token: expiring.Token}); failureReason(t, err) != ReasonExpired || store.state(expiring.Token) != StateExpired {
		t.Fatalf("expiry: %v state=%s", err, store.state(expiring.Token))
	}

	current = now
	revokedRequest := validIssueRequest()
	revokedRequest.Binding.GuestInstanceID = "guest-revoked"
	revoked, err := issuer.Issue(context.Background(), revokedRequest)
	if err != nil {
		t.Fatal(err)
	}
	wrong := revoked.Binding
	wrong.GuestInstanceID = "guest-other"
	if err := issuer.RevokeBinding(context.Background(), RevokeBindingRequest{ContractVersion: Version, Binding: wrong}); err != nil {
		t.Fatalf("absent revoke: %v", err)
	}
	wrongIssue := validIssueRequest()
	wrongIssue.Binding = wrong
	if _, err := issuer.Issue(context.Background(), wrongIssue); failureReason(t, err) != ReasonRevoked {
		t.Fatalf("durable absent-binding revocation did not reject later issue: %v", err)
	}
	if store.state(revoked.Token) != StateIssued {
		t.Fatal("wrong binding revoked the enrollment")
	}
	for range 2 {
		if err := issuer.RevokeBinding(context.Background(), RevokeBindingRequest{ContractVersion: Version, Binding: revoked.Binding}); err != nil {
			t.Fatalf("idempotent revoke: %v", err)
		}
	}
	if _, err = issuer.Exchange(context.Background(), ExchangeRequest{ContractVersion: Version, Binding: revoked.Binding, Token: revoked.Token}); failureReason(t, err) != ReasonRevoked {
		t.Fatalf("revoked exchange: %v", err)
	}
}

func TestFakeIssuerGuestConformanceCancellationCapacityAndRedaction(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	store := &fakeDurableStore{records: map[string]fakeRecord{}}
	var diagnostics strings.Builder
	identityCanary := bytes.Repeat([]byte("identity-canary-"), 3)
	issuer := newFakeIssuer(store, func() time.Time { return now }, deterministicRandom(9), func(_ Binding, issued time.Time) (RuntimeIdentity, error) {
		return RuntimeIdentity{Type: RuntimeIdentityType, Opaque: base64.RawURLEncoding.EncodeToString(identityCanary), IssuedAt: FormatTimestamp(issued), ExpiresAt: FormatTimestamp(issued.Add(time.Hour))}, nil
	})
	issuer.diagnosticSink = func(message string) { diagnostics.WriteString(message + "\n") }
	envelope, err := issuer.Issue(context.Background(), validIssueRequest())
	if err != nil {
		t.Fatal(err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := issuer.Exchange(cancelled, ExchangeRequest{ContractVersion: Version, Binding: envelope.Binding, Token: envelope.Token}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled exchange: %v", err)
	}
	if store.state(envelope.Token) != StateIssued {
		t.Fatal("cancelled exchange mutated durable state")
	}

	unknownToken := opaqueValue(TokenBytes, 0xee)
	_, invalidErr := issuer.Exchange(context.Background(), ExchangeRequest{ContractVersion: Version, Binding: envelope.Binding, Token: unknownToken})
	if failureReason(t, invalidErr) != ReasonInvalidToken {
		t.Fatalf("invalid token: %v", invalidErr)
	}
	result, err := issuer.Exchange(context.Background(), ExchangeRequest{ContractVersion: Version, Binding: envelope.Binding, Token: envelope.Token})
	if err != nil {
		t.Fatal(err)
	}

	ordinary := append(store.snapshot(), []byte(diagnostics.String()+invalidErr.Error()+fmt.Sprint(envelope, result))...)
	for _, canary := range [][]byte{[]byte(envelope.Token), []byte(unknownToken), identityCanary, []byte(result.RuntimeIdentity.Opaque)} {
		if bytes.Contains(ordinary, canary) {
			t.Fatalf("sensitive canary leaked into state/error/diagnostics: %q", canary)
		}
	}

	failureRequest := validIssueRequest()
	failureRequest.Binding.GuestInstanceID = "identity-failure-guest"
	failureIssuer := newFakeIssuer(store, func() time.Time { return now }, deterministicRandom(0xb1), func(Binding, time.Time) (RuntimeIdentity, error) {
		return RuntimeIdentity{}, errors.New("upstream returned identity-canary-sensitive-body")
	})
	failureEnvelope, err := failureIssuer.Issue(context.Background(), failureRequest)
	if err != nil {
		t.Fatal(err)
	}
	_, err = failureIssuer.Exchange(context.Background(), ExchangeRequest{ContractVersion: Version, Binding: failureEnvelope.Binding, Token: failureEnvelope.Token})
	if failureReason(t, err) != ReasonIdentityFailure || strings.Contains(err.Error(), "identity-canary") {
		t.Fatalf("identity failure was not sanitized: %v", err)
	}

	full := &fakeDurableStore{records: map[string]fakeRecord{}}
	for index := 0; index < maxFakeEntries; index++ {
		full.records[fmt.Sprintf("sha256:%064x", index)] = fakeRecord{Binding: Binding{GuestInstanceID: fmt.Sprintf("guest-%d", index)}, State: StateExpired}
	}
	capacityIssuer := newFakeIssuer(full, func() time.Time { return now }, deterministicRandom(10), validIdentityFactory(0x91))
	if _, err := capacityIssuer.Issue(context.Background(), validIssueRequest()); failureReason(t, err) != ReasonCapacity {
		t.Fatalf("capacity error: %v", err)
	}
}

func TestFakeIssuerTombstonesShareTheHardCapacityBound(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	store := &fakeDurableStore{}
	issuer := newFakeIssuer(store, func() time.Time { return now }, deterministicRandom(0x91), validIdentityFactory(0x92))
	live, err := issuer.Issue(context.Background(), validIssueRequest())
	if err != nil {
		t.Fatal(err)
	}

	completed := make(map[ExecutionScope]struct{}, maxFakeEntries-1)
	for index := 0; index < maxFakeEntries-1; index++ {
		binding := live.Binding
		binding.AgentRunUID = fmt.Sprintf("completed-run-%d", index)
		binding.ExecutionID = fmt.Sprintf("completed-execution-%d", index)
		binding.DesiredGeneration = int64(index + 2)
		binding.GuestInstanceID = fmt.Sprintf("absent-guest-%d", index)
		if err := issuer.RevokeBinding(context.Background(), RevokeBindingRequest{ContractVersion: Version, Binding: binding}); err != nil {
			t.Fatalf("fill tombstone %d: %v", index, err)
		}
		completed[binding.ExecutionScope()] = struct{}{}
	}
	if store.usedEntries() != maxFakeEntries {
		t.Fatalf("durable entry count = %d, want %d", store.usedEntries(), maxFakeEntries)
	}
	overflow := live.Binding
	overflow.DesiredGeneration = maxFakeEntries + 2
	overflow.GuestInstanceID = "overflow-absent-guest"
	if err := issuer.RevokeBinding(context.Background(), RevokeBindingRequest{ContractVersion: Version, Binding: overflow}); failureReason(t, err) != ReasonCapacity {
		t.Fatalf("tombstone overflow did not fail closed: %v", err)
	}
	if store.usedEntries() != maxFakeEntries || store.state(live.Token) != StateIssued {
		t.Fatal("capacity failure evicted or mutated a live enrollment")
	}
	if _, err := issuer.Exchange(context.Background(), ExchangeRequest{ContractVersion: Version, Binding: live.Binding, Token: live.Token}); err != nil {
		t.Fatalf("live enrollment stopped working at tombstone capacity: %v", err)
	}
	if err := issuer.RevokeExecution(context.Background(), RevokeExecutionRequest{ContractVersion: Version, ExecutionScope: live.Binding.ExecutionScope()}); err != nil {
		t.Fatalf("execution cleanup could not compact its live record at capacity: %v", err)
	}
	if store.activeRuntimeIdentities(live.Binding.ExecutionScope()) != 0 || store.usedEntries() != maxFakeEntries {
		t.Fatal("execution cleanup at capacity did not atomically replace its record with a tombstone")
	}
	if removed := store.garbageCollectCompleted(now.Add(MaxTombstoneRetention), completed); removed != maxFakeEntries-1 || store.usedEntries() != 1 {
		t.Fatalf("completed-scope tombstone GC removed=%d entries=%d", removed, store.usedEntries())
	}
	completed[live.Binding.ExecutionScope()] = struct{}{}
	if removed := store.garbageCollectCompleted(now.Add(MaxTombstoneRetention), completed); removed != 1 || store.usedEntries() != 0 {
		t.Fatalf("completed execution tombstone GC removed=%d entries=%d", removed, store.usedEntries())
	}
}

func TestFakeIssuerNeverReissuesTheSameRevokedBinding(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	store := &fakeDurableStore{records: map[string]fakeRecord{}}
	issuer := newFakeIssuer(store, func() time.Time { return now }, io.MultiReader(
		bytes.NewReader(bytes.Repeat([]byte{0x22}, TokenBytes)),
		bytes.NewReader(bytes.Repeat([]byte{0x23}, TokenBytes)),
		bytes.NewReader(bytes.Repeat([]byte{0x24}, TokenBytes)),
		bytes.NewReader(bytes.Repeat([]byte{0x25}, TokenBytes)),
	), validIdentityFactory(0xa1))
	request := validIssueRequest()
	first, err := issuer.Issue(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Issue(context.Background(), request); failureReason(t, err) != ReasonAlreadyIssued {
		t.Fatalf("duplicate issue: %v", err)
	}
	if err := issuer.RevokeBinding(context.Background(), RevokeBindingRequest{ContractVersion: Version, Binding: request.Binding}); err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Issue(context.Background(), request); failureReason(t, err) != ReasonRevoked {
		t.Fatalf("revoked binding was reissued: %v", err)
	}
	request.Binding.GuestInstanceID = "replacement-guest"
	second, err := issuer.Issue(context.Background(), request)
	if err != nil || second.Token == first.Token {
		t.Fatalf("new guest binding after revocation: same=%v err=%v", second.Token == first.Token, err)
	}
}

func validIssueRequest() IssueRequest {
	return IssueRequest{ContractVersion: Version, Binding: validBinding(), TTLSeconds: 300}
}

func deterministicRandom(value byte) io.Reader {
	var data []byte
	for offset := 0; offset < maxFakeEntries+2; offset++ {
		data = append(data, bytes.Repeat([]byte{value + byte(offset)}, TokenBytes)...)
	}
	return bytes.NewReader(data)
}

func validIdentityFactory(value byte) func(Binding, time.Time) (RuntimeIdentity, error) {
	return func(binding Binding, issued time.Time) (RuntimeIdentity, error) {
		identity := sha256.Sum256([]byte(fmt.Sprintf("%d:%s:%s:%s:%d:%s", value, binding.AgentRunUID, binding.ExecutionID, binding.DriverRegistration, binding.DesiredGeneration, binding.GuestInstanceID)))
		return RuntimeIdentity{Type: RuntimeIdentityType, Opaque: base64.RawURLEncoding.EncodeToString(identity[:]), IssuedAt: FormatTimestamp(issued), ExpiresAt: FormatTimestamp(issued.Add(time.Hour))}, nil
	}
}

func failureReason(t *testing.T, err error) FailureReason {
	t.Helper()
	if err == nil {
		t.Fatal("expected failure")
	}
	reason, ok := FailureReasonOf(err)
	if !ok {
		t.Fatalf("not a sanitized enrollment failure: %v", err)
	}
	return reason
}
