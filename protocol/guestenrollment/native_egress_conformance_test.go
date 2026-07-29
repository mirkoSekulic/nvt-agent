package guestenrollment

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeNativeEgressRecord struct {
	Binding   Binding
	Digest    string
	Sequence  uint64
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type fakeNativeEgressStore struct {
	mu              sync.Mutex
	runtimeBindings map[string]Binding
	records         map[string]fakeNativeEgressRecord
	sequences       map[Binding]uint64
	revokedBindings map[Binding]bool
	revokedScopes   map[ExecutionScope]bool
	loseResponse    bool
	maxEntries      int
}

func (*fakeNativeEgressStore) String() string   { return "[native egress durable store]" }
func (*fakeNativeEgressStore) GoString() string { return "[native egress durable store]" }

type fakeNativeEgressAuthority struct {
	store *fakeNativeEgressStore
	now   func() time.Time
}

var _ NativeEgressAuthority = (*fakeNativeEgressAuthority)(nil)

type fakeNativeEgressSequenceSnapshot struct {
	Binding  Binding `json:"binding"`
	Sequence uint64  `json:"sequence"`
}

type fakeNativeEgressStoreSnapshot struct {
	RuntimeBindings map[string]Binding                 `json:"runtime_bindings"`
	Records         []fakeNativeEgressRecord           `json:"records"`
	Sequences       []fakeNativeEgressSequenceSnapshot `json:"sequences"`
	RevokedBindings []Binding                          `json:"revoked_bindings"`
	RevokedScopes   []ExecutionScope                   `json:"revoked_scopes"`
}

func newFakeNativeEgressStore() *fakeNativeEgressStore {
	return &fakeNativeEgressStore{
		runtimeBindings: map[string]Binding{}, records: map[string]fakeNativeEgressRecord{}, sequences: map[Binding]uint64{},
		revokedBindings: map[Binding]bool{}, revokedScopes: map[ExecutionScope]bool{},
	}
}

func addFakeRuntimeIdentity(t *testing.T, store *fakeNativeEgressStore, binding Binding, fill byte) string {
	t.Helper()
	identity := opaqueValue(RuntimeIdentityBytes, fill)
	digest, err := RuntimeIdentityDigest(identity)
	if err != nil {
		t.Fatal(err)
	}
	store.runtimeBindings[digest] = binding
	return identity
}

func (store *fakeNativeEgressStore) durableEntriesLocked() int {
	return len(store.sequences) + len(store.revokedBindings) + len(store.revokedScopes)
}

func (store *fakeNativeEgressStore) durableLimit() int {
	if store.maxEntries > 0 {
		return store.maxEntries
	}
	return MaxNativeEgressIdentityEntries
}

func (store *fakeNativeEgressStore) snapshot() ([]byte, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value := fakeNativeEgressStoreSnapshot{RuntimeBindings: map[string]Binding{}}
	for digest, binding := range store.runtimeBindings {
		value.RuntimeBindings[digest] = binding
	}
	for _, record := range store.records {
		value.Records = append(value.Records, record)
	}
	for binding, sequence := range store.sequences {
		value.Sequences = append(value.Sequences, fakeNativeEgressSequenceSnapshot{Binding: binding, Sequence: sequence})
	}
	for binding := range store.revokedBindings {
		value.RevokedBindings = append(value.RevokedBindings, binding)
	}
	for scope := range store.revokedScopes {
		value.RevokedScopes = append(value.RevokedScopes, scope)
	}
	return json.Marshal(value)
}

func (authority *fakeNativeEgressAuthority) IssueNativeEgress(_ context.Context, runtimeIdentity string, request NativeEgressIssueRequest) (NativeEgressIssueResult, error) {
	if ValidateNativeEgressIssueRequest(request) != nil {
		return NativeEgressIssueResult{}, NewFailure(ReasonInvalidRequest)
	}
	runtimeDigest, err := RuntimeIdentityDigest(runtimeIdentity)
	if err != nil {
		return NativeEgressIssueResult{}, NewFailure(ReasonUnauthorized)
	}
	store := authority.store
	store.mu.Lock()
	defer store.mu.Unlock()
	runtimeBinding, runtimeActive := store.runtimeBindings[runtimeDigest]
	if !runtimeActive || runtimeBinding != request.Binding || store.revokedBindings[request.Binding] || store.revokedScopes[request.Binding.ExecutionScope()] {
		return NativeEgressIssueResult{}, NewFailure(ReasonUnauthorized)
	}
	if _, known := store.sequences[request.Binding]; !known && store.durableEntriesLocked() >= store.durableLimit() {
		return NativeEgressIssueResult{}, NewFailure(ReasonCapacity)
	}
	now := authority.now()
	live := 0
	for digest, record := range store.records {
		if !now.Before(record.ExpiresAt) {
			delete(store.records, digest)
			continue
		}
		if record.Binding == request.Binding {
			live++
		}
	}
	if live >= MaxLiveNativeEgressCredentials || store.sequences[request.Binding] >= MaxGuestSessionIssuanceSequence {
		return NativeEgressIssueResult{}, NewFailure(ReasonCapacity)
	}
	sequence := store.sequences[request.Binding] + 1
	credential, err := GenerateNativeEgressCredential(sequence)
	if err != nil {
		return NativeEgressIssueResult{}, NewFailure(ReasonIdentityFailure)
	}
	digest, _ := NativeEgressCredentialDigest(credential)
	record := fakeNativeEgressRecord{Binding: request.Binding, Digest: digest, Sequence: sequence, IssuedAt: now, ExpiresAt: now.Add(MaxNativeEgressCredentialLifetime)}
	store.records[digest] = record
	store.sequences[request.Binding] = sequence
	if store.loseResponse {
		store.loseResponse = false
		return NativeEgressIssueResult{}, errors.New("response lost")
	}
	return nativeEgressIssueResult(record, credential), nil
}

func (authority *fakeNativeEgressAuthority) AuthenticateNativeEgress(_ context.Context, credential string, request NativeEgressAuthenticateRequest) (NativeEgressStatus, error) {
	if ValidateNativeEgressAuthenticateRequest(request) != nil {
		return NativeEgressStatus{}, NewFailure(ReasonInvalidRequest)
	}
	digest, err := NativeEgressCredentialDigest(credential)
	if err != nil {
		return NativeEgressStatus{}, NewFailure(ReasonUnauthorized)
	}
	store := authority.store
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[digest]
	if !ok || record.Binding != request.Binding || store.revokedBindings[record.Binding] || store.revokedScopes[record.Binding.ExecutionScope()] || !authority.now().Before(record.ExpiresAt) {
		return NativeEgressStatus{}, NewFailure(ReasonUnauthorized)
	}
	return nativeEgressStatus(record), nil
}

func (authority *fakeNativeEgressAuthority) RevokeNativeEgressBinding(_ context.Context, request NativeEgressRevokeBindingRequest) error {
	if ValidateNativeEgressRevokeBindingRequest(request) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	store := authority.store
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.revokedScopes[request.Binding.ExecutionScope()] || store.revokedBindings[request.Binding] {
		return nil
	}
	if _, known := store.sequences[request.Binding]; !known && store.durableEntriesLocked() >= store.durableLimit() {
		return NewFailure(ReasonCapacity)
	}
	delete(store.sequences, request.Binding)
	store.revokedBindings[request.Binding] = true
	for digest, record := range store.records {
		if record.Binding == request.Binding {
			delete(store.records, digest)
		}
	}
	return nil
}

func (authority *fakeNativeEgressAuthority) RevokeNativeEgressExecution(_ context.Context, request NativeEgressRevokeExecutionRequest) error {
	if ValidateNativeEgressRevokeExecutionRequest(request) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	store := authority.store
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.revokedScopes[request.ExecutionScope] {
		return nil
	}
	reclaimed := false
	for binding := range store.sequences {
		if binding.ExecutionScope() == request.ExecutionScope {
			delete(store.sequences, binding)
			reclaimed = true
		}
	}
	for binding := range store.revokedBindings {
		if binding.ExecutionScope() == request.ExecutionScope {
			delete(store.revokedBindings, binding)
			reclaimed = true
		}
	}
	if !reclaimed && store.durableEntriesLocked() >= store.durableLimit() {
		return NewFailure(ReasonCapacity)
	}
	store.revokedScopes[request.ExecutionScope] = true
	for digest, record := range store.records {
		if record.Binding.ExecutionScope() == request.ExecutionScope {
			delete(store.records, digest)
		}
	}
	return nil
}

func nativeEgressIssueResult(record fakeNativeEgressRecord, credential string) NativeEgressIssueResult {
	return NativeEgressIssueResult{
		ContractVersion: NativeEgressIdentityVersion, Binding: record.Binding,
		Credential: NativeEgressCredential{
			Type: NativeEgressCredentialType, Opaque: credential, Audience: NativeEgressAudience,
			IssuedAt: FormatTimestamp(record.IssuedAt), ExpiresAt: FormatTimestamp(record.ExpiresAt),
		},
	}
}

func nativeEgressStatus(record fakeNativeEgressRecord) NativeEgressStatus {
	return NativeEgressStatus{
		ContractVersion: NativeEgressIdentityVersion, CredentialType: NativeEgressCredentialType,
		Binding: record.Binding, Audience: NativeEgressAudience, Sequence: record.Sequence,
		IssuedAt: FormatTimestamp(record.IssuedAt), ExpiresAt: FormatTimestamp(record.ExpiresAt),
	}
}

func TestNativeEgressIdentityConformanceRestartResponseLossExpiryAndRevocation(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	binding := validBinding()
	store := newFakeNativeEgressStore()
	runtimeIdentity := addFakeRuntimeIdentity(t, store, binding, 0xa1)
	store.loseResponse = true
	newAuthority := func() *fakeNativeEgressAuthority {
		return &fakeNativeEgressAuthority{store: store, now: func() time.Time { return now }}
	}
	issue := NativeEgressIssueRequest{ContractVersion: NativeEgressIdentityVersion, Binding: binding, Audience: NativeEgressAudience}
	authenticate := NativeEgressAuthenticateRequest{ContractVersion: NativeEgressIdentityVersion, Binding: binding, Audience: NativeEgressAudience}

	if _, err := newAuthority().IssueNativeEgress(context.Background(), runtimeIdentity, issue); err == nil {
		t.Fatal("committed first response loss was not surfaced")
	}
	recovered, err := newAuthority().IssueNativeEgress(context.Background(), runtimeIdentity, issue)
	if err != nil || ValidateNativeEgressIssueResult(recovered) != nil {
		t.Fatalf("bounded recovery after restart: %#v %v", recovered, err)
	}
	status, err := newAuthority().AuthenticateNativeEgress(context.Background(), recovered.Credential.Opaque, authenticate)
	if err != nil || status.Sequence != 2 || ValidateNativeEgressStatus(status) != nil {
		t.Fatalf("restart authentication: %#v %v", status, err)
	}
	persisted, err := store.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	runtimeDigest, _ := RuntimeIdentityDigest(runtimeIdentity)
	recoveredDigest, _ := NativeEgressCredentialDigest(recovered.Credential.Opaque)
	if !strings.Contains(string(persisted), runtimeDigest) || !strings.Contains(string(persisted), recoveredDigest) {
		t.Fatalf("snapshot did not exercise persisted digests: %s", persisted)
	}
	for _, secret := range []string{runtimeIdentity, recovered.Credential.Opaque} {
		if strings.Contains(string(persisted), secret) {
			t.Fatalf("plaintext credential entered durable snapshot: %s", persisted)
		}
	}
	if _, err := newAuthority().IssueNativeEgress(context.Background(), runtimeIdentity, issue); nativeEgressFailureReason(err) != ReasonCapacity {
		t.Fatalf("third live issue reason=%v", err)
	}

	wrong := authenticate
	wrong.Binding.DriverRegistration = "other-driver"
	if _, err := newAuthority().AuthenticateNativeEgress(context.Background(), recovered.Credential.Opaque, wrong); nativeEgressFailureReason(err) != ReasonUnauthorized {
		t.Fatalf("cross-driver authentication reason=%v", err)
	}
	wrong.Audience = NativeGuestControlAudience
	if _, err := newAuthority().AuthenticateNativeEgress(context.Background(), recovered.Credential.Opaque, wrong); nativeEgressFailureReason(err) != ReasonInvalidRequest {
		t.Fatalf("cross-purpose authentication reason=%v", err)
	}

	now = now.Add(MaxNativeEgressCredentialLifetime)
	if _, err := newAuthority().AuthenticateNativeEgress(context.Background(), recovered.Credential.Opaque, authenticate); nativeEgressFailureReason(err) != ReasonUnauthorized {
		t.Fatalf("expired authentication reason=%v", err)
	}
	now = now.Add(time.Second)
	reissued, err := newAuthority().IssueNativeEgress(context.Background(), runtimeIdentity, issue)
	if err != nil || reissued.Credential.Opaque == recovered.Credential.Opaque {
		t.Fatalf("issue after expiry: %v", err)
	}
	if err := newAuthority().RevokeNativeEgressBinding(context.Background(), NativeEgressRevokeBindingRequest{ContractVersion: NativeEgressIdentityVersion, Binding: binding}); err != nil {
		t.Fatal(err)
	}
	if _, err := newAuthority().AuthenticateNativeEgress(context.Background(), reissued.Credential.Opaque, authenticate); nativeEgressFailureReason(err) != ReasonUnauthorized {
		t.Fatalf("binding revocation reason=%v", err)
	}

	replacement := binding
	replacement.GuestInstanceID = "replacement-guest"
	replacementRuntimeIdentity := addFakeRuntimeIdentity(t, store, replacement, 0xa2)
	replacementIssue := issue
	replacementIssue.Binding = replacement
	if _, err := newAuthority().IssueNativeEgress(context.Background(), runtimeIdentity, replacementIssue); nativeEgressFailureReason(err) != ReasonUnauthorized {
		t.Fatalf("old guest runtime identity authorized replacement: %v", err)
	}
	replacementResult, err := newAuthority().IssueNativeEgress(context.Background(), replacementRuntimeIdentity, replacementIssue)
	if err != nil {
		t.Fatal(err)
	}
	if err := newAuthority().RevokeNativeEgressExecution(context.Background(), NativeEgressRevokeExecutionRequest{ContractVersion: NativeEgressIdentityVersion, ExecutionScope: binding.ExecutionScope()}); err != nil {
		t.Fatal(err)
	}
	replacementAuth := authenticate
	replacementAuth.Binding = replacement
	if _, err := newAuthority().AuthenticateNativeEgress(context.Background(), replacementResult.Credential.Opaque, replacementAuth); nativeEgressFailureReason(err) != ReasonUnauthorized {
		t.Fatalf("execution revocation reason=%v", err)
	}
	if _, err := newAuthority().IssueNativeEgress(context.Background(), replacementRuntimeIdentity, replacementIssue); nativeEgressFailureReason(err) != ReasonUnauthorized {
		t.Fatalf("execution tombstone did not prevent issue: %v", err)
	}

	snapshot, err := store.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{runtimeIdentity, replacementRuntimeIdentity, recovered.Credential.Opaque, reissued.Credential.Opaque, replacementResult.Credential.Opaque} {
		if strings.Contains(string(snapshot), secret) {
			t.Fatalf("plaintext credential entered durable snapshot: %s", snapshot)
		}
	}
}

func TestNativeEgressIdentityIssueRequiresRuntimeIdentityExactBinding(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	binding := validBinding()
	store := newFakeNativeEgressStore()
	runtimeIdentity := addFakeRuntimeIdentity(t, store, binding, 0xb1)
	authority := &fakeNativeEgressAuthority{store: store, now: func() time.Time { return now }}

	mutations := map[string]func(*Binding){
		"agent run UID":       func(value *Binding) { value.AgentRunUID = "other-run-uid" },
		"execution ID":        func(value *Binding) { value.ExecutionID = "other-execution" },
		"driver registration": func(value *Binding) { value.DriverRegistration = "other-driver" },
		"desired generation":  func(value *Binding) { value.DesiredGeneration++ },
		"guest instance ID":   func(value *Binding) { value.GuestInstanceID = "other-guest" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			wrong := binding
			mutate(&wrong)
			_, err := authority.IssueNativeEgress(context.Background(), runtimeIdentity, NativeEgressIssueRequest{
				ContractVersion: NativeEgressIdentityVersion, Binding: wrong, Audience: NativeEgressAudience,
			})
			if nativeEgressFailureReason(err) != ReasonUnauthorized {
				t.Fatalf("binding mutation authorized: %v", err)
			}
		})
	}
	replacement := binding
	replacement.GuestInstanceID = "replacement-guest"
	replacementIdentity := addFakeRuntimeIdentity(t, store, replacement, 0xb2)
	if _, err := authority.IssueNativeEgress(context.Background(), replacementIdentity, NativeEgressIssueRequest{
		ContractVersion: NativeEgressIdentityVersion, Binding: replacement, Audience: NativeEgressAudience,
	}); err != nil {
		t.Fatalf("replacement's exact runtime identity was rejected: %v", err)
	}
}

func TestNativeEgressIdentityConcurrentIssuanceIsBounded(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	binding := validBinding()
	store := newFakeNativeEgressStore()
	runtimeIdentity := addFakeRuntimeIdentity(t, store, binding, 0xc1)
	authority := &fakeNativeEgressAuthority{store: store, now: func() time.Time { return now }}
	request := NativeEgressIssueRequest{ContractVersion: NativeEgressIdentityVersion, Binding: binding, Audience: NativeEgressAudience}
	results := make(chan error, 16)
	var group sync.WaitGroup
	for range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := authority.IssueNativeEgress(context.Background(), runtimeIdentity, request)
			results <- err
		}()
	}
	group.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		} else if nativeEgressFailureReason(err) != ReasonCapacity {
			t.Fatalf("unexpected concurrent error: %v", err)
		}
	}
	if succeeded != MaxLiveNativeEgressCredentials || len(store.records) != MaxLiveNativeEgressCredentials {
		t.Fatalf("success=%d records=%d", succeeded, len(store.records))
	}
}

func TestNativeEgressIdentityDurableBindingCapacityIsBounded(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	first := validBinding()
	second := first
	second.AgentRunUID = "another-run-uid"
	second.ExecutionID = "another-execution"
	store := newFakeNativeEgressStore()
	store.maxEntries = 1
	identities := map[Binding]string{
		first:  addFakeRuntimeIdentity(t, store, first, 0xd1),
		second: addFakeRuntimeIdentity(t, store, second, 0xd2),
	}
	authority := &fakeNativeEgressAuthority{store: store, now: func() time.Time { return now }}
	for _, binding := range []Binding{first, second} {
		_, err := authority.IssueNativeEgress(context.Background(), identities[binding], NativeEgressIssueRequest{
			ContractVersion: NativeEgressIdentityVersion, Binding: binding, Audience: NativeEgressAudience,
		})
		if binding == first && err != nil {
			t.Fatal(err)
		}
		if binding == second && nativeEgressFailureReason(err) != ReasonCapacity {
			t.Fatalf("binding capacity error=%v", err)
		}
	}
	if MaxNativeEgressIdentityEntries != MaxDurableEntries || MaxNativeEgressIdentityEntries <= 0 {
		t.Fatalf("invalid durable entry bound=%d", MaxNativeEgressIdentityEntries)
	}
}

func TestNativeEgressIdentityTombstonesShareDurableCapacity(t *testing.T) {
	t.Run("binding tombstones", func(t *testing.T) {
		store := newFakeNativeEgressStore()
		store.maxEntries = 1
		authority := &fakeNativeEgressAuthority{store: store, now: time.Now}
		first := validBinding()
		second := first
		second.GuestInstanceID = "unknown-second-guest"
		if err := authority.RevokeNativeEgressBinding(context.Background(), NativeEgressRevokeBindingRequest{
			ContractVersion: NativeEgressIdentityVersion, Binding: first,
		}); err != nil {
			t.Fatal(err)
		}
		if err := authority.RevokeNativeEgressBinding(context.Background(), NativeEgressRevokeBindingRequest{
			ContractVersion: NativeEgressIdentityVersion, Binding: second,
		}); nativeEgressFailureReason(err) != ReasonCapacity {
			t.Fatalf("unbounded absent binding tombstone: %v", err)
		}
		store.mu.Lock()
		entries := store.durableEntriesLocked()
		store.mu.Unlock()
		if entries != 1 {
			t.Fatalf("durable entries=%d", entries)
		}
	})

	t.Run("execution tombstones", func(t *testing.T) {
		store := newFakeNativeEgressStore()
		store.maxEntries = 1
		authority := &fakeNativeEgressAuthority{store: store, now: time.Now}
		first := validBinding().ExecutionScope()
		second := first
		second.ExecutionID = "unknown-second-execution"
		if err := authority.RevokeNativeEgressExecution(context.Background(), NativeEgressRevokeExecutionRequest{
			ContractVersion: NativeEgressIdentityVersion, ExecutionScope: first,
		}); err != nil {
			t.Fatal(err)
		}
		if err := authority.RevokeNativeEgressExecution(context.Background(), NativeEgressRevokeExecutionRequest{
			ContractVersion: NativeEgressIdentityVersion, ExecutionScope: second,
		}); nativeEgressFailureReason(err) != ReasonCapacity {
			t.Fatalf("unbounded absent execution tombstone: %v", err)
		}
		store.mu.Lock()
		entries := store.durableEntriesLocked()
		store.mu.Unlock()
		if entries != 1 {
			t.Fatalf("durable entries=%d", entries)
		}
	})

	t.Run("known lifecycle is atomically replaced", func(t *testing.T) {
		now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
		store := newFakeNativeEgressStore()
		store.maxEntries = 1
		binding := validBinding()
		identity := addFakeRuntimeIdentity(t, store, binding, 0xe1)
		authority := &fakeNativeEgressAuthority{store: store, now: func() time.Time { return now }}
		if _, err := authority.IssueNativeEgress(context.Background(), identity, NativeEgressIssueRequest{
			ContractVersion: NativeEgressIdentityVersion, Binding: binding, Audience: NativeEgressAudience,
		}); err != nil {
			t.Fatal(err)
		}
		if err := authority.RevokeNativeEgressBinding(context.Background(), NativeEgressRevokeBindingRequest{
			ContractVersion: NativeEgressIdentityVersion, Binding: binding,
		}); err != nil {
			t.Fatalf("cleanup could not replace its lifecycle at capacity: %v", err)
		}
		store.mu.Lock()
		entries := store.durableEntriesLocked()
		_, sequenceRemained := store.sequences[binding]
		tombstoned := store.revokedBindings[binding]
		store.mu.Unlock()
		if entries != 1 || sequenceRemained || !tombstoned {
			t.Fatalf("entries=%d sequence=%t tombstone=%t", entries, sequenceRemained, tombstoned)
		}
	})
}

func nativeEgressFailureReason(err error) FailureReason {
	reason, _ := FailureReasonOf(err)
	return reason
}
