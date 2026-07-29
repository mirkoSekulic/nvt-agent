package guestenrollment

import (
	"context"
	"errors"
	"fmt"
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
	runtimeDigest   string
	records         map[string]fakeNativeEgressRecord
	sequences       map[Binding]uint64
	revokedBindings map[Binding]bool
	revokedScopes   map[ExecutionScope]bool
	loseResponse    bool
	maxBindings     int
}

func (*fakeNativeEgressStore) String() string   { return "[native egress durable store]" }
func (*fakeNativeEgressStore) GoString() string { return "[native egress durable store]" }

type fakeNativeEgressAuthority struct {
	store *fakeNativeEgressStore
	now   func() time.Time
}

var _ NativeEgressAuthority = (*fakeNativeEgressAuthority)(nil)

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
	if runtimeDigest != store.runtimeDigest || store.revokedBindings[request.Binding] || store.revokedScopes[request.Binding.ExecutionScope()] {
		return NativeEgressIssueResult{}, NewFailure(ReasonUnauthorized)
	}
	maxBindings := store.maxBindings
	if maxBindings == 0 {
		maxBindings = MaxNativeEgressIdentityBindings
	}
	if _, known := store.sequences[request.Binding]; !known && len(store.sequences) >= maxBindings {
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
	authority.store.mu.Lock()
	defer authority.store.mu.Unlock()
	authority.store.revokedBindings[request.Binding] = true
	for digest, record := range authority.store.records {
		if record.Binding == request.Binding {
			delete(authority.store.records, digest)
		}
	}
	return nil
}

func (authority *fakeNativeEgressAuthority) RevokeNativeEgressExecution(_ context.Context, request NativeEgressRevokeExecutionRequest) error {
	if ValidateNativeEgressRevokeExecutionRequest(request) != nil {
		return NewFailure(ReasonInvalidRequest)
	}
	authority.store.mu.Lock()
	defer authority.store.mu.Unlock()
	authority.store.revokedScopes[request.ExecutionScope] = true
	for digest, record := range authority.store.records {
		if record.Binding.ExecutionScope() == request.ExecutionScope {
			delete(authority.store.records, digest)
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
	runtimeIdentity := opaqueValue(RuntimeIdentityBytes, 0xa1)
	runtimeDigest, err := RuntimeIdentityDigest(runtimeIdentity)
	if err != nil {
		t.Fatal(err)
	}
	binding := validBinding()
	store := &fakeNativeEgressStore{
		runtimeDigest: runtimeDigest, records: map[string]fakeNativeEgressRecord{}, sequences: map[Binding]uint64{},
		revokedBindings: map[Binding]bool{}, revokedScopes: map[ExecutionScope]bool{}, loseResponse: true,
	}
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
	replacementIssue := issue
	replacementIssue.Binding = replacement
	replacementResult, err := newAuthority().IssueNativeEgress(context.Background(), runtimeIdentity, replacementIssue)
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
	if _, err := newAuthority().IssueNativeEgress(context.Background(), runtimeIdentity, replacementIssue); nativeEgressFailureReason(err) != ReasonUnauthorized {
		t.Fatalf("execution tombstone did not prevent issue: %v", err)
	}

	snapshot := fmt.Sprintf("%#v", store)
	for _, secret := range []string{runtimeIdentity, recovered.Credential.Opaque, reissued.Credential.Opaque, replacementResult.Credential.Opaque, binding.AgentRunUID, binding.GuestInstanceID} {
		if strings.Contains(snapshot, secret) {
			t.Fatalf("plaintext secret entered durable snapshot: %s", snapshot)
		}
	}
}

func TestNativeEgressIdentityConcurrentIssuanceIsBounded(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	runtimeIdentity := opaqueValue(RuntimeIdentityBytes, 0xa2)
	runtimeDigest, _ := RuntimeIdentityDigest(runtimeIdentity)
	binding := validBinding()
	store := &fakeNativeEgressStore{
		runtimeDigest: runtimeDigest, records: map[string]fakeNativeEgressRecord{}, sequences: map[Binding]uint64{},
		revokedBindings: map[Binding]bool{}, revokedScopes: map[ExecutionScope]bool{},
	}
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
	runtimeIdentity := opaqueValue(RuntimeIdentityBytes, 0xa3)
	runtimeDigest, _ := RuntimeIdentityDigest(runtimeIdentity)
	first := validBinding()
	second := first
	second.AgentRunUID = "another-run-uid"
	second.ExecutionID = "another-execution"
	store := &fakeNativeEgressStore{
		runtimeDigest: runtimeDigest, records: map[string]fakeNativeEgressRecord{}, sequences: map[Binding]uint64{},
		revokedBindings: map[Binding]bool{}, revokedScopes: map[ExecutionScope]bool{}, maxBindings: 1,
	}
	authority := &fakeNativeEgressAuthority{store: store, now: func() time.Time { return now }}
	for _, binding := range []Binding{first, second} {
		_, err := authority.IssueNativeEgress(context.Background(), runtimeIdentity, NativeEgressIssueRequest{
			ContractVersion: NativeEgressIdentityVersion, Binding: binding, Audience: NativeEgressAudience,
		})
		if binding == first && err != nil {
			t.Fatal(err)
		}
		if binding == second && nativeEgressFailureReason(err) != ReasonCapacity {
			t.Fatalf("binding capacity error=%v", err)
		}
	}
	if MaxNativeEgressIdentityBindings != MaxDurableEntries || MaxNativeEgressIdentityBindings <= 0 {
		t.Fatalf("invalid durable binding bound=%d", MaxNativeEgressIdentityBindings)
	}
}

func nativeEgressFailureReason(err error) FailureReason {
	reason, _ := FailureReasonOf(err)
	return reason
}
