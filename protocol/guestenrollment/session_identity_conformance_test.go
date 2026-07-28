package guestenrollment

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeGuestSessionRecord struct {
	Binding   Binding
	Digest    string
	Sequence  uint64
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type fakeGuestSessionStore struct {
	mu               sync.Mutex
	runtimeIdentity  string
	binding          Binding
	records          map[string]fakeGuestSessionRecord
	nextRandom       byte
	issuanceSequence uint64
	loseResponse     bool
	revoked          bool
}

type fakeGuestSessionAuthority struct {
	store *fakeGuestSessionStore
	now   func() time.Time
}

var _ GuestSessionAuthority = (*fakeGuestSessionAuthority)(nil)

func (authority *fakeGuestSessionAuthority) IssueGuestSession(_ context.Context, runtimeIdentity string, request GuestSessionIssueRequest) (GuestSessionIssueResult, error) {
	if ValidateGuestSessionIssueRequest(request) != nil {
		return GuestSessionIssueResult{}, NewFailure(ReasonInvalidRequest)
	}
	store := authority.store
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.revoked || runtimeIdentity != store.runtimeIdentity || request.Binding != store.binding {
		return GuestSessionIssueResult{}, NewFailure(ReasonUnauthorized)
	}
	now := authority.now()
	for digest, record := range store.records {
		if !now.Before(record.ExpiresAt) {
			delete(store.records, digest)
		}
	}
	if len(store.records) >= MaxLiveGuestSessionsPerBinding {
		return GuestSessionIssueResult{}, NewFailure(ReasonCapacity)
	}
	if store.issuanceSequence >= MaxGuestSessionIssuanceSequence {
		return GuestSessionIssueResult{}, NewFailure(ReasonCapacity)
	}
	store.issuanceSequence++
	store.nextRandom++
	credential, err := generateGuestSessionCredential(store.issuanceSequence, bytes.NewReader(bytes.Repeat([]byte{store.nextRandom}, GuestSessionCredentialRandomBytes)))
	if err != nil {
		return GuestSessionIssueResult{}, NewFailure(ReasonIdentityFailure)
	}
	digest, _ := GuestSessionCredentialDigest(credential)
	record := fakeGuestSessionRecord{
		Binding: request.Binding, Digest: digest, Sequence: store.issuanceSequence, IssuedAt: now,
		ExpiresAt: now.Add(MaxGuestSessionCredentialLifetime),
	}
	store.records[digest] = record
	if store.loseResponse {
		store.loseResponse = false
		return GuestSessionIssueResult{}, errors.New("response lost")
	}
	return guestSessionIssueResult(record, credential), nil
}

func (authority *fakeGuestSessionAuthority) AuthenticateGuestSession(_ context.Context, credential string, request GuestSessionAuthenticateRequest) (GuestSessionStatus, error) {
	if ValidateGuestSessionAuthenticateRequest(request) != nil {
		return GuestSessionStatus{}, NewFailure(ReasonInvalidRequest)
	}
	digest, err := GuestSessionCredentialDigest(credential)
	if err != nil {
		return GuestSessionStatus{}, NewFailure(ReasonUnauthorized)
	}
	store := authority.store
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[digest]
	if store.revoked || !ok || record.Binding != request.Binding || !authority.now().Before(record.ExpiresAt) {
		return GuestSessionStatus{}, NewFailure(ReasonUnauthorized)
	}
	return guestSessionStatus(record), nil
}

func (authority *fakeGuestSessionAuthority) revokeBinding(binding Binding) {
	authority.store.mu.Lock()
	defer authority.store.mu.Unlock()
	if authority.store.binding == binding {
		authority.store.revoked = true
		clear(authority.store.records)
	}
}

func guestSessionIssueResult(record fakeGuestSessionRecord, credential string) GuestSessionIssueResult {
	return GuestSessionIssueResult{
		ContractVersion: GuestSessionIdentityVersion,
		Binding:         record.Binding,
		Credential: GuestSessionCredential{
			Type: GuestSessionCredentialType, Opaque: credential, Audience: NativeGuestControlAudience,
			IssuedAt: FormatTimestamp(record.IssuedAt), ExpiresAt: FormatTimestamp(record.ExpiresAt),
		},
	}
}

func guestSessionStatus(record fakeGuestSessionRecord) GuestSessionStatus {
	return GuestSessionStatus{
		ContractVersion: GuestSessionIdentityVersion, CredentialType: GuestSessionCredentialType,
		Binding: record.Binding, Audience: NativeGuestControlAudience,
		IssuedAt: FormatTimestamp(record.IssuedAt), ExpiresAt: FormatTimestamp(record.ExpiresAt),
	}
}

func guestSessionCredentialSequence(t *testing.T, credential string) uint64 {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(credential)
	if err != nil || len(decoded) != GuestSessionCredentialBytes {
		t.Fatalf("decode guest session credential: %v", err)
	}
	return binary.BigEndian.Uint64(decoded[:8])
}

func TestGuestSessionIdentityConformance(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	binding := validBinding()
	store := &fakeGuestSessionStore{
		runtimeIdentity: opaqueValue(RuntimeIdentityBytes, 0x61),
		binding:         binding,
		records:         map[string]fakeGuestSessionRecord{},
		nextRandom:      0x70,
	}
	newAuthority := func() *fakeGuestSessionAuthority {
		return &fakeGuestSessionAuthority{store: store, now: func() time.Time { return now }}
	}
	issue := GuestSessionIssueRequest{ContractVersion: GuestSessionIdentityVersion, Binding: binding, Audience: NativeGuestControlAudience}
	auth := GuestSessionAuthenticateRequest{ContractVersion: GuestSessionIdentityVersion, Binding: binding, Audience: NativeGuestControlAudience}

	first, err := newAuthority().IssueGuestSession(context.Background(), store.runtimeIdentity, issue)
	if err != nil || ValidateGuestSessionIssueResult(first) != nil {
		t.Fatalf("first issue: %#v %v", first, err)
	}
	if got := guestSessionCredentialSequence(t, first.Credential.Opaque); got != 1 {
		t.Fatalf("first issuance sequence = %d, want 1", got)
	}
	if _, err := newAuthority().AuthenticateGuestSession(context.Background(), first.Credential.Opaque, auth); err != nil {
		t.Fatalf("authenticate after restart: %v", err)
	}

	store.loseResponse = true
	if _, err := newAuthority().IssueGuestSession(context.Background(), store.runtimeIdentity, issue); err == nil {
		t.Fatal("lost response was not surfaced")
	}
	if len(store.records) != MaxLiveGuestSessionsPerBinding {
		t.Fatalf("lost response durable records = %d", len(store.records))
	}
	if _, err := newAuthority().IssueGuestSession(context.Background(), store.runtimeIdentity, issue); failureReason(t, err) != ReasonCapacity {
		t.Fatalf("unbounded reissue reason = %v", err)
	}

	wrong := auth
	wrong.Binding.GuestInstanceID = "wrong"
	if _, err := newAuthority().AuthenticateGuestSession(context.Background(), first.Credential.Opaque, wrong); failureReason(t, err) != ReasonUnauthorized {
		t.Fatalf("wrong binding reason = %v", err)
	}
	wrongAudience := auth
	wrongAudience.Audience = "caller-selected"
	if _, err := newAuthority().AuthenticateGuestSession(context.Background(), first.Credential.Opaque, wrongAudience); failureReason(t, err) != ReasonInvalidRequest {
		t.Fatalf("wrong audience reason = %v", err)
	}

	now = now.Add(MaxGuestSessionCredentialLifetime)
	if _, err := newAuthority().AuthenticateGuestSession(context.Background(), first.Credential.Opaque, auth); failureReason(t, err) != ReasonUnauthorized {
		t.Fatalf("expired credential reason = %v", err)
	}
	reissued, err := newAuthority().IssueGuestSession(context.Background(), store.runtimeIdentity, issue)
	if err != nil {
		t.Fatalf("issue after expiry: %v", err)
	}
	if reissued.Credential.Opaque == first.Credential.Opaque {
		t.Fatal("expired credential was revived")
	}

	authority := newAuthority()
	authority.revokeBinding(binding)
	if _, err := newAuthority().AuthenticateGuestSession(context.Background(), reissued.Credential.Opaque, auth); failureReason(t, err) != ReasonUnauthorized {
		t.Fatalf("revoked credential reason = %v", err)
	}
	if _, err := newAuthority().IssueGuestSession(context.Background(), store.runtimeIdentity, issue); failureReason(t, err) != ReasonUnauthorized {
		t.Fatalf("revoked issuance reason = %v", err)
	}
}

func TestGuestSessionFirstResponseLossAllowsOneBoundedRecovery(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	binding := validBinding()
	store := &fakeGuestSessionStore{
		runtimeIdentity: opaqueValue(RuntimeIdentityBytes, 0x63),
		binding:         binding,
		records:         map[string]fakeGuestSessionRecord{},
		nextRandom:      0x20,
		loseResponse:    true,
	}
	newAuthority := func() *fakeGuestSessionAuthority {
		return &fakeGuestSessionAuthority{store: store, now: func() time.Time { return now }}
	}
	issue := GuestSessionIssueRequest{ContractVersion: GuestSessionIdentityVersion, Binding: binding, Audience: NativeGuestControlAudience}
	auth := GuestSessionAuthenticateRequest{ContractVersion: GuestSessionIdentityVersion, Binding: binding, Audience: NativeGuestControlAudience}

	if _, err := newAuthority().IssueGuestSession(context.Background(), store.runtimeIdentity, issue); err == nil {
		t.Fatal("first committed response loss was not surfaced")
	}
	if len(store.records) != 1 || store.issuanceSequence != 1 {
		t.Fatalf("first response loss records=%d sequence=%d", len(store.records), store.issuanceSequence)
	}
	recovered, err := newAuthority().IssueGuestSession(context.Background(), store.runtimeIdentity, issue)
	if err != nil {
		t.Fatalf("bounded recovery issue: %v", err)
	}
	if got := guestSessionCredentialSequence(t, recovered.Credential.Opaque); got != 2 {
		t.Fatalf("recovery issuance sequence = %d, want 2", got)
	}
	if _, err := newAuthority().AuthenticateGuestSession(context.Background(), recovered.Credential.Opaque, auth); err != nil {
		t.Fatalf("authenticate recovered credential: %v", err)
	}
	if len(store.records) != MaxLiveGuestSessionsPerBinding {
		t.Fatalf("recovery records = %d", len(store.records))
	}
	if _, err := newAuthority().IssueGuestSession(context.Background(), store.runtimeIdentity, issue); failureReason(t, err) != ReasonCapacity {
		t.Fatalf("third issue reason = %v", err)
	}
}

func TestGuestSessionConcurrentIssuanceIsDurablyBounded(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	binding := validBinding()
	store := &fakeGuestSessionStore{runtimeIdentity: opaqueValue(RuntimeIdentityBytes, 0x62), binding: binding, records: map[string]fakeGuestSessionRecord{}, nextRandom: 0x10}
	authority := &fakeGuestSessionAuthority{store: store, now: func() time.Time { return now }}
	request := GuestSessionIssueRequest{ContractVersion: GuestSessionIdentityVersion, Binding: binding, Audience: NativeGuestControlAudience}

	var wg sync.WaitGroup
	results := make(chan error, 16)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := authority.IssueGuestSession(context.Background(), store.runtimeIdentity, request)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		} else if failureReason(t, err) != ReasonCapacity {
			t.Fatalf("unexpected concurrent error %v", err)
		}
	}
	if succeeded != MaxLiveGuestSessionsPerBinding || len(store.records) != MaxLiveGuestSessionsPerBinding {
		t.Fatalf("success=%d records=%d", succeeded, len(store.records))
	}
}
