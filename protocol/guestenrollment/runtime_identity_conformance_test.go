package guestenrollment

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type runtimeIdentityRecord struct {
	Digest    string
	Binding   Binding
	IssuedAt  time.Time
	ExpiresAt time.Time
	Active    bool
}

type runtimeIdentityStore struct {
	mu      sync.Mutex
	record  runtimeIdentityRecord
	history map[string]struct{}
}

type fakeRuntimeIdentityAuthority struct {
	store            *runtimeIdentityStore
	now              func() time.Time
	loseNextResponse bool
}

var _ RuntimeIdentityAuthority = (*fakeRuntimeIdentityAuthority)(nil)

func (authority *fakeRuntimeIdentityAuthority) Authenticate(_ context.Context, identity string, request RuntimeIdentityStatusRequest) (RuntimeIdentityStatus, error) {
	if ValidateRuntimeIdentityStatusRequest(request) != nil {
		return RuntimeIdentityStatus{}, NewFailure(ReasonInvalidRequest)
	}
	digest, err := RuntimeIdentityDigest(identity)
	if err != nil {
		return RuntimeIdentityStatus{}, NewFailure(ReasonUnauthorized)
	}
	authority.store.mu.Lock()
	defer authority.store.mu.Unlock()
	return authority.statusLocked(digest, request.Binding)
}

func (authority *fakeRuntimeIdentityAuthority) Rotate(_ context.Context, identity string, request RuntimeIdentityRotateRequest) (RuntimeIdentityStatus, error) {
	if ValidateRuntimeIdentityRotateRequest(request) != nil {
		return RuntimeIdentityStatus{}, NewFailure(ReasonInvalidRequest)
	}
	currentDigest, err := RuntimeIdentityDigest(identity)
	if err != nil {
		return RuntimeIdentityStatus{}, NewFailure(ReasonUnauthorized)
	}
	successorDigest, err := RuntimeIdentityDigest(request.Successor)
	if err != nil || successorDigest == currentDigest {
		return RuntimeIdentityStatus{}, NewFailure(ReasonInvalidRequest)
	}
	authority.store.mu.Lock()
	defer authority.store.mu.Unlock()
	if _, err := authority.statusLocked(currentDigest, request.Binding); err != nil {
		return RuntimeIdentityStatus{}, err
	}
	if _, reused := authority.store.history[successorDigest]; reused {
		return RuntimeIdentityStatus{}, NewFailure(ReasonInvalidRequest)
	}
	if len(authority.store.history) >= MaxRuntimeIdentityHistoryPerEnrollment {
		return RuntimeIdentityStatus{}, NewFailure(ReasonCapacity)
	}
	now := authority.now().UTC().Truncate(time.Second)
	if now.Before(authority.store.record.IssuedAt) {
		now = authority.store.record.IssuedAt
	}
	authority.store.history[currentDigest] = struct{}{}
	authority.store.record.Digest = successorDigest
	authority.store.record.IssuedAt = now
	authority.store.record.ExpiresAt = now.Add(time.Hour)
	status, err := authority.statusLocked(successorDigest, request.Binding)
	if authority.loseNextResponse {
		authority.loseNextResponse = false
		return RuntimeIdentityStatus{}, errors.New("response lost")
	}
	return status, err
}

func (authority *fakeRuntimeIdentityAuthority) statusLocked(digest string, binding Binding) (RuntimeIdentityStatus, error) {
	record := authority.store.record
	if !record.Active || record.Digest != digest || record.Binding != binding || !authority.now().Before(record.ExpiresAt) {
		return RuntimeIdentityStatus{}, NewFailure(ReasonUnauthorized)
	}
	return RuntimeIdentityStatus{
		ContractVersion: RuntimeIdentityVersion,
		IdentityType:    RuntimeIdentityType,
		Binding:         binding,
		IssuedAt:        FormatTimestamp(record.IssuedAt),
		ExpiresAt:       FormatTimestamp(record.ExpiresAt),
	}, nil
}

func TestRuntimeIdentityRotationConformance(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	clock := now
	binding := validBinding()
	initial, _ := generateRuntimeIdentity(bytes.NewReader(bytes.Repeat([]byte{0x31}, RuntimeIdentityBytes)))
	initialDigest, _ := RuntimeIdentityDigest(initial)
	store := &runtimeIdentityStore{record: runtimeIdentityRecord{
		Digest: initialDigest, Binding: binding, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Active: true,
	}, history: make(map[string]struct{})}
	newAuthority := func() *fakeRuntimeIdentityAuthority {
		return &fakeRuntimeIdentityAuthority{store: store, now: func() time.Time { return clock }}
	}
	authority := newAuthority()
	statusRequest := RuntimeIdentityStatusRequest{ContractVersion: RuntimeIdentityVersion, Binding: binding}
	if _, err := authority.Authenticate(context.Background(), initial, statusRequest); err != nil {
		t.Fatalf("initial status: %v", err)
	}

	first, _ := generateRuntimeIdentity(bytes.NewReader(bytes.Repeat([]byte{0x32}, RuntimeIdentityBytes)))
	if _, err := authority.Rotate(context.Background(), initial, RuntimeIdentityRotateRequest{ContractVersion: RuntimeIdentityVersion, Binding: binding, Successor: first}); err != nil {
		t.Fatalf("first rotation: %v", err)
	}
	if _, err := authority.Authenticate(context.Background(), initial, statusRequest); runtimeFailureReason(err) != ReasonUnauthorized {
		t.Fatalf("predecessor status error = %v", err)
	}
	if _, err := newAuthority().Authenticate(context.Background(), first, statusRequest); err != nil {
		t.Fatalf("status after restart: %v", err)
	}
	if _, err := newAuthority().Rotate(context.Background(), first, RuntimeIdentityRotateRequest{ContractVersion: RuntimeIdentityVersion, Binding: binding, Successor: initial}); runtimeFailureReason(err) != ReasonInvalidRequest {
		t.Fatalf("historical predecessor reuse error = %v", err)
	}

	wrong := statusRequest
	wrong.Binding.GuestInstanceID = "wrong-guest"
	if _, err := authority.Authenticate(context.Background(), first, wrong); runtimeFailureReason(err) != ReasonUnauthorized {
		t.Fatalf("wrong binding error = %v", err)
	}

	second, _ := generateRuntimeIdentity(bytes.NewReader(bytes.Repeat([]byte{0x33}, RuntimeIdentityBytes)))
	third, _ := generateRuntimeIdentity(bytes.NewReader(bytes.Repeat([]byte{0x34}, RuntimeIdentityBytes)))
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, successor := range []string{second, third} {
		go func(successor string) {
			<-start
			_, err := authority.Rotate(context.Background(), first, RuntimeIdentityRotateRequest{ContractVersion: RuntimeIdentityVersion, Binding: binding, Successor: successor})
			results <- err
		}(successor)
	}
	close(start)
	successes := 0
	unauthorized := 0
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else if runtimeFailureReason(err) == ReasonUnauthorized {
			unauthorized++
		}
	}
	if successes != 1 || unauthorized != 1 {
		t.Fatalf("CAS outcomes success=%d unauthorized=%d", successes, unauthorized)
	}

	active := second
	if _, err := authority.Authenticate(context.Background(), second, statusRequest); err != nil {
		active = third
	}
	proposed, _ := generateRuntimeIdentity(bytes.NewReader(bytes.Repeat([]byte{0x35}, RuntimeIdentityBytes)))
	authority.loseNextResponse = true
	if _, err := authority.Rotate(context.Background(), active, RuntimeIdentityRotateRequest{ContractVersion: RuntimeIdentityVersion, Binding: binding, Successor: proposed}); err == nil {
		t.Fatal("lost response was not surfaced")
	}
	// Recovery never generates a second candidate: authenticate the already
	// known proposal first, then discard the predecessor only after success.
	if _, err := newAuthority().Authenticate(context.Background(), proposed, statusRequest); err != nil {
		t.Fatalf("ambiguous response recovery: %v", err)
	}

	clock = now.Add(2 * time.Hour)
	if _, err := authority.Authenticate(context.Background(), proposed, statusRequest); runtimeFailureReason(err) != ReasonUnauthorized {
		t.Fatalf("expired identity error = %v", err)
	}
	store.mu.Lock()
	store.record.Active = false // execution-scope revocation after restart
	store.record = runtimeIdentityRecord{}
	store.history = make(map[string]struct{})
	store.mu.Unlock()
	if _, err := newAuthority().Authenticate(context.Background(), proposed, statusRequest); runtimeFailureReason(err) != ReasonUnauthorized {
		t.Fatalf("revoked identity error = %v", err)
	}
	store.mu.Lock()
	if len(store.history) != 0 {
		t.Fatalf("revocation retained %d predecessor digests", len(store.history))
	}
	store.mu.Unlock()
}

func runtimeFailureReason(err error) FailureReason {
	reason, _ := FailureReasonOf(err)
	return reason
}
