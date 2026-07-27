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

const maxFakeRecords = 64

type fakeRecord struct {
	TokenDigest           string         `json:"token_digest"`
	Binding               Binding        `json:"binding"`
	IssuedAt              string         `json:"issued_at"`
	ExpiresAt             string         `json:"expires_at"`
	State                 LifecycleState `json:"state"`
	RuntimeIdentityDigest string         `json:"runtime_identity_digest,omitempty"`
	RuntimeIdentityActive bool           `json:"runtime_identity_active,omitempty"`
}

type fakeDurableStore struct {
	mu              sync.Mutex
	records         map[string]fakeRecord
	revokedBindings map[Binding]struct{}
}

type fakeIssuer struct {
	store          *fakeDurableStore
	now            func() time.Time
	random         io.Reader
	identity       func(Binding, time.Time) (RuntimeIdentity, error)
	diagnosticSink func(string)
}

type fakeGuest struct {
	binding Binding
	issuer  Issuer
}

func (guest fakeGuest) bootstrap(ctx context.Context, encodedEnvelope []byte) (ExchangeResult, error) {
	envelope, err := DecodeBootstrapEnvelope(encodedEnvelope)
	if err != nil {
		return ExchangeResult{}, err
	}
	if envelope.Binding != guest.binding {
		return ExchangeResult{}, NewFailure(ReasonBindingMismatch)
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
	return &fakeIssuer{store: store, now: now, random: random, identity: identity, diagnosticSink: func(string) {}}
}

func (issuer *fakeIssuer) Issue(ctx context.Context, request IssueRequest) (BootstrapEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return BootstrapEnvelope{}, err
	}
	if err := ValidateIssueRequest(request); err != nil {
		issuer.diagnosticSink("issue invalid-request")
		return BootstrapEnvelope{}, err
	}
	now := issuer.now().UTC().Truncate(time.Second)
	issuer.store.mu.Lock()
	defer issuer.store.mu.Unlock()
	if len(issuer.store.records) >= maxFakeRecords {
		return BootstrapEnvelope{}, NewFailure(ReasonCapacity)
	}
	if _, revoked := issuer.store.revokedBindings[request.Binding]; revoked {
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
		ContractVersion: Version, Binding: request.Binding, IssuerURL: request.IssuerURL, Token: token,
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
	issuer.store.mu.Lock()
	defer issuer.store.mu.Unlock()
	record, found := issuer.store.records[digest]
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
	if !issuer.now().Before(expires) {
		record.State = StateExpired
		issuer.store.records[digest] = record
		return ExchangeResult{}, NewFailure(ReasonExpired)
	}
	if record.Binding != request.Binding {
		return ExchangeResult{}, NewFailure(ReasonBindingMismatch)
	}
	identity, err := issuer.identity(record.Binding, issuer.now().UTC().Truncate(time.Second))
	if err != nil || ValidateExchangeResult(ExchangeResult{ContractVersion: Version, Binding: record.Binding, RuntimeIdentity: identity}) != nil {
		return ExchangeResult{}, NewFailure(ReasonIdentityFailure)
	}
	record.State = StateConsumed
	identityDigest := sha256.Sum256([]byte(identity.Opaque))
	record.RuntimeIdentityDigest = "sha256:" + hex.EncodeToString(identityDigest[:])
	record.RuntimeIdentityActive = true
	issuer.store.records[digest] = record
	return ExchangeResult{ContractVersion: Version, Binding: record.Binding, RuntimeIdentity: identity}, nil
}

func (issuer *fakeIssuer) Revoke(ctx context.Context, request RevokeRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateRevokeRequest(request); err != nil {
		return err
	}
	issuer.store.mu.Lock()
	defer issuer.store.mu.Unlock()
	if issuer.store.revokedBindings == nil {
		issuer.store.revokedBindings = make(map[Binding]struct{})
	}
	issuer.store.revokedBindings[request.Binding] = struct{}{}
	for digest, record := range issuer.store.records {
		if record.Binding == request.Binding {
			record.State = StateRevoked
			record.RuntimeIdentityActive = false
			issuer.store.records[digest] = record
		}
	}
	return nil
}

func (store *fakeDurableStore) snapshot() []byte {
	store.mu.Lock()
	defer store.mu.Unlock()
	revoked := make([]Binding, 0, len(store.revokedBindings))
	for binding := range store.revokedBindings {
		revoked = append(revoked, binding)
	}
	encoded, _ := json.Marshal(struct {
		Records map[string]fakeRecord `json:"records"`
		Revoked []Binding             `json:"revoked_bindings"`
	}{Records: store.records, Revoked: revoked})
	return encoded
}

func (store *fakeDurableStore) state(token string) LifecycleState {
	digest, _ := TokenDigest(token)
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.records[digest].State
}

func (store *fakeDurableStore) runtimeIdentityActive(token string) bool {
	digest, _ := TokenDigest(token)
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.records[digest].RuntimeIdentityActive
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
	result, err := (fakeGuest{binding: request.Binding, issuer: issuerAfterRestart}).bootstrap(context.Background(), encodedEnvelope)
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
	if err := issuerAfterRestart.Revoke(context.Background(), RevokeRequest{ContractVersion: Version, Binding: request.Binding}); err != nil {
		t.Fatalf("revoke consumed enrollment: %v", err)
	}
	if store.runtimeIdentityActive(envelope.Token) {
		t.Fatal("revocation left the runtime identity active")
	}
	if _, err := issuerAfterRestart.Exchange(context.Background(), ExchangeRequest{ContractVersion: Version, Binding: request.Binding, Token: envelope.Token}); failureReason(t, err) != ReasonRevoked {
		t.Fatalf("exchange after runtime-identity revocation: %v", err)
	}
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
	if err := issuer.Revoke(context.Background(), RevokeRequest{ContractVersion: Version, Binding: wrong}); err != nil {
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
		if err := issuer.Revoke(context.Background(), RevokeRequest{ContractVersion: Version, Binding: revoked.Binding}); err != nil {
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
	for index := 0; index < maxFakeRecords; index++ {
		full.records[fmt.Sprintf("sha256:%064x", index)] = fakeRecord{Binding: Binding{GuestInstanceID: fmt.Sprintf("guest-%d", index)}, State: StateExpired}
	}
	capacityIssuer := newFakeIssuer(full, func() time.Time { return now }, deterministicRandom(10), validIdentityFactory(0x91))
	if _, err := capacityIssuer.Issue(context.Background(), validIssueRequest()); failureReason(t, err) != ReasonCapacity {
		t.Fatalf("capacity error: %v", err)
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
	if err := issuer.Revoke(context.Background(), RevokeRequest{ContractVersion: Version, Binding: request.Binding}); err != nil {
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
	return IssueRequest{ContractVersion: Version, Binding: validBinding(), IssuerURL: "https://enrollment.nvt-system.svc/v1/guest-enrollment/exchange", TTLSeconds: 300}
}

func deterministicRandom(value byte) io.Reader {
	var data []byte
	for offset := 0; offset < maxFakeRecords+2; offset++ {
		data = append(data, bytes.Repeat([]byte{value + byte(offset)}, TokenBytes)...)
	}
	return bytes.NewReader(data)
}

func validIdentityFactory(value byte) func(Binding, time.Time) (RuntimeIdentity, error) {
	return func(_ Binding, issued time.Time) (RuntimeIdentity, error) {
		return RuntimeIdentity{Type: RuntimeIdentityType, Opaque: opaqueValue(TokenBytes, value), IssuedAt: FormatTimestamp(issued), ExpiresAt: FormatTimestamp(issued.Add(time.Hour))}, nil
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
