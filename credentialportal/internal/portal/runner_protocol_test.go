package portal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

//nolint:govet // Test fixture fields mirror the runner contract for readability.
type scriptedCredentialRunner struct {
	document []byte
	action   providerAction
	wantCode string
	reason   string
}

type blockingCredentialRunner struct {
	started chan struct{}
	stopped chan struct{}
}

func (r blockingCredentialRunner) Acknowledge(_ context.Context, _ string) error { return nil }
func (r blockingCredentialRunner) Cancel(_ context.Context, _ string) error      { return nil }
func (r blockingCredentialRunner) Ready(_ context.Context) error                 { return nil }

func (r scriptedCredentialRunner) Acknowledge(_ context.Context, _ string) error { return nil }
func (r scriptedCredentialRunner) Cancel(_ context.Context, _ string) error      { return nil }
func (r scriptedCredentialRunner) Ready(_ context.Context) error                 { return nil }

func (r blockingCredentialRunner) Run(
	ctx context.Context,
	_, _ string,
	_ <-chan string,
	publish func(providerAction),
) ([]byte, string) {
	publish(providerAction{AuthorizationURL: fakeCodexDeviceURL, UserCode: fakeDeviceCode})
	close(r.started)
	<-ctx.Done()
	close(r.stopped)

	return nil, reasonTimeout
}

func (r scriptedCredentialRunner) Run(
	ctx context.Context,
	_, _ string,
	code <-chan string,
	publish func(providerAction),
) ([]byte, string) {
	publish(r.action)
	if r.wantCode != "" {
		select {
		case provided := <-code:
			if provided != r.wantCode {
				return nil, reasonProcessFailed
			}
		case <-ctx.Done():
			return nil, reasonTimeout
		}
	}
	if r.reason != "" {
		return nil, r.reason
	}

	return bytes.Clone(r.document), ""
}

func protocolManager(
	t *testing.T,
	adapter string,
	runner CredentialRunner,
) (*EnrollmentManager, *memoryPatcher, *httptest.Server, *RunnerServer) {
	t.Helper()
	cfg := testConfig()
	key := bytes.Repeat([]byte("k"), runnerKeyBytes)
	runnerServer, err := NewRunnerServer(key, cfg.Enrollment, runner)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(runnerServer)
	client, err := NewHTTPRunnerClient(server.URL, key, cfg.Enrollment.MaxOutputBytes)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	patcher := &memoryPatcher{value: []byte("old-secret")}
	manager := NewEnrollmentManager(cfg, patcher, NewAuditLogger(&bytes.Buffer{}), client)
	if _, ok := defaultEnrollmentAdapters()[adapter]; !ok {
		server.Close()
		t.Fatal("invalid test adapter")
	}

	return manager, patcher, server, runnerServer
}

func TestAuthenticatedRunnerProtocolCompletesExactBoundSlotWithoutSecretAuthority(t *testing.T) {
	runner := scriptedCredentialRunner{
		document: validClaude(fakeCLIAccess, fakeCLIRefresh),
		action: providerAction{
			AuthorizationURL: "https://claude.com/cai/oauth/authorize?state=runner-test",
			NeedsCode:        true,
		},
		wantCode: "fake-claude-callback-code",
	}
	manager, patcher, server, runnerServer := protocolManager(t, AdapterClaudeOAuthFile, runner)
	defer runnerServer.Close()
	defer server.Close()
	defer manager.Close()
	principal := Principal{Issuer: testIdentityIssuer, Subject: testBobSubject}
	initial, err := manager.Start(t.Context(), principal, testConfig().Slots[1], time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	action := waitEnrollmentStatus(t, manager, principal, initial.ID, enrollmentActionRequired, enrollmentFailed)
	if action.Status == enrollmentFailed {
		t.Fatalf("runner protocol failed before action: %s", action.Reason)
	}
	if action.AuthorizationURL != runner.action.AuthorizationURL || !action.NeedsCode {
		t.Fatal("authenticated runner action handoff changed")
	}
	if err := manager.ProvideCode(principal, initial.ID, runner.wantCode); err != nil {
		t.Fatal(err)
	}
	if err := manager.ProvideCode(principal, initial.ID, "replay"); !errors.Is(err, ErrEnrollmentState) {
		t.Fatal("one-time provider code was replayable")
	}
	waitEnrollmentStatus(t, manager, principal, initial.ID, enrollmentSucceeded)
	if patcher.calls != 1 || patcher.name != testPortalSeed || patcher.key != testClaudeCredentialKey ||
		ValidateCredential(AdapterClaudeOAuthFile, patcher.value) != nil {
		t.Fatal("portal did not validate and patch the exact owner-bound destination")
	}
	runnerServer.mu.Lock()
	_, retained := runnerServer.sessions[initial.ID]
	_, acknowledged := runnerServer.ackedIDs[initial.ID]
	runnerServer.mu.Unlock()
	if retained || !acknowledged {
		t.Fatal("portal did not acknowledge the result after the exact Secret patch")
	}
}

//nolint:gocyclo // This protocol security test keeps unsigned, authenticated, and replay attempts together.
func TestRunnerProtocolRejectsUnsignedAndReplayedRequests(t *testing.T) {
	cfg := testConfig()
	key := bytes.Repeat([]byte("a"), runnerKeyBytes)
	runnerServer, err := NewRunnerServer(
		key,
		cfg.Enrollment,
		scriptedCredentialRunner{reason: reasonProcessFailed},
	)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(runnerServer)
	defer server.Close()
	defer runnerServer.Close()
	client, err := NewHTTPRunnerClient(server.URL, key, cfg.Enrollment.MaxOutputBytes)
	if err != nil {
		t.Fatal(err)
	}
	if readyErr := client.Ready(t.Context()); readyErr != nil {
		t.Fatal("authenticated runner readiness failed")
	}
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	path := "/v1/sessions/" + id
	body, err := json.Marshal(runnerStartRequest{
		Adapter: AdapterClaudeOAuthFile, ExpiresAt: time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	unsignedResponse, err := http.DefaultClient.Do(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if closeErr := unsignedResponse.Body.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if unsignedResponse.StatusCode != http.StatusUnauthorized {
		t.Fatal("runner accepted an unauthenticated request")
	}
	first, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if signErr := signRunnerRequest(first, body, key, time.Now()); signErr != nil {
		t.Fatal(signErr)
	}
	second, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	second.Header = first.Header.Clone()
	firstResponse, err := http.DefaultClient.Do(first)
	if err != nil {
		t.Fatal(err)
	}
	if closeErr := firstResponse.Body.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if firstResponse.StatusCode != http.StatusAccepted {
		t.Fatal("runner rejected the first authenticated request")
	}
	secondResponse, err := http.DefaultClient.Do(second)
	if err != nil {
		t.Fatal(err)
	}
	if err := secondResponse.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if secondResponse.StatusCode != http.StatusUnauthorized {
		t.Fatal("runner accepted a replayed protocol request")
	}
}

func TestRunnerProtocolCancellationWaitsForRunnerCleanup(t *testing.T) {
	runner := blockingCredentialRunner{started: make(chan struct{}), stopped: make(chan struct{})}
	manager, patcher, server, runnerServer := protocolManager(t, AdapterCodexOAuthFile, runner)
	defer runnerServer.Close()
	defer server.Close()
	defer manager.Close()
	principal := Principal{Issuer: testIdentityIssuer, Subject: testAliceSubject}
	initial, err := manager.Start(t.Context(), principal, testConfig().Slots[0], time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	waitEnrollmentStatus(t, manager, principal, initial.ID, enrollmentActionRequired)
	<-runner.started
	if err := manager.Cancel(principal, initial.ID); err != nil {
		t.Fatal(err)
	}
	waitEnrollmentStatus(t, manager, principal, initial.ID, enrollmentCancelled)
	select {
	case <-runner.stopped:
	default:
		t.Fatal("terminal cancellation became visible before runner cleanup")
	}
	if patcher.calls != 0 {
		t.Fatal("cancelled runner patched a Secret")
	}
	runnerServer.mu.Lock()
	remaining := len(runnerServer.sessions)
	runnerServer.mu.Unlock()
	if remaining != 0 {
		t.Fatal("cancelled protocol session retained runner capacity")
	}
}

func TestSecretPatchFailureCancelsRetainedRunnerResult(t *testing.T) {
	runner := scriptedCredentialRunner{
		document: validCodex(fakeCLIAccess, fakeCLIRefresh),
		action:   providerAction{AuthorizationURL: fakeCodexDeviceURL, UserCode: fakeDeviceCode},
	}
	manager, patcher, server, runnerServer := protocolManager(t, AdapterCodexOAuthFile, runner)
	defer runnerServer.Close()
	defer server.Close()
	defer manager.Close()
	patcher.err = errTestAPI
	principal := Principal{Issuer: testIdentityIssuer, Subject: testAliceSubject}
	initial, err := manager.Start(t.Context(), principal, testConfig().Slots[0], time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	failed := waitEnrollmentStatus(t, manager, principal, initial.ID, enrollmentFailed)
	if failed.Reason != reasonSecretUpdateFailed {
		t.Fatal("Secret patch failure returned the wrong sanitized reason")
	}
	runnerServer.mu.Lock()
	remaining := len(runnerServer.sessions)
	runnerServer.mu.Unlock()
	if remaining != 0 {
		t.Fatal("Secret patch failure retained a runner result")
	}
}

func TestRunnerResultRemainsRetrievableUntilIdempotentAcknowledgment(t *testing.T) {
	cfg := testConfig()
	key := bytes.Repeat([]byte("r"), runnerKeyBytes)
	runnerServer, err := NewRunnerServer(
		key,
		cfg.Enrollment,
		scriptedCredentialRunner{
			document: validCodex(fakeCLIAccess, fakeCLIRefresh),
			action: providerAction{
				AuthorizationURL: fakeCodexDeviceURL,
				UserCode:         fakeDeviceCode,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(runnerServer)
	defer server.Close()
	defer runnerServer.Close()
	client, err := NewHTTPRunnerClient(server.URL, key, cfg.Enrollment.MaxOutputBytes)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("b", 43)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	document, reason := client.Run(ctx, id, AdapterCodexOAuthFile, nil, func(providerAction) {})
	if reason != "" || ValidateCredential(AdapterCodexOAuthFile, document) != nil {
		t.Fatal("runner did not return a valid retained result")
	}
	defer clearBytes(document)
	second, err := client.request(ctx, http.MethodGet, "/v1/sessions/"+id, nil)
	if err != nil || !bytes.Equal(document, second.Document) {
		t.Fatal("unacknowledged runner result was not retrievable")
	}
	clearBytes(second.Document)
	runnerServer.mu.Lock()
	retained := runnerServer.sessions[id].document
	runnerServer.mu.Unlock()
	if err := client.Acknowledge(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := client.Acknowledge(ctx, id); err != nil {
		t.Fatal("idempotent acknowledgment was rejected")
	}
	runnerServer.mu.Lock()
	_, exists := runnerServer.sessions[id]
	runnerServer.mu.Unlock()
	if exists || !allZero(retained) {
		t.Fatal("acknowledged result remained retained or was not wiped")
	}
}

//nolint:gocyclo // This lifecycle regression intentionally crosses the session limit through expiry and cancellation.
func TestRunnerCancellationAndExpiryReclaimCapacityAndWipeResults(t *testing.T) {
	cfg := testConfig()
	cfg.Enrollment.MaxSessions = 2
	cfg.Enrollment.MaxConcurrent = 2
	key := bytes.Repeat([]byte("c"), runnerKeyBytes)
	runnerServer, err := NewRunnerServer(
		key,
		cfg.Enrollment,
		scriptedCredentialRunner{
			document: validCodex(fakeCLIAccess, fakeCLIRefresh),
			action: providerAction{
				AuthorizationURL: fakeCodexDeviceURL,
				UserCode:         fakeDeviceCode,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(runnerServer)
	defer server.Close()
	defer runnerServer.Close()
	client, err := NewHTTPRunnerClient(server.URL, key, cfg.Enrollment.MaxOutputBytes)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	ids := []string{strings.Repeat("d", 43), strings.Repeat("e", 43)}
	for _, id := range ids {
		document, reason := client.Run(ctx, id, AdapterCodexOAuthFile, nil, func(providerAction) {})
		clearBytes(document)
		if reason != "" {
			t.Fatal("failed to retain a result near the session limit")
		}
	}
	runnerServer.mu.Lock()
	first := runnerServer.sessions[ids[0]]
	firstBytes := first.document
	if len(runnerServer.sessions) != cfg.Enrollment.MaxSessions {
		runnerServer.mu.Unlock()
		t.Fatal("test did not reach the runner session limit")
	}
	first.timer.Stop()
	first.expiresAt = time.Now().Add(20 * time.Millisecond)
	first.timer = time.AfterFunc(20*time.Millisecond, func() { runnerServer.expire(ids[0], first) })
	runnerServer.mu.Unlock()
	expiryDeadline := time.Now().Add(time.Second)
	for {
		runnerServer.mu.Lock()
		_, retained := runnerServer.sessions[ids[0]]
		runnerServer.mu.Unlock()
		if !retained {
			break
		}
		if time.Now().After(expiryDeadline) {
			t.Fatal("abandoned runner result did not expire")
		}
		time.Sleep(time.Millisecond)
	}
	if !allZero(firstBytes) {
		t.Fatal("expired unacknowledged credential bytes were not wiped")
	}
	replacementID := strings.Repeat("f", 43)
	document, reason := client.Run(ctx, replacementID, AdapterCodexOAuthFile, nil, func(providerAction) {})
	clearBytes(document)
	if reason != "" {
		t.Fatal("expired session capacity was not reclaimed")
	}
	if err := client.Cancel(ctx, replacementID); err != nil {
		t.Fatal(err)
	}
	if err := client.Cancel(ctx, ids[1]); err != nil {
		t.Fatal(err)
	}
	runnerServer.mu.Lock()
	remaining := len(runnerServer.sessions)
	runnerServer.mu.Unlock()
	if remaining != 0 {
		t.Fatal("cancelled sessions were not removed after cleanup")
	}
	for index := range cfg.Enrollment.MaxSessions + 2 {
		id := fmt.Sprintf("cancelled-session-%024d", index)
		document, runReason := client.Run(ctx, id, AdapterCodexOAuthFile, nil, func(providerAction) {})
		clearBytes(document)
		if runReason != "" {
			t.Fatal("repeated cancellation exhausted runner session capacity")
		}
		if err := client.Cancel(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHTTPRunnerClientCancelsRemoteSessionAfterPostStartFailure(t *testing.T) {
	cancelled := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.Method {
		case http.MethodPost:
			writeRunnerJSON(response, http.StatusAccepted, runnerResponse{Status: runnerStatusRunning})
		case http.MethodGet:
			panic(http.ErrAbortHandler)
		case http.MethodDelete:
			cancelled <- struct{}{}
			writeRunnerJSON(response, http.StatusOK, runnerResponse{Status: runnerStatusRunning})
		}
	}))
	defer server.Close()
	client, err := NewHTTPRunnerClient(server.URL, bytes.Repeat([]byte("x"), runnerKeyBytes), 4096)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	_, reason := client.Run(
		ctx,
		strings.Repeat("g", 43),
		AdapterCodexOAuthFile,
		nil,
		func(providerAction) {},
	)
	if reason != reasonRunnerUnavailable {
		t.Fatal("post-start protocol failure did not fail closed")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("post-start protocol failure did not cancel the remote session")
	}
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}

	return true
}
