package portal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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

func (r blockingCredentialRunner) Run(
	ctx context.Context,
	_, _ string,
	_ <-chan string,
	publish func(providerAction),
) ([]byte, string) {
	publish(providerAction{AuthorizationURL: "https://auth.openai.com/codex/device", UserCode: "ABCD-EFGH"})
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
) (*EnrollmentManager, *memoryPatcher, *httptest.Server) {
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

	return manager, patcher, server
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
	manager, patcher, server := protocolManager(t, AdapterClaudeOAuthFile, runner)
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
}

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
	manager, patcher, server := protocolManager(t, AdapterCodexOAuthFile, runner)
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
}
