package portal

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/mirkoSekulic/nvt-agent/protocol/eligibility"
)

const dynamicCredentialNeedle = "DYNAMIC-PORTAL-CREDENTIAL-NEEDLE"

//nolint:govet // Test record order mirrors the broker mutation interface.
type brokerMutation struct {
	Principal   Principal
	Template    string
	OperationID string
	Credential  []byte
	Action      string
}

type memoryPrincipalAccountBroker struct {
	accounts    map[string]DynamicAccountState
	readyErr    error
	accountErr  error
	mutationErr error
	mutations   []brokerMutation
	mu          sync.Mutex
}

func newMemoryPrincipalAccountBroker() *memoryPrincipalAccountBroker {
	return &memoryPrincipalAccountBroker{accounts: map[string]DynamicAccountState{}}
}

func principalMapKey(principal Principal) string {
	return principal.Issuer + "\x00" + principal.Subject
}

func (b *memoryPrincipalAccountBroker) Ready(_ context.Context) error { return b.readyErr }

func (b *memoryPrincipalAccountBroker) Account(
	_ context.Context,
	principal Principal,
) (DynamicAccountState, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.accountErr != nil {
		return DynamicAccountState{}, b.accountErr
	}
	state, ok := b.accounts[principalMapKey(principal)]
	if !ok {
		return DynamicAccountState{State: accountStateNotEnrolled}, nil
	}
	if state.State == accountStateUnready {
		return DynamicAccountState{State: accountStateUnready}, nil
	}
	return state, nil
}

func (b *memoryPrincipalAccountBroker) CompleteEnrollment(
	_ context.Context,
	principal Principal,
	template, operationID string,
	credential []byte,
) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.mutationErr != nil {
		return b.mutationErr
	}
	key := principalMapKey(principal)
	if current, ok := b.accounts[key]; ok && current.State != accountStateRevoked {
		return &brokerOperationError{reason: "account-already-enrolled"}
	}
	b.mutations = append(b.mutations, brokerMutation{
		Principal: principal, Template: template, OperationID: operationID,
		Credential: bytes.Clone(credential), Action: dynamicActionEnroll,
	})
	b.accounts[key] = DynamicAccountState{State: accountStateReady, Template: template, Generation: 1}
	return nil
}

func (b *memoryPrincipalAccountBroker) Reconnect(
	_ context.Context,
	principal Principal,
	operationID string,
	credential []byte,
) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.mutationErr != nil {
		return b.mutationErr
	}
	key := principalMapKey(principal)
	current, ok := b.accounts[key]
	if !ok || current.State == accountStateRevoked {
		return &brokerOperationError{reason: reasonAccountNotFound}
	}
	b.mutations = append(b.mutations, brokerMutation{
		Principal: principal, Template: current.Template, OperationID: operationID,
		Credential: bytes.Clone(credential), Action: dynamicActionReconnect,
	})
	if current.Generation < 1 {
		current.Generation = 1
	}
	current.State = accountStateReady
	current.Generation++
	b.accounts[key] = current
	return nil
}

func (b *memoryPrincipalAccountBroker) Revoke(
	_ context.Context,
	principal Principal,
	operationID string,
) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.mutationErr != nil {
		return b.mutationErr
	}
	key := principalMapKey(principal)
	current, ok := b.accounts[key]
	if !ok || current.State == accountStateRevoked {
		return &brokerOperationError{reason: reasonAccountNotFound}
	}
	b.mutations = append(b.mutations, brokerMutation{
		Principal: principal, Template: current.Template, OperationID: operationID, Action: "revoke",
	})
	current.State = accountStateRevoked
	b.accounts[key] = current
	return nil
}

type scriptedDynamicRunner struct {
	reason string
	calls  int
	acks   int
	mu     sync.Mutex
}

func (r *scriptedDynamicRunner) Run(
	ctx context.Context,
	_, adapter string,
	code <-chan string,
	publish func(providerAction),
) ([]byte, string) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	if r.reason != "" {
		return nil, r.reason
	}
	if adapter == AdapterClaudeOAuthFile {
		publish(providerAction{AuthorizationURL: "https://claude.com/cai/oauth/authorize", NeedsCode: true})
		select {
		case <-ctx.Done():
			return nil, reasonTimeout
		case <-code:
			return validClaude(dynamicCredentialNeedle, "refresh-needle"), ""
		}
	}
	publish(providerAction{AuthorizationURL: fakeCodexDeviceURL, UserCode: fakeDeviceCode})
	return validCodex(dynamicCredentialNeedle, "refresh-needle"), ""
}

func (r *scriptedDynamicRunner) Acknowledge(_ context.Context, _ string) error {
	r.mu.Lock()
	r.acks++
	r.mu.Unlock()
	return nil
}

func (r *scriptedDynamicRunner) Cancel(_ context.Context, _ string) error { return nil }
func (r *scriptedDynamicRunner) Ready(_ context.Context) error            { return nil }

func authenticatedDynamicServer(
	t *testing.T,
	principal Principal,
	broker PrincipalAccountBroker,
	runner CredentialRunner,
	recovery bool,
) (*Server, *http.Cookie, string, *bytes.Buffer) {
	t.Helper()
	cfg := testDynamicConfig()
	cfg.RecoveryUpload.Enabled = recovery
	sum := sha512.Sum512([]byte(strings.Repeat("d", 64)))
	cookies := securecookie.New(sum[:32], sum[32:])
	cookies.MaxAge(cfg.Auth.Session.MaxAgeSeconds)
	auth := &Authenticator{cfg: cfg, cookies: cookies, sessions: map[string]session{}, now: time.Now}
	csrf := testCSRFToken
	id := "dynamic-opaque-session"
	auth.sessions[id] = session{Principal: principal, CSRF: csrf, ExpiresAt: time.Now().Add(time.Hour)}
	encoded, err := cookies.Encode(cfg.Auth.Session.CookieName, id)
	if err != nil {
		t.Fatal(err)
	}
	audit := &bytes.Buffer{}
	server := NewServer(cfg, auth, nil, NewAuditLogger(audit), runner, broker)
	return server, &http.Cookie{Name: cfg.Auth.Session.CookieName, Value: encoded}, csrf, audit
}

func waitHTTPEnrollment(
	t *testing.T,
	server *Server,
	principal Principal,
	startedBody []byte,
) EnrollmentStatus {
	t.Helper()
	var started EnrollmentStatus
	if err := json.Unmarshal(startedBody, &started); err != nil || started.ID == "" {
		t.Fatal("dynamic enrollment did not return a bounded session identifier")
	}
	return waitEnrollmentStatus(t, server.enrollments, principal, started.ID, enrollmentSucceeded, enrollmentFailed)
}

//nolint:gocyclo // One end-to-end test deliberately verifies all custody and non-disclosure invariants together.
func TestDynamicEligibleUnknownPrincipalEnrollsAndReconnectsBeforeExpiryWithoutDisclosure(t *testing.T) {
	principal := Principal{Issuer: testIdentityIssuer, Subject: "new-dynamic-user", DisplayName: "New user"}
	broker := newMemoryPrincipalAccountBroker()
	runner := &scriptedDynamicRunner{}
	server, cookie, csrf, audit := authenticatedDynamicServer(t, principal, broker, runner, false)
	defer server.Close()

	dashboard := request(t, server, cookie, "", http.MethodGet, "/agents/credentials/", "", nil)
	if dashboard.Code != http.StatusOK || !strings.Contains(dashboard.Body.String(), "Approved one") ||
		!strings.Contains(dashboard.Body.String(), "Broker-reported account state: not-enrolled") ||
		strings.Contains(dashboard.Body.String(), dynamicCredentialNeedle) ||
		strings.Contains(dashboard.Body.String(), "Recovery upload (optional)") {
		t.Fatal("dynamic unknown-principal dashboard was unsafe or incomplete")
	}

	started := request(
		t, server, cookie, csrf, http.MethodPost,
		"/agents/credentials/templates/"+testDynamicTemplateOne+"/connect", "", nil,
	)
	if started.Code != http.StatusAccepted {
		t.Fatalf("dynamic enrollment start failed: %d %s", started.Code, started.Body.String())
	}
	completed := waitHTTPEnrollment(t, server, principal, started.Body.Bytes())
	if completed.Status != enrollmentSucceeded {
		t.Fatalf("dynamic enrollment failed: %#v", completed)
	}

	started = request(
		t, server, cookie, csrf, http.MethodPost,
		"/agents/credentials/templates/"+testDynamicTemplateOne+"/connect", "", nil,
	)
	if started.Code != http.StatusAccepted {
		t.Fatalf("dynamic reconnect before expiry failed to start: %d", started.Code)
	}
	completed = waitHTTPEnrollment(t, server, principal, started.Body.Bytes())
	if completed.Status != enrollmentSucceeded {
		t.Fatal("dynamic reconnect before expiry failed")
	}

	broker.mu.Lock()
	defer broker.mu.Unlock()
	if len(broker.mutations) != 2 || broker.mutations[0].Action != dynamicActionEnroll ||
		broker.mutations[1].Action != dynamicActionReconnect ||
		broker.mutations[0].Principal != principal || broker.mutations[0].Template != testDynamicTemplateOne ||
		broker.mutations[0].OperationID == "" || broker.mutations[1].OperationID == "" ||
		broker.mutations[0].OperationID == broker.mutations[1].OperationID {
		t.Fatal("dynamic broker custody did not preserve exact principal/template/action/operation binding")
	}
	observable := dashboard.Body.String() + started.Body.String() + audit.String()
	if strings.Contains(observable, dynamicCredentialNeedle) || strings.Contains(observable, "refresh-needle") {
		t.Fatal("dynamic credential appeared in browser or audit output")
	}
}

func TestDynamicReconnectsAccountUnreadyAndSupportsAuthorizationCodeAdapter(t *testing.T) {
	principal := Principal{Issuer: testIdentityIssuer, Subject: "degraded-user"}
	broker := newMemoryPrincipalAccountBroker()
	broker.accounts[principalMapKey(principal)] = DynamicAccountState{
		State: accountStateUnready, Template: testDynamicTemplateTwo, Generation: 4,
	}
	runner := &scriptedDynamicRunner{}
	server, cookie, csrf, _ := authenticatedDynamicServer(t, principal, broker, runner, false)
	defer server.Close()
	started := request(
		t, server, cookie, csrf, http.MethodPost,
		"/agents/credentials/templates/"+testDynamicTemplateTwo+"/connect", "", nil,
	)
	if started.Code != http.StatusAccepted {
		t.Fatalf("account-unready reconnect failed to start: %d", started.Code)
	}
	var enrollment EnrollmentStatus
	if err := json.Unmarshal(started.Body.Bytes(), &enrollment); err != nil {
		t.Fatal(err)
	}
	action := waitEnrollmentStatus(
		t, server.enrollments, principal, enrollment.ID, enrollmentActionRequired,
	)
	if !action.NeedsCode || action.UserCode != "" || action.AuthorizationURL == "" {
		t.Fatal("authorization-code adapter did not expose an explicit empty code handoff")
	}
	code := request(
		t, server, cookie, csrf, http.MethodPost,
		"/agents/credentials/enrollments/"+enrollment.ID+"/code", jsonContentType,
		[]byte(`{"code":"synthetic-authorization-code"}`),
	)
	if code.Code != http.StatusNoContent {
		t.Fatalf("authorization code submission failed: %d", code.Code)
	}
	if result := waitEnrollmentStatus(
		t, server.enrollments, principal, enrollment.ID, enrollmentSucceeded,
	); result.Status != enrollmentSucceeded {
		t.Fatal("account-unready authorization-code reconnect failed")
	}
}

func TestDynamicPrincipalIsolationTemplateConflictRevokeAndRecoveryFallback(t *testing.T) {
	alice := Principal{Issuer: testIdentityIssuer, Subject: "dynamic-alice"}
	bob := Principal{Issuer: testIdentityIssuer, Subject: "dynamic-bob"}
	broker := newMemoryPrincipalAccountBroker()
	broker.accounts[principalMapKey(alice)] = DynamicAccountState{
		State: accountStateReady, Template: testDynamicTemplateOne, Generation: 1,
	}
	runner := &scriptedDynamicRunner{}
	aliceServer, aliceCookie, csrf, _ := authenticatedDynamicServer(t, alice, broker, runner, true)
	defer aliceServer.Close()
	bobServer, bobCookie, _, _ := authenticatedDynamicServer(t, bob, broker, runner, false)
	defer bobServer.Close()

	csrfDenied := request(
		t, aliceServer, aliceCookie, "", http.MethodPost,
		"/agents/credentials/templates/"+testDynamicTemplateOne+"/connect", "", nil,
	)
	if csrfDenied.Code != http.StatusForbidden || runner.calls != 0 {
		t.Fatal("dynamic enrollment did not fail closed before runner execution on CSRF")
	}
	conflict := request(
		t, aliceServer, aliceCookie, csrf, http.MethodPost,
		"/agents/credentials/templates/"+testDynamicTemplateTwo+"/connect", "", nil,
	)
	if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), "template-conflict") ||
		runner.calls != 0 {
		t.Fatal("active template switch did not fail before runner execution")
	}
	cross := request(t, bobServer, bobCookie, "", http.MethodGet, "/agents/credentials/account", "", nil)
	if cross.Code != http.StatusOK || strings.Contains(cross.Body.String(), testDynamicTemplateOne) ||
		!strings.Contains(cross.Body.String(), accountStateNotEnrolled) {
		t.Fatal("second principal observed the first principal's account")
	}
	override := request(
		t, bobServer, bobCookie, "", http.MethodGet,
		"/agents/credentials/account?subject=dynamic-alice", "", nil,
	)
	if override.Code != http.StatusNotFound {
		t.Fatal("request parameter was allowed to override the authenticated principal")
	}

	recovery := request(
		t, aliceServer, aliceCookie, csrf, http.MethodPut,
		"/agents/credentials/templates/"+testDynamicTemplateOne+"/credential", jsonContentType,
		validCodex(dynamicCredentialNeedle, "recovery-refresh"),
	)
	if recovery.Code != http.StatusOK || strings.Contains(recovery.Body.String(), dynamicCredentialNeedle) {
		t.Fatal("explicit recovery fallback failed or disclosed credential content")
	}

	revokeRequest := httptest.NewRequestWithContext(
		t.Context(), http.MethodPost, "https://portal.example/agents/credentials/account/revoke", nil,
	)
	revokeRequest.AddCookie(aliceCookie)
	revokeRequest.Header.Set("Origin", "https://portal.example")
	revokeRequest.Header.Set(csrfHeader, csrf)
	revokeRequest.Header.Set(confirmHeader, "revoke")
	revokeResponse := httptest.NewRecorder()
	aliceServer.ServeHTTP(revokeResponse, revokeRequest)
	if revokeResponse.Code != http.StatusOK || strings.Contains(revokeResponse.Body.String(), dynamicCredentialNeedle) {
		t.Fatal("dynamic account revoke failed or disclosed credential content")
	}
}

func TestDynamicEligibilityAndDependenciesFailClosedWithoutReassignment(t *testing.T) {
	cfg := testDynamicConfig()
	cfg.Auth.Eligibility = &eligibility.Policy{Default: eligibility.DefaultDeny, Rules: []eligibility.Rule{{
		ID: "eligible-group", Effect: eligibility.EffectAllow,
		ClaimPath: testEligibilityGroups + "[]", Values: []string{testEligibleValue},
	}}}
	auth := &Authenticator{cfg: cfg}
	unknown := Principal{Issuer: testIdentityIssuer, Subject: "unknown"}
	if !auth.admits(unknown, map[string]any{testEligibilityGroups: []any{testEligibleValue}}) ||
		auth.admits(unknown, map[string]any{testEligibilityGroups: []any{"removed"}}) {
		t.Fatal("dynamic eligibility did not fail closed for a removed principal")
	}

	broker := newMemoryPrincipalAccountBroker()
	broker.accounts[principalMapKey(unknown)] = DynamicAccountState{
		State: accountStateReady, Template: testDynamicTemplateOne, Generation: 1,
	}
	broker.accountErr = ErrBrokerUnavailable
	runner := &scriptedDynamicRunner{}
	server, cookie, csrf, _ := authenticatedDynamicServer(t, unknown, broker, runner, false)
	defer server.Close()
	connect := request(
		t, server, cookie, csrf, http.MethodPost,
		"/agents/credentials/templates/"+testDynamicTemplateOne+"/connect", "", nil,
	)
	if connect.Code != http.StatusServiceUnavailable || runner.calls != 0 {
		t.Fatal("broker unavailability did not fail before runner execution")
	}
	broker.accountErr = nil
	broker.mutationErr = ErrBrokerUnavailable
	started := request(
		t, server, cookie, csrf, http.MethodPost,
		"/agents/credentials/templates/"+testDynamicTemplateOne+"/connect", "", nil,
	)
	if started.Code != http.StatusAccepted {
		t.Fatal("broker-failure enrollment did not start")
	}
	result := waitHTTPEnrollment(t, server, unknown, started.Body.Bytes())
	if result.Status != enrollmentFailed || result.Reason != "broker-unavailable" {
		t.Fatal("broker completion failure was not stable and fail-closed")
	}
	broker.mu.Lock()
	account := broker.accounts[principalMapKey(unknown)]
	broker.mu.Unlock()
	if account.Template != testDynamicTemplateOne || account.Generation != 1 {
		t.Fatal("failed reconnect reassigned or replaced the existing account")
	}

	broker.mutationErr = nil
	runner.reason = "runner-process-failed"
	started = request(
		t, server, cookie, csrf, http.MethodPost,
		"/agents/credentials/templates/"+testDynamicTemplateOne+"/connect", "", nil,
	)
	if started.Code != http.StatusAccepted {
		t.Fatal("runner-failure enrollment did not start")
	}
	result = waitHTTPEnrollment(t, server, unknown, started.Body.Bytes())
	if result.Status != enrollmentFailed || result.Reason != runner.reason {
		t.Fatal("runner failure was not stable and fail-closed")
	}
	broker.mu.Lock()
	mutations := len(broker.mutations)
	broker.mu.Unlock()
	if mutations != 0 {
		t.Fatal("runner failure reached broker custody")
	}
}

func TestDynamicLogoutCancelsEnrollmentAndPortalRestartRequiresAuthentication(t *testing.T) {
	principal := Principal{Issuer: testIdentityIssuer, Subject: "dynamic-session-owner"}
	broker := newMemoryPrincipalAccountBroker()
	runner := blockingCredentialRunner{started: make(chan struct{}), stopped: make(chan struct{})}
	server, cookie, csrf, _ := authenticatedDynamicServer(t, principal, broker, runner, false)

	started := request(
		t, server, cookie, csrf, http.MethodPost,
		"/agents/credentials/templates/"+testDynamicTemplateOne+"/connect", "", nil,
	)
	if started.Code != http.StatusAccepted {
		t.Fatal("dynamic enrollment did not start before logout")
	}
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("dynamic runner did not start")
	}
	loggedOut := request(
		t, server, cookie, csrf, http.MethodPost, "/agents/credentials/logout", "", nil,
	)
	if loggedOut.Code != http.StatusNoContent {
		t.Fatal("dynamic logout failed")
	}
	select {
	case <-runner.stopped:
	case <-time.After(time.Second):
		t.Fatal("dynamic logout did not stop the runner")
	}
	var enrollment EnrollmentStatus
	if err := json.Unmarshal(started.Body.Bytes(), &enrollment); err != nil {
		t.Fatal(err)
	}
	if status := waitEnrollmentStatus(
		t, server.enrollments, principal, enrollment.ID, enrollmentCancelled,
	); status.Status != enrollmentCancelled {
		t.Fatal("dynamic logout did not cancel the enrollment")
	}
	server.Close()

	cfg := testDynamicConfig()
	sum := sha512.Sum512([]byte(strings.Repeat("d", 64)))
	cookies := securecookie.New(sum[:32], sum[32:])
	cookies.MaxAge(cfg.Auth.Session.MaxAgeSeconds)
	restartedAuth := &Authenticator{cfg: cfg, cookies: cookies, sessions: map[string]session{}, now: time.Now}
	restarted := NewServer(
		cfg, restartedAuth, nil, NewAuditLogger(&bytes.Buffer{}), &scriptedDynamicRunner{}, broker,
	)
	defer restarted.Close()
	response := request(t, restarted, cookie, "", http.MethodGet, "/agents/credentials/", "", nil)
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/agents/credentials/login" {
		t.Fatal("portal restart accepted an in-memory session from the prior process")
	}
}
