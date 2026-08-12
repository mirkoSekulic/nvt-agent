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
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/mirkoSekulic/nvt-agent/protocol/eligibility"
)

const dynamicCredentialNeedle = "DYNAMIC-PORTAL-CREDENTIAL-NEEDLE"

//nolint:govet // Test record order mirrors the broker mutation interface.
type brokerMutation struct {
	Principal            Principal
	Template             string
	OperationID          string
	Credential           []byte
	EligibilityExpiresAt time.Time
	Action               string
}

type memoryPrincipalAccountBroker struct {
	accounts         map[string]DynamicAccountState
	readyErr         error
	accountErr       error
	mutationErr      error
	mutations        []brokerMutation
	mu               sync.Mutex
	switchRequests   int
	switchAuthorized bool
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
	return state, nil
}

func (b *memoryPrincipalAccountBroker) CompleteEnrollment(
	_ context.Context,
	principal Principal,
	template, operationID string,
	credential []byte,
	eligibilityExpiresAt time.Time,
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
		Credential: bytes.Clone(credential), EligibilityExpiresAt: eligibilityExpiresAt,
		Action: dynamicActionEnroll,
	})
	b.accounts[key] = DynamicAccountState{State: accountStateReady, Template: template, Generation: 1}
	return nil
}

func (b *memoryPrincipalAccountBroker) Reconnect(
	_ context.Context,
	principal Principal,
	operationID string,
	credential []byte,
	eligibilityExpiresAt time.Time,
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
		Credential: bytes.Clone(credential), EligibilityExpiresAt: eligibilityExpiresAt,
		Action: dynamicActionReconnect,
	})
	if current.Generation < 1 {
		current.Generation = 1
	}
	current.State = accountStateReady
	current.Generation++
	b.accounts[key] = current
	return nil
}

func (b *memoryPrincipalAccountBroker) RenewEligibility(_ context.Context, _ Principal, _ time.Time) error {
	return nil
}
func (b *memoryPrincipalAccountBroker) RevokeEligibility(_ context.Context, _ Principal) error {
	return nil
}

func (b *memoryPrincipalAccountBroker) RequestTemplateSwitch(
	_ context.Context,
	principal Principal,
	_ string,
) (string, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.mutationErr != nil {
		return "", false, b.mutationErr
	}
	current, ok := b.accounts[principalMapKey(principal)]
	if !ok || current.State != accountStateRevoked {
		return "", false, &brokerOperationError{reason: "template-switch-not-revoked"}
	}
	b.switchRequests++
	if b.switchAuthorized {
		return "", true, nil
	}
	return "switch-request", false, nil
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

type recordingSwitchCoordinator struct {
	err   error
	calls []string
	mu    sync.Mutex
}

func (c *recordingSwitchCoordinator) Authorize(_ context.Context, requestID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, requestID)
	return c.err
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

func (r *scriptedDynamicRunner) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

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
	expiresAt := time.Now().Add(time.Hour)
	auth.sessions[id] = session{
		Principal: principal, CSRF: csrf, ExpiresAt: expiresAt, EligibilityExpiresAt: expiresAt,
	}
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

//nolint:gocyclo,cyclop // One test deliberately verifies the complete custody/non-disclosure lifecycle.
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
		broker.mutations[0].OperationID == broker.mutations[1].OperationID ||
		broker.mutations[0].EligibilityExpiresAt.Before(time.Now().Add(50*time.Minute)) ||
		broker.mutations[1].EligibilityExpiresAt.Before(time.Now().Add(50*time.Minute)) {
		t.Fatal("dynamic broker custody did not preserve exact principal/template/action/operation binding")
	}
	observable := dashboard.Body.String() + started.Body.String() + audit.String()
	if strings.Contains(observable, dynamicCredentialNeedle) || strings.Contains(observable, "refresh-needle") {
		t.Fatal("dynamic credential appeared in browser or audit output")
	}
}

func TestDynamicShortEligibilityLeaseBindsEnrollmentAndRequiresFreshLoginAfterExpiry(t *testing.T) {
	principal := Principal{Issuer: testIdentityIssuer, Subject: "short-lease-owner"}
	broker := newMemoryPrincipalAccountBroker()
	runner := &scriptedDynamicRunner{}
	cfg := testDynamicConfig()
	cfg.Auth.Session.MaxAgeSeconds = 3600
	cfg.Dynamic.Broker.EligibilityLeaseSeconds = 300
	evaluatedAt := time.Now().Truncate(time.Second)
	clock := evaluatedAt
	leaseExpiresAt := evaluatedAt.Add(300 * time.Second)
	sessionExpiresAt := evaluatedAt.Add(time.Hour)

	sum := sha512.Sum512([]byte(strings.Repeat("l", 64)))
	cookies := securecookie.New(sum[:32], sum[32:])
	cookies.MaxAge(cfg.Auth.Session.MaxAgeSeconds)
	auth := &Authenticator{
		cfg: cfg, cookies: cookies, sessions: map[string]session{}, now: func() time.Time { return clock },
	}
	const sessionID = "short-lease-session"
	auth.sessions[sessionID] = session{
		Principal: principal, CSRF: testCSRFToken,
		ExpiresAt: sessionExpiresAt, EligibilityExpiresAt: leaseExpiresAt,
	}
	encoded, err := cookies.Encode(cfg.Auth.Session.CookieName, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: cfg.Auth.Session.CookieName, Value: encoded}
	server := NewServer(cfg, auth, nil, NewAuditLogger(&bytes.Buffer{}), runner, broker)
	defer server.Close()

	started := request(
		t, server, cookie, testCSRFToken, http.MethodPost,
		"/agents/credentials/templates/"+testDynamicTemplateOne+"/connect", "", nil,
	)
	if started.Code != http.StatusAccepted {
		t.Fatalf("immediate short-lease enrollment failed: %d %s", started.Code, started.Body.String())
	}
	completed := waitHTTPEnrollment(t, server, principal, started.Body.Bytes())
	if completed.Status != enrollmentSucceeded {
		t.Fatalf("immediate short-lease enrollment did not complete: %#v", completed)
	}
	broker.mu.Lock()
	if len(broker.mutations) != 1 || !broker.mutations[0].EligibilityExpiresAt.Equal(leaseExpiresAt) ||
		broker.mutations[0].EligibilityExpiresAt.After(sessionExpiresAt) {
		broker.mu.Unlock()
		t.Fatal("enrollment did not retain the exact original evaluated eligibility expiry")
	}
	broker.mu.Unlock()

	clock = leaseExpiresAt.Add(time.Second)
	expired := request(
		t, server, cookie, testCSRFToken, http.MethodPost,
		"/agents/credentials/templates/"+testDynamicTemplateOne+"/connect", "", nil,
	)
	if expired.Code != http.StatusUnauthorized || runner.callCount() != 1 {
		t.Fatalf(
			"expired eligibility did not require fresh login: status=%d calls=%d",
			expired.Code, runner.callCount(),
		)
	}
}

func TestDynamicReconnectsAccountUnreadyAndSupportsAuthorizationCodeAdapter(t *testing.T) {
	principal := Principal{Issuer: testIdentityIssuer, Subject: "degraded-user"}
	var assertionKey []byte
	var reconnects atomic.Int32
	broker, assertionKey := newTestPrincipalAccountBroker(t, http.HandlerFunc(
		func(response http.ResponseWriter, request *http.Request) {
			response.Header().Set("Content-Type", jsonContentType)
			if verified := verifyTestPrincipalAssertion(
				t, request.Header.Get("Authorization"), assertionKey,
			); verified != principal {
				t.Error("portal changed the authenticated principal on the broker request")
			}
			switch request.URL.Path {
			case "/v1/principal-accounts/readiness":
				writeBrokerTestResponse(
					t, response,
					`{"ok":true,"state":"unready","template":"`+testDynamicTemplateTwo+`","generation":4}`,
				)
			case "/v1/principal-accounts/reconnect":
				reconnects.Add(1)
				writeBrokerTestResponse(
					t, response,
					`{"ok":true,"state":"ready","template":"`+testDynamicTemplateTwo+`","generation":5}`,
				)
			default:
				response.WriteHeader(http.StatusNotFound)
			}
		},
	))
	runner := &scriptedDynamicRunner{}
	server, cookie, csrf, _ := authenticatedDynamicServer(t, principal, broker, runner, false)
	defer server.Close()
	wrongTemplate := request(
		t, server, cookie, csrf, http.MethodPost,
		"/agents/credentials/templates/"+testDynamicTemplateOne+"/connect", "", nil,
	)
	if wrongTemplate.Code != http.StatusConflict || runner.callCount() != 0 || reconnects.Load() != 0 {
		t.Fatal("account-unready reconnect accepted a template other than the committed template")
	}
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
	if runner.callCount() != 1 || reconnects.Load() != 1 {
		t.Fatal("matching-template reconnect did not run exactly once")
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
	if csrfDenied.Code != http.StatusForbidden || runner.callCount() != 0 {
		t.Fatal("dynamic enrollment did not fail closed before runner execution on CSRF")
	}
	conflict := request(
		t, aliceServer, aliceCookie, csrf, http.MethodPost,
		"/agents/credentials/templates/"+testDynamicTemplateTwo+"/connect", "", nil,
	)
	if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), "template-conflict") ||
		runner.callCount() != 0 {
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
	postRevokeSwitch := request(
		t, aliceServer, aliceCookie, csrf, http.MethodPost,
		"/agents/credentials/templates/"+testDynamicTemplateTwo+"/connect", "", nil,
	)
	if postRevokeSwitch.Code != http.StatusConflict || runner.callCount() != 0 {
		t.Fatal("revocation removed the durable template switch lock")
	}
}

func TestDynamicRevokedTemplateSwitchUsesTargetFreeCoordinatorBeforeRunner(t *testing.T) {
	principal := Principal{Issuer: testIdentityIssuer, Subject: "switch-owner"}
	broker := newMemoryPrincipalAccountBroker()
	broker.accounts[principalMapKey(principal)] = DynamicAccountState{
		State: accountStateRevoked, Template: testDynamicTemplateOne, Generation: 1,
	}
	runner := &scriptedDynamicRunner{}
	coordinator := &recordingSwitchCoordinator{}
	cfg := testDynamicConfig()
	cfg.Dynamic.TemplateSwitch = TemplateSwitchConfig{
		Enabled: true, CoordinatorURL: "http://nvt-operator:8082",
		RequestTimeoutSeconds: 2, MaxResponseBytes: 4096,
	}
	sum := sha512.Sum512([]byte(strings.Repeat("s", 64)))
	cookies := securecookie.New(sum[:32], sum[32:])
	cookies.MaxAge(cfg.Auth.Session.MaxAgeSeconds)
	auth := &Authenticator{cfg: cfg, cookies: cookies, sessions: map[string]session{}, now: time.Now}
	expiresAt := time.Now().Add(time.Hour)
	auth.sessions["switch-session"] = session{
		Principal: principal, CSRF: testCSRFToken, ExpiresAt: expiresAt, EligibilityExpiresAt: expiresAt,
	}
	encoded, err := cookies.Encode(cfg.Auth.Session.CookieName, "switch-session")
	if err != nil {
		t.Fatal(err)
	}
	server := NewServerWithSwitchCoordinator(
		cfg, auth, nil, NewAuditLogger(&bytes.Buffer{}), runner, broker, coordinator,
	)
	defer server.Close()
	cookie := &http.Cookie{Name: cfg.Auth.Session.CookieName, Value: encoded}
	response := request(
		t, server, cookie, testCSRFToken, http.MethodPost,
		"/agents/credentials/templates/"+testDynamicTemplateTwo+"/connect", "", nil,
	)
	if response.Code != http.StatusAccepted {
		t.Fatalf("authorized switch did not start enrollment: %d %q", response.Code, response.Body.String())
	}
	var started EnrollmentStatus
	if err := json.Unmarshal(response.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	waitEnrollmentStatus(t, server.enrollments, principal, started.ID, enrollmentActionRequired)
	if err := server.enrollments.ProvideCode(principal, started.ID, "synthetic-authorization-code"); err != nil {
		t.Fatal(err)
	}
	if result := waitEnrollmentStatus(
		t, server.enrollments, principal, started.ID, enrollmentSucceeded,
	); result.Status != enrollmentSucceeded {
		t.Fatalf("switched enrollment failed: %#v", result)
	}
	if broker.switchRequests != 1 || len(coordinator.calls) != 1 || coordinator.calls[0] != "switch-request" ||
		runner.callCount() != 1 || broker.accounts[principalMapKey(principal)].Template != testDynamicTemplateTwo {
		t.Fatalf(
			"switch path was not target-free and ordered: broker=%#v coordinator=%#v runner=%d",
			broker, coordinator.calls, runner.callCount(),
		)
	}
}

func TestDynamicTemplateSwitchActiveRunAndCoordinatorFailureStopBeforeRunner(t *testing.T) {
	principal := Principal{Issuer: testIdentityIssuer, Subject: "switch-denied"}
	for _, test := range []struct { //nolint:govet // Test-case field names favor readable literals.
		name   string
		err    error
		status int
		reason string
	}{
		{name: "active", err: ErrTemplateSwitchDenied, status: http.StatusConflict, reason: "active-agentruns"},
		{name: accountStateUnavailable, err: ErrTemplateSwitchUnavailable, status: http.StatusServiceUnavailable, reason: reasonBrokerUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			broker := newMemoryPrincipalAccountBroker()
			broker.accounts[principalMapKey(principal)] = DynamicAccountState{
				State: accountStateRevoked, Template: testDynamicTemplateOne, Generation: 1,
			}
			runner := &scriptedDynamicRunner{}
			coordinator := &recordingSwitchCoordinator{err: test.err}
			server, cookie, csrf, _ := authenticatedDynamicServer(t, principal, broker, runner, false)
			server.switchCoordinator = coordinator
			response := request(
				t, server, cookie, csrf, http.MethodPost,
				"/agents/credentials/templates/"+testDynamicTemplateTwo+"/connect", "", nil,
			)
			wrongResponse := response.Code != test.status ||
				!strings.Contains(response.Body.String(), test.reason)
			if wrongResponse || runner.callCount() != 0 {
				t.Fatalf(
					"switch dependency failure reached runner: %d %q calls=%d",
					response.Code, response.Body.String(), runner.callCount(),
				)
			}
		})
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
	if connect.Code != http.StatusServiceUnavailable || runner.callCount() != 0 {
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
	if result.Status != enrollmentFailed || result.Reason != reasonBrokerUnavailable {
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
