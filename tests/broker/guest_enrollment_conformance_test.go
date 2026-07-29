package broker_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	guestEnrollmentVersion         = "nvt.guest-enrollment/v1"
	guestEnrollmentIssuePath       = "/v1/guest-enrollment/issue"
	guestEnrollmentExchangePath    = "/v1/guest-enrollment/exchange"
	guestEnrollmentRevokeBinding   = "/v1/guest-enrollment/revoke-binding"
	guestEnrollmentRevokeExecution = "/v1/guest-enrollment/revoke-execution"
	guestEnrollmentCompleteCleanup = "/v1/guest-enrollment/complete-execution-cleanup"
	guestRuntimeIdentityStatus     = "/v1/guest-runtime-identity/status"
	guestRuntimeIdentityRotate     = "/v1/guest-runtime-identity/rotate"
	guestEnrollmentExchangeURL     = "https://broker.example/v1/guest-enrollment/exchange"
	guestRuntimeIdentityVersion    = "nvt.guest-runtime-identity/v1"
	guestSessionIdentityVersion    = "nvt.guest-session-identity/v1"
	guestSessionIdentityIssue      = "/v1/guest-session-identity/issue"
	guestSessionIdentityAuth       = "/v1/guest-session-identity/authenticate"
	guestSessionAudience           = "nvt.native-guest-control/v1"
	nativeEgressIdentityVersion    = "nvt.native-egress-identity/v1"
	nativeEgressIdentityIssue      = "/v1/native-egress-identity/issue"
	nativeEgressIdentityAuth       = "/v1/native-egress-identity/authenticate"
	nativeEgressRevokeBinding      = "/v1/native-egress-identity/revoke-binding"
	nativeEgressRevokeExecution    = "/v1/native-egress-identity/revoke-execution"
	nativeEgressAudience           = "nvt.native-egress/v1"
	guestEnrollmentOrchestrator    = "orchestrator-token-0123456789abcdef"
)

func newGuestEnrollmentBrokerFixture(t *testing.T) *brokerFixture {
	t.Helper()
	fixture := newBrokerFixtureBase(t, "", "")
	fixture.writeRoleIdentities(mediatedIdentities())
	tokenFile := filepath.Join(fixture.home, "guest-enrollment-orchestrator-token")
	if err := os.WriteFile(tokenFile, []byte(guestEnrollmentOrchestrator), 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.extraEnv = []string{
		"NVT_BROKER_GUEST_ENROLLMENT_ENABLED=true",
		"NVT_BROKER_GUEST_ENROLLMENT_DB=" + filepath.Join(fixture.home, "guest-enrollment.sqlite3"),
		"NVT_BROKER_GUEST_ENROLLMENT_EXCHANGE_URL=" + guestEnrollmentExchangeURL,
		"NVT_BROKER_GUEST_ENROLLMENT_ORCHESTRATOR_TOKEN_FILE=" + tokenFile,
	}
	fixture.start()
	t.Cleanup(fixture.stop)
	return fixture
}

func TestGuestEnrollmentAPIExactLifecycleRestartAndScopeCleanup(t *testing.T) {
	fixture := newGuestEnrollmentBrokerFixture(t)
	firstRequest := enrollmentIssueRequest("run-uid", "execution-1", 1, "guest-first", 300)
	status, first := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, firstRequest)
	assertEnrollmentStatus(t, status, first, http.StatusOK, "")
	if first["exchange_url"] != guestEnrollmentExchangeURL {
		t.Fatalf("issuer returned caller-independent URL %v", first["exchange_url"])
	}
	firstToken := first["token"].(string)

	wrongExchange := enrollmentExchangeRequest(first)
	wrongBinding := cloneObject(wrongExchange["binding"])
	wrongBinding["guest_instance_id"] = "wrong-guest"
	wrongExchange["binding"] = wrongBinding
	status, body := fixture.postJSONWithToken("", guestEnrollmentExchangePath, wrongExchange)
	assertEnrollmentStatus(t, status, body, http.StatusForbidden, "binding-mismatch")

	fixture.stop()
	fixture.start()
	status, exchanged := fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(first))
	assertEnrollmentStatus(t, status, exchanged, http.StatusOK, "")
	identity := cloneObject(exchanged["runtime_identity"])["opaque"].(string)
	status, runtimeStatus := fixture.postJSONWithToken(identity, guestRuntimeIdentityStatus, runtimeIdentityStatusRequest(first))
	assertEnrollmentStatus(t, status, runtimeStatus, http.StatusOK, "")
	if runtimeStatus["binding"] == nil || runtimeStatus["identity_type"] != "nvt.runtime-identity/v1" || runtimeStatus["opaque"] != nil {
		t.Fatalf("runtime identity status exposed invalid metadata: %v", runtimeStatus)
	}
	successor := runtimeIdentityCanary(0x6a)
	status, rotated := fixture.postJSONWithToken(identity, guestRuntimeIdentityRotate, runtimeIdentityRotateRequest(first, successor))
	assertEnrollmentStatus(t, status, rotated, http.StatusOK, "")
	if encoded, _ := json.Marshal(rotated); bytes.Contains(encoded, []byte(successor)) {
		t.Fatal("rotation response echoed the successor")
	}
	status, body = fixture.postJSONWithToken(identity, guestRuntimeIdentityStatus, runtimeIdentityStatusRequest(first))
	assertEnrollmentStatus(t, status, body, http.StatusUnauthorized, "unauthorized")
	status, body = fixture.postJSONWithToken(successor, guestRuntimeIdentityRotate, runtimeIdentityRotateRequest(first, identity))
	assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")
	fixture.stop()
	fixture.start()
	status, body = fixture.postJSONWithToken(successor, guestRuntimeIdentityStatus, runtimeIdentityStatusRequest(first))
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")
	status, body = fixture.postJSONWithToken(successor, guestRuntimeIdentityRotate, runtimeIdentityRotateRequest(first, identity))
	assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")
	status, body = fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(first))
	assertEnrollmentStatus(t, status, body, http.StatusConflict, "already-consumed")

	secondRequest := enrollmentIssueRequest("run-uid", "execution-1", 2, "guest-replacement", 300)
	status, second := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, secondRequest)
	assertEnrollmentStatus(t, status, second, http.StatusOK, "")
	unrelatedRequest := enrollmentIssueRequest("other-uid", "other-execution", 1, "other-guest", 300)
	status, unrelated := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, unrelatedRequest)
	assertEnrollmentStatus(t, status, unrelated, http.StatusOK, "")
	status, _ = fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(unrelated))
	if status != http.StatusOK {
		t.Fatalf("unrelated exchange status = %d", status)
	}

	status, body = fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentRevokeExecution, enrollmentRevokeExecutionRequest(firstRequest))
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")
	for _, envelope := range []map[string]any{first, second} {
		status, body = fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(envelope))
		assertEnrollmentStatus(t, status, body, http.StatusConflict, "revoked")
	}
	status, body = fixture.postJSONWithToken(successor, guestRuntimeIdentityStatus, runtimeIdentityStatusRequest(first))
	assertEnrollmentStatus(t, status, body, http.StatusUnauthorized, "unauthorized")
	status, body = fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, enrollmentIssueRequest("run-uid", "execution-1", 3, "guest-third", 300))
	assertEnrollmentStatus(t, status, body, http.StatusConflict, "revoked")
	status, body = fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(unrelated))
	assertEnrollmentStatus(t, status, body, http.StatusConflict, "already-consumed")

	// Treat the first successful response as lost, restart, and repeat from the
	// stable execution scope. Completion is durable and idempotent.
	status, body = fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentCompleteCleanup, enrollmentRevokeExecutionRequest(firstRequest))
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")
	fixture.stop()
	fixture.start()
	status, body = fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentCompleteCleanup, enrollmentRevokeExecutionRequest(firstRequest))
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")

	fixture.stop()
	for _, canary := range []string{firstToken, identity, successor} {
		if strings.Contains(fixture.stdout.String(), canary) || strings.Contains(fixture.stderr.String(), canary) {
			t.Fatalf("sensitive enrollment canary entered broker output")
		}
		audit, err := os.ReadFile(fixture.audit)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(audit, []byte(canary)) {
			t.Fatal("sensitive enrollment canary entered broker audit")
		}
		matches, err := filepath.Glob(filepath.Join(fixture.home, "guest-enrollment.sqlite3*"))
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range matches {
			content, err := os.ReadFile(match)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(content, []byte(canary)) {
				t.Fatalf("plaintext enrollment canary entered durable file %s", filepath.Base(match))
			}
		}
	}
	tokenDigest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(firstToken)))
	audit, err := os.ReadFile(fixture.audit)
	if err != nil {
		t.Fatal(err)
	}
	for _, digest := range []string{
		tokenDigest,
		fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(identity))),
		fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(successor))),
	} {
		if strings.Contains(fixture.stdout.String(), digest) || strings.Contains(fixture.stderr.String(), digest) {
			t.Fatal("sensitive enrollment digest entered broker output")
		}
		if bytes.Contains(audit, []byte(digest)) {
			t.Fatal("sensitive enrollment digest entered broker audit")
		}
	}
}

func TestGuestEnrollmentDedicatedAuthorizationAndIssuerOwnedURL(t *testing.T) {
	fixture := newGuestEnrollmentBrokerFixture(t)
	request := enrollmentIssueRequest("auth-uid", "auth-execution", 1, "auth-guest", 300)
	for _, unauthorized := range []string{"frontend-token", "frontend-egress-token"} {
		status, body := fixture.postJSONWithToken(unauthorized, guestEnrollmentIssuePath, request)
		assertEnrollmentStatus(t, status, body, http.StatusUnauthorized, "unauthorized")
		status, body = fixture.postJSONWithToken(unauthorized, guestEnrollmentRevokeExecution, enrollmentRevokeExecutionRequest(request))
		assertEnrollmentStatus(t, status, body, http.StatusUnauthorized, "unauthorized")
		status, body = fixture.postJSONWithToken(unauthorized, guestEnrollmentCompleteCleanup, enrollmentRevokeExecutionRequest(request))
		assertEnrollmentStatus(t, status, body, http.StatusUnauthorized, "unauthorized")
	}

	redirect := cloneObject(request)
	redirect["issuer_url"] = "https://attacker.example/steal"
	status, body := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, redirect)
	assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")

	status, envelope := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, request)
	assertEnrollmentStatus(t, status, envelope, http.StatusOK, "")
	if envelope["exchange_url"] != guestEnrollmentExchangeURL {
		t.Fatalf("exchange URL = %v", envelope["exchange_url"])
	}
	status, body = fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(envelope))
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")
	identity := cloneObject(body["runtime_identity"])["opaque"].(string)
	for _, unauthorized := range []string{"", "frontend-token", "frontend-egress-token", "not-a-runtime-identity"} {
		status, rejected := fixture.postJSONWithToken(unauthorized, guestRuntimeIdentityStatus, runtimeIdentityStatusRequest(envelope))
		assertEnrollmentStatus(t, status, rejected, http.StatusUnauthorized, "unauthorized")
	}
	wrongBinding := runtimeIdentityStatusRequest(envelope)
	wrongBinding["binding"] = cloneObject(envelope["binding"])
	wrongBinding["binding"].(map[string]any)["desired_generation"] = float64(2)
	status, body = fixture.postJSONWithToken(identity, guestRuntimeIdentityStatus, wrongBinding)
	assertEnrollmentStatus(t, status, body, http.StatusUnauthorized, "unauthorized")
	malformedRotate := runtimeIdentityRotateRequest(envelope, runtimeIdentityCanary(0x51))
	malformedRotate["unknown"] = true
	status, body = fixture.postJSONWithToken(identity, guestRuntimeIdentityRotate, malformedRotate)
	assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")
}

func TestGuestSessionIdentityExactLifecycleRestartAndRevocation(t *testing.T) {
	fixture := newGuestEnrollmentBrokerFixture(t)
	request := enrollmentIssueRequest("session-uid", "session-execution", 1, "session-guest", 300)
	status, envelope := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, request)
	assertEnrollmentStatus(t, status, envelope, http.StatusOK, "")
	status, exchanged := fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(envelope))
	assertEnrollmentStatus(t, status, exchanged, http.StatusOK, "")
	runtimeIdentity := cloneObject(exchanged["runtime_identity"])["opaque"].(string)

	status, issued := fixture.postJSONWithToken(runtimeIdentity, guestSessionIdentityIssue, guestSessionIssueRequest(envelope))
	assertEnrollmentStatus(t, status, issued, http.StatusOK, "")
	credential := cloneObject(issued["credential"])["opaque"].(string)
	if cloneObject(issued["credential"])["audience"] != guestSessionAudience {
		t.Fatalf("session audience = %v", cloneObject(issued["credential"])["audience"])
	}
	status, authenticated := fixture.postJSONWithToken(credential, guestSessionIdentityAuth, guestSessionAuthenticateRequest(envelope))
	assertEnrollmentStatus(t, status, authenticated, http.StatusOK, "")
	if authenticated["audience"] != guestSessionAudience || authenticated["credential_type"] != "nvt.guest-session-credential/v1" || authenticated["opaque"] != nil {
		t.Fatalf("unsafe session status %v", authenticated)
	}

	wrongBinding := guestSessionAuthenticateRequest(envelope)
	wrongBinding["binding"] = cloneObject(envelope["binding"])
	wrongBinding["binding"].(map[string]any)["guest_instance_id"] = "wrong"
	status, body := fixture.postJSONWithToken(credential, guestSessionIdentityAuth, wrongBinding)
	assertEnrollmentStatus(t, status, body, http.StatusUnauthorized, "unauthorized")
	wrongAudience := guestSessionIssueRequest(envelope)
	wrongAudience["audience"] = "caller-selected"
	status, body = fixture.postJSONWithToken(runtimeIdentity, guestSessionIdentityIssue, wrongAudience)
	assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")
	for _, unauthorized := range []string{"frontend-token", "frontend-egress-token", credential} {
		status, body = fixture.postJSONWithToken(unauthorized, guestSessionIdentityIssue, guestSessionIssueRequest(envelope))
		assertEnrollmentStatus(t, status, body, http.StatusUnauthorized, "unauthorized")
	}

	fixture.stop()
	fixture.start()
	status, body = fixture.postJSONWithToken(credential, guestSessionIdentityAuth, guestSessionAuthenticateRequest(envelope))
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")
	status, second := fixture.postJSONWithToken(runtimeIdentity, guestSessionIdentityIssue, guestSessionIssueRequest(envelope))
	assertEnrollmentStatus(t, status, second, http.StatusOK, "")
	secondCredential := cloneObject(second["credential"])["opaque"].(string)
	status, body = fixture.postJSONWithToken(runtimeIdentity, guestSessionIdentityIssue, guestSessionIssueRequest(envelope))
	assertEnrollmentStatus(t, status, body, http.StatusTooManyRequests, "capacity-exceeded")

	status, body = fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentRevokeExecution, enrollmentRevokeExecutionRequest(request))
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")
	for _, revoked := range []string{credential, secondCredential} {
		status, body = fixture.postJSONWithToken(revoked, guestSessionIdentityAuth, guestSessionAuthenticateRequest(envelope))
		assertEnrollmentStatus(t, status, body, http.StatusUnauthorized, "unauthorized")
	}

	fixture.stop()
	for _, canary := range []string{runtimeIdentity, credential, secondCredential} {
		if strings.Contains(fixture.stdout.String(), canary) || strings.Contains(fixture.stderr.String(), canary) {
			t.Fatal("guest session canary entered broker output")
		}
		audit, err := os.ReadFile(fixture.audit)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(audit, []byte(canary)) {
			t.Fatal("guest session canary entered broker audit")
		}
		matches, err := filepath.Glob(filepath.Join(fixture.home, "guest-enrollment.sqlite3*"))
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range matches {
			content, err := os.ReadFile(match)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(content, []byte(canary)) {
				t.Fatalf("plaintext guest session canary entered %s", filepath.Base(match))
			}
		}
	}
}

func TestNativeEgressIdentityHTTPExactLifecycleRestartAndSharedRevocation(t *testing.T) {
	fixture := newGuestEnrollmentBrokerFixture(t)
	request := enrollmentIssueRequest("egress-uid", "egress-execution", 1, "egress-guest", 300)
	status, envelope := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, request)
	assertEnrollmentStatus(t, status, envelope, http.StatusOK, "")
	status, exchanged := fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(envelope))
	assertEnrollmentStatus(t, status, exchanged, http.StatusOK, "")
	runtimeIdentity := cloneObject(exchanged["runtime_identity"])["opaque"].(string)

	status, issued := fixture.postJSONWithToken(runtimeIdentity, nativeEgressIdentityIssue, nativeEgressIssueRequest(envelope))
	assertEnrollmentStatus(t, status, issued, http.StatusOK, "")
	credential := cloneObject(issued["credential"])["opaque"].(string)
	if !strings.HasPrefix(credential, "nvt_eg1_") || cloneObject(issued["credential"])["audience"] != nativeEgressAudience {
		t.Fatalf("native egress issue result = %v", issued)
	}
	status, authenticated := fixture.postJSONWithToken(credential, nativeEgressIdentityAuth, nativeEgressAuthenticateRequest(envelope))
	assertEnrollmentStatus(t, status, authenticated, http.StatusOK, "")
	if authenticated["credential_type"] != "nvt.native-egress-credential/v1" || authenticated["audience"] != nativeEgressAudience || authenticated["sequence"] != float64(1) {
		t.Fatalf("native egress status = %v", authenticated)
	}
	if authenticated["opaque"] != nil || authenticated["credential"] != nil {
		t.Fatalf("native egress status exposed a credential: %v", authenticated)
	}

	for field, replacement := range map[string]any{
		"agent_run_uid": "other-uid", "execution_id": "other-execution",
		"driver_registration": "other-driver", "desired_generation": float64(2),
		"guest_instance_id": "other-guest",
	} {
		wrong := nativeEgressAuthenticateRequest(envelope)
		wrongBinding := cloneObject(wrong["binding"])
		wrongBinding[field] = replacement
		wrong["binding"] = wrongBinding
		status, body := fixture.postJSONWithToken(credential, nativeEgressIdentityAuth, wrong)
		assertEnrollmentStatus(t, status, body, http.StatusUnauthorized, "unauthorized")
		encodedError, _ := json.Marshal(body)
		if bytes.Contains(encodedError, []byte("egress-uid")) || bytes.Contains(encodedError, []byte("egress-guest")) {
			t.Fatalf("native egress error exposed binding metadata: %s", encodedError)
		}
		status, body = fixture.postJSONWithToken(runtimeIdentity, nativeEgressIdentityIssue, wrong)
		assertEnrollmentStatus(t, status, body, http.StatusUnauthorized, "unauthorized")
	}

	fixture.stop()
	fixture.start()
	status, body := fixture.postJSONWithToken(credential, nativeEgressIdentityAuth, nativeEgressAuthenticateRequest(envelope))
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")
	status, second := fixture.postJSONWithToken(runtimeIdentity, nativeEgressIdentityIssue, nativeEgressIssueRequest(envelope))
	assertEnrollmentStatus(t, status, second, http.StatusOK, "")
	secondCredential := cloneObject(second["credential"])["opaque"].(string)
	status, body = fixture.postJSONWithToken(runtimeIdentity, nativeEgressIdentityIssue, nativeEgressIssueRequest(envelope))
	assertEnrollmentStatus(t, status, body, http.StatusTooManyRequests, "capacity-exceeded")

	status, body = fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentRevokeExecution, enrollmentRevokeExecutionRequest(request))
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")
	for _, revoked := range []string{credential, secondCredential} {
		status, body = fixture.postJSONWithToken(revoked, nativeEgressIdentityAuth, nativeEgressAuthenticateRequest(envelope))
		assertEnrollmentStatus(t, status, body, http.StatusUnauthorized, "unauthorized")
	}

	fixture.stop()
	for _, canary := range []string{runtimeIdentity, credential, secondCredential} {
		if strings.Contains(fixture.stdout.String(), canary) || strings.Contains(fixture.stderr.String(), canary) {
			t.Fatal("native egress canary entered broker output")
		}
		audit, err := os.ReadFile(fixture.audit)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(audit, []byte(canary)) {
			t.Fatal("native egress canary entered broker audit")
		}
		digest := fmt.Sprintf(
			"sha256:%x",
			sha256.Sum256([]byte("nvt.native-egress-credential/v1\x00"+canary)),
		)
		if strings.Contains(fixture.stdout.String(), digest) || strings.Contains(fixture.stderr.String(), digest) || bytes.Contains(audit, []byte(digest)) {
			t.Fatal("native egress digest entered broker output or audit")
		}
		matches, err := filepath.Glob(filepath.Join(fixture.home, "guest-enrollment.sqlite3*"))
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range matches {
			content, err := os.ReadFile(match)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(content, []byte(canary)) {
				t.Fatalf("plaintext native egress canary entered %s", filepath.Base(match))
			}
		}
	}
}

func TestNativeEgressIdentityHTTPStrictInputAuthorityAndConcurrentCap(t *testing.T) {
	fixture := newGuestEnrollmentBrokerFixture(t)
	request := enrollmentIssueRequest("egress-strict", "egress-strict", 1, "egress-strict", 300)
	status, envelope := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, request)
	assertEnrollmentStatus(t, status, envelope, http.StatusOK, "")
	status, exchanged := fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(envelope))
	assertEnrollmentStatus(t, status, exchanged, http.StatusOK, "")
	runtimeIdentity := cloneObject(exchanged["runtime_identity"])["opaque"].(string)

	for _, malformed := range [][]byte{
		[]byte(`{"contract_version":"nvt.native-egress-identity/v1","binding":{},"audience":"nvt.native-egress/v1","audience":"nvt.native-egress/v1"}`),
		[]byte(`{"contract_version":"nvt.native-egress-identity/v1","binding":{"agent_run_uid":"one","agent_run_uid":"two"},"audience":"nvt.native-egress/v1"}`),
		[]byte(`{"contract_version":"wrong","binding":{},"audience":"nvt.native-egress/v1"} trailing`),
		bytes.Repeat([]byte{' '}, (8<<10)+1),
		[]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'},
	} {
		status, body := fixture.postEnrollmentRaw(runtimeIdentity, nativeEgressIdentityIssue, malformed)
		assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")
	}
	for field, value := range map[string]any{
		"contract_version": "nvt.native-egress-identity/v2",
		"audience":         "caller-selected",
		"unknown":          "forbidden",
	} {
		invalid := nativeEgressIssueRequest(envelope)
		invalid[field] = value
		status, body := fixture.postJSONWithToken(runtimeIdentity, nativeEgressIdentityIssue, invalid)
		assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")
	}
	for _, unauthorized := range []string{"frontend-token", "frontend-egress-token", guestSessionCredentialCanary(0x71)} {
		status, body := fixture.postJSONWithToken(unauthorized, nativeEgressIdentityIssue, nativeEgressIssueRequest(envelope))
		assertEnrollmentStatus(t, status, body, http.StatusUnauthorized, "unauthorized")
		status, body = fixture.postJSONWithToken(unauthorized, nativeEgressRevokeBinding, nativeEgressRevokeBindingRequest(envelope))
		assertEnrollmentStatus(t, status, body, http.StatusUnauthorized, "unauthorized")
	}

	start := make(chan struct{})
	type result struct {
		status int
		body   map[string]any
	}
	results := make(chan result, 8)
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			status, body := fixture.postJSONWithToken(runtimeIdentity, nativeEgressIdentityIssue, nativeEgressIssueRequest(envelope))
			results <- result{status, body}
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	successes := 0
	capacity := 0
	for result := range results {
		switch result.status {
		case http.StatusOK:
			successes++
		case http.StatusTooManyRequests:
			if result.body["error"] != "capacity-exceeded" {
				t.Fatalf("native egress error = %v", result.body)
			}
			capacity++
		default:
			t.Fatalf("native egress issue status=%d body=%v", result.status, result.body)
		}
	}
	if successes != 2 || capacity != 6 {
		t.Fatalf("native egress outcomes success=%d capacity=%d", successes, capacity)
	}
	status, body := fixture.postJSONWithToken(guestEnrollmentOrchestrator, nativeEgressRevokeBinding, nativeEgressRevokeBindingRequest(envelope))
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")

	executionRequest := enrollmentIssueRequest("egress-revoke-scope", "egress-revoke-scope", 1, "egress-revoke-scope", 300)
	status, executionEnvelope := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, executionRequest)
	assertEnrollmentStatus(t, status, executionEnvelope, http.StatusOK, "")
	status, body = fixture.postJSONWithToken(guestEnrollmentOrchestrator, nativeEgressRevokeExecution, nativeEgressRevokeExecutionRequest(executionEnvelope))
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")
	status, body = fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(executionEnvelope))
	assertEnrollmentStatus(t, status, body, http.StatusConflict, "revoked")
}

func TestNativeEgressIdentityHTTPAuthenticatesBeforeBodyAndPreservesRevocationHeadroom(t *testing.T) {
	fixture := newGuestEnrollmentBrokerFixture(t)
	unknown := "nvt_eg1_" + guestSessionCredentialCanary(0x20)
	connection := openIncompleteEnrollmentRequest(t, fixture, nativeEgressIdentityAuth, unknown)
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	statusLine, err := bufio.NewReader(connection).ReadString('\n')
	_ = connection.Close()
	if err != nil || !strings.Contains(statusLine, " 401 ") {
		t.Fatalf("unknown egress credential was not rejected before body read: status=%q error=%v", statusLine, err)
	}

	const bindings = 13
	credentials := make([]string, 0, bindings)
	envelopes := make([]map[string]any, 0, bindings)
	for index := range bindings {
		request := enrollmentIssueRequest(fmt.Sprintf("egress-admission-%d", index), fmt.Sprintf("egress-admission-%d", index), 1, fmt.Sprintf("egress-admission-%d", index), 300)
		status, envelope := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, request)
		assertEnrollmentStatus(t, status, envelope, http.StatusOK, "")
		status, exchanged := fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(envelope))
		assertEnrollmentStatus(t, status, exchanged, http.StatusOK, "")
		runtimeIdentity := cloneObject(exchanged["runtime_identity"])["opaque"].(string)
		status, issued := fixture.postJSONWithToken(runtimeIdentity, nativeEgressIdentityIssue, nativeEgressIssueRequest(envelope))
		assertEnrollmentStatus(t, status, issued, http.StatusOK, "")
		credentials = append(credentials, cloneObject(issued["credential"])["opaque"].(string))
		envelopes = append(envelopes, envelope)
	}

	// Twelve credentials can each occupy their four per-credential body slots,
	// reaching the 48-request guest ceiling while leaving sixteen of the shared
	// 64-operation bound reserved for trusted revocation.
	slow := make([]net.Conn, 0, 48)
	for _, credential := range credentials[:12] {
		for range 4 {
			slow = append(slow, openIncompleteEnrollmentRequest(t, fixture, nativeEgressIdentityAuth, credential))
		}
	}
	t.Cleanup(func() {
		for _, connection := range slow {
			_ = connection.Close()
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for {
		status, body := fixture.postEnrollmentRaw(credentials[12], nativeEgressIdentityAuth, []byte(`{}`))
		if status == http.StatusTooManyRequests {
			assertEnrollmentStatus(t, status, body, http.StatusTooManyRequests, "capacity-exceeded")
			break
		}
		if status != http.StatusBadRequest || time.Now().After(deadline) {
			t.Fatalf("native egress admission did not saturate: status=%d body=%v", status, body)
		}
		time.Sleep(10 * time.Millisecond)
	}
	status, body := fixture.postJSONWithToken(
		guestEnrollmentOrchestrator,
		nativeEgressRevokeExecution,
		nativeEgressRevokeExecutionRequest(envelopes[0]),
	)
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")
}

func TestGuestRuntimeIdentityConcurrentRotationIsSingleCAS(t *testing.T) {
	fixture := newGuestEnrollmentBrokerFixture(t)
	request := enrollmentIssueRequest("rotate-uid", "rotate-execution", 1, "rotate-guest", 300)
	status, envelope := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, request)
	assertEnrollmentStatus(t, status, envelope, http.StatusOK, "")
	status, exchanged := fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(envelope))
	assertEnrollmentStatus(t, status, exchanged, http.StatusOK, "")
	identity := cloneObject(exchanged["runtime_identity"])["opaque"].(string)

	start := make(chan struct{})
	type result struct {
		status int
		body   map[string]any
	}
	results := make(chan result, 2)
	var workers sync.WaitGroup
	for _, successor := range []string{runtimeIdentityCanary(0x61), runtimeIdentityCanary(0x62)} {
		workers.Add(1)
		go func(successor string) {
			defer workers.Done()
			<-start
			status, body := fixture.postJSONWithToken(identity, guestRuntimeIdentityRotate, runtimeIdentityRotateRequest(envelope, successor))
			results <- result{status: status, body: body}
		}(successor)
	}
	close(start)
	workers.Wait()
	close(results)
	successes := 0
	unauthorized := 0
	for result := range results {
		switch result.status {
		case http.StatusOK:
			successes++
		case http.StatusUnauthorized:
			if result.body["error"] != "unauthorized" {
				t.Fatalf("rotation error = %v", result.body)
			}
			unauthorized++
		default:
			t.Fatalf("rotation status=%d body=%v", result.status, result.body)
		}
	}
	if successes != 1 || unauthorized != 1 {
		t.Fatalf("rotation outcomes success=%d unauthorized=%d", successes, unauthorized)
	}
}

func TestGuestEnrollmentAuthenticatesBeforeBodyAndReservesRevocationCapacity(t *testing.T) {
	fixture := newGuestEnrollmentBrokerFixture(t)
	for _, path := range []string{
		guestEnrollmentIssuePath,
		guestEnrollmentRevokeBinding,
		guestEnrollmentRevokeExecution,
		guestEnrollmentCompleteCleanup,
	} {
		connection := openIncompleteEnrollmentRequest(t, fixture, path, "")
		if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		status, err := bufio.NewReader(connection).ReadString('\n')
		_ = connection.Close()
		if err != nil {
			t.Fatalf("%s did not reject unauthenticated request before reading its body: %v", path, err)
		}
		if !strings.Contains(status, " 401 ") {
			t.Fatalf("%s status line = %q, want 401", path, strings.TrimSpace(status))
		}
	}

	const exchangeHTTPBound = 64
	slow := saturateEnrollmentRequestSlots(t, fixture, guestEnrollmentExchangePath, "", exchangeHTTPBound)
	t.Cleanup(func() {
		for _, connection := range slow {
			_ = connection.Close()
		}
	})
	status, body := fixture.postEnrollmentRaw("", guestEnrollmentExchangePath, []byte(`{}`))
	assertEnrollmentStatus(t, status, body, http.StatusTooManyRequests, "capacity-exceeded")

	request := enrollmentIssueRequest("saturated-uid", "saturated-execution", 1, "saturated-guest", 300)
	started := time.Now()
	status, body = fixture.postJSONWithToken(
		guestEnrollmentOrchestrator,
		guestEnrollmentRevokeExecution,
		enrollmentRevokeExecutionRequest(request),
	)
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")
	if elapsed := time.Since(started); elapsed >= 2*time.Second {
		t.Fatalf("authoritative revoke was delayed by saturated public exchange traffic: %s", elapsed)
	}
}

func TestGuestEnrollmentControlRequestBodiesHaveIndependentBound(t *testing.T) {
	fixture := newGuestEnrollmentBrokerFixture(t)
	const controlHTTPBound = 16
	slow := saturateEnrollmentRequestSlots(t, fixture, guestEnrollmentIssuePath, guestEnrollmentOrchestrator, controlHTTPBound)
	t.Cleanup(func() {
		for _, connection := range slow {
			_ = connection.Close()
		}
	})
	status, body := fixture.postEnrollmentRaw(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, []byte(`{}`))
	assertEnrollmentStatus(t, status, body, http.StatusTooManyRequests, "capacity-exceeded")
}

func TestGuestRuntimeIdentityBodiesCannotStarveRevocation(t *testing.T) {
	fixture := newGuestEnrollmentBrokerFixture(t)
	unknown := openIncompleteEnrollmentRequest(t, fixture, guestRuntimeIdentityRotate, runtimeIdentityCanary(0x7a))
	if err := unknown.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	unknownStatus, err := bufio.NewReader(unknown).ReadString('\n')
	_ = unknown.Close()
	if err != nil || !strings.Contains(unknownStatus, " 401 ") {
		t.Fatalf("unknown runtime identity retained a slow body slot: status=%q err=%v", strings.TrimSpace(unknownStatus), err)
	}

	firstRequest := enrollmentIssueRequest("runtime-saturated-uid", "runtime-saturated-execution", 1, "runtime-saturated-guest", 300)
	status, first := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, firstRequest)
	assertEnrollmentStatus(t, status, first, http.StatusOK, "")
	status, firstExchange := fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(first))
	assertEnrollmentStatus(t, status, firstExchange, http.StatusOK, "")
	firstIdentity := cloneObject(firstExchange["runtime_identity"])["opaque"].(string)

	secondRequest := enrollmentIssueRequest("runtime-second-uid", "runtime-second-execution", 1, "runtime-second-guest", 300)
	status, second := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, secondRequest)
	assertEnrollmentStatus(t, status, second, http.StatusOK, "")
	status, secondExchange := fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(second))
	assertEnrollmentStatus(t, status, secondExchange, http.StatusOK, "")
	secondIdentity := cloneObject(secondExchange["runtime_identity"])["opaque"].(string)

	const perIdentityHTTPBound = 4
	slow := saturateEnrollmentRequestSlots(
		t,
		fixture,
		guestRuntimeIdentityRotate,
		firstIdentity,
		perIdentityHTTPBound,
	)
	t.Cleanup(func() {
		for _, connection := range slow {
			_ = connection.Close()
		}
	})
	status, body := fixture.postEnrollmentRaw(firstIdentity, guestRuntimeIdentityRotate, []byte(`{}`))
	assertEnrollmentStatus(t, status, body, http.StatusTooManyRequests, "capacity-exceeded")
	status, body = fixture.postJSONWithToken(secondIdentity, guestRuntimeIdentityStatus, runtimeIdentityStatusRequest(second))
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")

	started := time.Now()
	status, body = fixture.postJSONWithToken(
		guestEnrollmentOrchestrator,
		guestEnrollmentRevokeExecution,
		enrollmentRevokeExecutionRequest(firstRequest),
	)
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")
	if elapsed := time.Since(started); elapsed >= 2*time.Second {
		t.Fatalf("revocation was delayed by saturated runtime identity traffic: %s", elapsed)
	}
}

func TestGuestSessionIdentityAdmissionIsAuthenticatedBoundedAndIsolated(t *testing.T) {
	fixture := newGuestEnrollmentBrokerFixture(t)
	unknown := openIncompleteEnrollmentRequest(t, fixture, guestSessionIdentityAuth, guestSessionCredentialCanary(0x7b))
	if err := unknown.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	unknownStatus, err := bufio.NewReader(unknown).ReadString('\n')
	_ = unknown.Close()
	if err != nil || !strings.Contains(unknownStatus, " 401 ") {
		t.Fatalf("unknown session credential retained a slow body slot: status=%q err=%v", strings.TrimSpace(unknownStatus), err)
	}

	issueSession := func(uid string) (map[string]any, string) {
		request := enrollmentIssueRequest(uid, uid+"-execution", 1, uid+"-guest", 300)
		status, envelope := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, request)
		assertEnrollmentStatus(t, status, envelope, http.StatusOK, "")
		status, exchanged := fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(envelope))
		assertEnrollmentStatus(t, status, exchanged, http.StatusOK, "")
		runtimeIdentity := cloneObject(exchanged["runtime_identity"])["opaque"].(string)
		status, session := fixture.postJSONWithToken(runtimeIdentity, guestSessionIdentityIssue, guestSessionIssueRequest(envelope))
		assertEnrollmentStatus(t, status, session, http.StatusOK, "")
		return envelope, cloneObject(session["credential"])["opaque"].(string)
	}
	first, firstCredential := issueSession("session-saturated")
	second, secondCredential := issueSession("session-second")

	const perCredentialHTTPBound = 4
	slow := saturateEnrollmentRequestSlots(
		t,
		fixture,
		guestSessionIdentityAuth,
		firstCredential,
		perCredentialHTTPBound,
	)
	t.Cleanup(func() {
		for _, connection := range slow {
			_ = connection.Close()
		}
	})
	status, body := fixture.postEnrollmentRaw(firstCredential, guestSessionIdentityAuth, []byte(`{}`))
	assertEnrollmentStatus(t, status, body, http.StatusTooManyRequests, "capacity-exceeded")
	status, body = fixture.postJSONWithToken(secondCredential, guestSessionIdentityAuth, guestSessionAuthenticateRequest(second))
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")

	started := time.Now()
	status, body = fixture.postJSONWithToken(
		guestEnrollmentOrchestrator,
		guestEnrollmentRevokeExecution,
		enrollmentRevokeExecutionRequest(first),
	)
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")
	if elapsed := time.Since(started); elapsed >= 2*time.Second {
		t.Fatalf("revocation was delayed by saturated guest session traffic: %s", elapsed)
	}
}

func TestGuestSessionIdentityRateAdmissionIsPerCredential(t *testing.T) {
	fixture := newGuestEnrollmentBrokerFixture(t)
	issueSession := func(uid string) (map[string]any, string) {
		request := enrollmentIssueRequest(uid, uid+"-execution", 1, uid+"-guest", 300)
		status, envelope := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, request)
		assertEnrollmentStatus(t, status, envelope, http.StatusOK, "")
		status, exchanged := fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(envelope))
		assertEnrollmentStatus(t, status, exchanged, http.StatusOK, "")
		runtimeIdentity := cloneObject(exchanged["runtime_identity"])["opaque"].(string)
		status, session := fixture.postJSONWithToken(runtimeIdentity, guestSessionIdentityIssue, guestSessionIssueRequest(envelope))
		assertEnrollmentStatus(t, status, session, http.StatusOK, "")
		return envelope, cloneObject(session["credential"])["opaque"].(string)
	}
	first, firstCredential := issueSession("session-rate-first")
	second, secondCredential := issueSession("session-rate-second")
	rateLimited := false
	for range 64 {
		status, body := fixture.postJSONWithToken(firstCredential, guestSessionIdentityAuth, guestSessionAuthenticateRequest(first))
		if status == http.StatusTooManyRequests {
			assertEnrollmentStatus(t, status, body, http.StatusTooManyRequests, "capacity-exceeded")
			rateLimited = true
			break
		}
		assertEnrollmentStatus(t, status, body, http.StatusOK, "")
	}
	if !rateLimited {
		t.Fatal("noisy credential did not reach its rate bound")
	}
	status, body := fixture.postJSONWithToken(secondCredential, guestSessionIdentityAuth, guestSessionAuthenticateRequest(second))
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")
}

func TestGuestRuntimeIdentityRateAdmissionIsIsolated(t *testing.T) {
	fixture := newGuestEnrollmentBrokerFixture(t)
	issueAndExchange := func(uid string) (map[string]any, string) {
		request := enrollmentIssueRequest(uid, uid+"-execution", 1, uid+"-guest", 300)
		status, envelope := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, request)
		assertEnrollmentStatus(t, status, envelope, http.StatusOK, "")
		status, exchanged := fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(envelope))
		assertEnrollmentStatus(t, status, exchanged, http.StatusOK, "")
		return envelope, cloneObject(exchanged["runtime_identity"])["opaque"].(string)
	}
	first, firstIdentity := issueAndExchange("rate-first")
	second, secondIdentity := issueAndExchange("rate-second")

	for value := byte(0xa0); value < 0xa8; value++ {
		status, body := fixture.postJSONWithToken(runtimeIdentityCanary(value), guestRuntimeIdentityStatus, runtimeIdentityStatusRequest(first))
		assertEnrollmentStatus(t, status, body, http.StatusUnauthorized, "unauthorized")
	}

	limited := false
	deadline := time.Now().Add(3 * time.Second)
	for attempts := 0; attempts < 128 && time.Now().Before(deadline); attempts++ {
		status, body := fixture.postJSONWithToken(firstIdentity, guestRuntimeIdentityStatus, runtimeIdentityStatusRequest(first))
		if status == http.StatusTooManyRequests {
			assertEnrollmentStatus(t, status, body, http.StatusTooManyRequests, "capacity-exceeded")
			limited = true
			break
		}
		assertEnrollmentStatus(t, status, body, http.StatusOK, "")
	}
	if !limited {
		t.Fatal("noisy runtime identity did not reach its bounded rate admission")
	}
	status, body := fixture.postJSONWithToken(secondIdentity, guestRuntimeIdentityStatus, runtimeIdentityStatusRequest(second))
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")
}

func TestGuestEnrollmentExactRevokeStrictBoundsAndDisabledDefault(t *testing.T) {
	fixture := newGuestEnrollmentBrokerFixture(t)
	request := enrollmentIssueRequest("revoke-uid", "revoke-execution", 1, "revoke-guest", 300)
	status, envelope := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, request)
	assertEnrollmentStatus(t, status, envelope, http.StatusOK, "")
	for range 2 {
		status, body := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentRevokeBinding, map[string]any{
			"contract_version": guestEnrollmentVersion,
			"binding":          request["binding"],
		})
		assertEnrollmentStatus(t, status, body, http.StatusOK, "")
	}
	status, body := fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(envelope))
	assertEnrollmentStatus(t, status, body, http.StatusConflict, "revoked")

	duplicate := []byte(`{"contract_version":"nvt.guest-enrollment/v1","contract_version":"nvt.guest-enrollment/v1"}`)
	status, body = fixture.postEnrollmentRaw(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, duplicate)
	assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")
	status, body = fixture.postEnrollmentRaw(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, bytes.Repeat([]byte{' '}, 4097))
	assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")
	status, body = fixture.postEnrollmentRaw(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'})
	assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")
	status, body = fixture.postEnrollmentRaw(guestEnrollmentOrchestrator, guestEnrollmentCompleteCleanup, duplicate)
	assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")
	runtimeRequest := enrollmentIssueRequest("strict-runtime-uid", "strict-runtime-execution", 1, "strict-runtime-guest", 300)
	status, runtimeEnvelope := fixture.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, runtimeRequest)
	assertEnrollmentStatus(t, status, runtimeEnvelope, http.StatusOK, "")
	status, runtimeExchange := fixture.postJSONWithToken("", guestEnrollmentExchangePath, enrollmentExchangeRequest(runtimeEnvelope))
	assertEnrollmentStatus(t, status, runtimeExchange, http.StatusOK, "")
	runtimeIdentity := cloneObject(runtimeExchange["runtime_identity"])["opaque"].(string)
	runtimeDuplicate := []byte(`{"contract_version":"nvt.guest-runtime-identity/v1","binding":{},"successor":"x","successor":"y"}`)
	status, body = fixture.postEnrollmentRaw(runtimeIdentity, guestRuntimeIdentityRotate, runtimeDuplicate)
	assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")
	status, body = fixture.postEnrollmentRaw(runtimeIdentity, guestRuntimeIdentityRotate, bytes.Repeat([]byte{' '}, (16<<10)+1))
	assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")
	status, session := fixture.postJSONWithToken(runtimeIdentity, guestSessionIdentityIssue, guestSessionIssueRequest(runtimeEnvelope))
	assertEnrollmentStatus(t, status, session, http.StatusOK, "")
	sessionCredential := cloneObject(session["credential"])["opaque"].(string)
	sessionDuplicate := []byte(`{"contract_version":"nvt.guest-session-identity/v1","binding":{},"audience":"nvt.native-guest-control/v1","audience":"nvt.native-guest-control/v1"}`)
	status, body = fixture.postEnrollmentRaw(runtimeIdentity, guestSessionIdentityIssue, sessionDuplicate)
	assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")
	status, body = fixture.postEnrollmentRaw(runtimeIdentity, guestSessionIdentityIssue, bytes.Repeat([]byte{' '}, (8<<10)+1))
	assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")
	status, body = fixture.postEnrollmentRaw(sessionCredential, guestSessionIdentityAuth, bytes.Repeat([]byte{' '}, (4<<10)+1))
	assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")

	disabled := newBrokerFixture(t)
	status, body = disabled.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, request)
	assertEnrollmentStatus(t, status, body, http.StatusNotFound, "not-found")
	status, body = disabled.postEnrollmentRaw(guestEnrollmentOrchestrator, guestEnrollmentExchangePath, bytes.Repeat([]byte{'x'}, 32<<10))
	assertEnrollmentStatus(t, status, body, http.StatusNotFound, "not-found")
	status, body = disabled.postJSONWithToken(runtimeIdentityCanary(0x44), guestRuntimeIdentityStatus, runtimeIdentityStatusRequest(map[string]any{"binding": request["binding"]}))
	assertEnrollmentStatus(t, status, body, http.StatusNotFound, "not-found")
	status, body = disabled.postJSONWithToken(runtimeIdentityCanary(0x45), guestSessionIdentityIssue, guestSessionIssueRequest(runtimeEnvelope))
	assertEnrollmentStatus(t, status, body, http.StatusNotFound, "not-found")
	status, body = disabled.postJSONWithToken(guestSessionCredentialCanary(0x46), guestSessionIdentityAuth, guestSessionAuthenticateRequest(runtimeEnvelope))
	assertEnrollmentStatus(t, status, body, http.StatusNotFound, "not-found")
	status, body = disabled.postJSONWithToken(runtimeIdentityCanary(0x47), nativeEgressIdentityIssue, nativeEgressIssueRequest(runtimeEnvelope))
	assertEnrollmentStatus(t, status, body, http.StatusNotFound, "not-found")
	status, body = disabled.postJSONWithToken("nvt_eg1_"+guestSessionCredentialCanary(0x48), nativeEgressIdentityAuth, nativeEgressAuthenticateRequest(runtimeEnvelope))
	assertEnrollmentStatus(t, status, body, http.StatusNotFound, "not-found")
	status, body = disabled.postJSONWithToken(guestEnrollmentOrchestrator, nativeEgressRevokeExecution, nativeEgressRevokeExecutionRequest(runtimeEnvelope))
	assertEnrollmentStatus(t, status, body, http.StatusNotFound, "not-found")
	if matches, _ := filepath.Glob(filepath.Join(disabled.home, "*enrollment*")); len(matches) != 0 {
		t.Fatalf("disabled broker created enrollment state: %v", matches)
	}
}

func (f *brokerFixture) postEnrollmentRaw(token, path string, payload []byte) (int, map[string]any) {
	f.t.Helper()
	request, err := http.NewRequest(http.MethodPost, f.url+path, bytes.NewReader(payload))
	if err != nil {
		f.t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	decoded := map[string]any{}
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		f.t.Fatal(err)
	}
	return response.StatusCode, decoded
}

func openIncompleteEnrollmentRequest(t *testing.T, fixture *brokerFixture, path, token string) net.Conn {
	t.Helper()
	connection, err := net.DialTimeout("tcp", fixture.bind, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := "POST " + path + " HTTP/1.1\r\n" +
		"Host: " + fixture.bind + "\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 1\r\n" +
		"Connection: close\r\n"
	if token != "" {
		request += "Authorization: Bearer " + token + "\r\n"
	}
	request += "\r\n"
	if _, err := connection.Write([]byte(request)); err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	return connection
}

// saturateEnrollmentRequestSlots observes a rejected incomplete request before
// returning. Merely opening exactly bound sockets races handler admission on a
// loaded runner and does not prove that every semaphore slot is occupied.
func saturateEnrollmentRequestSlots(t *testing.T, fixture *brokerFixture, path, token string, bound int) []net.Conn {
	t.Helper()
	connections := make([]net.Conn, 0, bound+32)
	for range bound {
		connections = append(connections, openIncompleteEnrollmentRequest(t, fixture, path, token))
	}
	for range 32 {
		connection := openIncompleteEnrollmentRequest(t, fixture, path, token)
		if err := connection.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			_ = connection.Close()
			t.Fatal(err)
		}
		status, err := bufio.NewReader(connection).ReadString('\n')
		if err == nil {
			_ = connection.Close()
			if strings.Contains(status, " 429 ") {
				return connections
			}
			t.Fatalf("incomplete enrollment request was unexpectedly answered: %q", strings.TrimSpace(status))
		}
		if networkError, ok := err.(net.Error); !ok || !networkError.Timeout() {
			_ = connection.Close()
			t.Fatalf("wait for enrollment request admission: %v", err)
		}
		if err := connection.SetReadDeadline(time.Time{}); err != nil {
			_ = connection.Close()
			t.Fatal(err)
		}
		connections = append(connections, connection)
	}
	for _, connection := range connections {
		_ = connection.Close()
	}
	t.Fatal("enrollment request slots did not reach their configured bound")
	return nil
}

func enrollmentIssueRequest(uid, execution string, generation int64, guest string, ttl int) map[string]any {
	return map[string]any{
		"contract_version": guestEnrollmentVersion,
		"binding": map[string]any{
			"agent_run_uid":       uid,
			"execution_id":        execution,
			"driver_registration": "qemu-lab",
			"desired_generation":  generation,
			"guest_instance_id":   guest,
		},
		"ttl_seconds": ttl,
	}
}

func enrollmentExchangeRequest(envelope map[string]any) map[string]any {
	return map[string]any{
		"contract_version": guestEnrollmentVersion,
		"binding":          cloneObject(envelope["binding"]),
		"token":            envelope["token"],
	}
}

func runtimeIdentityStatusRequest(envelope map[string]any) map[string]any {
	return map[string]any{
		"contract_version": guestRuntimeIdentityVersion,
		"binding":          cloneObject(envelope["binding"]),
	}
}

func runtimeIdentityRotateRequest(envelope map[string]any, successor string) map[string]any {
	request := runtimeIdentityStatusRequest(envelope)
	request["successor"] = successor
	return request
}

func guestSessionIssueRequest(envelope map[string]any) map[string]any {
	return map[string]any{
		"contract_version": guestSessionIdentityVersion,
		"binding":          cloneObject(envelope["binding"]),
		"audience":         guestSessionAudience,
	}
}

func guestSessionAuthenticateRequest(envelope map[string]any) map[string]any {
	return guestSessionIssueRequest(envelope)
}

func nativeEgressIssueRequest(envelope map[string]any) map[string]any {
	return map[string]any{
		"contract_version": nativeEgressIdentityVersion,
		"binding":          cloneObject(envelope["binding"]),
		"audience":         nativeEgressAudience,
	}
}

func nativeEgressAuthenticateRequest(envelope map[string]any) map[string]any {
	return nativeEgressIssueRequest(envelope)
}

func nativeEgressRevokeBindingRequest(envelope map[string]any) map[string]any {
	return map[string]any{
		"contract_version": nativeEgressIdentityVersion,
		"binding":          cloneObject(envelope["binding"]),
	}
}

func nativeEgressRevokeExecutionRequest(envelope map[string]any) map[string]any {
	binding := cloneObject(envelope["binding"])
	return map[string]any{
		"contract_version": nativeEgressIdentityVersion,
		"execution_scope": map[string]any{
			"agent_run_uid":       binding["agent_run_uid"],
			"execution_id":        binding["execution_id"],
			"driver_registration": binding["driver_registration"],
		},
	}
}

func runtimeIdentityCanary(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func guestSessionCredentialCanary(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 40))
}

func enrollmentRevokeExecutionRequest(issue map[string]any) map[string]any {
	binding := cloneObject(issue["binding"])
	return map[string]any{
		"contract_version": guestEnrollmentVersion,
		"execution_scope": map[string]any{
			"agent_run_uid":       binding["agent_run_uid"],
			"execution_id":        binding["execution_id"],
			"driver_registration": binding["driver_registration"],
		},
	}
}

func cloneObject(value any) map[string]any {
	encoded, _ := json.Marshal(value)
	output := map[string]any{}
	_ = json.Unmarshal(encoded, &output)
	return output
}

func assertEnrollmentStatus(t *testing.T, status int, body map[string]any, expectedStatus int, reason string) {
	t.Helper()
	if status != expectedStatus {
		t.Fatalf("status=%d want=%d body=%v", status, expectedStatus, body)
	}
	if reason != "" && body["error"] != reason {
		t.Fatalf("error=%v want=%s body=%v", body["error"], reason, body)
	}
	if encoded, _ := json.Marshal(body); len(encoded) > 128<<10 {
		t.Fatalf("enrollment response exceeded bound: %d", len(encoded))
	}
}

func Example_guestEnrollmentPaths() {
	fmt.Println(guestEnrollmentIssuePath)
	fmt.Println(guestEnrollmentExchangePath)
	fmt.Println(guestEnrollmentCompleteCleanup)
	fmt.Println(guestSessionIdentityIssue)
	fmt.Println(guestSessionIdentityAuth)
	fmt.Println(nativeEgressIdentityIssue)
	fmt.Println(nativeEgressIdentityAuth)
	// Output:
	// /v1/guest-enrollment/issue
	// /v1/guest-enrollment/exchange
	// /v1/guest-enrollment/complete-execution-cleanup
	// /v1/guest-session-identity/issue
	// /v1/guest-session-identity/authenticate
	// /v1/native-egress-identity/issue
	// /v1/native-egress-identity/authenticate
}
