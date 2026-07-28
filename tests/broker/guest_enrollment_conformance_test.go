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
	fixture.stop()
	fixture.start()
	status, body = fixture.postJSONWithToken(successor, guestRuntimeIdentityStatus, runtimeIdentityStatusRequest(first))
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")
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
	const runtimeHTTPBound = 64
	slow := saturateEnrollmentRequestSlots(
		t,
		fixture,
		guestRuntimeIdentityRotate,
		runtimeIdentityCanary(0x7a),
		runtimeHTTPBound,
	)
	t.Cleanup(func() {
		for _, connection := range slow {
			_ = connection.Close()
		}
	})
	status, body := fixture.postEnrollmentRaw(runtimeIdentityCanary(0x7a), guestRuntimeIdentityRotate, []byte(`{}`))
	assertEnrollmentStatus(t, status, body, http.StatusTooManyRequests, "capacity-exceeded")

	request := enrollmentIssueRequest("runtime-saturated-uid", "runtime-saturated-execution", 1, "runtime-saturated-guest", 300)
	started := time.Now()
	status, body = fixture.postJSONWithToken(
		guestEnrollmentOrchestrator,
		guestEnrollmentRevokeExecution,
		enrollmentRevokeExecutionRequest(request),
	)
	assertEnrollmentStatus(t, status, body, http.StatusOK, "")
	if elapsed := time.Since(started); elapsed >= 2*time.Second {
		t.Fatalf("revocation was delayed by saturated runtime identity traffic: %s", elapsed)
	}
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
	runtimeDuplicate := []byte(`{"contract_version":"nvt.guest-runtime-identity/v1","binding":{},"successor":"x","successor":"y"}`)
	status, body = fixture.postEnrollmentRaw(runtimeIdentityCanary(0x44), guestRuntimeIdentityRotate, runtimeDuplicate)
	assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")
	status, body = fixture.postEnrollmentRaw(runtimeIdentityCanary(0x44), guestRuntimeIdentityRotate, bytes.Repeat([]byte{' '}, (16<<10)+1))
	assertEnrollmentStatus(t, status, body, http.StatusBadRequest, "invalid-request")

	disabled := newBrokerFixture(t)
	status, body = disabled.postJSONWithToken(guestEnrollmentOrchestrator, guestEnrollmentIssuePath, request)
	assertEnrollmentStatus(t, status, body, http.StatusNotFound, "not-found")
	status, body = disabled.postEnrollmentRaw(guestEnrollmentOrchestrator, guestEnrollmentExchangePath, bytes.Repeat([]byte{'x'}, 32<<10))
	assertEnrollmentStatus(t, status, body, http.StatusNotFound, "not-found")
	status, body = disabled.postJSONWithToken(runtimeIdentityCanary(0x44), guestRuntimeIdentityStatus, runtimeIdentityStatusRequest(map[string]any{"binding": request["binding"]}))
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

func runtimeIdentityCanary(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
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
	// Output:
	// /v1/guest-enrollment/issue
	// /v1/guest-enrollment/exchange
	// /v1/guest-enrollment/complete-execution-cleanup
}
